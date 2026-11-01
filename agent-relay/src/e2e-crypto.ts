/**
 * e2e-crypto.ts — EasyCodex E2E v1 端到端加密（服务端侧）
 *
 * 设计目标：经过不可信中转（公共 frp 等）时，apiKey 永不上线、业务帧全部加密。
 *
 * 握手（ws 明文阶段，复用 auth 首消息）：
 *   Client → auth { e2e:true, clientPub(b64), hmac: HMAC(apiKey, 'e2e-c1:'+clientPub) }
 *   Server → 校验 HMAC → 生成 X25519 临时密钥对 → shared = DH(serverPriv, clientPub)
 *           sessionKey = HKDF-SHA256(shared, salt=clientPub||serverPub, info='easycodex-e2e-v1')
 *           → reply { e2e:true, serverPub(b64), hmac: HMAC(apiKey, 'e2e-s1:'+serverPub+':'+clientPub) }
 *   Client → 校验服务端 HMAC → 同样派生 sessionKey → 双向认证完成
 *
 * 握手后所有 ws 帧：{"enc": base64(nonce12 || AES-256-GCM(sessionKey, frameJson) || tag16)}
 *
 * /media/* HTTP：签名头 X-E2E-Timestamp + X-E2E-Sign=HMAC(apiKey, 'media:'+ts+':'+originalUrl)；
 * 响应体用 mediaKey = HKDF(apiKey, salt='easycodex-media-salt', info='easycodex-media-v1') 加密。
 *
 * 与 Android 端 E2ECrypto.kt 协议常量必须保持一致。
 */
import crypto from 'node:crypto';

export const E2E_INFO = 'easycodex-e2e-v1';
export const E2E_CLIENT_PROOF_PREFIX = 'e2e-c1:';
export const E2E_SERVER_PROOF_PREFIX = 'e2e-s1:';
export const MEDIA_KEY_SALT = 'easycodex-media-salt';
export const MEDIA_KEY_INFO = 'easycodex-media-v1';
export const MEDIA_SIGN_PREFIX = 'media:';
/** 签名时间戳容差：±5 分钟 */
export const MEDIA_SIGN_SKEW_MS = 5 * 60 * 1000;

/** X25519 SPKI DER 固定 12 字节前缀（SEQ{SEQ{OID 1.3.101.110}, BIT STRING len 33}），后接 32 字节公钥 */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_RAW_PUB_LEN = 32;

export function hmacSha256(apiKey: string, message: string): Buffer {
  return crypto.createHmac('sha256', apiKey).update(message, 'utf8').digest();
}

export function timingSafeEqualB64(a: string, b: string): boolean {
  try {
    const ab = Buffer.from(a, 'base64');
    const bb = Buffer.from(b, 'base64');
    return ab.length === bb.length && ab.length > 0 && crypto.timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}

/** 客户端握手证明：HMAC(apiKey, 'e2e-c1:' + clientPubB64) */
export function clientProof(apiKey: string, clientPubB64: string): string {
  return hmacSha256(apiKey, E2E_CLIENT_PROOF_PREFIX + clientPubB64).toString('base64');
}

/** 服务端握手证明：HMAC(apiKey, 'e2e-s1:' + serverPubB64 + ':' + clientPubB64) */
export function serverProof(apiKey: string, serverPubB64: string, clientPubB64: string): string {
  return hmacSha256(apiKey, `${E2E_SERVER_PROOF_PREFIX}${serverPubB64}:${clientPubB64}`).toString('base64');
}

export interface X25519KeyPairB64 {
  publicKeyB64: string;
  privateKey: crypto.KeyObject;
}

export function generateX25519KeyPair(): X25519KeyPairB64 {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  return { publicKeyB64: spki.subarray(X25519_SPKI_PREFIX.length).toString('base64'), privateKey };
}

function importX25519PublicKey(rawPubB64: string): crypto.KeyObject {
  const raw = Buffer.from(rawPubB64, 'base64');
  if (raw.length !== X25519_RAW_PUB_LEN) {
    throw new Error(`Invalid X25519 public key length: ${raw.length}`);
  }
  return crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

/**
 * 服务端：用己方私钥 + 客户端公钥派生会话密钥。
 * sessionKey = HKDF-SHA256(shared, salt=clientPubRaw||serverPubRaw, info=E2E_INFO, 32)
 */
export function deriveSessionKey(
  privateKey: crypto.KeyObject,
  peerPublicKeyB64: string,
  selfPublicKeyB64: string,
  selfIsServer: boolean,
): Buffer {
  const shared = crypto.diffieHellman({ privateKey, publicKey: importX25519PublicKey(peerPublicKeyB64) });
  const clientRaw = Buffer.from(selfIsServer ? peerPublicKeyB64 : selfPublicKeyB64, 'base64');
  const serverRaw = Buffer.from(selfIsServer ? selfPublicKeyB64 : peerPublicKeyB64, 'base64');
  const derived = crypto.hkdfSync('sha256', shared, Buffer.concat([clientRaw, serverRaw]), E2E_INFO, 32);
  return Buffer.from(derived);
}

/** 加密一帧：返回 base64(nonce || ciphertext || tag) */
export function encryptFrame(sessionKey: Buffer, plaintext: string): string {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, nonce);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]).toString('base64');
}

/** 解密一帧；失败抛异常（调用方按协议错误处理） */
export function decryptFrame(sessionKey: Buffer, encB64: string): string {
  const buf = Buffer.from(encB64, 'base64');
  if (buf.length < 12 + 16 + 1) throw new Error('Encrypted frame too short');
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ct = buf.subarray(12, buf.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/** 加密帧的外层信封（明文 JSON 外壳 + enc 字段） */
export function wrapEncryptedFrame(sessionKey: Buffer, payloadJson: string): string {
  return JSON.stringify({ enc: encryptFrame(sessionKey, payloadJson) });
}

/** 若是加密信封则解密返回内层 JSON；否则原样返回（明文帧） */
export function unwrapFrame(sessionKey: Buffer | null, rawText: string): string {
  if (!sessionKey) return rawText;
  let outer: { enc?: unknown };
  try {
    outer = JSON.parse(rawText);
  } catch {
    return rawText; // 交给下游 JSON 解析报错，保持原有错误行为
  }
  if (typeof outer?.enc !== 'string') {
    throw new Error('Expected encrypted frame');
  }
  return decryptFrame(sessionKey, outer.enc);
}

// ---------- /media/* HTTP 签名与加密 ----------

export function deriveMediaKey(apiKey: string): Buffer {
  const derived = crypto.hkdfSync('sha256', apiKey, MEDIA_KEY_SALT, MEDIA_KEY_INFO, 32);
  return Buffer.from(derived);
}

export function mediaSignature(apiKey: string, timestamp: string, originalUrl: string): string {
  return hmacSha256(apiKey, `${MEDIA_SIGN_PREFIX}${timestamp}:${originalUrl}`).toString('base64');
}

/** 校验媒体请求签名；返回错误信息或 null（通过） */
export function verifyMediaRequest(
  apiKey: string,
  timestamp: string | undefined,
  signature: string | undefined,
  originalUrl: string,
): string | null {
  if (!timestamp || !signature) return 'Missing signature headers';
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > MEDIA_SIGN_SKEW_MS) {
    return 'Signature timestamp out of range';
  }
  const expected = mediaSignature(apiKey, timestamp, originalUrl);
  if (!timingSafeEqualB64(expected, signature)) return 'Invalid signature';
  return null;
}

/** 加密二进制体（媒体文件）：nonce || ct || tag */
export function encryptBuffer(mediaKey: Buffer, data: Buffer): Buffer {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', mediaKey, nonce);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]);
}

export function decryptBuffer(mediaKey: Buffer, data: Buffer): Buffer {
  if (data.length < 12 + 16 + 1) throw new Error('Encrypted payload too short');
  const nonce = data.subarray(0, 12);
  const tag = data.subarray(data.length - 16);
  const ct = data.subarray(12, data.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', mediaKey, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export function isLoopbackAddress(remoteAddress: string | undefined): boolean {
  if (!remoteAddress) return false;
  return (
    remoteAddress === '127.0.0.1' ||
    remoteAddress === '::1' ||
    remoteAddress === '::ffff:127.0.0.1' ||
    remoteAddress === 'localhost'
  );
}
