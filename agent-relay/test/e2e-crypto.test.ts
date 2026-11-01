import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import {
  clientProof,
  decryptBuffer,
  decryptFrame,
  deriveMediaKey,
  deriveSessionKey,
  encryptBuffer,
  encryptFrame,
  generateX25519KeyPair,
  isLoopbackAddress,
  mediaSignature,
  serverProof,
  timingSafeEqualB64,
  unwrapFrame,
  verifyMediaRequest,
  wrapEncryptedFrame,
} from '../src/e2e-crypto';

const API_KEY = crypto.randomBytes(32).toString('hex');

test('handshake: client/server derive identical session key, apiKey never transmitted', () => {
  const client = generateX25519KeyPair();
  // 客户端证明：HMAC(apiKey, 'e2e-c1:'+clientPub) —— apiKey 本身不上线
  const proof = clientProof(API_KEY, client.publicKeyB64);
  assert.ok(timingSafeEqualB64(proof, clientProof(API_KEY, client.publicKeyB64)));
  assert.ok(!timingSafeEqualB64(proof, clientProof('wrong-key', client.publicKeyB64)));

  // 服务端生成密钥对并各自派生会话密钥
  const server = generateX25519KeyPair();
  const serverKey = deriveSessionKey(server.privateKey, client.publicKeyB64, server.publicKeyB64, true);
  const clientKey = deriveSessionKey(client.privateKey, server.publicKeyB64, client.publicKeyB64, false);
  assert.deepEqual(clientKey, serverKey);

  // 服务端证明可被客户端用同一 apiKey 验证
  const sProof = serverProof(API_KEY, server.publicKeyB64, client.publicKeyB64);
  assert.ok(timingSafeEqualB64(sProof, serverProof(API_KEY, server.publicKeyB64, client.publicKeyB64)));
  assert.ok(!timingSafeEqualB64(sProof, serverProof('wrong-key', server.publicKeyB64, client.publicKeyB64)));
});

test('frame roundtrip: encrypt/decrypt, tamper and wrong key rejected', () => {
  const a = generateX25519KeyPair();
  const b = generateX25519KeyPair();
  const keyA = deriveSessionKey(a.privateKey, b.publicKeyB64, a.publicKeyB64, true);
  const keyB = deriveSessionKey(b.privateKey, a.publicKeyB64, b.publicKeyB64, false);

  const plaintext = JSON.stringify({ action: 'send_message', params: { text: '你好，codex' }, requestId: '1' });
  const envelope = wrapEncryptedFrame(keyA, plaintext);
  const parsed = JSON.parse(envelope);
  assert.equal(typeof parsed.enc, 'string');
  assert.ok(!envelope.includes('send_message'), 'envelope must not leak plaintext');

  assert.equal(unwrapFrame(keyB, envelope), plaintext);
  // 篡改密文最后一个 base64 字符 → GCM 校验必须失败
  const tampered = JSON.stringify({ enc: parsed.enc.slice(0, -1) + (parsed.enc.endsWith('A') ? 'B' : 'A') });
  assert.throws(() => unwrapFrame(keyB, tampered));
  assert.throws(() => unwrapFrame(deriveMediaKey('other'), envelope));
});

test('unwrapFrame passes plaintext through when no session key', () => {
  assert.equal(unwrapFrame(null, '{"action":"auth"}'), '{"action":"auth"}');
  assert.equal(unwrapFrame(null, 'not json'), 'not json');
});

test('decryptFrame rejects short payloads', () => {
  assert.throws(() => decryptFrame(deriveMediaKey('k'), Buffer.alloc(10).toString('base64')));
});

test('media: signature verify, skew window, tamper detection', () => {
  const url = '/media/image?path=%2Ftmp%2Fa.png&enc=1';
  const ts = String(Date.now());
  const sign = mediaSignature(API_KEY, ts, url);
  assert.equal(verifyMediaRequest(API_KEY, ts, sign, url), null);
  assert.equal(verifyMediaRequest(API_KEY, ts, sign, '/media/image?path=%2Ftmp%2Fb.png&enc=1'), 'Invalid signature');
  assert.equal(verifyMediaRequest(API_KEY, String(Date.now() - 10 * 60 * 1000), sign, url), 'Signature timestamp out of range');
  assert.equal(verifyMediaRequest(API_KEY, undefined, sign, url), 'Missing signature headers');
  assert.equal(verifyMediaRequest('other-key', ts, sign, url), 'Invalid signature');
});

test('media buffer roundtrip', () => {
  const key = deriveMediaKey(API_KEY);
  const data = crypto.randomBytes(64 * 1024);
  const enc = encryptBuffer(key, data);
  assert.deepEqual(decryptBuffer(key, enc), data);
  assert.throws(() => decryptBuffer(deriveMediaKey('wrong'), enc));
});

test('loopback detection', () => {
  assert.ok(isLoopbackAddress('127.0.0.1'));
  assert.ok(isLoopbackAddress('::1'));
  assert.ok(isLoopbackAddress('::ffff:127.0.0.1'));
  assert.ok(!isLoopbackAddress('192.168.1.5'));
  assert.ok(!isLoopbackAddress(undefined));
});
