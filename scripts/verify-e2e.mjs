// E2E 全链路验证：模拟 Android 客户端与 relay 完成握手 + 加密通信
import WebSocket from 'ws';
import {
  clientProof, serverProof, generateX25519KeyPair, deriveSessionKey,
  encryptFrame, decryptFrame, timingSafeEqualB64,
} from '/Users/quancs/code/easycodex/agent-relay/dist/e2e-crypto.js';

const API_KEY = process.env.TEST_API_KEY;
const URL_ = process.env.TEST_URL || 'ws://127.0.0.1:3939';
const results = [];
const ok = (name, pass, extra = '') => { results.push([name, pass]); console.log(`${pass ? '✔' : '✖'} ${name}${extra ? ' — ' + extra : ''}`); };

// ---------- 1. E2E 握手 + 加密业务帧 ----------
await new Promise((resolve) => {
  const ws = new WebSocket(URL_);
  let sessionKey = null;
  const client = generateX25519KeyPair();

  ws.on('open', () => {
    ws.send(JSON.stringify({
      action: 'auth', requestId: 'r1',
      params: { clientId: 'verify-client', e2e: true, clientPub: client.publicKeyB64, hmac: clientProof(API_KEY, client.publicKeyB64) },
    }));
  });

  ws.on('message', (raw) => {
    let text = raw.toString();
    if (sessionKey) {
      const outer = JSON.parse(text);
      ok('业务帧为密文信封', typeof outer.enc === 'string' && !text.includes('runtime_capabilities'));
      text = decryptFrame(sessionKey, outer.enc);
    }
    const msg = JSON.parse(text);

    if (msg.action === 'auth') {
      ok('握手应答带 e2e 标志', msg.data?.e2e === true);
      const { serverPub, hmac } = msg.data;
      ok('服务端 HMAC 证明校验通过', timingSafeEqualB64(hmac, serverProof(API_KEY, serverPub, client.publicKeyB64)));
      sessionKey = deriveSessionKey(client.privateKey, serverPub, client.publicKeyB64, false);
      ws.send(JSON.stringify({ enc: encryptFrame(sessionKey, JSON.stringify({ action: 'runtime_capabilities', requestId: 'r2', params: {} })) }));
      return;
    }
    if (msg.requestId === 'r2') {
      ok('加密请求获得加密应答', msg.type === 'response');
      ws.close();
      resolve();
    }
  });
  ws.on('error', (e) => { ok('E2E 连接', false, e.message); resolve(); });
  setTimeout(() => { ok('E2E 流程超时', false); try { ws.close(); } catch {} resolve(); }, 8000);
});

// ---------- 2. 错误 apiKey 被拒绝 ----------
await new Promise((resolve) => {
  const ws = new WebSocket(URL_);
  const client = generateX25519KeyPair();
  ws.on('open', () => {
    ws.send(JSON.stringify({
      action: 'auth', requestId: 'r1',
      params: { clientId: 'bad-client', e2e: true, clientPub: client.publicKeyB64, hmac: clientProof('wrong-key', client.publicKeyB64) },
    }));
  });
  ws.on('close', (code) => { ok('错误 apiKey 被拒绝(4001)', code === 4001, `code=${code}`); resolve(); });
  ws.on('error', () => {});
  setTimeout(() => { ok('错误 apiKey 被拒绝', false, 'timeout'); resolve(); }, 5000);
});

// ---------- 3. 回环豁免不了：明文旧客户端在 REQUIRE_E2E 下仍可连（loopback） ----------
await new Promise((resolve) => {
  const ws = new WebSocket(URL_);
  ws.on('open', () => ws.send(JSON.stringify({ action: 'auth', requestId: 'r1', params: { key: API_KEY, clientId: 'legacy' } })));
  ws.on('message', (raw) => {
    const msg = JSON.parse(raw.toString());
    if (msg.action === 'auth') { ok('回环旧版明文客户端兼容', msg.data?.ok === true); ws.close(); resolve(); }
  });
  ws.on('error', (e) => { ok('回环旧版明文客户端兼容', false, e.message); resolve(); });
  setTimeout(() => { ok('回环旧版明文客户端兼容', false, 'timeout'); resolve(); }, 5000);
});

// ---------- 4. /media/* 签名鉴权 ----------
const { mediaSignature, deriveMediaKey, encryptBuffer, decryptBuffer } = await import('/Users/quancs/code/easycodex/agent-relay/dist/e2e-crypto.js');
const ts = String(Date.now());
const mediaUrl = '/media/image?path=%2Ftmp%2Fnone.png&enc=1';
const sign = mediaSignature(API_KEY, ts, mediaUrl);
const httpBase = URL_.replace('ws://','http://').replace('wss://','https://');
const resp = await fetch(`${httpBase}${mediaUrl}`, { headers: { 'X-E2E-Timestamp': ts, 'X-E2E-Sign': sign } });
ok('媒体签名鉴权通过(403/404=已过鉴权层)', (resp.status === 404 || resp.status === 403), `status=${resp.status}`);
const respBad = await fetch(`${httpBase}${mediaUrl}`, { headers: { 'X-E2E-Timestamp': ts, 'X-E2E-Sign': mediaSignature('wrong', ts, mediaUrl) } });
ok('媒体错误签名被拒(401)', respBad.status === 401, `status=${respBad.status}`);
const mediaKey = deriveMediaKey(API_KEY);
const roundtrip = decryptBuffer(mediaKey, encryptBuffer(mediaKey, Buffer.from('hello media')));
ok('媒体加密体 roundtrip', roundtrip.toString() === 'hello media');

const failed = results.filter(([, p]) => !p).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
