import WebSocket from '/Users/quancs/code/easycodex/agent-relay/node_modules/ws/index.js';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {
  clientProof, serverProof, generateX25519KeyPair, deriveSessionKey,
  encryptFrame, decryptFrame, timingSafeEqualB64,
} from '/Users/quancs/code/easycodex/agent-relay/dist/e2e-crypto.js';

const API_KEY = process.env.TEST_API_KEY;
const URL_ = process.env.TEST_URL;
const expectedFp = new crypto.X509Certificate(fs.readFileSync(process.env.HOME + '/.easycodex/tls-cert.pem'))
  .fingerprint256.replace(/:/g, '').toLowerCase();

let tlsFpOk = false;
const ws = new WebSocket(URL_, { rejectUnauthorized: false });
let sessionKey = null;
const client = generateX25519KeyPair();
const done = (ok, msg) => { console.log(`${ok ? '✔' : '✖'} ${msg}`); process.exit(ok ? 0 : 1); };

ws.on('open', () => {
  const peerFp = ws._socket.getPeerCertificate()?.fingerprint256?.replace(/:/g, '').toLowerCase();
  tlsFpOk = peerFp === expectedFp;
  console.log(`${tlsFpOk ? '✔' : '✖'} TLS 证书指纹匹配（pinning 验证）${tlsFpOk ? '' : ` got=${peerFp}`}`);
  ws.send(JSON.stringify({
    action: 'auth', requestId: 'r1',
    params: { clientId: 'wss-verify', e2e: true, clientPub: client.publicKeyB64, hmac: clientProof(API_KEY, client.publicKeyB64) },
  }));
});
ws.on('message', (raw) => {
  let text = raw.toString();
  if (sessionKey) text = decryptFrame(sessionKey, JSON.parse(text).enc);
  const msg = JSON.parse(text);
  if (msg.action === 'auth') {
    console.log(msg.data?.e2e ? '✔ wss 上 E2E 握手成功' : '✖ 握手未带 e2e');
    const okProof = timingSafeEqualB64(msg.data.hmac, serverProof(API_KEY, msg.data.serverPub, client.publicKeyB64));
    sessionKey = deriveSessionKey(client.privateKey, msg.data.serverPub, client.publicKeyB64, false);
    ws.send(JSON.stringify({ enc: encryptFrame(sessionKey, JSON.stringify({ action: 'runtime_capabilities', requestId: 'r2', params: {} })) }));
    if (!okProof) done(false, '服务端证明不匹配');
    return;
  }
  if (msg.requestId === 'r2') done(tlsFpOk && msg.type === 'response', 'wss 公网隧道 + E2E 加密业务帧全通');
});
ws.on('error', (e) => done(false, e.message));
setTimeout(() => done(false, 'timeout'), 15000);
