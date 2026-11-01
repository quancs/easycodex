/**
 * tunnel.cjs — EasyCodex 内嵌 frpc 公网隧道管理
 *
 * 让手机经公共 frps 服务器访问本机 relay（配合 agent-relay 的 E2E v1 加密，
 * 中转方只能看到密文）。负责 frpc 二进制的下载/校验/解压、配置生成、
 * 进程生命周期（spawn、崩溃退避重启、退出清理）。
 *
 * 配置存于 desktop-relay.json 的 tunnel 段：
 *   { enabled, serverAddr, serverPort, token, remotePort, downloadBase }
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { spawn, execFileSync } = require('node:child_process');

const FRP_VERSION = '0.61.0';
const FRPC_ASSET_PREFIX = `frp_${FRP_VERSION}`;
const GITHUB_DOWNLOAD = `https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}`;
const CHECKSUMS_ASSET = 'frp_sha256_checksums.txt';
const RESTART_BACKOFF_MS = [2000, 5000, 15000, 30000];

function frpcAssetName() {
  if (process.platform === 'darwin' && process.arch === 'arm64') return `${FRPC_ASSET_PREFIX}_darwin_arm64.tar.gz`;
  if (process.platform === 'darwin') return `${FRPC_ASSET_PREFIX}_darwin_amd64.tar.gz`;
  if (process.platform === 'linux' && process.arch === 'arm64') return `${FRPC_ASSET_PREFIX}_linux_arm64.tar.gz`;
  if (process.platform === 'linux') return `${FRPC_ASSET_PREFIX}_linux_amd64.tar.gz`;
  if (process.platform === 'win32') return `${FRPC_ASSET_PREFIX}_windows_amd64.zip`;
  throw new Error(`Unsupported platform for frpc: ${process.platform}/${process.arch}`);
}

function cleanTunnelConfig(input) {
  const raw = input && typeof input === 'object' ? input : {};
  return {
    enabled: raw.enabled === true,
    serverAddr: typeof raw.serverAddr === 'string' ? raw.serverAddr.trim() : '',
    serverPort: Number.isFinite(Number(raw.serverPort)) && Number(raw.serverPort) > 0 ? Number(raw.serverPort) : 7000,
    token: typeof raw.token === 'string' ? raw.token.trim() : '',
    remotePort: Number.isFinite(Number(raw.remotePort)) && Number(raw.remotePort) > 0 ? Number(raw.remotePort) : 0,
    downloadBase: typeof raw.downloadBase === 'string' ? raw.downloadBase.trim() : '',
  };
}

function validateTunnelConfig(config) {
  if (!config.serverAddr) throw new Error('请填写 frps 服务器地址（serverAddr）');
  if (!config.remotePort) throw new Error('请填写 frps 上分配的远程端口（remotePort）');
  return config;
}

function createTunnelManager(deps) {
  const { appendLog, broadcastState, downloadFile, loadDesktopConfig, saveDesktopConfig } = deps;
  const binDir = path.join(os.homedir(), '.easycodex', 'bin');
  const frpcPath = path.join(binDir, process.platform === 'win32' ? 'frpc.exe' : 'frpc');
  const tomlPath = path.join(os.homedir(), '.easycodex', 'frpc.toml');

  let frpcProcess = null;
  let status = 'offline'; // offline | downloading | starting | online | error
  let lastError = '';
  let restartTimer = null;
  let restartAttempt = 0;
  let manualStop = false;

  function tunnelConfig() {
    return cleanTunnelConfig(loadDesktopConfig().tunnel);
  }

  function getState() {
    const config = tunnelConfig();
    return {
      ...config,
      status,
      lastError,
      frpcInstalled: fs.existsSync(frpcPath),
      frpVersion: FRP_VERSION,
      publicRelayUrl: status === 'online' ? publicRelayUrl(config) : '',
    };
  }

  function publicRelayUrl(config) {
    return `ws://${config.serverAddr}:${config.remotePort}`;
  }

  function downloadBase(config) {
    // downloadBase 支持镜像前缀（如 https://ghfast.top/https://github.com/...）
    return config.downloadBase || GITHUB_DOWNLOAD;
  }

  async function fetchText(url) {
    return new Promise((resolve, reject) => {
      const req = https.get(url, { headers: { 'User-Agent': 'easycodex-desktop-relay' }, timeout: 20000 }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          resolve(fetchText(new URL(res.headers.location, url).toString()));
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => resolve(body));
      });
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
    });
  }

  async function expectedSha256(config, assetName) {
    const text = await fetchText(`${downloadBase(config)}/${CHECKSUMS_ASSET}`);
    for (const line of text.split('\n')) {
      const [hash, name] = line.trim().split(/\s+/);
      if (name === assetName && /^[0-9a-f]{64}$/i.test(hash)) return hash.toLowerCase();
    }
    throw new Error(`checksums 中未找到 ${assetName}`);
  }

  async function ensureFrpc(config) {
    if (fs.existsSync(frpcPath)) return frpcPath;
    status = 'downloading';
    await broadcastState();
    const asset = frpcAssetName();
    const archivePath = path.join(binDir, asset);
    fs.mkdirSync(binDir, { recursive: true });
    appendLog(`Downloading frpc v${FRP_VERSION} (${asset})...`);
    await downloadFile(`${downloadBase(config)}/${asset}`, archivePath);
    const expected = await expectedSha256(config, asset);
    const actual = crypto.createHash('sha256').update(fs.readFileSync(archivePath)).digest('hex');
    if (actual !== expected) {
      fs.rmSync(archivePath, { force: true });
      throw new Error(`frpc 校验和不匹配（期望 ${expected.slice(0, 12)}…，实际 ${actual.slice(0, 12)}…）`);
    }
    // 解包并取出 frpc 二进制（release 包内路径为 <prefix>_<os>_<arch>/frpc）
    const extractDir = path.join(binDir, `frp-${FRP_VERSION}-extract`);
    fs.rmSync(extractDir, { recursive: true, force: true });
    fs.mkdirSync(extractDir, { recursive: true });
    if (asset.endsWith('.zip')) {
      execFileSync('unzip', ['-o', archivePath, '-d', extractDir]);
    } else {
      execFileSync('tar', ['-xzf', archivePath, '-C', extractDir]);
    }
    const innerDir = fs.readdirSync(extractDir).find((name) => name.startsWith(FRPC_ASSET_PREFIX));
    const binaryName = process.platform === 'win32' ? 'frpc.exe' : 'frpc';
    const extracted = innerDir && path.join(extractDir, innerDir, binaryName);
    if (!extracted || !fs.existsSync(extracted)) throw new Error('frpc 解压失败：未找到二进制');
    fs.copyFileSync(extracted, frpcPath);
    fs.chmodSync(frpcPath, 0o755);
    fs.rmSync(extractDir, { recursive: true, force: true });
    fs.rmSync(archivePath, { force: true });
    appendLog('frpc installed.');
    return frpcPath;
  }

  function writeFrpcToml(config, relayPort) {
    const lines = [
      `serverAddr = ${JSON.stringify(config.serverAddr)}`,
      `serverPort = ${config.serverPort}`,
    ];
    if (config.token) lines.push(`auth.token = ${JSON.stringify(config.token)}`);
    lines.push(
      '',
      '[[proxies]]',
      'name = "easycodex-relay"',
      'type = "tcp"',
      'localIP = "127.0.0.1"',
      `localPort = ${relayPort}`,
      `remotePort = ${config.remotePort}`,
      '',
    );
    fs.writeFileSync(tomlPath, lines.join('\n'), { encoding: 'utf8', mode: 0o600 });
  }

  function clearRestart() {
    if (restartTimer) clearTimeout(restartTimer);
    restartTimer = null;
  }

  function scheduleRestart() {
    clearRestart();
    const delay = RESTART_BACKOFF_MS[Math.min(restartAttempt, RESTART_BACKOFF_MS.length - 1)];
    restartAttempt += 1;
    appendLog(`frpc exited; restarting in ${delay / 1000}s (attempt ${restartAttempt})...`);
    restartTimer = setTimeout(() => {
      restartTimer = null;
      if (!manualStop && tunnelConfig().enabled) {
        void startTunnel().catch((err) => appendLog(`frpc restart failed: ${err.message}`));
      }
    }, delay);
  }

  async function startTunnel() {
    if (frpcProcess) return getState();
    manualStop = false;
    const config = validateTunnelConfig(tunnelConfig());
    const relayPort = Number(loadDesktopConfig().port) || 1501;
    await ensureFrpc(config);
    writeFrpcToml(config, relayPort);
    status = 'starting';
    lastError = '';
    appendLog(`Starting frpc tunnel → ${config.serverAddr}:${config.remotePort} (local ${relayPort})...`);
    await broadcastState();
    frpcProcess = spawn(frpcPath, ['-c', tomlPath], { shell: false, windowsHide: true });
    frpcProcess.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      appendLog(`[frpc] ${text.trim()}`);
      if (status === 'starting' && text.includes('start proxy success')) {
        status = 'online';
        restartAttempt = 0;
        appendLog(`Tunnel online: ${publicRelayUrl(config)}`);
        void broadcastState();
      }
    });
    frpcProcess.stderr.on('data', (chunk) => appendLog(`[frpc] ${chunk.toString().trim()}`));
    frpcProcess.on('error', async (error) => {
      lastError = error.message;
      status = 'error';
      frpcProcess = null;
      appendLog(`frpc failed to start: ${error.message}`);
      await broadcastState();
      scheduleRestart();
    });
    frpcProcess.on('close', async (code) => {
      frpcProcess = null;
      if (status !== 'online') lastError = `frpc exited with code ${code ?? 'unknown'}`;
      status = manualStop ? 'offline' : 'error';
      appendLog(`frpc exited with code ${code ?? 'unknown'}.`);
      await broadcastState();
      if (!manualStop && tunnelConfig().enabled) scheduleRestart();
    });
    return getState();
  }

  async function stopTunnel() {
    manualStop = true;
    clearRestart();
    if (frpcProcess) {
      try { frpcProcess.kill(); } catch { /* already dead */ }
      frpcProcess = null;
    }
    status = 'offline';
    await broadcastState();
    return getState();
  }

  function stopTunnelSync() {
    manualStop = true;
    clearRestart();
    if (frpcProcess) {
      try { frpcProcess.kill(); } catch { /* already dead */ }
      frpcProcess = null;
    }
  }

  async function saveTunnelConfig(input) {
    const next = cleanTunnelConfig(input);
    saveDesktopConfig({ tunnel: next });
    // 改配置时如果在跑就重启隧道使新配置生效
    if (frpcProcess) {
      await stopTunnel();
      if (next.enabled) await startTunnel();
    } else if (next.enabled) {
      await startTunnel();
    }
    return getState();
  }

  return {
    getState,
    publicRelayUrl: () => (status === 'online' ? publicRelayUrl(tunnelConfig()) : ''),
    isOnline: () => status === 'online',
    saveTunnelConfig,
    startTunnel,
    stopTunnel,
    stopTunnelSync,
  };
}

module.exports = { createTunnelManager, cleanTunnelConfig, FRP_VERSION };
