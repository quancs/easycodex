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
    // SakuraFrp 等多租户 frps 需要 user 字段；proxyName 必须与面板创建的隧道名一致
    user: typeof raw.user === 'string' ? raw.user.trim() : '',
    proxyName: typeof raw.proxyName === 'string' && raw.proxyName.trim() ? raw.proxyName.trim() : 'easycodex-relay',
    // tcp = 四层转发（需境外节点或自建 frps）；http = SakuraFrp 国内节点的 HTTP(S) 隧道（wss）
    proxyType: raw.proxyType === 'http' ? 'http' : 'tcp',
    subdomain: typeof raw.subdomain === 'string' ? raw.subdomain.trim() : '',
    remotePort: Number.isFinite(Number(raw.remotePort)) && Number(raw.remotePort) > 0 ? Number(raw.remotePort) : 0,
    downloadBase: typeof raw.downloadBase === 'string' ? raw.downloadBase.trim() : '',
    // 额外转发（自建 frps 场景，如 hapi hub）：[{name, localPort, remotePort}]
    extraProxies: Array.isArray(raw.extraProxies)
      ? raw.extraProxies
          .filter((p) => p && typeof p === 'object')
          .map((p) => ({
            name: String(p.name || '').trim(),
            localPort: Number(p.localPort) || 0,
            remotePort: Number(p.remotePort) || 0,
          }))
          .filter((p) => p.name && p.localPort > 0 && p.remotePort > 0)
      : [],
  };
}

function validateTunnelConfig(config) {
  if (!config.serverAddr) throw new Error('请填写 frps 服务器地址（serverAddr）');
  if (config.proxyType === 'http') {
    if (!config.subdomain) throw new Error('HTTP(S) 隧道需要填写子域名（subdomain）');
  } else if (!config.remotePort) {
    throw new Error('请填写 frps 上分配的远程端口（remotePort）');
  }
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
    if (config.proxyType === 'http') {
      // HTTP(S) 隧道：frps 终结 TLS，手机经 wss://子域名 连接（443 隐含）
      return `wss://${config.subdomain}`;
    }
    // TCP 隧道转发的是 relay 的 wss 端口（自签 TLS 穿透 frps 的 HTTP 拦截），指纹经二维码 tlsfp 下发
    return `wss://${config.serverAddr}:${config.remotePort}`;
  }

  /** 隧道配置完整且启用（不依赖瞬时连接状态，避免二维码在公网/局域网地址间抖动） */
  function publicRelayUrlIfConfigured() {
    const config = tunnelConfig();
    if (!config.enabled || !config.serverAddr) return '';
    if (config.proxyType === 'http') return config.subdomain ? publicRelayUrl(config) : '';
    return config.remotePort ? publicRelayUrl(config) : '';
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
    const lines = [];
    // SakuraFrp 等多租户 frps 要求 user 字段放在 serverAddr 之前
    if (config.user) lines.push(`user = ${JSON.stringify(config.user)}`);
    lines.push(
      `serverAddr = ${JSON.stringify(config.serverAddr)}`,
      `serverPort = ${config.serverPort}`,
    );
    if (config.token) lines.push(`auth.token = ${JSON.stringify(config.token)}`);
    // 与 SakuraFrp 面板生成的官方配置保持一致（明文 TCP，E2E 已在应用层加密）
    lines.push('', 'transport.tls.enable = false', 'transport.tls.disableCustomTLSFirstByte = false');
    lines.push('', '[[proxies]]', `name = ${JSON.stringify(config.proxyName)}`);
    if (config.proxyType === 'http') {
      lines.push(
        'type = "http"',
        'localIP = "127.0.0.1"',
        `localPort = ${relayPort}`,
        `subdomain = ${JSON.stringify(config.subdomain)}`,
        '',
      );
    } else {
      // TCP 隧道转发 wss 端口（relay 在 PORT+1 提供自签 TLS）
      lines.push(
        'type = "tcp"',
        'localIP = "127.0.0.1"',
        `localPort = ${relayPort + 1}`,
        `remotePort = ${config.remotePort}`,
        '',
      );
    }
    // 额外转发（自建 frps：hapi hub 等）
    for (const p of config.extraProxies) {
      lines.push(
        '',
        '[[proxies]]',
        `name = ${JSON.stringify(p.name)}`,
        'type = "tcp"',
        'localIP = "127.0.0.1"',
        `localPort = ${p.localPort}`,
        `remotePort = ${p.remotePort}`,
        '',
      );
    }
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
    // stdout 按块到达，关键日志行可能被切断——先攒进滚动缓冲再检测
    let stdoutBuffer = '';
    frpcProcess.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      appendLog(`[frpc] ${text.trim()}`);
      stdoutBuffer = (stdoutBuffer + text).slice(-8192);
      if (status === 'starting' && stdoutBuffer.includes('start proxy success')) {
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
    publicRelayUrl: publicRelayUrlIfConfigured,
    isOnline: () => status === 'online',
    saveTunnelConfig,
    startTunnel,
    stopTunnel,
    stopTunnelSync,
  };
}

module.exports = { createTunnelManager, cleanTunnelConfig, FRP_VERSION };
