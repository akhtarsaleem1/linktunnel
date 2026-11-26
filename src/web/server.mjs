import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ConfigStore } from '../config/store.mjs';
import { getLocalLanIps } from '../node/network-guard.mjs';
import { ClientNode } from '../node/client.mjs';
import { UnifiedProxyServer } from '../node/proxy.mjs';
import { SharerNode } from '../node/sharer.mjs';
import { generateQrSvg } from '../protocol/qr.mjs';
import { acceptWsUpgrade } from '../protocol/ws.mjs';
import {
  enableWindowsSystemProxy,
  readWindowsProxySettings,
  restoreWindowsSystemProxy,
  restoreWindowsSystemProxySync,
} from '../platform/win-proxy.mjs';
import { RelayServer } from '../relay/server.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
};

function readJsonBody(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function normalizeRelayUrl(url) {
  const trimmed = String(url || '').trim();
  if (!trimmed) return '';
  return trimmed.replace(/^(wss?:\/\/)0\.0\.0\.0(:|\/|$)/i, '$1127.0.0.1$2');
}

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}

function isLocalOrigin(origin) {
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '::1';
  } catch {
    return false;
  }
}

/**
 * Full-stack local control center orchestrating SharerNode, ClientNode, UnifiedProxyServer,
 * optional local RelayServer, Windows System Proxy toggle, and Web UI dashboard.
 */
export class LinkTunnelApp {
  constructor({ uiHost = '127.0.0.1', uiPort = 4321, dataDir = null } = {}) {
    this.uiHost = uiHost;
    this.uiPort = uiPort;
    this.store = new ConfigStore(dataDir);
    const cfg = this.store.get();

    this.clientNode = new ClientNode({ deviceId: cfg.deviceId, deviceName: cfg.deviceName });
    this.proxyServer = new UnifiedProxyServer({
      clientNode: this.clientNode,
      host: '127.0.0.1',
      port: cfg.proxyPort || 10808,
    });
    this.sharerNode = null;
    this.localRelay = null;
    this.httpServer = null;
    this.uiClients = new Set();
    this.winProxyActive = false;
    this._broadcastTimer = null;

    const pushUpdate = () => this._scheduleBroadcast();
    this.clientNode.on('state', (st) => {
      if (this.winProxyActive && (st.status === 'disconnected' || st.status === 'error')) {
        this.setSystemProxy(false).catch(() => {});
      }
      pushUpdate();
    });
    this.clientNode.on('log', pushUpdate);
    this.proxyServer.on('state', pushUpdate);

    this._onProcessExit = () => {
      if (this.winProxyActive) {
        restoreWindowsSystemProxySync(this.store.get().winProxyBackup);
      }
    };
    process.on('exit', this._onProcessExit);
  }

  async start() {
    // Crash recovery: if a previous session left our managed Windows system proxy enabled, restore it!
    const cfg = this.store.get();
    if (cfg.winProxyManaged && process.platform === 'win32') {
      await restoreWindowsSystemProxy(cfg.winProxyBackup).catch(() => {});
      this.store.update({ winProxyManaged: false, winProxyBackup: null });
    }

    await this.proxyServer.start();

    this.httpServer = http.createServer((req, res) => {
      this._handleHttp(req, res).catch((err) => {
        sendJson(res, 500, { ok: false, error: err.message });
      });
    });

    this.httpServer.on('upgrade', (req, socket, head) => {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      if (url.pathname === '/ws') {
        const ws = acceptWsUpgrade(req, socket, head);
        if (!ws) return;
        this.uiClients.add(ws);
        ws.on('close', () => this.uiClients.delete(ws));
        ws.on('error', () => this.uiClients.delete(ws));
        this.getFullState().then((st) => ws.sendJson({ type: 'state', data: st })).catch(() => {});
        return;
      }
      socket.destroy();
    });

    await new Promise((resolve, reject) => {
      this.httpServer.once('error', reject);
      this.httpServer.listen(this.uiPort, this.uiHost, () => {
        this.httpServer.removeListener('error', reject);
        const addr = this.httpServer.address();
        if (typeof addr === 'object' && addr) this.uiPort = addr.port;
        resolve();
      });
    });

    return { host: this.uiHost, port: this.uiPort, url: `http://${this.uiHost}:${this.uiPort}` };
  }

  _scheduleBroadcast() {
    if (this.uiClients.size === 0 || this._broadcastTimer) return;
    this._broadcastTimer = setTimeout(async () => {
      this._broadcastTimer = null;
      if (this.uiClients.size === 0) return;
      const state = await this.getFullState();
      const payload = JSON.stringify({ type: 'state', data: state });
      for (const ws of this.uiClients) {
        if (!ws.closed) ws.send(payload, false);
      }
    }, 150);
    this._broadcastTimer.unref?.();
  }

  async getFullState() {
    const cfg = this.store.get();
    const sysProxy =
      process.platform === 'win32'
        ? await readWindowsProxySettings()
        : { supported: false, enabled: false, proxyServer: '' };

    return {
      platform: process.platform,
      device: {
        deviceId: cfg.deviceId,
        deviceName: cfg.deviceName,
        defaultRelayUrl: cfg.defaultRelayUrl,
      },
      sharer: this.sharerNode
        ? this.sharerNode.getState()
        : { running: false, paused: false, peers: [], policy: {} },
      client: this.clientNode.getState(),
      proxy: this.proxyServer.getState(),
      relay: this.localRelay
        ? { running: true, port: this.localRelay.port, ...this.localRelay.getStats() }
        : { running: false, port: cfg.relayPort || 4320 },
      systemProxy: {
        ...sysProxy,
        managedByApp: this.winProxyActive,
      },
      lanIps: getLocalLanIps(),
      savedPeers: cfg.savedPeers || [],
      logs: [
        ...(this.sharerNode?.logs || []).map((l) => ({ ...l, scope: 'sharer' })),
        ...this.clientNode.logs.map((l) => ({ ...l, scope: 'client' })),
      ]
        .sort((a, b) => a.ts - b.ts)
        .slice(-80),
    };
  }

  async _handleHttp(req, res) {
    const url = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
    const pathname = url.pathname;

    // CSRF guard for mutating API routes when bound locally
    if (pathname.startsWith('/api/') && req.method !== 'GET') {
      if (this.uiHost === '127.0.0.1' && !isLocalOrigin(req.headers.origin)) {
        sendJson(res, 403, { ok: false, error: 'Cross-origin requests blocked' });
        return;
      }
    }

    if (pathname === '/api/state' && req.method === 'GET') {
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    if (pathname === '/api/qr' && req.method === 'GET') {
      const text = url.searchParams.get('text') || '';
      if (!text) {
        sendJson(res, 400, { ok: false, error: 'Missing text parameter' });
        return;
      }
      const { svg } = generateQrSvg(text, { ecc: 'M', margin: 3 });
      res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-store' });
      res.end(svg);
      return;
    }

    if (pathname === '/api/device' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const updates = {};
      if (typeof body.deviceName === 'string' && body.deviceName.trim()) {
        updates.deviceName = body.deviceName.trim().slice(0, 48);
        this.clientNode.deviceName = updates.deviceName;
        if (this.sharerNode) this.sharerNode.deviceName = updates.deviceName;
      }
      if (typeof body.defaultRelayUrl === 'string') {
        updates.defaultRelayUrl = body.defaultRelayUrl.trim();
      }
      this.store.update(updates);
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    // --- Sharer API ---
    if (pathname === '/api/share/start' && req.method === 'POST') {
      const body = await readJsonBody(req);
      if (this.sharerNode) await this.sharerNode.stop();

      const cfg = this.store.get();
      const maxMbps = Number(body.maxBandwidthMbps) || 0;
      const maxQuotaMb = Number(body.maxQuotaMb) || 0;
      const relayUrl = normalizeRelayUrl(
        typeof body.relayUrl === 'string' ? body.relayUrl : cfg.defaultRelayUrl
      );

      const parsedDirectPort =
        body.directPort !== undefined && body.directPort !== '' && body.directPort !== null
          ? Number(body.directPort)
          : cfg.directPort || 4322;

      this.sharerNode = new SharerNode({
        deviceId: cfg.deviceId,
        deviceName: cfg.deviceName,
        roomCode: body.roomCode || null,
        secret: body.secret || null,
        relayUrl,
        enableDirect: body.enableDirect !== false,
        directPort: Number.isFinite(parsedDirectPort) ? parsedDirectPort : 4322,
        publicDirectHost: typeof body.publicDirectHost === 'string' ? body.publicDirectHost.trim() : '',
        blockPrivateNetwork: body.blockPrivateNetwork !== false,
        maxBandwidthBps: maxMbps > 0 ? Math.floor((maxMbps * 1_000_000) / 8) : 0,
        maxQuotaBytes: maxQuotaMb > 0 ? Math.floor(maxQuotaMb * 1024 * 1024) : 0,
        maxPeers: Number(body.maxPeers) || 5,
      });

      this.sharerNode.on('state', () => this._scheduleBroadcast());
      this.sharerNode.on('log', () => this._scheduleBroadcast());
      if (relayUrl) this.store.update({ defaultRelayUrl: relayUrl });

      await this.sharerNode.start();
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    if (pathname === '/api/share/stop' && req.method === 'POST') {
      if (this.sharerNode) {
        await this.sharerNode.stop();
        this.sharerNode = null;
      }
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    if (pathname === '/api/share/pause' && req.method === 'POST') {
      const body = await readJsonBody(req);
      if (!this.sharerNode) {
        sendJson(res, 400, { ok: false, error: 'Sharer is not running' });
        return;
      }
      this.sharerNode.setPaused(Boolean(body.paused));
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    if (pathname === '/api/share/policy' && req.method === 'POST') {
      const body = await readJsonBody(req);
      if (!this.sharerNode) {
        sendJson(res, 400, { ok: false, error: 'Sharer is not running' });
        return;
      }
      const policyUpdate = {};
      if ('maxBandwidthMbps' in body) {
        const mbps = Number(body.maxBandwidthMbps) || 0;
        policyUpdate.maxBandwidthBps = mbps > 0 ? Math.floor((mbps * 1_000_000) / 8) : 0;
      }
      if ('maxQuotaMb' in body) {
        const mb = Number(body.maxQuotaMb) || 0;
        policyUpdate.maxQuotaBytes = mb > 0 ? Math.floor(mb * 1024 * 1024) : 0;
      }
      if ('blockPrivateNetwork' in body) {
        policyUpdate.blockPrivateNetwork = Boolean(body.blockPrivateNetwork);
      }
      this.sharerNode.updatePolicy(policyUpdate);
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    if (pathname === '/api/share/kick' && req.method === 'POST') {
      const body = await readJsonBody(req);
      if (!this.sharerNode) {
        sendJson(res, 400, { ok: false, error: 'Sharer is not running' });
        return;
      }
      this.sharerNode.kickPeer(String(body.peerKey || ''));
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    // --- Client API ---
    if (pathname === '/api/client/connect' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const state = await this.clientNode.connect({
        inviteUri: body.inviteUri,
        roomCode: body.roomCode,
        secret: body.secret,
        relayUrl: body.relayUrl !== undefined ? normalizeRelayUrl(body.relayUrl) : undefined,
        directEndpoints: body.directEndpoints,
        mode: body.mode || 'hybrid',
      });

      if (body.savePeer !== false && this.clientNode.config) {
        this.store.savePeer({
          name: body.peerLabel || this.clientNode.peerName || this.clientNode.config.roomCode,
          roomCode: this.clientNode.config.roomCode,
          secret: this.clientNode.config.secret,
          relayUrl: this.clientNode.config.relayUrl,
          directEndpoints: this.clientNode.config.directEndpoints,
          mode: this.clientNode.config.mode,
        });
      }
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, client: state, data: await this.getFullState() });
      return;
    }

    if (pathname === '/api/client/disconnect' && req.method === 'POST') {
      this.clientNode.disconnect();
      if (this.winProxyActive) {
        await this.setSystemProxy(false);
      }
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    if (pathname === '/api/client/check-ip' && req.method === 'POST') {
      const exitIp = await this.clientNode.checkExitIp();
      sendJson(res, 200, { ok: true, exitIp, data: await this.getFullState() });
      return;
    }

    if (pathname.startsWith('/api/peers/') && req.method === 'DELETE') {
      const roomCode = decodeURIComponent(pathname.slice('/api/peers/'.length));
      this.store.removePeer(roomCode);
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    // --- Proxy & System Proxy API ---
    if (pathname === '/api/proxy/config' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const nextHost = body.lanExpose ? '0.0.0.0' : '127.0.0.1';
      const nextPort = Number(body.port) || this.proxyServer.port;
      await this.proxyServer.reconfigure({
        host: nextHost,
        port: nextPort,
        auth: body.auth,
      });
      this.store.update({ proxyPort: this.proxyServer.port });
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    if (pathname === '/api/proxy/system' && req.method === 'POST') {
      const body = await readJsonBody(req);
      await this.setSystemProxy(Boolean(body.enabled));
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    // --- Local Relay API ---
    if (pathname === '/api/relay/start' && req.method === 'POST') {
      const body = await readJsonBody(req);
      if (this.localRelay) await this.localRelay.stop();
      const parsedPort =
        body.port !== undefined && body.port !== '' && body.port !== null ? Number(body.port) : 4320;
      const port = Number.isFinite(parsedPort) ? parsedPort : 4320;
      this.localRelay = new RelayServer({ host: body.host || '0.0.0.0', port });
      await this.localRelay.start();
      this.store.update({ relayPort: this.localRelay.port });
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    if (pathname === '/api/relay/stop' && req.method === 'POST') {
      if (this.localRelay) {
        await this.localRelay.stop();
        this.localRelay = null;
      }
      this._scheduleBroadcast();
      sendJson(res, 200, { ok: true, data: await this.getFullState() });
      return;
    }

    // Static UI file serving
    const relPath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const safePath = path.normalize(relPath).replace(/^(\.\.[/\\])+/, '');
    const fullPath = path.join(PUBLIC_DIR, safePath);
    if (!fullPath.startsWith(PUBLIC_DIR) || !fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(fullPath);
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    fs.createReadStream(fullPath).pipe(res);
  }

  async setSystemProxy(enabled) {
    const cfg = this.store.get();
    if (enabled) {
      if (this.clientNode.status !== 'connected') {
        throw new Error('Connect to a remote tunnel first before enabling Windows System Proxy');
      }
      const { backup } = await enableWindowsSystemProxy(this.proxyServer.port, cfg.winProxyBackup);
      this.winProxyActive = true;
      this.store.update({ winProxyBackup: backup, winProxyManaged: true });
    } else {
      await restoreWindowsSystemProxy(cfg.winProxyBackup);
      this.winProxyActive = false;
      this.store.update({ winProxyBackup: null, winProxyManaged: false });
    }
  }

  async stop() {
    clearTimeout(this._broadcastTimer);
    if (this._onProcessExit) {
      process.removeListener('exit', this._onProcessExit);
    }
    if (this.winProxyActive) {
      await this.setSystemProxy(false).catch(() => {});
    }
    this.clientNode.disconnect('App shutting down');
    if (this.sharerNode) await this.sharerNode.stop();
    await this.proxyServer.stop();
    if (this.localRelay) await this.localRelay.stop();
    for (const ws of this.uiClients) ws.destroy();
    this.uiClients.clear();
    if (this.httpServer) {
      await new Promise((resolve) => this.httpServer.close(() => resolve()));
      this.httpServer = null;
    }
  }
}
