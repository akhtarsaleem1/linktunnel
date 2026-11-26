import crypto from 'node:crypto';
import EventEmitter from 'node:events';
import { ClientHandshake, deriveRelayRoomHash, parseInviteUri } from '../crypto/e2ee.mjs';
import { MuxSession } from '../protocol/mux.mjs';
import { connectWs } from '../protocol/ws.mjs';

/**
 * Client Tunnel Node: connects to a remote Sharer using Hybrid (Direct + Relay), Direct, or Relay mode,
 * authenticates E2EE, and provides a multiplexed stream interface for the local proxy.
 */
export class ClientNode extends EventEmitter {
  constructor({ deviceId, deviceName = 'Client-Device' } = {}) {
    super();
    this.deviceId = deviceId || crypto.randomBytes(16).toString('hex');
    this.deviceName = deviceName;

    this.status = 'disconnected'; // disconnected | connecting | connected | reconnecting | error
    this.lastError = '';
    this.config = null; // { roomCode, secret, relayUrl, directEndpoints, mode }
    this.activeTransport = null; // 'direct' | 'relay'
    this.activeEndpoint = '';
    this.peerName = '';
    this.peerId = '';
    this.safetyCode = '';
    this.exitIp = '';

    this.ws = null;
    this.session = null;
    this._reconnectTimer = null;
    this._statsTimer = null;
    this._manualDisconnect = false;

    this.totalBytesTx = 0;
    this.totalBytesRx = 0;
    this._windowTx = 0;
    this._windowRx = 0;
    this.txBps = 0;
    this.rxBps = 0;
    this.speedHistory = []; // last 30 samples of { ts, rxBps, txBps }
    this.recentStreams = [];
    this.logs = [];
  }

  _log(level, message) {
    const entry = { ts: Date.now(), level, message };
    this.logs.push(entry);
    if (this.logs.length > 120) this.logs.shift();
    this.emit('log', entry);
  }

  async connect(options) {
    let cfg = { ...options };
    if (cfg.inviteUri) {
      const parsed = parseInviteUri(cfg.inviteUri);
      cfg = {
        ...parsed,
        ...cfg,
        roomCode: cfg.roomCode || parsed.roomCode,
        secret: cfg.secret || parsed.secret,
        relayUrl: cfg.relayUrl ?? parsed.relayUrl,
        directEndpoints: cfg.directEndpoints?.length ? cfg.directEndpoints : parsed.directEndpoints,
      };
    }

    if (!cfg.roomCode || !cfg.secret) {
      throw new Error('roomCode and secret (or inviteUri) are required');
    }

    this.disconnect('Reconfiguring connection');
    this._manualDisconnect = false;
    this.lastError = '';
    this.config = {
      roomCode: String(cfg.roomCode).trim().toUpperCase(),
      secret: String(cfg.secret),
      relayUrl: cfg.relayUrl ? String(cfg.relayUrl).trim() : '',
      directEndpoints: Array.isArray(cfg.directEndpoints) ? cfg.directEndpoints.filter(Boolean) : [],
      mode: cfg.mode || 'hybrid', // 'hybrid' | 'direct' | 'relay'
      autoReconnect: cfg.autoReconnect !== false,
    };

    this._startStatsTimer();
    return this._establishTunnel();
  }

  _startStatsTimer() {
    if (this._statsTimer) return;
    this._statsTimer = setInterval(() => {
      this.txBps = this._windowTx;
      this.rxBps = this._windowRx;
      this._windowTx = 0;
      this._windowRx = 0;
      this.speedHistory.push({ ts: Date.now(), rxBps: this.rxBps, txBps: this.txBps });
      if (this.speedHistory.length > 36) this.speedHistory.shift();
      this.emit('state', this.getState());
    }, 1000);
    this._statsTimer.unref?.();
  }

  async _establishTunnel() {
    if (this._manualDisconnect || !this.config) return null;
    this.status = 'connecting';
    this.emit('state', this.getState());

    const { mode, directEndpoints, relayUrl } = this.config;

    try {
      let chosen = null;

      if (mode === 'direct') {
        if (!directEndpoints.length) throw new Error('No direct endpoints provided for Direct mode');
        chosen = await this._tryAnyDirect(directEndpoints, 4000);
        if (!chosen) throw new Error('Could not reach any Direct endpoint');
      } else if (mode === 'relay') {
        if (!relayUrl) throw new Error('No Relay URL provided for Relay mode');
        chosen = await this._connectViaRelay(relayUrl, { tryDiscoveredDirect: false });
      } else {
        // Hybrid mode:
        // 1. If we already have direct endpoints, try them quickly first (1400ms).
        if (directEndpoints.length > 0) {
          chosen = await this._tryAnyDirect(directEndpoints, 1400);
        }
        // 2. Otherwise use Relay (which can also discover direct hints from Sharer!)
        if (!chosen) {
          if (!relayUrl) {
            throw new Error('Direct endpoints unreachable and no Relay URL configured');
          }
          chosen = await this._connectViaRelay(relayUrl, { tryDiscoveredDirect: true });
        }
      }

      this.ws = chosen.ws;
      this.activeTransport = chosen.transport;
      this.activeEndpoint = chosen.endpoint;
      this.peerId = chosen.peerId;
      this.peerName = chosen.peerName;
      this.safetyCode = chosen.cipher.safetyCode;

      const session = new MuxSession({
        role: 'client',
        cipher: chosen.cipher,
        sendRaw: (pkt) => this.ws?.send(pkt, true) ?? false,
        closeRaw: () => this.ws?.close(1000, 'Client closed'),
      });

      session.on('traffic', ({ tx, rx }) => {
        this.totalBytesTx += tx;
        this.totalBytesRx += rx;
        this._windowTx += tx;
        this._windowRx += rx;
      });
      session.on('rtt', () => this.emit('state', this.getState()));
      session.on('kicked', (reason) => {
        this._log('warn', `Kicked by exit node: ${reason}`);
        this.lastError = reason;
        this._manualDisconnect = true;
      });

      this.ws.on('message', (data, isBinary) => {
        if (!isBinary) {
          try {
            const msg = JSON.parse(data);
            if (msg.type === 'sharer_offline') {
              this._log('warn', 'Remote sharer went offline');
              session.close('Sharer went offline');
            }
          } catch {
            // ignore
          }
          return;
        }
        session.handleIncomingPacket(data);
      });

      this.ws.on('drain', () => session.notifyTransportDrain());
      const onDrop = (why) => {
        if (this.session === session) {
          this.session = null;
          this.ws = null;
          if (!session.closed) session.close(why);
          if (!this._manualDisconnect && this.config?.autoReconnect) {
            this.status = 'reconnecting';
            this._log('warn', `Tunnel disconnected (${why}); reconnecting in 3s...`);
            this._scheduleReconnect();
          } else {
            this.status = this.lastError ? 'error' : 'disconnected';
          }
          this.emit('state', this.getState());
        }
      };

      this.ws.on('close', () => onDrop('Connection closed'));
      this.ws.on('error', (err) => onDrop(err.message));

      this.session = session;
      this.status = 'connected';
      this._log(
        'info',
        `Connected to "${this.peerName}" via ${this.activeTransport.toUpperCase()} (${this.activeEndpoint}) [Safety ${this.safetyCode}]`
      );
      this.emit('state', this.getState());

      // Perform immediate ping & exit IP query in background
      session.sendPing();
      this.checkExitIp().catch(() => {});

      return this.getState();
    } catch (err) {
      this.status = 'error';
      this.lastError = err.message;
      this._log('error', `Connection failed: ${err.message}`);
      this.emit('state', this.getState());
      throw err;
    }
  }

  async _tryAnyDirect(endpoints, timeoutMs) {
    if (!endpoints || endpoints.length === 0) return null;
    let won = false;
    try {
      const winner = await Promise.any(
        endpoints.map(async (ep) => {
          const conn = await this._connectViaDirect(ep, timeoutMs);
          if (won) {
            conn.ws.destroy();
            throw new Error('Another endpoint already won');
          }
          won = true;
          return conn;
        })
      );
      return winner;
    } catch {
      return null;
    }
  }

  async _connectViaDirect(endpoint, timeoutMs = 2000) {
    const ws = await connectWs(endpoint, { timeoutMs });
    try {
      const { cipher, peerId, peerName } = await this._performDirectHandshake(ws, timeoutMs);
      return { ws, transport: 'direct', endpoint, cipher, peerId, peerName };
    } catch (err) {
      ws.destroy();
      throw err;
    }
  }

  _performDirectHandshake(ws, timeoutMs = 6000) {
    const hs = new ClientHandshake({
      roomCode: this.config.roomCode,
      secret: this.config.secret,
      deviceId: this.deviceId,
      deviceName: this.deviceName,
    });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.removeListener('message', onMsg);
        reject(new Error('E2EE handshake timeout'));
      }, timeoutMs);

      const onMsg = (data, isBinary) => {
        if (!isBinary) return;
        clearTimeout(timer);
        ws.removeListener('message', onMsg);
        try {
          resolve(hs.processServerHello(data));
        } catch (err) {
          reject(err);
        }
      };

      ws.on('message', onMsg);
      ws.once('close', () => {
        clearTimeout(timer);
        reject(new Error('Direct connection closed during handshake'));
      });
      ws.send(hs.createHello(), true);
    });
  }

  async _connectViaRelay(relayUrl, { tryDiscoveredDirect = false } = {}) {
    const ws = await connectWs(relayUrl, { timeoutMs: 8000 });
    const roomHash = deriveRelayRoomHash(this.config.roomCode);

    // Keep an error guard attached while negotiating join/sharer_online so async socket errors never crash
    let relayErr = null;
    const onEarlyError = (err) => {
      relayErr = err;
    };
    ws.on('error', onEarlyError);

    try {
      const joinInfo = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Relay join timeout')), 7000);
        const onMsg = (data, isBinary) => {
          if (isBinary) return;
          let msg;
          try {
            msg = JSON.parse(data);
          } catch {
            return;
          }
          if (msg.type === 'room_joined') {
            clearTimeout(timer);
            ws.removeListener('message', onMsg);
            resolve(msg);
          } else if (msg.type === 'error') {
            clearTimeout(timer);
            ws.removeListener('message', onMsg);
            reject(new Error(msg.message || 'Relay join failed'));
          }
        };
        ws.on('message', onMsg);
        ws.once('close', () => {
          clearTimeout(timer);
          reject(relayErr || new Error('Relay closed while joining room'));
        });
        ws.sendJson({ type: 'join_room', roomHash });
      });

      // Wait briefly for sharer to come online if not online yet
      let directHints = joinInfo.directHints || [];
      if (!joinInfo.sharerOnline) {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            ws.removeListener('message', onOnline);
            reject(new Error('Sharer is not currently online in this room'));
          }, 5000);
          const onOnline = (data, isBinary) => {
            if (isBinary) return;
            try {
              const msg = JSON.parse(data);
              if (msg.type === 'sharer_online') {
                clearTimeout(timer);
                ws.removeListener('message', onOnline);
                if (Array.isArray(msg.directHints)) directHints = msg.directHints;
                resolve();
              }
            } catch {
              // ignore
            }
          };
          ws.on('message', onOnline);
        });
      }

      // In hybrid mode, if relay shared directHints we haven't tried yet, race direct quickly!
      if (tryDiscoveredDirect && directHints.length > 0) {
        const directResult = await this._tryAnyDirect(directHints, 1200);
        if (directResult) {
          ws.removeListener('error', onEarlyError);
          ws.on('error', () => {});
          ws.close(1000, 'Upgraded to direct P2P');
          return directResult;
        }
      }

      const { cipher, peerId, peerName } = await this._performDirectHandshake(ws, 8000);
      ws.removeListener('error', onEarlyError);
      return { ws, transport: 'relay', endpoint: relayUrl, cipher, peerId, peerName };
    } catch (err) {
      ws.removeListener('error', onEarlyError);
      ws.destroy();
      throw err;
    }
  }

  _scheduleReconnect() {
    if (this._reconnectTimer || this._manualDisconnect) return;
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      if (!this._manualDisconnect) {
        this._establishTunnel().catch(() => {
          if (!this._manualDisconnect && this.config?.autoReconnect) {
            this._scheduleReconnect();
          }
        });
      }
    }, 3000);
    this._reconnectTimer.unref?.();
  }

  async openTunnelStream(host, port) {
    if (!this.session || this.session.closed) {
      throw new Error('Tunnel is not connected');
    }
    this.recentStreams.unshift({ host: `${host}:${port}`, ts: Date.now() });
    if (this.recentStreams.length > 30) this.recentStreams.length = 30;
    return this.session.openStream(host, port);
  }

  async checkExitIp() {
    if (!this.session || this.session.closed) return null;
    try {
      const res = await this.session.requestMeta({ op: 'check_ip' }, 8000);
      if (res?.exitIp) {
        this.exitIp = res.exitIp;
        this.emit('state', this.getState());
      }
      return this.exitIp;
    } catch {
      return null;
    }
  }

  disconnect(reason = 'Disconnected by user') {
    this._manualDisconnect = true;
    clearTimeout(this._reconnectTimer);
    this._reconnectTimer = null;
    if (this.session) {
      this.session.close(reason);
      this.session = null;
    }
    if (this.ws) {
      this.ws.close(1000, reason);
      this.ws = null;
    }
    if (reason === 'Disconnected by user') {
      clearInterval(this._statsTimer);
      this._statsTimer = null;
      this.status = 'disconnected';
      this.activeTransport = null;
      this.activeEndpoint = '';
      this.peerName = '';
      this.safetyCode = '';
      this.exitIp = '';
      this.txBps = 0;
      this.rxBps = 0;
      this._log('info', 'Tunnel disconnected');
      this.emit('state', this.getState());
    }
  }

  getState() {
    return {
      status: this.status,
      lastError: this.lastError,
      mode: this.config?.mode || 'hybrid',
      roomCode: this.config?.roomCode || '',
      relayUrl: this.config?.relayUrl || '',
      activeTransport: this.activeTransport,
      activeEndpoint: this.activeEndpoint,
      peerId: this.peerId,
      peerName: this.peerName,
      safetyCode: this.safetyCode,
      exitIp: this.exitIp,
      rttMs: this.session?.rttMs ?? null,
      activeStreams: this.session?.activeStreamCount || 0,
      txBps: this.txBps,
      rxBps: this.rxBps,
      totalBytesTx: this.totalBytesTx,
      totalBytesRx: this.totalBytesRx,
      speedHistory: this.speedHistory.slice(),
      recentStreams: this.recentStreams.slice(0, 12),
    };
  }
}
