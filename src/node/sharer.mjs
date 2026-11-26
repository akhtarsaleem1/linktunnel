import crypto from 'node:crypto';
import EventEmitter from 'node:events';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import {
  SharerHandshake,
  createInviteUri,
  deriveRelayRoomHash,
  generateRoomCode,
  generateSecret,
} from '../crypto/e2ee.mjs';
import { ERR_CODE, MuxSession } from '../protocol/mux.mjs';
import { acceptWsUpgrade, connectWs } from '../protocol/ws.mjs';
import { wrapRelayPacket, unwrapRelayPacket } from '../relay/server.mjs';
import { getLocalLanIps, resolveAndValidateTarget } from './network-guard.mjs';

function fetchExternalIp(timeoutMs = 5000) {
  return new Promise((resolve) => {
    const req = https.get('https://api.ipify.org?format=json', { timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve(parsed.ip || null);
        } catch {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
  });
}

/**
 * Sharer / Exit Node: shares this machine's internet connection over E2EE Relay and/or Direct WebSocket.
 */
export class SharerNode extends EventEmitter {
  constructor({
    deviceId,
    deviceName = 'Exit-Node',
    roomCode = null,
    secret = null,
    relayUrl = '',
    enableDirect = true,
    directHost = '0.0.0.0',
    directPort = 4322,
    publicDirectHost = '',
    blockPrivateNetwork = true,
    maxBandwidthBps = 0,
    maxQuotaBytes = 0,
    maxPeers = 5,
    maxStreamsPerPeer = 128,
    blockedDomains = [],
    allowedDomains = [],
  } = {}) {
    super();
    this.deviceId = deviceId || crypto.randomBytes(16).toString('hex');
    this.deviceName = deviceName;
    this.roomCode = roomCode ? String(roomCode).trim().toUpperCase() : generateRoomCode();
    this.secret = secret || generateSecret();
    this.relayUrl = relayUrl ? String(relayUrl).trim() : '';
    this.enableDirect = enableDirect;
    this.directHost = directHost;
    this.directPort = directPort;
    this.publicDirectHost = publicDirectHost;

    this.policy = {
      blockPrivateNetwork,
      maxBandwidthBps,
      maxQuotaBytes,
      maxPeers,
      maxStreamsPerPeer,
      blockedDomains,
      allowedDomains,
    };

    this.sharerToken = crypto.randomBytes(24).toString('hex');
    this.running = false;
    this.paused = false;
    this.observedPublicIp = '';
    this.directServer = null;
    this.relayWs = null;
    this.relayConnected = false;
    this._relayReconnectTimer = null;
    this._statsTimer = null;

    this.peers = new Map(); // key -> { key, source, sessionId?, ws?, handshakeDone, peerId, peerName, safetyCode, session, connectedAt, recentHosts }
    this.totalBytesTx = 0;
    this.totalBytesRx = 0;
    this._windowTx = 0;
    this._windowRx = 0;
    this.txBps = 0;
    this.rxBps = 0;
    this.logs = [];
  }

  _log(level, message) {
    const entry = { ts: Date.now(), level, message };
    this.logs.push(entry);
    if (this.logs.length > 120) this.logs.shift();
    this.emit('log', entry);
  }

  getDirectEndpoints() {
    if (!this.enableDirect || !this.directServer) return [];
    const hints = [];
    if (this.publicDirectHost) {
      hints.push(`ws://${this.publicDirectHost}:${this.directPort}/tunnel`);
    } else if (this.observedPublicIp && !this.observedPublicIp.includes(':')) {
      hints.push(`ws://${this.observedPublicIp}:${this.directPort}/tunnel`);
    }
    for (const lan of getLocalLanIps()) {
      hints.push(`ws://${lan.address}:${this.directPort}/tunnel`);
    }
    return Array.from(new Set(hints));
  }

  getInviteUri() {
    return createInviteUri({
      roomCode: this.roomCode,
      secret: this.secret,
      relayUrl: this.relayUrl,
      directEndpoints: this.getDirectEndpoints(),
      name: this.deviceName,
    });
  }

  async start() {
    if (this.running) return this.getState();
    this.running = true;

    if (this.enableDirect) {
      await this._startDirectListener();
    }
    if (this.relayUrl) {
      await this._connectRelay().catch((err) => {
        this._log('warn', `Initial relay connect failed (${err.message}); retrying in background`);
        this._scheduleRelayReconnect();
      });
    }

    this._statsTimer = setInterval(() => {
      this.txBps = this._windowTx;
      this.rxBps = this._windowRx;
      this._windowTx = 0;
      this._windowRx = 0;
      this.emit('state', this.getState());
    }, 1000);
    this._statsTimer.unref?.();

    this._log('info', `Sharing started (Room ${this.roomCode})`);
    this.emit('state', this.getState());
    return this.getState();
  }

  async _startDirectListener() {
    this.directServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ service: 'LinkTunnel Direct Exit Endpoint', roomCode: this.roomCode }));
    });

    this.directServer.on('upgrade', (req, socket, head) => {
      const ws = acceptWsUpgrade(req, socket, head);
      if (!ws) return;
      this._handleDirectPeer(ws);
    });

    await new Promise((resolve, reject) => {
      this.directServer.once('error', reject);
      this.directServer.listen(this.directPort, this.directHost, () => {
        this.directServer.removeListener('error', reject);
        const addr = this.directServer.address();
        if (typeof addr === 'object' && addr) this.directPort = addr.port;
        this._log('info', `Direct listener active on ${this.directHost}:${this.directPort}`);
        resolve();
      });
    });
  }

  _handleDirectPeer(ws) {
    if (this.peers.size >= this.policy.maxPeers) {
      ws.close(4002, 'Max peer limit reached');
      return;
    }
    const peerKey = `direct:${crypto.randomBytes(6).toString('hex')}`;
    const entry = {
      key: peerKey,
      source: 'direct',
      ws,
      handshakeDone: false,
      peerId: '',
      peerName: 'Connecting...',
      safetyCode: '',
      session: null,
      connectedAt: Date.now(),
      remoteAddr: ws.remoteAddress,
      recentHosts: [],
    };
    this.peers.set(peerKey, entry);

    ws.on('message', (data, isBinary) => {
      if (!isBinary) return;
      if (!entry.handshakeDone) {
        this._completePeerHandshake(entry, data, (resp) => ws.send(resp, true), () => ws.close(4003, 'Auth failed'));
        return;
      }
      entry.session?.handleIncomingPacket(data);
    });

    ws.on('drain', () => entry.session?.notifyTransportDrain());
    ws.on('close', () => this._removePeer(peerKey));
    ws.on('error', () => this._removePeer(peerKey));
  }

  async _connectRelay() {
    if (!this.running || !this.relayUrl) return;
    const roomHash = deriveRelayRoomHash(this.roomCode);
    const ws = await connectWs(this.relayUrl, { timeoutMs: 8000 });
    this.relayWs = ws;

    await new Promise((resolve, reject) => {
      let settled = false;
      const keepAliveTimer = setInterval(() => {
        if (!ws.closed) ws.ping();
      }, 25000);
      keepAliveTimer.unref?.();
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(new Error('Relay registration timeout'));
        }
      }, 6000);

      const onMsg = (data, isBinary) => {
        if (!isBinary) {
          let msg;
          try {
            msg = JSON.parse(data);
          } catch {
            return;
          }
          if (msg.type === 'sharer_registered') {
            clearTimeout(timer);
            this.relayConnected = true;
            if (msg.observedIp && !this.observedPublicIp) {
              this.observedPublicIp = msg.observedIp;
              // Refresh direct hints now that relay told us our external IP
              ws.sendJson({ type: 'update_hints', directHints: this.getDirectEndpoints() });
            }
            this._log('info', `Registered on relay ${this.relayUrl}`);
            this.emit('state', this.getState());
            if (!settled) {
              settled = true;
              resolve();
            }
          } else if (msg.type === 'error') {
            clearTimeout(timer);
            if (!settled) {
              settled = true;
              reject(new Error(msg.message || 'Relay registration error'));
            }
          } else if (msg.type === 'client_joined') {
            this._onRelayClientJoined(msg.sessionId);
          } else if (msg.type === 'client_left') {
            this._removePeer(`relay:${msg.sessionId}`);
          }
          return;
        }

        // Binary packet from relay: [sessionId:4][e2eePayload]
        let sessionId, payload;
        try {
          ({ sessionId, payload } = unwrapRelayPacket(data));
        } catch {
          return;
        }
        const peerKey = `relay:${sessionId}`;
        const entry = this.peers.get(peerKey);
        if (!entry) return;
        if (!entry.handshakeDone) {
          this._completePeerHandshake(
            entry,
            payload,
            (resp) => ws.send(wrapRelayPacket(sessionId, resp), true),
            () => ws.sendJson({ type: 'kick_session', sessionId, reason: 'Auth failed' })
          );
          return;
        }
        entry.session?.handleIncomingPacket(payload);
      };

      ws.on('message', onMsg);
      ws.on('drain', () => {
        for (const entry of this.peers.values()) {
          if (entry.source === 'relay') entry.session?.notifyTransportDrain();
        }
      });
      ws.on('close', () => {
        clearInterval(keepAliveTimer);
        clearTimeout(timer);
        if (this.relayWs === ws) {
          this.relayConnected = false;
          this.relayWs = null;
          for (const key of Array.from(this.peers.keys())) {
            if (key.startsWith('relay:')) this._removePeer(key);
          }
          if (this.running) {
            this._log('warn', 'Relay connection lost; scheduling reconnect');
            this._scheduleRelayReconnect();
          }
          this.emit('state', this.getState());
        }
        if (!settled) {
          settled = true;
          reject(new Error('Relay connection closed before registration'));
        }
      });
      ws.on('error', (err) => {
        clearTimeout(timer);
        if (!settled) {
          settled = true;
          reject(err);
        } else {
          this._log('warn', `Relay socket error: ${err.message}`);
        }
      });

      ws.sendJson({
        type: 'register_sharer',
        roomHash,
        sharerToken: this.sharerToken,
        directHints: this.getDirectEndpoints(),
        deviceName: this.deviceName,
      });
    });
  }

  _scheduleRelayReconnect() {
    if (!this.running || !this.relayUrl || this._relayReconnectTimer) return;
    this._relayReconnectTimer = setTimeout(() => {
      this._relayReconnectTimer = null;
      if (!this.running) return;
      this._connectRelay().catch((err) => {
        this._log('warn', `Relay reconnect failed: ${err.message}`);
        this._scheduleRelayReconnect();
      });
    }, 3000);
    this._relayReconnectTimer.unref?.();
  }

  _onRelayClientJoined(sessionId) {
    const peerKey = `relay:${sessionId}`;
    if (this.peers.size >= this.policy.maxPeers) {
      this.relayWs?.sendJson({ type: 'kick_session', sessionId, reason: 'Max peer limit reached' });
      return;
    }
    this.peers.set(peerKey, {
      key: peerKey,
      source: 'relay',
      sessionId,
      handshakeDone: false,
      peerId: '',
      peerName: 'Connecting...',
      safetyCode: '',
      session: null,
      connectedAt: Date.now(),
      remoteAddr: 'via-relay',
      recentHosts: [],
    });
  }

  _completePeerHandshake(entry, clientHelloBuf, sendRawFn, rejectFn) {
    try {
      const hs = new SharerHandshake({
        roomCode: this.roomCode,
        secret: this.secret,
        deviceId: this.deviceId,
        deviceName: this.deviceName,
      });
      const { response, peerId, peerName, cipher } = hs.processClientHello(clientHelloBuf);

      entry.handshakeDone = true;
      entry.peerId = peerId;
      entry.peerName = peerName;
      entry.safetyCode = cipher.safetyCode;

      const session = new MuxSession({
        role: 'sharer',
        cipher,
        sendRaw: (pkt) => {
          if (entry.source === 'relay') {
            if (!this.relayWs) return false;
            return this.relayWs.send(wrapRelayPacket(entry.sessionId, pkt), true);
          }
          return entry.ws?.send(pkt, true) ?? false;
        },
        closeRaw: () => {
          if (entry.source === 'relay') {
            this.relayWs?.sendJson({ type: 'kick_session', sessionId: entry.sessionId, reason: 'Closed' });
          } else {
            entry.ws?.close(1000, 'Closed');
          }
        },
        onOpenStream: (muxStream, target) => this._handleOutboundStream(entry, muxStream, target),
        onMetaRequest: (query) => this._handleMetaRequest(entry, query),
        maxBandwidthBps: this.policy.maxBandwidthBps,
        maxQuotaBytes: this.policy.maxQuotaBytes,
        maxStreams: this.policy.maxStreamsPerPeer,
      });

      session.on('traffic', ({ tx, rx }) => {
        this.totalBytesTx += tx;
        this.totalBytesRx += rx;
        this._windowTx += tx;
        this._windowRx += rx;
      });

      session.on('close', () => {
        this._removePeer(entry.key);
      });

      entry.session = session;
      sendRawFn(response);
      this._log('info', `Peer "${peerName}" authenticated via ${entry.source} (Safety ${cipher.safetyCode})`);
      this.emit('state', this.getState());
    } catch (err) {
      this._log('warn', `Rejected peer (${entry.key}): ${err.message}`);
      this._removePeer(entry.key);
      rejectFn();
    }
  }

  async _handleOutboundStream(entry, muxStream, { host, port }) {
    if (this.paused) {
      const err = new Error('Sharing is currently paused by exit node');
      err.errCode = ERR_CODE.BLOCKED;
      throw err;
    }

    let resolved;
    try {
      resolved = await resolveAndValidateTarget(host, port, this.policy);
    } catch (err) {
      const wrapped = new Error(err.message);
      wrapped.errCode = err.code === 'EBLOCKED' ? ERR_CODE.BLOCKED : ERR_CODE.UNREACHABLE;
      throw wrapped;
    }

    entry.recentHosts.unshift({ host: `${host}:${port}`, ts: Date.now() });
    if (entry.recentHosts.length > 20) entry.recentHosts.length = 20;

    return new Promise((resolve, reject) => {
      const targetSocket = net.connect({
        host: resolved.address,
        port,
        family: resolved.family,
      });

      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          targetSocket.destroy();
          const err = new Error(`Outbound timeout to ${host}:${port}`);
          err.errCode = ERR_CODE.UNREACHABLE;
          reject(err);
        }
      }, 12000);

      targetSocket.once('connect', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        muxStream.pipeSocket(targetSocket);
        resolve({
          boundAddress: targetSocket.localAddress || '0.0.0.0',
          boundPort: targetSocket.localPort || 0,
        });
      });

      targetSocket.once('error', (err) => {
        clearTimeout(timer);
        if (!settled) {
          settled = true;
          const wrapped = new Error(err.message);
          wrapped.errCode = err.code === 'ECONNREFUSED' ? ERR_CODE.REFUSED : ERR_CODE.UNREACHABLE;
          reject(wrapped);
        }
      });
    });
  }

  async _handleMetaRequest(entry, query) {
    if (query?.op === 'check_ip') {
      const ip = await fetchExternalIp();
      if (ip) this.observedPublicIp = ip;
      return {
        ok: true,
        exitIp: ip || this.observedPublicIp || 'Unknown',
        deviceName: this.deviceName,
        paused: this.paused,
      };
    }
    return {
      ok: true,
      deviceName: this.deviceName,
      paused: this.paused,
      policy: {
        maxBandwidthBps: this.policy.maxBandwidthBps,
        maxQuotaBytes: this.policy.maxQuotaBytes,
        blockPrivateNetwork: this.policy.blockPrivateNetwork,
      },
    };
  }

  _removePeer(peerKey) {
    const entry = this.peers.get(peerKey);
    if (!entry) return;
    this.peers.delete(peerKey);
    if (entry.session && !entry.session.closed) {
      entry.session.close('Peer removed');
    }
    if (entry.ws && !entry.ws.closed) {
      entry.ws.destroy();
    }
    if (entry.handshakeDone) {
      this._log('info', `Peer "${entry.peerName}" disconnected`);
    }
    this.emit('state', this.getState());
  }

  kickPeer(peerKey, reason = 'Disconnected by exit node owner') {
    const entry = this.peers.get(peerKey);
    if (!entry) return false;
    if (entry.session) {
      entry.session.kick(reason);
    } else {
      this._removePeer(peerKey);
    }
    return true;
  }

  setPaused(paused) {
    this.paused = Boolean(paused);
    this._log('info', this.paused ? 'Internet sharing paused' : 'Internet sharing resumed');
    this.emit('state', this.getState());
  }

  updatePolicy(partial = {}) {
    Object.assign(this.policy, partial);
    for (const entry of this.peers.values()) {
      if (entry.session) {
        if ('maxBandwidthBps' in partial) entry.session.setBandwidthLimit(this.policy.maxBandwidthBps);
        if ('maxQuotaBytes' in partial) entry.session.setQuotaLimit(this.policy.maxQuotaBytes);
      }
    }
    this._log('info', 'Sharer policy updated');
    this.emit('state', this.getState());
  }

  getState() {
    return {
      running: this.running,
      paused: this.paused,
      deviceName: this.deviceName,
      roomCode: this.roomCode,
      secret: this.secret,
      relayUrl: this.relayUrl,
      relayConnected: this.relayConnected,
      enableDirect: this.enableDirect,
      directPort: this.enableDirect ? this.directPort : null,
      directEndpoints: this.getDirectEndpoints(),
      inviteUri: this.running ? this.getInviteUri() : '',
      observedPublicIp: this.observedPublicIp,
      policy: { ...this.policy },
      txBps: this.txBps,
      rxBps: this.rxBps,
      totalBytesTx: this.totalBytesTx,
      totalBytesRx: this.totalBytesRx,
      peers: Array.from(this.peers.values()).map((p) => ({
        key: p.key,
        source: p.source,
        peerId: p.peerId,
        peerName: p.peerName,
        safetyCode: p.safetyCode,
        remoteAddr: p.remoteAddr,
        connectedAt: p.connectedAt,
        activeStreams: p.session?.activeStreamCount || 0,
        bytesTx: p.session?.bytesTx || 0,
        bytesRx: p.session?.bytesRx || 0,
        rttMs: p.session?.rttMs ?? null,
        recentHosts: p.recentHosts.slice(0, 6),
      })),
    };
  }

  async stop() {
    if (!this.running) return;
    this.running = false;
    clearInterval(this._statsTimer);
    clearTimeout(this._relayReconnectTimer);
    this._relayReconnectTimer = null;

    for (const key of Array.from(this.peers.keys())) {
      this._removePeer(key);
    }
    if (this.relayWs) {
      this.relayWs.close(1000, 'Sharer stopped');
      this.relayWs = null;
      this.relayConnected = false;
    }
    if (this.directServer) {
      await new Promise((resolve) => this.directServer.close(() => resolve()));
      this.directServer = null;
    }
    this._log('info', 'Internet sharing stopped');
    this.emit('state', this.getState());
  }
}
