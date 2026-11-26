import EventEmitter from 'node:events';

export const FRAME_TYPE = {
  OPEN: 0x01,
  OPEN_OK: 0x02,
  OPEN_ERR: 0x03,
  DATA: 0x04,
  FIN: 0x05,
  RST: 0x06,
  CREDIT: 0x07,
  PING: 0x10,
  PONG: 0x11,
  META_REQ: 0x12,
  META_RES: 0x13,
  KICK: 0x14,
};

export const ERR_CODE = {
  GENERAL: 0x01,
  BLOCKED: 0x02,
  UNREACHABLE: 0x03,
  REFUSED: 0x04,
  QUOTA_EXCEEDED: 0x05,
  LIMIT_EXCEEDED: 0x06,
};

export const INITIAL_STREAM_WINDOW = 512 * 1024; // 512 KB per stream
export const MAX_DATA_CHUNK = 32 * 1024; // 32 KB per encrypted frame

/**
 * Simple asynchronous token bucket rate limiter (bytes/sec).
 */
export class TokenBucket {
  constructor(bytesPerSecond = 0) {
    this.setRate(bytesPerSecond);
    this.tokens = this.capacity;
    this.lastRefill = Date.now();
  }

  setRate(bytesPerSecond) {
    this.rate = Math.max(0, Number(bytesPerSecond) || 0);
    this.capacity = this.rate > 0 ? Math.max(64 * 1024, Math.floor(this.rate * 0.5)) : Infinity;
    this.tokens = Math.min(this.tokens ?? this.capacity, this.capacity);
  }

  consumeWaitMs(bytes) {
    if (this.rate <= 0 || !Number.isFinite(this.rate)) return 0;
    const now = Date.now();
    const elapsedSec = Math.max(0, (now - this.lastRefill) / 1000);
    this.tokens = Math.min(this.capacity, this.tokens + elapsedSec * this.rate);
    this.lastRefill = now;

    if (this.tokens >= bytes) {
      this.tokens -= bytes;
      return 0;
    }
    const deficit = bytes - this.tokens;
    this.tokens -= bytes; // allow going slightly negative to keep FIFO smoothness
    return Math.ceil((deficit / this.rate) * 1000);
  }
}

export function encodeMuxFrame(type, streamId, payload = Buffer.alloc(0)) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const out = Buffer.allocUnsafe(5 + body.length);
  out[0] = type;
  out.writeUInt32BE(streamId >>> 0, 1);
  if (body.length > 0) body.copy(out, 5);
  return out;
}

export function decodeMuxFrame(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 5) {
    throw new Error('Mux frame too short');
  }
  return {
    type: buf[0],
    streamId: buf.readUInt32BE(1),
    payload: buf.subarray(5),
  };
}

/**
 * Virtual multiplexed stream over an E2EE tunnel session.
 */
export class MuxStream extends EventEmitter {
  constructor(session, id, { host = '', port = 0 } = {}) {
    super();
    this.session = session;
    this.id = id;
    this.host = host;
    this.port = port;
    this.sendWindow = INITIAL_STREAM_WINDOW;
    this.unackedRecv = 0;
    this.localClosed = false;
    this.remoteClosed = false;
    this.destroyed = false;
    this.bytesUp = 0;
    this.bytesDown = 0;
    this._drainWaiters = [];
    this._inboundAttached = false;
    this._inboundQueue = [];
    this._flushScheduled = false;

    this.on('newListener', (event) => {
      if (!this._inboundAttached && (event === 'data' || event === 'fin' || event === 'rst')) {
        if (!this._flushScheduled) {
          this._flushScheduled = true;
          queueMicrotask(() => {
            this._inboundAttached = true;
            this._flushInbound();
          });
        }
      }
    });
  }

  _deliverInbound(type, arg) {
    if (!this._inboundAttached) {
      this._inboundQueue.push([type, arg]);
      return;
    }
    if (type === 'data') this.emit('data', arg);
    else if (type === 'fin') this.emit('fin');
    else if (type === 'rst') this.emit('rst', arg);
  }

  _flushInbound() {
    while (this._inboundQueue.length > 0 && !this.destroyed) {
      const [type, arg] = this._inboundQueue.shift();
      if (type === 'data') this.emit('data', arg);
      else if (type === 'fin') this.emit('fin');
      else if (type === 'rst') this.emit('rst', arg);
    }
  }

  /**
   * Binds a local net.Socket directly to this MuxStream with bidirectional backpressure.
   */
  pipeSocket(socket) {
    this.socket = socket;
    socket.setNoDelay(true);

    let writingFromTunnel = false;
    let pendingSendTimer = null;

    const flushPauseState = () => {
      if (this.destroyed || this.localClosed || socket.destroyed) return;
      if (this.sendWindow <= 0 || this.session.backpressured) {
        socket.pause();
      } else {
        socket.resume();
      }
    };

    this._onWindowUpdate = flushPauseState;
    this._onSessionDrain = flushPauseState;

    socket.on('data', (chunk) => {
      if (this.destroyed || this.localClosed) return;
      this.session.sendStreamData(this, chunk);
      flushPauseState();
    });

    socket.on('end', () => {
      if (!this.destroyed && !this.localClosed) {
        this.localClosed = true;
        this.session.sendMuxControl(FRAME_TYPE.FIN, this.id);
        this._checkBothClosed();
      }
    });

    socket.on('error', () => {
      this.reset('socket error');
    });

    socket.on('close', () => {
      clearTimeout(pendingSendTimer);
      if (!this.destroyed && !this.remoteClosed && !this.localClosed) {
        this.reset('socket closed');
      } else {
        this.cleanup();
      }
    });

    this.on('data', (chunk) => {
      if (this.destroyed || socket.destroyed) return;
      const ok = socket.write(chunk);
      if (!ok) {
        writingFromTunnel = true;
        this.unackedRecv += chunk.length;
      } else {
        this._ackRecv(chunk.length);
      }
    });

    socket.on('drain', () => {
      if (writingFromTunnel) {
        writingFromTunnel = false;
        this._flushAck();
      }
    });

    this.on('fin', () => {
      if (!socket.destroyed && !socket.writableEnded) {
        socket.end();
      }
      this._checkBothClosed();
    });

    this.on('rst', () => {
      if (!socket.destroyed) socket.destroy();
      this.cleanup();
    });

    this._inboundAttached = true;
    this._flushInbound();
  }

  _ackRecv(bytes) {
    this.unackedRecv += bytes;
    if (this.unackedRecv >= INITIAL_STREAM_WINDOW / 4) {
      this._flushAck();
    }
  }

  _flushAck() {
    if (this.unackedRecv <= 0 || this.destroyed || this.remoteClosed) return;
    const ack = this.unackedRecv;
    this.unackedRecv = 0;
    const buf = Buffer.allocUnsafe(4);
    buf.writeUInt32BE(ack, 0);
    this.session.sendMuxControl(FRAME_TYPE.CREDIT, this.id, buf);
  }

  _addSendWindow(credits) {
    this.sendWindow += credits;
    if (this._onWindowUpdate) this._onWindowUpdate();
    while (this.sendWindow > 0 && this._drainWaiters.length > 0) {
      const resolve = this._drainWaiters.shift();
      resolve();
    }
  }

  _checkBothClosed() {
    if (this.localClosed && this.remoteClosed) {
      this.cleanup();
    }
  }

  reset(reason = '') {
    if (this.destroyed) return;
    this.destroyed = true;
    this.session.sendMuxControl(FRAME_TYPE.RST, this.id, Buffer.from(reason, 'utf8'));
    if (this.socket && !this.socket.destroyed) {
      this.socket.destroy();
    }
    this.cleanup();
  }

  cleanup() {
    if (this.destroyed && !this.session.streams.has(this.id)) return;
    this.destroyed = true;
    this.session.streams.delete(this.id);
    while (this._drainWaiters.length > 0) {
      const resolve = this._drainWaiters.shift();
      resolve();
    }
    this.emit('close');
  }
}

/**
 * Encrypted Multiplexer Session running on top of any framing transport:
 * `transport` must implement: `send(Buffer)`, `on('frame'|'close'|'error'|'drain')`, `close()`.
 */
export class MuxSession extends EventEmitter {
  constructor({
    role,
    cipher,
    sendRaw,
    closeRaw,
    onOpenStream = null,
    onMetaRequest = null,
    maxBandwidthBps = 0,
    maxQuotaBytes = 0,
    maxStreams = 256,
    pingIntervalMs = 5000,
  }) {
    super();
    this.role = role; // 'client' | 'sharer'
    this.cipher = cipher;
    this._sendRaw = sendRaw;
    this._closeRaw = closeRaw;
    this.onOpenStream = onOpenStream;
    this.onMetaRequest = onMetaRequest;
    this.maxStreams = maxStreams;
    this.maxQuotaBytes = maxQuotaBytes;
    this.rateLimiter = new TokenBucket(maxBandwidthBps);

    this.streams = new Map();
    this.pendingOpens = new Map();
    this.pendingMeta = new Map();
    this.nextStreamId = role === 'client' ? 1 : 2;
    this.nextMetaId = 1;
    this.closed = false;
    this.backpressured = false;

    this.bytesTx = 0;
    this.bytesRx = 0;
    this.rttMs = null;
    this._throttleQueue = [];
    this._throttleTimer = null;

    if (pingIntervalMs > 0) {
      this._pingTimer = setInterval(() => {
        if (!this.closed) this.sendPing();
      }, pingIntervalMs);
      this._pingTimer.unref?.();
    }
  }

  get activeStreamCount() {
    return this.streams.size;
  }

  get totalBytes() {
    return this.bytesTx + this.bytesRx;
  }

  setBandwidthLimit(bps) {
    this.rateLimiter.setRate(bps);
  }

  setQuotaLimit(bytes) {
    this.maxQuotaBytes = Math.max(0, Number(bytes) || 0);
  }

  notifyTransportDrain() {
    this.backpressured = false;
    for (const stream of this.streams.values()) {
      if (stream._onSessionDrain) stream._onSessionDrain();
    }
  }

  /**
   * Handles one incoming E2EE binary packet from the underlying transport.
   */
  handleIncomingPacket(packet) {
    if (this.closed) return;
    let plain;
    try {
      plain = this.cipher.decrypt(packet);
    } catch (err) {
      this.emit('error', new Error(`E2EE decryption failed: ${err.message}`));
      this.close('E2EE integrity error');
      return;
    }

    this.bytesRx += packet.length;
    if (this.maxQuotaBytes > 0 && this.totalBytes > this.maxQuotaBytes) {
      this.kick('Data quota exceeded');
      return;
    }
    this.emit('traffic', { rx: packet.length, tx: 0 });

    const { type, streamId, payload } = decodeMuxFrame(plain);
    this._dispatchFrame(type, streamId, payload);
  }

  _dispatchFrame(type, streamId, payload) {
    switch (type) {
      case FRAME_TYPE.PING: {
        this.sendMuxControl(FRAME_TYPE.PONG, 0, payload);
        break;
      }
      case FRAME_TYPE.PONG: {
        if (payload.length >= 8) {
          const sentAt = payload.readDoubleBE(0);
          this.rttMs = Math.max(0, Math.round(Date.now() - sentAt));
          this.emit('rtt', this.rttMs);
        }
        break;
      }
      case FRAME_TYPE.META_REQ: {
        const reqId = streamId;
        let query = {};
        try {
          query = JSON.parse(payload.toString('utf8') || '{}');
        } catch {
          query = {};
        }
        Promise.resolve(this.onMetaRequest ? this.onMetaRequest(query) : { ok: false })
          .then((res) => {
            if (!this.closed) {
              this.sendMuxControl(FRAME_TYPE.META_RES, reqId, Buffer.from(JSON.stringify(res), 'utf8'));
            }
          })
          .catch((err) => {
            if (!this.closed) {
              this.sendMuxControl(
                FRAME_TYPE.META_RES,
                reqId,
                Buffer.from(JSON.stringify({ ok: false, error: err.message }), 'utf8')
              );
            }
          });
        break;
      }
      case FRAME_TYPE.META_RES: {
        const waiter = this.pendingMeta.get(streamId);
        if (waiter) {
          this.pendingMeta.delete(streamId);
          clearTimeout(waiter.timer);
          try {
            waiter.resolve(JSON.parse(payload.toString('utf8') || '{}'));
          } catch (err) {
            waiter.reject(err);
          }
        }
        break;
      }
      case FRAME_TYPE.KICK: {
        const reason = payload.toString('utf8') || 'Disconnected by peer';
        this.emit('kicked', reason);
        this.close(reason);
        break;
      }
      case FRAME_TYPE.OPEN: {
        if (payload.length < 4) {
          this._sendOpenErr(streamId, ERR_CODE.GENERAL, 'Malformed OPEN frame');
          return;
        }
        const port = payload.readUInt16BE(0);
        const hostLen = payload.readUInt16BE(2);
        const host = payload.subarray(4, 4 + hostLen).toString('utf8');
        if (this.streams.size >= this.maxStreams) {
          this._sendOpenErr(streamId, ERR_CODE.LIMIT_EXCEEDED, 'Max concurrent streams reached');
          return;
        }
        if (!this.onOpenStream) {
          this._sendOpenErr(streamId, ERR_CODE.REFUSED, 'Peer does not accept outbound streams');
          return;
        }
        const stream = new MuxStream(this, streamId, { host, port });
        this.streams.set(streamId, stream);
        Promise.resolve(this.onOpenStream(stream, { host, port }))
          .then((info = {}) => {
            if (this.closed || stream.destroyed) return;
            const ipBuf = Buffer.from(String(info.boundAddress || '0.0.0.0'), 'utf8');
            const okPayload = Buffer.allocUnsafe(1 + ipBuf.length + 2);
            okPayload[0] = ipBuf.length;
            ipBuf.copy(okPayload, 1);
            okPayload.writeUInt16BE(info.boundPort || 0, 1 + ipBuf.length);
            this.sendMuxControl(FRAME_TYPE.OPEN_OK, streamId, okPayload);
          })
          .catch((err) => {
            this.streams.delete(streamId);
            stream.destroyed = true;
            this._sendOpenErr(streamId, err.errCode || ERR_CODE.UNREACHABLE, err.message || 'Connect failed');
          });
        break;
      }
      case FRAME_TYPE.OPEN_OK: {
        const pending = this.pendingOpens.get(streamId);
        if (pending) {
          this.pendingOpens.delete(streamId);
          clearTimeout(pending.timer);
          let boundAddress = '0.0.0.0';
          let boundPort = 0;
          if (payload.length >= 3) {
            const len = payload[0];
            boundAddress = payload.subarray(1, 1 + len).toString('utf8');
            boundPort = payload.readUInt16BE(1 + len);
          }
          pending.resolve({ stream: pending.stream, boundAddress, boundPort });
        }
        break;
      }
      case FRAME_TYPE.OPEN_ERR: {
        const pending = this.pendingOpens.get(streamId);
        const code = payload.length >= 1 ? payload[0] : ERR_CODE.GENERAL;
        const msg = payload.subarray(1).toString('utf8') || 'Stream open failed';
        const stream = this.streams.get(streamId);
        if (stream) {
          this.streams.delete(streamId);
          stream.destroyed = true;
        }
        if (pending) {
          this.pendingOpens.delete(streamId);
          clearTimeout(pending.timer);
          const err = new Error(msg);
          err.errCode = code;
          pending.reject(err);
        }
        break;
      }
      case FRAME_TYPE.DATA: {
        const stream = this.streams.get(streamId);
        if (stream && !stream.destroyed) {
          stream.bytesDown += payload.length;
          stream._deliverInbound('data', payload);
        }
        break;
      }
      case FRAME_TYPE.CREDIT: {
        const stream = this.streams.get(streamId);
        if (stream && !stream.destroyed && payload.length >= 4) {
          const credits = payload.readUInt32BE(0);
          stream._addSendWindow(credits);
        }
        break;
      }
      case FRAME_TYPE.FIN: {
        const stream = this.streams.get(streamId);
        if (stream && !stream.destroyed) {
          stream.remoteClosed = true;
          stream._deliverInbound('fin');
        }
        break;
      }
      case FRAME_TYPE.RST: {
        const stream = this.streams.get(streamId);
        if (stream) {
          stream.remoteClosed = true;
          stream._deliverInbound('rst', payload.toString('utf8'));
          stream.cleanup();
        }
        break;
      }
      default:
        break;
    }
  }

  _sendOpenErr(streamId, code, message) {
    const msgBuf = Buffer.from(String(message).slice(0, 200), 'utf8');
    const out = Buffer.allocUnsafe(1 + msgBuf.length);
    out[0] = code;
    msgBuf.copy(out, 1);
    this.sendMuxControl(FRAME_TYPE.OPEN_ERR, streamId, out);
  }

  openStream(host, port, timeoutMs = 15000) {
    if (this.closed) {
      return Promise.reject(new Error('Tunnel session is closed'));
    }
    if (this.streams.size >= this.maxStreams) {
      return Promise.reject(new Error('Max concurrent streams reached'));
    }

    const streamId = this.nextStreamId;
    this.nextStreamId += 2;
    const stream = new MuxStream(this, streamId, { host, port });
    this.streams.set(streamId, stream);

    const hostBuf = Buffer.from(String(host), 'utf8');
    const payload = Buffer.allocUnsafe(4 + hostBuf.length);
    payload.writeUInt16BE(port, 0);
    payload.writeUInt16BE(hostBuf.length, 2);
    hostBuf.copy(payload, 4);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pendingOpens.has(streamId)) {
          this.pendingOpens.delete(streamId);
          stream.reset('open timeout');
          const err = new Error(`Tunnel open timeout connecting to ${host}:${port}`);
          err.errCode = ERR_CODE.UNREACHABLE;
          reject(err);
        }
      }, timeoutMs);

      this.pendingOpens.set(streamId, { resolve, reject, timer, stream });
      this.sendMuxControl(FRAME_TYPE.OPEN, streamId, payload);
    });
  }

  requestMeta(query = {}, timeoutMs = 10000) {
    if (this.closed) return Promise.reject(new Error('Tunnel session closed'));
    const reqId = this.nextMetaId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pendingMeta.has(reqId)) {
          this.pendingMeta.delete(reqId);
          reject(new Error('Meta request timeout'));
        }
      }, timeoutMs);
      this.pendingMeta.set(reqId, { resolve, reject, timer });
      this.sendMuxControl(FRAME_TYPE.META_REQ, reqId, Buffer.from(JSON.stringify(query), 'utf8'));
    });
  }

  sendPing() {
    const buf = Buffer.allocUnsafe(8);
    buf.writeDoubleBE(Date.now(), 0);
    this.sendMuxControl(FRAME_TYPE.PING, 0, buf);
  }

  sendStreamData(stream, chunk) {
    for (let offset = 0; offset < chunk.length; offset += MAX_DATA_CHUNK) {
      const slice = chunk.subarray(offset, Math.min(chunk.length, offset + MAX_DATA_CHUNK));
      stream.sendWindow -= slice.length;
      stream.bytesUp += slice.length;
      this._enqueueEncrypted(encodeMuxFrame(FRAME_TYPE.DATA, stream.id, slice), true);
    }
  }

  sendMuxControl(type, streamId, payload) {
    if (this.closed) return;
    this._enqueueEncrypted(encodeMuxFrame(type, streamId, payload), false);
  }

  _enqueueEncrypted(muxFrame, applyRateLimit) {
    if (this.closed) return;
    if (applyRateLimit && this.rateLimiter.rate > 0) {
      const waitMs = this.rateLimiter.consumeWaitMs(muxFrame.length);
      if (waitMs > 0 || this._throttleQueue.length > 0) {
        this._throttleQueue.push({ muxFrame, waitMs });
        this._scheduleThrottleDrain();
        return;
      }
    }
    this._sendNow(muxFrame);
  }

  _scheduleThrottleDrain() {
    if (this._throttleTimer || this._throttleQueue.length === 0 || this.closed) return;
    const item = this._throttleQueue[0];
    this._throttleTimer = setTimeout(() => {
      this._throttleTimer = null;
      if (this.closed) return;
      const next = this._throttleQueue.shift();
      if (next) this._sendNow(next.muxFrame);
      while (this._throttleQueue.length > 0 && this._throttleQueue[0].waitMs === 0) {
        const fast = this._throttleQueue.shift();
        this._sendNow(fast.muxFrame);
      }
      if (this._throttleQueue.length > 0) {
        this._scheduleThrottleDrain();
      }
    }, Math.max(1, item.waitMs));
  }

  _sendNow(muxFrame) {
    if (this.closed) return;
    const estimatedWireLen = muxFrame.length + 24;
    if (this.maxQuotaBytes > 0 && this.totalBytes + estimatedWireLen > this.maxQuotaBytes) {
      this.kick('Data quota exceeded');
      return;
    }
    const encrypted = this.cipher.encrypt(muxFrame);
    this.bytesTx += encrypted.length;
    this.emit('traffic', { tx: encrypted.length, rx: 0 });
    const ok = this._sendRaw(encrypted);
    if (ok === false) {
      this.backpressured = true;
    }
  }

  kick(reason = 'Disconnected by exit node') {
    if (this.closed) return;
    try {
      const encrypted = this.cipher.encrypt(
        encodeMuxFrame(FRAME_TYPE.KICK, 0, Buffer.from(reason, 'utf8'))
      );
      this.bytesTx += encrypted.length;
      this._sendRaw(encrypted);
    } catch {
      // ignore send errors during kick
    }
    this.close(reason);
  }

  close(reason = 'Session closed') {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this._pingTimer);
    clearTimeout(this._throttleTimer);
    this._throttleQueue = [];

    for (const [id, pending] of this.pendingOpens.entries()) {
      clearTimeout(pending.timer);
      pending.reject(new Error(reason));
      this.pendingOpens.delete(id);
    }
    for (const [id, pending] of this.pendingMeta.entries()) {
      clearTimeout(pending.timer);
      pending.reject(new Error(reason));
      this.pendingMeta.delete(id);
    }
    for (const stream of Array.from(this.streams.values())) {
      stream.emit('rst', reason);
      if (stream.socket && !stream.socket.destroyed) stream.socket.destroy();
      stream.cleanup();
    }
    try {
      this._closeRaw?.(reason);
    } catch {
      // ignore
    }
    this.emit('close', reason);
  }
}
