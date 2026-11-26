import crypto from 'node:crypto';
import EventEmitter from 'node:events';
import net from 'node:net';
import tls from 'node:tls';

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export const OPCODE = {
  CONTINUATION: 0x0,
  TEXT: 0x1,
  BINARY: 0x2,
  CLOSE: 0x8,
  PING: 0x9,
  PONG: 0xa,
};

/**
 * Encodes an RFC 6455 WebSocket frame.
 */
export function encodeWsFrame(payload, { opcode = OPCODE.BINARY, masked = false, fin = true } = {}) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload || '');
  const len = data.length;
  let headerLen = 2;
  if (len >= 126 && len <= 0xffff) headerLen += 2;
  else if (len > 0xffff) headerLen += 8;
  if (masked) headerLen += 4;

  const out = Buffer.allocUnsafe(headerLen + len);
  out[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0f);

  let offset = 2;
  const maskBit = masked ? 0x80 : 0x00;
  if (len < 126) {
    out[1] = maskBit | len;
  } else if (len <= 0xffff) {
    out[1] = maskBit | 126;
    out.writeUInt16BE(len, 2);
    offset = 4;
  } else {
    out[1] = maskBit | 127;
    out.writeBigUInt64BE(BigInt(len), 2);
    offset = 10;
  }

  if (masked) {
    const mask = crypto.randomBytes(4);
    mask.copy(out, offset);
    offset += 4;
    for (let i = 0; i < len; i++) {
      out[offset + i] = data[i] ^ mask[i & 3];
    }
  } else if (len > 0) {
    data.copy(out, offset);
  }
  return out;
}

/**
 * Wraps an upgraded net.Socket / tls.TLSSocket as an RFC 6455 WebSocket connection.
 */
export class WsConnection extends EventEmitter {
  constructor(socket, { isClient = false, initialBuffer = null, maxPayloadBytes = 16 * 1024 * 1024 } = {}) {
    super();
    this.socket = socket;
    this.isClient = isClient;
    this.maxPayloadBytes = maxPayloadBytes;
    this.buffer = initialBuffer && initialBuffer.length ? Buffer.from(initialBuffer) : Buffer.alloc(0);
    this.fragments = [];
    this.fragmentOpcode = null;
    this.closed = false;
    this.readyState = 'OPEN';

    socket.setNoDelay(true);
    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('drain', () => this.emit('drain'));
    socket.on('error', (err) => {
      if (!this.closed) {
        this.closed = true;
        this.readyState = 'CLOSED';
        this.emit('error', err);
      }
    });
    socket.on('close', (hadError) => {
      if (!this.closed) {
        this.closed = true;
        this.readyState = 'CLOSED';
      }
      this.emit('close', hadError);
    });

    if (this.buffer.length > 0) {
      queueMicrotask(() => this._drainFrames());
    }
  }

  get remoteAddress() {
    return this.socket.remoteAddress || '';
  }

  get remotePort() {
    return this.socket.remotePort || 0;
  }

  /**
   * Sends a binary or text WebSocket message. Returns false if socket write buffer is full (backpressure).
   */
  send(data, isBinary = true) {
    if (this.closed || this.socket.destroyed) return false;
    const opcode = isBinary ? OPCODE.BINARY : OPCODE.TEXT;
    const frame = encodeWsFrame(data, { opcode, masked: this.isClient, fin: true });
    return this.socket.write(frame);
  }

  sendJson(obj) {
    return this.send(Buffer.from(JSON.stringify(obj), 'utf8'), false);
  }

  ping(payload = Buffer.alloc(0)) {
    if (this.closed || this.socket.destroyed) return false;
    return this.socket.write(encodeWsFrame(payload, { opcode: OPCODE.PING, masked: this.isClient, fin: true }));
  }

  pong(payload = Buffer.alloc(0)) {
    if (this.closed || this.socket.destroyed) return false;
    return this.socket.write(encodeWsFrame(payload, { opcode: OPCODE.PONG, masked: this.isClient, fin: true }));
  }

  pause() {
    this.socket.pause();
  }

  resume() {
    this.socket.resume();
  }

  close(code = 1000, reason = '') {
    if (this.closed) return;
    this.closed = true;
    this.readyState = 'CLOSING';
    const reasonBuf = Buffer.from(reason, 'utf8');
    const payload = Buffer.allocUnsafe(2 + reasonBuf.length);
    payload.writeUInt16BE(code, 0);
    reasonBuf.copy(payload, 2);
    try {
      if (!this.socket.destroyed) {
        this.socket.end(encodeWsFrame(payload, { opcode: OPCODE.CLOSE, masked: this.isClient, fin: true }));
      }
    } catch {
      this.socket.destroy();
    }
  }

  destroy() {
    this.closed = true;
    this.readyState = 'CLOSED';
    this.socket.destroy();
  }

  _onData(chunk) {
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
    this._drainFrames();
  }

  _drainFrames() {
    while (!this.closed && this.buffer.length >= 2) {
      const b0 = this.buffer[0];
      const b1 = this.buffer[1];
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let payloadLen = b1 & 0x7f;
      let offset = 2;

      if (payloadLen === 126) {
        if (this.buffer.length < 4) return;
        payloadLen = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (this.buffer.length < 10) return;
        const bigLen = this.buffer.readBigUInt64BE(2);
        if (bigLen > BigInt(this.maxPayloadBytes)) {
          this.close(1009, 'Frame too large');
          return;
        }
        payloadLen = Number(bigLen);
        offset = 10;
      }

      if (payloadLen > this.maxPayloadBytes) {
        this.close(1009, 'Frame too large');
        return;
      }

      const maskLen = masked ? 4 : 0;
      if (this.buffer.length < offset + maskLen + payloadLen) return;

      let payload;
      if (masked) {
        const mask = this.buffer.subarray(offset, offset + 4);
        const raw = this.buffer.subarray(offset + 4, offset + 4 + payloadLen);
        payload = Buffer.allocUnsafe(payloadLen);
        for (let i = 0; i < payloadLen; i++) {
          payload[i] = raw[i] ^ mask[i & 3];
        }
      } else {
        payload = Buffer.from(this.buffer.subarray(offset, offset + payloadLen));
      }

      this.buffer = this.buffer.subarray(offset + maskLen + payloadLen);
      this._handleFrame(fin, opcode, payload);
    }
  }

  _handleFrame(fin, opcode, payload) {
    // Control frames (PING, PONG, CLOSE) can arrive between fragments.
    if (opcode === OPCODE.PING) {
      this.pong(payload);
      return;
    }
    if (opcode === OPCODE.PONG) {
      this.emit('pong', payload);
      return;
    }
    if (opcode === OPCODE.CLOSE) {
      let code = 1000;
      let reason = '';
      if (payload.length >= 2) {
        code = payload.readUInt16BE(0);
        reason = payload.subarray(2).toString('utf8');
      }
      if (!this.closed) {
        this.close(code, reason);
      }
      this.emit('close_frame', { code, reason });
      return;
    }

    if (opcode !== OPCODE.CONTINUATION) {
      if (!fin) {
        this.fragmentOpcode = opcode;
        this.fragments = [payload];
        return;
      }
      this._emitMessage(opcode, payload);
      return;
    }

    if (this.fragmentOpcode === null) {
      this.close(1002, 'Unexpected continuation frame');
      return;
    }
    this.fragments.push(payload);
    if (fin) {
      const full = Buffer.concat(this.fragments);
      const op = this.fragmentOpcode;
      this.fragments = [];
      this.fragmentOpcode = null;
      this._emitMessage(op, full);
    }
  }

  _emitMessage(opcode, payload) {
    if (opcode === OPCODE.TEXT) {
      this.emit('message', payload.toString('utf8'), false);
    } else {
      this.emit('message', payload, true);
    }
  }
}

/**
 * Upgrades an incoming Node HTTP server request (`server.on('upgrade', ...)`) into a WsConnection.
 */
export function acceptWsUpgrade(req, socket, head) {
  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return null;
  }
  const accept = crypto.createHash('sha1').update(`${key}${WS_GUID}`).digest('base64');
  const headers = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '\r\n',
  ];
  socket.write(headers.join('\r\n'));
  return new WsConnection(socket, { isClient: false, initialBuffer: head });
}

/**
 * Connects to a ws:// or wss:// endpoint and resolves with a WsConnection.
 */
export function connectWs(wsUrl, { timeoutMs = 8000, rejectUnauthorized = true, headers = {} } = {}) {
  const parsed = new URL(wsUrl);
  const isTls = parsed.protocol === 'wss:';
  if (!isTls && parsed.protocol !== 'ws:') {
    return Promise.reject(new Error(`Unsupported WebSocket protocol: ${parsed.protocol}`));
  }

  const host = parsed.hostname;
  const port = parsed.port ? Number(parsed.port) : isTls ? 443 : 80;
  const path = `${parsed.pathname || '/'}${parsed.search || ''}`;

  return new Promise((resolve, reject) => {
    let settled = false;
    const secKey = crypto.randomBytes(16).toString('base64');
    const expectedAccept = crypto.createHash('sha1').update(`${secKey}${WS_GUID}`).digest('base64');

    const socket = isTls
      ? tls.connect({ host, port, servername: host, rejectUnauthorized })
      : net.connect({ host, port });

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        reject(new Error(`WebSocket connection timeout (${timeoutMs}ms) to ${wsUrl}`));
      }
    }, timeoutMs);

    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onHandshakeData);
      socket.removeListener('error', onError);
    };

    const onError = (err) => {
      if (!settled) {
        settled = true;
        cleanup();
        socket.destroy();
        reject(err);
      }
    };

    let responseBuf = Buffer.alloc(0);
    const onHandshakeData = (chunk) => {
      responseBuf = Buffer.concat([responseBuf, chunk]);
      const headerEnd = responseBuf.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (responseBuf.length > 16384) {
          onError(new Error('HTTP upgrade response too large'));
        }
        return;
      }

      const headerStr = responseBuf.subarray(0, headerEnd).toString('latin1');
      const trailing = responseBuf.subarray(headerEnd + 4);
      const lines = headerStr.split('\r\n');
      const statusLine = lines[0] || '';
      if (!statusLine.includes(' 101 ')) {
        onError(new Error(`WebSocket upgrade failed: ${statusLine}`));
        return;
      }

      const headerMap = {};
      for (let i = 1; i < lines.length; i++) {
        const idx = lines[i].indexOf(':');
        if (idx > 0) {
          headerMap[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
        }
      }
      if (headerMap['sec-websocket-accept'] !== expectedAccept) {
        onError(new Error('Invalid Sec-WebSocket-Accept header'));
        return;
      }

      settled = true;
      cleanup();
      resolve(new WsConnection(socket, { isClient: true, initialBuffer: trailing }));
    };

    socket.on('error', onError);
    socket.on('data', onHandshakeData);

    const connectEvent = isTls ? 'secureConnect' : 'connect';
    socket.once(connectEvent, () => {
      const hostHeader = parsed.port ? `${host}:${port}` : host;
      const reqLines = [
        `GET ${path} HTTP/1.1`,
        `Host: ${hostHeader}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Key: ${secKey}`,
        'Sec-WebSocket-Version: 13',
      ];
      for (const [k, v] of Object.entries(headers)) {
        reqLines.push(`${k}: ${v}`);
      }
      reqLines.push('\r\n');
      socket.write(reqLines.join('\r\n'));
    });
  });
}
