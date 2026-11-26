import EventEmitter from 'node:events';
import net from 'node:net';
import { ERR_CODE } from '../protocol/mux.mjs';

function formatIpv4(buf) {
  return `${buf[0]}.${buf[1]}.${buf[2]}.${buf[3]}`;
}

function formatIpv6(buf) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(buf.readUInt16BE(i).toString(16));
  }
  return parts.join(':');
}

function mapErrToSocks5Reply(err) {
  if (!err) return 0x01;
  switch (err.errCode) {
    case ERR_CODE.BLOCKED:
      return 0x02; // connection not allowed by ruleset
    case ERR_CODE.UNREACHABLE:
      return 0x04; // Host unreachable
    case ERR_CODE.REFUSED:
      return 0x05; // Connection refused
    default:
      return 0x01;
  }
}

function parseAuthority(authority, defaultPort) {
  const raw = String(authority || '').trim();
  if (!raw) throw new Error('Empty host');
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end === -1) throw new Error('Invalid IPv6 host');
    const host = raw.slice(1, end);
    const rest = raw.slice(end + 1);
    const port = rest.startsWith(':') ? Number(rest.slice(1)) : defaultPort;
    return { host, port };
  }
  const lastColon = raw.lastIndexOf(':');
  if (lastColon > 0 && raw.indexOf(':') === lastColon) {
    return { host: raw.slice(0, lastColon), port: Number(raw.slice(lastColon + 1)) || defaultPort };
  }
  return { host: raw, port: defaultPort };
}

function isLoopbackAddress(remoteAddress = '') {
  const ip = remoteAddress.replace(/^::ffff:/, '');
  return ip === '127.0.0.1' || ip === '::1';
}

/**
 * Unified local proxy server listening on a single port and automatically supporting:
 * - SOCKS5 (RFC 1928 + RFC 1929 auth + remote DNS resolution)
 * - SOCKS4 / SOCKS4a
 * - HTTP/HTTPS CONNECT tunneling
 * - Plain HTTP forward proxy
 * - /proxy.pac auto-configuration endpoint
 */
export class UnifiedProxyServer extends EventEmitter {
  constructor({
    clientNode,
    host = '127.0.0.1',
    port = 10808,
    auth = { enabled: false, username: '', password: '', bypassLocalhost: true },
  }) {
    super();
    this.clientNode = clientNode;
    this.host = host;
    this.port = port;
    this.auth = {
      enabled: Boolean(auth?.enabled),
      username: String(auth?.username || ''),
      password: String(auth?.password || ''),
      bypassLocalhost: auth?.bypassLocalhost !== false,
    };

    this.server = null;
    this.running = false;
    this.activeConnections = 0;
    this.totalConnections = 0;
  }

  async start() {
    if (this.running) return this.getState();
    this.server = net.createServer((socket) => this._handleSocket(socket));
    this.server.on('error', (err) => this.emit('error', err));

    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, this.host, () => {
        this.server.removeListener('error', reject);
        const addr = this.server.address();
        if (typeof addr === 'object' && addr) this.port = addr.port;
        this.running = true;
        resolve();
      });
    });

    this.emit('state', this.getState());
    return this.getState();
  }

  async stop() {
    if (!this.running || !this.server) return;
    this.running = false;
    const srv = this.server;
    this.server = null;
    await new Promise((resolve) => srv.close(() => resolve()));
    this.emit('state', this.getState());
  }

  async reconfigure({ host, port, auth }) {
    const needRestart =
      this.running && ((host && host !== this.host) || (typeof port === 'number' && port !== this.port));
    if (host) this.host = host;
    if (typeof port === 'number') this.port = port;
    if (auth) {
      this.auth = {
        enabled: Boolean(auth.enabled),
        username: String(auth.username || ''),
        password: String(auth.password || ''),
        bypassLocalhost: auth.bypassLocalhost !== false,
      };
    }
    if (needRestart) {
      await this.stop();
      await this.start();
    } else {
      this.emit('state', this.getState());
    }
    return this.getState();
  }

  _requiresAuth(socket) {
    if (!this.auth.enabled) return false;
    if (this.auth.bypassLocalhost && isLoopbackAddress(socket.remoteAddress)) return false;
    return true;
  }

  _verifyCredentials(username, password) {
    return username === this.auth.username && password === this.auth.password;
  }

  _handleSocket(socket) {
    this.activeConnections++;
    this.totalConnections++;
    let settled = false;

    const cleanupCounter = () => {
      if (!settled) {
        settled = true;
        this.activeConnections = Math.max(0, this.activeConnections - 1);
      }
    };
    socket.once('close', cleanupCounter);
    socket.on('error', () => {
      if (!socket.destroyed) socket.destroy();
    });

    socket.once('data', (firstChunk) => {
      if (!firstChunk || firstChunk.length === 0) {
        socket.destroy();
        return;
      }
      const ver = firstChunk[0];
      if (ver === 0x05) {
        this._handleSocks5(socket, firstChunk);
      } else if (ver === 0x04) {
        this._handleSocks4(socket, firstChunk);
      } else {
        this._handleHttpProxy(socket, firstChunk);
      }
    });
  }

  _handleSocks5(socket, initialBuf) {
    let buf = initialBuf;
    let stage = 'greeting'; // greeting | auth | request
    const needAuth = this._requiresAuth(socket);

    const onData = async (chunk) => {
      if (chunk) buf = Buffer.concat([buf, chunk]);

      try {
        if (stage === 'greeting') {
          if (buf.length < 2) return;
          const nMethods = buf[1];
          if (buf.length < 2 + nMethods) return;
          const methods = buf.subarray(2, 2 + nMethods);
          buf = buf.subarray(2 + nMethods);

          if (needAuth) {
            if (!methods.includes(0x02)) {
              socket.end(Buffer.from([0x05, 0xff]));
              return;
            }
            socket.write(Buffer.from([0x05, 0x02]));
            stage = 'auth';
          } else {
            if (!methods.includes(0x00)) {
              socket.end(Buffer.from([0x05, 0xff]));
              return;
            }
            socket.write(Buffer.from([0x05, 0x00]));
            stage = 'request';
          }
        }

        if (stage === 'auth') {
          if (buf.length < 2) return;
          const uLen = buf[1];
          if (buf.length < 3 + uLen) return;
          const pLen = buf[2 + uLen];
          if (buf.length < 3 + uLen + pLen) return;
          const user = buf.subarray(2, 2 + uLen).toString('utf8');
          const pass = buf.subarray(3 + uLen, 3 + uLen + pLen).toString('utf8');
          buf = buf.subarray(3 + uLen + pLen);

          if (!this._verifyCredentials(user, pass)) {
            socket.end(Buffer.from([0x01, 0x01]));
            return;
          }
          socket.write(Buffer.from([0x01, 0x00]));
          stage = 'request';
        }

        if (stage === 'request') {
          if (buf.length < 4) return;
          const ver = buf[0];
          const cmd = buf[1];
          const atyp = buf[3];
          if (ver !== 0x05) {
            socket.destroy();
            return;
          }

          let addrLen = 0;
          let host = '';
          let headerSize = 0;

          if (atyp === 0x01) {
            addrLen = 4;
            headerSize = 4 + 4 + 2;
            if (buf.length < headerSize) return;
            host = formatIpv4(buf.subarray(4, 8));
          } else if (atyp === 0x03) {
            if (buf.length < 5) return;
            addrLen = buf[4];
            headerSize = 5 + addrLen + 2;
            if (buf.length < headerSize) return;
            host = buf.subarray(5, 5 + addrLen).toString('utf8');
          } else if (atyp === 0x04) {
            addrLen = 16;
            headerSize = 4 + 16 + 2;
            if (buf.length < headerSize) return;
            host = formatIpv6(buf.subarray(4, 20));
          } else {
            socket.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            return;
          }

          const port = buf.readUInt16BE(headerSize - 2);
          const trailing = buf.subarray(headerSize);
          socket.removeListener('data', onData);

          if (cmd !== 0x01) {
            socket.end(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            return;
          }

          try {
            const { stream } = await this.clientNode.openTunnelStream(host, port);
            if (socket.destroyed) {
              stream.reset('local closed');
              return;
            }
            const reply = Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            socket.write(reply);
            stream.pipeSocket(socket);
            if (trailing.length > 0) {
              stream.session.sendStreamData(stream, trailing);
            }
          } catch (err) {
            const code = mapErrToSocks5Reply(err);
            if (!socket.destroyed) {
              socket.end(Buffer.from([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            }
          }
        }
      } catch {
        socket.destroy();
      }
    };

    socket.on('data', onData);
    onData(null);
  }

  _handleSocks4(socket, initialBuf) {
    let buf = initialBuf;
    const onData = async (chunk) => {
      if (chunk) buf = Buffer.concat([buf, chunk]);
      if (buf.length < 9) return;
      const cmd = buf[1];
      const port = buf.readUInt16BE(2);
      const ipBytes = buf.subarray(4, 8);
      const userEnd = buf.indexOf(0x00, 8);
      if (userEnd === -1) return;

      let host = formatIpv4(ipBytes);
      let reqEnd = userEnd + 1;
      // SOCKS4a domain extension when IP is 0.0.0.x (x != 0)
      if (ipBytes[0] === 0 && ipBytes[1] === 0 && ipBytes[2] === 0 && ipBytes[3] !== 0) {
        const domainEnd = buf.indexOf(0x00, userEnd + 1);
        if (domainEnd === -1) return;
        host = buf.subarray(userEnd + 1, domainEnd).toString('utf8');
        reqEnd = domainEnd + 1;
      }

      const trailing = buf.subarray(reqEnd);
      socket.removeListener('data', onData);

      if (cmd !== 0x01 || this._requiresAuth(socket)) {
        socket.end(Buffer.from([0x00, 0x5b, 0, 0, 0, 0, 0, 0]));
        return;
      }

      try {
        const { stream } = await this.clientNode.openTunnelStream(host, port);
        if (socket.destroyed) {
          stream.reset('local closed');
          return;
        }
        socket.write(Buffer.from([0x00, 0x5a, 0, 0, 0, 0, 0, 0]));
        stream.pipeSocket(socket);
        if (trailing.length > 0) {
          stream.session.sendStreamData(stream, trailing);
        }
      } catch {
        if (!socket.destroyed) socket.end(Buffer.from([0x00, 0x5b, 0, 0, 0, 0, 0, 0]));
      }
    };
    socket.on('data', onData);
    onData(null);
  }

  _handleHttpProxy(socket, initialBuf) {
    let buf = initialBuf;

    const onData = async (chunk) => {
      if (chunk) buf = Buffer.concat([buf, chunk]);
      const headerEnd = buf.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (buf.length > 65536) socket.destroy();
        return;
      }

      socket.removeListener('data', onData);
      const rawHeader = buf.subarray(0, headerEnd).toString('latin1');
      const trailing = buf.subarray(headerEnd + 4);
      const lines = rawHeader.split('\r\n');
      const reqLine = lines[0] || '';
      const [method = '', target = '', version = 'HTTP/1.1'] = reqLine.split(' ');

      const headers = {};
      for (let i = 1; i < lines.length; i++) {
        const idx = lines[i].indexOf(':');
        if (idx > 0) {
          headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim();
        }
      }

      // Direct local PAC file serving on the proxy port itself
      if (method.toUpperCase() === 'GET' && target === '/proxy.pac') {
        const proxyAddr = headers.host || `127.0.0.1:${this.port}`;
        const pac = `function FindProxyForURL(url, host) {\n  if (isPlainHostName(host) || shExpMatch(host, "*.local") || isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0") || isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") || isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";\n  return "PROXY ${proxyAddr}; SOCKS5 ${proxyAddr}; DIRECT";\n}\n`;
        socket.end(
          `HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: ${Buffer.byteLength(
            pac
          )}\r\nConnection: close\r\n\r\n${pac}`
        );
        return;
      }

      if (this._requiresAuth(socket)) {
        const authHdr = headers['proxy-authorization'] || '';
        let ok = false;
        if (authHdr.toLowerCase().startsWith('basic ')) {
          const decoded = Buffer.from(authHdr.slice(6).trim(), 'base64').toString('utf8');
          const sep = decoded.indexOf(':');
          if (sep !== -1) {
            ok = this._verifyCredentials(decoded.slice(0, sep), decoded.slice(sep + 1));
          }
        }
        if (!ok) {
          socket.end(
            'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="LinkTunnel"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
          );
          return;
        }
      }

      if (method.toUpperCase() === 'CONNECT') {
        let host, port;
        try {
          ({ host, port } = parseAuthority(target, 443));
        } catch {
          socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
          return;
        }

        try {
          const { stream } = await this.clientNode.openTunnelStream(host, port);
          if (socket.destroyed) {
            stream.reset('local closed');
            return;
          }
          socket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: LinkTunnel/1.0\r\n\r\n');
          stream.pipeSocket(socket);
          if (trailing.length > 0) {
            stream.session.sendStreamData(stream, trailing);
          }
        } catch (err) {
          if (!socket.destroyed) {
            socket.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nTunnel Error: ${err.message}`);
          }
        }
        return;
      }

      // Plain HTTP forward proxy
      let parsedUrl;
      try {
        parsedUrl = target.startsWith('http://') || target.startsWith('https://')
          ? new URL(target)
          : new URL(`http://${headers.host}${target.startsWith('/') ? target : '/' + target}`);
      } catch {
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        return;
      }

      const host = parsedUrl.hostname;
      const port = parsedUrl.port ? Number(parsedUrl.port) : 80;
      const originPath = `${parsedUrl.pathname || '/'}${parsedUrl.search || ''}`;

      // Rewrite request headers without hop-by-hop proxy headers
      const outLines = [`${method} ${originPath} ${version}`];
      for (let i = 1; i < lines.length; i++) {
        const lower = lines[i].toLowerCase();
        if (
          lower.startsWith('proxy-connection:') ||
          lower.startsWith('proxy-authorization:') ||
          lower.startsWith('connection:')
        ) {
          continue;
        }
        if (lines[i]) outLines.push(lines[i]);
      }
      outLines.push('Connection: close');
      const rewrittenHeader = Buffer.from(`${outLines.join('\r\n')}\r\n\r\n`, 'latin1');

      try {
        const { stream } = await this.clientNode.openTunnelStream(host, port);
        if (socket.destroyed) {
          stream.reset('local closed');
          return;
        }
        stream.pipeSocket(socket);
        stream.session.sendStreamData(stream, rewrittenHeader);
        if (trailing.length > 0) {
          stream.session.sendStreamData(stream, trailing);
        }
      } catch (err) {
        if (!socket.destroyed) {
          socket.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nTunnel Error: ${err.message}`);
        }
      }
    };

    socket.on('data', onData);
    onData(null);
  }

  getState() {
    return {
      running: this.running,
      host: this.host,
      port: this.port,
      lanExposed: this.host === '0.0.0.0',
      authEnabled: this.auth.enabled,
      activeConnections: this.activeConnections,
      totalConnections: this.totalConnections,
    };
  }
}
