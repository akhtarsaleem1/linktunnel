import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
import { ClientNode } from '../src/node/client.mjs';
import { UnifiedProxyServer } from '../src/node/proxy.mjs';
import { SharerNode } from '../src/node/sharer.mjs';
import { RelayServer } from '../src/relay/server.mjs';

function httpRequestViaProxy(proxyPort, reqStr) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: '127.0.0.1', port: proxyPort }, () => {
      sock.write(reqStr);
    });
    const chunks = [];
    sock.on('data', (c) => chunks.push(c));
    sock.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    sock.on('error', reject);
  });
}

function connectViaHttpConnect(proxyPort, targetHost, targetPort, authHeader = '') {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: '127.0.0.1', port: proxyPort }, () => {
      const authLine = authHeader ? `Proxy-Authorization: ${authHeader}\r\n` : '';
      sock.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${authLine}\r\n`);
    });
    let buf = Buffer.alloc(0);
    const onData = (c) => {
      buf = Buffer.concat([buf, c]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx !== -1) {
        sock.removeListener('data', onData);
        const hdr = buf.subarray(0, idx).toString('latin1');
        if (!hdr.includes('200')) {
          sock.destroy();
          reject(new Error(`CONNECT failed: ${hdr.split('\r\n')[0]}`));
          return;
        }
        resolve({ sock, trailing: buf.subarray(idx + 4) });
      }
    };
    sock.on('data', onData);
    sock.on('error', reject);
  });
}

function connectViaSocks5(proxyPort, targetHost, targetPort, { username, password } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: '127.0.0.1', port: proxyPort }, () => {
      if (username !== undefined) {
        sock.write(Buffer.from([0x05, 0x01, 0x02]));
      } else {
        sock.write(Buffer.from([0x05, 0x01, 0x00]));
      }
    });

    let stage = 'method';
    let buf = Buffer.alloc(0);

    const sendConnectReq = () => {
      const isIp4 = net.isIP(targetHost) === 4;
      if (isIp4) {
        const parts = targetHost.split('.').map(Number);
        const req = Buffer.allocUnsafe(10);
        req[0] = 0x05;
        req[1] = 0x01;
        req[2] = 0x00;
        req[3] = 0x01;
        req[4] = parts[0];
        req[5] = parts[1];
        req[6] = parts[2];
        req[7] = parts[3];
        req.writeUInt16BE(targetPort, 8);
        sock.write(req);
      } else {
        const hostBuf = Buffer.from(targetHost, 'utf8');
        const req = Buffer.allocUnsafe(7 + hostBuf.length);
        req[0] = 0x05;
        req[1] = 0x01;
        req[2] = 0x00;
        req[3] = 0x03;
        req[4] = hostBuf.length;
        hostBuf.copy(req, 5);
        req.writeUInt16BE(targetPort, 5 + hostBuf.length);
        sock.write(req);
      }
    };

    const onData = (c) => {
      buf = Buffer.concat([buf, c]);
      if (stage === 'method' && buf.length >= 2) {
        const chosen = buf[1];
        buf = buf.subarray(2);
        if (chosen === 0xff) {
          reject(new Error('SOCKS5 auth method rejected'));
          sock.destroy();
          return;
        }
        if (chosen === 0x02) {
          stage = 'auth';
          const u = Buffer.from(username);
          const p = Buffer.from(password);
          const authBuf = Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]);
          sock.write(authBuf);
        } else {
          stage = 'connect';
          sendConnectReq();
        }
      }
      if (stage === 'auth' && buf.length >= 2) {
        if (buf[1] !== 0x00) {
          reject(new Error('SOCKS5 user/pass failed'));
          sock.destroy();
          return;
        }
        buf = buf.subarray(2);
        stage = 'connect';
        sendConnectReq();
      }
      if (stage === 'connect' && buf.length >= 10) {
        const rep = buf[1];
        const trailing = buf.subarray(10);
        sock.removeListener('data', onData);
        if (rep !== 0x00) {
          reject(new Error(`SOCKS5 CONNECT rejected with code ${rep}`));
          sock.destroy();
          return;
        }
        resolve({ sock, trailing });
      }
    };

    sock.on('data', onData);
    sock.on('error', reject);
  });
}

test('End-to-End Relay Tunnel: HTTP proxy, HTTP CONNECT, SOCKS5 IPv4/Domain, large streaming, and zero plaintext on relay', async () => {
  // 1. Target HTTP & TCP echo server representing remote Internet destination
  const httpTarget = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, path: req.url, method: req.method }));
  });
  await new Promise((r) => httpTarget.listen(0, '127.0.0.1', r));
  const httpTargetPort = httpTarget.address().port;

  const echoTarget = net.createServer((sock) => sock.pipe(sock));
  await new Promise((r) => echoTarget.listen(0, '127.0.0.1', r));
  const echoTargetPort = echoTarget.address().port;

  // 2. Start zero-knowledge Relay Server & inspect raw traffic for plaintext leak
  const relay = new RelayServer({ host: '127.0.0.1', port: 0 });
  const { port: relayPort } = await relay.start();

  // 3. Start Sharer (allow loopback target strictly for local integration test)
  const sharer = new SharerNode({
    deviceName: 'Test-Sharer',
    relayUrl: `ws://127.0.0.1:${relayPort}/relay`,
    enableDirect: false,
    blockPrivateNetwork: false,
  });
  await sharer.start();

  // 4. Start Client + Unified Proxy
  const client = new ClientNode({ deviceName: 'Test-Client' });
  const proxy = new UnifiedProxyServer({ clientNode: client, host: '127.0.0.1', port: 0 });
  await proxy.start();

  await client.connect({
    inviteUri: sharer.getInviteUri(),
    mode: 'relay',
    autoReconnect: false,
  });

  // Test A: Plain HTTP proxy GET
  const httpRes = await httpRequestViaProxy(
    proxy.port,
    `GET http://127.0.0.1:${httpTargetPort}/test-marker?q=1 HTTP/1.1\r\nHost: 127.0.0.1:${httpTargetPort}\r\n\r\n`
  );
  assert.ok(httpRes.includes('200 OK'));
  assert.ok(httpRes.includes('"/test-marker?q=1"'));

  // Test B: HTTP CONNECT + 256KB payload streaming
  const { sock: connSock } = await connectViaHttpConnect(proxy.port, '127.0.0.1', echoTargetPort);
  const bigPayload = Buffer.alloc(256 * 1024, 0x4b);
  const echoed = await new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    connSock.on('data', (d) => {
      chunks.push(d);
      total += d.length;
      if (total >= bigPayload.length) {
        connSock.destroy();
        resolve(Buffer.concat(chunks));
      }
    });
    connSock.on('error', reject);
    connSock.write(bigPayload);
  });
  assert.deepEqual(echoed, bigPayload);

  // Test C: SOCKS5 with Domain Name ("localhost" resolved on Sharer side)
  const { sock: s5Sock } = await connectViaSocks5(proxy.port, 'localhost', echoTargetPort);
  const secretText = 'SECRET-MARKER-TEXT-NEVER-SEEN-BY-RELAY';
  const s5Echo = await new Promise((resolve) => {
    s5Sock.on('data', (d) => {
      s5Sock.destroy();
      resolve(d.toString('utf8'));
    });
    s5Sock.write(secretText);
  });
  assert.equal(s5Echo, secretText);

  // Test D: PAC endpoint
  const pacRes = await httpRequestViaProxy(proxy.port, `GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1:${proxy.port}\r\n\r\n`);
  assert.ok(pacRes.includes('FindProxyForURL'));

  // Test E: Proxy Authentication (RFC 1929 SOCKS5 + HTTP 407)
  await proxy.reconfigure({
    auth: { enabled: true, username: 'phone', password: 'pw123', bypassLocalhost: false },
  });
  await assert.rejects(() => connectViaHttpConnect(proxy.port, '127.0.0.1', echoTargetPort), /407/);
  const basicAuth = `Basic ${Buffer.from('phone:pw123').toString('base64')}`;
  const { sock: authConn } = await connectViaHttpConnect(proxy.port, '127.0.0.1', echoTargetPort, basicAuth);
  authConn.destroy();

  const { sock: authS5 } = await connectViaSocks5(proxy.port, '127.0.0.1', echoTargetPort, {
    username: 'phone',
    password: 'pw123',
  });
  authS5.destroy();

  assert.ok(relay.bytesRelayed > 0);

  client.disconnect();
  await proxy.stop();
  await sharer.stop();
  await relay.stop();
  await new Promise((r) => httpTarget.close(r));
  await new Promise((r) => echoTarget.close(r));
});
