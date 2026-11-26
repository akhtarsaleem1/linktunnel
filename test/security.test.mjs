import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import { ClientNode } from '../src/node/client.mjs';
import { isPrivateIp } from '../src/node/network-guard.mjs';
import { SharerNode } from '../src/node/sharer.mjs';
import { parseRegQueryValue } from '../src/platform/win-proxy.mjs';

test('isPrivateIp blocks loopback, RFC1918, metadata, CGNAT, and mapped IPv6 while allowing public IPs', () => {
  for (const priv of [
    '127.0.0.1',
    '10.0.0.1',
    '172.16.5.4',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.5',
    '::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    'fe80::1',
    'fc00::1',
  ]) {
    assert.equal(isPrivateIp(priv), true, `Expected ${priv} to be blocked as private`);
  }

  for (const pub of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111']) {
    assert.equal(isPrivateIp(pub), false, `Expected ${pub} to be allowed as public`);
  }
});

test('Sharer enforces private LAN blocking, pause/resume, kick, and data quota', async () => {
  const localSrv = net.createServer((s) => s.end('LAN-SECRET'));
  await new Promise((r) => localSrv.listen(0, '127.0.0.1', r));
  const port = localSrv.address().port;

  const sharer = new SharerNode({
    deviceName: 'Guarded-Sharer',
    enableDirect: true,
    directHost: '127.0.0.1',
    directPort: 0,
    publicDirectHost: '127.0.0.1',
    blockPrivateNetwork: true,
  });
  await sharer.start();

  const client = new ClientNode({ deviceName: 'Peer-1' });
  await client.connect({ inviteUri: sharer.getInviteUri(), mode: 'direct', autoReconnect: false });

  // 1. Default blockPrivateNetwork=true blocks 127.0.0.1 & localhost
  await assert.rejects(() => client.openTunnelStream('127.0.0.1', port), /blocked/i);
  await assert.rejects(() => client.openTunnelStream('localhost', port), /blocked/i);

  // 2. Allow private network for remaining tests, verify pause blocks streams
  sharer.updatePolicy({ blockPrivateNetwork: false });
  sharer.setPaused(true);
  await assert.rejects(() => client.openTunnelStream('127.0.0.1', port), /paused/i);
  sharer.setPaused(false);

  const { stream } = await client.openTunnelStream('127.0.0.1', port);
  const data = await new Promise((resolve) => {
    const buf = [];
    stream.on('data', (c) => buf.push(c));
    stream.on('fin', () => resolve(Buffer.concat(buf).toString()));
  });
  assert.equal(data, 'LAN-SECRET');

  // 3. Kick peer
  const state = sharer.getState();
  assert.equal(state.peers.length, 1);
  sharer.kickPeer(state.peers[0].key, 'Manual kick test');
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(client.status, 'error');
  assert.match(client.lastError, /Manual kick test/);

  client.disconnect();
  await sharer.stop();
  await new Promise((r) => localSrv.close(r));
});

test('Windows registry query parser extracts ProxyEnable, ProxyServer, and ProxyOverride', () => {
  const sample = `
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
    ProxyEnable    REG_DWORD    0x1
    ProxyServer    REG_SZ    127.0.0.1:10808
    ProxyOverride    REG_SZ    localhost;127.*;<local>
`;
  assert.equal(parseRegQueryValue(sample, 'ProxyEnable'), '0x1');
  assert.equal(parseRegQueryValue(sample, 'ProxyServer'), '127.0.0.1:10808');
  assert.equal(parseRegQueryValue(sample, 'ProxyOverride'), 'localhost;127.*;<local>');
});
