import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import { ClientNode } from '../src/node/client.mjs';
import { SharerNode } from '../src/node/sharer.mjs';
import { RelayServer } from '../src/relay/server.mjs';

test('Hybrid mode chooses Direct P2P when reachable and falls back to Relay when Direct is unreachable', async () => {
  const target = net.createServer((s) => {
    s.on('data', (d) => s.write(Buffer.concat([Buffer.from('OK:'), d])));
  });
  await new Promise((r) => target.listen(0, '127.0.0.1', r));
  const targetPort = target.address().port;

  const relay = new RelayServer({ host: '127.0.0.1', port: 0 });
  const { port: relayPort } = await relay.start();

  // Case 1: Direct listener active -> Hybrid picks 'direct'
  const sharer = new SharerNode({
    deviceName: 'Direct-Capable-Sharer',
    relayUrl: `ws://127.0.0.1:${relayPort}/relay`,
    enableDirect: true,
    directHost: '127.0.0.1',
    directPort: 0,
    publicDirectHost: '127.0.0.1',
    blockPrivateNetwork: false,
  });
  await sharer.start();

  const client1 = new ClientNode({ deviceName: 'Hybrid-Direct-Client' });
  await client1.connect({
    inviteUri: sharer.getInviteUri(),
    mode: 'hybrid',
    autoReconnect: false,
  });
  assert.equal(client1.activeTransport, 'direct');

  const { stream: st1 } = await client1.openTunnelStream('127.0.0.1', targetPort);
  const res1 = await new Promise((resolve) => {
    st1.on('data', (d) => resolve(d.toString()));
    st1.session.sendStreamData(st1, Buffer.from('ping'));
  });
  assert.equal(res1, 'OK:ping');
  st1.reset();
  client1.disconnect();
  await sharer.stop();

  // Case 2: Sharer behind NAT (no reachable Direct endpoint) -> Hybrid falls back to 'relay'
  const natSharer = new SharerNode({
    deviceName: 'NAT-Sharer',
    relayUrl: `ws://127.0.0.1:${relayPort}/relay`,
    enableDirect: false,
    blockPrivateNetwork: false,
  });
  await natSharer.start();

  const client2 = new ClientNode({ deviceName: 'Hybrid-Relay-Client' });
  await client2.connect({
    roomCode: natSharer.roomCode,
    secret: natSharer.secret,
    relayUrl: `ws://127.0.0.1:${relayPort}/relay`,
    directEndpoints: ['ws://127.0.0.1:1/tunnel'], // unreachable direct port
    mode: 'hybrid',
    autoReconnect: false,
  });
  assert.equal(client2.activeTransport, 'relay');

  client2.disconnect();
  await natSharer.stop();
  await relay.stop();
  await new Promise((r) => target.close(r));
});

test('Mutual bidirectional sharing: Peer A and Peer B share internet to each other simultaneously', async () => {
  const targetA = net.createServer((s) => s.end('FROM_NODE_A'));
  const targetB = net.createServer((s) => s.end('FROM_NODE_B'));
  await new Promise((r) => targetA.listen(0, '127.0.0.1', r));
  await new Promise((r) => targetB.listen(0, '127.0.0.1', r));

  const relay = new RelayServer({ host: '127.0.0.1', port: 0 });
  const { port: relayPort } = await relay.start();
  const relayUrl = `ws://127.0.0.1:${relayPort}/relay`;

  const sharerA = new SharerNode({ deviceName: 'Node-A', relayUrl, enableDirect: false, blockPrivateNetwork: false });
  const sharerB = new SharerNode({ deviceName: 'Node-B', relayUrl, enableDirect: false, blockPrivateNetwork: false });
  await sharerA.start();
  await sharerB.start();

  const clientOnA = new ClientNode({ deviceName: 'Node-A-Client' });
  const clientOnB = new ClientNode({ deviceName: 'Node-B-Client' });
  await Promise.all([
    clientOnA.connect({ inviteUri: sharerB.getInviteUri(), mode: 'relay', autoReconnect: false }),
    clientOnB.connect({ inviteUri: sharerA.getInviteUri(), mode: 'relay', autoReconnect: false }),
  ]);

  const readAll = (stream) =>
    new Promise((resolve) => {
      const parts = [];
      stream.on('data', (d) => parts.push(d));
      stream.on('fin', () => resolve(Buffer.concat(parts).toString()));
    });

  const [{ stream: sFromB }, { stream: sFromA }] = await Promise.all([
    clientOnA.openTunnelStream('127.0.0.1', targetB.address().port),
    clientOnB.openTunnelStream('127.0.0.1', targetA.address().port),
  ]);

  const [gotFromB, gotFromA] = await Promise.all([readAll(sFromB), readAll(sFromA)]);
  assert.equal(gotFromB, 'FROM_NODE_B');
  assert.equal(gotFromA, 'FROM_NODE_A');

  clientOnA.disconnect();
  clientOnB.disconnect();
  await sharerA.stop();
  await sharerB.stop();
  await relay.stop();
  await new Promise((r) => targetA.close(r));
  await new Promise((r) => targetB.close(r));
});
