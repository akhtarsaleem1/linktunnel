import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { OPCODE, WsConnection, acceptWsUpgrade, connectWs, encodeWsFrame } from '../src/protocol/ws.mjs';

test('WebSocket handles small, 16-bit, and >64KB binary frames + ping/pong', async () => {
  const server = http.createServer();
  let serverWs = null;
  server.on('upgrade', (req, socket, head) => {
    serverWs = acceptWsUpgrade(req, socket, head);
    serverWs.on('message', (data, isBinary) => {
      serverWs.send(data, isBinary);
    });
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();

  const clientWs = await connectWs(`ws://127.0.0.1:${port}/ws`);

  const echo = (payload) =>
    new Promise((resolve) => {
      clientWs.once('message', (msg) => resolve(msg));
      clientWs.send(payload, true);
    });

  const small = Buffer.from('hello');
  assert.deepEqual(await echo(small), small);

  const medium = Buffer.alloc(1500, 0xab);
  assert.deepEqual(await echo(medium), medium);

  const large = Buffer.alloc(120 * 1024, 0x5c);
  assert.deepEqual(await echo(large), large);

  // Test ping/pong
  await new Promise((resolve) => {
    clientWs.once('pong', (p) => {
      assert.equal(p.toString(), 'ping-1');
      resolve();
    });
    clientWs.ping(Buffer.from('ping-1'));
  });

  // Test fragmented frame assembly from client to server
  const part1 = encodeWsFrame(Buffer.from('part-one-'), { opcode: OPCODE.BINARY, masked: true, fin: false });
  const part2 = encodeWsFrame(Buffer.from('part-two'), { opcode: OPCODE.CONTINUATION, masked: true, fin: true });
  const assembled = await new Promise((resolve) => {
    clientWs.once('message', (msg) => resolve(msg));
    clientWs.socket.write(Buffer.concat([part1, part2]));
  });
  assert.equal(assembled.toString(), 'part-one-part-two');

  clientWs.destroy();
  serverWs?.destroy();
  await new Promise((r) => server.close(r));
});
