import assert from 'node:assert/strict';
import test from 'node:test';
import { ClientHandshake, SharerHandshake, generateDeviceId, generateRoomCode, generateSecret } from '../src/crypto/e2ee.mjs';
import { MuxSession, TokenBucket } from '../src/protocol/mux.mjs';

function createLinkedSessions({ sharerQuota = 0, sharerRate = 0, onOpenStream = null } = {}) {
  const roomCode = generateRoomCode();
  const secret = generateSecret();
  const cHs = new ClientHandshake({ roomCode, secret, deviceId: generateDeviceId(), deviceName: 'C' });
  const sHs = new SharerHandshake({ roomCode, secret, deviceId: generateDeviceId(), deviceName: 'S' });
  const { response, cipher: sCipher } = sHs.processClientHello(cHs.createHello());
  const { cipher: cCipher } = cHs.processServerHello(response);

  let clientSession;
  let sharerSession;

  clientSession = new MuxSession({
    role: 'client',
    cipher: cCipher,
    pingIntervalMs: 0,
    sendRaw: (pkt) => {
      queueMicrotask(() => {
        if (!sharerSession.closed) sharerSession.handleIncomingPacket(pkt);
      });
      return true;
    },
  });

  sharerSession = new MuxSession({
    role: 'sharer',
    cipher: sCipher,
    pingIntervalMs: 0,
    maxQuotaBytes: sharerQuota,
    maxBandwidthBps: sharerRate,
    onOpenStream,
    sendRaw: (pkt) => {
      queueMicrotask(() => {
        if (!clientSession.closed) clientSession.handleIncomingPacket(pkt);
      });
      return true;
    },
  });

  return { clientSession, sharerSession };
}

test('MuxSession enforces data quota cap and cleans up streams', async () => {
  const { clientSession, sharerSession } = createLinkedSessions({
    sharerQuota: 1200,
    onOpenStream: async (stream) => {
      stream.on('data', (d) => stream.session.sendStreamData(stream, d));
      return {};
    },
  });

  let kickedMsg = '';
  clientSession.on('kicked', (msg) => {
    kickedMsg = msg;
  });

  const { stream } = await clientSession.openStream('example.com', 80);
  clientSession.sendStreamData(stream, Buffer.alloc(2000, 0x7a));

  await new Promise((r) => setTimeout(r, 80));
  assert.equal(kickedMsg, 'Data quota exceeded');
  assert.equal(clientSession.closed, true);
  assert.equal(sharerSession.closed, true);
});

test('TokenBucket computes wait delay when burst is exhausted', () => {
  const bucket = new TokenBucket(100_000); // 100 KB/s, cap 64 KB
  assert.equal(bucket.consumeWaitMs(32_000), 0);
  assert.equal(bucket.consumeWaitMs(32_000), 0);
  const wait = bucket.consumeWaitMs(50_000);
  assert.ok(wait >= 400, `Expected throttle delay >= 400ms, got ${wait}`);
});
