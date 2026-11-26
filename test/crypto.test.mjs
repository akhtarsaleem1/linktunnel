import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ClientHandshake,
  SharerHandshake,
  createInviteUri,
  deriveRelayRoomHash,
  generateDeviceId,
  generateRoomCode,
  generateSecret,
  parseInviteUri,
} from '../src/crypto/e2ee.mjs';

test('Invite URI creation and parsing round-trip', () => {
  const roomCode = generateRoomCode();
  const secret = generateSecret();
  const uri = createInviteUri({
    roomCode,
    secret,
    relayUrl: 'wss://relay.example.com/relay',
    directEndpoints: ['ws://203.0.113.10:4322/tunnel'],
    name: 'Home-Fiber',
  });

  assert.match(uri, /^linktunnel:\/\/v1\?d=/);
  const parsed = parseInviteUri(uri);
  assert.equal(parsed.roomCode, roomCode);
  assert.equal(parsed.secret, secret);
  assert.equal(parsed.relayUrl, 'wss://relay.example.com/relay');
  assert.deepEqual(parsed.directEndpoints, ['ws://203.0.113.10:4322/tunnel']);
  assert.equal(parsed.name, 'Home-Fiber');
});

test('Relay room hash never exposes raw secret', () => {
  const h1 = deriveRelayRoomHash('LT-ABCD-EFGH');
  const h2 = deriveRelayRoomHash('lt-abcd-efgh');
  assert.equal(h1, h2);
  assert.equal(h1.length, 32);
  assert.ok(!h1.includes('ABCD'));
});

test('X25519 + PSK handshake derives matching E2EE session ciphers and safety code', () => {
  const roomCode = generateRoomCode();
  const secret = generateSecret();

  const clientHs = new ClientHandshake({
    roomCode,
    secret,
    deviceId: generateDeviceId(),
    deviceName: 'Laptop',
  });
  const sharerHs = new SharerHandshake({
    roomCode,
    secret,
    deviceId: generateDeviceId(),
    deviceName: 'Desktop',
  });

  const helloC = clientHs.createHello();
  const { response: helloS, cipher: sharerCipher, peerName: seenBySharer } = sharerHs.processClientHello(helloC);
  const { cipher: clientCipher, peerName: seenByClient } = clientHs.processServerHello(helloS);

  assert.equal(seenBySharer, 'Laptop');
  assert.equal(seenByClient, 'Desktop');
  assert.equal(clientCipher.safetyCode, sharerCipher.safetyCode);
  assert.match(clientCipher.safetyCode, /^[0-9A-F]{4}-[0-9A-F]{4}$/);

  const msg1 = Buffer.from('secret internet packet 1');
  const enc1 = clientCipher.encrypt(msg1);
  assert.ok(!enc1.includes(msg1));
  assert.deepEqual(sharerCipher.decrypt(enc1), msg1);

  const msg2 = Buffer.from('response internet packet 2');
  const enc2 = sharerCipher.encrypt(msg2);
  assert.deepEqual(clientCipher.decrypt(enc2), msg2);

  // Replay protection
  assert.throws(() => clientCipher.decrypt(enc2), /Replay or out-of-order/);

  // Tamper protection
  const enc3 = clientCipher.encrypt(Buffer.from('hello'));
  enc3[enc3.length - 1] ^= 0xff;
  assert.throws(() => sharerCipher.decrypt(enc3));
});

test('Wrong pairing secret is rejected during handshake', () => {
  const roomCode = generateRoomCode();
  const clientHs = new ClientHandshake({
    roomCode,
    secret: 'wrong-secret',
    deviceId: generateDeviceId(),
  });
  const sharerHs = new SharerHandshake({
    roomCode,
    secret: 'correct-secret',
    deviceId: generateDeviceId(),
  });

  const helloC = clientHs.createHello();
  assert.throws(() => sharerHs.processClientHello(helloC), /wrong invite secret/i);
});
