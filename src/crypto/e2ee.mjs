import crypto from 'node:crypto';

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const SAFE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

export const PROTOCOL_VERSION = 1;
export const CIPHER_NAME = 'chacha20-poly1305';

/**
 * Generates an unambiguous human-friendly pairing code like "LT-7K4M-9P2X".
 */
export function generateRoomCode() {
  const bytes = crypto.randomBytes(8);
  let chars = '';
  for (let i = 0; i < 8; i++) {
    chars += SAFE_ALPHABET[bytes[i] % SAFE_ALPHABET.length];
  }
  return `LT-${chars.slice(0, 4)}-${chars.slice(4, 8)}`;
}

/**
 * Generates a high-entropy pairing secret string.
 */
export function generateSecret(byteLength = 12) {
  return crypto.randomBytes(byteLength).toString('base64url');
}

/**
 * Generates a persistent random device/node ID (16 hex bytes).
 */
export function generateDeviceId() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Derives an opaque relay routing identifier from a room code so the relay
 * never needs to store or inspect the raw invite secret.
 */
export function deriveRelayRoomHash(roomCode) {
  return crypto
    .createHash('sha256')
    .update(`linktunnel-relay-room-v1:${String(roomCode).trim().toUpperCase()}`)
    .digest('hex')
    .slice(0, 32);
}

/**
 * Derives the 32-byte Pre-Shared Key (PSK) binding roomCode and secret.
 */
export function derivePsk(roomCode, secret) {
  if (!roomCode || !secret) {
    throw new Error('Both roomCode and secret are required');
  }
  return crypto
    .createHash('sha256')
    .update(`linktunnel-psk-v1:${String(roomCode).trim().toUpperCase()}:${String(secret)}`)
    .digest();
}

/**
 * Encodes an invite payload into a shareable `linktunnel://v1?...` URI.
 */
export function createInviteUri({ roomCode, secret, relayUrl = '', directEndpoints = [], name = '' }) {
  const payload = {
    v: PROTOCOL_VERSION,
    r: roomCode,
    s: secret,
    ...(relayUrl ? { relay: relayUrl } : {}),
    ...(directEndpoints?.length ? { direct: directEndpoints } : {}),
    ...(name ? { name } : {}),
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `linktunnel://v1?d=${encoded}`;
}

/**
 * Parses a `linktunnel://v1?d=...` invite URI or raw JSON invite string.
 */
export function parseInviteUri(input) {
  const raw = String(input || '').trim();
  if (!raw) throw new Error('Invite URI is empty');

  let payload;
  if (raw.startsWith('linktunnel://')) {
    const url = new URL(raw);
    const data = url.searchParams.get('d');
    if (!data) throw new Error('Invalid invite URI: missing data parameter');
    payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
  } else if (raw.startsWith('{')) {
    payload = JSON.parse(raw);
  } else {
    throw new Error('Unrecognized invite format (expected linktunnel:// URI)');
  }

  if (!payload.r || !payload.s) {
    throw new Error('Invite is missing room code or secret');
  }

  return {
    version: payload.v || 1,
    roomCode: String(payload.r).trim().toUpperCase(),
    secret: String(payload.s),
    relayUrl: payload.relay ? String(payload.relay) : '',
    directEndpoints: Array.isArray(payload.direct) ? payload.direct.map(String) : [],
    name: payload.name ? String(payload.name) : '',
  };
}

/**
 * Generates an ephemeral X25519 keypair and returns { privateKey, rawPublicKey (32 bytes) }.
 */
export function generateEphemeralX25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const rawPublicKey = spki.subarray(spki.length - 32);
  return { privateKey, rawPublicKey };
}

/**
 * Computes raw 32-byte X25519 ECDH shared secret from local privateKey and peer's raw 32-byte public key.
 */
export function computeX25519SharedSecret(privateKey, peerRawPublicKey) {
  if (!Buffer.isBuffer(peerRawPublicKey) || peerRawPublicKey.length !== 32) {
    throw new Error('Peer X25519 public key must be 32 bytes');
  }
  const spki = Buffer.concat([X25519_SPKI_PREFIX, peerRawPublicKey]);
  const peerKey = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return crypto.diffieHellman({ privateKey, publicKey: peerKey });
}

function hmacSha256(key, parts) {
  const h = crypto.createHmac('sha256', key);
  for (const part of parts) {
    h.update(part);
  }
  return h.digest();
}

function constantTimeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Serializes ClientHello handshake payload and verifies SharerHello.
 */
export class ClientHandshake {
  constructor({ roomCode, secret, deviceId, deviceName = 'Client' }) {
    this.psk = derivePsk(roomCode, secret);
    this.deviceId = Buffer.from(String(deviceId).slice(0, 32).padEnd(32, '0'), 'hex').subarray(0, 16);
    this.deviceName = String(deviceName).slice(0, 64);
    this.nonceC = crypto.randomBytes(32);
    const kp = generateEphemeralX25519();
    this.privateKey = kp.privateKey;
    this.ePubC = kp.rawPublicKey;
  }

  createHello() {
    const nameBuf = Buffer.from(this.deviceName, 'utf8');
    const macC = hmacSha256(this.psk, [
      Buffer.from('C2S-HELLO-V1'),
      this.deviceId,
      this.nonceC,
      this.ePubC,
      nameBuf,
    ]);
    return Buffer.concat([
      Buffer.from([PROTOCOL_VERSION, nameBuf.length]),
      this.deviceId,
      this.nonceC,
      this.ePubC,
      macC,
      nameBuf,
    ]);
  }

  processServerHello(buf) {
    // [ver:1][nameLen:1][sharerId:16][nonceS:32][ePubS:32][macS:32][name...]
    if (!Buffer.isBuffer(buf) || buf.length < 114) {
      throw new Error('Malformed server handshake');
    }
    const ver = buf[0];
    if (ver !== PROTOCOL_VERSION) {
      throw new Error(`Unsupported protocol version: ${ver}`);
    }
    const nameLen = buf[1];
    if (buf.length !== 114 + nameLen) {
      throw new Error('Corrupt server handshake length');
    }
    const sharerId = buf.subarray(2, 18);
    const nonceS = buf.subarray(18, 50);
    const ePubS = buf.subarray(50, 82);
    const macS = buf.subarray(82, 114);
    const nameBuf = buf.subarray(114);

    const expectedMac = hmacSha256(this.psk, [
      Buffer.from('S2C-HELLO-V1'),
      sharerId,
      nonceS,
      ePubS,
      this.nonceC,
      this.ePubC,
      nameBuf,
    ]);
    if (!constantTimeEqual(macS, expectedMac)) {
      throw new Error('Authentication failed: invalid secret or MITM attempt');
    }

    const sharedSecret = computeX25519SharedSecret(this.privateKey, ePubS);
    const session = deriveSessionCipher('client', sharedSecret, this.psk, this.nonceC, nonceS);
    return {
      peerId: sharerId.toString('hex'),
      peerName: nameBuf.toString('utf8') || 'Exit Node',
      cipher: session,
    };
  }
}

/**
 * Verifies ClientHello and produces SharerHello + derived E2EE session cipher.
 */
export class SharerHandshake {
  constructor({ roomCode, secret, deviceId, deviceName = 'Exit Node' }) {
    this.psk = derivePsk(roomCode, secret);
    this.deviceId = Buffer.from(String(deviceId).slice(0, 32).padEnd(32, '0'), 'hex').subarray(0, 16);
    this.deviceName = String(deviceName).slice(0, 64);
  }

  processClientHello(buf) {
    // [ver:1][nameLen:1][clientId:16][nonceC:32][ePubC:32][macC:32][name...]
    if (!Buffer.isBuffer(buf) || buf.length < 114) {
      throw new Error('Malformed client handshake');
    }
    const ver = buf[0];
    if (ver !== PROTOCOL_VERSION) {
      throw new Error(`Unsupported protocol version: ${ver}`);
    }
    const nameLen = buf[1];
    if (buf.length !== 114 + nameLen) {
      throw new Error('Corrupt client handshake length');
    }

    const clientId = buf.subarray(2, 18);
    const nonceC = buf.subarray(18, 50);
    const ePubC = buf.subarray(50, 82);
    const macC = buf.subarray(82, 114);
    const clientNameBuf = buf.subarray(114);

    const expectedMac = hmacSha256(this.psk, [
      Buffer.from('C2S-HELLO-V1'),
      clientId,
      nonceC,
      ePubC,
      clientNameBuf,
    ]);
    if (!constantTimeEqual(macC, expectedMac)) {
      throw new Error('Peer authentication failed: wrong invite secret');
    }

    const nonceS = crypto.randomBytes(32);
    const kp = generateEphemeralX25519();
    const sharerNameBuf = Buffer.from(this.deviceName, 'utf8');
    const macS = hmacSha256(this.psk, [
      Buffer.from('S2C-HELLO-V1'),
      this.deviceId,
      nonceS,
      kp.rawPublicKey,
      nonceC,
      ePubC,
      sharerNameBuf,
    ]);

    const response = Buffer.concat([
      Buffer.from([PROTOCOL_VERSION, sharerNameBuf.length]),
      this.deviceId,
      nonceS,
      kp.rawPublicKey,
      macS,
      sharerNameBuf,
    ]);

    const sharedSecret = computeX25519SharedSecret(kp.privateKey, ePubC);
    const cipher = deriveSessionCipher('sharer', sharedSecret, this.psk, nonceC, nonceS);

    return {
      response,
      peerId: clientId.toString('hex'),
      peerName: clientNameBuf.toString('utf8') || 'Peer',
      cipher,
    };
  }
}

function deriveSessionCipher(role, sharedSecret, psk, nonceC, nonceS) {
  const salt = crypto.createHash('sha256').update(nonceC).update(nonceS).update(psk).digest();
  const keyMaterial = Buffer.from(
    crypto.hkdfSync('sha256', sharedSecret, salt, Buffer.from('linktunnel-session-v1'), 80)
  );

  const c2sKey = keyMaterial.subarray(0, 32);
  const s2cKey = keyMaterial.subarray(32, 64);
  const c2sIvPrefix = keyMaterial.subarray(64, 68);
  const s2cIvPrefix = keyMaterial.subarray(68, 72);
  const safetyBytes = keyMaterial.subarray(72, 80);

  const safetyCode = `${safetyBytes.subarray(0, 2).toString('hex').toUpperCase()}-${safetyBytes
    .subarray(2, 4)
    .toString('hex')
    .toUpperCase()}`;

  if (role === 'client') {
    return new SessionCipher({
      sendKey: c2sKey,
      recvKey: s2cKey,
      sendIvPrefix: c2sIvPrefix,
      recvIvPrefix: s2cIvPrefix,
      safetyCode,
    });
  }
  return new SessionCipher({
    sendKey: s2cKey,
    recvKey: c2sKey,
    sendIvPrefix: s2cIvPrefix,
    recvIvPrefix: c2sIvPrefix,
    safetyCode,
  });
}

/**
 * Stateful authenticated encryption cipher for multiplexed frames.
 * Format: [seq: 8B uint64BE][ciphertext: N][authTag: 16B]
 */
export class SessionCipher {
  constructor({ sendKey, recvKey, sendIvPrefix, recvIvPrefix, safetyCode }) {
    this.sendKey = Buffer.from(sendKey);
    this.recvKey = Buffer.from(recvKey);
    this.sendIvPrefix = Buffer.from(sendIvPrefix);
    this.recvIvPrefix = Buffer.from(recvIvPrefix);
    this.safetyCode = safetyCode;
    this.sendSeq = 0n;
    this.recvSeq = 0n;
  }

  encrypt(plaintext) {
    const seq = this.sendSeq++;
    const seqBuf = Buffer.allocUnsafe(8);
    seqBuf.writeBigUInt64BE(seq, 0);

    const nonce = Buffer.concat([this.sendIvPrefix, seqBuf]);
    const cipher = crypto.createCipheriv(CIPHER_NAME, this.sendKey, nonce, { authTagLength: 16 });
    cipher.setAAD(seqBuf);
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([seqBuf, enc, tag]);
  }

  decrypt(packet) {
    if (!Buffer.isBuffer(packet) || packet.length < 24) {
      throw new Error('Encrypted packet too short');
    }
    const seqBuf = packet.subarray(0, 8);
    const seq = seqBuf.readBigUInt64BE(0);
    if (seq !== this.recvSeq) {
      throw new Error(`Replay or out-of-order frame detected (expected ${this.recvSeq}, got ${seq})`);
    }

    const ciphertext = packet.subarray(8, packet.length - 16);
    const tag = packet.subarray(packet.length - 16);
    const nonce = Buffer.concat([this.recvIvPrefix, seqBuf]);

    const decipher = crypto.createDecipheriv(CIPHER_NAME, this.recvKey, nonce, { authTagLength: 16 });
    decipher.setAAD(seqBuf);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    this.recvSeq++;
    return plain;
  }
}
