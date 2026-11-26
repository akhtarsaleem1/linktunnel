import EventEmitter from 'node:events';
import http from 'node:http';
import { acceptWsUpgrade } from '../protocol/ws.mjs';

/**
 * Wraps a binary payload with a 4-byte sessionId header for Sharer <-> Relay multiplexing.
 */
export function wrapRelayPacket(sessionId, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const out = Buffer.allocUnsafe(4 + body.length);
  out.writeUInt32BE(sessionId >>> 0, 0);
  if (body.length > 0) body.copy(out, 4);
  return out;
}

export function unwrapRelayPacket(packet) {
  if (!Buffer.isBuffer(packet) || packet.length < 4) {
    throw new Error('Relay packet too short');
  }
  return {
    sessionId: packet.readUInt32BE(0),
    payload: packet.subarray(4),
  };
}

/**
 * Zero-knowledge E2EE Relay & Signaling Server.
 * Routes opaque E2EE binary frames between Sharers (Exit Nodes) and Clients.
 */
export class RelayServer extends EventEmitter {
  constructor({ host = '0.0.0.0', port = 4320, maxRooms = 5000 } = {}) {
    super();
    this.host = host;
    this.port = port;
    this.maxRooms = maxRooms;
    this.rooms = new Map(); // roomHash -> { sharerWs, sharerToken, directHints, deviceName, observedIp, clients: Map<sessionId, ws> }
    this.nextSessionId = 1;
    this.bytesRelayed = 0;
    this.startedAt = null;
    this.server = null;
  }

  start() {
    if (this.server) return Promise.resolve({ port: this.port, host: this.host });

    this.startedAt = Date.now();
    this.server = http.createServer((req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      if (url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(this.getStats()));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          service: 'LinkTunnel E2EE Relay',
          protocol: 1,
          wsEndpoint: '/relay',
          ...this.getStats(),
        })
      );
    });

    this.server.on('upgrade', (req, socket, head) => {
      const ws = acceptWsUpgrade(req, socket, head);
      if (!ws) return;
      this._attachConnection(ws, req);
    });

    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, this.host, () => {
        this.server.removeListener('error', reject);
        const addr = this.server.address();
        this.port = typeof addr === 'object' && addr ? addr.port : this.port;
        this.emit('listening', { host: this.host, port: this.port });
        resolve({ host: this.host, port: this.port });
      });
    });
  }

  getStats() {
    let activeClients = 0;
    let activeSharers = 0;
    for (const room of this.rooms.values()) {
      if (room.sharerWs) activeSharers++;
      activeClients += room.clients.size;
    }
    return {
      ok: true,
      rooms: this.rooms.size,
      activeSharers,
      activeClients,
      bytesRelayed: this.bytesRelayed,
      uptimeSec: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
    };
  }

  _getOrCreateRoom(roomHash) {
    let room = this.rooms.get(roomHash);
    if (!room) {
      if (this.rooms.size >= this.maxRooms) {
        return null;
      }
      room = {
        roomHash,
        sharerWs: null,
        sharerToken: null,
        directHints: [],
        deviceName: '',
        observedIp: '',
        clients: new Map(),
      };
      this.rooms.set(roomHash, room);
    }
    return room;
  }

  _cleanupRoomIfEmpty(roomHash) {
    const room = this.rooms.get(roomHash);
    if (room && !room.sharerWs && room.clients.size === 0) {
      this.rooms.delete(roomHash);
    }
  }

  _attachConnection(ws, req) {
    const remoteIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || ws.remoteAddress || '';
    let role = null; // 'sharer' | 'client'
    let currentRoomHash = null;
    let clientSessionId = null;

    // Keep-alive WebSocket ping every 25s so cloud proxies (Render, Cloudflare, Nginx) don't drop idle sockets
    const keepAliveTimer = setInterval(() => {
      if (!ws.closed) ws.ping();
    }, 25000);
    keepAliveTimer.unref?.();

    ws.on('message', (data, isBinary) => {
      if (!isBinary) {
        let msg;
        try {
          msg = JSON.parse(data);
        } catch {
          ws.sendJson({ type: 'error', message: 'Invalid JSON control frame' });
          return;
        }

        if (msg.type === 'register_sharer') {
          const roomHash = String(msg.roomHash || '').trim();
          const sharerToken = String(msg.sharerToken || '').trim();
          if (!roomHash || !sharerToken) {
            ws.sendJson({ type: 'error', message: 'roomHash and sharerToken required' });
            return;
          }
          const room = this._getOrCreateRoom(roomHash);
          if (!room) {
            ws.sendJson({ type: 'error', message: 'Relay room capacity reached' });
            return;
          }
          if (room.sharerWs && room.sharerToken !== sharerToken) {
            ws.sendJson({ type: 'error', message: 'Room already claimed by another sharer' });
            return;
          }
          if (room.sharerWs && room.sharerWs !== ws) {
            try {
              room.sharerWs.close(1000, 'Replaced by reconnecting sharer');
            } catch {
              // ignore
            }
          }

          role = 'sharer';
          currentRoomHash = roomHash;
          room.sharerWs = ws;
          room.sharerToken = sharerToken;
          room.directHints = Array.isArray(msg.directHints) ? msg.directHints.slice(0, 8) : [];
          room.deviceName = String(msg.deviceName || '').slice(0, 64);
          room.observedIp = remoteIp;

          ws.sendJson({
            type: 'sharer_registered',
            roomHash,
            observedIp: remoteIp,
          });

          // Notify any waiting clients in the room that sharer came online
          for (const [sid, clientWs] of room.clients.entries()) {
            clientWs.sendJson({
              type: 'sharer_online',
              sessionId: sid,
              directHints: room.directHints,
            });
            ws.sendJson({ type: 'client_joined', sessionId: sid });
          }
          return;
        }

        if (msg.type === 'update_hints' && role === 'sharer' && currentRoomHash) {
          const room = this.rooms.get(currentRoomHash);
          if (room && room.sharerWs === ws) {
            room.directHints = Array.isArray(msg.directHints) ? msg.directHints.slice(0, 8) : [];
          }
          return;
        }

        if (msg.type === 'kick_session' && role === 'sharer' && currentRoomHash) {
          const room = this.rooms.get(currentRoomHash);
          const sid = Number(msg.sessionId);
          const target = room?.clients.get(sid);
          if (target) {
            room.clients.delete(sid);
            target.close(4001, String(msg.reason || 'Disconnected by sharer'));
          }
          return;
        }

        if (msg.type === 'join_room') {
          const roomHash = String(msg.roomHash || '').trim();
          if (!roomHash) {
            ws.sendJson({ type: 'error', message: 'roomHash required' });
            return;
          }
          const room = this._getOrCreateRoom(roomHash);
          if (!room) {
            ws.sendJson({ type: 'error', message: 'Relay room capacity reached' });
            return;
          }
          role = 'client';
          currentRoomHash = roomHash;
          clientSessionId = this.nextSessionId++;
          room.clients.set(clientSessionId, ws);

          ws.sendJson({
            type: 'room_joined',
            sessionId: clientSessionId,
            sharerOnline: Boolean(room.sharerWs),
            directHints: room.directHints,
          });

          if (room.sharerWs) {
            room.sharerWs.sendJson({ type: 'client_joined', sessionId: clientSessionId });
          }
          return;
        }

        return;
      }

      // Binary forwarding (zero-knowledge opaque E2EE payload)
      if (!currentRoomHash) return;
      const room = this.rooms.get(currentRoomHash);
      if (!room) return;

      if (role === 'client' && clientSessionId) {
        if (!room.sharerWs) return;
        this.bytesRelayed += data.length;
        const wrapped = wrapRelayPacket(clientSessionId, data);
        const ok = room.sharerWs.send(wrapped, true);
        if (!ok) ws.pause();
      } else if (role === 'sharer') {
        let sid, payload;
        try {
          ({ sessionId: sid, payload } = unwrapRelayPacket(data));
        } catch {
          return;
        }
        const target = room.clients.get(sid);
        if (!target) return;
        this.bytesRelayed += payload.length;
        const ok = target.send(payload, true);
        if (!ok) ws.pause();
      }
    });

    ws.on('drain', () => {
      if (!currentRoomHash) return;
      const room = this.rooms.get(currentRoomHash);
      if (!room) return;
      if (role === 'sharer') {
        for (const c of room.clients.values()) c.resume();
      } else if (role === 'client' && room.sharerWs) {
        room.sharerWs.resume();
      }
    });

    const onDisconnect = () => {
      clearInterval(keepAliveTimer);
      if (!currentRoomHash) return;
      const room = this.rooms.get(currentRoomHash);
      if (!room) return;

      if (role === 'sharer' && room.sharerWs === ws) {
        room.sharerWs = null;
        for (const [sid, clientWs] of room.clients.entries()) {
          try {
            clientWs.sendJson({ type: 'sharer_offline', sessionId: sid });
          } catch {
            // ignore
          }
        }
      } else if (role === 'client' && clientSessionId) {
        if (room.clients.delete(clientSessionId) && room.sharerWs) {
          try {
            room.sharerWs.sendJson({ type: 'client_left', sessionId: clientSessionId });
          } catch {
            // ignore
          }
        }
      }
      this._cleanupRoomIfEmpty(currentRoomHash);
    };

    ws.on('close', onDisconnect);
    ws.on('error', onDisconnect);
  }

  async stop() {
    if (!this.server) return;
    for (const room of this.rooms.values()) {
      room.sharerWs?.destroy();
      for (const clientWs of room.clients.values()) {
        clientWs.destroy();
      }
    }
    this.rooms.clear();
    await new Promise((resolve) => this.server.close(() => resolve()));
    this.server = null;
  }
}
