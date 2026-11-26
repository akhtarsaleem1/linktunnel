import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateDeviceId } from '../crypto/e2ee.mjs';

export function resolveDataDir(customDir = null) {
  if (customDir) return customDir;
  if (process.env.LINKTUNNEL_DATA_DIR) return process.env.LINKTUNNEL_DATA_DIR;
  return path.join(os.homedir(), '.linktunnel');
}

export class ConfigStore {
  constructor(dataDir = null) {
    this.dataDir = resolveDataDir(dataDir);
    this.configPath = path.join(this.dataDir, 'config.json');
    this.data = this._load();
  }

  _defaultData() {
    return {
      deviceId: generateDeviceId(),
      deviceName: os.hostname() || 'My-Device',
      defaultRelayUrl: '',
      proxyPort: 10808,
      directPort: 4322,
      relayPort: 4320,
      savedPeers: [],
      winProxyBackup: null,
      winProxyManaged: false,
    };
  }

  _load() {
    try {
      if (fs.existsSync(this.configPath)) {
        const parsed = JSON.parse(fs.readFileSync(this.configPath, 'utf8'));
        return { ...this._defaultData(), ...parsed };
      }
    } catch {
      // fall through to defaults
    }
    const defaults = this._defaultData();
    this._write(defaults);
    return defaults;
  }

  _write(nextData) {
    fs.mkdirSync(this.dataDir, { recursive: true });
    fs.writeFileSync(this.configPath, JSON.stringify(nextData, null, 2), 'utf8');
  }

  get() {
    return { ...this.data };
  }

  update(partial) {
    this.data = { ...this.data, ...partial };
    this._write(this.data);
    return this.get();
  }

  savePeer(peer) {
    const existing = this.data.savedPeers.filter((p) => p.roomCode !== peer.roomCode);
    const entry = {
      name: peer.name || peer.roomCode,
      roomCode: peer.roomCode,
      secret: peer.secret,
      relayUrl: peer.relayUrl || '',
      directEndpoints: peer.directEndpoints || [],
      mode: peer.mode || 'hybrid',
      updatedAt: Date.now(),
    };
    this.data.savedPeers = [entry, ...existing].slice(0, 20);
    this._write(this.data);
    return this.data.savedPeers;
  }

  removePeer(roomCode) {
    this.data.savedPeers = this.data.savedPeers.filter((p) => p.roomCode !== roomCode);
    this._write(this.data);
    return this.data.savedPeers;
  }
}
