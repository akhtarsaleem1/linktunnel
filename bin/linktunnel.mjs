#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { ConfigStore } from '../src/config/store.mjs';
import { ClientNode } from '../src/node/client.mjs';
import { UnifiedProxyServer } from '../src/node/proxy.mjs';
import { SharerNode } from '../src/node/sharer.mjs';
import { enableWindowsSystemProxy, restoreWindowsSystemProxy } from '../src/platform/win-proxy.mjs';
import { RelayServer } from '../src/relay/server.mjs';
import { LinkTunnelApp } from '../src/web/server.mjs';

function parseArgs(argv, defaultCommand = 'ui') {
  const args = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const eq = token.indexOf('=');
      if (eq !== -1) {
        flags[token.slice(2, eq)] = token.slice(eq + 1);
      } else {
        const key = token.slice(2);
        const next = argv[i + 1];
        if (next && !next.startsWith('--')) {
          flags[key] = next;
          i++;
        } else {
          flags[key] = true;
        }
      }
    } else {
      args.push(token);
    }
  }
  return { command: args[0] || defaultCommand, positional: args.slice(1), flags };
}

function openBrowser(url) {
  if (process.platform === 'win32') {
    spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' }).unref();
  } else if (process.platform === 'darwin') {
    spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
  } else {
    spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
  }
}

function printHelp() {
  console.log(`
LinkTunnel — Long-Distance E2EE Internet Sharing Tunnel

Usage:
  linktunnel ui [--port 4321] [--host 127.0.0.1] [--no-open]
      Start the interactive Web Dashboard & local SOCKS5/HTTP proxy.

  linktunnel relay [--port 4320] [--host 0.0.0.0]
      Run the zero-knowledge Relay & Signaling server (deploy on VPS/cloud).

  linktunnel share [--relay wss://...] [--direct-port 4322] [--room LT-XXXX] [--secret ...] [--max-mbps 0] [--allow-lan]
      Share this device's internet connection and print an Invite URI.

  linktunnel connect <inviteUri> [--mode hybrid|relay|direct] [--proxy-port 10808] [--lan] [--system-proxy]
      Connect to a remote Exit Node and expose local SOCKS5 + HTTP proxy.
`);
}

async function runUi(flags) {
  const port = Number(flags.port || flags['ui-port'] || process.env.PORT || 4321);
  const host = String(flags.host || flags['ui-host'] || '127.0.0.1');
  const app = new LinkTunnelApp({ uiHost: host, uiPort: port });
  const info = await app.start();

  console.log(`LinkTunnel Dashboard running at ${info.url}`);
  console.log(`Unified SOCKS5 + HTTP Proxy listening on 127.0.0.1:${app.proxyServer.port}`);

  if (!flags['no-open'] && process.env.LINKTUNNEL_NO_OPEN !== '1') {
    openBrowser(info.url);
  }

  const shutdown = async () => {
    console.log('\nShutting down LinkTunnel...');
    await app.stop();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

async function runRelay(flags) {
  const port = Number(flags.port || process.env.PORT || 4320);
  const host = String(flags.host || '0.0.0.0');
  const relay = new RelayServer({ host, port });
  const info = await relay.start();
  const connectHost = info.host === '0.0.0.0' || info.host === '::' ? '127.0.0.1' : info.host;
  console.log(`LinkTunnel E2EE Relay bound on ${info.host}:${info.port}`);
  console.log(`Local Relay URL : ws://${connectHost}:${info.port}/relay`);
  console.log(`Health endpoint : http://${connectHost}:${info.port}/health`);

  const shutdown = async () => {
    await relay.stop();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

async function runShare(flags) {
  const store = new ConfigStore();
  const cfg = store.get();
  const maxMbps = Number(flags['max-mbps'] || 0);
  const sharer = new SharerNode({
    deviceId: cfg.deviceId,
    deviceName: String(flags.name || cfg.deviceName),
    roomCode: flags.room || null,
    secret: flags.secret || null,
    relayUrl: flags.relay ? String(flags.relay) : '',
    enableDirect: flags['no-direct'] ? false : true,
    directPort: Number(flags['direct-port'] || 4322),
    publicDirectHost: flags['public-host'] ? String(flags['public-host']) : '',
    blockPrivateNetwork: !flags['allow-lan'],
    maxBandwidthBps: maxMbps > 0 ? Math.floor((maxMbps * 1_000_000) / 8) : 0,
  });

  sharer.on('log', (l) => console.log(`[${l.level.toUpperCase()}] ${l.message}`));
  const state = await sharer.start();
  console.log('\n=== Share Session Ready ===');
  console.log(`Pair Code : ${state.roomCode}`);
  console.log(`Secret    : ${state.secret}`);
  console.log(`Invite URI: ${state.inviteUri}`);
  console.log('===========================\n');

  const shutdown = async () => {
    await sharer.stop();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

async function runConnect(positional, flags) {
  const inviteUri = positional[0] || flags.invite || '';
  const store = new ConfigStore();
  const cfg = store.get();
  const client = new ClientNode({
    deviceId: cfg.deviceId,
    deviceName: String(flags.name || cfg.deviceName),
  });
  client.on('log', (l) => console.log(`[${l.level.toUpperCase()}] ${l.message}`));

  const proxy = new UnifiedProxyServer({
    clientNode: client,
    host: flags.lan ? '0.0.0.0' : '127.0.0.1',
    port: Number(flags['proxy-port'] || cfg.proxyPort || 10808),
  });
  await proxy.start();

  await client.connect({
    inviteUri: inviteUri || undefined,
    roomCode: flags.room,
    secret: flags.secret,
    relayUrl: flags.relay,
    directEndpoints: flags.direct ? [String(flags.direct)] : [],
    mode: String(flags.mode || 'hybrid'),
  });

  let sysBackup = null;
  if (flags['system-proxy'] && process.platform === 'win32') {
    const res = await enableWindowsSystemProxy(proxy.port, cfg.winProxyBackup);
    sysBackup = res.backup;
    store.update({ winProxyBackup: sysBackup, winProxyManaged: true });
    console.log(`Windows System Proxy enabled -> 127.0.0.1:${proxy.port}`);
  }

  console.log(`Unified SOCKS5 + HTTP Proxy ready on ${proxy.host}:${proxy.port}`);

  const shutdown = async () => {
    if (sysBackup || store.get().winProxyManaged) {
      await restoreWindowsSystemProxy(sysBackup || store.get().winProxyBackup).catch(() => {});
      store.update({ winProxyManaged: false, winProxyBackup: null });
    }
    client.disconnect();
    await proxy.stop();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

const isCloudRelayEnv =
  process.env.RENDER === 'true' ||
  Boolean(process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_SERVICE_ID || process.env.FLY_APP_NAME);
const defaultCommand = isCloudRelayEnv ? 'relay' : 'ui';
const { command, positional, flags } = parseArgs(process.argv.slice(2), defaultCommand);

if (flags.help || flags.h || command === 'help') {
  printHelp();
  process.exit(0);
}

if (command === 'ui') {
  runUi(flags).catch((err) => {
    console.error(err);
    process.exit(1);
  });
} else if (command === 'relay') {
  runRelay(flags).catch((err) => {
    console.error(err);
    process.exit(1);
  });
} else if (command === 'share') {
  runShare(flags).catch((err) => {
    console.error(err);
    process.exit(1);
  });
} else if (command === 'connect') {
  runConnect(positional, flags).catch((err) => {
    console.error(err);
    process.exit(1);
  });
} else {
  printHelp();
  process.exit(1);
}
