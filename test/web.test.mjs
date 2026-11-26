import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { connectWs } from '../src/protocol/ws.mjs';
import { LinkTunnelApp } from '../src/web/server.mjs';

test('Web Dashboard API orchestrates relay, sharer, client, WS feed, and QR SVG cleanly', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'linktunnel-test-'));
  const app = new LinkTunnelApp({ uiHost: '127.0.0.1', uiPort: 0, dataDir: tmpDir });
  // Ensure ephemeral proxy port in tests
  app.proxyServer.port = 0;

  const { url, port } = await app.start();
  let uiWs = null;
  try {
    const post = async (p, body = {}) => {
      const r = await fetch(`${url}${p}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      return r.json();
    };

    const htmlRes = await fetch(`${url}/`);
    assert.equal(htmlRes.status, 200);
    const html = await htmlRes.text();
    assert.ok(html.includes('LinkTunnel'));

    const cssRes = await fetch(`${url}/styles.css`);
    assert.equal(cssRes.status, 200);
    assert.match(cssRes.headers.get('content-type'), /text\/css/);

    const jsRes = await fetch(`${url}/app.js`);
    assert.equal(jsRes.status, 200);
    assert.match(jsRes.headers.get('content-type'), /javascript/);

    // Verify WebSocket live dashboard feed
    uiWs = await connectWs(`ws://127.0.0.1:${port}/ws`);
    const initialMsg = await new Promise((resolve) => {
      uiWs.once('message', (data) => resolve(JSON.parse(data)));
    });
    assert.equal(initialMsg.type, 'state');
    assert.equal(initialMsg.data.sharer.running, false);

    // Start local relay
    const relayRes = await post('/api/relay/start', { port: 0 });
    assert.equal(relayRes.ok, true);
    const relayPort = relayRes.data.relay.port;
    assert.ok(relayPort > 0);

    // Start sharing
    const shareRes = await post('/api/share/start', {
      relayUrl: `ws://127.0.0.1:${relayPort}/relay`,
      directPort: 0,
      maxBandwidthMbps: 10,
      maxQuotaMb: 500,
    });
    assert.equal(shareRes.ok, true, `shareRes failed: ${JSON.stringify(shareRes)}`);
    assert.equal(shareRes.data.sharer.running, true);
    assert.ok(shareRes.data.sharer.inviteUri.startsWith('linktunnel://v1?d='));

    // Fetch QR SVG for invite
    const qrRes = await fetch(`${url}/api/qr?text=${encodeURIComponent(shareRes.data.sharer.inviteUri)}`);
    assert.equal(qrRes.status, 200);
    assert.equal(qrRes.headers.get('content-type'), 'image/svg+xml');

    // Connect client to our own share via relay/hybrid
    const connRes = await post('/api/client/connect', {
      inviteUri: shareRes.data.sharer.inviteUri,
      mode: 'hybrid',
    });
    assert.equal(connRes.ok, true);
    assert.equal(connRes.data.client.status, 'connected');
    assert.equal(connRes.data.savedPeers.length, 1);

    // Disconnect and stop
    const discRes = await post('/api/client/disconnect');
    assert.equal(discRes.data.client.status, 'disconnected');

    const stopShareRes = await post('/api/share/stop');
    assert.equal(stopShareRes.data.sharer.running, false);
  } finally {
    uiWs?.destroy();
    await app.stop();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
