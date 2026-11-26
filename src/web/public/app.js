const $ = (id) => document.getElementById(id);

let latestState = null;

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatRate(bps) {
  return `${formatBytes(bps)}/s`;
}

function showToast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => {
    el.hidden = true;
  }, 3000);
}

async function api(url, method = 'GET', body = null) {
  const opts = { method, headers: {} };
  if (body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok || !data.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  if (data.data) renderState(data.data);
  return data;
}

function renderSparkline(history = []) {
  const svg = $('sparklineSvg');
  if (!history.length) {
    svg.innerHTML = '';
    return;
  }
  const w = 280;
  const h = 44;
  const maxVal = Math.max(1024, ...history.map((s) => Math.max(s.rxBps, s.txBps)));
  const stepX = history.length > 1 ? w / (history.length - 1) : w;

  const buildPoints = (key) =>
    history
      .map((s, idx) => {
        const x = (idx * stepX).toFixed(1);
        const y = (h - 4 - (s[key] / maxVal) * (h - 8)).toFixed(1);
        return `${x},${y}`;
      })
      .join(' ');

  const rxPts = buildPoints('rxBps');
  const txPts = buildPoints('txBps');
  svg.innerHTML = `
    <polyline fill="none" stroke="#38bdf8" stroke-width="2" points="${rxPts}" />
    <polyline fill="none" stroke="#10b981" stroke-width="1.5" stroke-dasharray="3 2" points="${txPts}" />
  `;
}

function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderState(state) {
  latestState = state;
  const { device, sharer, client, proxy, relay, systemProxy, lanIps, savedPeers, logs } = state;

  if (document.activeElement !== $('deviceNameInput')) {
    $('deviceNameInput').value = device.deviceName || '';
  }

  // Relay button
  const relayBtn = $('relayToggleBtn');
  if (relay.running) {
    relayBtn.textContent = `Stop Local Relay (:${relay.port})`;
    relayBtn.className = 'btn btn-emerald btn-sm';
  } else {
    relayBtn.textContent = 'Start Local Relay';
    relayBtn.className = 'btn btn-secondary btn-sm';
  }

  // Global status pill
  const statusPill = $('globalStatusPill');
  const statusText = $('globalStatusText');
  if (client.status === 'connected') {
    statusPill.className = 'status-pill status-connected';
    statusText.textContent = `Connected (${client.activeTransport?.toUpperCase() || 'TUNNEL'})`;
  } else if (client.status === 'connecting' || client.status === 'reconnecting') {
    statusPill.className = 'status-pill status-connecting';
    statusText.textContent = client.status === 'reconnecting' ? 'Reconnecting...' : 'Connecting...';
  } else if (sharer.running) {
    statusPill.className = 'status-pill status-sharing';
    statusText.textContent = `Sharing (${sharer.peers.length} peer${sharer.peers.length === 1 ? '' : 's'})`;
  } else if (client.status === 'error') {
    statusPill.className = 'status-pill status-error';
    statusText.textContent = 'Error';
  } else {
    statusPill.className = 'status-pill status-idle';
    statusText.textContent = 'Ready';
  }

  // Topology & telemetry
  $('topoLocalName').textContent = device.deviceName || 'This Device';
  $('topoProxyAddr').textContent = `Proxy ${proxy.host}:${proxy.port}`;
  $('topoRemoteName').textContent = client.status === 'connected' ? client.peerName || client.roomCode : 'Not Connected';
  $('topoExitIp').textContent = client.exitIp ? `Exit IP: ${client.exitIp}` : 'Exit IP: —';

  const linkEl = $('topoLinkVisual');
  if (client.status === 'connected') {
    linkEl.classList.add('active');
    $('topoTransportBadge').textContent = client.activeTransport === 'direct' ? 'Direct P2P' : 'Relay Tunnel';
    $('topoSafetyBadge').hidden = !client.safetyCode;
    $('topoSafetyBadge').textContent = `Safety ${client.safetyCode}`;
    $('topoRtt').textContent = client.rttMs !== null ? `RTT: ${client.rttMs} ms` : 'RTT: —';
    $('topoStreams').textContent = `Streams: ${client.activeStreams}`;
  } else {
    linkEl.classList.remove('active');
    $('topoTransportBadge').textContent = client.status === 'connecting' ? 'Connecting...' : 'Idle';
    $('topoSafetyBadge').hidden = true;
    $('topoRtt').textContent = 'RTT: —';
    $('topoStreams').textContent = 'Streams: 0';
  }

  const totalRxRate = (client.rxBps || 0) + (sharer.rxBps || 0);
  const totalTxRate = (client.txBps || 0) + (sharer.txBps || 0);
  $('metricRxRate').textContent = formatRate(totalRxRate);
  $('metricTxRate').textContent = formatRate(totalTxRate);
  $('metricRxTotal').textContent = `Total ${formatBytes((client.totalBytesRx || 0) + (sharer.totalBytesRx || 0))}`;
  $('metricTxTotal').textContent = `Total ${formatBytes((client.totalBytesTx || 0) + (sharer.totalBytesTx || 0))}`;
  renderSparkline(client.speedHistory);

  // Sharer card
  const sharerBadge = $('sharerBadge');
  if (sharer.running) {
    sharerBadge.textContent = sharer.paused ? 'Paused' : 'Sharing Active';
    sharerBadge.className = sharer.paused ? 'pill pill-warn' : 'pill pill-on';
    $('startShareBtn').hidden = true;
    $('pauseShareBtn').hidden = false;
    $('pauseShareBtn').textContent = sharer.paused ? 'Resume' : 'Pause';
    $('stopShareBtn').hidden = false;
    $('shareActiveBox').hidden = false;

    $('activeRoomCode').textContent = sharer.roomCode;
    $('activeSecret').textContent = sharer.secret;
    $('activeRelayStatus').textContent = sharer.relayUrl
      ? sharer.relayConnected
        ? `Connected (${sharer.relayUrl})`
        : `Reconnecting (${sharer.relayUrl})`
      : 'Direct Only (no relay configured)';
    $('activeShareTraffic').textContent = `${formatBytes(sharer.totalBytesTx)} sent / ${formatBytes(
      sharer.totalBytesRx
    )} recv`;

    if ($('activeInviteUri').value !== sharer.inviteUri) {
      $('activeInviteUri').value = sharer.inviteUri;
      $('shareQrImg').src = `/api/qr?text=${encodeURIComponent(sharer.inviteUri)}`;
    }

    $('connectedPeerCount').textContent = String(sharer.peers.length);
    const peersEl = $('connectedPeersList');
    if (sharer.peers.length === 0) {
      peersEl.innerHTML = '<div class="empty-state">Waiting for remote devices to connect...</div>';
    } else {
      peersEl.innerHTML = sharer.peers
        .map(
          (p) => `
          <div class="peer-item">
            <div>
              <strong>${escapeHtml(p.peerName)}</strong>
              <span class="badge">${escapeHtml(p.source.toUpperCase())}</span>
              <span class="badge">Safety ${escapeHtml(p.safetyCode)}</span>
              <div class="peer-meta">
                Streams: ${p.activeStreams} • Sent ${formatBytes(p.bytesTx)} • Recv ${formatBytes(p.bytesRx)}
              </div>
            </div>
            <button class="btn btn-danger btn-sm kick-btn" data-key="${escapeHtml(p.key)}">Kick</button>
          </div>`
        )
        .join('');
      for (const btn of peersEl.querySelectorAll('.kick-btn')) {
        btn.onclick = () => api('/api/share/kick', 'POST', { peerKey: btn.dataset.key }).catch((e) => showToast(e.message));
      }
    }
  } else {
    sharerBadge.textContent = 'Offline';
    sharerBadge.className = 'pill pill-off';
    $('startShareBtn').hidden = false;
    $('pauseShareBtn').hidden = true;
    $('stopShareBtn').hidden = true;
    $('shareActiveBox').hidden = true;
  }

  // Client card
  const clientBadge = $('clientBadge');
  const connectedOrBusy = client.status === 'connected' || client.status === 'connecting' || client.status === 'reconnecting';
  if (client.status === 'connected') {
    clientBadge.textContent = `Connected (${client.activeTransport})`;
    clientBadge.className = 'pill pill-on';
  } else if (client.status === 'connecting' || client.status === 'reconnecting') {
    clientBadge.textContent = client.status;
    clientBadge.className = 'pill pill-warn';
  } else if (client.status === 'error') {
    clientBadge.textContent = 'Error';
    clientBadge.className = 'pill pill-warn';
  } else {
    clientBadge.textContent = 'Disconnected';
    clientBadge.className = 'pill pill-off';
  }
  $('connectBtn').hidden = connectedOrBusy;
  $('disconnectBtn').hidden = !connectedOrBusy;
  $('checkExitIpBtn').hidden = client.status !== 'connected';

  // Saved peers
  const savedSec = $('savedPeersSection');
  if (savedPeers && savedPeers.length > 0) {
    savedSec.hidden = false;
    $('savedPeersChips').innerHTML = savedPeers
      .map(
        (p) => `
        <span class="peer-chip" data-room="${escapeHtml(p.roomCode)}">
          <span>${escapeHtml(p.name || p.roomCode)}</span>
          <span class="del-chip" data-del="${escapeHtml(p.roomCode)}" title="Remove">×</span>
        </span>`
      )
      .join('');
    for (const chip of $('savedPeersChips').querySelectorAll('.peer-chip')) {
      chip.onclick = (ev) => {
        if (ev.target.dataset.del) {
          ev.stopPropagation();
          api(`/api/peers/${encodeURIComponent(ev.target.dataset.del)}`, 'DELETE').catch((e) => showToast(e.message));
          return;
        }
        const peer = savedPeers.find((x) => x.roomCode === chip.dataset.room);
        if (!peer) return;
        $('connectInviteUri').value = '';
        $('connectRoomCode').value = peer.roomCode;
        $('connectSecret').value = peer.secret;
        $('connectRelayUrl').value = peer.relayUrl || '';
        $('connectDirectUrl').value = (peer.directEndpoints && peer.directEndpoints[0]) || '';
        $('connectMode').value = peer.mode || 'hybrid';
        showToast(`Loaded "${peer.name}" — click Connect to Tunnel`);
      };
    }
  } else {
    savedSec.hidden = true;
  }

  // Proxy & System Proxy
  $('proxyEndpointCode').textContent = `${proxy.host}:${proxy.port}`;
  $('lanExposeCheck').checked = Boolean(proxy.lanExposed);
  const sysBtn = $('toggleSysProxyBtn');
  if (state.platform !== 'win32') {
    sysBtn.disabled = true;
    sysBtn.textContent = 'System Proxy (Manual on Linux/macOS)';
  } else if (systemProxy.managedByApp || (systemProxy.enabled && systemProxy.proxyServer === `127.0.0.1:${proxy.port}`)) {
    sysBtn.disabled = false;
    sysBtn.textContent = 'Disable Windows System Proxy';
    sysBtn.className = 'btn btn-emerald btn-sm';
  } else if (client.status !== 'connected') {
    sysBtn.disabled = true;
    sysBtn.textContent = 'Enable Windows System Proxy (Connect first)';
    sysBtn.className = 'btn btn-secondary btn-sm';
  } else {
    sysBtn.disabled = false;
    sysBtn.textContent = 'Enable Windows System Proxy';
    sysBtn.className = 'btn btn-secondary btn-sm';
  }

  const mobileBox = $('mobileSetupBox');
  if (proxy.lanExposed && lanIps.length > 0) {
    mobileBox.hidden = false;
    const lanIp = lanIps[0].address;
    const pacUrl = `http://${lanIp}:${proxy.port}/proxy.pac`;
    $('lanProxyHost').textContent = lanIp;
    $('lanProxyPort').textContent = String(proxy.port);
    $('lanPacUrl').textContent = pacUrl;
    const qrSrc = `/api/qr?text=${encodeURIComponent(pacUrl)}`;
    if (!$('mobileQrImg').src.endsWith(qrSrc)) {
      $('mobileQrImg').src = qrSrc;
    }
  } else {
    mobileBox.hidden = true;
  }

  // Logs
  const logEl = $('logFeed');
  if (!logs || logs.length === 0) {
    logEl.innerHTML = '<div class="log-entry muted">No activity yet.</div>';
  } else {
    logEl.innerHTML = logs
      .slice()
      .reverse()
      .map((l) => {
        const t = new Date(l.ts).toLocaleTimeString();
        return `<div class="log-entry log-${escapeHtml(l.level)}">[${t}] (${escapeHtml(l.scope)}) ${escapeHtml(
          l.message
        )}</div>`;
      })
      .join('');
  }
}

// Event bindings
$('saveDeviceBtn').onclick = () => {
  api('/api/device', 'POST', { deviceName: $('deviceNameInput').value })
    .then(() => showToast('Device name saved'))
    .catch((e) => showToast(e.message));
};

$('relayToggleBtn').onclick = () => {
  const running = latestState?.relay?.running;
  api(running ? '/api/relay/stop' : '/api/relay/start', 'POST', { port: 4320 })
    .then(() => showToast(running ? 'Local relay stopped' : 'Local relay started on :4320'))
    .catch((e) => showToast(e.message));
};

$('useLocalRelayShareBtn').onclick = () => {
  const port = latestState?.relay?.port || 4320;
  $('shareRelayUrl').value = `ws://127.0.0.1:${port}/relay`;
};

$('shareForm').onsubmit = (e) => {
  e.preventDefault();
  api('/api/share/start', 'POST', {
    relayUrl: $('shareRelayUrl').value.trim(),
    roomCode: $('shareRoomCode').value.trim(),
    secret: $('shareSecret').value.trim(),
    directPort: Number($('shareDirectPort').value) || 4322,
    publicDirectHost: $('sharePublicHost').value.trim(),
    maxBandwidthMbps: Number($('shareMaxMbps').value) || 0,
    maxQuotaMb: Number($('shareMaxQuotaMb').value) || 0,
    blockPrivateNetwork: $('shareBlockPrivate').checked,
  })
    .then(() => showToast('Internet sharing started'))
    .catch((err) => showToast(err.message));
};

$('pauseShareBtn').onclick = () => {
  const nextPaused = !latestState?.sharer?.paused;
  api('/api/share/pause', 'POST', { paused: nextPaused }).catch((e) => showToast(e.message));
};

$('stopShareBtn').onclick = () => {
  api('/api/share/stop', 'POST', {})
    .then(() => showToast('Sharing stopped'))
    .catch((e) => showToast(e.message));
};

$('copyInviteBtn').onclick = async () => {
  const val = $('activeInviteUri').value;
  if (!val) return;
  try {
    await navigator.clipboard.writeText(val);
    showToast('Invite link copied!');
  } catch {
    $('activeInviteUri').select();
    document.execCommand('copy');
    showToast('Invite link copied!');
  }
};

$('connectForm').onsubmit = (e) => {
  e.preventDefault();
  const inviteUri = $('connectInviteUri').value.trim();
  const direct = $('connectDirectUrl').value.trim();
  api('/api/client/connect', 'POST', {
    inviteUri: inviteUri || undefined,
    roomCode: $('connectRoomCode').value.trim() || undefined,
    secret: $('connectSecret').value || undefined,
    relayUrl: $('connectRelayUrl').value.trim() || undefined,
    directEndpoints: direct ? [direct] : [],
    mode: $('connectMode').value,
  })
    .then(() => showToast('Tunnel connected!'))
    .catch((err) => showToast(`Connect failed: ${err.message}`));
};

$('disconnectBtn').onclick = () => {
  api('/api/client/disconnect', 'POST', {})
    .then(() => showToast('Tunnel disconnected'))
    .catch((e) => showToast(e.message));
};

$('checkExitIpBtn').onclick = () => {
  api('/api/client/check-ip', 'POST', {})
    .then((res) => showToast(res.exitIp ? `Exit IP: ${res.exitIp}` : 'Could not fetch exit IP'))
    .catch((e) => showToast(e.message));
};

$('toggleSysProxyBtn').onclick = () => {
  const currentlyOn =
    latestState?.systemProxy?.managedByApp ||
    (latestState?.systemProxy?.enabled &&
      latestState?.systemProxy?.proxyServer === `127.0.0.1:${latestState?.proxy?.port}`);
  api('/api/proxy/system', 'POST', { enabled: !currentlyOn })
    .then(() => showToast(!currentlyOn ? 'Windows system proxy enabled' : 'Windows system proxy restored'))
    .catch((e) => showToast(e.message));
};

$('lanExposeCheck').onchange = () => {
  api('/api/proxy/config', 'POST', { lanExpose: $('lanExposeCheck').checked })
    .then(() => showToast($('lanExposeCheck').checked ? 'LAN proxy sharing enabled' : 'LAN proxy sharing disabled'))
    .catch((e) => showToast(e.message));
};

function connectWsFeed() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws`);
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.type === 'state' && msg.data) {
        renderState(msg.data);
      }
    } catch {
      // ignore
    }
  };
  ws.onclose = () => {
    setTimeout(connectWsFeed, 2000);
  };
}

api('/api/state').catch(() => {});
connectWsFeed();
