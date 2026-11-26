# LinkTunnel

End-to-end encrypted (`X25519` + `HKDF-SHA256` + `ChaCha20-Poly1305`) internet-sharing tunneling app for sharing connections between distant devices across NATs and firewalls.

## Key Features
- **Relay + Direct Hybrid Transport**: Automatically uses low-latency Direct P2P when reachable and seamlessly falls back to a self-hostable zero-knowledge Relay server when devices are behind CGNAT/firewalls.
- **True End-to-End Encryption**: The relay server only sees opaque encrypted frames and cannot inspect domains, DNS queries, or payloads. Both devices verify a matching **Safety Code**.
- **Mutual Bidirectional Sharing**: Any device can act as an **Exit Node (Sharer)**, a **Client**, or both at the same time.
- **Unified Local Proxy (SOCKS5 + HTTP/HTTPS + PAC)**: Single local port (`10808`) handles SOCKS5 (with remote DNS resolution), SOCKS4/4a, HTTP/HTTPS `CONNECT`, and `/proxy.pac`.
- **One-Click Windows System Proxy Toggle**: Safely backs up and restores your original Windows `Internet Settings` proxy registry keys (with crash recovery).
- **Mobile & LAN Sharing + QR Codes**: Share the active tunnel with nearby Android/iOS devices on your Wi-Fi using a scannable PAC QR code or peer invite QR code.
- **Sharer Safety Controls**: Built-in private LAN/router blocking (SSRF & DNS-rebinding protection), speed limiting (Mbps), data quota caps, pause/resume, and peer kick.
- **Zero External Dependencies**: Runs natively on Node.js 18+ (tested on Node 24) with no `npm install` needed.

---

## Quick Start

### 1. Launch the Interactive Web Dashboard
```bash
npm start
# or directly:
node bin/linktunnel.mjs ui
```
Open `http://127.0.0.1:4321` (opens automatically by default).

### 2. Long-Distance Setup (Different Cities / Networks)

Because home routers and mobile carriers sit behind NAT/CGNAT, long-distance connections need either:
- **Option A — Deploy on Render (Free Temporary Relay)** using [render.yaml](render.yaml):
  1. Push this repository to GitHub (private or public).
  2. In Render Dashboard, choose **New + → Blueprint** (or **Web Service**) and select the repository.
  3. Render detects `render.yaml` automatically (`node bin/linktunnel.mjs relay --host 0.0.0.0`, health check `/health`).
  4. Once live at `https://your-service.onrender.com`, use `wss://your-service.onrender.com/relay` as your **Relay Server URL**.
  *(Note: Render Free tier sleeps after 15 minutes with zero active requests/connections; keep one client/sharer connected or visit `/health` to wake it.)*

- **Option B — Host the Relay on any VPS / Docker**:
  ```bash
  node bin/linktunnel.mjs relay --port 4320
  ```
  Or with Docker:
  ```bash
  docker build -t linktunnel-relay .
  docker run -d -p 4320:4320 --name linktunnel-relay linktunnel-relay
  ```
  Put your relay behind HTTPS/TLS (Caddy, Nginx, Fly.io, Railway) to get a `wss://your-relay.example.com/relay` URL.

- **Option C — Zero-VPS Instant Tunnel with Cloudflare Quick Tunnel**:
  On Device A, click **Start Local Relay** in the dashboard (or run `node bin/linktunnel.mjs relay --port 4320`), then run:
  ```bash
  cloudflared tunnel --url http://localhost:4320
  ```
  Replace `https://` with `wss://` (e.g., `wss://random-name.trycloudflare.com/relay`) and paste it into **Relay Server URL**.

- **Option D — Direct Mode (Port Forward / Public IP / Tailscale)**:
  Forward TCP port `4322` on the Sharer's router (or enter your Tailscale/ZeroTier/public IP in **Public IP / DDNS**) and leave Relay blank or use Hybrid mode.

### 3. Share & Connect
1. **Device A (Sharer)**: Open **Share My Internet**, paste the Relay URL (or configure Direct Port), set optional speed/data limits, and click **Start Sharing Internet**. Copy the generated **`linktunnel://...` Invite Link** (or scan the QR).
2. **Device B (Client)**: Paste the **Invite Link** into **Use Remote Internet** and click **Connect to Tunnel**.
3. Click **Enable Windows System Proxy** (or configure any browser/app to use `127.0.0.1:10808` as HTTP or SOCKS5 proxy).
4. Click **Verify Exit IP** to confirm your traffic is exiting through Device A!

---

## CLI Usage

```bash
# Start Web UI Dashboard
node bin/linktunnel.mjs ui --port 4321

# Run Relay Server
node bin/linktunnel.mjs relay --port 4320

# Share Internet from CLI
node bin/linktunnel.mjs share --relay wss://your-relay/relay --max-mbps 25

# Connect from CLI + enable Windows system proxy
node bin/linktunnel.mjs connect "linktunnel://v1?d=..." --system-proxy
```

## Running Tests
```bash
npm test
```
