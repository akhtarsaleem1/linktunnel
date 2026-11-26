import dns from 'node:dns/promises';
import net from 'node:net';
import os from 'node:os';

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    num = (num << 8) | n;
  }
  return num >>> 0;
}

export function isPrivateIpv4(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  const b0 = (n >>> 24) & 0xff;
  const b1 = (n >>> 16) & 0xff;
  if (b0 === 0) return true; // 0.0.0.0/8
  if (b0 === 10) return true; // 10.0.0.0/8
  if (b0 === 127) return true; // 127.0.0.0/8 loopback
  if (b0 === 169 && b1 === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true; // 172.16.0.0/12
  if (b0 === 192 && b1 === 168) return true; // 192.168.0.0/16
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true; // 100.64.0.0/10 CGNAT
  if (b0 === 192 && b1 === 0 && ((n >>> 8) & 0xff) === 0) return true; // 192.0.0.0/24
  if (b0 >= 224) return true; // multicast & reserved
  return false;
}

export function isPrivateIp(ip) {
  const clean = String(ip || '').split('%')[0].trim().toLowerCase();
  const ipVersion = net.isIP(clean);
  if (ipVersion === 4) return isPrivateIpv4(clean);
  if (ipVersion !== 6) return true;

  if (clean === '::' || clean === '::1') return true;
  if (clean.startsWith('::ffff:')) {
    const v4Part = clean.slice(7);
    if (net.isIP(v4Part) === 4) return isPrivateIpv4(v4Part);
    // Hex-encoded IPv4-mapped IPv6 like ::ffff:7f00:1
    const hexParts = v4Part.split(':');
    if (hexParts.length === 2) {
      const hi = parseInt(hexParts[0], 16);
      const lo = parseInt(hexParts[1], 16);
      if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
        const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return isPrivateIpv4(v4);
      }
    }
    return true;
  }
  if (clean.startsWith('fe80:') || clean.startsWith('fe9') || clean.startsWith('fea') || clean.startsWith('feb')) {
    return true; // fe80::/10 link-local
  }
  if (clean.startsWith('fc') || clean.startsWith('fd')) {
    return true; // fc00::/7 ULA
  }
  if (clean.startsWith('ff')) {
    return true; // ff00::/8 multicast
  }
  return false;
}

export function matchesDomainRule(hostname, pattern) {
  const host = String(hostname || '').toLowerCase().trim();
  const pat = String(pattern || '').toLowerCase().trim();
  if (!pat) return false;
  if (pat.startsWith('*.')) {
    const suffix = pat.slice(1); // ".example.com"
    return host === pat.slice(2) || host.endsWith(suffix);
  }
  return host === pat;
}

/**
 * Resolves a target host and verifies all resolved IPs against the sharer's security policy.
 * Returns { address, family } so the caller connects directly to the validated IP (preventing DNS rebinding).
 */
export async function resolveAndValidateTarget(host, port, policy = {}) {
  const cleanHost = String(host || '').trim().replace(/^\[|\]$/g, '');
  if (!cleanHost) {
    const err = new Error('Empty target hostname');
    err.code = 'EBLOCKED';
    throw err;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    const err = new Error(`Invalid port: ${port}`);
    err.code = 'EBLOCKED';
    throw err;
  }

  const blockPrivate = policy.blockPrivateNetwork !== false;
  const blockedDomains = Array.isArray(policy.blockedDomains) ? policy.blockedDomains : [];
  const allowedDomains = Array.isArray(policy.allowedDomains) ? policy.allowedDomains : [];

  for (const pat of blockedDomains) {
    if (matchesDomainRule(cleanHost, pat)) {
      const err = new Error(`Domain blocked by policy: ${cleanHost}`);
      err.code = 'EBLOCKED';
      throw err;
    }
  }
  if (allowedDomains.length > 0 && !allowedDomains.some((pat) => matchesDomainRule(cleanHost, pat))) {
    const err = new Error(`Domain not in allowlist: ${cleanHost}`);
    err.code = 'EBLOCKED';
    throw err;
  }

  if (blockPrivate && (cleanHost.toLowerCase() === 'localhost' || cleanHost.toLowerCase().endsWith('.local'))) {
    const err = new Error(`Private hostname blocked: ${cleanHost}`);
    err.code = 'EBLOCKED';
    throw err;
  }

  const literalFamily = net.isIP(cleanHost);
  if (literalFamily !== 0) {
    if (blockPrivate && isPrivateIp(cleanHost)) {
      const err = new Error(`Private/loopback IP blocked by sharer policy: ${cleanHost}`);
      err.code = 'EBLOCKED';
      throw err;
    }
    return { address: cleanHost, family: literalFamily };
  }

  const results = await dns.lookup(cleanHost, { all: true, verbatim: true });
  if (!results || results.length === 0) {
    throw new Error(`DNS lookup returned no addresses for ${cleanHost}`);
  }

  if (blockPrivate) {
    for (const r of results) {
      if (isPrivateIp(r.address)) {
        const err = new Error(`DNS resolved to private IP (${r.address}), blocked by sharer policy`);
        err.code = 'EBLOCKED';
        throw err;
      }
    }
  }

  // Prefer IPv4 when available for widest outbound compatibility
  const v4 = results.find((r) => r.family === 4);
  return v4 || results[0];
}

/**
 * Lists non-internal local IPv4 addresses (for LAN mobile setup and direct endpoint hints).
 */
export function getLocalLanIps() {
  try {
    const ifaces = os.networkInterfaces();
    const ips = [];
    for (const [name, addrs] of Object.entries(ifaces)) {
      if (!addrs) continue;
      for (const info of addrs) {
        if (info.family === 'IPv4' && !info.internal) {
          ips.push({ interface: name, address: info.address });
        }
      }
    }
    return ips;
  } catch {
    // Non-rooted Android 11+ (Termux) may deny netlink interface enumeration
    return [];
  }
}
