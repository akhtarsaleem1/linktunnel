import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const REG_PATH = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const DEFAULT_BYPASS = 'localhost;127.*;10.*;172.16.*;192.168.*;*.local;<local>';
const WININET_REFRESH_PS = `
Add-Type -Namespace WinInet -Name Native -MemberDefinition '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);'
[WinInet.Native]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[WinInet.Native]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
`;

export function parseRegQueryValue(output, valueName) {
  const regex = new RegExp(`^\\s*${valueName}\\s+REG_\\w+\\s+(.*)$`, 'mi');
  const m = String(output || '').match(regex);
  if (!m) return null;
  return m[1].trim();
}

export async function readWindowsProxySettings() {
  if (process.platform !== 'win32') {
    return { supported: false, enabled: false, proxyServer: '', proxyOverride: '' };
  }
  try {
    const { stdout } = await execFileAsync('reg.exe', ['query', REG_PATH]);
    const enableRaw = parseRegQueryValue(stdout, 'ProxyEnable');
    const serverRaw = parseRegQueryValue(stdout, 'ProxyServer');
    const overrideRaw = parseRegQueryValue(stdout, 'ProxyOverride');
    return {
      supported: true,
      enabled: enableRaw === '0x1' || enableRaw === '1',
      proxyServer: serverRaw || '',
      proxyOverride: overrideRaw || '',
    };
  } catch (err) {
    return { supported: true, enabled: false, proxyServer: '', proxyOverride: '', error: err.message };
  }
}

async function notifyWinInetRefresh() {
  if (process.platform !== 'win32') return;
  await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WININET_REFRESH_PS]);
}

/**
 * Enables Windows user-level HTTP/HTTPS system proxy pointing to 127.0.0.1:<port>,
 * returning a backup snapshot of the previous registry state so it can be cleanly restored.
 */
export async function enableWindowsSystemProxy(port, previousBackup = null) {
  if (process.platform !== 'win32') {
    throw new Error('System proxy toggle is currently automated on Windows only; configure OS proxy manually.');
  }
  const backup = previousBackup || (await readWindowsProxySettings());
  const proxyServer = `127.0.0.1:${port}`;

  await execFileAsync('reg.exe', ['add', REG_PATH, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f']);
  await execFileAsync('reg.exe', ['add', REG_PATH, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', proxyServer, '/f']);
  await execFileAsync('reg.exe', ['add', REG_PATH, '/v', 'ProxyOverride', '/t', 'REG_SZ', '/d', DEFAULT_BYPASS, '/f']);
  await notifyWinInetRefresh();

  return { backup, activeServer: proxyServer };
}

/**
 * Restores Windows system proxy settings from backup (or disables ProxyEnable cleanly).
 */
export async function restoreWindowsSystemProxy(backup = null) {
  if (process.platform !== 'win32') return { restored: false };

  if (backup && backup.supported) {
    const enableVal = backup.enabled ? '1' : '0';
    await execFileAsync('reg.exe', ['add', REG_PATH, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', enableVal, '/f']);
    if (backup.proxyServer) {
      await execFileAsync('reg.exe', ['add', REG_PATH, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', backup.proxyServer, '/f']);
    } else {
      await execFileAsync('reg.exe', ['delete', REG_PATH, '/v', 'ProxyServer', '/f']).catch(() => {});
    }
    if (backup.proxyOverride) {
      await execFileAsync('reg.exe', ['add', REG_PATH, '/v', 'ProxyOverride', '/t', 'REG_SZ', '/d', backup.proxyOverride, '/f']);
    }
  } else {
    await execFileAsync('reg.exe', ['add', REG_PATH, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f']);
    await execFileAsync('reg.exe', ['delete', REG_PATH, '/v', 'ProxyServer', '/f']).catch(() => {});
  }
  await notifyWinInetRefresh();
  return { restored: true };
}

/**
 * Synchronous fallback used on abrupt Node exit so browsers never remain stuck on 127.0.0.1.
 */
export function restoreWindowsSystemProxySync(backup = null) {
  if (process.platform !== 'win32') return;
  try {
    if (backup && backup.supported) {
      execFileSync('reg.exe', ['add', REG_PATH, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', backup.enabled ? '1' : '0', '/f']);
      if (backup.proxyServer) {
        execFileSync('reg.exe', ['add', REG_PATH, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', backup.proxyServer, '/f']);
      } else {
        try {
          execFileSync('reg.exe', ['delete', REG_PATH, '/v', 'ProxyServer', '/f']);
        } catch {
          // ignore
        }
      }
      if (backup.proxyOverride) {
        execFileSync('reg.exe', ['add', REG_PATH, '/v', 'ProxyOverride', '/t', 'REG_SZ', '/d', backup.proxyOverride, '/f']);
      }
    } else {
      execFileSync('reg.exe', ['add', REG_PATH, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f']);
    }
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WININET_REFRESH_PS]);
  } catch {
    // best-effort on exit
  }
}
