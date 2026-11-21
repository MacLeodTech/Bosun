// Bytes travel as base64. Text views show UTF-8 when the bytes are valid UTF-8 and Latin-1 otherwise, so that
// editing and sending back never changes bytes the user didn't touch.

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

export type TextMode = 'utf8' | 'latin1';

export interface Decoded { text: string; mode: TextMode }

export function bytesToText(bytes: Uint8Array): Decoded {
  try {
    return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), mode: 'utf8' };
  } catch {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
    return { text: s, mode: 'latin1' };
  }
}

export function textToBytes(text: string, mode: TextMode): Uint8Array {
  if (mode === 'utf8') return new TextEncoder().encode(text);
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

export function hexDump(bytes: Uint8Array, max = 64 * 1024): string {
  const lines: string[] = [];
  const n = Math.min(bytes.length, max);
  for (let off = 0; off < n; off += 16) {
    const row = bytes.subarray(off, Math.min(off + 16, n));
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, '0')).join(' ');
    const asc = Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${off.toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  ${asc}`);
  }
  if (bytes.length > max) lines.push(`… ${bytes.length - max} more bytes`);
  return lines.join('\n');
}

/** Split a raw HTTP message into head and body at the first blank line. */
export function splitMessage(bytes: Uint8Array): { head: Uint8Array; body: Uint8Array } {
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (bytes[i] === 10 && bytes[i + 1] === 10) return { head: bytes.subarray(0, i), body: bytes.subarray(i + 2) };
    if (i + 3 < bytes.length && bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) {
      return { head: bytes.subarray(0, i), body: bytes.subarray(i + 4) };
    }
  }
  return { head: bytes, body: new Uint8Array() };
}

export function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

export function fmtTime(ms: number): string {
  const d = new Date(ms);
  return d.toLocaleTimeString(undefined, { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

export function flowUrl(f: { scheme: string; host: string; port: number; path: string }): string {
  const def = (f.scheme === 'http' && f.port === 80) || (f.scheme === 'https' && f.port === 443);
  const host = f.host.includes(':') ? `[${f.host}]` : f.host;
  return `${f.scheme}://${host}${def ? '' : ':' + f.port}${f.path}`;
}
