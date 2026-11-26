// Hex editing helpers. The hex editor shows bytes as rows of 16 two-digit pairs and reads them back from whatever
// the person typed or pasted, so the parser is forgiving about spaces and line breaks and strict about everything
// else: it returns null rather than guess.

export const HEX_ROW = 16;
/** Past this many bytes the hex editor is read-only: one text control per byte row does not scale. */
export const HEX_EDIT_MAX = 256 * 1024;

/** Bytes as rows of `HEX_ROW` space-separated pairs, one row per line. */
export function formatHex(bytes: Uint8Array): string {
  const rows: string[] = [];
  for (let off = 0; off < bytes.length; off += HEX_ROW) {
    const row = bytes.subarray(off, Math.min(off + HEX_ROW, bytes.length));
    rows.push(Array.from(row, (b) => b.toString(16).padStart(2, '0')).join(' '));
  }
  return rows.join('\n');
}

/** The printable-ASCII view of each row, for the column beside the hex. */
export function asciiRows(bytes: Uint8Array): string[] {
  const rows: string[] = [];
  for (let off = 0; off < bytes.length; off += HEX_ROW) {
    const row = bytes.subarray(off, Math.min(off + HEX_ROW, bytes.length));
    rows.push(Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join(''));
  }
  return rows;
}

/** Bytes from hex text. Whitespace anywhere is ignored; an optional `0x` is not (it is not hex). Null when invalid. */
export function parseHex(text: string): Uint8Array | null {
  const digits = text.replace(/\s+/g, '');
  if (digits.length % 2 !== 0 || /[^0-9a-fA-F]/.test(digits)) return null;
  const out = new Uint8Array(digits.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(digits.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Why `parseHex` refused a text, in words. */
export function hexProblem(text: string): string {
  const digits = text.replace(/\s+/g, '');
  const bad = /[^0-9a-fA-F]/.exec(digits);
  if (bad) return `"${bad[0]}" is not a hex digit (position ${bad.index + 1}).`;
  if (digits.length % 2 !== 0) return 'A byte is two digits; there is one left over.';
  return '';
}
