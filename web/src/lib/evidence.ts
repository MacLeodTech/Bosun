// Where the passive scanner's evidence sits in a message as it is shown. The scanner gives byte ranges into the
// stored message; the viewer wants (line, from, to) in the text it displays. Only positions are computed here: the
// viewer draws them as plain-text spans, never as markup.

export interface Range { start: number; end: number }
export interface Mark { line: number; from: number; to: number }

const MAX_RANGES = 50;

/** `bytes` is the message as stored, `text` what it was decoded to (UTF-8 unless `utf8` is false, then one char
 * per byte). Ranges outside the loaded bytes are dropped. A range that crosses lines becomes one mark per line. */
export function marks(bytes: Uint8Array, text: string, utf8: boolean, ranges: Range[]): Mark[] {
  const dec = new TextDecoder('utf-8');
  const at = (b: number) => (utf8 ? dec.decode(bytes.subarray(0, b)).length : b);
  const starts = [0];
  for (let i = text.indexOf('\n'); i >= 0; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
  const lineOf = (off: number) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= off) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };
  const out: Mark[] = [];
  for (const r of ranges.slice(0, MAX_RANGES)) {
    if (r.end <= r.start || r.start >= bytes.length) continue;
    const s = at(r.start);
    const e = Math.min(at(Math.min(r.end, bytes.length)), text.length);
    for (let l = lineOf(s); l <= lineOf(Math.max(s, e - 1)) && l < starts.length; l++) {
      const from = Math.max(s, starts[l]!) - starts[l]!;
      const to = Math.min(e, (starts[l + 1] ?? text.length + 1) - 1) - starts[l]!;
      if (to > from) out.push({ line: l, from, to });
    }
  }
  return out;
}
