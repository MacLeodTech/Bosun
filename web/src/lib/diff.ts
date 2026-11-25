// Line and word diffs (Myers' O(ND) algorithm). Bounded on purpose: past MAX_EDITS differences the part that differs
// is reported as "all removed, all added" rather than spending seconds in the browser.

export type Op = { kind: 'same' | 'add' | 'del'; text: string };
type Kind = Op['kind'];

const LINE_EDITS = 2000;
const WORD_EDITS = 400;
/** Texts beyond this many lines are not diffed at all (the memory for the trace grows with the edit count). */
const MAX_LINES = 200_000;

/** Edit script turning `a` into `b`, or null when it needs more than `maxD` edits. */
function myers<T>(a: T[], b: T[], eq: (x: T, y: T) => boolean, maxD: number): Kind[] | null {
  const n = a.length;
  const m = b.length;
  const max = Math.min(n + m, maxD);
  const off = max + 1;
  const v = new Int32Array(2 * max + 3);
  // trace[d] is the frontier before round d, kept only for the diagonals round d can read: k in [-d-1, d+1].
  const trace: Int32Array[] = [];
  for (let d = 0; d <= max; d++) {
    trace.push(v.slice(off - d - 1, off + d + 2));
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[off + k - 1]! < v[off + k + 1]!) ? v[off + k + 1]! : v[off + k - 1]! + 1;
      let y = x - k;
      while (x < n && y < m && eq(a[x]!, b[y]!)) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= n && y >= m) return backtrack(trace, d, n, m);
    }
  }
  return null;
}

function backtrack(trace: Int32Array[], dEnd: number, n: number, m: number): Kind[] {
  const ops: Kind[] = [];
  let x = n;
  let y = m;
  for (let d = dEnd; d > 0; d--) {
    const t = trace[d]!;
    const at = (k: number) => t[k + d + 1]!;
    const k = x - y;
    const prevK = k === -d || (k !== d && at(k - 1) < at(k + 1)) ? k + 1 : k - 1;
    const prevX = at(prevK);
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      ops.push('same');
      x--;
      y--;
    }
    ops.push(x === prevX ? 'add' : 'del');
    x = prevX;
    y = prevY;
  }
  while (x > 0 && y > 0) {
    ops.push('same');
    x--;
    y--;
  }
  return ops.reverse();
}

/** Diff two sequences: trims what both ends share, runs Myers on the middle, falls back to replace-all. */
function diffSeq<T>(a: T[], b: T[], eq: (x: T, y: T) => boolean, maxD: number): { kind: Kind; item: T }[] {
  let s = 0;
  while (s < a.length && s < b.length && eq(a[s]!, b[s]!)) s++;
  let e = 0;
  while (e < a.length - s && e < b.length - s && eq(a[a.length - 1 - e]!, b[b.length - 1 - e]!)) e++;
  const ma = a.slice(s, a.length - e);
  const mb = b.slice(s, b.length - e);
  const out: { kind: Kind; item: T }[] = a.slice(0, s).map((item) => ({ kind: 'same' as Kind, item }));
  const script = ma.length && mb.length ? myers(ma, mb, eq, maxD) : null;
  if (script) {
    let i = 0;
    let j = 0;
    for (const k of script) {
      if (k === 'same') {
        out.push({ kind: 'same', item: ma[i++]! });
        j++;
      } else if (k === 'del') out.push({ kind: 'del', item: ma[i++]! });
      else out.push({ kind: 'add', item: mb[j++]! });
    }
  } else {
    for (const item of ma) out.push({ kind: 'del', item });
    for (const item of mb) out.push({ kind: 'add', item });
  }
  for (const item of a.slice(a.length - e)) out.push({ kind: 'same', item });
  return out;
}

export function diffLines(a: string, b: string): Op[] {
  const x = a.split('\n');
  const y = b.split('\n');
  if (x.length > MAX_LINES || y.length > MAX_LINES) {
    return [...x.map((text): Op => ({ kind: 'del', text })), ...y.map((text): Op => ({ kind: 'add', text }))];
  }
  return diffSeq(x, y, (p, q) => p === q, LINE_EDITS).map((o): Op => ({ kind: o.kind, text: o.item }));
}

const WORD = /\s+|\w+|[^\w\s]/g;

/** A word-level diff of two changed lines, for highlighting what changed inside them. */
export function diffWords(a: string, b: string): Op[] {
  const x = a.match(WORD) ?? [];
  const y = b.match(WORD) ?? [];
  return diffSeq(x, y, (p, q) => p === q, WORD_EDITS).map((o): Op => ({ kind: o.kind, text: o.item }));
}
