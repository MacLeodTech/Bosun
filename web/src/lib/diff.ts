// A line diff for comparing one response with the one before it. It is a plain longest-common-subsequence over
// lines; past a size where that would be slow it falls back to "everything changed".

export type Op = { kind: 'same' | 'add' | 'del'; text: string };

const LIMIT = 1500;

export function diffLines(a: string, b: string): Op[] {
  const x = a.split('\n');
  const y = b.split('\n');
  if (x.length > LIMIT || y.length > LIMIT) {
    return [...x.map((text): Op => ({ kind: 'del', text })), ...y.map((text): Op => ({ kind: 'add', text }))];
  }
  // Trim what both ends share, then run the table over the middle.
  let s = 0;
  while (s < x.length && s < y.length && x[s] === y[s]) s++;
  let e = 0;
  while (e < x.length - s && e < y.length - s && x[x.length - 1 - e] === y[y.length - 1 - e]) e++;
  const m = x.slice(s, x.length - e);
  const n = y.slice(s, y.length - e);
  const t: number[][] = Array.from({ length: m.length + 1 }, () => new Array<number>(n.length + 1).fill(0));
  for (let i = m.length - 1; i >= 0; i--) {
    for (let j = n.length - 1; j >= 0; j--) {
      t[i]![j] = m[i] === n[j] ? t[i + 1]![j + 1]! + 1 : Math.max(t[i + 1]![j]!, t[i]![j + 1]!);
    }
  }
  const out: Op[] = x.slice(0, s).map((text): Op => ({ kind: 'same', text }));
  let i = 0;
  let j = 0;
  while (i < m.length && j < n.length) {
    if (m[i] === n[j]) {
      out.push({ kind: 'same', text: m[i]! });
      i++;
      j++;
    } else if (t[i + 1]![j]! >= t[i]![j + 1]!) out.push({ kind: 'del', text: m[i++]! });
    else out.push({ kind: 'add', text: n[j++]! });
  }
  while (i < m.length) out.push({ kind: 'del', text: m[i++]! });
  while (j < n.length) out.push({ kind: 'add', text: n[j++]! });
  out.push(...x.slice(x.length - e).map((text): Op => ({ kind: 'same', text })));
  return out;
}
