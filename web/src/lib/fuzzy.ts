// Fuzzy matching for the command palette: every character of the query must appear in the text, in order.
// Higher scores are better. Contiguous matches, matches at the start of a word and matches near the start win.

export interface Match { score: number; idx: number[] }

const isWordChar = (c: string) => /[A-Za-z0-9]/.test(c);

export function fuzzy(query: string, text: string): Match | null {
  const q = query.toLowerCase().replace(/\s+/g, '');
  if (!q) return { score: 0, idx: [] };
  const t = text.toLowerCase();
  // A plain substring beats any scattered match.
  const at = t.indexOf(q);
  if (at >= 0) {
    const boundary = at === 0 || !isWordChar(text[at - 1]!);
    return { score: 1000 - at + (boundary ? 100 : 0) - Math.min(text.length, 200) / 10, idx: Array.from({ length: q.length }, (_, i) => at + i) };
  }
  const idx: number[] = [];
  let from = 0;
  let score = 0;
  for (const ch of q) {
    const i = t.indexOf(ch, from);
    if (i < 0) return null;
    const prev = idx[idx.length - 1];
    if (prev !== undefined && i === prev + 1) score += 15;
    else score -= Math.min(i - from, 10);
    if (i === 0 || !isWordChar(text[i - 1]!)) score += 12;
    idx.push(i);
    from = i + 1;
  }
  return { score: score - Math.min(text.length, 200) / 20, idx };
}
