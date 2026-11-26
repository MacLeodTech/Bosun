// The History table's columns, its sort keys, and the colour highlights. Pure, so it can be tested without a page.

export type SortKey = 'id' | 'time' | 'method' | 'host' | 'path' | 'status' | 'size' | 'req_size' | 'duration' | 'ttfb' | 'mime';
export type ColKey = 'id' | 'method' | 'marks' | 'host' | 'path' | 'status' | 'length' | 'mime' | 'time' | 'duration' | 'ttfb' | 'reqlen' | 'source' | 'tags';

export interface Col {
  key: ColKey;
  title: string;
  /** A CSS grid track. */
  width: string;
  /** What the server sorts by when this header is clicked (absent: not sortable). */
  sort?: SortKey;
  /** Always shown: the table is useless without it. */
  required?: boolean;
}

export const COLS: Col[] = [
  { key: 'id', title: '#', width: '3rem', sort: 'id' },
  { key: 'method', title: 'Method', width: '4.6rem', sort: 'method' },
  { key: 'marks', title: 'Marks', width: '2.4rem' },
  { key: 'host', title: 'Host', width: '13rem', sort: 'host' },
  { key: 'path', title: 'Path', width: 'minmax(8rem, 1fr)', sort: 'path', required: true },
  { key: 'status', title: 'Status', width: '4.6rem', sort: 'status' },
  { key: 'length', title: 'Length', width: '6.2rem', sort: 'size' },
  { key: 'mime', title: 'MIME', width: '6rem', sort: 'mime' },
  { key: 'time', title: 'Time', width: '7.8rem', sort: 'time' },
  { key: 'duration', title: 'Duration', width: '5.5rem', sort: 'duration' },
  { key: 'ttfb', title: 'TTFB', width: '5rem', sort: 'ttfb' },
  { key: 'reqlen', title: 'Req. size', width: '6rem', sort: 'req_size' },
  { key: 'source', title: 'Source', width: '5.5rem' },
  { key: 'tags', title: 'Tags', width: '9rem' },
];

export const DEFAULT_COLS: ColKey[] = ['id', 'method', 'marks', 'host', 'path', 'status', 'length', 'mime', 'time'];

const known = new Set<string>(COLS.map((c) => c.key));

/** A stored column list made safe: known keys only, no repeats, in table order, the path always there. */
export function normalizeCols(x: unknown): ColKey[] {
  const want = new Set(Array.isArray(x) ? x.filter((k): k is string => typeof k === 'string' && known.has(k)) : []);
  if (!want.size) return [...DEFAULT_COLS];
  want.add('path');
  return COLS.filter((c) => want.has(c.key)).map((c) => c.key);
}

export const colOf = (k: ColKey): Col => COLS.find((c) => c.key === k)!;

/** The CSS `grid-template-columns` for the chosen columns. */
export function template(cols: ColKey[]): string {
  return cols.map((k) => colOf(k).width).join(' ');
}

// ---- highlights: a reserved tag, so they search (`tag:hl:red`), export and need no schema of their own

export const HL_COLORS = ['red', 'orange', 'yellow', 'green', 'blue', 'purple'] as const;
export type Highlight = (typeof HL_COLORS)[number];
export const HL_PREFIX = 'hl:';

export function highlightOf(tags: readonly string[] | undefined): Highlight | null {
  for (const t of tags ?? []) {
    const c = t.toLowerCase().startsWith(HL_PREFIX) ? t.slice(HL_PREFIX.length).toLowerCase() : '';
    if ((HL_COLORS as readonly string[]).includes(c)) return c as Highlight;
  }
  return null;
}

/** The tags a person sees and edits: everything except the highlight tags. */
export const plainTags = (tags: readonly string[] | undefined): string[] => (tags ?? []).filter((t) => !t.toLowerCase().startsWith(HL_PREFIX));

/** The next sort after clicking a header: the first click sorts descending (newest, biggest), then ascending, then back to the default. */
export function nextSort(cur: { key: SortKey; asc: boolean }, clicked: SortKey): { key: SortKey; asc: boolean } {
  if (clicked === 'id') return { key: 'id', asc: cur.key === 'id' ? !cur.asc : false };
  if (cur.key !== clicked) return { key: clicked, asc: false };
  return cur.asc ? { key: 'id', asc: false } : { key: clicked, asc: true };
}
