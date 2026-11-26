// The History filter as one line of text: `host:example.com method:GET,POST status:4xx scope:in -ext:png,css login`.
// `parseQuery` turns it into the structured filter the server's /flows endpoint already understands, plus a chip
// for each recognised term so the UI can show (and remove) them. Anything that is not `key:value` is free text.
//
// The parser is total: any string gives a result, and a malformed term becomes an error message, never an exception.

export interface FlowFilter {
  text: string;
  host: string;
  /** Comma-separated, upper case. */
  methods: string;
  statusMin?: number;
  statusMax?: number;
  inScopeOnly: boolean;
  /** Comma-separated extensions to hide, lower case. */
  hideExt: string;
  /** The line uses something only the server understands (or, not, groups, tag:, header: ...): the live tail can't match it here. */
  serverOnly: boolean;
}

export type ChipKey = 'host' | 'method' | 'status' | 'scope' | 'ext' | 'text' | 'other';
export interface Chip { key: ChipKey; label: string; start: number; end: number }
export interface Parsed { filter: FlowFilter; chips: Chip[]; errors: string[] }

export const DEFAULT_QUERY = '-ext:png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,css';
const MAX_QUERY = 2000;

interface Tok { raw: string; text: string; start: number; end: number }

const isSpace = (c: string) => c === ' ' || c === '\t' || c === '\n' || c === '\r';

/** Split on whitespace; double quotes group words (and are removed from `text`). */
function tokenize(q: string): Tok[] {
  const out: Tok[] = [];
  const n = q.length;
  let i = 0;
  while (i < n) {
    while (i < n && isSpace(q[i]!)) i++;
    if (i >= n) break;
    const start = i;
    let text = '';
    let quoted = false;
    while (i < n && (quoted || !isSpace(q[i]!))) {
      if (q[i] === '"') quoted = !quoted;
      else text += q[i];
      i++;
    }
    out.push({ raw: q.slice(start, i), text, start, end: i });
  }
  return out;
}

/** Words and terms the server's query language has and this parser does not: operators, groups and the newer keys. */
const SERVER_ONLY = /^(?:or|and|not)$|^-?\(|\)$|^-?(?:header|tag|mime|path|note|port|scheme|size|since|until|has|source):/i;

const KEYS: Record<string, ChipKey> = { host: 'host', h: 'host', method: 'method', m: 'method', status: 'status', s: 'status', scope: 'scope', ext: 'ext' };

function parseStatus(v: string): [number | undefined, number | undefined] | null {
  let m = /^([1-5])xx$/i.exec(v);
  if (m) return [Number(m[1]) * 100, Number(m[1]) * 100 + 99];
  m = /^(\d{3})$/.exec(v);
  if (m) return [Number(m[1]), Number(m[1])];
  m = /^(\d{3})-(\d{3})$/.exec(v);
  if (m && Number(m[1]) <= Number(m[2])) return [Number(m[1]), Number(m[2])];
  m = /^(>=|>|<=|<)(\d{3})$/.exec(v);
  if (m) {
    const n = Number(m[2]);
    return m[1] === '>=' ? [n, undefined] : m[1] === '>' ? [n + 1, undefined] : m[1] === '<=' ? [undefined, n] : [undefined, n - 1];
  }
  return null;
}

export function parseQuery(query: string): Parsed {
  const q = query.slice(0, MAX_QUERY);
  const filter: FlowFilter = { text: '', host: '', methods: '', inScopeOnly: false, hideExt: '', serverOnly: false };
  const chips: Chip[] = [];
  const errors: string[] = [];
  const words: string[] = [];
  for (const t of tokenize(q)) {
    const m = /^(-?)([A-Za-z]+):(.*)$/.exec(t.text);
    const key = m ? KEYS[m[2]!.toLowerCase()] : undefined;
    if (!m || !key) {
      if (SERVER_ONLY.test(t.text)) {
        filter.serverOnly = true;
        chips.push({ key: 'other', label: t.raw, start: t.start, end: t.end });
        continue;
      }
      words.push(t.text);
      chips.push({ key: 'text', label: t.text, start: t.start, end: t.end });
      continue;
    }
    const neg = m[1] === '-';
    const val = m[3]!;
    const chip = (): Chip => ({ key, label: t.raw, start: t.start, end: t.end });
    if (neg && key !== 'ext') {
      errors.push(`"-" only works with ext: (in "${t.raw}")`);
    } else if (!val) {
      errors.push(`${m[2]}: needs a value`);
    } else if (key === 'host') {
      filter.host = val.replace(/^[a-z]+:\/\//i, '').toLowerCase();
      chips.push(chip());
    } else if (key === 'method') {
      if (!/^[A-Za-z]+(,[A-Za-z]+)*$/.test(val)) errors.push(`method: expects names such as GET,POST (in "${t.raw}")`);
      else {
        filter.methods = val.toUpperCase();
        chips.push(chip());
      }
    } else if (key === 'status') {
      const r = parseStatus(val);
      if (!r) errors.push(`status: expects 404, 400-499, 4xx or >=400 (in "${t.raw}")`);
      else {
        [filter.statusMin, filter.statusMax] = r;
        chips.push(chip());
      }
    } else if (key === 'scope') {
      if (val.toLowerCase() !== 'in') {
        // `scope:out` is the server's; whether it is valid is for the server to say.
        filter.serverOnly = true;
        chips.push(chip());
      } else {
        filter.inScopeOnly = true;
        chips.push(chip());
      }
    } else if (key === 'ext') {
      if (!neg) errors.push(`ext: can only hide extensions, write -ext:${val} (in "${t.raw}")`);
      else if (!/^[A-Za-z0-9_,.+-]+$/.test(val)) errors.push(`ext: expects names such as -ext:png,css (in "${t.raw}")`);
      else {
        filter.hideExt = val.toLowerCase();
        chips.push(chip());
      }
    }
  }
  filter.text = words.join(' ');
  return { filter, chips, errors };
}

/** The query without one chip's term. */
export function removeChip(query: string, chip: Chip): string {
  const q = query.slice(0, MAX_QUERY);
  return (q.slice(0, chip.start) + ' ' + q.slice(chip.end)).replace(/\s+/g, ' ').trim();
}

const quoteIfNeeded = (s: string) => (/\s/.test(s) ? `"${s.replace(/"/g, '')}"` : s);

/** The query with `key:value` set, replacing an earlier term of the same key. */
export function withTerm(query: string, key: 'host' | 'method' | 'status' | 'scope', value: string): string {
  const { chips } = parseQuery(query);
  let q = query.slice(0, MAX_QUERY);
  for (const c of chips.filter((c) => c.key === key).sort((a, b) => b.start - a.start)) q = removeChip(q, c);
  return `${q} ${key}:${quoteIfNeeded(value)}`.trim();
}

/** The query with its free text replaced. */
export function withText(query: string, text: string): string {
  const { chips } = parseQuery(query);
  let q = query.slice(0, MAX_QUERY);
  for (const c of chips.filter((c) => c.key === 'text').sort((a, b) => b.start - a.start)) q = removeChip(q, c);
  const t = text.trim();
  return t ? `${q} ${quoteIfNeeded(t)}`.trim() : q;
}

/** The parts of a flow the filter looks at, so this works for the list and the live tail alike. */
export interface Filterable { host: string; method: string; status?: number | null; in_scope: boolean; path: string }

/** Whether a flow passes the structured part of the filter (free text needs the server, which can search bodies). */
export function matchesFlow(f: FlowFilter, x: Filterable): boolean {
  if (f.host && !x.host.includes(f.host.toLowerCase())) return false;
  if (f.methods && !f.methods.split(',').map((m) => m.trim()).includes(x.method)) return false;
  if (f.statusMin !== undefined && (x.status ?? 0) < f.statusMin) return false;
  if (f.statusMax !== undefined && (x.status ?? 0) > f.statusMax) return false;
  if (f.inScopeOnly && !x.in_scope) return false;
  const ext = x.path.split('?')[0]!.split('.').pop()?.toLowerCase() ?? '';
  if (f.hideExt && f.hideExt.split(',').map((e) => e.trim().toLowerCase()).includes(ext)) return false;
  return true;
}
