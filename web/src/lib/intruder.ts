// The pure parts of the Intruder page: what the form turns into for the API, position markers, and sorting, filtering
// and exporting results. No DOM, so they are tested on their own.

import type { components } from './api-types';

type S = components['schemas'];
export type AttackType = S['AttackType'];
export type Row = S['Row'];
export type AttackInfo = S['AttackInfo'];
export type StartBody = S['StartBody'];
export type PayloadSet = S['PayloadSet'];
export type Op = S['Op'];

export const MARK = '§';

export const ATTACK_TYPES: { id: AttackType; label: string; help: string }[] = [
  { id: 'sniper', label: 'Sniper', help: 'One set. Each position in turn gets every payload; the others keep their text.' },
  { id: 'battering_ram', label: 'Battering ram', help: 'One set. Every position gets the same payload at once.' },
  { id: 'pitchfork', label: 'Pitchfork', help: 'One set per position, stepped together until the shortest runs out.' },
  { id: 'cluster_bomb', label: 'Cluster bomb', help: 'One set per position, every combination.' },
];

/** Encoders and decoders offered in processing rules. */
export const OPS: { id: Op; label: string }[] = [
  { id: 'url_encode', label: 'URL-encode' },
  { id: 'html_encode', label: 'HTML-encode' },
  { id: 'base64_encode', label: 'Base64-encode' },
  { id: 'base64url_encode', label: 'Base64url-encode' },
  { id: 'hex_encode', label: 'Hex-encode' },
  { id: 'unicode_escape', label: 'Unicode-escape' },
  { id: 'sha256', label: 'SHA-256' },
  { id: 'sha512', label: 'SHA-512' },
  { id: 'url_decode', label: 'URL-decode' },
  { id: 'html_decode', label: 'HTML-decode' },
  { id: 'base64_decode', label: 'Base64-decode' },
  { id: 'hex_decode', label: 'Hex-decode' },
];

export type SourceKind = 'list' | 'numbers' | 'brute_force' | 'null' | 'case_changes';
export type ProcKind = 'prefix' | 'suffix' | 'encode' | 'replace_regex' | 'skip_if_matches';

export interface ProcUi { type: ProcKind; value: string; op: Op; pattern: string; replacement: string }
export interface SetUi {
  source: SourceKind;
  /** One payload per line (lists and case changes). */
  list: string;
  from: number; to: number; step: number; base: 'decimal' | 'hex'; digits: number;
  charset: string; minLen: number; maxLen: number;
  count: number;
  processing: ProcUi[];
}
export interface GrepMatchUi { pattern: string; regex: boolean; caseInsensitive: boolean }
export interface OptionsUi {
  concurrency: number; delayMs: number; retries: number; maxRequests: number | null;
  updateContentLength: boolean; verifyTls: boolean; timeoutSecs: number;
}

export const blankSet = (): SetUi => ({
  source: 'list', list: '', from: 1, to: 100, step: 1, base: 'decimal', digits: 0,
  charset: 'abcdefghijklmnopqrstuvwxyz', minLen: 1, maxLen: 3, count: 10, processing: [],
});
export const blankProc = (type: ProcKind = 'prefix'): ProcUi => ({ type, value: '', op: 'url_encode', pattern: '', replacement: '' });
export const blankOptions = (): OptionsUi => ({
  concurrency: 5, delayMs: 0, retries: 0, maxRequests: null, updateContentLength: true, verifyTls: false, timeoutSecs: 30,
});

/** One payload per line; blank lines are left out. */
const lines = (t: string) => t.split(/\r?\n/).filter((l) => l !== '');

export function setBody(s: SetUi): PayloadSet {
  const source: S['PayloadSource'] =
    s.source === 'list' ? { type: 'list', items: lines(s.list) }
    : s.source === 'case_changes' ? { type: 'case_changes', items: lines(s.list) }
    : s.source === 'numbers' ? { type: 'numbers', from: s.from, to: s.to, step: s.step, base: s.base, min_digits: s.digits }
    : s.source === 'brute_force' ? { type: 'brute_force', charset: s.charset, min_len: s.minLen, max_len: s.maxLen }
    : { type: 'null', count: s.count };
  const processing = s.processing.map((p): S['Processing'] =>
    p.type === 'prefix' ? { type: 'prefix', value: p.value }
    : p.type === 'suffix' ? { type: 'suffix', value: p.value }
    : p.type === 'encode' ? { type: 'encode', op: p.op }
    : p.type === 'replace_regex' ? { type: 'replace_regex', pattern: p.pattern, replacement: p.replacement }
    : { type: 'skip_if_matches', pattern: p.pattern });
  return { source, processing };
}

/** The reverse of `setBody`, for opening an attack that was run before. Anything it does not understand is left blank. */
export function setFromBody(b: PayloadSet): SetUi {
  const s = blankSet();
  const src = b.source;
  if (src.type === 'list' || src.type === 'case_changes') { s.source = src.type; s.list = src.items.join('\n'); }
  else if (src.type === 'numbers') { s.source = 'numbers'; s.from = src.from; s.to = src.to; s.step = src.step ?? 1; s.base = src.base ?? 'decimal'; s.digits = src.min_digits ?? 0; }
  else if (src.type === 'brute_force') { s.source = 'brute_force'; s.charset = src.charset; s.minLen = src.min_len; s.maxLen = src.max_len; }
  else if (src.type === 'null') { s.source = 'null'; s.count = src.count; }
  s.processing = (b.processing ?? []).map((p) => {
    const u = blankProc(p.type);
    if (p.type === 'prefix' || p.type === 'suffix') u.value = p.value;
    else if (p.type === 'encode') u.op = p.op;
    else if (p.type === 'replace_regex') { u.pattern = p.pattern; u.replacement = p.replacement; }
    else u.pattern = p.pattern;
    return u;
  });
  return s;
}

export function optionsBody(o: OptionsUi): S['Options'] {
  return {
    concurrency: o.concurrency, delay_ms: o.delayMs, retries: o.retries, max_requests: o.maxRequests || null,
    update_content_length: o.updateContentLength, verify_tls: o.verifyTls, timeout_secs: o.timeoutSecs,
  };
}

/** The request as bytes in base64: line ends become CRLF unless the text already has them, and non-ASCII is UTF-8. */
export function requestB64(text: string): string {
  const t = text.includes('\r\n') ? text : text.replace(/\n/g, '\r\n');
  const bytes = new TextEncoder().encode(t);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** How many positions the text has (pairs of markers). */
export function countPositions(text: string): number {
  let n = 0;
  for (const ch of text) if (ch === MARK) n++;
  return Math.floor(n / 2);
}

/** Put markers around the selected text (or an empty position at a caret). */
export function markSelection(text: string, start: number, end: number): { text: string; start: number; end: number } {
  return { text: text.slice(0, start) + MARK + text.slice(start, end) + MARK + text.slice(end), start: start + 1, end: end + 1 };
}

export function clearMarks(text: string): string {
  return text.split(MARK).join('');
}

/** Mark the value of every query parameter in the request line and of every form field in a urlencoded body. */
export function autoMark(text: string): string {
  const t = clearMarks(text);
  const nl = t.indexOf('\n');
  const first = nl < 0 ? t : t.slice(0, nl);
  const rest = nl < 0 ? '' : t.slice(nl);
  const q = first.replace(/([?&][^=&\s#]+=)([^&\s#]*)/g, `$1${MARK}$2${MARK}`);
  const split = rest.search(/\r?\n\r?\n/);
  if (split < 0) return q + rest;
  const gap = /^\r?\n\r?\n/.exec(rest.slice(split))![0];
  const head = rest.slice(0, split + gap.length);
  const body = rest.slice(split + gap.length);
  const isForm = /content-type:\s*application\/x-www-form-urlencoded/i.test(head);
  const marked = isForm ? body.replace(/(^|&)([^=&\s]+=)([^&\s]*)/g, `$1$2${MARK}$3${MARK}`) : body;
  return q + head + marked;
}

// ---- results

export type SortKey = 'index' | 'payload' | 'status' | 'length' | 'time' | `match:${number}` | `extract:${number}`;

const cmp = (a: number | string, b: number | string) => (a < b ? -1 : a > b ? 1 : 0);

export function sortRows(rows: Row[], key: SortKey, asc: boolean): Row[] {
  const val = (r: Row): number | string =>
    key === 'index' ? r.index
    : key === 'payload' ? r.payloads.join('\u0000')
    : key === 'status' ? (r.status ?? -1)
    : key === 'length' ? r.length
    : key === 'time' ? r.time_ms
    : key.startsWith('match:') ? (r.matches[Number(key.slice(6))] ? 1 : 0)
    : (r.extracts[Number(key.slice(8))] ?? '');
  const out = rows.slice().sort((a, b) => cmp(val(a), val(b)) || a.index - b.index);
  return asc ? out : out.reverse();
}

/**
 * Filter by text: words must all be found in the payloads, the status, the error or an extracted value. `status:404`,
 * `length:>1000`, `time:>500`, `match` (any grep rule matched) and `error` (no answer) narrow by field.
 */
export function filterRows(rows: Row[], q: string): Row[] {
  const terms = q.trim().split(/\s+/).filter(Boolean);
  if (!terms.length) return rows;
  const test = (r: Row, t: string): boolean => {
    const m = /^(status|length|time):(>=|<=|>|<|=)?(\d+)$/.exec(t);
    if (m) {
      const v = m[1] === 'status' ? (r.status ?? -1) : m[1] === 'length' ? r.length : r.time_ms;
      const n = Number(m[3]);
      switch (m[2]) {
        case '>': return v > n;
        case '<': return v < n;
        case '>=': return v >= n;
        case '<=': return v <= n;
        default: return v === n;
      }
    }
    if (t === 'match') return r.matches.some(Boolean);
    if (t === 'error') return !!r.error || r.status == null;
    const hay = [...r.payloads, String(r.status ?? ''), r.error ?? '', ...r.extracts.map((e) => e ?? '')].join('\n').toLowerCase();
    return hay.includes(t.toLowerCase());
  };
  return rows.filter((r) => terms.every((t) => test(r, t)));
}

/** One CSV cell. Target-controlled text that a spreadsheet would run as a formula gets a leading quote. */
export function csvCell(v: string | number | boolean | null | undefined): string {
  let s = v == null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function rowsToCsv(rows: Row[], matchLabels: string[], extractLabels: string[]): string {
  const head = ['request', 'position', 'payloads', 'status', 'length', 'time_ms', 'flow', 'error', ...matchLabels.map((l) => `match: ${l}`), ...extractLabels.map((l) => `extract: ${l}`)];
  const out = [head.map(csvCell).join(',')];
  for (const r of rows) {
    out.push([
      r.index + 1, r.position == null ? '' : r.position + 1, r.payloads.join(' | '), r.status ?? '', r.length, r.time_ms, r.flow_id ?? '', r.error ?? '',
      ...matchLabels.map((_, i) => (r.matches[i] ? 'yes' : '')), ...extractLabels.map((_, i) => r.extracts[i] ?? ''),
    ].map(csvCell).join(','));
  }
  return out.join('\r\n') + '\r\n';
}
