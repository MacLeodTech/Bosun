// The pure parts of the History query bar: completion of the word at the caret, the list of past queries, and the
// conversion between the server's byte offsets and JavaScript string positions. The grammar itself is the server's
// (docs/query-language.md); nothing here decides what a query means.

export interface KeyInfo { key: string; hint: string; values?: string[] }

/** The keys the server knows, with a few values worth offering. */
export const KEYS: KeyInfo[] = [
  { key: 'host', hint: 'host contains', values: [] },
  { key: 'method', hint: 'GET,POST', values: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'] },
  { key: 'status', hint: '404, 4xx, >=400', values: ['2xx', '3xx', '4xx', '5xx', '>=400'] },
  { key: 'scope', hint: 'in or out of scope', values: ['in', 'out'] },
  { key: 'ext', hint: 'path extension (-ext: hides)', values: ['png', 'css', 'js', 'json', 'html'] },
  { key: 'source', hint: 'where it came from', values: ['proxy', 'repeater', 'intruder', 'scanner', 'import'] },
  { key: 'header', hint: 'name or name=value', values: ['content-type', 'authorization', 'cookie', 'set-cookie', 'user-agent'] },
  { key: 'tag', hint: 'has this tag' },
  { key: 'note', hint: 'note contains' },
  { key: 'has', hint: 'note, error, edited, response', values: ['note', 'error', 'edited', 'response'] },
  { key: 'mime', hint: 'response type contains', values: ['json', 'html', 'javascript', 'image', 'xml'] },
  { key: 'path', hint: 'path contains' },
  { key: 'port', hint: 'port number' },
  { key: 'scheme', hint: 'http or https', values: ['http', 'https'] },
  { key: 'size', hint: 'response size: >10k, 1k-1m', values: ['>10k', '>1m', '<1k'] },
  { key: 'since', hint: 'started after: 10m, 2h, 7d, a date', values: ['10m', '1h', '1d', '7d'] },
  { key: 'until', hint: 'started before: 10m, 2h, 7d, a date', values: ['10m', '1h', '1d', '7d'] },
];

export interface Suggestion {
  /** What is shown. */
  label: string;
  hint: string;
  /** The text that replaces the word at the caret. */
  insert: string;
}

export interface Completion {
  /** The word being completed: `from` to `to` in the line. */
  from: number;
  to: number;
  items: Suggestion[];
}

const isSpace = (c: string) => c === ' ' || c === '\t' || c === '\n' || c === '\r';

/** Suggestions for the word the caret is in or at the end of. Returns none inside a quoted phrase. */
export function complete(line: string, caret: number): Completion {
  const at = Math.max(0, Math.min(caret, line.length));
  const none: Completion = { from: at, to: at, items: [] };
  // An odd number of quotes before the caret means the caret is inside a phrase.
  if (((line.slice(0, at).match(/"/g) ?? []).length & 1) === 1) return none;
  let from = at;
  while (from > 0 && !isSpace(line[from - 1]!)) from--;
  let to = at;
  while (to < line.length && !isSpace(line[to]!)) to++;
  const word = line.slice(from, at);
  const stripped = word.replace(/^-?\(*/, '');
  const lead = word.length - stripped.length;
  const start = from + lead;
  const colon = stripped.indexOf(':');
  if (colon < 0) {
    if (!stripped) return none;
    const p = stripped.toLowerCase();
    const items = KEYS.filter((k) => k.key.startsWith(p) && k.key !== p).map((k) => ({ label: `${k.key}:`, hint: k.hint, insert: `${k.key}:` }));
    return { from: start, to: start + (to - start), items: items.slice(0, 8) };
  }
  const key = stripped.slice(0, colon).toLowerCase();
  const info = KEYS.find((k) => k.key === key);
  if (!info?.values?.length) return none;
  const value = stripped.slice(colon + 1);
  // After a comma the new part is what is completed.
  const comma = value.lastIndexOf(',');
  const typed = value.slice(comma + 1).toLowerCase();
  const base = start + colon + 1 + comma + 1;
  const items = info.values
    .filter((v) => v.toLowerCase().startsWith(typed) && v.toLowerCase() !== typed)
    .map((v) => ({ label: v, hint: `${key}:`, insert: v }));
  return { from: base, to: start + (to - start), items: items.slice(0, 8) };
}

/** The line with the suggestion put in place of the word it completes. */
export function applyCompletion(line: string, c: Completion, s: Suggestion): { line: string; caret: number } {
  const next = line.slice(0, c.from) + s.insert + line.slice(c.to);
  return { line: next, caret: c.from + s.insert.length };
}

// ---- past queries

export const MAX_PAST = 25;

/** `past` with `q` first and no repeats; blank queries are not kept. */
export function remember(past: string[], q: string): string[] {
  const t = q.trim();
  if (!t) return past;
  return [t, ...past.filter((p) => p !== t)].slice(0, MAX_PAST);
}

// ---- byte offsets

/** The server reports positions in UTF-8 bytes; JavaScript strings index UTF-16 units. */
export function byteToIndex(s: string, byteOffset: number): number {
  if (byteOffset <= 0) return 0;
  let bytes = 0;
  let i = 0;
  while (i < s.length && bytes < byteOffset) {
    const cp = s.codePointAt(i)!;
    bytes += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    i += cp > 0xffff ? 2 : 1;
  }
  return i;
}
