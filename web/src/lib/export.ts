// Turning recorded requests into things to paste or save: a cURL command (POSIX shell or PowerShell), code snippets, and
// a HAR file. All pure text-in, text-out, so every format has golden tests, including hostile header values.
//
// Secrets (cookies, authorization and similar headers) are replaced by REDACTED unless the caller asks to keep them.
// Cookie names stay, so the output still shows which cookies were there.

export type Header = [name: string, value: string];

export interface ParsedRequest {
  method: string;
  url: string;
  headers: Header[];
  body: string;
}

const MAX_BODY = 64 * 1024;
/** Headers the tools below set themselves or that make no sense to replay. */
const SKIP = new Set(['host', 'content-length', 'connection', 'accept-encoding']);

const SECRET = new Set(['authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'api-key', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token', 'x-amz-security-token']);

export const REDACTED = 'REDACTED';

/** A header value with its secret parts replaced. Cookie headers keep the cookie names. */
export function redactValue(name: string, value: string): string {
  const n = name.toLowerCase();
  if (!SECRET.has(n)) return value;
  if (n === 'cookie') return value.split(';').map((c) => { const t = c.trim(); const i = t.indexOf('='); return i < 0 ? REDACTED : `${t.slice(0, i)}=${REDACTED}`; }).join('; ');
  if (n === 'set-cookie') {
    const parts = value.split(';');
    const first = parts[0] ?? '';
    const i = first.indexOf('=');
    parts[0] = i < 0 ? REDACTED : `${first.slice(0, i)}=${REDACTED}`;
    return parts.join(';');
  }
  return REDACTED;
}

export const redactHeaders = (hs: Header[]): Header[] => hs.map(([k, v]): Header => [k, redactValue(k, v)]);

/** Lone surrogates cannot be written in most languages' string literals; U+FFFD is the honest stand-in. */
const wellFormed = (s: string) => s.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '�');

/** `head` is the start line and headers; `body` the text after the blank line. `scheme` is http or https. */
export function parseRequest(head: string, body: string, scheme: string, binary = false): ParsedRequest | null {
  if (binary || body.length > MAX_BODY || !scheme) return null;
  const lines = head.split(/\r?\n/);
  const m = /^(\S+)\s+(\S+)/.exec(lines[0] ?? '');
  if (!m) return null;
  const headers = lines
    .slice(1)
    .filter((l) => l.length)
    .map((l): Header => {
      const i = l.indexOf(':');
      return i < 0 ? [l, ''] : [l.slice(0, i), l.slice(i + 1).trim()];
    });
  const host = headers.find(([k]) => k.toLowerCase() === 'host')?.[1];
  const absolute = /^[a-z]+:\/\//i.test(m[2]!);
  if (!host && !absolute) return null;
  return { method: m[1]!, url: absolute ? m[2]! : `${scheme}://${host}${m[2]}`, headers, body };
}

const keep = (r: ParsedRequest, secrets: boolean): Header[] => {
  const hs = r.headers.filter(([k]) => !SKIP.has(k.toLowerCase()));
  return secrets ? hs : redactHeaders(hs);
};

// ---- cURL

/** POSIX shell: single quotes hold everything literally; a quote inside is `'\''`. */
const posix = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** PowerShell: single quotes are literal too, but PowerShell also reads the typographic single quotes as quotes. */
const ps = (s: string) => `'${s.replace(/['‘’‚‛]/g, (c) => c + c)}'`;

export function toCurl(r: ParsedRequest, shell: 'posix' | 'powershell' = 'posix', secrets = false): string {
  const hs = keep(r, secrets);
  if (shell === 'powershell') {
    // `curl` in PowerShell is an alias of Invoke-WebRequest, and native arguments lose their double quotes on older
    // versions, so this is Invoke-WebRequest with its own parameters. Repeated headers are joined (the hashtable
    // cannot hold two); Content-Type and User-Agent have parameters of their own.
    const merged = new Map<string, { name: string; values: string[] }>();
    for (const [k, v] of hs) {
      const e = merged.get(k.toLowerCase());
      if (e) e.values.push(v);
      else merged.set(k.toLowerCase(), { name: k, values: [v] });
    }
    const join = (e: { name: string; values: string[] }) => e.values.join(e.name.toLowerCase() === 'cookie' ? '; ' : ', ');
    const ct = merged.get('content-type');
    const ua = merged.get('user-agent');
    merged.delete('content-type');
    merged.delete('user-agent');
    const parts = [`Invoke-WebRequest -Uri ${ps(r.url)} -Method ${ps(r.method)}`];
    if (merged.size) parts.push(`-Headers @{ ${[...merged.values()].map((e) => `${ps(e.name)} = ${ps(join(e))}`).join('; ')} }`);
    if (ct) parts.push(`-ContentType ${ps(join(ct))}`);
    if (ua) parts.push(`-UserAgent ${ps(join(ua))}`);
    if (r.body) parts.push(`-Body ${ps(r.body)}`);
    return parts.join(' `\n  ');
  }
  const parts = [`curl -i -X ${r.method} ${posix(r.url)}`];
  for (const [k, v] of hs) parts.push(`-H ${posix(`${k}: ${v}`)}`);
  if (r.body) parts.push(`--data-binary ${posix(r.body)}`);
  return parts.join(' \\\n  ');
}

// ---- code snippets

export type Snippet = 'python' | 'javascript' | 'go';
export const SNIPPETS: { id: Snippet; label: string }[] = [
  { id: 'python', label: 'Python (requests)' },
  { id: 'javascript', label: 'JavaScript (fetch)' },
  { id: 'go', label: 'Go (net/http)' },
];

/** A string literal that JSON, Python, JavaScript and Go all read the same way. */
const lit = (s: string) => JSON.stringify(wellFormed(s));

export function toSnippet(r: ParsedRequest, lang: Snippet, secrets = false): string {
  const hs = keep(r, secrets);
  if (lang === 'python') {
    const lines = ['import requests', '', 'response = requests.request(', `    ${lit(r.method)},`, `    ${lit(r.url)},`];
    // A list of pairs keeps repeated headers; requests accepts it.
    if (hs.length) lines.push(`    headers=[${hs.map(([k, v]) => `(${lit(k)}, ${lit(v)})`).join(', ')}],`);
    if (r.body) lines.push(`    data=${lit(r.body)}.encode("utf-8"),`);
    lines.push(')', 'print(response.status_code)', 'print(response.text)');
    return lines.join('\n');
  }
  if (lang === 'javascript') {
    const opts = [`  method: ${lit(r.method)},`];
    if (hs.length) opts.push(`  headers: [${hs.map(([k, v]) => `[${lit(k)}, ${lit(v)}]`).join(', ')}],`);
    if (r.body) opts.push(`  body: ${lit(r.body)},`);
    return [`const response = await fetch(${lit(r.url)}, {`, ...opts, '});', 'console.log(response.status, await response.text());'].join('\n');
  }
  const body = r.body ? `strings.NewReader(${lit(r.body)})` : 'nil';
  return [
    'package main',
    '',
    'import (',
    '\t"fmt"',
    '\t"io"',
    '\t"net/http"',
    ...(r.body ? ['\t"strings"'] : []),
    ')',
    '',
    'func main() {',
    `\treq, err := http.NewRequest(${lit(r.method)}, ${lit(r.url)}, ${body})`,
    '\tif err != nil {',
    '\t\tpanic(err)',
    '\t}',
    ...hs.map(([k, v]) => `\treq.Header.Add(${lit(k)}, ${lit(v)})`),
    '\tres, err := http.DefaultClient.Do(req)',
    '\tif err != nil {',
    '\t\tpanic(err)',
    '\t}',
    '\tdefer res.Body.Close()',
    '\tout, _ := io.ReadAll(res.Body)',
    '\tfmt.Println(res.Status, string(out))',
    '}',
  ].join('\n');
}

// ---- HAR 1.2

export interface HarMessage {
  /** The start line and headers, as text. */
  head: string;
  /** The body as bytes; `text` is used when it is valid UTF-8, base64 otherwise. */
  body: Uint8Array;
  /** The body's size on the wire when it is more than what is held here. */
  bodySize?: number;
}

export interface HarInput {
  startedMs: number;
  durationMs: number | null;
  url: string;
  method: string;
  httpVersion: string;
  request: HarMessage;
  response: HarMessage | null;
  status: number | null;
}

const headerList = (head: string): Header[] =>
  head.split(/\r?\n/).slice(1).filter((l) => l.length).map((l): Header => { const i = l.indexOf(':'); return i < 0 ? [l, ''] : [l.slice(0, i), l.slice(i + 1).trim()]; });

const pairs = (hs: Header[]) => hs.map(([name, value]) => ({ name, value }));

function content(m: HarMessage, mime: string) {
  let text: string | null = null;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(m.body);
  } catch {
    text = null;
  }
  if (text !== null) return { size: m.bodySize ?? m.body.length, mimeType: mime, text };
  let bin = '';
  for (const b of m.body) bin += String.fromCharCode(b);
  return { size: m.bodySize ?? m.body.length, mimeType: mime, text: btoa(bin), encoding: 'base64' };
}

function cookiesOf(hs: Header[], header: 'cookie' | 'set-cookie') {
  const out: { name: string; value: string }[] = [];
  for (const [k, v] of hs) {
    if (k.toLowerCase() !== header) continue;
    const list = header === 'cookie' ? v.split(';') : [v.split(';')[0] ?? ''];
    for (const c of list) {
      const t = c.trim();
      const i = t.indexOf('=');
      if (t) out.push(i < 0 ? { name: t, value: '' } : { name: t.slice(0, i), value: t.slice(i + 1) });
    }
  }
  return out;
}

/** A HAR 1.2 document. `secrets` false replaces cookie and authorization values everywhere they appear. */
export function toHar(entries: HarInput[], secrets = false, version = '0'): object {
  const clean = (hs: Header[]) => (secrets ? hs : redactHeaders(hs));
  return {
    log: {
      version: '1.2',
      creator: { name: 'Bosun', version },
      entries: entries.map((e) => {
        const rh = clean(headerList(e.request.head));
        const ct = rh.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? '';
        const q = (() => {
          try {
            return [...new URL(e.url).searchParams].map(([name, value]) => ({ name, value }));
          } catch {
            return [];
          }
        })();
        const res = e.response;
        const sh = res ? clean(headerList(res.head)) : [];
        const sct = sh.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? '';
        return {
          startedDateTime: new Date(e.startedMs).toISOString(),
          time: e.durationMs ?? 0,
          request: {
            method: e.method,
            url: e.url,
            httpVersion: e.httpVersion,
            cookies: cookiesOf(rh, 'cookie'),
            headers: pairs(rh),
            queryString: q,
            ...(e.request.body.length ? { postData: { mimeType: ct, text: content(e.request, ct).text, ...(content(e.request, ct).encoding ? { comment: 'base64' } : {}) } } : {}),
            headersSize: -1,
            bodySize: e.request.bodySize ?? e.request.body.length,
          },
          response: res
            ? {
                status: e.status ?? 0,
                statusText: (/^\S+\s+\d+\s*(.*)$/.exec(res.head.split(/\r?\n/)[0] ?? '')?.[1] ?? '').trim(),
                httpVersion: (res.head.split(/\s/)[0] ?? e.httpVersion) || e.httpVersion,
                cookies: cookiesOf(sh, 'set-cookie'),
                headers: pairs(sh),
                content: content(res, sct),
                redirectURL: sh.find(([k]) => k.toLowerCase() === 'location')?.[1] ?? '',
                headersSize: -1,
                bodySize: res.bodySize ?? res.body.length,
              }
            : { status: 0, statusText: '', httpVersion: e.httpVersion, cookies: [], headers: [], content: { size: 0, mimeType: '' }, redirectURL: '', headersSize: -1, bodySize: -1 },
          cache: {},
          timings: { send: 0, wait: e.durationMs ?? 0, receive: 0 },
        };
      }),
    },
  };
}
