// "Copy as cURL": a shell command for an HTTP request given as text. Only for text bodies of a size a command line can
// hold; anything else returns null and the caller hides the action.

const MAX_BODY = 64 * 1024;
const SKIP = new Set(['host', 'content-length', 'connection', 'accept-encoding']);

const quote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** `head` is the start line and headers; `body` the text after the blank line. `scheme` is http or https. */
export function buildCurl(head: string, body: string, scheme: string, binary = false): string | null {
  if (binary || body.length > MAX_BODY || !scheme) return null;
  const lines = head.split(/\r?\n/);
  const m = /^(\S+)\s+(\S+)/.exec(lines[0] ?? '');
  if (!m) return null;
  const headers = lines
    .slice(1)
    .filter((l) => l.length)
    .map((l): [string, string] => {
      const i = l.indexOf(':');
      return i < 0 ? [l, ''] : [l.slice(0, i), l.slice(i + 1).trim()];
    });
  const host = headers.find(([k]) => k.toLowerCase() === 'host')?.[1];
  if (!host && !/^[a-z]+:\/\//i.test(m[2]!)) return null;
  const url = /^[a-z]+:\/\//i.test(m[2]!) ? m[2]! : `${scheme}://${host}${m[2]}`;
  const parts = [`curl -i -X ${m[1]} ${quote(url)}`];
  for (const [k, v] of headers) if (!SKIP.has(k.toLowerCase())) parts.push(`-H ${quote(`${k}: ${v}`)}`);
  if (body) parts.push(`--data-binary ${quote(body)}`);
  return parts.join(' \\\n  ');
}
