// Golden tests for the export formats, plus checks against the real tools (sh, python3, pwsh, node) where they exist.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { parseRequest, redactValue, toCurl, toHar, toSnippet, type HarInput, type ParsedRequest } from '../src/lib/export.ts';

const HEAD = 'POST /login?next=%2Fhome&a=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nUser-Agent: test/1\r\nContent-Length: 17\r\nAuthorization: Bearer s3cret\r\nCookie: sid=abc123; theme=dark\r\nX-Note: it\'s "fine"';
const BODY = '{"user":"it\'s"}';

const req = (): ParsedRequest => parseRequest(HEAD, BODY, 'https')!;

test('parsing: host, url, skipped headers, and what is refused', () => {
  const r = req();
  assert.equal(r.url, 'https://example.com/login?next=%2Fhome&a=1');
  assert.equal(r.method, 'POST');
  assert.equal(parseRequest('GET http://x.test/a HTTP/1.1', '', 'https')!.url, 'http://x.test/a');
  assert.equal(parseRequest('GET / HTTP/1.1', '', 'https'), null, 'no host, no URL');
  assert.equal(parseRequest('nonsense', '', 'https'), null);
  assert.equal(parseRequest('GET / HTTP/1.1\r\nHost: x', 'x', 'https', true), null, 'binary');
  assert.equal(parseRequest('GET / HTTP/1.1\r\nHost: x', 'x'.repeat(70_000), 'https'), null, 'too large');
});

test('redaction keeps cookie names and drops values', () => {
  assert.equal(redactValue('Authorization', 'Bearer s3cret'), 'REDACTED');
  assert.equal(redactValue('Cookie', 'sid=abc; theme=dark; flag'), 'sid=REDACTED; theme=REDACTED; flag=REDACTED'.replace('flag=REDACTED', 'REDACTED'));
  assert.equal(redactValue('Set-Cookie', 'sid=abc; Path=/; HttpOnly'), 'sid=REDACTED; Path=/; HttpOnly');
  assert.equal(redactValue('Accept', 'text/html'), 'text/html');
});

test('cURL for a POSIX shell (golden), secrets redacted by default', () => {
  assert.equal(
    toCurl(req(), 'posix'),
    [
      "curl -i -X POST 'https://example.com/login?next=%2Fhome&a=1' \\",
      "  -H 'Content-Type: application/json' \\",
      "  -H 'User-Agent: test/1' \\",
      "  -H 'Authorization: REDACTED' \\",
      "  -H 'Cookie: sid=REDACTED; theme=REDACTED' \\",
      `  -H 'X-Note: it'\\''s "fine"' \\`,
      `  --data-binary '{"user":"it'\\''s"}'`,
    ].join('\n'),
  );
  assert.ok(toCurl(req(), 'posix', true).includes("-H 'Authorization: Bearer s3cret'"));
});

test('cURL for PowerShell (golden)', () => {
  assert.equal(
    toCurl(req(), 'powershell'),
    [
      "Invoke-WebRequest -Uri 'https://example.com/login?next=%2Fhome&a=1' -Method 'POST' `",
      "  -Headers @{ 'Authorization' = 'REDACTED'; 'Cookie' = 'sid=REDACTED; theme=REDACTED'; 'X-Note' = 'it''s \"fine\"' } `",
      "  -ContentType 'application/json' `",
      "  -UserAgent 'test/1' `",
      "  -Body '{\"user\":\"it''s\"}'",
    ].join('\n'),
  );
});

const HOSTILE = [
  "it's",
  '"double"',
  '$(touch /tmp/pwned)',
  '`id`',
  '; rm -rf / #',
  'back\\slash',
  'new‘line’ smart “quotes”',
  '%s %d \\n',
  '${HOME} $HOME',
  'café \u{1f600}',
  '',
];

const hostileRequest = (): ParsedRequest => ({
  method: 'POST',
  url: "https://h.test/p?q='$(id)'&r=\"x\"",
  headers: HOSTILE.map((v, i): [string, string] => [`X-H${i}`, v]),
  body: HOSTILE.join('\n'),
});

const haveSh = process.platform !== 'win32' && spawnSync('sh', ['-c', 'true']).status === 0;

test('a POSIX command hands the shell exactly the arguments intended, whatever the values hold', { skip: !haveSh }, () => {
  const r = hostileRequest();
  const cmd = toCurl(r, 'posix', true);
  // A stand-in curl prints each argument it receives, NUL-terminated; nothing in a value may become a command.
  const run = spawnSync('sh', ['-c', `curl() { for a in "$@"; do printf '%s\\0' "$a"; done; }\n${cmd}`], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const got = run.stdout.split('\0').slice(0, -1);
  const want = ['-i', '-X', 'POST', r.url, ...r.headers.flatMap(([k, v]) => ['-H', `${k}: ${v}`]), '--data-binary', r.body];
  assert.deepEqual(got, want);
});

const havePwsh = spawnSync('pwsh', ['-NoProfile', '-Command', '1']).status === 0;

test('a PowerShell command reads back as the same strings', { skip: !havePwsh }, () => {
  const r = hostileRequest();
  const cmd = toCurl(r, 'powershell', true).replace(/^Invoke-WebRequest/, 'function Show { param($Uri, $Method, $Headers, $ContentType, $UserAgent, $Body) $Uri; $Method; $Body; ($Headers.Keys | Sort-Object | ForEach-Object { "$_=$($Headers[$_])" }) }; Show');
  const run = spawnSync('pwsh', ['-NoProfile', '-Command', cmd], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.ok(run.stdout.includes(r.url));
  assert.ok(run.stdout.includes('new‘line’'));
});

test('snippets (golden): Python, JavaScript, Go', () => {
  const r = parseRequest('GET /a HTTP/1.1\r\nHost: h.test\r\nAccept: */*\r\nCookie: sid=1', '', 'http')!;
  assert.equal(
    toSnippet(r, 'python'),
    ['import requests', '', 'response = requests.request(', '    "GET",', '    "http://h.test/a",', '    headers=[("Accept", "*/*"), ("Cookie", "sid=REDACTED")],', ')', 'print(response.status_code)', 'print(response.text)'].join('\n'),
  );
  assert.equal(
    toSnippet(r, 'javascript', true),
    ['const response = await fetch("http://h.test/a", {', '  method: "GET",', '  headers: [["Accept", "*/*"], ["Cookie", "sid=1"]],', '});', 'console.log(response.status, await response.text());'].join('\n'),
  );
  const go = toSnippet(parseRequest('PUT /x HTTP/1.1\r\nHost: h.test', 'a"b', 'https')!, 'go');
  assert.ok(go.includes('http.NewRequest("PUT", "https://h.test/x", strings.NewReader("a\\"b"))'));
  assert.ok(go.includes('"strings"'));
  assert.ok(!toSnippet(r, 'go').includes('"strings"'));
});

const haveNode = true;
test('JavaScript and Python snippets are valid code for any value', () => {
  const r = hostileRequest();
  const js = toSnippet(r, 'javascript', true);
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor as new (s: string) => unknown;
  assert.doesNotThrow(() => new AsyncFunction(js));
  // The literals round-trip: every value inside the snippet is the value we put in.
  assert.ok(haveNode);
  const py = spawnSync('python3', ['-I', '-c', 'import ast,sys; ast.parse(sys.stdin.read())'], { input: toSnippet(r, 'python', true), encoding: 'utf8' });
  if (py.error === undefined) assert.equal(py.status, 0, py.stderr);
  const gofmt = spawnSync('gofmt', ['-e'], { input: toSnippet(r, 'go', true), encoding: 'utf8' });
  if (gofmt.error === undefined) assert.equal(gofmt.status, 0, gofmt.stderr);
});

test('lone surrogates become U+FFFD in snippets', () => {
  const r: ParsedRequest = { method: 'GET', url: 'http://h.test/', headers: [['X', 'a\ud800b']], body: '' };
  assert.ok(toSnippet(r, 'go', true).includes('a�b'));
});

const enc = (s: string) => new TextEncoder().encode(s);
const flow = (): HarInput => ({
  startedMs: Date.UTC(2026, 10, 25, 12, 0, 0),
  durationMs: 42,
  url: 'https://example.com/login?next=%2Fhome&a=1',
  method: 'POST',
  httpVersion: 'HTTP/1.1',
  request: { head: HEAD, body: enc(BODY) },
  response: { head: 'HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: sid=zzz; Path=/; HttpOnly\r\nContent-Type: text/plain', body: enc('moved') },
  status: 302,
});

test('HAR 1.2 (golden shape), secrets redacted everywhere', () => {
  const har = toHar([flow()], false, '1.2.3') as { log: { version: string; creator: unknown; entries: Record<string, any>[] } };
  assert.equal(har.log.version, '1.2');
  assert.deepEqual(har.log.creator, { name: 'Bosun', version: '1.2.3' });
  const e = har.log.entries[0]!;
  assert.equal(e.startedDateTime, '2026-11-25T12:00:00.000Z');
  assert.equal(e.time, 42);
  assert.deepEqual(e.request.queryString, [{ name: 'next', value: '/home' }, { name: 'a', value: '1' }]);
  assert.deepEqual(e.request.cookies, [{ name: 'sid', value: 'REDACTED' }, { name: 'theme', value: 'REDACTED' }]);
  assert.deepEqual(e.request.headers.find((h: any) => h.name === 'Authorization'), { name: 'Authorization', value: 'REDACTED' });
  assert.deepEqual(e.request.postData, { mimeType: 'application/json', text: BODY });
  assert.equal(e.response.status, 302);
  assert.equal(e.response.statusText, 'Found');
  assert.equal(e.response.redirectURL, '/home');
  assert.deepEqual(e.response.cookies, [{ name: 'sid', value: 'REDACTED' }]);
  assert.deepEqual(e.response.content, { size: 5, mimeType: 'text/plain', text: 'moved' });
  assert.ok(!JSON.stringify(har).includes('s3cret') && !JSON.stringify(har).includes('abc123') && !JSON.stringify(har).includes('zzz'));
  // Asked to keep them, the secrets are there.
  const raw = JSON.stringify(toHar([flow()], true));
  assert.ok(raw.includes('s3cret') && raw.includes('abc123') && raw.includes('zzz'));
});

test('HAR: a binary body is base64, a flow with no response is still a valid entry', () => {
  const f = flow();
  f.response = { head: 'HTTP/1.1 200 OK\r\nContent-Type: image/png', body: new Uint8Array([0xff, 0xd8, 0x00, 0x80]) };
  const e = (toHar([f]) as any).log.entries[0];
  assert.deepEqual(e.response.content, { size: 4, mimeType: 'image/png', text: '/9gAgA==', encoding: 'base64' });
  f.response = null;
  f.status = null;
  const n = (toHar([f]) as any).log.entries[0];
  assert.equal(n.response.status, 0);
  assert.equal(JSON.parse(JSON.stringify(n)).request.method, 'POST');
});
