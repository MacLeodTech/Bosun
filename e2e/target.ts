// A stand-in for a hostile site. Its pages try to run script in whatever shows them; `/hit` records every
// call-back, so a test can assert that none arrived.
import http from 'node:http';

export const hits: string[] = [];
export const seen: { path: string; headers: http.IncomingHttpHeaders }[] = [];

export const EVIL_PAGE = `<!doctype html><title>evil</title>
<h1 id="evil-heading">evil page</h1>
<script>fetch('/hit?from=inline-script')</script>
<img src="/missing.png" onerror="fetch('/hit?from=onerror')">
<svg onload="fetch('/hit?from=svg-onload')"></svg>
<a href="javascript:fetch('/hit?from=js-url')">click</a>`;

export function startTarget(port: number): Promise<http.Server> {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://target.invalid');
    seen.push({ path: url.pathname, headers: req.headers });
    if (url.pathname === '/hit') {
      hits.push(url.searchParams.get('from') ?? '?');
      res.writeHead(204).end();
    } else if (url.pathname === '/evil') {
      res.writeHead(200, { 'content-type': 'text/html' }).end(EVIL_PAGE);
    } else if (url.pathname === '/big') {
      // 700 KiB of text with a marker at each end: more than one page of the history view.
      const body = 'START-MARK ' + 'x'.repeat(700 * 1024) + ' END-MARK';
      res.writeHead(200, { 'content-type': 'text/plain' }).end(body);
    } else if (url.pathname === '/json') {
      // About 190 KiB of compact JSON: 2,500 records, and tens of thousands of lines once pretty-printed.
      const items = Array.from({ length: 2500 }, (_, i) => ({ id: i, name: `item-${i}`, tags: ['a', 'b'], ok: i % 2 === 0, score: i * 1.5, note: null }));
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ items }));
    } else if (url.pathname === '/hits') {
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(hits));
    } else if (url.pathname === '/echo') {
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(req.headers));
    } else {
      res.writeHead(200, { 'content-type': 'text/plain' }).end(`hello from ${url.pathname}`);
    }
  });
  // `/ws` answers the upgrade and echoes each small text frame back as "echo: <text>" (a test stand-in, not a
  // full WebSocket server: payloads under 126 bytes, masked as clients send them).
  server.on('upgrade', (req, socket) => {
    seen.push({ path: new URL(req.url ?? '/', 'http://target.invalid').pathname, headers: req.headers });
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n');
    let buf = Buffer.alloc(0);
    socket.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 2) {
        const len = buf[1]! & 0x7f;
        const masked = (buf[1]! & 0x80) !== 0;
        const head = 2 + (masked ? 4 : 0);
        if (len >= 126 || buf.length < head + len) return;
        const opcode = buf[0]! & 0x0f;
        const payload = Buffer.from(buf.subarray(head, head + len));
        if (masked) for (let i = 0; i < len; i++) payload[i] = payload[i]! ^ buf[2 + (i % 4)]!;
        buf = buf.subarray(head + len);
        if (opcode === 0x1) {
          const out = Buffer.from('echo: ' + payload.toString());
          socket.write(Buffer.concat([Buffer.from([0x81, out.length]), out]));
        } else if (opcode === 0x8) {
          socket.end(Buffer.from([0x88, 0]));
          return;
        }
      }
    });
    socket.on('error', () => {});
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

/** Send a request through the Bosun proxy, the way a proxied browser would. */
export function viaProxy(proxyPort: number, url: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      { host: '127.0.0.1', port: proxyPort, method: 'GET', path: url, headers: { host: u.host, ...headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString() }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}
