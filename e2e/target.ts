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
    } else if (url.pathname === '/hits') {
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(hits));
    } else if (url.pathname === '/echo') {
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(req.headers));
    } else {
      res.writeHead(200, { 'content-type': 'text/plain' }).end(`hello from ${url.pathname}`);
    }
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
