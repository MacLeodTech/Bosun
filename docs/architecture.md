# Architecture

One engine, many front ends. The engine exposes a single versioned API (`/api/v1`, JSON plus a WebSocket event
stream). The web UI, the desktop app, the CLI and the planned TUI are all clients of it. No front end has a
private back door.

## Crates

| Crate | What it does |
|---|---|
| `bosun-model` | Shared types (flows, targets, WebSocket messages) and lenient raw HTTP parsing. No I/O. |
| `bosun-ca` | The per-install CA (P-256, path length 0), leaf certificates on demand (LRU cache), the sealed data key. |
| `bosun-store` | SQLite storage: projects (`.bosun`: flows, zstd content-addressed bodies, FTS5 trigram search, WebSocket messages, settings) and the account database (users, sessions, API tokens, audit log). |
| `bosun-scope` | Scope rules and the gate every tool request passes through, with the global stop switch. |
| `bosun-proxy` | The MITM proxy (hyper 1 + rustls): CONNECT, TLS interception with ALPN, h1/h2, WebSockets, upstream proxies, intercept, match and replace, the recorder, the loop guard. |
| `bosun-api` | axum API, authentication and authorisation, request-level security, the event stream, the embedded web UI, the browser launcher. |
| `bosun` | The library that assembles an engine from a config (`Engine::start`), and the CLI. |
| `bosun-desktop` | Tauri 2 shell: runs `Engine` in-process and shows the web UI in a native window. |
| `web/` | Svelte 5 + TypeScript UI, built to static files and embedded with `rust-embed`. |

## Flow of a proxied request

1. A client connects to the proxy listener. The connection is refused if it comes from one of the proxy's own
   outbound sockets (loop guard), or from a client not allowed by `allow_clients`/proxy auth.
2. `CONNECT host:443`: the proxy peeks at the first byte. TLS (0x16) is intercepted with a leaf certificate for
   the SNI name (or the CONNECT host), unless the host is on the pass-through list. Anything else is tunnelled.
3. The request is checked against match-and-replace rules, then held for interception if that is on and the
   request is in scope (or all requests, if configured).
4. The upstream connector refuses targets that are the engine's own listeners, connects directly or through the
   upstream proxy, and registers the local address of its socket with the loop guard.
5. Responses up to `max_buffered_response` are buffered (so they can be intercepted and rewritten); larger or
   streaming responses are passed through a tee that records up to `record_body_limit`.
6. The recorder batches flows to SQLite on its own thread (up to 256 per transaction or every 50 ms) and publishes
   a summary event for the UI.

## Storage

A project is one SQLite file in WAL mode with `secure_delete`. Bodies are stored once per content hash,
compressed with zstd. Full-text search uses a contentless FTS5 table with the trigram tokenizer, so substring
search works without storing the text twice. Account data lives in a separate `app.db`, so a project file can be
shared without sharing accounts.

## Front-end rules

- No inline script or style anywhere (the CSP forbids both). Dynamic sizes are set through the CSSOM.
- Target content is shown as text; the render view is a sandboxed `srcdoc` iframe without scripts.
- Bytes travel as base64 and are shown as UTF-8 when valid, Latin-1 otherwise, so edits never alter untouched bytes.
- The UI is a dock of panels (`web/src/lib/layout.ts`, `workspace.svelte.ts`, `components/dock/`). The layout is a tree
  of splits and tab groups; `layout.ts` is pure and tested (`npm test` in `web/`). Panels stay mounted while their tab
  is in the background, so a panel must not act on window-level input unless `usePanel().visible` is true.
- Why our own dock and not `dockview-core` (spike, 2026-11-25, by reading the package, not by a browser run): the
  npm package ships no stylesheet, so the whole `.dv-*` class set would still have to be written and kept in step
  with a library that is about 400 KB minified; its pop-out path copies stylesheets by injecting `<style>` elements,
  which `style-src 'self'` blocks; and our pop-out design (a second app instance per window, sharing the session) does
  not use its pop-out at all. The engine is about 600 lines with property-style tests.
