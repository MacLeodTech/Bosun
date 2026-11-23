# Bosun

A free, fast, low-memory intercepting proxy and dynamic application security testing (DAST) toolkit, written in
Rust. The goal is one tool that covers what Burp Suite Professional and OWASP ZAP do (intercepting proxy,
Repeater, Intruder, Sequencer, an out-of-band interaction server, passive and active scanning), for homelabbers,
hobbyists and individual security testers.

> The bosun is the ship's officer who inspects the hull and rigging and reports what is wrong before the
> weather finds it. Bosun does that for web applications.

**Status: early (M1).** The proxy, history, intercept, match-and-replace, scope, site map, CA, accounts and the
web UI work. Repeater, Intruder, Sequencer, the scanner and the OAST server are next; see
[roadmap.md](roadmap.md).

## What works today

- **Intercepting proxy**: HTTP/1.1 and HTTP/2, HTTPS interception with a per-install CA, WebSockets (recorded
  message by message), streaming responses (SSE, large downloads), upstream HTTP and SOCKS5 proxies, TLS
  pass-through for pinned hosts, invisible (transparent) proxying.
- **Intercept**: hold requests and/or responses, edit them as raw text, forward or drop; in-scope only by default.
- **Match and replace** on request/response first lines, headers and bodies (literal or regex).
- **HTTP history** with full-text search (FTS5 trigram), filters, a virtualised list that stays fast at millions of
  rows, raw/headers/hex/render views, automatic decoding of gzip, deflate, Brotli and zstd bodies, the original
  message kept next to the edited one.
- **Target**: site map and a scope editor (include/exclude rules). Every active tool will send only to in-scope
  targets.
- **Open browser**: launches Chromium/Chrome with its own profile, already using the proxy and trusting the CA by
  key pin, so the CA never has to be installed anywhere.
- **Front ends**: web UI (container or local), desktop app (Tauri), CLI. A TUI is planned. All of them use the
  same authenticated API.

## Quick start

### Local

```sh
npm --prefix web ci && npm --prefix web run build      # the web UI (embedded into the binary)
cargo build --release -p bosun
./target/release/bosun serve
```

The first run prints a link with a one-time setup code. Open it to create the admin account. Then:

- point a browser at the proxy, `127.0.0.1:8080`, or use **Settings → Open browser**;
- for your own browser, download the CA from `http://bosun/` (through the proxy) and import it **into a
  separate browser profile only**.

### Container

```sh
docker compose -f compose.example.yaml up -d
docker compose -f compose.example.yaml logs bosun    # the setup link
```

Both ports are published on 127.0.0.1 only. Read the comments in `compose.example.yaml` and
`docker/bosun.toml` before exposing either on a network.

### Desktop

```sh
npm --prefix web run build && cargo build --release -p bosun-desktop
```

Linux needs `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev`.

## Commands

| Command | |
|---|---|
| `bosun serve [--project NAME] [--proxy ADDR] [--listen ADDR]` | Run the proxy and the UI/API |
| `bosun doctor` | Check the install (permissions, keys, CA trust, exposure) |
| `bosun ca export [--der] [--out FILE]`, `ca info` | The CA certificate and its fingerprints |
| `bosun user add NAME [--role viewer\|tester\|admin]`, `user passwd NAME`, `user list` | Accounts (password on stdin) |
| `bosun example-config` | An annotated configuration file |

Configuration: `--config FILE` or `BOSUN_CONFIG`. Data: `--data-dir`, `BOSUN_DATA_DIR`, else the platform data
directory. The data key: `BOSUN_DATA_KEY` (base64) or `BOSUN_DATA_KEY_FILE`, else `<data>/data.key`.

## Security

See [SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model.md). In short: everything listens on
loopback by default; the proxy refuses to be an open proxy; the UI needs an account even on localhost and
defends against CSRF, DNS rebinding and hostile pages in the proxied browser; target content is never rendered in
the UI's origin; the CA key is encrypted at rest; no `unsafe` code.

## Licence

[Apache-2.0](LICENSE). Free for any use, including paid penetration-testing work for clients.
