# Roadmap

The plan for Bosun: a free, Rust-based replacement for Burp Suite Professional and OWASP ZAP, for
homelabbers, hobbyists and individual security testers. This file holds all planned work. Each milestone ends
with something usable and tested. Tick items off as they land, and add new work here rather than in issues alone.

Guiding goals, which apply to every milestone:

- **Coverage.** Everything Burp Pro and ZAP do for a single tester: proxy, manual tools, automated scanning and
  out-of-band testing.
- **Efficiency.** A low memory footprint, with budgets enforced in CI. Fast on large histories.
- **An iron-tight security posture.** Hostile content is the default. See `docs/threat-model.md`, and keep it in
  step with every change.
- **One engine, every front end.** The web UI (local or container), the desktop app, the CLI and later a TUI. All
  of them use the same authenticated API.

Legend: `[x]` done, `[ ]` to do, `[~]` partly done.

---

## M0 Foundations: done

- [x] Cargo workspace (edition 2024, resolver 3, pinned toolchain), `unsafe` forbidden, clippy lints
- [x] Licence (PolyForm Noncommercial 1.0.0) and `NOTICE`
- [x] `SECURITY.md`, `docs/threat-model.md`, `docs/architecture.md`, `CLAUDE.md`
- [x] `bosun-model`: flow and target types, lenient raw HTTP parsing
- [x] `bosun-store`: project files (SQLite WAL, zstd content-addressed bodies, FTS5 trigram search) and the account
  database (users, sessions, API tokens, append-only audit log)
- [x] `bosun-api`: axum API with Host/Origin/Sec-Fetch checks, CSRF, roles, rate-limited sign-in, one-time setup
  code, the event stream, the embedded UI
- [x] Svelte 5 web UI shell, built under a strict CSP
- [x] Tauri 2 desktop shell (written; first compile happens in CI)
- [x] `bosun doctor`
- [x] CI: fmt, clippy, tests, UI check/build/audit, cargo-deny, gitleaks, Trivy (fs and image), CodeQL, Dependabot

## M1 Proxy: done, with a few items open

- [x] Per-install CA with sealed key, leaf certificate cache, SPKI hash
- [x] MITM proxy: HTTP/1.1, HTTP/2 (ALPN), WebSockets, CONNECT, TLS pass-through list, invisible mode
- [x] Upstream HTTP and SOCKS5 proxies; optional upstream TLS verification
- [x] Not an open proxy (loopback default, auth or allowlist otherwise); loop guard against proxying into itself
- [x] Intercept requests/responses (edit, forward, drop, forward all, in-scope only)
- [x] Match and replace (first line, headers, body; literal or regex)
- [x] HTTP history: search, filters, virtualised list, raw/headers/hex/render views, decoded bodies, originals
  of edited messages, notes
- [x] WebSocket message history
- [x] Site map and scope editor
- [x] "Open browser": a system Chromium with its own profile and the CA pinned by SPKI
- [x] CLI: `serve`, `doctor`, `ca`, `user`, `example-config`
- [x] Container image (distroless, nonroot) and compose example
- [ ] **Run the image and desktop CI jobs for the first time, and fix what they find** (neither could be built in
  the dev environment)
- [ ] Bundle Chrome for Testing with the desktop installers (download, verify by SHA-256, keep it updated)
- [ ] One-time login ticket for the desktop app, so it doesn't ask for a password on every launch
- [ ] Optional TOTP second factor for UI accounts
- [ ] Projects in the UI: create, switch, export and import `.bosun` files; project-level settings
- [ ] History: column chooser, sorting, colour highlights, bulk tag/delete, "send to" menu (wired up in M2)
- [ ] Response interception rules (intercept only when the response matches a condition)
- [ ] Proxy listener management in the UI (several listeners, per-listener options) and a live-config reload
- [ ] Request/response size and timing stats in history
- [ ] HTTP/3 (QUIC) for the client side and upstream
- [ ] Health endpoint and a `bosun healthcheck` subcommand for container health checks (distroless has no curl)

## M2 Manual tools

- [ ] `bosun-http`: a raw request engine that sends bytes exactly as written (malformed requests, duplicate
  headers, bare LF, unusual methods), over HTTP/1.1, HTTP/2 (its own frames), and WebSockets
- [ ] Optional `legacy-tls` backend (OpenSSL, opt-in feature) for very old targets, upstream only
- [ ] **Repeater**: tabs, per-tab history (back/forward), h1/h2/WebSocket, raw bytes, "update Content-Length",
  follow redirects (optional), response diff with the previous send, send groups (in order or in parallel,
  single-packet attack for race conditions)
- [ ] **Decoder**: chains of URL, HTML, Base64/Base64url, hex, gzip/deflate/brotli/zstd, JWT, Unicode escapes,
  hashing, "smart decode"
- [ ] **Comparer**: word- and byte-level diff of any two messages or texts
- [ ] **Organizer**: save requests with notes and status for follow-up
- [ ] **Logger**: every request from every tool (not just the proxy), with filters
- [ ] "Send to Repeater, Intruder, Comparer or Decoder" everywhere a message is shown
- [ ] Request editor with syntax highlighting (CodeMirror 6), a hex editor, and pretty-printing of JSON, XML and
  HTML (as text, never rendered)
- [ ] Engagement helpers: generate a CSRF PoC, find comments and scripts, find references, analyse a target
  (parameters and endpoints)
- [ ] The scope gate enforced for every tool request (refuse out-of-scope, a per-host rate limit, the stop switch)

## M3 Intruder and Sequencer

- [ ] **Intruder** attack types: sniper, battering ram, pitchfork, cluster bomb
- [ ] Payload sources: simple lists, files, numbers, dates, brute-forcer, character substitution, case
  modification, null payloads, recursive grep, results of earlier attacks
- [ ] Payload processing: prefix and suffix, encode and decode, hash, regex replace, skip rules
- [ ] Bundled wordlists and support for SecLists
- [ ] Results table: grep match, grep extract, status, length and timing columns, sorting, filtering, export
- [ ] Resource pools: concurrency, delays, throttling, retries
- [ ] **Sequencer**: live capture (from a request and a token location) and manual load
- [ ] Analysis: FIPS 140-2 tests (monobit, poker, runs, long runs), character-level and bit-level analysis,
  entropy estimate, a verdict, exportable results

## M4 Passive scanner, the check engine and reports

- [ ] Passive scanner on all proxied traffic (and on imports), off the hot path, deduplicated
- [ ] Finding model: issue type, severity, confidence, evidence (highlighted request and response ranges),
  remediation, CWE and OWASP references, status (new, confirmed, false positive)
- [ ] `bosun-checks`: a YAML check language (request templates, matchers, extractors, OAST hooks), versioned and
  validated
- [ ] Import a compatible subset of Nuclei templates (MIT; keep their notices)
- [ ] Port ZAP's passive rules where useful (Apache-2.0; attribution in `NOTICE`)
- [ ] Passive checks for: security headers, cookie flags, CSP weaknesses, CORS, information disclosure (stack
  traces, versions, private IPs, keys), mixed content, vulnerable JS libraries (Retire.js-style data), JWT
  issues, cacheable sensitive responses, open redirect hints, and directory listings
- [ ] `bosun-report`: HTML (self-contained, no script), JSON, SARIF, JUnit and Markdown; secrets redacted by default
- [ ] An issues view in the UI with filters and grouping, and links back to the evidence

## M5 Active scanning

- [ ] `bosun-crawl`: an HTTP spider (forms, links, robots.txt, sitemap.xml) bounded by scope and depth
- [ ] Browser crawler: chrome-headless-shell pooled over CDP (`bosun-browser`), one context per task, started on
  demand and stopped when idle, sandbox on, a seccomp profile in the container. Working name: "Deckhand".
- [ ] A `BrowserEngine` trait so other engines can be added (see M8)
- [ ] Insertion points: query, body (form, JSON, XML, multipart), headers, cookies, path segments, nested
  encodings (Base64 or JSON inside a parameter), GraphQL variables
- [ ] Scan policies (checks, strength, thresholds), scan queue, pause/resume, a live progress view
- [ ] Core active checks: SQL injection (error, boolean, time), reflected and stored XSS, SSTI, OS command
  injection, path traversal and LFI, XXE, open redirect, CRLF and header injection, Host header attacks, CORS
  misconfiguration, file upload, JWT attacks, deserialization indicators, prototype pollution, GraphQL issues,
  auth and session weaknesses, TLS configuration
- [ ] "Destructive" checks flagged and off by default
- [ ] `bosun-auth`: session handling (login macros, token refresh, recorded browser logins, re-auth on expiry)
- [ ] Multi-user authorisation matrix (IDOR and access-control testing across accounts)
- [ ] `bosun scan` CLI: headless CI scan from a URL or an API definition, exit code from a severity
  threshold, SARIF output
- [ ] An in-repo `testbed` crate with known vulnerabilities, so scanner tests in CI are deterministic

## M6 OAST server and API imports

- [ ] **Lookout**: a separate, self-hostable OAST server binary and image with DNS, HTTP/HTTPS (ACME) and SMTP
  listeners, per-payload correlation IDs, a polling API with per-client keys, automatic expiry of interactions,
  and no access to project data
- [ ] Client side: Lookout or interactsh-compatible servers, and an OAST payload generator in Repeater and Intruder
- [ ] OAST checks: blind SQL injection, SSRF, XXE, RCE, blind XSS, DNS rebinding probes
- [ ] Imports: OpenAPI/Swagger 2 and 3, GraphQL introspection, Postman collections, HAR, plain URL lists; and
  Burp XML exports where the format allows

## M7 Plugins and advanced checks

- [ ] `bosun-plugin`: a wasmtime component-model host, a WIT interface, fuel and memory caps, no WASI filesystem or
  network, all I/O through host calls that go through the scope gate
- [ ] Capability manifests that the user approves; minisign-signed plugins and check/template feeds
- [ ] A Rust guest SDK, example plugins, docs; later SDKs for other languages that compile to WASM
- [ ] Plugin hooks: passive and active checks, message editors and views, payload generators and processors,
  context menu actions, UI panels in a sandboxed iframe
- [ ] Advanced checks: request smuggling (CL.TE, TE.CL, H2 downgrade, client-side desync), web cache poisoning and
  deception, DOM XSS through browser instrumentation, race conditions, OAuth/OIDC misconfiguration

## M8 Teams, containers, engines and the TUI

- [ ] Multi-user hardening: OIDC sign-in, per-project permissions, collaboration (shared projects, live updates)
- [ ] An in-container browser streamed into the web UI over CDP screencast (for container mode)
- [ ] Lightpanda as an opt-in fast crawler engine that falls back to Chromium when a page breaks
- [ ] Track Servo as an embeddable pure-Rust engine
- [ ] `bosun-tui`: a ratatui client over the same API
- [ ] Encrypted projects (SQLCipher feature) and an encrypted credential vault for auth configs

## Release and packaging (from the first public release onwards)

- [ ] **Decide the licence before the first public release.** PolyForm Noncommercial bars paid client work,
  which cuts out the individual professionals in the target audience. Options: dual licence, AGPL, or a
  commercial-use exception for individuals.
- [ ] Finish the name check for Bosun: domains and trademarks (crates.io `bosun` is taken, though the crates are
  never published; the GitHub repos with this name are unrelated: an old monitoring tool and a small agent
  orchestrator). No Burp, Collaborator or ZAP branding anywhere.
- [ ] A release workflow: tagged builds for Linux, macOS and Windows (x86_64 and aarch64), multi-arch images, a
  CycloneDX SBOM, cosign-signed images and artifacts, checksums, release notes
- [ ] Desktop installers (AppImage/deb/rpm, dmg, msi) with Chrome for Testing bundled; code signing and
  notarisation where affordable
- [ ] Auto-update for the desktop app, signed, off by default in managed environments
- [ ] A docs site: getting started, CA and browser setup, container deployment behind a reverse proxy, the API
  reference (OpenAPI generated from code with `utoipa`), writing checks and plugins
- [ ] A migration guide from Burp and ZAP (shortcut equivalents, importing projects and history)

## Quality, performance and security work (continuous)

- [ ] Footprint budgets in CI: engine idle RSS under 50 MB, proxy throughput and latency benchmarks (criterion),
  tracked image sizes
- [ ] `cargo-fuzz` targets: the HTTP parser, the WebSocket frame parser, decoders and decompression, the scope
  rule compiler, the YAML check loader, the plugin host boundary
- [ ] Playwright end-to-end tests of the UI against `bosun serve`, including a test that the render view
  cannot run script
- [ ] Scanner benchmarks against OWASP Juice Shop, DVWA, WebGoat, VAmPI/crAPI and the OWASP Benchmark, comparing
  detection rate, false positives, scan time and peak memory with ZAP on the same targets
- [ ] Property tests for scope matching and for raw message round-trips
- [ ] A weekly scheduled CI run (already configured) and the SBOM published with each release
- [ ] A security review before each milestone ships: threat model updated, new endpoints checked for role
  checks and audit entries
- [ ] Accessibility and keyboard shortcuts across the UI (Burp-compatible where sensible)

## Housekeeping

- [ ] Create the GitHub repository (MacLeodTech/Bosun) and choose its visibility (private while self-hosted runners are in use)
- [ ] Set up branch protection and required checks once CI is green
