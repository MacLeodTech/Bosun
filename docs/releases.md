# Releases and finished work

What has been delivered, moved here from `roadmap.md` once it landed. `roadmap.md` lists only what is still to do.

There is no tagged release yet. The first public preview is v0.2, at the end of Phase 3. Until then everything below is on
`main`. Work packages (WP-nn) keep their numbers, so the roadmap's "Depends on" column still refers to them.

Newest first. Each entry keeps the work package's original brief (why, do, done when) and its "Done" note.

## Phase 3, track A (branch `wp-43`, 2026-11-25)

- **WP-28 Proxy hot path** (`wp-43`, 2026-11-26). `new_flow` no longer re-parses (method, path, version and status are
  passed through); bodies stay `Bytes`; a request that isn't recorded, held or touched by a rule isn't serialised; request
  bodies stream with a capped tee for the record when intercept and request-body rules don't need them (413 and 503
  admission kept); flow ids are reserved only for recorded or held flows. Criterion benchmarks in
  `crates/bosun-proxy/benches`: 4 MiB upload 5.2 to 1.8 ms, 4 MiB download 8.3 to 6.9 ms, small GET unchanged (~167 µs).
  Left: a streamed request recorded before its upload ends is stored with only the part captured so far.

- **WP-23 Server mode** (`wp-43`, 2026-11-26). `GET /healthz` and `bosun healthcheck` (with `api.tls` on it only checks
  that the port accepts connections); `BOSUN_ADMIN_USER`, `BOSUN_ADMIN_PASSWORD_FILE` and
  `BOSUN_BOOTSTRAP_TOKEN_FILE` create the first admin and a full API token at start-up (audited; ignored once any user
  exists); `password_file` for `proxy.auth` and `proxy.upstream`; `BOSUN_LOG_FORMAT=json`; an optional unauthenticated
  Prometheus `/metrics` on its own listener (`metrics_listen`, off by default). The memory budget already followed the
  cgroup limit. Dockerfile healthcheck and a CI container smoke test (not run locally: needs Docker).

- **WP-32 CA management** (`wp-43`, 2026-11-26). `bosun ca rotate [--permit-domain D]...` creates a new CA, keeps the
  old certificate in `ca/previous/` and deletes its key (restart needed; the launched browser takes the new pin on its
  next launch). `--permit-domain` makes a name-constrained CA (all IP addresses excluded). `doctor` warns 30 days
  before expiry and fails after; `ca info` and `/ca` show expiry and constraint, and Settings warns. The constraint is a
  flag, not taken from the scope automatically.

- **WP-26 CLI client commands, first part** (`wp-43`, 2026-11-26). `history list|search|show|export` (HAR 1.2 and
  ndjson), `scope get|set|add`, `rules get|set|import`, `intercept on|off|status|queue|forward|drop`, `events
  [--follow]`, `ca export --server/--profile`, and `--json`, `--ndjson` and `--quiet` output; `history search` exits 4
  when nothing matches. An integration test runs each command against a live engine. Left: the OS keychain.

- **WP-47 Intruder, first part, and the rest of WP-43** (`wp-43`, 2026-11-26). The `bosun-intruder` crate: sniper, battering
  ram, pitchfork and cluster bomb; payload sources list, numbers (decimal or hex), brute force, null payloads and case
  changes; processing (prefix, suffix, encode and hash through `bosun-codec`, regex replace, skip rules); a pool
  with concurrency, delay, retries and a stop switch, sending through the Repeater's engine so the gate, the per-host
  rate limit and the memory budget apply (a request the limit holds back is retried for up to 60 s). Limits: 1M
  requests, 20 positions, 200k list items, three attacks at once. Results go to the project (migration 4 of the
  project file) and over the event stream; an attack found running at open is marked interrupted. API under
  `/intruder/*` (tester to run, viewer to read; start, stop and delete audited), the Intruder panel (position markers,
  grep match and extract, sorting, filter, CSV and JSON export) and the `intruder_plan` fuzz target. "Send to
  Intruder" is in the History menu and the Repeater, which finishes WP-43. Left: see WP-47 in the roadmap.

- **WP-48 Sequencer** (`wp-43`, 2026-11-26). The `bosun-sequencer` crate (pure, bounded, fuzzed): FIPS 140-2 monobit, poker,
  runs and long-run tests, character-level and bit-level analysis, an entropy estimate, counter and repeat
  detection and a verdict (excellent, good, poor, not random; under 100 tokens is marked unreliable). Token
  extraction from a header, a cookie or a body regex. API: `POST /sequencer/analyze` (viewer) and a live capture
  job (`/sequencer/capture`, status, stop; tester) that sends through the Repeater's engine, so the gate, the
  rate limit and the recording apply. Sequencer panel with Export JSON. Not done: captured requests are recorded
  with the Repeater's source, regexes run on the raw body (no chunked or gzip decoding), captures are kept in
  memory only.

- **WP-39 TOTP second factor** (`wp-43`, 2026-11-26). RFC 6238 (SHA-1, 6 digits, 30 s, previous/current/next step) with
  constant-time comparison and a per-account replay guard. Enrolment is enforced only after a first valid code, which
  also returns 10 one-time recovery codes (stored as SHA-256 hashes). Secrets are sealed with the install's data key.
  `POST /auth/login` answers `second_factor: totp` with a pending token (5 minutes, bound to the client address, five
  tries) and `POST /auth/login/totp` completes the sign-in. Code attempts share the login limiter plus 10 failures
  per account. Admins can reset a user's factor (`DELETE /users/{id}/totp`, `bosun user totp-reset`) and require one
  of all password accounts (`PUT /auth/totp/required`). The sign-in page, Settings and `bosun login` handle the second
  step. Not done: SSO sessions and the desktop login ticket are never asked for a code; API tokens made before
  "required" was switched on keep working; pending sign-ins are in memory, so a restart drops them; no per-user
  indicator in the users list. Migration 4 of the account database.

- **WP-25 CLI local admin commands** (`wp-43`, 2026-11-26). `bosun project list|create|rename|delete|export|import|backup`,
  `token create|list|revoke`, `user role|delete|sessions`, `audit` (with filters and paging), `serve --no-ui`,
  `completions` and `man`. They work on the data directory with no engine running; project commands exit 3 while
  a running Bosun holds the project. Every change writes an audit entry ("via CLI"). Exit codes: 0 ok, 1 failure,
  2 usage, 3 project in use, 4 not found, 5 delete not confirmed. New dependencies: `rpassword`, `clap_complete`,
  `clap_mangen`. Not done: revoking a single session from the CLI.

- **WP-45 Engagement helpers, rest** (`wp-43`, 2026-11-26). `GET /analysis?host=&port=&limit=`: the distinct endpoints and
  parameters of one host across the history, with counts, status codes and example values. Paths fold ids into
  `{n}`, `{uuid}` and `{hex}`, so `/users/1` and `/users/2` are one endpoint. It reads the newest 5,000 requests
  (at most 20,000) and a request body only for methods that can carry one (up to 64 KiB). The counting is
  `bosun_codec::engage::Analyzer` (bounded: 5,000 endpoints and 5,000 parameters, then `truncated`), covered by unit
  tests, the API test and the `engage` fuzz target. The Host analysis panel (History menu: "Analyse this host…") has
  a Playwright test.
- **WP-42 leftovers** (`wp-43`, 2026-11-26). MD5 and SHA-1 (`md-5` and `sha1`, the RustCrypto crates next to the
  existing `sha2`; `cargo deny` passes), gzip, zlib, Brotli and Zstandard compression, in the API and the Decoder panel;
  and `bosun decode [STEPS…] [--file F] [--smart] [--list] [--limit N]`, which runs the same chain offline on stdin or
  a file. Exit code 2 names the failed step. Not done: nothing left of WP-42.

- **Recorder under bursts** (PR #32). The proxy now counts refused connections, and a test pins how the recorder
  behaves under a burst (see the PR for what the 7,000 requests a second burst showed).
- **WP-75 History query language and saved filters** (PR #33, UI in the `wp-43` branch). The grammar is parsed in Rust
  (`GET /flows/query` for chips and errors, `GET /flows?q=`), compiled to SQL with bound parameters only, a 5 second
  deadline, a `history_query` fuzz target, the query bar with completion and recent queries, and saved filters.
  Saved filters live in the project setting `saved_filters`, not in a table (a deviation from the brief's "a
  migration"). Documented in `docs/query-language.md`. Reuse of the bar for Intruder results is in WP-47.
- **WP-43 History, Organizer and "send to"** (`wp-43`). Server-side sorting and paging by any column, a column chooser,
  colour highlights (reserved tags `hl:<colour>`), bulk tag changes (`POST /flows/tags`), "send to" Decoder and
  Comparer from the History menu, and the Organizer (migration v3, `/organizer`, a status and a note per saved
  request). No separate Logger panel: History lists every source (Source column, `source:`), and a second History
  instance needs multi-instance panels. Left: Send to Intruder (with WP-47).
- **WP-77 Export** (`wp-43`). Copy as cURL for POSIX shells and PowerShell, snippets in Python, JavaScript and Go, and a
  HAR 1.2 export of the selection. Cookie and authorization values become `REDACTED` unless "Keep cookies and
  authorization values" is ticked (a per-browser preference, off by default). Golden tests, including hostile values run
  through a real shell. Left: the round trip through HAR import, with WP-60.
- **WP-45 Engagement helpers, first part** (`wp-43`). `bosun_codec::engage` (comments, scripts, links, forms,
  resources, URLs, quoted paths, request parameters, the CSRF page builder; an `engage` fuzz target),
  `GET /flows/{id}/engage`, `GET /flows/{id}/csrf-poc` (an attachment with a sandboxing CSP), the Findings panel and
  History menu items. Analysing a target across the whole history is above.

## Phase 3 so far (on `main`)

- **Web UI upgrade** (PR #25). The `web/` restructure from `docs/ui-ux-upgrade-plan.md`, phases 0 to 5: a dockable
  workspace (own dock engine, saved layouts, browser pop-out windows), a strict type scale and colour tokens in a
  low-glare dark and light theme, a shortcut map, a command registry and palette, context menus, drag and drop,
  multi-select, a client-side filter bar, a shared message viewer, an accessibility audit and a 100,000-row
  performance pass. Partly delivers WP-44 (viewer only), WP-73, WP-80 and the UI half of WP-75; what is left is
  in the roadmap's "UI follow-ups". It also scoped the secret scan allowlist (`.gitleaks.toml`) for the UI's storage-key
  names and shortcut strings, `generic-api-key` rule and `web/src` only.

- **Branding** (PR #22). The app icon, the logo on the sign-in page and in the README, the favicon, `icon.ico` (tauri-build
  needs it on Windows), the startup banner (`bosun serve`, only on a terminal, honours `NO_COLOR`) and
  `scripts/bosun.sh` (build, run, install, container, check). Source art is in `assets/`.
- **Competitive analysis** (PR #22). `docs/competitive-analysis.md` compares Bosun with Burp, Caido, mitmproxy, Proxyman,
  Wireshark, Nmap, sqlmap, Nessus and the DAST tools, and became WP-75 to WP-86 in the roadmap.
- **Secret scan allowlist** (PR #22). `.gitleaks.toml` allows the RFC 6455 sample `Sec-WebSocket-Key` that the WebSocket
  tests use. `gitleaks git` scans every branch in the clone, so one test value on one branch failed every PR.
- **WP-41 Repeater, first slice** (PR #22). Connection reuse (opt-in pooling that keeps the scope gate and DNS pinning),
  HTTP/2 multiplexing with a single-packet batch mode, `/repeater/send` and `/repeater/settings`, the `bosun-client`
  methods, and the Repeater page. What is left is in the roadmap's WP-41 entry.

- **WP-41 finished** (PRs #28, #30, and the CLI PR). Repeater tabs saved in the project, `/repeater/ws`, the page's
  WebSocket mode, and `bosun login`, `bosun status` and `bosun repeater send FILE`.

### WP-40: the raw request engine

**WP-40** `bosun-http`: the raw request engine · Phase 3 · L

- **Why:** Repeater, Intruder, Sequencer and the scanner must send bytes exactly as written, which hyper won't do.
- **Do:**
  - A new crate that sends a raw message over HTTP/1.1 (byte for byte: duplicate headers, bare LF, odd methods,
    no normalisation), HTTP/2 (its own frame writer, so malformed requests are possible) and WebSockets.
  - Every send goes through `Gate::check` and connects to the pinned address (WP-10); bodies are read under the
    memory budget (WP-05); results are recorded as flows with the tool's `FlowSource`.
  - Timings (DNS, connect, TLS, first byte, total), the TLS details and the negotiated protocol are kept with the
    flow.
  - "Update Content-Length" and redirect following are options, not defaults.
- **Done when:** tests against a local test server show malformed requests arrive unchanged, out-of-scope targets
  are refused, and HTTP/2 frames are as written.
- **Done (PR #22):** the `bosun-http` crate: raw HTTP/1.1 (bytes as written), redirects, an upstream proxy, WebSockets
  and an HTTP/2 frame writer, with a fuzz target (`raw_framing`). Everything goes through `Gate::check` and the memory
  budget, and is recorded with its tool's `FlowSource`. The raw engine's `legacy-tls` option stays WP-46.

### WP-42: Decoder and Comparer

**WP-42** Decoder and Comparer · Phase 3 · M

- **Do:**
  - **Decoder:** chains of URL, HTML, Base64/Base64url, hex, gzip/deflate/brotli/zstd, JWT, Unicode escapes and
    hashing, plus "smart decode". Implemented in Rust behind an endpoint, so the CLI and plugins share it, with the
    WP-06 decompression caps.
  - **Comparer:** word-level and byte-level diff of any two messages or texts.
  - Fuzz targets for the decoders.
- **Done when:** unit tests cover each codec, including bombs and invalid input.
- **Done (PR #23 and the UI PR):** the `bosun-codec` crate (URL, HTML, Base64 and Base64url, hex, gzip, deflate, brotli,
  zstd, JWT, Unicode escapes, SHA-256 and SHA-512, smart decode, word and byte diff), the `/decoder/apply`,
  `/decoder/smart` and `/comparer/diff` endpoints, client methods, OpenAPI, tests, the `codec` fuzz target, and the
  Decoder and Comparer panels. The MD5, SHA-1, compression encoders and `bosun decode` that were left are in the track A entry above.

### WP-44: Message editor

**WP-44** Message editor (CodeMirror 6, hex, pretty-print) · Phase 3 · M

- **Do:**
  - CodeMirror 6 for the raw editor, with HTTP syntax highlighting; a hex editor; pretty-printing of JSON, XML and
    HTML as text, never rendered.
  - Check CodeMirror under the strict CSP. If anything is blocked, use `EditorView.cspNonce` with a per-response
    nonce from the server instead of loosening `style-src`. Record the decision in the threat model.
  - Large messages stay responsive (load bodies in pages from WP-12's endpoints).
- **Done when:** a Playwright test edits and sends a message, and the CSP header is unchanged or only gains a nonce.
- **Done:** the editor (`RawEditor`, `HexEditor`, `MessageEditor`) is used by the Repeater and by Intercept's edit
  view. CodeMirror adds its styles as a `<style>` element, which `style-src 'self'` blocks, but inside a shadow root
  it adopts a constructed stylesheet instead, which the policy does not govern. So the editor is mounted in a shadow
  root, and the CSP header is **unchanged** (no nonce, no `unsafe-inline`); the e2e test asserts both. Colours come
  from the existing tokeniser (not a CodeMirror language package), so only `@codemirror/state`, `view` and `commands`
  were added. Window-level shortcuts now read the real event target (`lib/typing.ts`), because inside a shadow root
  `event.target` is the host element: Intercept's single-key shortcuts had fired while typing. **Not done:** paging
  an editable body (the editor holds what the message view has loaded; the hex view is read-only past 256 KiB).

## After Phase 2 (on `main`)

- **CI hardening** (PR #12, #13). The container image smoke test no longer fails on SIGPIPE (it captures
  `docker logs` before matching). The macOS test job is paused because GitHub's macOS runners queue or cancel
  often; Windows and Linux run on every pull request. Re-enabling it is on the roadmap's Housekeeping list.
- **HTTP/2 version swap** (PR #14). Found by the `http_messages` fuzz target. The parser rewrote `HTTP/2` anywhere in
  the request line, so a target containing that text did not survive parse, serialise, parse. Only the last word of
  the line counts now, with a regression test.
- **E2E intercept race** (PR #15). The intercept tests now wait for the server to save the setting before sending
  traffic (`setIntercept` in `e2e/tests/ui.spec.ts`).
- **Dependabot** (PR #6 to #10). The three CodeQL actions (4.39.4), the e2e npm group and tokio-tungstenite 0.30.

## Phase 2: foundation (PR #11, merged 2026-11-23)

The plan, as written:

> **Phase 2: foundation.**
> - Track A, engine: WP-10, WP-35, WP-11, WP-12, WP-17.
> - Track B, platform: WP-13, then WP-14; WP-15; WP-16; WP-37.
> - M2 (Phase 3, track A) may start once **WP-10, WP-12 and WP-35** are done, without waiting for the rest.
> - Gate: OpenAPI spec committed with the drift check; embedded mode and login tickets work; projects API; footprint
>   budgets in CI; security review 2.

| WP | Title |
|---|---|
| WP-10 | Scope gate with address pinning (blocks M2) |
| WP-11 | Storage concurrency |
| WP-12 | Flow API v2 and non-blocking handlers (blocks M2) |
| WP-13 | OpenAPI contract and generated clients |
| WP-14 | The `bosun-client` crate |
| WP-15 | Embedded engine mode and login tickets |
| WP-16 | Projects API and UI |
| WP-17 | Event stream resume |
| WP-35 | Schema migrations framework (blocks M2) |
| WP-37 | Footprint budgets in CI |

### WP-10 Scope gate with address pinning (blocks M2) · Phase 2 · M

- **Why:** `bosun-scope` checks host *names* only. Once Repeater, Intruder or the scanner send traffic, a scoped
  name that resolves to an internal address (DNS rebinding, `169.254.169.254`, the host's own networks) turns
  Bosun into an SSRF tool. That matters most in container mode.
- **Do:**
  - `Gate::check` resolves the name and returns a **pinned** target: the addresses tools must connect to. Tools
    never resolve again.
  - Refuse loopback, link-local, cloud-metadata, unspecified and (in container/server mode) the host's own
    networks, unless an include rule names that address or network explicitly.
  - Add an `allow_private` switch per scope rule.
  - A per-host rate limit and the stop switch live in the same gate.
  - Document it in the threat model.
- **Done when:** tests show that a name resolving to `127.0.0.1` or `169.254.169.254` is refused, an explicit IP
  rule allows it, and the pinned address is what the connector uses.
- **Done (Phase 2).** `Gate::check` resolves the name (blocking: call from `spawn_blocking`) and returns `Pinned`
  with the addresses to connect to. Refused: loopback, link-local (includes the metadata addresses), unspecified and
  multicast, IPv4-mapped forms, the host's own networks (`set_protected_networks`), and any name with one such answer
  among several. An include rule opens them with `allow_private` (an "Allow local" column in the scope editor) or by
  naming the IP literally. The Repeater's out-of-scope policy does not lift this. The per-host rate limit is
  `set_rate_limit`. Still to do: WP-23 fills `set_protected_networks` from the server's interfaces and exposes
  the rate limit in the config; WP-40 connects to `Pinned::addrs`.

### WP-11 Storage concurrency · Phase 2 · M

- **Why:** one `Mutex<Connection>` per database means history reads and the recorder block each other, and
  `put_blob` hashes and compresses up to 64 MiB *inside* the transaction.
- **Do:**
  - One writer connection, plus a small pool of read-only connections (WAL allows concurrent readers). Reads use
    the pool.
  - Hash and compress bodies on the recorder thread before taking the writer.
  - The same split for `AppDb`.
- **Done when:** a benchmark or test shows `list_flows` latency stays flat while the recorder writes large batches.
- **Done (Phase 2).** `Project` and `AppDb` have one writer and read-only connections opened on demand (up to four
  kept idle); hashing, compression and indexing happen before the writer is taken, and blobs are inserted with
  `INSERT OR IGNORE`. A test holds the writer inside an open transaction and shows reads still answer. Not done: a
  timing benchmark (WP-27 owns the benchmarks), and in-memory databases (tests) still share one connection.

### WP-12 Flow API v2 and non-blocking handlers · Phase 2 · M

- **Why:** `GET /flows/{id}` returns the request, response, both originals and the decoded body as base64 in one
  JSON document (up to about 200 MB). Several handlers, and every audit write, call SQLite on async worker threads.
- **Do:**
  - `GET /flows/{id}` returns metadata, header blocks and body sizes only.
  - New body endpoints serve raw bytes as `application/octet-stream` with `Range` support:
    `/flows/{id}/request/body`, `/response/body`, `/original-request/body`, `/original-response/body`, and
    `/response/body?decoded=1`.
  - Update the UI's MessageView to fetch bodies lazily and show large ones in pages.
  - Move every SQLite call in handlers, `Caller::audit`, `setup` and `login` into `spawn_blocking`.
- **Done when:** a 50 MB response can be viewed without the API allocating more than the requested range; there is
  no direct SQLite call left in async code.
- **Done (Phase 2).** `GET /flows/{id}` is the summary, each message's header block and the sizes.
  `/flows/{id}/{request|response|original-request|original-response}/body` streams raw bytes with a single `Range`
  (`bytes=a-b`, `a-`, `-n`), as an attachment; `?decoded=1` undoes the content-encoding as a stream, capped at
  32 MiB (a decoded range is buffered, at most 8 MiB). Reads use SQLite's incremental blob interface and a streaming
  zstd decoder, so memory use is a few 64 KiB chunks. The UI loads 256 KiB pages with "Load more" and a download
  link. Every SQLite call in handlers, `Caller::audit`, setup, login and SSO runs on a blocking thread
  (`AppState::with_app`, `AppState::audit`); only start-up code still calls the stores directly. There is no
  automated peak-memory check: `unsafe` is forbidden, so a counting allocator is not an option.

### WP-13 OpenAPI contract and generated clients · Phase 2 · M

- **Why:** four front ends (web, WinUI, CLI, TUI) can't share hand-written types. `web/src/lib/types.ts` already
  duplicates the Rust types.
- **Do:**
  - Annotate the API with `utoipa` and write `docs/openapi.json` from a test or a `cargo xtask`.
  - CI fails when the committed spec drifts from the code.
  - Generate the TypeScript types for `web/` from it (replacing `types.ts`). Document how the C# client for WinUI
    is generated (NSwag or Kiota).
  - Version rules: additive changes only within `/api/v1`.
- **Done when:** the UI builds against generated types, and the drift check fails on an undocumented change.
- **Done (Phase 2).** The description lives in `crates/bosun-api/src/openapi.rs` (operations and response shapes
  in one place; the schemas derive from the real types) and is committed as `docs/openapi.json`. A test fails when
  they differ (`BLESS=1 cargo test -p bosun-api --test api openapi` rewrites it) and another calls every documented
  route on the real router; a third reads the router's source and fails when a served route is missing from the
  description. `npm run gen:api` writes `web/src/lib/api-types.ts`; CI fails if it is stale. Gap: `types.ts` is
  still partly hand-written: the event type and the project types come from (or are checked against) the generated
  ones, and checks fail the build when the shared shapes disagree, but the other interfaces are still written out
  (the generated ones use `i64` aliases and optional fields that would touch most pages). The description now says
  base64 string (not `number[]`) for the byte fields (`raw`, `head`, `payload`), as they are on the wire.
- **Replaces:** the `utoipa` part of "A docs site" under Release.

### WP-14 The `bosun-client` crate · Phase 2 · M

- **Why:** the CLI, the TUI and the integration tests all need a typed Rust client for the API.
- **Do:**
  - A new crate (reqwest with rustls) with token auth and typed methods for every endpoint.
  - A streaming events subscription with resume (WP-17).
  - Errors that map API messages and status codes.
  - Port `crates/bosun-api/tests/api.rs` to it where it makes the tests clearer.
- **Done when:** the crate covers the whole OpenAPI surface and is used by at least the API tests.
- **Done (Phase 2).** `crates/bosun-client`: typed methods for every operation, cookie or bearer auth (CSRF header
  sent for cookie sessions), range reads of bodies, and `EventStream` with resume (`?since&epoch`), `reload`
  handling and `reconnect()`; extra CA certificates for a TLS engine. Tests in `crates/bosun-api/tests/client.rs`
  run it against a real engine, and one fails when an operation exists without a client method. Not done: retries
  with backoff for plain requests (callers decide), and a blocking wrapper.

### WP-15 Embedded engine mode and login tickets · Phase 2 · M

- **Why:** every desktop shell (WinUI 3 on Windows, Tauri elsewhere) should run the engine as a **child process**.
  That keeps `unsafe` and a C interface out of the engine and isolates crashes. The desktop app also shouldn't ask
  for a password on every launch.
- **Do:**
  - `bosun serve --embedded`:
    - loopback listeners on random ports (or the configured ones);
    - prints one JSON line to stdout with `api_url`, `proxy_addr`, `ca_spki` and `login_ticket`, then logs to
      stderr only;
    - exits when stdin closes (parent gone);
    - on Windows also honours a parent-supplied Job Object.
  - Login tickets: a single-use, 60-second token, created only for the embedded parent.
    `POST /api/v1/auth/ticket` exchanges it for a session cookie, and the exchange is audited.
- **Done when:** an integration test starts `bosun serve --embedded`, reads the handshake, exchanges the ticket,
  rejects a second exchange, and sees the process exit when stdin is closed.
- **Replaces:** M1 "One-time login ticket for the desktop app".
- **Decision for the owner:** whether the desktop app has its own local admin account created silently, or asks
  for a password once and then uses tickets.
- **Done (Phase 2).** `bosun serve --embedded`: loopback only, random ports unless given, one JSON line on stdout
  (`api_url`, `proxy_addr`, `ca_spki`, `login_ticket`, `version`), logs on stderr, exits when stdin closes.
  `POST /auth/ticket` (single use, 60 s, constant-time compare, loopback peers only, rate limited, audited) makes
  the first local admin (`desktop`) if there are no users and returns a session. Tests: `crates/bosun/tests/embedded.rs`
  starts the real binary (handshake, ticket, parent-exit shutdown). Not done: the desktop shells themselves
  (WP-18, WP-19), which start it this way.

### WP-16 Projects API and UI · Phase 2 · L

- **Why:** an engine opens one project, chosen at start-up. The desktop and server modes need to manage projects
  at run time.
- **Do:**
  - Endpoints to list, create, open (switch), close, rename, delete, export and import projects. Switching swaps
    the recorder, scope, rules and intercept settings atomically.
  - Import copies the rows into a newly created schema, never opening a foreign file in place (uses WP-06's
    checks).
  - Project-level settings, a recent-projects list, and online backup through SQLite's backup API
    (`bosun project backup`).
  - UI: a project switcher and dialogs.
  - Audit every project operation.
- **Done when:** API tests cover the switch, an import of a hostile file (refused cleanly) and an export/import
  round trip.
- **Replaces:** M1 "Projects in the UI".
- **Done (Phase 2).** `/projects` (list, create, open, close, rename, delete, export, backup, import), all admin
  except listing, all audited; names map to files in the projects folder and nowhere else. Switching opens the new
  project first, then swaps recorder, scope, rules and intercept settings together under a lock that setting saves
  also take, drops held intercept messages, starts interception off, starts a new event epoch and sends
  `project_switched`. Import never opens the upload as a project: it is checked, rebuilt with `VACUUM INTO` into a
  new file and only then named (fuzz target `import_project`). The UI has a Projects page (create, open, close,
  rename, delete, export, back up, import) and shows the open project in the header; pages remount on a switch.
  Tests: `crates/bosun-api/tests/projects.rs`, `crates/bosun-store/tests/transfer.rs`, the e2e test. Gaps: the
  "recent" list is names only and only shown in the API; a project opened by path (`--project /x.bosun`) is shown but
  cannot be managed; imports are limited to 2 GiB and take a copy in the projects folder first (disk twice
  over until it finishes).

### WP-17 Event stream resume · Phase 2 · S

- **Why:** a client that falls behind gets `lagged` and has to reload everything.
- **Do:**
  - Give each event a sequence number and keep a ring buffer of recent events.
  - `/events?since=N` replays from the buffer, or says "reload" when N is too old.
  - The UI reconnects with `since`.
- **Done when:** a test disconnects, generates events and reconnects without losing any.
- **Done (Phase 2).** `EventBus` (in `bosun-proxy`) numbers every event from 1 and keeps the last N (4096 in the
  engine) in a ring. A new connection gets `{"type":"hello","epoch","seq"}`; reconnecting with
  `?since=N&epoch=E` replays what was missed, or sends `{"type":"reload"}` when N is too old, comes from another
  engine run, or the client lagged past the ring. The recorder now announces flows even when nobody is
  listening, so a client that was away finds them in the ring. The UI keeps the last number and reloads its data
  on `reload`. A project switch starts a new epoch, so positions from before it are answered with `reload` too.

### WP-35 Schema migrations framework · Phase 2 · S

- **Why:** the store only knows `user_version = 1`. M2 adds tables (Organizer, Repeater tabs, Logger), and every
  later milestone adds more, so migrations must exist before M2.
- **Do:**
  - An ordered list of migrations per database (project and `app.db`), each run in a transaction that also sets
    `user_version`.
  - Refuse files newer than the binary (this already happens), and back up the file before migrating.
  - The schema check from WP-06 validates against the result of running all migrations.
  - A test helper that builds a database at any version, for migration tests.
- **Done when:** a test migrates a v1 file through a dummy v2 migration, and a failing migration leaves the file
  untouched.
- **Done (Phase 2).** `bosun_store::migrate` runs an ordered list per database, each step in a transaction that
  records `user_version`, copies the file to `<file>.pre-v<N>.bak` first, and refuses newer files. A step marked
  `rebuild` runs with reference checks off and `foreign_key_check` before the commit. The project's schema check
  compares against the migrations up to the file's own version. Tests build a database at any earlier version
  (`MIGRATIONS[..n]`). Project v2 (blobs get a rowid) is the first real migration.

### WP-37 Footprint budgets in CI · Phase 2 · S

- **Do:**
  - Measure idle RSS of `bosun serve` (budget: under 50 MB) and the image size, on every pull request.
  - Fail on regressions over a threshold; record the numbers in a CI summary.
  - Leave hooks for the throughput and latency benchmarks that WP-27 and WP-28 add.
- **Done when:** CI fails when idle RSS goes over budget.
- **Done (Phase 2).** `footprint-budgets.json` holds a budget and a baseline per metric; `scripts/footprint.py`
  measures idle RSS of a release `bosun serve` (`idle`) and image size (`image`), or takes any `name=value`
  (`check`), fails when over budget or more than `regression_pct` (15) over the baseline, and writes a table to the
  run summary. CI has a `footprint` job and an image-size step. Measured: 16 MB idle (budget 50), 40 MB image
  (budget 60). The benchmarks of WP-27 and WP-28 report through `check` once they have a budget entry. Raise a
  baseline in the pull request that justifies it. The first CI numbers on GitHub's runners may differ a little
  from these local ones; adjust the baselines from the first run if so.

## Phase 1: harden what exists (PR #5, merged 2026-11-23)

The plan, as written:

> **Phase 1: harden what exists.** WP-01 to WP-09, WP-36, and the README correction from WP-31.
> - Start WP-36 (the test harness) first or alongside, so each fix lands with a test. WP-01 and WP-02 are quick
>   wins; then WP-03 to WP-08; WP-09 once Linux CI is green.
> - Gate: every review finding in WP-01 to WP-09 fixed with a regression test; CI on Linux, Windows and macOS; security
>   review 1.

| WP | Title |
|---|---|
| WP-01 | Clean environment for child processes |
| WP-02 | Pass-through tunnels through the connector |
| WP-03 | Sign-in hardening and trusted proxies |
| WP-04 | Connection limits and timeouts |
| WP-05 | A global memory budget |
| WP-06 | Untrusted project files and the project lock |
| WP-07 | Session and token lifecycle |
| WP-08 | UI TLS without the interception CA |
| WP-09 | CI on Windows and macOS |
| WP-36 | Test harness: Playwright, property tests, first fuzz targets |

### WP-01 Clean environment for child processes · Phase 1 · S

- **Why:** `BrowserLauncher::launch` (`crates/bosun-api/src/browser.rs`) starts Chromium with Bosun's whole
  environment. When `BOSUN_DATA_KEY` is set, the browser that loads hostile pages holds the key that unseals the CA
  private key.
- **Do:**
  - Start the browser with a cleared environment plus an allowlist: `PATH`, `HOME`, `USERPROFILE`, `LOCALAPPDATA`,
    `APPDATA`, `TEMP`/`TMP`, `DISPLAY`, `WAYLAND_DISPLAY`, `XDG_*`, `DBUS_SESSION_BUS_ADDRESS`, `LANG`/`LC_*`,
    `SystemRoot` (Windows).
  - Add one helper for spawning child processes, so later ones (crawler browsers, plugins) get the same rule.
  - Note it in the threat model under "Information disclosure".
- **Done when:** a unit test checks that the command's environment never contains `BOSUN_DATA_KEY` or
  `BOSUN_DATA_KEY_FILE`, and that the allowlisted variables survive.

### WP-02 Pass-through tunnels through the connector · Phase 1 · S

- **Why:** `passthrough_tunnel` (`crates/bosun-proxy/src/server.rs`) calls `TcpStream::connect` directly. That
  skips the loop guard, the refusal of Bosun's own listeners and **the upstream proxy**. Users who chain through
  SOCKS or Tor leak their real address for pass-through hosts.
- **Do:**
  - Open pass-through connections through `Connector`, plain TCP with no TLS. Factor out a `connect_tcp` that
    returns a registered stream.
  - Remove the "connect directly in this version" comment.
- **Done when:** tests show that a pass-through CONNECT goes through a configured SOCKS5 upstream (use a test SOCKS
  server); that a pass-through to the API address is refused; and that the outbound socket is registered with the
  loop guard.

### WP-03 Sign-in hardening and trusted proxies · Phase 1 · M

- **Why:** `crates/bosun-api/src/auth.rs`:
  - Anyone can make the server run argon2 (about 19 MiB and tens of milliseconds each) with unlimited concurrency,
    and failures are counted only *after* hashing, so a burst of parallel sign-ins exhausts CPU and memory.
  - Ten failures lock a username for 15 minutes, so anyone can lock out `admin`.
  - Behind a reverse proxy every client has the proxy's address, so per-address limits and audit addresses are
    wrong.
- **Do:**
  - A semaphore caps concurrent password hashing (default 2, configurable). Requests that can't get a slot quickly
    get 429.
  - Count the attempt before hashing.
  - Replace the hard lock with increasing delays per (address, username) pair, plus a per-address cap. Keep the
    timing equal for unknown users.
  - Add `api.trusted_proxies` (a list of networks). Only when the peer is in that list, take the client address
    from `X-Forwarded-For` (rightmost untrusted entry) and the scheme from `X-Forwarded-Proto`. Use that address
    for rate limits, `Caller.remote` and audit entries.
  - Apply the same cap to `/setup` and to `change_password`.
- **Done when:** tests show that:
  - 50 parallel wrong sign-ins never run more than N hashes at once;
  - another address can still sign in while one address is being throttled;
  - forwarded headers are ignored from untrusted peers and honoured from trusted ones.
- **Decision for the owner:** the default delay schedule.

### WP-04 Connection limits and timeouts · Phase 1 · M

- **Why:** the API server (`crates/bosun-api/src/lib.rs`, `serve`) and intercepted TLS connections
  (`server.rs`, `mitm`) use `hyper_util` auto builders with no timer, so the header-read timeout doesn't apply.
  Neither listener caps connections, which leaves both open to slowloris and file-handle exhaustion.
- **Do:**
  - Set `TokioTimer`, a header-read timeout and idle timeouts on every server builder.
  - HTTP/2: set max concurrent streams, keep-alive pings and a max header list size.
  - Cap concurrent connections per listener with a semaphore, and log refusals at a rate-limited level.
  - Add `proxy.max_connections` and `api.max_connections` to the config, with documented defaults.
- **Done when:** a test that opens a connection and sends headers one byte at a time gets disconnected on both
  listeners; a test going over the connection cap is refused while existing connections keep working.

### WP-05 A global memory budget · Phase 1 · M

- **Why:** nothing bounds total memory:
  - every request body is buffered up to 64 MiB, with unlimited concurrency;
  - the recorder channel (`crates/bosun-proxy/src/recorder.rs`) is unbounded;
  - the intercept queue (`intercept.rs`) has no size cap and no timeout, and each held item can be 64 MiB.
  
  With the example `mem_limit: 512m`, a handful of large requests can kill the process.
- **Do:**
  - A byte-counting budget shared by the proxy, the recorder and the intercept queue. Request bodies, buffered
    responses and queued records reserve bytes before allocating.
  - Default budget: a fraction of the cgroup `memory.max` when there is one, otherwise a fixed value. Add a config
    key.
  - Bounded recorder queue. When it is full, record metadata only and mark the body as dropped. Never block the
    proxy, and keep a counter that `/proxy` reports.
  - Intercept queue: a cap on item count and total bytes, plus optional `intercept.timeout_secs` (forward
    unedited when it expires). Refusals are visible in the UI.
- **Done when:**
  - a test sends many concurrent large bodies and stays under the budget, with clean 503 or 413 responses;
  - a test with a stalled recorder shows proxying continues and the drop counter rises;
  - a test shows the intercept cap.
- **Decision for the owner:** what to do when the recorder queue is full (metadata only, as above, or drop the
  oldest).

### WP-06 Untrusted project files and the project lock · Phase 1 · M

- **Why:**
  - `get_blob` and WebSocket payloads in `crates/bosun-store/src/project.rs` use an unbounded `zstd::decode_all`, so
    a hostile `.bosun` file can exhaust memory. The threat model wrongly says stored bodies are bounded.
  - SQLite opens project files with default (trusting) settings.
  - Two processes can open one project; the in-memory flow-id counter then collides and failed batches are lost.
- **Do:**
  - Bounded decompression (stored `size` checked against a cap, decoder read through `take`). Treat a mismatch as
    corruption.
  - On open: `PRAGMA trusted_schema=OFF`, `cell_size_check=ON`, `SQLITE_DBCONFIG_DEFENSIVE`. Check that the schema
    (tables, columns, triggers, views) matches what this version created exactly; refuse files with extra triggers
    or views.
  - An exclusive lock file per project (`<project>.lock`, using an advisory-lock crate), with a clear error naming
    the other process.
  - Write failures in the recorder: retry once, then emit an event and count it instead of only logging.
  - Fix the threat-model text.
- **Done when:** tests cover a zstd bomb in `blobs`, a project with an extra trigger, a second `Project::open` on a
  locked file, and a forced write error.

### WP-07 Session and token lifecycle · Phase 1 · M

- **Why** (`crates/bosun-store/src/app.rs`, `crates/bosun-api/src/handlers.rs`):
  - A password change ends sessions but not API tokens, so a stolen password can be turned into a token that
    survives the reset.
  - Tokens have no expiry or scope.
  - Sessions slide forever, with a database write on every request.
  - There is no way to change roles or list and revoke sessions.
  - Intercept edits and forward-all aren't audited.
- **Do:**
  - Revoke a user's tokens on password change (always, or by a choice in the request).
  - Tokens get an optional expiry and a scope (`read` or `full`). `read` tokens can only make GET requests.
    `last_used_ms` is updated, throttled.
  - Sessions get an absolute maximum lifetime (config, default 7 days) next to the idle timeout. Only extend expiry
    when it has moved by more than a minute.
  - Admin endpoints: change a role (never demote the last admin), list and revoke a user's sessions and tokens. Add
    these to the Settings UI.
  - Audit `intercept.forward_edited`, `intercept.drop`, `intercept.forward_all` and intercept settings changes.
- **Done when:** API tests cover each rule above, including "a token made before a password change no longer
  works" and "a read token gets 403 on PUT".

### WP-08 UI TLS without the interception CA · Phase 1 · S

- **Why:** `api.tls` serves the UI with a certificate from the interception CA, which pushes users to trust that CA
  in their everyday browser. The threat model says never to do that.
- **Do:**
  - Add `api.tls_cert` and `api.tls_key` (PEM files, reloaded on SIGHUP or on change).
  - When `api.tls` is on without them, use a separate self-signed UI certificate kept in the data directory. Its
    key is sealed like the CA key. It is not a CA and can't sign anything else.
  - Document the reverse-proxy setup as the recommended one.
  - `doctor` warns when the UI is served on a non-loopback address without TLS.
- **Done when:** a test checks that the UI certificate's issuer is not the interception CA, and that configured
  certificate files are served.

### WP-09 CI on Windows and macOS · Phase 1 · S

- **Why:** the engine must run on all three operating systems, but CI tests Linux only, and there are `cfg(unix)`
  code paths (permissions, signals).
- **Do:**
  - Run the `rust` job on `windows-latest` and `macos-latest` too (tests only; fmt and clippy can stay on Linux).
  - Fix what fails: path handling, the permission checks (make `check_private` and `private_dir` meaningful on
    Windows or say why not), and Ctrl-Break/console-close handling in `shutdown_signal`.
  - Add the Windows per-user Chrome path to the browser search list.
- **Done when:** all three operating systems pass on a pull request.
- **Depends on:** CI green on Linux (see Housekeeping).

### WP-36 Test harness: Playwright, property tests, first fuzz targets · Phase 1 · M

- **Why:** the hardening and rework in Phases 1 and 2 touch the UI and the parsers. They need tests that catch
  regressions, and the WinUI and Tauri apps show the same UI.
- **Do:**
  - Playwright end-to-end tests against `bosun serve` with a temporary data directory: setup, sign-in, history
    live updates, intercept edit and forward, scope editing. Include **a test that the render view cannot run
    script** (a response with inline script and an `onerror` handler that would call back to the test).
  - Property tests (`proptest`) for scope matching and for raw message parse and serialise round trips.
  - `cargo-fuzz` targets: the HTTP parser, the WebSocket frame parser, the decoders and decompression, and the
    scope rule compiler. Run each for a short time in CI, and longer in the weekly scheduled run.
- **Done when:** the three kinds of test run in CI, and a deliberately broken render sandbox fails the Playwright
  test.

## Phase 0: ready the repository (done before Phase 1)

The plan, as written:

> **Phase 0: ready the repository.** WP-34.
> - Owner: approve the commit and push; confirm the repository visibility.
> - Gate: CI green on Linux; branch protection and required checks on.

| WP | Title |
|---|---|
| WP-34 | Repository and CI ready |

### WP-34 Repository and CI ready · Phase 0 · M

- **Why:** nothing else can merge safely until CI is green and `main` is protected.
- **Do:**
  - Ask the owner, then commit and push the pending changes (the Apache-2.0 switch, the hosted-runner workflows,
    the README, roadmap and Cargo edits).
  - Confirm the repository visibility with `gh repo view`, and that no `RUNNER` variable is set.
  - Re-run CI on GitHub-hosted runners:
    - Read the **SAST + SCA** failure (gitleaks or Trivy fs; suspects are test keys under `target/` or in test
      fixtures). Fix it, or add a narrow, commented allowlist entry.
    - Run the **Container image** and **Desktop shell** jobs for the first time and fix what they find.
  - Review the Dependabot PRs (TypeScript 7, Node 26, `actions/setup-go` 7.1.0).
  - Turn on branch protection with the required checks.
- **Done when:** every CI job passes on `main`; branch protection requires them.
- **Status (2026-11-23):** done. CodeQL skips `tests/`, `e2e/` and `fuzz/` (`.github/codeql/codeql-config.yml`): test fixtures hold throw-away passwords that its hard-coded-key query reports as critical. The repo is public; CI is green on `main`; branch protection requires the six
  CI jobs (add `e2e` and the `fuzz` matrix to the required list once they have passed on a pull request).
  - Code scanning: the custom CodeQL workflow works now that the default setup is off (re-run on `main` passed).
    Its nine first findings were false positives or by design and are dismissed with a comment each (zeroed
    buffers filled by the RNG, conditional `Secure` cookies, `http://` in tests, a CLI that prints the username).
  - `glib` alert: dismissed as not used. It is only Tauri's Linux GTK 0.18 dependency; Bosun makes no GVariant
    calls. Revisit when Tauri moves to a newer GTK stack, or when WP-15 replaces the shell.
  - Dependabot PRs, taken onto the phase branch so they are verified once, not four times: #2 (`setup-go` 7.1.0)
    and #1 (Node 26: the Docker web stage builds; `setup-node` moved to 26 to match) are applied. #4 (cargo group)
    is applied in full, with `rand` 0.10, `argon2` 0.6 and `chacha20poly1305` 0.11 migrated and two
    known-answer tests (an old sealed blob still opens, an old password hash still verifies). #3 (TypeScript 7)
    is **not** applied: `svelte-check` cannot load it, so Dependabot now ignores TypeScript majors. The four
    Dependabot PRs close themselves when the phase PR merges; close #3 by hand.
- **Owner tasks:** approving the push; the visibility setting.

## Baseline: M0 foundations and M1 proxy

Delivered before the phase plan, as checked off in the milestone lists.

### M0 Foundations

- [x] Cargo workspace (edition 2024, resolver 3, pinned toolchain), `unsafe` forbidden, clippy lints
- [x] Licence (Apache-2.0, changed from PolyForm Noncommercial) and `NOTICE`
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

### M1 Proxy

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
- [x] **Run the image and desktop CI jobs for the first time, and fix what they find** (neither could be built in
  the dev environment) → **WP-34**
- [x] One-time login ticket for the desktop app, so it doesn't ask for a password on every launch: **WP-15**
- [x] Projects in the UI: create, switch, export and import `.bosun` files; project-level settings: **WP-16**

## Quality, release and housekeeping items

- [x] Licence decided: Apache-2.0 (was PolyForm Noncommercial, which barred paid client work).
- [x] Footprint budgets in CI: idle RSS under 50 MB and the image size, checked on every pull request (**WP-37**)
- [x] Playwright end-to-end tests of the UI against `bosun serve`, including a test that the render view
  cannot run script → **WP-36**
- [x] Property tests for scope matching and for raw message round-trips → **WP-36**
- [x] Create the GitHub repository (MacLeodTech/Bosun); public, CI on GitHub-hosted runners only
- [x] Confirm visibility really is public (the last check said PRIVATE) and the repo has no `RUNNER` variable → **WP-34**
- [x] Commit the Apache-2.0 switch and the hosted-runner workflows → **WP-34**
- [x] Get CI green: SAST + SCA, Container image and Desktop shell have not passed yet → **WP-34**
- [x] Set up branch protection and required checks once CI is green → **WP-34**
- [x] Review the Dependabot PRs: TypeScript 7 is not applied (`svelte-check` cannot load it), the rest are merged → **WP-34**
