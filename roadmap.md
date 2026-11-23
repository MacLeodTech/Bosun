# Roadmap

The plan for Bosun: a free, Rust-based replacement for Burp Suite Professional and OWASP ZAP, for
homelabbers, hobbyists and individual security testers. This file holds all planned work. The implementation
strategy (phases, and work packages WP-01 to WP-74) sets the order; the milestone checklists list the features.
Each phase ends with something usable and tested. Tick items off as they land, and add new work here as a work
package rather than in issues alone.

Guiding goals, which apply to every milestone:

- **Coverage.** Everything Burp Pro and ZAP do for a single tester: proxy, manual tools, automated scanning and
  out-of-band testing.
- **Efficiency.** A low memory footprint, with budgets enforced in CI. Fast on large histories.
- **An iron-tight security posture.** Hostile content is the default. See `docs/threat-model.md`, and keep it in
  step with every change.
- **One engine, every front end.** The web UI (local, or in a container under Docker or Podman), the desktop app
  (WinUI 3 on Windows, Tauri on macOS and Linux), the CLI and later a TUI. All of them use the same authenticated
  API.

Legend: `[x]` done, `[ ]` to do, `[~]` partly done.

---

## Where we are (updated 2026-11-23): resume here

- **Code:** M0 and M1 are written and pass fmt, clippy and tests locally. The Docker image and `bosun-desktop`
  have never been built (no Docker socket or webview libraries in the dev environment).
- **Repo:** `MacLeodTech/Bosun`, `main` pushed (commits 357d61a, 98f41c8). The Apache-2.0 switch, the
  hosted-runner-only workflows and the README/roadmap/Cargo edits are **uncommitted**.
- **Visibility:** the owner says it is public, but `gh repo view` still reported PRIVATE. Check it first.
- **CI policy:** GitHub-hosted runners only (`ubuntu-latest` is hard-coded). Never the homelab self-hosted pools
  for this repo, and no `RUNNER` variable. Earlier hosted runs failed on an account billing block, not on code.
- **Next, in order** (see the phase plan below):
  1. **Phase 0, WP-34:** commit and push the pending changes (ask the owner first), get CI green on
     GitHub-hosted runners, review the Dependabot PRs, turn on branch protection.
  2. **Phase 1:** the hardening packages WP-01 to WP-09, with the test harness (WP-36) alongside.
  3. **Phase 2:** the foundation packages. M2 starts as soon as WP-10, WP-12 and WP-35 are done, with the raw
     request engine (WP-40) and then Repeater (WP-41).
- **Decided (2026-11-23):** the product keeps the name Bosun. Published artefacts use distinct names: the crates.io
  crate is `bosun-dast` (the installed binary stays `bosun`), and any npm package goes under the `@macleodtech` scope.
  Windows code signing is deferred; unsigned builds ship until then. The name check found a medium risk: a pending
  Class 9 filing for BOSUN (Bosun Technology Limited, Jan 2025, serial 98940487) to look up on TSDR before v0.2.

---

## Implementation strategy

All remaining work, from the 2026-11-23 codebase review and from the milestones, is in **work packages WP-01 to
WP-74**. The phase plan below sets the order. Work package numbers are stable identifiers, not the order. The
milestone sections further down are the feature checklists; every open item there names the package that
delivers it.

Sizes: **S** is about a session, **M** a few sessions, **L** should be split into several pull requests.

### How the phases work

- Phases run in order. Within a phase, the tracks can run in parallel (separate Claude sessions on separate
  branches) as long as each package's dependencies in the index are done.
- Each phase ends at a **gate**: its exit criteria, plus a security review. The review updates the threat model,
  checks every new endpoint for its role check and audit entries, and needs `cargo deny`, Trivy and CodeQL clean.
  From Phase 3 on, every gate is a tagged release.
- **Owner tasks** are things only the owner can do (accounts, purchases, decisions). They are listed per phase.

### Phase plan

**Phase 0: ready the repository.** WP-34.
- Owner: approve the commit and push; confirm the repository visibility.
- Gate: CI green on Linux; branch protection and required checks on.

**Phase 1: harden what exists.** WP-01 to WP-09, WP-36, and the README correction from WP-31.
- Start WP-36 (the test harness) first or alongside, so each fix lands with a test. WP-01 and WP-02 are quick
  wins; then WP-03 to WP-08; WP-09 once Linux CI is green.
- Gate: every review finding in WP-01 to WP-09 fixed with a regression test; CI on Linux, Windows and macOS; security
  review 1.

**Phase 2: foundation.**
- Track A, engine: WP-10, WP-35, WP-11, WP-12, WP-17.
- Track B, platform: WP-13, then WP-14; WP-15; WP-16; WP-37.
- M2 (Phase 3, track A) may start once **WP-10, WP-12 and WP-35** are done, without waiting for the rest.
- Gate: OpenAPI spec committed with the drift check; embedded mode and login tickets work; projects API; footprint
  budgets in CI; security review 2.

**Phase 3: manual tools and the front ends. Release v0.2, the first public preview.**
- Track A, M2 tools: WP-40, then WP-41, WP-42 and WP-44, then WP-43 and WP-45. Also WP-38 and WP-39, the M1
  follow-ups.
- Track B, server and CLI: WP-23, then WP-24; WP-25; WP-26.
- Track C, desktop: WP-20 and WP-21, then WP-18 and WP-19, then WP-22.
- Track D, release: WP-69, WP-70 (the first pages), WP-31.
- Owner: look up the pending BOSUN Class 9 filing before v0.2; an Apple Developer account. Windows signing is deferred.
- Gate: v0.2 for Windows, macOS and Linux; Docker and Podman images; the CLI; security review 3.

**Phase 4: Intruder, Sequencer and performance. Release v0.3.**
- WP-47, WP-48, WP-27, WP-28, WP-32, WP-33. WP-46 is optional.
- Gate: footprint budgets green on storage v2; the WP-27 and WP-28 benchmarks recorded here.

**Phase 5: passive scanning and reports. Release v0.4.**
- WP-49, then WP-50 and WP-51; WP-29; WP-73.

**Phase 6: active scanning. Release v0.5.**
- WP-52, WP-68, WP-53, then WP-54 (with the testbed), then WP-55 and WP-56, then WP-57; WP-72.

**Phase 7: OAST and imports. Release v0.6.**
- WP-58, then WP-59; WP-60.

**Phase 8: plugins and advanced checks. Release v0.7.**
- WP-61, then WP-62; WP-63.

**Phase 9: teams, more front ends and 1.0.**
- WP-30, then WP-64; WP-65, WP-66, WP-67, WP-71, WP-74.
- Gate for 1.0: the docs complete, the migration guide, scanner benchmarks published, and an external security
  review (the owner decides whether to commission one).

### Platform contracts

Once the package that creates a contract has landed, every later package must use it. This is what makes the
features and the front ends fit together:

- **Outbound traffic from any tool** goes through `Gate::check` and uses the pinned address it returns (WP-10). It
  is recorded with its own `FlowSource`, so the Logger (WP-43) sees it.
- **Buffering** reserves bytes from the memory budget (WP-05).
- **Starting a process** (browsers, crawlers) uses the clean-environment helper (WP-01).
- **Schema changes** are new migrations (WP-35). Existing migrations are never edited.
- **New endpoints:**
  - OpenAPI annotations (WP-13);
  - a `bosun-client` method (WP-14);
  - a CLI subcommand where it is useful from a terminal (WP-26);
  - `caller.require`;
  - an audit entry when they change state.
- **Live updates** go through the event stream with sequence numbers (WP-17).
- **Secrets at rest** (auth configs, client certificates, OAST keys) are sealed with the data key (WP-20). From
  WP-29 on they also go in the encrypted vault (WP-68), never in project rows in the clear.
- **UI** stays under the strict CSP. New screens show up in the WinUI and Tauri apps through their webviews without
  extra work; only native-only screens need shell work.
- **New server binaries**, such as Lookout, reuse the Docker and Podman pipeline (WP-24) and the server-mode
  features (WP-23).
- **Signed artifacts** (plugins, check feeds, desktop updates) use the signing set up in WP-22 and WP-69.
- **Tests:** UI flows get a Playwright test (WP-36), and every new parser gets a fuzz target.

### Handing a work package to Claude

Use a prompt like: *"Implement WP-07 from roadmap.md. Read CLAUDE.md and docs/threat-model.md first. Work on a
branch named `wp-07-session-lifecycle`. Stop and ask before anything the package marks as a decision."*

For packages from Phase 5 on, the descriptions are shorter. Ask first: *"Expand WP-54 into a detailed brief: why,
design, tasks, tests, done-when, and how to split it into pull requests. Update roadmap.md with it, then stop."*
Review that brief, then hand over the implementation.

These rules apply to every package:

- Work on one branch per phase and open one pull request per phase, so CI runs once on verified work. Don't commit to `main`.
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and for UI changes `npm run check` and
  `npm run build` all pass. Every bug fixed gets a regression test.
- Follow CLAUDE.md: `unsafe` stays forbidden, CSP rules, every handler calls `caller.require`, audit entries for
  changes to scope, rules, accounts and tokens. Use the platform contracts above.
- Update `docs/threat-model.md`, `docs/architecture.md`, `README.md` and the example configs when behaviour changes.
- Tick the package off in the index and in the milestone items that name it.

### Index (in phase order)

| Status | WP | Title | Phase | Size | Depends on |
|---|---|---|---|---|---|
| [x] | WP-34 | Repository and CI ready | 0 | M | |
| [x] | WP-36 | Test harness: Playwright, property tests, first fuzz targets | 1 | M | WP-34 |
| [x] | WP-01 | Clean environment for child processes | 1 | S | |
| [x] | WP-02 | Pass-through tunnels through the connector | 1 | S | |
| [x] | WP-03 | Sign-in hardening and trusted proxies | 1 | M | |
| [x] | WP-04 | Connection limits and timeouts | 1 | M | |
| [x] | WP-05 | A global memory budget | 1 | M | |
| [x] | WP-06 | Untrusted project files and the project lock | 1 | M | |
| [x] | WP-07 | Session and token lifecycle | 1 | M | |
| [x] | WP-08 | UI TLS without the interception CA | 1 | S | |
| [~] | WP-09 | CI on Windows and macOS (code done, waiting for a CI run) | 1 | S | WP-34 |
| [ ] | WP-10 | Scope gate with address pinning (blocks M2) | 2 | M | |
| [ ] | WP-35 | Schema migrations framework (blocks M2) | 2 | S | WP-06 |
| [ ] | WP-11 | Storage concurrency | 2 | M | WP-06 |
| [ ] | WP-12 | Flow API v2 and non-blocking handlers (blocks M2) | 2 | M | |
| [ ] | WP-17 | Event stream resume | 2 | S | |
| [ ] | WP-13 | OpenAPI contract and generated clients | 2 | M | WP-12 |
| [ ] | WP-14 | The `bosun-client` crate | 2 | M | WP-13 |
| [ ] | WP-15 | Embedded engine mode and login tickets | 2 | M | |
| [ ] | WP-16 | Projects API and UI | 2 | L | WP-06, WP-11, WP-35 |
| [ ] | WP-37 | Footprint budgets in CI | 2 | S | WP-09 |
| [ ] | WP-40 | `bosun-http`: the raw request engine | 3 | L | WP-05, WP-10 |
| [ ] | WP-41 | Repeater | 3 | L | WP-40, WP-12, WP-13, WP-35 |
| [ ] | WP-42 | Decoder and Comparer | 3 | M | WP-13 |
| [ ] | WP-44 | Message editor (CodeMirror 6, hex, pretty-print) | 3 | M | |
| [ ] | WP-43 | History, Organizer, Logger and "send to" | 3 | M | WP-35, WP-41 |
| [ ] | WP-45 | Engagement helpers | 3 | M | WP-41 |
| [ ] | WP-38 | Proxy follow-ups from M1 | 3 | M | WP-04, WP-12 |
| [ ] | WP-39 | TOTP second factor | 3 | M | WP-07 |
| [ ] | WP-23 | Server mode in the engine | 3 | M | WP-03 |
| [ ] | WP-24 | Docker and Podman support | 3 | M | WP-23 |
| [ ] | WP-25 | CLI: local admin commands | 3 | M | WP-07, WP-16 |
| [ ] | WP-26 | CLI: client commands | 3 | L | WP-14 |
| [ ] | WP-20 | Data key in the OS keychain | 3 | M | |
| [ ] | WP-21 | Browser provisioning | 3 | M | WP-01 |
| [ ] | WP-18 | Windows desktop app (WinUI 3) | 3 | L | WP-09, WP-13, WP-15 |
| [ ] | WP-19 | Tauri shell on the child-process model | 3 | M | WP-15 |
| [ ] | WP-22 | Desktop packaging and updates | 3 | L | WP-18, WP-19, WP-21 |
| [ ] | WP-69 | Release workflow | 3 | M | WP-09, WP-24 |
| [ ] | WP-70 | Docs site | 3 | M | WP-13 |
| [ ] | WP-31 | Transparent HTTPS (invisible mode for TLS) | 3 | M | |
| [ ] | WP-47 | Intruder | 4 | L | WP-40, WP-41 |
| [ ] | WP-48 | Sequencer | 4 | M | WP-40 |
| [ ] | WP-27 | Storage layout v2 and benchmarks | 4 | L | WP-11, WP-35 |
| [ ] | WP-28 | Proxy hot path | 4 | M | WP-05 |
| [ ] | WP-32 | CA management | 4 | M | |
| [ ] | WP-33 | Protocol gaps | 4 | M | WP-20 |
| [ ] | WP-46 | Optional `legacy-tls` backend | 4 | M | WP-40 |
| [ ] | WP-49 | Passive scanner, findings and the issues view | 5 | L | WP-05, WP-35 |
| [ ] | WP-50 | `bosun-checks`: the check language and passive checks | 5 | L | WP-49 |
| [ ] | WP-51 | `bosun-report` | 5 | M | WP-49 |
| [ ] | WP-29 | Encrypted projects | 5 | L | WP-20, WP-27 |
| [ ] | WP-73 | Accessibility and keyboard shortcuts | 5 | M | WP-44 |
| [ ] | WP-52 | `bosun-crawl`: the HTTP spider | 6 | M | WP-10, WP-40 |
| [ ] | WP-68 | Encrypted credential vault | 6 | M | WP-20, WP-29 |
| [ ] | WP-53 | Browser crawler and the `BrowserEngine` trait | 6 | L | WP-01, WP-21, WP-24 |
| [ ] | WP-54 | Active scan engine and the testbed | 6 | L | WP-40, WP-49, WP-50 |
| [ ] | WP-55 | Core active checks | 6 | L | WP-54 |
| [ ] | WP-56 | `bosun-auth` and the authorisation matrix | 6 | L | WP-54, WP-68 |
| [ ] | WP-57 | `bosun scan` for CI | 6 | M | WP-25, WP-26, WP-51, WP-54 |
| [ ] | WP-72 | Scanner benchmarks against ZAP | 6 | M | WP-55 |
| [ ] | WP-58 | Lookout, the OAST server | 7 | L | WP-23, WP-24 |
| [ ] | WP-59 | OAST client, payloads and checks | 7 | M | WP-58, WP-41, WP-47, WP-54 |
| [ ] | WP-60 | Imports (OpenAPI, GraphQL, Postman, HAR, URL lists, Burp XML) | 7 | M | WP-16 |
| [ ] | WP-61 | Plugin host | 8 | L | WP-05, WP-10, WP-69 |
| [ ] | WP-62 | Plugin SDK and hooks | 8 | L | WP-61 |
| [ ] | WP-63 | Advanced checks | 8 | L | WP-40, WP-53, WP-54 |
| [ ] | WP-30 | Multi-user server semantics | 9 | L | WP-23 |
| [ ] | WP-64 | Teams: OIDC, per-project permissions, collaboration | 9 | L | WP-30, WP-16, WP-17 |
| [ ] | WP-65 | In-container browser over CDP screencast | 9 | L | WP-53, WP-24 |
| [ ] | WP-66 | Alternative browser engines | 9 | M | WP-53 |
| [ ] | WP-67 | `bosun-tui` | 9 | L | WP-14 |
| [ ] | WP-71 | Migration guide from Burp and ZAP | 9 | S | WP-60 |
| [ ] | WP-74 | HTTP/3 | 9 | L | WP-40 |

---

### Work package details

### WP-01 to WP-09: harden what exists

#### WP-01 Clean environment for child processes · Phase 1 · S

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

#### WP-02 Pass-through tunnels through the connector · Phase 1 · S

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

#### WP-03 Sign-in hardening and trusted proxies · Phase 1 · M

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

#### WP-04 Connection limits and timeouts · Phase 1 · M

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

#### WP-05 A global memory budget · Phase 1 · M

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

#### WP-06 Untrusted project files and the project lock · Phase 1 · M

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

#### WP-07 Session and token lifecycle · Phase 1 · M

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

#### WP-08 UI TLS without the interception CA · Phase 1 · S

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

#### WP-09 CI on Windows and macOS · Phase 1 · S

- **Why:** the engine must run on all three operating systems, but CI tests Linux only, and there are `cfg(unix)`
  code paths (permissions, signals).
- **Do:**
  - Run the `rust` job on `windows-latest` and `macos-latest` too (tests only; fmt and clippy can stay on Linux).
  - Fix what fails: path handling, the permission checks (make `check_private` and `private_dir` meaningful on
    Windows or say why not), and Ctrl-Break/console-close handling in `shutdown_signal`.
  - Add the Windows per-user Chrome path to the browser search list.
- **Done when:** all three operating systems pass on a pull request.
- **Depends on:** CI green on Linux (see Housekeeping).

### WP-10 to WP-17: foundation

#### WP-10 Scope gate with address pinning (blocks M2) · Phase 2 · M

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

#### WP-11 Storage concurrency · Phase 2 · M

- **Why:** one `Mutex<Connection>` per database means history reads and the recorder block each other, and
  `put_blob` hashes and compresses up to 64 MiB *inside* the transaction.
- **Do:**
  - One writer connection, plus a small pool of read-only connections (WAL allows concurrent readers). Reads use
    the pool.
  - Hash and compress bodies on the recorder thread before taking the writer.
  - The same split for `AppDb`.
- **Done when:** a benchmark or test shows `list_flows` latency stays flat while the recorder writes large batches.

#### WP-12 Flow API v2 and non-blocking handlers · Phase 2 · M

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

#### WP-13 OpenAPI contract and generated clients · Phase 2 · M

- **Why:** four front ends (web, WinUI, CLI, TUI) can't share hand-written types. `web/src/lib/types.ts` already
  duplicates the Rust types.
- **Do:**
  - Annotate the API with `utoipa` and write `docs/openapi.json` from a test or a `cargo xtask`.
  - CI fails when the committed spec drifts from the code.
  - Generate the TypeScript types for `web/` from it (replacing `types.ts`). Document how the C# client for WinUI
    is generated (NSwag or Kiota).
  - Version rules: additive changes only within `/api/v1`.
- **Done when:** the UI builds against generated types, and the drift check fails on an undocumented change.
- **Replaces:** the `utoipa` part of "A docs site" under Release.

#### WP-14 The `bosun-client` crate · Phase 2 · M

- **Why:** the CLI, the TUI and the integration tests all need a typed Rust client for the API.
- **Do:**
  - A new crate (reqwest with rustls) with token auth and typed methods for every endpoint.
  - A streaming events subscription with resume (WP-17).
  - Errors that map API messages and status codes.
  - Port `crates/bosun-api/tests/api.rs` to it where it makes the tests clearer.
- **Done when:** the crate covers the whole OpenAPI surface and is used by at least the API tests.

#### WP-15 Embedded engine mode and login tickets · Phase 2 · M

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

#### WP-16 Projects API and UI · Phase 2 · L

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

#### WP-17 Event stream resume · Phase 2 · S

- **Why:** a client that falls behind gets `lagged` and has to reload everything.
- **Do:**
  - Give each event a sequence number and keep a ring buffer of recent events.
  - `/events?since=N` replays from the buffer, or says "reload" when N is too old.
  - The UI reconnects with `since`.
- **Done when:** a test disconnects, generates events and reconnects without losing any.

### WP-18 to WP-26: the front ends

#### WP-18 Windows desktop app (WinUI 3) · Phase 3 · L

- **Why:** the owner wants a native Windows app built on WinUI 3. WinUI 3 is written in C# or C++; Rust can't host
  WinUI 3 XAML, and calling the engine as a library would need `unsafe`. So the app is a C# shell around the engine
  as a child process.
- **Do:**
  - A new `desktop/windows/` folder: C# (.NET 8 or later), Windows App SDK, WinUI 3.
  - The shell starts the `bosun` binary in `--embedded` mode (WP-15), inside a Job Object set to kill it on close,
    reads the handshake and signs in with the ticket.
  - **Native parts:** a `NavigationView` shell, title bar, tray icon, toast notifications (for example "request
    held in intercept"), file pickers for project import and export, the first-run flow, and the project and
    settings pages (using the C# client from WP-13).
  - **Feature screens:** the existing Svelte UI in a **WebView2** control. Hardening:
    - navigation only to the engine's origin (cancel `NavigationStarting` and `NewWindowRequested` for anything
      else; open external links in the default browser only after asking);
    - `AreHostObjectsAllowed = false`, `IsWebMessageEnabled = false`;
    - developer tools and default context menus off in release builds;
    - its own user-data folder;
    - make sure the WebView2 itself never goes through the Bosun proxy.
  - Port individual screens to native WinUI only where it clearly pays off. The Svelte UI stays the one feature UI.
  - CI: build on `windows-latest`.
- **Done when:** on Windows 10 and 11, the app starts the engine, signs in without a password, shows history live,
  launches the proxied browser, and leaves no engine process behind after a crash or close.

#### WP-19 Tauri shell on the child-process model · Phase 3 · M

- **Why:** macOS and Linux keep Tauri, but it should behave like the Windows app. Today `crates/bosun-desktop` runs
  the engine in-process.
- **Do:**
  - Switch `bosun-desktop` to spawn `bosun serve --embedded` and sign in with the ticket.
  - Keep the no-IPC rule and the navigation filter.
  - Allow only one running instance (focus the existing window).
  - Update `docs/architecture.md`.
- **Done when:** the desktop CI job builds on Linux and macOS, and a smoke test launches the app headless where
  possible.

#### WP-20 Data key in the OS keychain · Phase 3 · M

- **Why:** by default `data.key` sits in the same directory as the data it protects.
- **Do:**
  - A `keychain` data-key source using the `keyring` crate (Windows Credential Manager, macOS Keychain, Secret
    Service on Linux).
  - The desktop apps default to it. Servers keep `BOSUN_DATA_KEY_FILE`.
  - `bosun key migrate --to keychain|file` moves the key, re-sealing the CA key.
  - `doctor` reports where the key lives.
- **Done when:** tests use a mock keychain store; migration round-trips; a missing keychain entry gives a clear
  error.

#### WP-21 Browser provisioning · Phase 3 · M

- **Why:** bundling Chrome for Testing makes every installer about 150 MB, and system browser discovery misses
  common installs.
- **Do:**
  - Download Chrome for Testing on first use (with consent) from the official JSON endpoints, verify its SHA-256,
    store it under the data directory, and offer updates.
  - Search more locations: per-user Chrome on Windows (`%LOCALAPPDATA%`), snap and flatpak Chromium on Linux.
  - The settings page shows which browser will be used.
- **Done when:** tests cover the hash check (refuses a wrong hash) and the search order.
- **Replaces:** M1 "Bundle Chrome for Testing with the desktop installers".

#### WP-22 Desktop packaging and updates · Phase 3 · L

- **Do:**
  - Windows: MSIX signed with Azure Trusted Signing (or another signing certificate), and a winget manifest.
  - macOS: a signed and notarised dmg (needs an Apple Developer account).
  - Linux: AppImage, deb and rpm (Flatpak later).
  - Signed auto-update, off by default when a managed-environment policy is set.
  - A tagged-release workflow with checksums and SBOMs.
- **Replaces:** Release items "Desktop installers" and "Auto-update for the desktop app".
- **Decision for the owner:** deferred (2026-11-23). Ship unsigned Windows builds for now. The free option to try later
    is SignPath Foundation, which signs open-source projects at no cost.

#### WP-23 Server mode in the engine · Phase 3 · M

- **Why:** the container needs features that don't exist yet: health checks, setup without a terminal, secrets
  from files and operational output.
- **Do:**
  - `GET /healthz` (no auth, no detail) and a `bosun healthcheck` subcommand, which needs no curl in distroless.
  - Non-interactive setup: `BOSUN_ADMIN_USER` plus `BOSUN_ADMIN_PASSWORD_FILE`, and optionally
    `BOSUN_BOOTSTRAP_TOKEN_FILE`, to create the first admin and an API token at start-up. Audited, and ignored when
    users already exist.
  - `password_file` options for `proxy.auth` and the upstream proxy credentials.
  - JSON logs (`BOSUN_LOG_FORMAT=json`), and an optional Prometheus `/metrics` on a separate listener (off by
    default).
  - Size the WP-05 memory budget from the cgroup limit.
- **Done when:** the container smoke test uses `bosun healthcheck` and the non-interactive setup.
- **Replaces:** M1 "Health endpoint and a `bosun healthcheck` subcommand".

#### WP-24 Docker and Podman support · Phase 3 · M

- **Why:** the container must work the same under Docker and Podman, rootful and rootless.
- **Do:**
  - **Image:**
    - Fully qualified base image names in the `Dockerfile` (`docker.io/library/node:…`, `docker.io/library/rust:…`).
      Podman refuses or asks about short names under strict short-name policy.
    - Keep the digest pins.
    - `HEALTHCHECK CMD ["/usr/local/bin/bosun", "healthcheck"]`. Podman keeps it only in Docker-format images, so
      build with `--format docker` or define the health check in compose and Quadlet as well.
    - Multi-arch (amd64, arm64).
    - Cosign signature and SBOM.
  - **Rootless:**
    - Document and test volume ownership for UID 65532 under user namespaces (`podman run
      --userns=keep-id:uid=65532,gid=65532`,
      or the `:U` volume option).
    - Use `:Z` on bind mounts under SELinux.
    - Check that the data directory permission checks work with mapped UIDs.
  - **Networking:**
    - Rootless Podman (`pasta`/`slirp4netns`) and Docker's userland proxy hide or rewrite client addresses, so
      `allow_clients` can't be the only control. Document it in `docker/bosun.toml`; recommend proxy auth when the
      port is published beyond loopback.
    - Show `host.containers.internal` versus `host.docker.internal` for reaching targets on the host.
  - **Deployment files:**
    - `compose.example.yaml` checked with both `docker compose` and `podman compose`. Keep to keys both support:
      `mem_limit`, `pids_limit`, `read_only`, `cap_drop`, `security_opt`, `tmpfs`.
    - A Quadlet unit (`deploy/podman/bosun.container` plus a `.volume`) for systemd-managed rootless Podman, with
      `ReadOnly=true`, `DropCapability=ALL`, `NoNewPrivileges=true`, `HealthCmd=`, `Secret=` for the data key, and
      `AutoUpdate=registry`.
    - Secrets: `docker secret`/compose secrets and `podman secret` both mounted at `/run/secrets/bosun_data_key`.
  - **CI:** an image job for Podman next to the Docker one (build with buildah/podman, run rootless, the same smoke
    test, Trivy).
  - **Docs:** a "Containers" page covering Docker, Docker rootless, Podman rootful and rootless, and a reverse proxy
    in front.
- **Done when:** CI builds and smoke-tests the image under Docker and rootless Podman, and the Quadlet unit starts,
  passes its health check and restarts on failure in a test VM or runner.

#### WP-25 CLI: local admin commands · Phase 3 · M

- **Do:**
  - `user role`, `user delete`, `user sessions [--revoke]`, `token create|list|revoke`.
  - `project list|export|import|backup` (built on WP-16).
  - Hidden password input when stdin is a terminal (`rpassword`), still read from stdin for scripts.
  - `serve --no-ui` for recording only.
  - Shell completions (`clap_complete`) and man pages (`clap_mangen`).
  - `--json` output for `list` commands.
- **Done when:** each command has a test (CLI tests with `assert_cmd` against a temporary data directory).

#### WP-26 CLI: client commands · Phase 3 · L

- **Why:** a CLI for a running engine (local or a server), not just local administration.
- **Do:**
  - Built on `bosun-client`.
  - `bosun login --server URL` with named profiles in the config directory; the token is kept in the OS keychain,
    or in a 0600 file when there is no keychain.
  - `history list|search|show|export` (HAR and ndjson), `scope get|set|add`, `rules get|set|import`,
    `intercept on|off|queue|forward|drop`, `ca export`, `status`, `events --follow`.
  - Output as tables, `--json` or `--ndjson`; meaningful exit codes; `--quiet`.
  - Later packages add `repeater send` (M2) and `scan` (M5).
- **Done when:** integration tests run each command against an engine started in the test.

### WP-27 to WP-33: performance and depth

#### WP-27 Storage layout v2 and benchmarks · Phase 4 · L

- **Depends on:** WP-11, WP-35.

- **Why:**
  - Content addressing on whole raw messages rarely deduplicates anything, because headers such as `Date` and
    cookies differ.
  - `delete_flows` scans every flow to clean up blobs.
  - "Fast at millions of rows" isn't measured, and host search and extension filters scan the whole table.
- **Do:**
  - Store header blocks and bodies separately and deduplicate bodies only. Count references to blobs, or clean
    them up in the background.
  - Write the v1-to-v2 migration with the framework from WP-35, tested on a real v1 file.
  - Indexes for host search (for example a reversed-host column) and extensions (an `ext` column).
  - Criterion benchmarks at 1 million flows, tracked in CI as part of the footprint budgets.
- **Done when:** a v1 project migrates, the benchmarks run in CI, and the measured storage saving is noted here.

#### WP-28 Proxy hot path · Phase 4 · M

- **Why:**
  - Each message is copied about three times, and `new_flow` re-parses the full request and response to get
    values already known.
  - Request bodies are always fully buffered.
  - Flow ids are reserved for flows that won't be recorded.
- **Do:**
  - Pass the method, path and status through instead of re-parsing.
  - Keep bodies as `Bytes` (no copies).
  - Stream request bodies (with a capped tee for recording) when neither intercept nor a request-body rule needs
    them buffered.
  - Reserve an id only when recording.
  - Criterion throughput and latency benchmarks.
- **Done when:** the benchmarks show the improvement and the proxy tests still pass.

#### WP-29 Encrypted projects · Phase 5 · L

- **Why:** project files hold captured credentials in the clear.
- **Do:**
  - Encryption inside the app: each project has its own key, wrapped by the data key. Bodies and header blocks are
    compressed, then sealed with XChaCha20-Poly1305, before they are stored.
  - Exporting a project asks for a passphrase (argon2id) to wrap the project key, so it can be shared.
  - No SQLCipher and no OpenSSL.
  - Searchable text stays unencrypted, or there is an option to skip indexing; this is a decision for the owner.
- **Replaces:** M8 "Encrypted projects (SQLCipher feature)".

#### WP-30 Multi-user server semantics · Phase 9 · L

- **Why:**
  - All users share one intercept queue and one history.
  - Proxy traffic isn't linked to any user.
  - Proxy auth is one shared plaintext credential, with no brute-force limit.
- **Do:**
  - Proxy credentials per user (a username plus an API token with a `proxy` scope).
  - Record which user sent each flow, and filter history by user.
  - Intercept queues per user, or claiming an item so others can't act on it.
  - Rate-limit failed proxy authentication.
- **Relates to:** M8 multi-user hardening.

#### WP-31 Transparent HTTPS (invisible mode for TLS) · Phase 3 · M

- **Why:** the README promises invisible (transparent) proxying, but a TLS ClientHello arriving directly at the
  listener is handed to the HTTP/1 server, so transparent HTTPS doesn't work.
- **Do:**
  - First (do this in Phase 1, it is one line): change the README to say "HTTP only" until this lands.
  - Then: when `invisible` is on, peek at the first byte on accept; for TLS, take the target from the SNI (and
    optionally from the original destination on Linux through `SO_ORIGINAL_DST`, which needs a safe wrapper or a
    crate) and intercept as for CONNECT.
- **Done when:** a test sends HTTPS straight to the listener with SNI and gets the flow recorded.

#### WP-32 CA management · Phase 4 · M

- **Do:**
  - `bosun ca rotate` (new CA, old one kept for reference, the browser profile updated with the new pin).
  - Expiry warnings in `doctor` and the UI.
  - An optional **name-constrained** CA (limited to the scope's domains) for installing on test devices.
  - Document when to use each.

#### WP-33 Protocol gaps · Phase 4 · M

- **Do:**
  - Client certificates for targets that require them (per-host PKCS#12 or PEM, keys sealed with the data key).
  - Inflate `permessage-deflate` WebSocket messages for display.
  - Upstream SNI override and HTTP/1 header-case preservation for edited requests.

### WP-34 to WP-39: repository, quality and M1 follow-ups

#### WP-34 Repository and CI ready · Phase 0 · M

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
- **Status (2026-11-23):** done. The repo is public; CI is green on `main`; branch protection requires the six
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

#### WP-35 Schema migrations framework · Phase 2 · S

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

#### WP-36 Test harness: Playwright, property tests, first fuzz targets · Phase 1 · M

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

#### WP-37 Footprint budgets in CI · Phase 2 · S

- **Do:**
  - Measure idle RSS of `bosun serve` (budget: under 50 MB) and the image size, on every pull request.
  - Fail on regressions over a threshold; record the numbers in a CI summary.
  - Leave hooks for the throughput and latency benchmarks that WP-27 and WP-28 add.
- **Done when:** CI fails when idle RSS goes over budget.

#### WP-38 Proxy follow-ups from M1 · Phase 3 · M

- **Do:**
  - **Response interception rules:** hold a response only when it matches conditions (status, MIME type, header
    or body match, the request was intercepted).
  - **Listener management:** several proxy listeners, each with its own options (address, invisible mode,
    pass-through, auth). Managed in the UI, changed live without a restart, using the connection limits from
    WP-04. Every change is audited.
  - **Live config reload** for the settings that can change safely; the others say a restart is needed.
  - **Size and timing stats in history:** request and response sizes, time to first byte and total time, as
    sortable columns.
- **Done when:** API and Playwright tests cover each item; adding a listener needs no restart.

#### WP-39 TOTP second factor · Phase 3 · M

- **Do:**
  - Optional TOTP per account (RFC 6238), with the secret sealed with the data key, and one-time recovery codes.
  - Sign-in asks for the code after the password. Codes count towards the WP-03 limits.
  - Admins can require TOTP for everyone, and reset a user's TOTP (audited).
  - The desktop login ticket (WP-15) skips TOTP, because it is a local, single-use exchange.
- **Done when:** API tests cover enrolment, sign-in, a replayed code (refused), recovery codes and admin reset.

### WP-40 to WP-46: M2 manual tools

#### WP-40 `bosun-http`: the raw request engine · Phase 3 · L

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

#### WP-41 Repeater · Phase 3 · L

- **Do:**
  - Tabs, saved in the project (a migration, WP-35), with per-tab history and back/forward.
  - HTTP/1.1, HTTP/2 and WebSocket sends through WP-40.
  - A response diff with the previous send.
  - Send groups: in order, in parallel, and the single-packet attack for race conditions.
  - Endpoints in OpenAPI, a `bosun-client` method and `bosun repeater send` in the CLI (WP-26).
- **Done when:** API and Playwright tests cover tabs, history, diff and send groups; the CLI command sends a raw
  file.

#### WP-42 Decoder and Comparer · Phase 3 · M

- **Do:**
  - **Decoder:** chains of URL, HTML, Base64/Base64url, hex, gzip/deflate/brotli/zstd, JWT, Unicode escapes and
    hashing, plus "smart decode". Implemented in Rust behind an endpoint, so the CLI and plugins share it, with the
    WP-06 decompression caps.
  - **Comparer:** word-level and byte-level diff of any two messages or texts.
  - Fuzz targets for the decoders.
- **Done when:** unit tests cover each codec, including bombs and invalid input.

#### WP-43 History, Organizer, Logger and "send to" · Phase 3 · M

- **Do:**
  - **History:** a column chooser, sorting, colour highlights, bulk tag and delete.
  - **Organizer:** save requests with notes and a status for follow-up (a migration).
  - **Logger:** every request from every tool, using the `FlowSource` each tool records, with filters.
  - **"Send to"** Repeater, Intruder, Comparer or Decoder from everywhere a message is shown.
- **Done when:** Playwright tests cover each view and the send-to menu.

#### WP-44 Message editor (CodeMirror 6, hex, pretty-print) · Phase 3 · M

- **Do:**
  - CodeMirror 6 for the raw editor, with HTTP syntax highlighting; a hex editor; pretty-printing of JSON, XML and
    HTML as text, never rendered.
  - Check CodeMirror under the strict CSP. It adds its styles with constructed stylesheets or `<style>`
    elements; if anything is blocked, use `EditorView.cspNonce` with a per-response nonce from the server instead
    of loosening `style-src`. Record the decision in the threat model.
  - Large messages stay responsive (load bodies in pages from WP-12's endpoints).
- **Done when:** a Playwright test edits and sends a message, and the CSP header is unchanged or only gains a
  nonce.

#### WP-45 Engagement helpers · Phase 3 · M

- **Do:** generate a CSRF proof of concept (as a file to download, never rendered in the UI's origin), find
  comments and scripts, find references, and analyse a target (parameters and endpoints from history).
- **Done when:** unit tests on recorded fixtures; the PoC download has `Content-Disposition: attachment`.

#### WP-46 Optional `legacy-tls` backend · Phase 4 · M

- **Do:**
  - An opt-in Cargo feature (OpenSSL) for very old targets (SSLv3, TLS 1.0, weak ciphers), upstream only, used by
    WP-40 when a per-target setting asks for it.
  - A `cargo-deny` exception scoped to the feature; it is not in default builds or the published images.
- **Done when:** a feature-gated test reaches a TLS 1.0 test server; default builds still contain no OpenSSL.

### WP-47 and WP-48: M3 Intruder and Sequencer

#### WP-47 Intruder · Phase 4 · L

- **Do:**
  - Attack types: sniper, battering ram, pitchfork, cluster bomb.
  - Payload sources: lists, files, numbers, dates, brute-forcer, character substitution, case changes, null
    payloads, recursive grep, the results of earlier attacks. Bundled wordlists and SecLists support.
  - Payload processing: prefix and suffix, encode and decode, hash, regex replace, skip rules.
  - Resource pools: concurrency, delays, throttling and retries, inside the gate's per-host rate limit (WP-10) and
    the memory budget (WP-05).
  - A results table with grep match, grep extract, status, length and timing; sorting, filtering and export.
    Results are stored with a migration and streamed over the event stream.
  - The stop switch halts attacks at once.
- **Done when:** tests against a local server cover each attack type, the rate limit and the stop switch.

#### WP-48 Sequencer · Phase 4 · M

- **Do:**
  - Live capture (a request and a token location, sent through WP-40) and manual load.
  - Analysis: FIPS 140-2 tests (monobit, poker, runs, long runs), character-level and bit-level analysis, an
    entropy estimate and a verdict; exportable results.
- **Done when:** known-good and known-bad token sets get the right verdicts.

### WP-49 to WP-51: M4 passive scanning and reports

#### WP-49 Passive scanner, findings and the issues view · Phase 5 · L

- **Do:**
  - A passive scanner fed from the recorder through a bounded queue (WP-05), off the hot path, also run on
    imports. Deduplicated.
  - The finding model: issue type, severity, confidence, evidence (highlighted ranges in the request and
    response), remediation, CWE and OWASP references, status (new, confirmed, false positive). Stored with a
    migration.
  - An issues view in the UI with filters, grouping and links back to the evidence.
- **Done when:** a backlog of recorded traffic is scanned without slowing the proxy; findings survive a restart.

#### WP-50 `bosun-checks`: the check language and passive checks · Phase 5 · L

- **Do:**
  - A YAML check language (request templates, matchers, extractors, OAST hooks), versioned and validated, with a
    fuzz target for the loader.
  - Import a compatible subset of Nuclei templates (MIT; keep their notices).
  - Port ZAP's passive rules where useful (Apache-2.0; attribution in `NOTICE`).
  - Passive checks: security headers, cookie flags, CSP weaknesses, CORS, information disclosure, mixed content,
    vulnerable JS libraries (Retire.js-style data), JWT issues, cacheable sensitive responses, open redirect hints,
    directory listings.
- **Done when:** every check has a positive and a negative fixture test.

#### WP-51 `bosun-report` · Phase 5 · M

- **Do:**
  - HTML (self-contained, no script), JSON, SARIF, JUnit and Markdown reports. Secrets are redacted by default.
  - Endpoints, a `bosun report` CLI command, and a Playwright test that the HTML report runs no script.
- **Done when:** golden-file tests for each format; the SARIF validates against its schema.

### WP-52 to WP-57, WP-68 and WP-72: M5 active scanning

#### WP-52 `bosun-crawl`: the HTTP spider · Phase 6 · M

- **Do:** an HTTP spider (forms, links, robots.txt, sitemap.xml) bounded by scope, depth and the gate's rate limit,
  sending through WP-40.
- **Done when:** a crawl of the testbed finds every linked page and never leaves scope.

#### WP-53 Browser crawler and the `BrowserEngine` trait · Phase 6 · L

- **Do:**
  - "Deckhand": chrome-headless-shell pooled over CDP (`bosun-browser`), one context per task, started on demand
    and stopped when idle, with the sandbox on.
  - The browser comes from WP-21's provisioning and is started with WP-01's clean environment.
  - A seccomp profile for the container, tested under Docker and Podman (WP-24).
  - A `BrowserEngine` trait so other engines can be added (WP-66).
- **Done when:** the crawler finds script-generated links on the testbed; idle browsers are stopped.

#### WP-54 Active scan engine and the testbed · Phase 6 · L

- **Do:**
  - First, the in-repo `testbed` crate: a small server with known vulnerabilities, so scanner tests in CI are
    deterministic.
  - Insertion points: query, body (form, JSON, XML, multipart), headers, cookies, path segments, nested encodings
    (Base64 or JSON inside a parameter), GraphQL variables.
  - Scan policies (checks, strength, thresholds), a scan queue, pause and resume, a live progress view.
  - Checks come from WP-50's language and from Rust checks; all traffic goes through WP-40 and the gate.
- **Done when:** a scan of the testbed finds its planted issues, pauses and resumes, and stays in scope.

#### WP-55 Core active checks · Phase 6 · L

- **Do:**
  - SQL injection (error, boolean, time), reflected and stored XSS, SSTI, OS command injection, path traversal
    and LFI, XXE, open redirect, CRLF and header injection, Host header attacks, CORS misconfiguration, file upload,
    JWT attacks, deserialization indicators, prototype pollution, GraphQL issues, auth and session weaknesses, and
    TLS configuration.
  - "Destructive" checks flagged and off by default.
- **Done when:** each check has testbed coverage, plus a negative case for false positives.

#### WP-56 `bosun-auth` and the authorisation matrix · Phase 6 · L

- **Do:**
  - Session handling: login macros, token refresh, recorded browser logins, re-auth on expiry. Credentials live
    in the encrypted vault (WP-68).
  - A multi-user authorisation matrix for IDOR and access-control testing across accounts.
- **Done when:** a scan of the testbed's logged-in area stays logged in, and the matrix finds its planted IDOR.

#### WP-57 `bosun scan` for CI · Phase 6 · M

- **Do:**
  - A headless scan from a URL or an API definition (WP-60 later adds more import formats), with the exit code
    set by a severity threshold and SARIF output (WP-51).
  - Runs without the UI (`serve --no-ui` from WP-25) or against a remote engine (WP-26).
  - Documented recipes for GitHub Actions and GitLab CI, and use as a container image (WP-24).
- **Done when:** a CI job scans the testbed and fails on its planted high-severity issue.

#### WP-68 Encrypted credential vault · Phase 6 · M

- **Do:** a vault for auth configs, client certificates (WP-33) and OAST keys (WP-59), sealed with the project key
  from WP-29 and the data key. Its secrets are never sent to the UI in full; they are referenced by id.
- **Done when:** tests show vault contents are unreadable in the project file and absent from API responses.

#### WP-72 Scanner benchmarks against ZAP · Phase 6 · M

- **Do:** run Bosun and ZAP against OWASP Juice Shop, DVWA, WebGoat, VAmPI/crAPI and the OWASP Benchmark;
  compare detection rate, false positives, scan time and peak memory. Publish the results and repeat each release.
- **Done when:** the numbers are published in the docs (WP-70).

### WP-58 to WP-60: M6 OAST and imports

#### WP-58 Lookout, the OAST server · Phase 7 · L

- **Do:**
  - A separate, self-hostable binary and image with DNS, HTTP/HTTPS (ACME) and SMTP listeners.
  - Per-payload correlation IDs, a polling API with per-client keys, automatic expiry of interactions, and no
    access to project data.
  - Reuses the server-mode features (WP-23) and the Docker and Podman pipeline, including a Quadlet unit (WP-24).
  - Its own threat model section.
- **Done when:** a test client registers, triggers DNS and HTTP interactions and polls them back.

#### WP-59 OAST client, payloads and checks · Phase 7 · M

- **Do:**
  - The client for Lookout and interactsh-compatible servers; its keys live in the vault (WP-68).
  - An OAST payload generator in Repeater (WP-41) and Intruder (WP-47).
  - OAST checks in the scanner (WP-54): blind SQL injection, SSRF, XXE, RCE, blind XSS, DNS rebinding probes.
- **Done when:** the testbed's blind SSRF is found through a local Lookout.

#### WP-60 Imports · Phase 7 · M

- **Do:** OpenAPI/Swagger 2 and 3, GraphQL introspection, Postman collections, HAR, plain URL lists, and Burp XML
  exports where the format allows. Imports go through the WP-16 import path, with size caps, and fuzz targets for
  each parser.
- **Done when:** fixture files of each format import; hostile fixtures are refused cleanly.

### WP-61 to WP-63: M7 plugins and advanced checks

#### WP-61 Plugin host · Phase 8 · L

- **Do:**
  - `bosun-plugin`: a wasmtime component-model host, a WIT interface, fuel and memory caps (memory counts against
    WP-05), no WASI filesystem or network. All I/O goes through host calls that use the scope gate (WP-10).
  - Capability manifests the user approves; minisign-signed plugins and check feeds, using the release signing
    from WP-69.
  - A fuzz target for the host boundary.
- **Done when:** tests show a plugin can't exceed its caps, reach the network outside the gate, or load unsigned
  when signatures are required.

#### WP-62 Plugin SDK and hooks · Phase 8 · L

- **Do:**
  - A Rust guest SDK, example plugins and docs; later, SDKs for other languages that compile to WASM.
  - Hooks: passive and active checks, message editors and views, payload generators and processors, context
    menu actions, and UI panels in a sandboxed iframe (the CSP rules hold).
- **Done when:** each hook has an example plugin with a test.

#### WP-63 Advanced checks · Phase 8 · L

- **Do:** request smuggling (CL.TE, TE.CL, H2 downgrade, client-side desync, using WP-40's raw HTTP/2 frames), web
  cache poisoning and deception, DOM XSS through browser instrumentation (WP-53), race conditions (WP-41's
  single-packet sends), and OAuth/OIDC misconfiguration.
- **Done when:** each check has a testbed case.

### WP-64 to WP-74: M8, release and the long tail

#### WP-64 Teams: OIDC, per-project permissions, collaboration · Phase 9 · L

- **Do:** OIDC sign-in, per-project permissions, and collaboration (shared projects with live updates over the
  WP-17 event stream). Builds on WP-30's per-user attribution.
- **Done when:** two users on one server see each other's work live and can't open projects they aren't allowed
  to.

#### WP-65 In-container browser over CDP screencast · Phase 9 · L

- **Do:** a browser inside the container (WP-53's engine), streamed into the web UI over a CDP screencast, so
  server users can browse through the proxy without configuring their own browser. Input events go through the
  API with role checks; the stream is shown in the UI without executing target content in the UI's origin.
- **Done when:** a Playwright test browses the testbed through the streamed browser.

#### WP-66 Alternative browser engines · Phase 9 · M

- **Do:** Lightpanda as an opt-in fast crawler engine behind the `BrowserEngine` trait, falling back to Chromium
  when a page breaks. Keep a note here on Servo's progress as an embeddable pure-Rust engine.
- **Done when:** the crawler runs on Lightpanda with the fallback tested.

#### WP-67 `bosun-tui` · Phase 9 · L

- **Do:** a ratatui client over the API using `bosun-client` (WP-14): history, intercept, Repeater, scan
  progress.
- **Done when:** the TUI can intercept and forward a request against a test engine.

#### WP-69 Release workflow · Phase 3 · M

- **Do:**
  - Tagged builds for Linux, macOS and Windows (x86_64 and aarch64), and multi-arch images for Docker and Podman
    (WP-24).
  - A CycloneDX SBOM, cosign-signed images and artifacts, checksums and release notes.
  - The weekly scheduled CI run publishes a fresh SBOM.
  - The signing set up here is reused for plugins and check feeds (WP-61).
- **Done when:** a test tag produces a complete, verifiable release.

#### WP-70 Docs site · Phase 3 · M (grows every phase)

- **Do:** getting started, CA and browser setup, containers (Docker, Docker rootless, Podman, Quadlet, reverse
  proxy), the desktop apps, the CLI, and the API reference from the OpenAPI spec (WP-13). Later phases add
  writing checks (WP-50) and plugins (WP-62).
- **Done when:** the site builds in CI and is published with each release.

#### WP-71 Migration guide from Burp and ZAP · Phase 9 · S

- **Do:** shortcut equivalents, and how to import projects and history (WP-60). No Burp, Collaborator or ZAP
  branding.

#### WP-73 Accessibility and keyboard shortcuts · Phase 5 · M

- **Do:** keyboard navigation and visible focus everywhere, ARIA roles for tables, tabs and dialogs, contrast that
  passes WCAG 2.2 AA in light and dark themes, and a shortcut map (familiar to Burp users where sensible), with a
  shortcut help overlay. Shortcuts must not clash with WebView2 or the Tauri webview.
- **Done when:** axe checks in the Playwright suite (WP-36) pass on every main view.

#### WP-74 HTTP/3 · Phase 9 · L

- **Do:** HTTP/3 (QUIC) for the client side (the browser to the proxy) and upstream, on a rustls-based QUIC stack,
  with recording and interception like HTTP/2.
- **Done when:** a browser using HTTP/3 through the proxy is recorded, and an upstream HTTP/3-only test server is
  reachable.


---

## Milestone checklists

The features each milestone delivers. Every open item names the work package (or phase gate) that delivers it;
the phase plan above sets the order. Tick an item here when its package lands.

### M0 Foundations: done

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

### M1 Proxy: done, with a few items open

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
- [ ] Bundle Chrome for Testing with the desktop installers (download, verify by SHA-256, keep it updated): **WP-21**
- [ ] One-time login ticket for the desktop app, so it doesn't ask for a password on every launch: **WP-15**
- [ ] Optional TOTP second factor for UI accounts → **WP-39**
- [ ] Projects in the UI: create, switch, export and import `.bosun` files; project-level settings: **WP-16**
- [ ] History: column chooser, sorting, colour highlights, bulk tag/delete, "send to" menu (wired up in M2) → **WP-43**
- [ ] Response interception rules (intercept only when the response matches a condition) → **WP-38**
- [ ] Proxy listener management in the UI (several listeners, per-listener options) and a live-config reload → **WP-38**
- [ ] Request/response size and timing stats in history → **WP-38**
- [ ] HTTP/3 (QUIC) for the client side and upstream → **WP-74**
- [ ] Health endpoint and a `bosun healthcheck` subcommand for container health checks (distroless has no curl):
  **WP-23**

### M2 Manual tools

- [ ] `bosun-http`: a raw request engine that sends bytes exactly as written (malformed requests, duplicate
  headers, bare LF, unusual methods), over HTTP/1.1, HTTP/2 (its own frames), and WebSockets → **WP-40**
- [ ] Optional `legacy-tls` backend (OpenSSL, opt-in feature) for very old targets, upstream only → **WP-46**
- [ ] **Repeater**: tabs, per-tab history (back/forward), h1/h2/WebSocket, raw bytes, "update Content-Length",
  follow redirects (optional), response diff with the previous send, send groups (in order or in parallel,
  single-packet attack for race conditions) → **WP-41**
- [ ] **Decoder**: chains of URL, HTML, Base64/Base64url, hex, gzip/deflate/brotli/zstd, JWT, Unicode escapes,
  hashing, "smart decode" → **WP-42**
- [ ] **Comparer**: word- and byte-level diff of any two messages or texts → **WP-42**
- [ ] **Organizer**: save requests with notes and status for follow-up → **WP-43**
- [ ] **Logger**: every request from every tool (not just the proxy), with filters → **WP-43**
- [ ] "Send to Repeater, Intruder, Comparer or Decoder" everywhere a message is shown → **WP-43**
- [ ] Request editor with syntax highlighting (CodeMirror 6), a hex editor, and pretty-printing of JSON, XML and
  HTML (as text, never rendered) → **WP-44**
- [ ] Engagement helpers: generate a CSRF PoC, find comments and scripts, find references, analyse a target
  (parameters and endpoints) → **WP-45**
- [ ] The scope gate enforced for every tool request (refuse out-of-scope, a per-host rate limit, the stop switch),
  with pinned addresses: **WP-10** must land first

### M3 Intruder and Sequencer

- [ ] **Intruder** attack types: sniper, battering ram, pitchfork, cluster bomb → **WP-47**
- [ ] Payload sources: simple lists, files, numbers, dates, brute-forcer, character substitution, case
  modification, null payloads, recursive grep, results of earlier attacks → **WP-47**
- [ ] Payload processing: prefix and suffix, encode and decode, hash, regex replace, skip rules → **WP-47**
- [ ] Bundled wordlists and support for SecLists → **WP-47**
- [ ] Results table: grep match, grep extract, status, length and timing columns, sorting, filtering, export → **WP-47**
- [ ] Resource pools: concurrency, delays, throttling, retries → **WP-47**
- [ ] **Sequencer**: live capture (from a request and a token location) and manual load → **WP-48**
- [ ] Analysis: FIPS 140-2 tests (monobit, poker, runs, long runs), character-level and bit-level analysis,
  entropy estimate, a verdict, exportable results → **WP-48**

### M4 Passive scanner, the check engine and reports

- [ ] Passive scanner on all proxied traffic (and on imports), off the hot path, deduplicated → **WP-49**
- [ ] Finding model: issue type, severity, confidence, evidence (highlighted request and response ranges),
  remediation, CWE and OWASP references, status (new, confirmed, false positive) → **WP-49**
- [ ] `bosun-checks`: a YAML check language (request templates, matchers, extractors, OAST hooks), versioned and
  validated → **WP-50**
- [ ] Import a compatible subset of Nuclei templates (MIT; keep their notices) → **WP-50**
- [ ] Port ZAP's passive rules where useful (Apache-2.0; attribution in `NOTICE`) → **WP-50**
- [ ] Passive checks for: security headers, cookie flags, CSP weaknesses, CORS, information disclosure (stack
  traces, versions, private IPs, keys), mixed content, vulnerable JS libraries (Retire.js-style data), JWT
  issues, cacheable sensitive responses, open redirect hints, and directory listings → **WP-50**
- [ ] `bosun-report`: HTML (self-contained, no script), JSON, SARIF, JUnit and Markdown; secrets redacted by default
  → **WP-51**
- [ ] An issues view in the UI with filters and grouping, and links back to the evidence → **WP-49**

### M5 Active scanning

- [ ] `bosun-crawl`: an HTTP spider (forms, links, robots.txt, sitemap.xml) bounded by scope and depth → **WP-52**
- [ ] Browser crawler: chrome-headless-shell pooled over CDP (`bosun-browser`), one context per task, started on
  demand and stopped when idle, sandbox on, a seccomp profile in the container. Working name: "Deckhand". → **WP-53**
- [ ] A `BrowserEngine` trait so other engines can be added (see M8) → **WP-53**
- [ ] Insertion points: query, body (form, JSON, XML, multipart), headers, cookies, path segments, nested
  encodings (Base64 or JSON inside a parameter), GraphQL variables → **WP-54**
- [ ] Scan policies (checks, strength, thresholds), scan queue, pause/resume, a live progress view → **WP-54**
- [ ] Core active checks: SQL injection (error, boolean, time), reflected and stored XSS, SSTI, OS command
  injection, path traversal and LFI, XXE, open redirect, CRLF and header injection, Host header attacks, CORS
  misconfiguration, file upload, JWT attacks, deserialization indicators, prototype pollution, GraphQL issues,
  auth and session weaknesses, TLS configuration → **WP-55**
- [ ] "Destructive" checks flagged and off by default → **WP-55**
- [ ] `bosun-auth`: session handling (login macros, token refresh, recorded browser logins, re-auth on expiry) →
  **WP-56**
- [ ] Multi-user authorisation matrix (IDOR and access-control testing across accounts) → **WP-56**
- [ ] `bosun scan` CLI: headless CI scan from a URL or an API definition, exit code from a severity
  threshold, SARIF output → **WP-57**
- [ ] An in-repo `testbed` crate with known vulnerabilities, so scanner tests in CI are deterministic → **WP-54**

### M6 OAST server and API imports

- [ ] **Lookout**: a separate, self-hostable OAST server binary and image with DNS, HTTP/HTTPS (ACME) and SMTP
  listeners, per-payload correlation IDs, a polling API with per-client keys, automatic expiry of interactions,
  and no access to project data → **WP-58**
- [ ] Client side: Lookout or interactsh-compatible servers, and an OAST payload generator in Repeater and Intruder →
  **WP-59**
- [ ] OAST checks: blind SQL injection, SSRF, XXE, RCE, blind XSS, DNS rebinding probes → **WP-59**
- [ ] Imports: OpenAPI/Swagger 2 and 3, GraphQL introspection, Postman collections, HAR, plain URL lists; and
  Burp XML exports where the format allows → **WP-60**

### M7 Plugins and advanced checks

- [ ] `bosun-plugin`: a wasmtime component-model host, a WIT interface, fuel and memory caps, no WASI filesystem or
  network, all I/O through host calls that go through the scope gate → **WP-61**
- [ ] Capability manifests that the user approves; minisign-signed plugins and check/template feeds → **WP-61**
- [ ] A Rust guest SDK, example plugins, docs; later SDKs for other languages that compile to WASM → **WP-62**
- [ ] Plugin hooks: passive and active checks, message editors and views, payload generators and processors,
  context menu actions, UI panels in a sandboxed iframe → **WP-62**
- [ ] Advanced checks: request smuggling (CL.TE, TE.CL, H2 downgrade, client-side desync), web cache poisoning and
  deception, DOM XSS through browser instrumentation, race conditions, OAuth/OIDC misconfiguration → **WP-63**

### M8 Teams, containers, engines and the TUI

- [ ] Multi-user hardening: OIDC sign-in, per-project permissions, collaboration (shared projects, live updates);
  builds on **WP-30**; delivered by **WP-64**
- [ ] An in-container browser streamed into the web UI over CDP screencast (for container mode) → **WP-65**
- [ ] Lightpanda as an opt-in fast crawler engine that falls back to Chromium when a page breaks → **WP-66**
- [ ] Track Servo as an embeddable pure-Rust engine → **WP-66**
- [ ] `bosun-tui`: a ratatui client over the same API (uses `bosun-client`, **WP-14**); delivered by **WP-67**
- [ ] Encrypted projects (in-app encryption, not SQLCipher: **WP-29**) and an encrypted credential vault for auth
  configs; delivered by **WP-68**

### Release and packaging (from the first public release onwards)

- [x] Licence decided: Apache-2.0 (was PolyForm Noncommercial, which barred paid client work).
- [ ] Finish the name check for Bosun: the name is kept (decided 2026-11-23, crate `bosun-dast`, npm `@macleodtech`).
  Still to do: look up the pending BOSUN Class 9 filing (serial 98940487) and pick a domain (the crates are
  never published; the GitHub repos with this name are unrelated: an old monitoring tool and a small agent
  orchestrator). No Burp, Collaborator or ZAP branding anywhere. → owner task, Phase 3
- [ ] A release workflow: tagged builds for Linux, macOS and Windows (x86_64 and aarch64), multi-arch images for
  Docker and Podman (**WP-24**), a CycloneDX SBOM, cosign-signed images and artifacts, checksums, release notes;
  delivered by **WP-69**
- [ ] Desktop installers (MSIX/winget, dmg, AppImage/deb/rpm), code signing and notarisation: **WP-22**
- [ ] Auto-update for the desktop app, signed, off by default in managed environments: **WP-22**
- [ ] A docs site: getting started, CA and browser setup, container deployment behind a reverse proxy, the API
  reference (OpenAPI generated from code with `utoipa`, **WP-13**), writing checks and plugins; delivered by **WP-70**
- [ ] A migration guide from Burp and ZAP (shortcut equivalents, importing projects and history) → **WP-71**

### Quality, performance and security work (continuous)

- [ ] Footprint budgets in CI (benchmarks start in **WP-27** and **WP-28**): engine idle RSS under 50 MB, proxy
  throughput and latency benchmarks (criterion), tracked image sizes; delivered by **WP-37**
- [ ] `cargo-fuzz` targets: the HTTP parser, the WebSocket frame parser, decoders and decompression, the scope
  rule compiler, the YAML check loader, the plugin host boundary → **WP-36**, then each package that adds a parser
- [ ] Playwright end-to-end tests of the UI against `bosun serve`, including a test that the render view
  cannot run script → **WP-36**
- [ ] Scanner benchmarks against OWASP Juice Shop, DVWA, WebGoat, VAmPI/crAPI and the OWASP Benchmark, comparing
  detection rate, false positives, scan time and peak memory with ZAP on the same targets → **WP-72**
- [ ] Property tests for scope matching and for raw message round-trips → **WP-36**
- [ ] A weekly scheduled CI run (already configured) and the SBOM published with each release → **WP-69**
- [ ] A security review before each milestone ships: threat model updated, new endpoints checked for role
  checks and audit entries → every phase gate
- [ ] Accessibility and keyboard shortcuts across the UI (Burp-compatible where sensible) → **WP-73**

### Housekeeping

- [x] Create the GitHub repository (MacLeodTech/Bosun); public, CI on GitHub-hosted runners only
- [x] Confirm visibility really is public (the last check said PRIVATE) and the repo has no `RUNNER` variable →
  **WP-34**
- [x] Commit the Apache-2.0 switch and the hosted-runner workflows → **WP-34**
- [x] Get CI green: SAST + SCA, Container image and Desktop shell have not passed yet → **WP-34**
- [ ] Review the Dependabot PRs (TypeScript 7, Node 26, setup-go 7.1.0) → **WP-34**
- [x] Set up branch protection and required checks once CI is green → **WP-34**
