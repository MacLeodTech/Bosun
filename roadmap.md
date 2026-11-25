# Roadmap

The plan for Bosun: a free, Rust-based replacement for Burp Suite Professional and OWASP ZAP, for
homelabbers, hobbyists and individual security testers. This file holds all planned work. The implementation
strategy (phases, and work packages WP-01 to WP-86) sets the order; the milestone checklists list the features.
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

Legend: `[x]` done, `[ ]` to do, `[~]` partly done. Finished work moves to `docs/releases.md`.

---

## Where we are (updated 2026-11-25): resume here

- **Finished work** (the work packages, milestone items and what each phase delivered) is in `docs/releases.md`.
  This file lists only what is still to do.
- **Code:** Phases 0, 1 and 2 are merged to `main` (PR #5, then PR #11). That is M0 and M1, the hardening packages
  WP-01 to WP-09, the test harness (WP-36) and the foundation packages WP-10 to WP-17, WP-35 and WP-37. The Dependabot
  updates open at the time (PRs #6 to #10) are merged too. `bosun-desktop` still needs the platform webview libraries
  to build, so CI builds it on Linux only.
- **Repo:** `MacLeodTech/Bosun` is **public**. `main` has branch protection with required status checks. CI runs on
  GitHub-hosted runners only (`ubuntu-latest`, plus `windows-latest` for the test job; the macOS test job is paused, see Housekeeping); never the homelab self-hosted
  pools for this repo, and no `RUNNER` variable. Every PR so far has gone in as one branch per phase.
- **Gates:** the Phase 1 and Phase 2 security reviews are done. The Phase 2 review found nothing to fix; its one note
  (an imported project's scope can carry `allow_private` rules) is by design and in `docs/threat-model.md`.
- **Open follow-ups from Phase 2:** the footprint baselines in `footprint-budgets.json` (idle 17.0 MB, image 40.0 MB)
  came from a dev machine. Compare them with the first numbers the CI `footprint` job prints on GitHub's runners and
  adjust. Consider a Dependabot group for `github/codeql-action/*`, because `init`, `analyze` and `upload-sarif`
  must be the same version and Dependabot opens them as three PRs.
- **Merged to `main` (2026-11-25):** PR #22 (it combined #18 to #21; the fix in #17 went in before it) brought WP-40
  (`bosun-http`), the first slice of WP-41 (the Repeater), the branding (icons, logo, banner, `icon.ico` for Windows,
  `scripts/bosun.sh`), `docs/competitive-analysis.md` and WP-75 to WP-86. PR #23 brought the Rust side of WP-42
  (`bosun-codec`, `/decoder/*`, `/comparer/diff`, the `codec` fuzz target). The desktop app builds on Linux and opens
  on Windows; the sign-in logo, the Repeater page and first-run setup in the Windows window have not been checked
  by eye.
- **UI restructure merged (PR #25, 2026-11-25):** the Windows session's `ui-phase0` work is on `main`. `web/` is free
  again. The plan and what was built are in `docs/ui-ux-upgrade-plan.md`. It is a dockable workspace (own dock
  engine, saved layouts, browser pop-out windows), a strict type scale and colour tokens, a shortcut map and help
  overlay, a command registry and palette, context menus, drag and drop, multi-select, a filter bar, a shared
  message viewer (tokeniser, pretty-print, windowed code view, diff) and an accessibility audit in the e2e suite.
  **To add a tool page:** add its id to `web/src/lib/panelids.ts`, an entry in `web/src/lib/panels.ts`, and register
  its commands with `commands.register([...])` (see `builtin.ts`). Do not add a page to `App.svelte`.
  Items left out of PR #25 are under "UI follow-ups" below.
- **In flight:** nothing.
- **Next, in order** (see the phase plan below):
  1. Finish WP-41 (the Repeater page's WebSocket mode; the CLI one needs WP-26). Small WP-42 leftovers: MD5 and SHA-1 (new
     dependencies), compression encoders, and `bosun decode` (with WP-26); "Send to Decoder or Comparer" is in WP-43.
  2. **Phase 3, track A (M2):** WP-44, then WP-43 and WP-45, then WP-77 (copy as curl, HAR export; small,
     used every day). WP-38 and WP-39 are the M1 follow-ups.
  3. **Phase 3, tracks B to D:** server mode and the CLI (WP-23 to WP-26), the desktop shell (WP-18 to WP-22) and
     release work (WP-69, WP-70, WP-31). These can run in parallel sessions on separate branches. Windows desktop
     is built with Tauri for now; WP-18 (WinUI 3) is still planned.
  4. **Owner tasks before v0.2:** look up the pending BOSUN Class 9 filing; an Apple Developer account.
  5. **After v0.2:** Phase 4 (Intruder, Sequencer, WP-75, WP-76, WP-79), then Phase 5 and on as in the phase plan.
     Order within a phase is by value: pick the package that unblocks the most others (WP-49 unblocks the scanner;
     WP-47 unblocks WP-59 and WP-81).
- **UI follow-ups (from PR #25; owner: the Linux session unless noted):**
  1. **Server-side filter (WP-75, Rust).** The History filter line (`web/src/lib/query.ts`: `host:` `method:` `status:`
     `scope:` `-ext:` and free text, quoted words, comma lists) is parsed in the browser and mapped onto the
     parameters `/flows` already takes (`text`, `host`, `methods`, `status_min`, `status_max`, `in_scope_only`,
     `hide_ext`). Move the grammar into Rust behind an endpoint (store, API, client, `openapi.json`, a fuzz target),
     add the terms the UI cannot do (headers, body text, tags, source, size, time, and/or/not), and keep the current
     syntax valid. When it lands, the UI swaps `parseQuery` for a call and keeps the chips.
  2. **Recorder drops requests under a burst.** About 7,000 requests a second through the proxy were stored at only
     31 to 34 per cent; at about 1,200 a second all 100,000 were stored (found while testing the UI at 100,000
     rows; the list shows exactly what the server returns). Reproduce with a load generator, find where they are
     dropped (a bounded channel, a write queue, a batch size), and either fix it or count and report the drops.
     Add a test at a fixed rate.
  3. **Scanner and Intruder panels** when WP-47 and WP-49 land: reuse the shared viewer (`MessageView`, `CodeView`,
     `DiffView`). The Decoder and Comparer panels are on `main` (PR #26).
  4. **Tag and note row actions** in History (WP-43), if the API supports them; the row context menu and command
     registry are ready for them.
  5. **axe-core scan (WP-73)** with `@axe-core/playwright`: needs the owner's approval for the new dependency
     (pinned, `npm audit` in CI). Until then the e2e suite has an in-page audit.
  6. **Screen-reader pass** (NVDA, VoiceOver or Orca) on the dock, tabs, menus and table: needs a person.
  7. **Desktop pop-out and shortcuts.** Pop-out windows work in the browser only; the page cannot tell it is in the
     desktop shell. `Alt+1..9` and `Ctrl+Alt+I` replace `Ctrl+1..9` and `Ctrl+Shift+I`, which browsers reserve.
- **Decisions waiting for the owner:** WP-78 (WireGuard or per-OS local capture), WP-83 (how far SQL injection
  exploitation goes) and WP-86 (AI assistance: scope and cost). Also whether to keep a separate WinUI 3 app (WP-18)
  now that the Tauri build works on Windows.
- **Decided (2026-11-23):** the product keeps the name Bosun. Published artefacts use distinct names: the crates.io
  crate is `bosun-dast` (the installed binary stays `bosun`), and any npm package goes under the `@macleodtech` scope.
  Windows code signing is deferred; unsigned builds ship until then. The name check found a medium risk: a pending
  Class 9 filing for BOSUN (Bosun Technology Limited, Jan 2025, serial 98940487) to look up on TSDR before v0.2.

---

## Implementation strategy

All remaining work, from the 2026-11-23 codebase review and from the milestones, is in **work packages WP-01 to
WP-86**. The phase plan below sets the order. Work package numbers are stable identifiers, not the order. The
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

**Phases 0 to 2: done** (repository and CI, hardening, foundation). See `docs/releases.md` for what each delivered.

**Phase 3: manual tools and the front ends. Release v0.2, the first public preview.**
- Track A, M2 tools: WP-41 (finish), then WP-44, then WP-43 and WP-45. Also WP-38 and WP-39, the M1
  follow-ups.
- Track B, server and CLI: WP-23, then WP-24; WP-25; WP-26.
- Track C, desktop: WP-20 and WP-21, then WP-18 and WP-19, then WP-22.
- Track D, release: WP-69, WP-70 (the first pages), WP-31.
- Quick win from the gap analysis: WP-77 (copy as curl, HAR export) once WP-43 lands.
- Owner: look up the pending BOSUN Class 9 filing before v0.2; an Apple Developer account. Windows signing is deferred.
- Gate: v0.2 for Windows, macOS and Linux; Docker and Podman images; the CLI; security review 3.

**Phase 4: Intruder, Sequencer and performance. Release v0.3.**
- WP-47, WP-48, WP-27, WP-28, WP-32, WP-33. WP-46 is optional.
- From the gap analysis: WP-75 (history query language), WP-76 (Map Local, Map Remote, throttling), WP-79 (gRPC,
  Protobuf, GraphQL).
- Gate: footprint budgets green on storage v2; the WP-27 and WP-28 benchmarks recorded here.

**Phase 5: passive scanning and reports. Release v0.4.**
- WP-49, then WP-50 and WP-51; WP-29; WP-73, then WP-80.

**Phase 6: active scanning. Release v0.5.**
- WP-52, WP-68, WP-53, then WP-54 (with the testbed), then WP-55 and WP-56, then WP-57; WP-72.
- From the gap analysis: WP-81 (content and parameter discovery), WP-82 (fingerprints and known-vulnerable
  components).

**Phase 7: OAST and imports. Release v0.6.**
- WP-58, then WP-59; WP-60; WP-85.

**Phase 8: plugins and advanced checks. Release v0.7.**
- WP-61, then WP-62; WP-63; WP-83 and WP-84.

**Phase 9: teams, more front ends and 1.0.**
- WP-30, then WP-64; WP-65, WP-66, WP-67, WP-71, WP-74; WP-78 and WP-86.
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
- When a package lands, move its details (with a short "Done" note) and its ticked milestone items to
  `docs/releases.md`, and remove its row from the index above. Packages still listed here are open.

### Index (in phase order)

Open work packages only. Finished ones (WP-01 to WP-17, WP-34 to WP-37, WP-40) are in `docs/releases.md`; their numbers stay
valid in the "Depends on" column.

| Status | WP | Title | Phase | Size | Depends on |
|---|---|---|---|---|---|
| [ ] | WP-41 | Repeater | 3 | L | WP-40, WP-12, WP-13, WP-35 |
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
| [ ] | WP-77 | Export: copy as curl, HAR export, code snippets | 3 | S | WP-43 |
| [ ] | WP-47 | Intruder | 4 | L | WP-40, WP-41 |
| [ ] | WP-48 | Sequencer | 4 | M | WP-40 |
| [ ] | WP-27 | Storage layout v2 and benchmarks | 4 | L | WP-11, WP-35 |
| [ ] | WP-28 | Proxy hot path | 4 | M | WP-05 |
| [ ] | WP-32 | CA management | 4 | M | |
| [ ] | WP-33 | Protocol gaps | 4 | M | WP-20 |
| [ ] | WP-46 | Optional `legacy-tls` backend | 4 | M | WP-40 |
| [ ] | WP-75 | History query language and saved filters | 4 | M | WP-43 |
| [ ] | WP-76 | Map Local, Map Remote and throttling | 4 | M | WP-10, WP-38 |
| [ ] | WP-79 | gRPC, Protobuf and GraphQL-aware views and rules | 4 | M | WP-33, WP-44 |
| [ ] | WP-49 | Passive scanner, findings and the issues view | 5 | L | WP-05, WP-35 |
| [ ] | WP-50 | `bosun-checks`: the check language and passive checks | 5 | L | WP-49 |
| [ ] | WP-51 | `bosun-report` | 5 | M | WP-49 |
| [ ] | WP-29 | Encrypted projects | 5 | L | WP-20, WP-27 |
| [ ] | WP-73 | Accessibility and keyboard shortcuts | 5 | M | WP-44 |
| [ ] | WP-80 | Command palette and one shared message viewer | 5 | M | WP-44, WP-73 |
| [ ] | WP-52 | `bosun-crawl`: the HTTP spider | 6 | M | WP-10, WP-40 |
| [ ] | WP-68 | Encrypted credential vault | 6 | M | WP-20, WP-29 |
| [ ] | WP-53 | Browser crawler and the `BrowserEngine` trait | 6 | L | WP-01, WP-21, WP-24 |
| [ ] | WP-54 | Active scan engine and the testbed | 6 | L | WP-40, WP-49, WP-50 |
| [ ] | WP-55 | Core active checks | 6 | L | WP-54 |
| [ ] | WP-56 | `bosun-auth` and the authorisation matrix | 6 | L | WP-54, WP-68 |
| [ ] | WP-57 | `bosun scan` for CI | 6 | M | WP-25, WP-26, WP-51, WP-54 |
| [ ] | WP-72 | Scanner benchmarks against ZAP | 6 | M | WP-55 |
| [ ] | WP-81 | Content and parameter discovery | 6 | M | WP-47, WP-52 |
| [ ] | WP-82 | Technology fingerprint and known-vulnerable components | 6 | M | WP-49, WP-69 |
| [ ] | WP-58 | Lookout, the OAST server | 7 | L | WP-23, WP-24 |
| [ ] | WP-59 | OAST client, payloads and checks | 7 | M | WP-58, WP-41, WP-47, WP-54 |
| [ ] | WP-60 | Imports (OpenAPI, GraphQL, Postman, HAR, URL lists, Burp XML) | 7 | M | WP-16 |
| [ ] | WP-85 | Issue tracker export | 7 | S | WP-49, WP-51 |
| [ ] | WP-61 | Plugin host | 8 | L | WP-05, WP-10, WP-69 |
| [ ] | WP-62 | Plugin SDK and hooks | 8 | L | WP-61 |
| [ ] | WP-63 | Advanced checks | 8 | L | WP-40, WP-53, WP-54 |
| [ ] | WP-83 | SQL injection exploitation helper (opt-in) | 8 | L | WP-55 |
| [ ] | WP-84 | Scheduled scans and scan diff | 8 | M | WP-51, WP-57 |
| [ ] | WP-30 | Multi-user server semantics | 9 | L | WP-23 |
| [ ] | WP-64 | Teams: OIDC, per-project permissions, collaboration | 9 | L | WP-30, WP-16, WP-17 |
| [ ] | WP-65 | In-container browser over CDP screencast | 9 | L | WP-53, WP-24 |
| [ ] | WP-66 | Alternative browser engines | 9 | M | WP-53 |
| [ ] | WP-67 | `bosun-tui` | 9 | L | WP-14 |
| [ ] | WP-71 | Migration guide from Burp and ZAP | 9 | S | WP-60 |
| [ ] | WP-74 | HTTP/3 | 9 | L | WP-40 |
| [ ] | WP-78 | Proxy modes: reverse proxy, WireGuard or local capture, TLS key log | 9 | L | WP-31, WP-32 |
| [ ] | WP-86 | Optional AI assistance | 9 | L | WP-49, WP-62 |

---

### Work package details

Open packages only; finished ones are in `docs/releases.md`.

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

### WP-38 and WP-39: M1 follow-ups

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

### WP-41 to WP-46: M2 manual tools

#### WP-41 Repeater · Phase 3 · L

- **Do:**
  - Tabs, saved in the project (a migration, WP-35), with per-tab history and back/forward.
  - HTTP/1.1, HTTP/2 and WebSocket sends through WP-40.
  - A response diff with the previous send.
  - Send groups: in order, in parallel, and the single-packet attack for race conditions.
  - Endpoints in OpenAPI, a `bosun-client` method and `bosun repeater send` in the CLI (WP-26).
- **Done when:** API and Playwright tests cover tabs, history, diff and send groups; the CLI command sends a raw
  file.
- **Progress (2026-11-25):** the first slice is on `main`: connection reuse, HTTP/2 multiplexing, `/repeater/send` and
  `/repeater/settings`, the `bosun-client` methods and the Repeater page (history, diff, send groups, the out-of-scope
  toggle) and tabs saved in the project (`/repeater/tabs`, kept in the project's settings table rather than a new
  table; responses are not saved). WebSocket sends are in the API (`/repeater/ws`: raw handshake, frames with any opcode, flags and mask, a listen window; recorded as a flow with messages). **Still open:** the WebSocket mode of the Repeater page, and `bosun repeater send` (needs the client
  commands of WP-26).

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
- **Progress (2026-11-25, PR #25):** the read-only viewer is done and shared (`MessageView`, `CodeView`, `DiffView`:
  HTTP, JSON, XML and HTML tokeniser, pretty-print as text, windowed rendering of large bodies, diff). Still open:
  the editable CodeMirror editor and the hex editor.

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
- **Progress (2026-11-25, PR #25):** shortcut map and help overlay, visible focus, ARIA roles, a CI contrast check of
  every text token in both themes, an in-page accessibility audit and a keyboard-only test in the e2e suite. Still
  open: the axe-core scan (needs approval for the dependency) and a screen-reader pass.

#### WP-74 HTTP/3 · Phase 9 · L

- **Do:** HTTP/3 (QUIC) for the client side (the browser to the proxy) and upstream, on a rustls-based QUIC stack,
  with recording and interception like HTTP/2.
- **Done when:** a browser using HTTP/3 through the proxy is recorded, and an upstream HTTP/3-only test server is
  reachable.


### WP-75 to WP-86: gaps found against other tools

From `docs/competitive-analysis.md` (2026-11-25), which compares Bosun with Burp, Caido, mitmproxy, Proxyman, ZAP and
others. Every package here follows the platform contracts above. Packages that decode or parse untrusted input get a
fuzz target; ones that send traffic go through the gate.

#### WP-75 History query language and saved filters · Phase 4 · M

- **Do:**
  - A small typed filter language over history (host, method, status, headers, body text, tags, source, size, time,
    with and/or/not), parsed in Rust behind an endpoint so the UI, CLI and plugins share it.
  - Saved filters per project (a migration), a query bar with autocomplete and a history of past queries.
  - The same language drives Logger and Intruder results (WP-43, WP-47).
  - A fuzz target for the parser; queries run against the store with a time and row limit, never string-built SQL.
- **Done when:** the grammar is documented; unit and property tests cover it; a Playwright test saves and re-runs a filter.
- **Progress (2026-11-25):** the UI half exists in `web/src/lib/query.ts` (a client-side parser mapped onto the `/flows`
  parameters, a filter bar with chips, the default hide-static-files query). The Rust grammar, endpoint, saved filters,
  fuzz target and the extra terms are still to do; see "UI follow-ups" at the top.

#### WP-76 Map Local, Map Remote and throttling · Phase 4 · M

- **Do:**
  - Rules that answer a matching request from a local file (Map Local) or send it to another host (Map Remote),
    next to match-and-replace, with an audit entry on change.
  - Throttle and latency simulation per host or rule.
  - Map Remote's new target goes through `Gate::check`; Map Local reads only from a directory the user picked, with
    no path traversal (tested).
- **Done when:** tests cover each rule type, the path-traversal case, and an out-of-scope Map Remote target being refused.

#### WP-77 Export: copy as curl, HAR export, code snippets · Phase 3 · S

- **Do:** copy a request as `curl` (quoted safely for POSIX shells and PowerShell), export selected flows as HAR, and
  generate snippets for a few languages. Secrets (cookies, authorization headers) are redacted unless the user ticks
  a box. HAR import is in WP-60.
- **Done when:** golden tests for each format, including hostile header values; once WP-60 lands, an exported HAR file imports back unchanged.

#### WP-78 Proxy modes: reverse proxy, WireGuard or local capture, TLS key log · Phase 9 · L

- **Do:**
  - Reverse-proxy mode: listen in front of one upstream and rewrite Host.
  - A TLS key log file option (`SSLKEYLOGFILE` format) so Wireshark can decrypt captures; off by default, with a
    warning because the file exposes traffic secrets.
  - WireGuard or local capture mode and guided setup for phones and emulators, on top of WP-31's transparent proxying.
  - Decision first: ask the owner whether WireGuard (a user-space implementation) or per-OS local capture is wanted.
  - The first pull request may be reverse mode and the key log alone; they can be pulled into an earlier phase.
- **Done when:** a test client through each mode is recorded and the scope gate still applies; the key log decrypts a
  captured session in a test; the threat model covers the new listener and the key file.

#### WP-79 gRPC, Protobuf and GraphQL-aware views and rules · Phase 4 · M

- **Do:**
  - Decode gRPC and Protobuf (with a user-supplied schema, or schema-less field numbers), and edit and re-send them.
  - GraphQL-aware matching and editing by operation name; query and variables shown separately.
  - Decoders respect WP-06's size caps and have fuzz targets.
- **Done when:** a recorded gRPC call shows decoded fields; a rule fires on a GraphQL operation name.

#### WP-80 Command palette and one shared message viewer · Phase 5 · M

- **Do:**
  - A keyboard command palette (go to a page, open a flow, run a saved filter, toggle settings), with keyboard
    paths for every item (builds on WP-73).
  - Check that History, Repeater, Intruder results and Findings all use the same message viewer and editor (WP-44),
    and that tabs can be reordered or grouped.
- **Done when:** a Playwright test drives the palette and the viewer is shared by each tool.
- **Progress (2026-11-25, PR #25):** the palette (fuzzy search, recent commands, keyboard paths), the command registry,
  tabs that can be reordered, grouped and moved by drag and drop, and the shared viewer are built, with Playwright
  tests. Still open: Repeater, Intruder results and Findings using the shared viewer when those panels land.

#### WP-81 Content and parameter discovery · Phase 6 · M

- **Do:**
  - A tool for forced browsing of paths, files and parameters from wordlists, with recursion, soft-404 detection and
    response clustering, reusing Intruder's engine (WP-47) and the crawler's queue (WP-52).
  - Bounded by scope and the gate's per-host rate limit; a stop switch.
- **Done when:** a run against the testbed finds planted hidden paths and parameters and ignores soft-404s.

#### WP-82 Technology fingerprint and known-vulnerable components · Phase 6 · M

- **Do:**
  - Passive fingerprinting of servers, frameworks and libraries from headers, cookies and script URLs (a finding
    type under WP-49).
  - Match detected versions to an offline advisory feed (OSV or similar), signed and updated like the check feeds
    (WP-69), with no lookups to third parties by default.
- **Done when:** fixtures with known versions produce the expected findings; the feed update verifies its signature.

#### WP-83 SQL injection exploitation helper (opt-in) · Phase 8 · L

- **Do:**
  - Beyond detection (WP-55): confirm the injection type, identify the database, and apply tamper transforms for
    filters. Data extraction is limited to what the user confirms for each target.
  - Marked destructive-class: off by default, a confirmation per target, an audit entry, the gate and rate limit.
  - Ask the owner how far extraction should go before starting.
- **Done when:** tests against the testbed's vulnerable endpoints; an unconfirmed target is refused.

#### WP-84 Scheduled scans and scan diff · Phase 8 · M

- **Do:** recurring scans from a project or saved scan config (server mode), a comparison of two runs (new, fixed and
  unchanged findings), and notifications only to destinations the user configured.
- **Done when:** a scheduled run produces a diff in a test; the schedule survives a restart.

#### WP-85 Issue tracker export · Phase 7 · S

- **Do:** push a finding to GitHub issues, Jira or Linear. Credentials go in the vault (WP-68); the destination host
  is on a user-set allow list; secrets in evidence are redacted by default.
- **Done when:** tests against a mock tracker; a host off the allow list is refused.

#### WP-86 Optional AI assistance · Phase 9 · L

- **Do:**
  - Off by default. Explain a response, suggest test ideas, draft a check from a finding. The user supplies a local
    or remote model endpoint; nothing is sent anywhere until they configure one, and what is sent is shown first.
  - Model output is untrusted input: it is never executed or rendered as HTML, and any request it proposes goes
    through the gate and needs the user's approval. No agent mode without a separate decision.
  - Ask the owner about scope and cost before starting.
- **Done when:** the threat model covers it; tests show that nothing leaves without configuration and that proposed
  requests are gated.

---

## Milestone checklists

The features each milestone delivers. Every open item names the work package (or phase gate) that delivers it;
the phase plan above sets the order. Tick an item here when its package lands.

### M1 Proxy: done except these items

- [ ] Bundle Chrome for Testing with the desktop installers (download, verify by SHA-256, keep it updated): **WP-21**
- [ ] Optional TOTP second factor for UI accounts → **WP-39**
- [ ] History: column chooser, sorting, colour highlights, bulk tag/delete, "send to" menu (wired up in M2) → **WP-43**
- [ ] Response interception rules (intercept only when the response matches a condition) → **WP-38**
- [ ] Proxy listener management in the UI (several listeners, per-listener options) and a live-config reload → **WP-38**
- [ ] Request/response size and timing stats in history → **WP-38**
- [ ] HTTP/3 (QUIC) for the client side and upstream → **WP-74**
- [ ] Health endpoint and a `bosun healthcheck` subcommand for container health checks (distroless has no curl):
  **WP-23**

### M2 Manual tools

- [ ] Optional `legacy-tls` backend (OpenSSL, opt-in feature) for very old targets, upstream only → **WP-46**
- [ ] **Repeater**: tabs, per-tab history (back/forward), h1/h2/WebSocket, raw bytes, "update Content-Length",
  follow redirects (optional), response diff with the previous send, send groups (in order or in parallel,
  single-packet attack for race conditions) → **WP-41**
- [ ] **Organizer**: save requests with notes and status for follow-up → **WP-43**
- [ ] **Logger**: every request from every tool (not just the proxy), with filters → **WP-43**
- [ ] "Send to Repeater, Intruder, Comparer or Decoder" everywhere a message is shown → **WP-43**
- [ ] Request editor with syntax highlighting (CodeMirror 6), a hex editor, and pretty-printing of JSON, XML and
  HTML (as text, never rendered) → **WP-44**
- [ ] Engagement helpers: generate a CSRF PoC, find comments and scripts, find references, analyse a target
  (parameters and endpoints) → **WP-45**
- [ ] The scope gate enforced for every tool request (refuse out-of-scope, a per-host rate limit, the stop switch),
  with pinned addresses: **WP-10** must land first
- [ ] Typed history filters with saved queries and a query bar → **WP-75**
- [ ] Map Local, Map Remote and throttling → **WP-76**
- [ ] Copy as curl, HAR export and code snippets → **WP-77**
- [ ] gRPC, Protobuf and GraphQL-aware views and rules → **WP-79**
- [ ] A command palette, and one message viewer shared by every tool → **WP-80**

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
- [ ] Technology fingerprints and known-vulnerable component findings from an offline advisory feed → **WP-82**

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
- [ ] Content and parameter discovery (forced browsing) → **WP-81**
- [ ] Scheduled scans and a diff between two runs → **WP-84**

### M6 OAST server and API imports

- [ ] **Lookout**: a separate, self-hostable OAST server binary and image with DNS, HTTP/HTTPS (ACME) and SMTP
  listeners, per-payload correlation IDs, a polling API with per-client keys, automatic expiry of interactions,
  and no access to project data → **WP-58**
- [ ] Client side: Lookout or interactsh-compatible servers, and an OAST payload generator in Repeater and Intruder →
  **WP-59**
- [ ] OAST checks: blind SQL injection, SSRF, XXE, RCE, blind XSS, DNS rebinding probes → **WP-59**
- [ ] Imports: OpenAPI/Swagger 2 and 3, GraphQL introspection, Postman collections, HAR, plain URL lists; and
  Burp XML exports where the format allows → **WP-60**
- [ ] Push findings to GitHub, Jira or Linear → **WP-85**

### M7 Plugins and advanced checks

- [ ] `bosun-plugin`: a wasmtime component-model host, a WIT interface, fuel and memory caps, no WASI filesystem or
  network, all I/O through host calls that go through the scope gate → **WP-61**
- [ ] Capability manifests that the user approves; minisign-signed plugins and check/template feeds → **WP-61**
- [ ] A Rust guest SDK, example plugins, docs; later SDKs for other languages that compile to WASM → **WP-62**
- [ ] Plugin hooks: passive and active checks, message editors and views, payload generators and processors,
  context menu actions, UI panels in a sandboxed iframe → **WP-62**
- [ ] Advanced checks: request smuggling (CL.TE, TE.CL, H2 downgrade, client-side desync), web cache poisoning and
  deception, DOM XSS through browser instrumentation, race conditions, OAuth/OIDC misconfiguration → **WP-63**
- [ ] Opt-in SQL injection exploitation helper → **WP-83**

### M8 Teams, containers, engines and the TUI

- [ ] Multi-user hardening: OIDC sign-in, per-project permissions, collaboration (shared projects, live updates);
  builds on **WP-30**; delivered by **WP-64**
- [ ] An in-container browser streamed into the web UI over CDP screencast (for container mode) → **WP-65**
- [ ] Lightpanda as an opt-in fast crawler engine that falls back to Chromium when a page breaks → **WP-66**
- [ ] Track Servo as an embeddable pure-Rust engine → **WP-66**
- [ ] `bosun-tui`: a ratatui client over the same API (uses `bosun-client`, **WP-14**); delivered by **WP-67**
- [ ] Encrypted projects (in-app encryption, not SQLCipher: **WP-29**) and an encrypted credential vault for auth
  configs; delivered by **WP-68**
- [ ] Reverse-proxy mode, WireGuard or local capture, and a TLS key log file → **WP-78**
- [ ] Optional, off-by-default AI assistance → **WP-86**

### Release and packaging (from the first public release onwards)

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

- [ ] Throughput and latency benchmarks (criterion) and tracked image sizes feed the footprint budgets in CI → **WP-27**, **WP-28**
- [ ] `cargo-fuzz` targets: the HTTP parser, the WebSocket frame parser, decoders and decompression, the scope
  rule compiler, the YAML check loader, the plugin host boundary → **WP-36**, then each package that adds a parser
- [ ] Scanner benchmarks against OWASP Juice Shop, DVWA, WebGoat, VAmPI/crAPI and the OWASP Benchmark, comparing
  detection rate, false positives, scan time and peak memory with ZAP on the same targets → **WP-72**
- [ ] A weekly scheduled CI run (already configured) and the SBOM published with each release → **WP-69**
- [ ] A security review before each milestone ships: threat model updated, new endpoints checked for role
  checks and audit entries → every phase gate
- [ ] Accessibility and keyboard shortcuts across the UI (Burp-compatible where sensible) → **WP-73**

### Housekeeping

- [ ] Re-enable the macOS test job (`macos-latest` in the `portable` matrix of `ci.yml`), paused 2026-11-23 because
  GitHub's macOS runners queue or cancel often and made unrelated PRs fail. Do it before the v0.2 gate, which needs
  macOS builds → **WP-09**, **WP-69**
