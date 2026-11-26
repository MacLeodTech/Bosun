# Threat model

Bosun is an intercepting proxy and DAST toolkit. Its whole job is to process hostile input: every response
from a target, every page the user browses through the proxy, and later every scan result is attacker-controlled.
This document says what is protected, from whom, and how. Code comments refer back to it.

## What is being protected

1. **The CA private key.** Whoever holds it can impersonate any site to any browser that trusts the CA.
2. **The user's session with the UI/API.** It controls the proxy, intercepted traffic, scope and (later) active
   scans, so taking it over turns Bosun into an attack tool pointed wherever the attacker likes.
3. **Recorded traffic.** Project files hold credentials, cookies and tokens for the systems being tested.
4. **Third parties.** Active tools must only send traffic to targets the user put in scope.
5. **The machine Bosun runs on.** No path from traffic or project files to code execution.

## Trust boundaries

```
 target sites (hostile) ──► proxy ──► recorder ──► project file (.bosun)
        ▲                     │                        │
        │                 scope gate ◄── tools/scanner  │
        │                     │                        ▼
 proxied browser (sees hostile pages) ───────►  UI/API  ◄── signed-in user (web UI, desktop, CLI, scripts)
                                                 ▲
                                    other hosts on the network (container mode)
```

- **Target content → everything.** Responses are parsed by the proxy, stored, and shown in the UI. They are
  never trusted, never rendered in the UI's origin, and never executed.
- **The proxied browser → the UI/API.** The same browser the user browses hostile sites with is often the one
  that shows the UI. A hostile page must not be able to talk to the API with the user's cookie.
- **The network → the proxy and UI.** By default both listen on loopback only.
- **Project files → the engine.** A `.bosun` file may come from someone else.

## Threats by STRIDE category

### Spoofing

- *A web page talks to the API as the user (CSRF, cross-site WebSocket hijacking).* Cookies are `SameSite=Strict`
  and `HttpOnly`; every state-changing request with a cookie must carry the per-session CSRF token in a header,
  which a cross-origin page cannot set without a CORS preflight the API never answers. The Origin header must
  match the UI's own origin exactly (scheme, host and port) or an allowlisted origin, on every request including
  the WebSocket upgrade; `Sec-Fetch-Site: cross-site` is refused. There is no CORS at all.
- *Non-interactive setup (containers).* `BOSUN_ADMIN_USER` with `BOSUN_ADMIN_PASSWORD_FILE` (and optionally
  `BOSUN_BOOTSTRAP_TOKEN_FILE`, whose content becomes a full-scope API token) create the first admin at start-up,
  only while there are no users, and each is audited (`setup`, `token.create`). Secrets come from files, never from
  environment values, so they stay out of `docker inspect` and process listings; the same holds for
  `password_file` on `proxy.auth` and the upstream proxy. Whoever can write those files or set that environment
  controls the first admin, which is the same trust as owning the container. `/healthz` is the only unauthenticated
  route besides `/status`: it returns `ok` and nothing else. The optional `/metrics` listener
  (`metrics_listen`, off by default) has no authentication and shows only counters; bind it to an internal interface.
- *DNS rebinding.* A hostile page rebinds its own name to 127.0.0.1 and becomes "same origin" with the UI. The
  Host header must be a known name (loopback names plus `api.hosts`); anything else gets 421.
- *Guessing passwords.* argon2id hashes, a 12-character minimum, the same work for unknown users as for wrong
  passwords. Attempts are counted *before* hashing. Each (address, username) pair gets three free tries, then
  waits 1 s, 2 s, 4 s and so on up to 60 s; one address gets 30 attempts per 15 minutes in total. Nobody is
  locked out by someone else's guesses, because the delay is per pair. At most `api.max_password_hashes` (default
  2) hashes run at once, and sign-in, `/setup` and password change share that cap. A distributed guesser (many
  addresses against one user) is slowed only by that cap, so use a long password and put the UI behind your
  own front door if it is exposed.
- *Stolen sessions and tokens.* Sessions end after `api.session_hours` idle (default 12) and at most
  `api.session_max_hours` after sign-in (default 168), however active; the idle expiry is only rewritten when it
  moves by over a minute. A password change ends the user's sessions and, by default, their API tokens, so a token
  made with a stolen password does not survive the reset. API tokens may expire (`expires_days`) and may be
  `read` scoped: such a token is refused (403) on anything but GET and HEAD. Users can list and end their own
  sessions; admins can list and end anyone's sessions and tokens and change roles (a role change ends the user's
  sessions; the last admin cannot be demoted).
- *A stolen or guessed password (TOTP second factor).* An account can turn on an RFC 6238 second factor (HMAC-SHA-1,
  6 digits, 30 s). Enrolment is two steps (a secret, then a first valid code), so a half-finished setup never locks
  anyone out. With it on, `POST /auth/login` only checks the password and returns a five-minute `pending` token
  bound to the client address; no session or cookie exists until `POST /auth/login/totp` receives the token and a
  code. A pending sign-in allows five code tries. Codes are compared in constant time against the previous, current
  and next step; the newest step used is stored in the account database and an equal or older step is refused, so
  a code works once (the update is atomic, so two simultaneous requests cannot both win). Wrong codes use the
  password limiter (three free tries per address and account, then growing delays; per-address caps) and also count
  towards ten failures per account across all addresses in 15 minutes, which locks the second factor of that
  account (and only that) for the rest of the window: guessing a six-digit code from many addresses is stopped at
  about ten tries per window. Ten recovery codes (80 bits each) are shown once, stored as SHA-256 hashes and work once; using one is audited.
  Turning the factor off, or making new recovery codes, needs a valid code or recovery code (so a stolen session
  cannot remove it). An admin can reset a user's factor (`DELETE /users/{id}/totp`, or `bosun user totp-reset`; the
  user's sessions end) for a lost device, and can require a second factor of every password account: until a
  session's account has one, the API answers 403 for everything except the enrolment pages. Limits worth knowing:
  single sign-on sessions are not asked for a code (the identity provider is the second factor) and are not subject
  to the requirement; API tokens made before the requirement keep working (they are not ambient credentials, and
  making one needs a session); the desktop login ticket skips the code, as it is a local single-use exchange.
- *Spoofed client addresses.* Behind a reverse proxy every client shares the proxy's address. Set
  `api.trusted_proxies` to the proxy's network; only then are `X-Forwarded-For` (the rightmost entry that is not a
  trusted proxy) and `X-Forwarded-Proto` believed, and used for limits, audit entries and the `Secure` cookie.
  From any other peer the headers are ignored.
- *The first-run setup.* No default account. The first admin is created with a random one-time code printed to
  the operator's terminal or container log; the browser link carries it in the URL fragment, which is never sent
  to the server or written to its logs.

- *Login tickets (the desktop app signing in).* An embedded engine (`bosun serve --embedded`) listens on loopback
  only and prints one single-use ticket on its stdout, which only the parent process reads. `POST /auth/ticket`
  exchanges it for an admin session: the ticket lives 60 seconds, is compared in constant time, is destroyed by
  the first attempt that matches (and by expiry), is refused from any non-loopback peer, and goes through the same
  per-address attempt limits as passwords. Both outcomes are audited. A page in the user's browser cannot use one: it
  never sees it, and the Origin and Host rules still apply to the request.

### Tampering

- *Traffic that reaches the UI through the proxy.* Requests the proxy would send to its own listeners are refused
  (the proxy knows the API's address), and the API refuses any connection whose source address belongs to one of
  the proxy's own outbound sockets (covers aliases such as other loopback addresses or the host's LAN address).
- *Compressed WebSocket messages from a target.* The proxy relays `permessage-deflate` frames untouched and inflates
  a copy only to record it. The copy is capped at the record limit (1 MiB per message), so a decompression bomb is
  cut and flagged truncated; corrupt data is stored as the raw compressed bytes, flagged. The extension header the
  server sends is read tolerantly, and the frame parser, inflater and header reader share the `ws_frames` fuzz target.
- *Upstream SNI override.* `proxy.upstream_sni` (restart-only, a config-file setting) sends a chosen server name to a
  target instead of its own. It changes only the TLS name; the request still goes through `Gate::check` for the
  original host, and with `verify_upstream_tls` the certificate is checked against the name sent.
- *Hostile HTML in the UI.* The UI's CSP forbids inline script and inline style and allows nothing but its own
  origin. Responses are shown as text; the "render" view is an iframe with an empty `sandbox` attribute (no
  scripts, opaque origin) whose `srcdoc` also inherits the UI's CSP. Syntax colour is drawn from a tokeniser's
  output as `<span>` elements, never as markup built from the body. The render frame is told the UI's colour scheme
  through one `<meta name="color-scheme">` that the UI writes (after the doctype, so the page's rendering mode
  does not change); the `sandbox` attribute and the CSP are untouched.
- *The message editor (CodeMirror 6).* CodeMirror writes its styles into a `<style>` element, which `style-src 'self'`
  blocks. In a shadow root it adopts a constructed stylesheet instead, which the policy does not govern, so the editor
  lives in one and the policy stays exactly as it was: no nonce, no `unsafe-inline`, and the e2e test checks the
  header. Target text is only the editor's document and span class names, never markup. Window shortcuts read the
  event's composed path, because inside a shadow root `event.target` is the host. Chromium's own editing can try to
  write an inline `style` attribute when typing replaces a selection; that is blocked (`style-src-attr`), and nothing
  depends on it.
- *Requests moved between tools.* Dragging requests, the palette, context menus and shortcuts all pass flow **ids**,
  never message bodies; a receiving tool fetches by id through the API, so the scope gate, role checks and audit
  still apply. A request sent to the Repeater travels through `sessionStorage` (as it already did) and is removed
  when read. Deleting from the History list is delayed by a five-second undo window, and the server is asked only
  when it passes; closing the page in that window leaves the requests stored.
- *Pop-out windows.* A pop-out is the same UI at `#/popout/<id>`, opened with `window.open` from the browser build. It is
  same-origin, so it uses the same session cookie, fetches its own CSRF token and opens its own event stream; it has no
  access the main window lacks. Windows talk over a same-origin `BroadcastChannel` and exchange only flow ids, panel
  names and window ids; every message is validated before use and anything else is dropped. Target content is never
  passed between windows. The desktop shell is unchanged: it exposes no IPC and may navigate only to the engine's
  origin, so it cannot open pop-outs (the UI reports that the window could not be opened).
- *Project files.* Opened with a bundled, current SQLite (`cargo deny` fails the build on SQLite advisories),
  with `trusted_schema` off, `cell_size_check` on and SQLite's defensive mode set. A file must carry exactly the
  schema this version creates: an extra trigger, view, table or index, or an altered column, is refused (a
  trigger would run the file author's SQL on our connection). Stored bodies are decompressed through a hard
  limit (128 MiB per body, 4 MiB per WebSocket message) and must match the size the file records, so a
  decompression bomb is refused as corruption. Importing someone else's project means copying rows into a new
  file, never working in the foreign file: `POST /projects/import` streams the upload (at most 2 GiB) into a private
  temporary file, opens it read-only with the checks above plus SQLite's quick check, and has SQLite write its live
  content into a fresh file (`VACUUM INTO`), so free pages, stale data and anything else hiding in the original do
  not come along. That file is then opened and upgraded like any other and only then given its name. A refused
  import leaves no file behind and writes an audit entry. A project name is 1 to 64 characters of letters, digits,
  spaces, dots, dashes and underscores (no path separators, no leading dot, no Windows device names), and names
  map to `<projects dir>/<name>.bosun`, so no request can name a file anywhere else. The import path has a fuzz
  target (`import_project`).
- *Switching projects.* Admin only, one operation at a time. The new project is opened and checked first, so a
  locked, damaged or hostile file changes nothing. Then the recorder, scope, rules and intercept settings change
  together (a request already in flight finishes into the project it began in), held intercept messages are
  dropped (nobody approved forwarding them in the new project), interception starts off, and every connected
  client gets `project_switched` with a new event epoch, so none of them keeps showing, or acting on, the old
  project's data. Settings saves wait for a switch in progress, so a setting is never saved to one project and applied
  to another. Exports and backups are consistent snapshots (`VACUUM INTO`) and are audited; they hold everything the
  project holds, credentials included, and are written owner-only.
- *A stale or replayed event position.* The stream names its epoch (a new one with each engine run and each project
  switch); a position from another epoch is answered with `reload`, never with events from the wrong project.
- *Two processes on one project.* `<project>.lock` is held exclusively while a project is open; a second open
  fails and names the process that holds it.

### Repudiation

- An append-only audit log (database triggers refuse UPDATE and DELETE) records sign-ins, account, token, scope,
  rule, kill-switch, role, session-revocation, login-ticket, second-factor (enrolment, enable, disable, recovery
  codes used or replaced, failed codes, the require-everyone policy, admin and CLI resets), project (create, open, close, rename, delete, export,
  backup, import and refused imports), proxy listener changes (`proxy.listener.add|update|remove`: address and
  options, never the password) and live proxy settings (`proxy.config.update`: the values that changed), and intercept changes (settings, response filter, drop, edited forward, forward-all),
  with the user and remote address. Admins can read it in the UI.

### Information disclosure

- *The CA key at rest.* Sealed with ChaCha20-Poly1305 under a 32-byte data key that lives apart from it:
  `BOSUN_DATA_KEY`, a mounted secret file, or `data.key` (0600). Files and directories are created 0600/0700, and
  the key file's permissions are checked on load.
  The desktop apps keep the data key in the OS keychain for new installs (`data_key_store = "keychain"`;
  Credential Manager, macOS Keychain, Secret Service), so copying the data directory alone no longer yields it.
  An existing `data.key` stays until `bosun key migrate --to keychain` moves it (the CA key is opened with the
  moved key before the file is overwritten and removed). A missing keychain entry is an error, never a silently
  generated new key, so the sealed CA is not orphaned. Anything running as the same OS user can still ask the
  keychain for the key; `doctor` reports where it lives. The real keychain is not exercised in CI (tests use an
  in-memory store).
- *The UI's certificate.* The interception CA never issues the UI's certificate, so nobody is pushed to trust it in
  an everyday browser. With `api.tls` the UI serves `api.tls_cert`/`api.tls_key` (re-read on change or SIGHUP) or a
  self-signed certificate of its own: not a CA, key sealed like the CA's. A reverse proxy is the recommended setup
  (`docs/ui-tls.md`); `doctor` warns about a network-facing UI without TLS.
- *File permissions on Windows.* On Linux and macOS data files are 0600 and directories 0700, and the key file's mode
  is checked on load. Windows has no such modes; Bosun relies on the data directory being inside the user's profile
  (`%LOCALAPPDATA%`), which other standard users cannot read, and does not rewrite ACLs. Keep the data directory
  there (or somewhere only you can read) and use disk encryption.
- *The CA's reach.* One CA per install, never shared. The launched browser trusts it by SPKI pin
  (`--ignore-certificate-errors-spki-list`) in its own profile, so it never needs installing system-wide.
  `doctor` warns if it finds the CA in a system bundle.
  *Lifetime and rotation.* The CA lasts three years. `doctor` and the Settings page warn 30 days before expiry
  (`doctor` fails once it has expired). `bosun ca rotate` makes a new CA and keeps only the old certificate (in
  `ca/previous/`), deleting the old key so a retired key cannot be stolen later; it is a local command on the
  data directory and needs a restart. Rotate after the data key or the data directory may have leaked, and
  replace the CA wherever it was installed by hand. `--permit-domain` makes the new CA name-constrained (DNS
  names under the listed domains only, all IP addresses excluded), which limits what a stolen key can
  impersonate on test devices to the scope's own domains; it relies on the client enforcing the constraint
  (current browsers and OSes do, some embedded TLS stacks do not).
- *Secrets in child processes.* The launched browser (and any later child: crawler browsers, plugins) starts from an
  empty environment plus an allowlist (`PATH`, `HOME`, display and `XDG_*` variables and similar), so
  `BOSUN_DATA_KEY` never reaches a process that loads hostile pages. Every spawn goes through
  `child::clean_command`.
- *Secrets in responses.* API responses are `Cache-Control: no-store`; tokens are stored only as SHA-256 hashes
  and shown once; password hashes never leave the account database. TOTP secrets are sealed with the data key
  (ChaCha20-Poly1305, bound to the user id) before they reach the account database, and shown once at enrolment;
  recovery codes are stored only as hashes. Someone who holds both the account database and the data key can read
  the secrets, as with the CA key.
- *Reports (`bosun-report`).* A report carries target content (URLs, evidence excerpts), so each format escapes it
  for its own syntax, and secrets (URL credentials, `Authorization`, cookies, bearer tokens, JWTs, `password=`-style
  pairs) are redacted unless the caller opts out. The HTML report has no script, no links and no external loads,
  and a CSP of `default-src 'none'` plus the hash of its own stylesheet, in a `<meta>` and as the header to serve it
  under (`html_csp`); it is never rendered in the UI's origin. Redaction is pattern-based and best effort: a secret
  with an unusual name can survive, so treat a report as sensitive. `GET /issues/report` needs the viewer role; keeping secrets (`redact=0`) needs the tester role and is audited
  (`issues.report`). The response is always an attachment, `nosniff`, with `sandbox` plus the report's own CSP (the
  API's CSP layer keeps a handler's stricter policy), and the UI saves it as a file instead of showing it. A
  Playwright test opens a saved report and checks that no script exists and nothing is requested. `bosun report
  --input` renders a file offline.
- *An open proxy.* The proxy refuses to start on a non-loopback address without proxy authentication or a
  client allowlist. The same check applies to every listener added while running (`POST /proxy/listeners`), so an
  admin cannot open one by mistake; each listener has its own credentials and allowlist, and a listener's
  credentials are never returned by the API or written to the audit log. Added listeners (with their passwords) are
  kept in the account database, the passwords sealed with the data key, so they come back after a restart.

### Denial of service

- Bodies the proxy buffers are capped (request 64 MiB, buffered response 64 MiB; larger responses stream through
  and are recorded truncated). Decompression for display stops at 32 MiB (no zip bombs). WebSocket frames are
  parsed incrementally and recorded up to 1 MiB each. Header counts are capped. The certificate cache is an
  LRU. Upstream connections time out.
- *Memory exhaustion.* One byte budget (`proxy.memory_budget_mib`; default half the container's cgroup limit, else
  1 GiB) covers request bodies as they are read, buffered responses, captured response bodies and history waiting
  to be written. Past it, requests get 503 and recorded bodies are dropped. The recorder queue is bounded and
  never blocks the proxy: when it is full or memory is short, a flow is recorded as headers only and marked
  truncated (counters in `/proxy` under `stats`). A write that fails is retried once; after that the batch is
  counted as lost and a `recorder_failed` event tells the UI. The intercept queue is capped by item and byte count
  (`max_intercept_items`, `max_intercept_bytes`): a message that does not fit is refused with 503 and is *not*
  forwarded, and the UI shows it. An optional timeout forwards a held message unedited. When a request body is
  refused (413 or 503) the proxy first reads and discards the rest of it, at most 8 MiB and 5 seconds, storing and
  reserving nothing, so the client can finish its upload and read the answer instead of getting a reset. That costs a
  refused request bounded bandwidth and time on a connection that the connection limits already cap.
- *Slow and many connections.* Both listeners set a header-read timeout (`header_timeout_secs`, default 30; it
  also bounds idle keep-alive connections), HTTP/2 limits (100 concurrent streams, 64 KiB header list, keep-alive
  pings) and a cap on concurrent connections (`proxy.max_connections` 1024, `api.max_connections` 256). Past the
  cap, new connections are closed at once and existing ones keep working. Keep the caps well under half the
  process's open-file limit: a proxied connection also holds an upstream socket. Refused proxy connections are
  counted (`connections_refused` in `/proxy` stats): they never become flows, so a load test that opens more than
  the cap will see fewer flows in History than requests sent. Each proxy listener may also set `max_connections`
  (changed live, audited with the other listener options): past it that listener closes new connections, so one
  exposed listener cannot use up the shared cap; refusals there are not counted in `connections_refused`.
- *History queries.* The query language (`docs/query-language.md`) is parsed in Rust and compiled to an SQL
  condition that uses bound parameters only: no query text is ever part of the statement. Length, term count and
  nesting are capped, a query that runs over five seconds is interrupted, and the result size is capped like any
  listing. The parser has a fuzz target that also runs what it produces against a real project (it found that a NUL
  character cut a bound full-text phrase short).
- *Copies and exports.* A recorded request carries other people's secrets (session cookies, bearer tokens). "Copy as
  cURL, PowerShell, Python, JavaScript or Go" and the HAR export replace the values of `Authorization`, `Cookie`,
  `Set-Cookie`, API-key and CSRF headers with `REDACTED` (cookie names stay) unless the person ticks "Keep cookies and
  authorization values", a preference of that browser that starts off. Values go into shell and code text only through
  quoting that the tests check against a real shell, and the HAR file is built in the browser from the same API calls
  the viewer makes (bodies over 2 MiB are cut), so the scope gate, roles and audit log are not bypassed. Query strings are
  not redacted: a token in a URL is exported as it was recorded.
- *Organizer and tags.* Notes, tags and the status of kept requests are text a tester wrote; they are shown as text.
  Bulk tag changes and the Organizer need the tester role, are capped (5,000 flows per call, 32 tags of 64 characters),
  and are not audited because they change no scope, rule, account or token.
- *Passive scanner (`bosun-scan`).* A hostile target controls every byte the scanner reads. The rules only read
  recorded flows: they send nothing, so they need no scope-gate check. They cap what they read (1 MiB of a body, 256
  headers, no compressed bodies), copy only short, truncated strings into an issue (the cookie name, a header value of
  at most 120 characters, the path without its query string, so tokens in URLs are not copied), and run behind
  `catch_unwind` so a rule bug skips one flow instead of stopping the scanner. Issues are capped at 50,000 per project
  (past that only the counts of known issues grow), and the queue is a mark on each flow in the project file, so a flood
  of traffic cannot grow memory: the scanner works through it in batches of 32 on its own thread and pauses between
  batches so the recorder's writes are not starved. The UI shows an issue's text and the matched excerpt only as text
  (`<mark>` around the range, never `{@html}`). Reading issues needs the viewer role; changing a status and starting a
  rescan need the tester role and are audited (`issue.status`, `issues.rescan`).
- *Check language and passive checks (`bosun-checks`).* A check is data from a file or an import, so it is untrusted
  like the traffic it runs on. The loader (`lang::parse`, `nuclei::import`) reads at most 256 KiB, refuses unknown
  fields, wrong versions and anything past fixed caps (32 matchers, 64 patterns each, 8 requests, 16 paths), builds
  regexes with the `regex` crate (linear time, 1 MiB size limit) and lets a YAML document expand only as far as the
  parser's alias budget allows. A check cannot run code, and a request path must start with `{{BaseURL}}` or `/`, so a
  check cannot send a request to another host; the variables are a fixed list and an unknown one is an error. Nuclei
  features that would change what a check means (raw requests, payloads, `dsl`, flows, other protocols) are refused by
  name, not dropped. Matching reads a body only when it is stored uncompressed, up to 1 MiB, and a part that cannot be
  read never matches (negative matchers included). Findings copy only short strings (hosts of mixed-content URLs, claim
  names of a JWT, library versions, extracted values cut at 120 characters), never a token, a password or a query
  string. The loader is fuzzed (`check_language`). The code checks run behind the scanner's `catch_unwind`. Active
  checks, once the scan engine sends them (WP-54), go through the scope gate like every other tool.
- *Custom checks (WP-50).* A project can store its own passive checks (`/checks`, table `checks`). The text goes
  through the same loader and caps as above before it is stored (256 KiB, 200 checks per project, a `passive` section
  required, ids of built-in rules refused) and is compiled again when the scanner loads it, so a file edited by hand
  gets the same validation; a check that no longer loads is skipped and logged. A custom check is data: it cannot send
  a request or run code, and it only reads recorded flows, so it needs no scope-gate check. Reading needs the viewer
  role; validating, adding, replacing, switching and deleting need the tester role and are audited (`check.add`,
  `check.update`, `check.enable`, `check.delete`). The UI shows the YAML only in a textarea and the loader's message as
  text. What a check extracts is cut at 120 characters like a built-in's.
  The `jwt-weak-secret` check verifies a token's HMAC against a short fixed list of common secrets (no cracking, no network); it reports that the secret is on the list but never copies the secret or the token into the issue.
- Held intercept items are released if the client goes away, and interception always starts off after a restart.

- *Hostile import files (WP-60).* `POST /import` reads OpenAPI/Swagger (JSON or YAML), GraphQL introspection,
  Postman, HAR, URL lists and Burp XML, all attacker-controlled when the file comes from a target or a third
  party. Input is capped at 32 MiB, at most 2000 requests come out of one import, bodies are cut at 1 MiB, and
  JSON/XML nesting is limited. YAML anchors and aliases are refused before parsing (no alias expansion, so no
  "billion laughs"); the XML reader never resolves entities: a DOCTYPE that declares one is refused, and so is any
  reference beyond the five predefined and numeric ones (no XXE, no entity expansion). `$ref` is followed only
  inside the same document and to a bounded depth; nothing is fetched. Every parser has a fuzz target
  (`import_formats`). The UI's Import panel shows the pasted text, the hosts and the request lines only as text
  (never as HTML) and previews with a dry run first; the hosts are listed so the scope can be checked before a tab
  is sent, which still passes `Gate::check`.

### Elevation of privilege

- Roles: viewer (read), tester (change scope, rules, intercept), admin (accounts, audit, proxy listeners and live
  proxy settings: they decide who can reach the proxy and how much it holds). Every handler checks the role it
  needs. API tokens carry their owner's role. Settings that cannot change safely while running (upstream proxy,
  upstream TLS verification, memory budget, intercept queue limits, the configured address) are refused with 409
  rather than half applied; removing a listener leaves connections it already accepted to finish.
- *Out-of-scope traffic from tools.* Every request from Repeater, Intruder, the scanner, the crawler and plugins
  goes through one gate (`bosun-scope`) that refuses out-of-scope targets and honours a global stop switch. The
  proxy itself is exempt: it forwards what the user's own browser asks for.
- *Imports send nothing of their own.* The importers only produce request definitions; they open no connection
  (not even to fetch a `$ref` or a server URL). The one fetch is explicit: a GraphQL import with `introspection_url`
  POSTs the standard introspection query to that URL through the Repeater's engine, so the scope gate (scope, kill
  switch, rate limit, protected networks, the Repeater's out-of-scope setting) decides first; an out-of-scope
  endpoint gets 403 and no connection. The answer is parsed like a pasted file, never rendered, and the import is
  audited with the URL. HAR and Burp responses are stored as flows (source `import`) only when `store_responses` is
  set: they are target-controlled bytes like any recorded response, shown only in the sandboxed viewers, and nothing
  is sent. Items are saved as Repeater tabs, and a tab is sent
  only when a tester sends it, through the same scope gate as any Repeater request. Imported items are validated
  (absolute http/https URL, method token, no control characters in header names or values, framing headers
  dropped) so a crafted file cannot smuggle a second request or header. The reply lists the hosts involved so the
  scope can be checked first. The import needs the tester role and writes an audit entry (`import.requests`).
- *A scoped name pointed at the machine Bosun runs on (SSRF, DNS rebinding).* The gate resolves the name itself and
  returns the addresses the tool must connect to; tools never resolve again. It refuses loopback, link-local (which
  includes `169.254.169.254` and the IPv6 metadata address), unspecified and multicast addresses, IPv4-mapped IPv6
  forms of those, and the host's own networks when the server lists them. One internal address among several
  answers refuses the whole name. Only an include rule that names the address literally, or sets `allow_private`,
  lifts this, and the Repeater's "send out of scope" choice does not. A per-host rate limit sits in the same gate.
  Open: the server does not yet fill in its own networks (WP-23), so in container mode only the address classes
  above are refused.
- *Raw sends (`bosun-http`).* The raw request engine is the one place tools send bytes (HTTP/1.1, HTTP/2 frames,
  WebSocket frames). It calls the gate, connects only to the addresses the gate returned and never resolves a name
  itself. Behind an upstream proxy it asks the proxy for the pinned IP address, not the name, and it uses the
  proxy's loop guard, so a request aimed at Bosun's own listeners is refused. Responses are read under the memory
  budget and a per-message cap (16 MiB by default; the rest is cut off and marked truncated). Framing is scanned
  without trusting the server: a bad chunk size, a short body or an oversized frame ends the read with an error
  and keeps what arrived. WebSocket frames from the server are capped in size per frame.
  - *Redirects* are off unless asked for. Each hop goes through the gate, so a redirect to an out-of-scope or
    internal address is not followed and the chain says why; credentials are dropped when the host changes.
  - *HTTP/2 plans* may be malformed on purpose, but their `HEADERS` frames are decoded to read the `:path`, and
    every path goes through the gate; a plan whose header blocks cannot be decoded is refused rather than sent
    unchecked. HPACK decoding uses `fluke-hpack`, which panics on some cut-off blocks; a structural check runs
    first and a panic is caught, so server bytes cannot take the caller down.
  - Certificate checking is off by default for tools, because test targets often have bad certificates;
    `verify_tls` turns it on.
  - *Connection reuse and multiplexing.* Pooling is off unless a send asks for it. The gate is asked on every
    send, whether or not a connection is pooled, and a pooled HTTP/1.1 connection or the shared HTTP/2 connection
    is used only if its peer address is one the gate has just pinned for that name, so a name that now resolves
    elsewhere (DNS rebinding) never reaches an old connection. A connection is also keyed by scheme, host, port
    and whether the certificate is checked, so a send that asked for checking never rides one made without it.
    Only a connection the last exchange left clean goes back (no `Connection: close`, framed body, no extra
    bytes); idle ones expire after 30 s, are checked for liveness before use and are dropped when a project is
    opened. A stale one is retried once, for idempotent methods only. The HTTP/2 driver keeps both flow-control
    windows, honours the server's stream limit, reserves response bytes from the memory budget as they arrive,
    cuts off a response over the cap with `RST_STREAM`, cancels streams whose caller gave up, and stops using a
    connection after `GOAWAY`. A batch passes the gate for every `:path` before any byte is written.
  - The framing code has a fuzz target (`raw_framing`).
- *The Decoder and Comparer API (`/decoder/apply`, `/decoder/smart`, `/comparer/diff`).* Pure computation on bytes in the
  request: nothing is fetched, stored or sent, so the viewer role is enough. The risks are memory and CPU, so the input
  is capped (4 MiB; 1 MiB per side for a diff), every step's output is capped at 4 MiB (a decompression bomb ends the
  chain with an error), a chain is at most 16 steps, intermediate outputs are returned truncated, the diff table is
  capped (very different large inputs are reported coarsely) and the work runs off the async threads. The codecs are
  in `bosun-codec` (no I/O), covered by property tests and the `codec` fuzz target. Output is data for display as text;
  the UI never renders it as HTML.
- *`bosun decode`.* The Decoder's chain on stdin or a file, in the user's own process: no engine, no network, no
  account. Input and every step's output are capped (`--limit`, 16 MiB by default), so a decompression bomb ends the
  chain with exit code 2. MD5 and SHA-1 are offered to match what targets compute, not for anything Bosun protects.
- *The host analysis (`/analysis`).* Read-only on stored requests, so the viewer role is enough; it sends nothing
  and writes nothing, so it needs no gate check or audit entry. Cost is bounded: at most 20,000 requests are read,
  a request body only up to 64 KiB, and the result holds at most 5,000 endpoints and 5,000 parameters with a few
  short example values each. The work runs off the async threads. Every name, path and value in the result is the
  target's text; the UI shows it as text only, and a link back to the history only fills the filter bar.
- *The client commands (`bosun login`, `status`, `repeater send`).* They are clients of the API like any other: the
  server checks the role, the scope gate, the audit and the recording, so the CLI adds no way around them. `login` reads
  the password from stdin, makes a 90-day API token and signs the session out again; the token is kept in
  `profiles.json` in the client directory, created readable by its owner only (0600 on Unix; Windows relies on the
  profile folder's ACL). A token in the environment (`BOSUN_TOKEN`) wins over the file. Where the OS has a keychain (Windows Credential Manager, macOS Keychain, the Secret Service on Linux) `bosun login` keeps the token there instead and the file holds only the server address; with no keychain it falls back to the file, with a note. `BOSUN_KEYCHAIN=off` forces the file.
- *The local admin commands (`bosun project`, `token`, `user role|delete|sessions`, `audit`).* They work on the data
  directory directly, so they are as trusted as the account that can read it: whoever can run them can already read the
  data key, the account database and every project. They add no remote surface. They write the same audit entries as
  the API (account, role, session, token and project changes; imports that were refused), with no user name and
  "via CLI" in the detail, and a project that a running engine holds is refused (exit 3) instead of being opened a
  second time, by the same lock the engine uses. Deleting a project or an account asks for the name to be typed, or
  `--yes` when there is no terminal; the last admin can neither be demoted nor deleted. `token create` prints the
  token once on stdout (only its hash is stored), so keep it out of shared logs. Imports use the same rebuild as the
  API (`import_foreign`), never opening the file in place. `serve --no-ui` runs the proxy and recorder without the
  UI/API listener or accounts. A password typed at a terminal is not echoed.
- *The Repeater API (`/repeater/send`, `/repeater/ws`, `/repeater/settings`).* Sending needs the tester role; reading the setting,
  the viewer role. Every send goes through the gate with the Repeater's policy: out-of-scope targets are refused
  unless the setting is on, and the setting starts off, is not stored in the project, goes back off whenever a
  project is opened, and changing it is audited. Each send is audited (target, count, mode) and recorded as a flow
  with source `repeater`, so nothing the Repeater sends is hidden from history. The kill switch stops it. Counts
  are capped (100; 50 for a single-packet batch), and so are the request (4 MiB) and, by the engine, the
  response. `/repeater/ws` takes the same role, gate, audit and recording: the handshake goes through the gate with
  the Repeater's policy, and frames are capped (100 sent, 1 MiB each, 200 read, at most 10 s of listening) and
  stored as the flow's messages. A connection lasts one call and is closed before it returns. Tabs are saved in the project (`/repeater/tabs`, viewer to read, tester to write: at most 100 tabs and 8 MiB,
  each an object; responses are not stored). A request can hold credentials, but so does every flow in the same file,
  and the project file is already the place those live, with its permissions, export and backup rules.
- *The Sequencer API (`/sequencer/analyze`, `/sequencer/capture`, `/sequencer/capture/{id}`, `.../stop`).* The
  analysis is pure computation on strings (`bosun-sequencer`, no I/O): viewer role, at most 10,000 tokens of 1,024
  characters and 4 MiB in all, FIPS blocks capped at eight, run off the async threads, covered by property tests and
  the `sequencer` fuzz target (which also feeds the token extractor hostile responses and patterns). A live capture
  needs the tester role and is a series of requests sent by the Repeater's engine, so each one goes through the
  gate with the Repeater's policy (scope, kill switch, per-host rate limit: a rate-limit refusal is waited out a
  second at a time, any other refusal ends the capture as failed), is recorded as a flow with source `repeater`,
  and the capture is audited (target, count) as is its stop. The number of requests is capped (5,000), so is the
  request (1 MiB) and the pause (10 s); at most two captures run at once and eight are kept in memory (not in the
  project; they are gone on restart); a stop switch ends one after the request in flight, and ten failures in a row
  end it. A body pattern is a regular expression run by the `regex` crate (no backtracking; 512 characters, compiled
  size capped) over the response, and an extracted token is cut at 1,024 characters. Tokens are session secrets: they
  stay in the server's memory and the page, are not written to the project, and are exported only when the user
  saves the result (which holds per-position statistics, not the tokens).
- *The Intruder API (`/intruder/*`).* Planning, starting, stopping and deleting an attack need the tester role;
  listing attacks and reading results, the viewer role. Every request goes through the gate as source `intruder`
  (an automated source), with no out-of-scope setting at all: a target outside the scope fails the attack at its first
  request. The per-host rate limit applies on top of the attack's own concurrency (1 to 64) and delay; a request the
  limit holds back is retried for up to 60 seconds, never dropped, and the kill switch ends the attack as stopped.
  Starting, stopping and deleting an attack are audited (target, type, request count), and each request sent is
  recorded as a flow with source `intruder`. An attack is bounded before it starts: at most 1,000,000 requests, 20
  positions, 200,000 list items, a 1 MiB request and 64 KiB per payload, and at most 3 running at once; payload and
  grep patterns are regular expressions run by the `regex` crate (linear time), and brute-force and number
  sources are generated by index, so a large set costs no memory. Stopping drops the requests in flight; changing
  or closing the project stops every attack first, and an attack found running when a project is opened is marked
  interrupted. Results (payloads, status, length, time and grep values from the response) are kept in the project
  file, a row at a time, so they hold what the target sent back and are shown only as text in the UI; a CSV export
  puts a quote before any cell that a spreadsheet would run as a formula. Payload lists loaded from a file are read
  in the browser and sent as text. The request template and payload sets parser has a fuzz target (`intruder_plan`).
- *The spider (`bosun-crawl`, API `/crawl/*`, `bosun crawl run`, the Spider panel).* Every request, `robots.txt` and sitemaps
  included, goes through `Engine::send` and so through the gate as source `crawler` (an automated source: out of
  scope is refused, never prompted). Links are also checked against the scope before they are queued, so an
  out-of-scope link is listed in the report and not requested; the gate stays the guarantee. Redirects are not
  followed by the engine: a `Location` is a link like the others, so every hop is checked. The target's pages decide
  what gets requested, so the crawl is bounded: depth, a page limit (at most 1,000,000), a concurrency of 1 to 32,
  a response cap per page, only `http` and `https` links, and the per-host rate limit is waited out (up to 60
  seconds a request) and never bypassed; the kill switch ends the crawl. `POST` forms are listed and not sent unless
  the tester turns that on, since a form can change data; `GET` forms are sent with the values the page gives
  them. `robots.txt` is obeyed by default (what it hides is still listed) and its patterns are matched in linear
  time. The HTML, robots and sitemap readers take untrusted input and have a fuzz target (`crawl_html`). Extra
  headers (such as a session cookie) are refused if they hold a line break. The API: starting and stopping a crawl
  need the tester role, listing and reading results the viewer role; start and stop are audited (start URLs, depth,
  page limit, and whether `POST` forms were on). The API caps `max_pages` at 20,000, runs at most 2 crawls at once and
  keeps the last 8 in memory only (nothing is added to the project file); the pages it fetched are recorded as flows
  with source `crawler`, which is how they reach the history and the site map. Page rows, forms and links are
  target content and are shown only as text in the UI. `POST` forms are sent only when the request sets
  `submit_post_forms` (an explicit checkbox in the panel, a flag in the CLI).
- *Target content served by the API.* The body endpoints return raw stored bytes as `application/octet-stream`
  with `Content-Disposition: attachment` and `nosniff`, so a browser never interprets them in the UI's origin;
  the UI shows them as text or in the sandboxed render frame. Reads are streamed with an enforced size, so a
  corrupt or hostile project file cannot make a read run on or allocate more than a few chunks.
- *Upgrading a project or account file.* Each migration runs in one transaction, after the file is copied to
  `<file>.pre-v<N>.bak` (owner-only, like the file). A failed step leaves the file as it was. These copies hold the
  same secrets as the file and are not deleted automatically: remove them after checking the upgrade.
- `unsafe` code is forbidden in every crate.
- Containers run as nonroot on a distroless base, read-only root, all capabilities dropped.
- The desktop window exposes no Tauri IPC commands and may only navigate to the engine's own origin.

## Out of scope

- An attacker who already controls the machine, the data directory or the data key.
- Weaknesses of the targets themselves (finding those is the point).
- A CA installed system-wide by the user despite the warnings.
