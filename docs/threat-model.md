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
- *Hostile HTML in the UI.* The UI's CSP forbids inline script and inline style and allows nothing but its own
  origin. Responses are shown as text; the "render" view is an iframe with an empty `sandbox` attribute (no
  scripts, opaque origin) whose `srcdoc` also inherits the UI's CSP. Syntax colour is drawn from a tokeniser's
  output as `<span>` elements, never as markup built from the body. The render frame is told the UI's colour scheme
  through one `<meta name="color-scheme">` that the UI writes (after the doctype, so the page's rendering mode
  does not change); the `sandbox` attribute and the CSP are untouched.
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
  rule, kill-switch, role, session-revocation, login-ticket, project (create, open, close, rename, delete, export,
  backup, import and refused imports) and intercept changes (settings, drop, edited forward, forward-all),
  with the user and remote address. Admins can read it in the UI.

### Information disclosure

- *The CA key at rest.* Sealed with ChaCha20-Poly1305 under a 32-byte data key that lives apart from it:
  `BOSUN_DATA_KEY`, a mounted secret file, or `data.key` (0600). Files and directories are created 0600/0700, and
  the key file's permissions are checked on load.
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
- *Secrets in child processes.* The launched browser (and any later child: crawler browsers, plugins) starts from an
  empty environment plus an allowlist (`PATH`, `HOME`, display and `XDG_*` variables and similar), so
  `BOSUN_DATA_KEY` never reaches a process that loads hostile pages. Every spawn goes through
  `child::clean_command`.
- *Secrets in responses.* API responses are `Cache-Control: no-store`; tokens are stored only as SHA-256 hashes
  and shown once; password hashes never leave the account database.
- *An open proxy.* The proxy refuses to start on a non-loopback address without proxy authentication or a
  client allowlist.

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
  process's open-file limit: a proxied connection also holds an upstream socket.
- Held intercept items are released if the client goes away, and interception always starts off after a restart.

### Elevation of privilege

- Roles: viewer (read), tester (change proxy settings, scope, intercept), admin (accounts, audit). Every handler
  checks the role it needs. API tokens carry their owner's role.
- *Out-of-scope traffic from tools.* Every request from Repeater, Intruder, the scanner, the crawler and plugins
  goes through one gate (`bosun-scope`) that refuses out-of-scope targets and honours a global stop switch. The
  proxy itself is exempt: it forwards what the user's own browser asks for.
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
