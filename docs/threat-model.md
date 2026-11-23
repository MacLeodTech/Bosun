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

### Tampering

- *Traffic that reaches the UI through the proxy.* Requests the proxy would send to its own listeners are refused
  (the proxy knows the API's address), and the API refuses any connection whose source address belongs to one of
  the proxy's own outbound sockets (covers aliases such as other loopback addresses or the host's LAN address).
- *Hostile HTML in the UI.* The UI's CSP forbids inline script and inline style and allows nothing but its own
  origin. Responses are shown as text; the "render" view is an iframe with an empty `sandbox` attribute (no
  scripts, opaque origin) whose `srcdoc` also inherits the UI's CSP.
- *Project files.* Opened with a bundled, current SQLite (`cargo deny` fails the build on SQLite advisories),
  with `trusted_schema` off, `cell_size_check` on and SQLite's defensive mode set. A file must carry exactly the
  schema this version creates: an extra trigger, view, table or index, or an altered column, is refused (a
  trigger would run the file author's SQL on our connection). Stored bodies are decompressed through a hard
  limit (128 MiB per body, 4 MiB per WebSocket message) and must match the size the file records, so a
  decompression bomb is refused as corruption. Importing someone else's project means copying rows into a new
  file, never working in the foreign file.
- *Two processes on one project.* `<project>.lock` is held exclusively while a project is open; a second open
  fails and names the process that holds it.

### Repudiation

- An append-only audit log (database triggers refuse UPDATE and DELETE) records sign-ins, account, token, scope,
  rule, kill-switch, role, session-revocation and intercept changes (settings, drop, edited forward, forward-all),
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
  forwarded, and the UI shows it. An optional timeout forwards a held message unedited.
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
- `unsafe` code is forbidden in every crate.
- Containers run as nonroot on a distroless base, read-only root, all capabilities dropped.
- The desktop window exposes no Tauri IPC commands and may only navigate to the engine's own origin.

## Out of scope

- An attacker who already controls the machine, the data directory or the data key.
- Weaknesses of the targets themselves (finding those is the point).
- A CA installed system-wide by the user despite the warnings.
