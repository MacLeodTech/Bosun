# The Bosun API

The engine serves a JSON API under `/api/v1` and a WebSocket event stream at `/api/v1/events`.
The description is [`openapi.json`](openapi.json), generated from the code (`crates/bosun-api/src/openapi.rs`).

## Rules for changes

- Within `/api/v1`, changes are additive: new endpoints, new optional request fields, new response fields.
  Clients must ignore response fields they do not know. Removing or renaming anything needs `/api/v2`.
- After changing a handler or a type that the API exposes, regenerate both files and commit them:

  ```sh
  BLESS=1 cargo test -p bosun-api --test api openapi   # docs/openapi.json
  cd web && npm run gen:api                             # web/src/lib/api-types.ts
  ```

  The tests and CI fail when either is stale.

## Signing in

- A browser uses the session cookie; send the CSRF token (from `/auth/me`) as `x-csrf-token` on changes.
- Other clients use an API token: `Authorization: Bearer bosun_…` (create one with `POST /tokens`). A `read` token
  can only make GET requests.

## The event stream

Every event has a `seq`. The first message is `{"type":"hello","epoch":"…","seq":N}`. To resume after a drop,
connect with `?since=<last seq>&epoch=<epoch>`: missed events are replayed, or `{"type":"reload"}` says to fetch
the data again.

Active scans send `scan_started`, `scan_progress` (at most four a second) and `scan_done` (`done`, `stopped` or
`failed`); fetch `/scan/scans/{id}` for the findings. `bosun scan` (see `docs/ci.md`) polls instead.

A new epoch starts when the engine does and whenever the open project changes. A `project_switched` event
(`{name, temporary}`) means everything held from before is from another project: clients drop it and fetch it
again (the web UI reloads its pages). A position from an earlier epoch is answered with `reload`.

## Projects

Projects live in the engine's projects folder and are addressed by name only (`GET /projects` lists them and says
which is open). Everyone can list; the rest need the admin role and is audited.

| | |
|---|---|
| `POST /projects` | create (`{name, open}`) |
| `POST /projects/{name}/open`, `POST /projects/close` | switch; `close` opens a temporary in-memory project |
| `POST /projects/{name}/rename`, `DELETE /projects/{name}` | not for the open project |
| `GET /projects/{name}/export` | a consistent copy as a download (also of the open project) |
| `POST /projects/{name}/backup` | a copy in the `backups` folder on the engine's machine |
| `POST /projects/import?name=…&open=…` | the body is a project file (`application/octet-stream`, at most 2 GiB). It is checked and its content copied into a new project; it is never opened as it came |

Status codes: 409 (name taken, project open or locked by another process), 422 (not a usable Bosun project, or
from a newer Bosun), 413 (too large).

## The credential vault

`/vault` holds named secrets (kinds `password`, `token`, `api_key`, `auth_config`, `client_cert_password`, `oast_key`,
`other`). `GET /vault` (viewer) lists id, name, kind, timestamps and a masked hint; no response ever carries the
secret. `POST /vault`, `PATCH /vault/{id}` (rename, re-kind, replace the secret) and `DELETE /vault/{id}` need the admin
role and are audited by name (`vault.create`, `vault.update`, `vault.delete`). Other features refer to an entry by its
id. 400 (bad name, kind or secret), 404, 409 (name taken, or 500 entries).

## Signed-in scans and crawls

`POST /scan/scans` and `POST /crawl/crawls` take an optional `session`: `login` (`url`, `method` default `POST`, `headers`,
`body`, `content_type`), `capture` (`{kind: "cookies"}`, `{kind: "body", pattern, header, prefix}` or
`{kind: "header", from, header, prefix}`) and `expiry` (`statuses`, `redirect_contains`, `body_contains`; default 401 or a
redirect to a login page). The first request signs in; every request then carries the session's headers, and an answer that
means the session ended signs in again and repeats the request. The login may name vault entries as `{{vault:ID}}`,
`{{vault:ID|url}}` (percent-encoded) or `{{vault:ID|json}}` (escaped for a JSON string); they are opened on the server and
only go into the login request. A failed sign-in ends the scan (state `failed`, with the reason) or stops the crawl, and is
not tried again, so a wrong password cannot lock the account. At most 25 sign-ins per run. 400 for a missing vault entry,
a bad pattern or header.

## Content and parameter discovery

`POST /discover/runs` (tester; audited as `discover.start`) tries a wordlist against `base`. Mode `paths` (default)
requests each word (and each word with every entry of `extensions`) below the directory and probes the directories it
finds down to `max_depth`; mode `params` sends each name as a parameter (`post: true` puts it in a body). `words` empty
means the built-in list. Before probing, random names are requested to learn what "not found" looks like: a site that
answers 200 to everything gives no hits, and many hits with the same answer (8 or more) are dropped as a wildcard and
counted in `noise`. `GET /discover/runs/{id}` lists the `results` (status, size, `note`, `cluster`), the `directories`
probed and whether `max_requests` cut it short; `POST .../stop` throws the stop switch. Every request goes through the
scope gate and the per-host rate limit; a refused request ends the run (`failed`, with the reason). Only hits are
recorded as flows. 400 (bad URL, mode, word or header), 429 (two runs already going).

## Known-vulnerable components

The passive scanner fingerprints servers, frameworks and libraries (`technology-fingerprint`, Info) and matches the
versions it finds against an offline advisory database (`vulnerable-component`). `GET /advisories` (viewer) says which
database is in force: `bundled` (a small one that ships with the program) or `feed`. A feed is a JSON file
(`schema` 1, `sequence`, `generated`, `advisories` with `id`, `product`, `summary`, `severity`, `ranges` of
`introduced`/`fixed`/`last_affected`, `cwe`, `references`) and a detached Ed25519 signature over its exact bytes.
`PUT /advisories/trust` (admin) sets the base64 public keys that may sign one (at most 5); `POST /advisories/feed`
(admin) takes `{feed, signature, rescan}` (the feed as text; at most about 2 MiB over the API) and loads it only when
the signature verifies under a trusted key and its `sequence` is higher than the database in force (422: no key or
no match; 409: not newer; 400: not a valid feed). A loaded feed replaces the built-in advisories, and by default the
recorded traffic is scanned again. `DELETE /advisories/feed` goes back to the built-in ones. `bosun advisory keygen
<file>` and `bosun advisory sign <key> <feed>` make the keys and the signature.

## The authorisation matrix

`POST /auth-matrix` (tester; audited as `authmatrix.run`) replays recorded flows as each given account and as nobody,
and compares every answer with the owner's. Body: `identities` (name plus `headers`, or `vault` entries naming a
`vault_id`, the `header` to set and an optional `prefix`), `probes` (`flow_id`, `owner`, `allowed`, `label`) and
`options`. Up to 20 identities and 200 probes. Vault secrets are opened on the server and never returned or audited.
Every send goes through the scope gate. The answer has `rows` (one cell per account) and `findings` (broken access
control, or no login needed). With `save_issues: true` each finding is also saved as an issue (rule `authz-matrix`,
pointing at the probe's recorded flow, once per account and request), and `issues_saved` counts them. 400 (bad names or headers, missing vault entry), 404 (no such flow).

## Embedded mode

`bosun serve --embedded` is for a desktop app that starts the engine as a child process. It listens on loopback only
(random ports unless given), writes one JSON line to stdout
(`{"api_url","proxy_addr","ca_spki","login_ticket","version"}`), logs to stderr, and exits when its stdin closes (or
the parent dies). The app signs in with `POST /auth/ticket {"ticket": …}` (single use, 60 seconds) and gets an
admin session, creating a local admin account the first time. `ca_spki` is the base64 SHA-256 of the CA's public key,
for pinning the interception CA when launching a browser.

## Generating a client

- **TypeScript:** `npm run gen:api` in `web/` (openapi-typescript).
- **C# (the WinUI app):** generate from `docs/openapi.json` with Kiota
  (`kiota generate -l CSharp -d docs/openapi.json -c BosunClient -n Bosun.Client -o Client`) or NSwag
  (`nswag openapi2csclient /input:docs/openapi.json /classname:BosunClient /namespace:Bosun.Client`).
  Run it in the app's build so the client cannot drift from the engine it ships with. Cookie auth is not needed
  there: the shell signs in with a login ticket (WP-15).
- **Rust:** the `bosun-client` crate: every operation, the event stream with resume and reconnect, optional extra
  CA certificates for a TLS engine. A test fails when an operation is added without a client method.
