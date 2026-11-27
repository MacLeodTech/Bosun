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
