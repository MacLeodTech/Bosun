# Testing

Everything below runs in CI (`.github/workflows/ci.yml`). Run the same things locally before pushing.

| Kind | Where | Run it |
|---|---|---|
| Unit and integration tests | `crates/*/src`, `crates/*/tests` | `cargo test` |
| Property tests (`proptest`) | the `properties` module inside the unit tests of `bosun-scope`, `bosun-model` and `bosun-proxy` (`ws.rs`) | `cargo test` |
| End-to-end (Playwright) | `e2e/` | `cargo build -p bosun`, then `cd e2e && npm ci && npx playwright install chromium && npm test` |
| Fuzzing (`cargo-fuzz`) | `fuzz/` | `cd fuzz && cargo +nightly fuzz run <target> -- -max_total_time=30` |

## Property tests

They state rules that must hold for any input: scope matching (excludes win, `*` covers exactly one label, the query
string never changes the answer, an empty scope contains nothing), raw HTTP messages (serialise then parse gives the
same message; bare LF equals CRLF), and the WebSocket frame parser (any chunking gives the same frames; the record
limit holds). When proptest finds a failing case it writes `proptest-regressions/` next to the crate: commit that
file together with the fix.

## End-to-end

The suite starts the `bosun` binary (`BOSUN_BIN` overrides the path) with a throw-away data directory and a small
stand-in "hostile" site (`e2e/target.ts`), then drives the UI in Chromium: first-run setup, sign-in, scope editing,
live history, intercept edit/forward/drop, the Repeater (send, diff, groups, out-of-scope refusal), and the check that the render view cannot run a hostile page's script. The
ports are 18080 (proxy), 18090 (UI) and 18099 (target); override with `BOSUN_E2E_PROXY_PORT`, `BOSUN_E2E_UI_PORT`
and `BOSUN_E2E_TARGET_PORT`. A failed CI run keeps the Playwright traces as an artifact.

The render-sandbox test has two layers on purpose. The `sandbox=""` attribute assertion guards the sandbox itself.
The call-back assertion guards the outcome (no script, event handler or `javascript:` link of the page runs); the UI's
CSP, which the `srcdoc` inherits, would stop inline script even if the sandbox were weakened, so the attribute
assertion is what fails first.

## Fuzzing

| Target | What it feeds |
|---|---|
| `http_messages` | raw requests and responses (parse, serialise, parse again must agree) |
| `raw_framing` | the raw engine's parsers: HTTP/1.1 to HTTP/2 conversion, chunked scanner (same answer however reads are split), `Content-Length` rewrite (idempotent), WebSocket and HTTP/2 frames (round trip), HPACK blocks (no panic), redirect resolution |
| `codec` | the Decoder and Comparer: every decoder on arbitrary input (no panic, output within the limit), smart decode, and a diff that rebuilds both sides |
| `ws_frames` | a WebSocket byte stream cut into arbitrary pieces |
| `decode_body` | stored, compressed bodies (the decompression limit and the size check must hold) |
| `scope_rules` | scope host patterns and path regexes (compile and match) |
| `rewrite_rules` | match-and-replace rules applied to messages |

Pull requests fuzz each target for 30 seconds; the weekly run does 10 minutes. A crash prints the input in the job
log. Reproduce with `cargo +nightly fuzz run <target> <path-to-input>`, fix it, and add a regression test next to the
parser (the first find, the status line `HTTP/2 024`, is `a_status_below_100_is_written_with_three_digits`).
New parsers of untrusted input get a target (the roadmap requires it).
