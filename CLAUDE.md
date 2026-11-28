# Bosun: notes for working in this repo

- Rust 2024, toolchain pinned in `rust-toolchain.toml`. `unsafe` is forbidden workspace-wide.
- `cargo test` / `cargo clippy --all-targets -- -D warnings` cover the default members. `bosun-desktop` is not a
  default member (it needs the platform webview); never use `--workspace` for build/test locally unless the
  webview libraries are installed. `cargo deny --workspace check` is fine (it doesn't compile).
- The web UI is in `web/` (Svelte 5, TypeScript, Vite): `npm run check` (warnings fail) and `npm run build`.
  `crates/bosun-api/build.rs` embeds `web/dist` if it exists, otherwise a placeholder page; `BOSUN_WEB_DIST`
  overrides the path.
- The UI runs under a strict CSP: no inline `<script>`, no `style=` attributes or `style:` directives (use the
  `css` action in `web/src/lib/style.ts`), no `{@html}` with target content.
- More tests (all run in CI, see `docs/testing.md`):
  - `proptest` property tests sit in the unit-test modules, so plain `cargo test` runs them.
  - `cd e2e && npm ci && npx playwright install chromium && npm test` drives the real UI against `target/debug/bosun`
    (build it first with `cargo build -p bosun`, and rebuild the web UI before that if it changed).
  - `cd fuzz && cargo +nightly fuzz run <target> -- -max_total_time=30` (needs nightly and `cargo install cargo-fuzz`).
    A new parser of untrusted input gets a fuzz target in `fuzz/fuzz_targets/` and an entry in `fuzz/Cargo.toml`
    and in the CI matrix.
- Security rules (see `docs/threat-model.md`):
  - every API handler takes a `Caller` and calls `caller.require(role)` first;
  - every outbound request from a tool goes through `bosun_scope::Gate::check`;
  - target content is never rendered in the UI's origin;
  - anything that changes scope, rules, accounts or tokens writes an audit entry.
- Keep `docs/threat-model.md` in step with behaviour changes that affect it.

## Navigating the code

If `.codegraph/` exists, use `codegraph_explore` (or `codegraph explore "<symbols or question>"`) before grep/find
or reading files. If not, use normal search and do not run `codegraph init`.

## Workflow

- Branch for work. Commit only when asked. Never push or open a PR until the owner confirms.
- Every bug fix gets a regression test that fails without the fix.
- Ask before adding a dependency.
