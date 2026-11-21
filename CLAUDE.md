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
- Security rules (see `docs/threat-model.md`):
  - every API handler takes a `Caller` and calls `caller.require(role)` first;
  - every outbound request from a tool goes through `bosun_scope::Gate::check`;
  - target content is never rendered in the UI's origin;
  - anything that changes scope, rules, accounts or tokens writes an audit entry.
- Keep `docs/threat-model.md` in step with behaviour changes that affect it.
