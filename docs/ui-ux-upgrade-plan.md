# UI/UX upgrade plan

Status: proposal. Audit date 2026-11-25, branch `branding`.

**Basis.** This audit comes from reading the code: `App.svelte`, `app.css`, `History`, `Intercept`, `Target`,
`MessageView`, `VirtualList`, `session.svelte.ts`, `style.ts`, `docs/threat-model.md` and `docs/releases.md`.
I did **not** read `Rules`, `Projects`, `Settings`, `Auth`, `bytes.ts` or `flowbody.ts`, and I did not run the app
or take screenshots. Findings about rendered appearance (contrast, spacing) are inferred from CSS and should be
confirmed in the running UI before Phase 0 closes.

**Stack facts that constrain every choice below.**
- Svelte 5 (runes), TypeScript, Vite. No UI dependencies at all; the whole UI is about 1,700 lines of hand-written
  Svelte plus a 40-line `app.css`.
- Strict CSP: no inline script, no `style=` or `style:`. Dynamic sizes go through `use:css`
  (`web/src/lib/style.ts`), which sets properties via the CSSOM.
- No `{@html}` with target content. Target content is never rendered in the UI's origin.
- `npm run check` fails on any warning, including Svelte a11y warnings.
- The desktop window "exposes no Tauri IPC commands and may only navigate to the engine's own origin"
  (`threat-model.md`).
- Repeater, Decoder, Comparer, Intruder and Scanner do not exist yet. Repeater tabs, Organizer and Logger are
  planned for M2. Only Intercept, History, Match & replace, Target, Projects and Settings exist today.

---

## 1. UI/UX audit and friction points

Severity: **H** blocks the goals, **M** costs time daily, **L** polish.

### Navigation and state
| # | Finding | Evidence | Sev |
|---|---|---|---|
| 1 | Every page is torn down on tab switch. Selected flow, filters, scroll position and the loaded request/response are lost. Going History, then Intercept, then back resets everything. | `App.svelte` renders one page inside `{#key generation}`. History keeps all state in component-local `$state` and calls `reload()` in `onMount`. | H |
| 2 | Layout is fixed. History is a hard-coded 1fr / 1.4fr vertical grid, request and response are a fixed 50/50, and Target is a fixed 1.3fr / 1fr. Nothing resizes, docks or hides. | `History.svelte` `.layout`, `.pair`; `Target.svelte` `.cols` | H |
| 3 | Six top-level tabs of unequal weight. Settings and Projects sit beside the work surfaces. The intercept state is visible only as a count badge, so there is no persistent "intercept on" indicator. | `App.svelte` `pages` | M |
| 4 | Navigation is hash-only (`#history`). It carries no flow id, so a flow cannot be deep-linked or restored after a reload. | `go()` | M |

### History (the main surface)
| # | Finding | Evidence | Sev |
|---|---|---|---|
| 5 | **The list moves under the cursor.** A live flow does `flows = [e.flow, ...flows]`. A prepend shifts every row down while the user reads or clicks. There is no pause or follow control and no anchoring. | `History.svelte` `onMount` handler | H |
| 6 | No keyboard navigation. Rows are `<button>`s, so Tab visits 500 of them. There is no j/k or arrow movement, no Home/End, no type-to-filter, and the selection is never scrolled into view. | `VirtualList` has no key handling or `scrollToIndex` | H |
| 7 | Columns can't be resized, reordered, hidden or sorted. The template is a fixed `grid-template-columns`. Host shows `scheme://host:port` on every row, which wastes about 16rem on repeated text. | `.row` | M |
| 8 | The header row is a separate block from the scrolling body. With a scrollbar present, header and body columns drift by the scrollbar width. | `.row.head` vs `.vl { overflow-y: auto }` | M |
| 9 | Filtering is eight unlabeled inputs behind a submit button. It has no query language, no saved filters, and no chips showing what is active. Free-text search goes to the server while the other filters also run client-side in `matches()`, so there are two filter implementations. A text filter turns live updates into a "N new" counter instead of live results. | `History.svelte` toolbar, `matches`, `pending` | H |
| 10 | No multi-select, so bulk delete, bulk send and bulk tag are impossible. There is no context menu and no per-row actions. Row state (tags, notes, edited, WebSocket, error) is not visible in the row. | `open(f)` is the only row action | H |
| 11 | Status is encoded by colour only (`.st-2` to `.st-5`). Method has no colour. Numeric columns lack tabular numerals, so digits jitter while scanning. | `.st-*`, `app.css` | M |
| 12 | `VirtualList` is fixed at 24px rows. Row keys are `start + i` (index-based), so every scroll step re-keys the DOM. It calls `onNearEnd` on every scroll event. | `VirtualList.svelte` | M |

### Message viewer
| # | Finding | Evidence | Sev |
|---|---|---|---|
| 13 | No syntax highlighting, search, line numbers, wrap toggle, JSON/HTML pretty-print or collapse. The body is one `<pre>` using `word-break: break-all`, which splits tokens mid-word. A 256 KiB page is rendered into one DOM node. | `MessageView.svelte` | H |
| 14 | "Original (before edits)" replaces the panes instead of diffing them. There is no way to see what a match-and-replace rule or an intercept edit changed. | `History.svelte` `detailTab`, `parts()` | H |
| 15 | The view mode (raw, headers, hex, render) is per message pane and resets on every flow because of the `{#key}`. Choosing "headers" for 50 requests in a row means 50 re-clicks. | `MessageView` local `view`; `{#key ...}` in History | M |
| 16 | The render view is a hard `background: #fff` iframe. In dark mode it is a glare block. The sandbox itself is correct and must stay. | `.render` | L |
| 17 | The view names are lowercase tab labels with no icons, counts or sizes. The headers view is a `kv` table with no per-header actions (copy, add to match & replace, filter by). | `MessageView` | L |

### Intercept
| # | Finding | Evidence | Sev |
|---|---|---|---|
| 18 | The queue is a list of truncated one-line strings (`phase METHOD url status`). Forward and Drop are in the top toolbar, far from the message being edited. There are no shortcuts, and the edit pane is a bare textarea. | `Intercept.svelte` | H |
| 19 | The held request can't be compared with the original while editing, and can't be sent to another tool. | `Intercept.svelte` | M |

### Visual system
| # | Finding | Evidence | Sev |
|---|---|---|---|
| 20 | There are about 12 colour tokens and no semantic layers: no method, status, syntax, diff, severity or surface-elevation tokens. Colour is hard-coded in places (`#000` on accent, `#fff`, `#111`). | `app.css`, `App.svelte` | M |
| 21 | The theme follows `prefers-color-scheme` only, with no manual switch. The light palette overrides only some tokens, so `--accent`, `--ok` and the others are shared across themes without separate contrast checks. | `app.css` | M |
| 22 | Every `button` has a 1px border, a fill and a 4px radius, so toolbars read as rows of boxes. This is the "heavy borders" look to avoid. Navigation buttons correctly have no border. | `app.css` `button` | M |
| 23 | The fonts are `system-ui` and `ui-monospace` stacks with no bundled fonts. Windows, macOS and Linux webviews will each render differently. | `app.css` | L |

### Cross-tool workflow
| # | Finding | Sev |
|---|---|---|
| 24 | There is no command palette, no shortcut registry and no context menu anywhere. Moving anything between views means copy and paste. | H |
| 25 | No shared selection or "current flow" exists. Each page fetches its own data independently, so tools can't share a flow without reloading it. | H |
| 26 | Target and History don't talk to each other. You can add a host to scope from Target, but not from a History row. Site-map paths can't open the matching flows. | M |

---

## 2. Modular layout and windowing architecture

### 2.1 Decision: build a small layout engine, don't adopt a docking library yet
The project ships no runtime UI dependencies, has a supply-chain posture (`cargo deny`, pinned versions), and a CSP
that bans inline styles. Most docking libraries (golden-layout, rc-dock) are not Svelte-native.
`dockview-core` is framework-agnostic and the most plausible candidate. **Spike first** (2 days): check that it
works under the CSP and with Svelte 5 snippets, how large it is, and whether its drag overlays support the
quadrant targets below. If the spike passes, adopt it. If not, build the engine in 2.2. Everything else in this
plan is independent of the choice, because panels talk only to the `workspace` store.

### 2.2 Model
```ts
// web/src/lib/workspace.svelte.ts
type PanelId = 'history' | 'intercept' | 'target' | 'rules' | 'repeater' | 'decoder' | 'compare' | 'scanner' | 'settings' | 'projects';

type Node =
  | { kind: 'split'; dir: 'row' | 'col'; sizes: number[]; children: Node[] }   // sizes sum to 1
  | { kind: 'group'; active: string; tabs: Tab[] };                            // a tab stack

interface Tab { id: string; panel: PanelId; params?: Record<string, unknown>; pinned?: boolean }

interface Workspace { version: 1; root: Node; windows: Record<string, Node>; presets: Record<string, Node> }
```
- The tree is the single serialisable source of truth. Sizes are fractions. Panels receive their size from CSS
  custom properties set through `use:css` on the split container (`--size-0`, `--size-1`), so it stays
  CSP-compliant.
- A **panel registry** maps `PanelId` to `{ component, title, icon, singleton?: boolean, minSize }`. History,
  Intercept, Target, Rules, Settings and Projects are singletons. Repeater and Decoder allow many tabs.
- **Keep-alive.** Panels stay mounted when their tab is inactive (hidden with the `hidden` attribute, not
  `{#if}`). This fixes finding 1. Page-level state that matters (filters, selection, scroll) also moves into
  stores (`historyView.svelte.ts`) so it survives a panel being closed and reopened. The `{#key generation}`
  project-switch remount becomes a per-panel key bump.

### 2.3 Interactions
| Capability | Spec |
|---|---|
| Draggable tabs | Pointer events (not HTML5 drag), with a 4px move threshold. Drag a tab to reorder within its group, or onto another group. Middle-click closes. Double-click maximises the group. |
| Split-pane resize | 4px hit area drawn as a 1px line. Cursor changes on hover, double-click resets to the default size, arrow keys resize when focused (`role="separator"`, `aria-valuenow`). Min sizes come from the registry. |
| Quadrant docking | While dragging, show five drop zones on the hovered group: centre (merge as tab), and top, bottom, left, right (split at 50%). The outer window edges also accept a drop, which makes a full-width or full-height split at the root. |
| Pop-out windows | See 2.4. |
| Presets | Built-ins: **Triage** (History on the left, request and response stacked on the right), **Intercept** (queue on the left, editor on the right, History in a bottom strip), **Focus** (one panel, no chrome). Users can save, rename, delete, export and import a preset as JSON. |
| Reset | A "Reset layout" command always exists. A layout that fails validation on load falls back to Triage and logs a warning. |

### 2.4 Pop-out windows and the threat model
- A pop-out is the same web app at `/#/popout/<windowId>`, opened with `window.open` in the browser build.
  It is same-origin, so it shares the session cookie. It calls `/auth/me` for its own CSRF token (`setCsrf` is
  held in memory per window), and opens its own event WebSocket.
- Windows share layout and selection through `BroadcastChannel('bosun-workspace')`. The server stays the
  source of truth for flow data, so no message payload carries bodies. Messages carry flow ids and layout
  deltas only.
- **Desktop (Tauri).** The rule that the window may navigate only to the engine's own origin and exposes no IPC
  commands must hold. A pop-out therefore needs a Rust-side window-creation path restricted to the same origin,
  with no new IPC surface exposed to the page. That is a `bosun-desktop` change and needs a threat-model update.
  Until then, the desktop build hides the pop-out command rather than weakening the rule. **This needs a decision
  from you before Phase 4.**
- Target content continues to appear only as text or in the empty-`sandbox` iframe. Drag payloads carry flow
  ids, never bodies, so no new path puts target content into the UI's origin.

### 2.5 Persistence
- Layout and presets: `localStorage` key `bosun.workspace.v1`, validated against the schema on load. Per
  browser profile, no server work, and a corrupt value is discarded.
- Phase 4 option: store presets per user on the server so they follow the user between browser and desktop.
  Layout is a UI preference, not scope, rules, accounts or tokens, so it would not need an audit entry. Say if
  you want it audited anyway.

---

## 3. Typography, colour and data visualisation

### 3.1 Type scale
Bundle the fonts from `web/public/` and serve them from the same origin (CSP allows only own origin; confirm
`font-src` in the CSP header before adding `@font-face`). Suggested: **Inter** (UI) and **JetBrains Mono** (data),
both OFL-licensed. Fall back to the current system stacks so a missing font file degrades cleanly.

| Token | Size / line | Use |
|---|---|---|
| `--fs-xs` | 11 / 14 | Badges, column headers, status bar |
| `--fs-sm` | 12 / 16 | UI default: toolbars, tabs, forms |
| `--fs-md` | 13 / 18 | Panel titles, dialog body |
| `--fs-lg` | 15 / 20 | Page headings (rare) |
| `--fs-data` | 12 / 16 (mono) | Table rows, message bodies, hex |

Rules:
- All numeric table columns (`#`, status, length, time) use `font-variant-numeric: tabular-nums`.
- Use `font-variant-ligatures: none` in code so `!=` and `=>` show the real characters.
- Wrap bodies at word boundaries (`overflow-wrap: anywhere` only for tokens with no break points), not
  `break-all`. Offer a **wrap toggle** (off by default for hex and headers).

### 3.2 Density
- Row height **22px** default, with a **20px compact** and **26px comfortable** setting (a CSS custom property,
  read by `VirtualList` through its `rowHeight` prop). Cell padding is 0 6px. Toolbars are 28px.
- No card grids and no large paddings: panel padding is 8px, group gaps are 1px lines, not spacing.
- Replace per-button borders with a **flat button**: no border, transparent fill, hover fill, 4px radius.
  Reserve the outlined style for the primary and destructive actions only. This addresses finding 22.

### 3.3 Semantic colour tokens
Never use raw hex in components. Components reference semantic tokens only. The values below are **starting
points**: the contrast ratios have not been computed. Add a small script in CI that fails if a text token has
less than 4.5:1 against its surface in either theme.

Surfaces and text: `--surface-0` (app), `--surface-1` (panel), `--surface-2` (raised/hover), `--surface-sel`
(selection), `--border-subtle`, `--border-strong`, `--text-1`, `--text-2` (muted), `--text-3` (disabled),
`--accent`, `--focus-ring`.

| Group | Tokens (dark / light starting values) |
|---|---|
| HTTP methods | `--m-get` #5aa6e8 / #1f6fb5, `--m-post` #5fbf77 / #1f7a3a, `--m-put` #e3b341 / #8a6200, `--m-patch` #4fc3b0 / #0f7566, `--m-delete` #e5534b / #b3261e, `--m-other` (HEAD, OPTIONS, etc.) uses `--text-2` |
| Status | `--st-2xx` green, `--st-3xx` blue, `--st-4xx` amber, `--st-5xx` red, `--st-err` red with a **✕** glyph. The colour is never the only signal: 4xx and 5xx also get a medium weight, and errors show the glyph. |
| Syntax | `--sx-key`, `--sx-string`, `--sx-number`, `--sx-bool` (also null), `--sx-punct`, `--sx-hname`, `--sx-hvalue`, `--sx-tag`, `--sx-attr`, `--sx-comment` |
| Diff | `--df-add-bg`, `--df-del-bg` (about 15% alpha of green and red), `--df-add-word`, `--df-del-word` (about 35% alpha, for word-level highlights), plus `+` and `−` gutter markers so colour-blind users can read it |
| State | `--ok`, `--info`, `--warn`, `--bad` (kept), plus `--held` for intercepted items |

Theme: `data-theme="dark|light|system"` on `<html>`, a toggle in the status bar, and the choice kept in
`localStorage`. The light palette is designed separately, not derived from the dark one. The render iframe gets
the same dark surface in dark mode where the page allows it (a `srcdoc` wrapper with `color-scheme`), while
keeping `sandbox=""`.

### 3.4 Syntax highlighting without `{@html}`
Write a small tokeniser (no dependency) for the HTTP start line and headers, JSON, HTML/XML, URL-encoded forms and a
light JavaScript pass. It returns `{ text, cls }[]` per line and the component renders spans with
`{#each}`. Class names map to the `--sx-*` tokens, so this complies with the "no `{@html}` with target content"
rule. Tokenise only the visible lines of a windowed body view. Past a size cap (suggest 1 MiB per message) fall
back to plain text with a notice. **Fuzz the tokeniser**: it parses untrusted input, so `CLAUDE.md` requires a fuzz
target in `fuzz/fuzz_targets/` and a CI matrix entry. (The existing fuzz targets are Rust, so the tokeniser's
robustness test may belong in Vitest/proptest-style property tests instead. Confirm the project's preference.)

### 3.5 The history table
Default columns: `#`, a state glyph column (edited, note, WS, error), Method (coloured, 5 characters wide),
Host (scheme dropped, port shown only when non-default), Path (flex, middle-ellipsis with the full URL in a
tooltip), Status, Length, MIME (short form: `json`, `html`), Time (relative on hover, absolute in the cell).
Out-of-scope rows are dimmed (already done). A 2px left bar marks the selected row and tagged rows get a small
coloured dot. Sticky header lives inside the scroller, so it never drifts.

### 3.6 Message viewer features
Line numbers, find-in-message (Ctrl+F with match count, next/prev), pretty-print for JSON, HTML and XML
(display-only, the stored bytes are unchanged), a wrap toggle, a copy-selection and copy-as-cURL action, and a
**diff mode** for Original versus current (word-level, gutter markers, collapsed unchanged regions). View mode
(raw, headers, hex, render) is a global preference with a per-pane override, so it stops resetting.

---

## 4. Cross-tool workflow and navigation

### 4.1 A shared command registry
```ts
// web/src/lib/commands.ts
interface Command { id: string; title: string; keys?: string; when?: () => boolean; run: (ctx: Ctx) => void }
// Ctx = { flows: number[]; tab?: Tab; panel?: PanelId }   // ids only, never bodies
```
Everything below (palette, context menu, shortcuts, toolbar buttons) is a view onto this one registry, so
adding a tool means registering commands, not editing four places. Commands declare `when`, so Repeater commands
stay hidden until a role (`tester`) and the panel exist. Role checks must still happen in the API
(`caller.require`), the UI check is only convenience.

### 4.2 Command palette
`Ctrl+K` opens a centred, 520px list: fuzzy search over commands, panels, presets, hosts from the site map and
recent flow ids (`#1234`). Prefix modes: `>` commands (default), `#` flow by id, `/` host or path, `@` panel.
Arrow keys and Enter, Esc closes, and the last-used commands sort first. Build it as a dialog with
`role="dialog"` and a proper focus trap so `svelte-check` a11y stays clean.

### 4.3 Shortcuts (proposed, resolve conflicts with the browser and Tauri before fixing them)
| Scope | Keys | Action |
|---|---|---|
| Global | `Ctrl+K` | Command palette |
| Global | `Ctrl+1…9` | Focus panel by dock order |
| Global | `Ctrl+\` | Split the active group right |
| Global | `Ctrl+Shift+\` | Maximise or restore the active group |
| Global | `Ctrl+Shift+I` | Toggle intercept (with a visible state in the status bar) |
| History | `j` / `k`, `↑` / `↓` | Move selection, scroll into view |
| History | `Enter` | Open in the detail pane |
| History | `Space` | Toggle pause or follow on the live tail |
| History | `Shift+↑/↓`, `Ctrl+A` | Extend or select all |
| History | `/` | Focus the filter bar |
| History | `Delete` | Delete (tester role, with undo toast) |
| Any flow | `Ctrl+R` | Send to Repeater |
| Any flow | `Ctrl+E` | Send to Decoder |
| Any flow | `Ctrl+D` | Add to Compare (first press sets A, second sets B) |
| Any flow | `Ctrl+Shift+S` | Add host to scope |
| Intercept | `F` / `D` / `Shift+F` | Forward / Drop / Forward all |
| Message | `Ctrl+F` | Find in message |

### 4.4 Context menus
Right-click or the menu key on a row, a header, or selected text. Flat 1px-border menus, 24px items, keys shown
at the right, submenus kept to one level. History row: Send to (Repeater, Decoder, Compare A/B, Scanner), Copy
(URL, as cURL, request, response), Scope (add host, exclude host), Tag, Note, Delete. Selected text in a
message: Send to Decoder, Search in History, Add to match & replace. Use `role="menu"` and `role="menuitem"`.

### 4.5 Drag and drop
Dragging one or more rows carries `application/x-bosun-flow` with **flow ids only**. Drop targets: a dock zone
(creates a Repeater tab or whichever tool the zone belongs to), an existing tool tab, the Compare A/B slots, and
the tag chips in a sidebar. A drag preview shows the count. Dropping never copies bodies in the page: the
receiving tool fetches by id from the API, so the scope gate, audit and role checks still apply.

### 4.6 Keeping state across tools
- A `selection` store holds `{ flowIds, focusFlow }`. History, Target, Intercept and the other tools read it, so
  selecting a flow in History shows it in an open Compare slot or a Repeater "origin" link without a reload.
- Sending to Repeater creates a **tab** with `params.originFlow`, and that tab is persisted by the server (M2
  plans Repeater tabs in the store). The Repeater edit buffer lives in the tab, so closing the panel doesn't lose it.
- **Deep links.** Routes become `#/history?flow=1234`, `#/repeater/<tab>`. A reload restores layout and selection.
- A **status bar** (22px) always shows: connection, intercept on/off with the held count, current project,
  scope summary, role, the layout preset and the theme toggle. Project and user move out of the header here.
- Undo toasts for destructive actions (delete flows) that call the API only after a 5-second window, or call a
  restore endpoint if one exists. Check with the API owner which is feasible.

### 4.7 Intercept
Two-column: the queue as a compact table (phase, method, host, path, age), with a held-time countdown for the
auto-forward timeout. The editor opens beside it with Forward, Drop and Forward all pinned to the editor's own
toolbar. A Diff toggle compares the edit against the original. The status bar shows the held count and flashes
once for a new item. It does not steal focus.

---

## 5. Phased implementation plan

Estimates are in engineering days for one person who knows the code, and exclude review. They are rough.

### Phase 0: foundation and quick wins (about 5 days, no architecture change)
**Status (branch `ui-phase0`, uncommitted):** built and passing `npm run check`, `npm run build` and the e2e suite
(11 tests, 2 new). Two deliberate differences from the table: fonts are *not* bundled yet (refined system stacks
instead; bundling needs font files added to the repo), and the header stays outside the scroller but shares its
reserved scrollbar gutter, which fixes the drift without changing the list's scroll maths. The live tail also
holds new rows while the pointer is over the list, not only when scrolled or paused.

| Task | Component and spec | Fixes |
|---|---|---|
| Token layer | Rewrite `app.css` into `tokens.css` (surfaces, text, method, status, syntax, diff) plus `base.css`. `data-theme` switch. Contrast script in CI. | 20, 21 |
| Fonts and numerals | Bundle Inter and JetBrains Mono. Type scale tokens. `tabular-nums` on numeric columns. | 11, 23 |
| Flat buttons | Restyle `button` as flat. Add `.btn-primary` and `.btn-danger`. | 22 |
| History table | Method and status colours (with glyphs). Drop the scheme from Host. Move the header into the scroller (sticky). Row height token. | 7, 8, 11 |
| Live tail | `follow` flag (default on when scrolled to top). If the user has scrolled or selected, buffer new flows and show "N new" instead of inserting. | 5 |
| Keyboard in `VirtualList` | `scrollToIndex`, `activeIndex`, `onkeydown` on the list (`role="listbox"` with `aria-activedescendant`), and stable keys by flow id. | 6, 12 |
| Persist view state | Move History filters, selection and view mode into `historyView.svelte.ts`. Restore on remount. | 1, 15 |
| Intercept shortcuts | `F` / `D` / `Shift+F`, plus move the buttons to the editor toolbar. | 18 |

Acceptance: `npm run check` and `npm run build` pass, e2e still green, and a Playwright test covers "select a
flow, switch tab, come back, selection and filters are intact".

### Phase 1: workspace engine (about 8 to 10 days, after the dock-library spike)
**Status (branch `ui-phase0`):** built. The spike ruled `dockview-core` out (reasons in `docs/architecture.md`), so the engine is our own: `lib/layout.ts` (pure model, 14 tests including a seeded random walk), `workspace.svelte.ts` (store, persistence, presets), `components/dock/`. Differences from the table: History is now two panels (list and **Request / response**) so Triage can place them side by side; a panel that is moved to another group remounts (its state lives in stores); the status bar shows project, intercept, open request and connection, but not yet the scope or flow counts.
| Task | Component and spec |
|---|---|
| Spike | 2 days: `dockview-core` under the CSP with Svelte 5. Decision recorded in `docs/architecture.md`. |
| `workspace.svelte.ts` | Tree model, schema validation, `localStorage` persistence, migrations by `version`. Unit tests (including property tests for split/merge invariants: sizes sum to 1, no empty groups). |
| `Dock.svelte`, `SplitPane.svelte`, `TabGroup.svelte` | As in 2.2 and 2.3. Panel registry. Keep-alive rendering. |
| Pages become panels | Wrap the existing pages. Replace `App.svelte`'s page switch. Per-panel `generation` key. |
| Presets | Triage, Intercept, Focus built-ins. Save, rename, delete, import and export. "Reset layout". |
| Status bar | Per 4.6. |

Acceptance: layout survives reload, a corrupt saved layout falls back safely, drag tab to quadrant works with
the mouse and has a keyboard alternative (move panel command in the palette).

### Phase 2: the viewer (about 8 days)
| Task | Component and spec |
|---|---|
| Tokeniser | `lib/highlight/*.ts` for HTTP, JSON, HTML/XML, forms and light JS. Render by `{#each}`. Size cap. Tests and a robustness test per 3.4. |
| `CodeView.svelte` | Windowed, line-numbered, wrap toggle, find. Replaces the `<pre>` in `MessageView`. |
| Pretty-print | Display-only JSON, HTML and XML. |
| `DiffView.svelte` | Line and word diff (a small Myers implementation, bounded). Used for Original versus current and for Compare. |
| Headers view | Table with copy and "filter History by this" per header. |
| Dark-mode render | Themed `srcdoc` wrapper, `sandbox=""` unchanged. |

Acceptance: a 256 KiB JSON body scrolls without jank, and the sandbox, CSP and "no target content in the UI
origin" tests (e2e) are unchanged and passing.

### Phase 3: commands and cross-tool flow (about 8 days; Repeater and Decoder integration lands with M2)
| Task | Component and spec |
|---|---|
| `commands.ts` and `shortcuts.ts` | Registry, key matching with chords, a conflict report, and a "Keyboard shortcuts" help overlay. |
| `CommandPalette.svelte` | Per 4.2. |
| `ContextMenu.svelte` | Per 4.4, accessible roles. |
| Multi-select in History | Shift/Ctrl click, keyboard extension, and a selection bar with bulk actions. |
| Filter bar | One query line with chips (`host:`, `method:`, `status:`, `ext:`, `scope:`, free text). Replaces the eight inputs. Saved filters. The same query is applied by the server, which removes the duplicated client `matches()` (needs an API change, coordinate with the API owner). |
| Drag and drop | Per 4.5. |
| Deep links | Per 4.6. |
| Tool hooks | `Send to Repeater / Decoder / Compare` commands register themselves when the tool panels exist. Until then they are hidden. |

### Phase 4: pop-out and shared state (about 5 days, desktop part depends on a decision)
| Task | Component and spec |
|---|---|
| Browser pop-out | Per 2.4, with `BroadcastChannel` sync and a per-window CSRF fetch. |
| Desktop pop-out | Rust-side same-origin window creation without IPC. Update `threat-model.md`. Skip if you decline. |
| Server-side presets | Optional, per 2.5. |

### Phase 5: hardening and polish (about 4 days)
Accessibility pass with the keyboard only and a screen reader on the dock, tabs, menus and table. Light theme
review at the contrast threshold. Performance check at 100k rows (scroll, filter, live tail). Playwright specs for
layout, palette, shortcuts, drag and drop, and pop-out. Update `docs/testing.md` and `docs/threat-model.md` where
behaviour changed.

### Risks
- **Scope creep into M2.** Repeater, Decoder, Compare and Scanner panels are separate work owned by M2. This plan
  provides their hosting, commands and drag targets, and doesn't build the tools.
- **a11y warnings fail CI.** Custom tab, menu, listbox and separator widgets will need correct roles and keyboard
  handling from the start.
- **Layout bugs are user-hostile.** Always validate and fall back, and keep "Reset layout" reachable from the
  palette even if the dock fails to render.
- **Colour values and contrast are unverified.** Treat 3.3 as a draft until the CI script runs.

### Decisions (resolved 2026-11-25)
1. **Dock library:** run the `dockview-core` spike first (Phase 1). Build our own engine only if it fails.
2. **Desktop pop-out:** browser-only for now. The desktop build hides the command. No `bosun-desktop` change and no
   threat-model change. Revisit after the dock ships.
3. **Presets:** `localStorage` only, with JSON import and export. Server-side presets are deferred.
4. **Shortcuts:** Burp-like (`Ctrl+R` for Repeater), as in 4.3.
5. **Filter query:** server-side, in Phase 3. Phases 0 to 2 keep the current filters. This needs an API change,
   so coordinate with the session that owns the API.
