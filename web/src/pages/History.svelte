<script lang="ts">
  // The request list. Opening a request is the flow-detail panel's job: this panel only sets `historyView.openId`.
  import { isTyping } from '../lib/typing';
  import { onMount, untrack } from 'svelte';
  import { api, qs } from '../lib/api';
  import { css } from '../lib/style';
  import { commands, currentCtx } from '../lib/commands.svelte';
  import { contextMenu } from '../lib/contextmenu.svelte';
  import { changeTags, deleteFlows } from '../lib/flowactions';
  import { colOf, highlightOf, HL_COLORS, HL_PREFIX, COLS, nextSort, plainTags, template, type ColKey } from '../lib/histcols';
  import { historyView as v } from '../lib/historyView.svelte';
  import { tidyMenu, type MenuItem } from '../lib/menu';
  import { usePanel } from '../lib/panelctx';
  import { matchesFlow, parseQuery } from '../lib/query';
  import { prefs } from '../lib/prefs.svelte';
  import { session } from '../lib/session.svelte';
  import { format } from '../lib/shortcuts';
  import { workspace } from '../lib/workspace.svelte';
  import { flowUrl, fmtSize, fmtTime } from '../lib/bytes';
  import type { FlowSummary } from '../lib/types';
  import VirtualList from '../components/VirtualList.svelte';
  import FilterBar from '../components/FilterBar.svelte';
  import Menu from '../components/Menu.svelte';

  /** Row height in px: the one source for the list maths and the row CSS (--row-h). */
  const ROW_H = 22;
  /** The MIME type a dragged selection carries: flow ids only, never message bodies. */
  const FLOW_DND = 'application/x-bosun-flow';

  const panel = usePanel();
  // Rows are only ever replaced, never edited in place, so no deep proxy: with 100,000 rows a proxy per row is slow.
  let flows = $state.raw<FlowSummary[]>([]);
  let loadingMore = false;
  let exhausted = false;

  const parsed = $derived(parseQuery(v.query));
  const filter = $derived(parsed.filter);
  /** What the list shows: the loaded flows, minus any in the undo window of a delete. */
  const shown = $derived(v.pending.length ? flows.filter((f) => !v.pending.includes(f.id)) : flows);
  const selSet = $derived(new Set(v.selected));

  // Live tail. New flows are shown at once only when that moves nothing under the user: the list is at the top, the
  // pointer is not over it, and the tail is not paused. Otherwise they wait here and "N new" shows them.
  let held = $state.raw<FlowSummary[]>([]);
  /** New flows that can't be matched on this side (a text search is active), so showing them means reloading. */
  let unmatched = $state(0);
  let paused = $state(false);
  let hovering = false;
  let list = $state<{ scrollToTop(): void; atTop(): boolean } | undefined>();
  let bar = $state<{ focus(): void } | undefined>();
  let root = $state<HTMLElement | undefined>();
  const waiting = $derived(held.length + unmatched);
  // A sorted list is a snapshot: a new flow has no place in it that this side can work out.
  const simpleFilter = $derived(!filter.text && !filter.serverOnly && v.sort.key === 'id' && !v.sort.asc);
  const cols = $derived(v.cols);
  const gridCols = $derived(template(cols));
  const activeIndex = $derived(v.selectedId === null ? -1 : shown.findIndex((f) => f.id === v.selectedId));
  const canEdit = $derived(session.can('tester'));

  function params(extra: Record<string, number | undefined> = {}) {
    // The whole line goes to the server, which owns the grammar (docs/query-language.md).
    return qs({ q: v.query.trim() || undefined, sort: v.sort.key === 'id' ? undefined : v.sort.key, asc: v.sort.asc || undefined, limit: 500, ...extra });
  }

  async function reload() {
    held = [];
    unmatched = 0;
    exhausted = false;
    flows = await api.get<FlowSummary[]>(`/flows${params()}`);
  }

  async function more() {
    if (loadingMore || exhausted || !flows.length) return;
    loadingMore = true;
    try {
      // The id order pages by the last id; any other order pages by how many rows are already loaded.
      const at = v.sort.key === 'id' ? { before: flows[flows.length - 1]!.id } : { offset: flows.length };
      const next = await api.get<FlowSummary[]>(`/flows${params(at)}`);
      if (!next.length) exhausted = true;
      flows = [...flows, ...next];
    } finally {
      loadingMore = false;
    }
  }

  const canFollow = () => !paused && !hovering && (list?.atTop() ?? true);

  /** Show what has been waiting. */
  function flush() {
    if (unmatched) {
      reload();
      return;
    }
    if (held.length) flows = [...held, ...flows];
    held = [];
  }

  function follow() {
    if (waiting && canFollow()) flush();
  }

  let openTimer: ReturnType<typeof setTimeout> | undefined;

  /** Open a flow in the detail panel. */
  function open(f: { id: number }) {
    clearTimeout(openTimer);
    v.select([f.id], f.id);
    v.openId = f.id;
    // Opening a request on purpose brings the detail panel up if it was closed.
    workspace.reveal('flow', 'history');
  }

  /** Select everything from the anchor to row `i`. */
  function selectRange(i: number) {
    const a = shown.findIndex((f) => f.id === (v.anchorId ?? v.selectedId));
    const from = a < 0 ? i : a;
    const [lo, hi] = from < i ? [from, i] : [i, from];
    v.selected = shown.slice(lo, hi + 1).map((f) => f.id);
    v.selectedId = shown[i]!.id;
  }

  /** Arrow-key movement: highlight at once, load the detail once the user stops for a moment. */
  function moveTo(i: number, extend: boolean) {
    const f = shown[i];
    if (!f) return;
    if (extend) {
      selectRange(i);
      return;
    }
    v.select([f.id], f.id);
    clearTimeout(openTimer);
    openTimer = setTimeout(() => (v.openId = f.id), 90);
  }

  function onRowClick(e: MouseEvent, f: FlowSummary, i: number) {
    if (e.shiftKey) selectRange(i);
    else if (e.ctrlKey || e.metaKey) {
      const had = selSet.has(f.id);
      v.selected = had ? v.selected.filter((x) => x !== f.id) : [...v.selected, f.id];
      v.selectedId = had ? (v.selected[v.selected.length - 1] ?? null) : f.id;
      v.anchorId = f.id;
    } else open(f);
  }

  function selectAll() {
    v.selected = shown.map((f) => f.id);
    v.selectedId ??= shown[0]?.id ?? null;
  }

  function deleteSelected() {
    if (canEdit) deleteFlows(v.ids);
  }

  // A flow was deleted for good elsewhere (the detail panel, or an undo window that passed).
  let seenRemoval = untrack(() => v.removedTick);
  $effect(() => {
    const tick = v.removedTick;
    untrack(() => {
      if (tick === seenRemoval) return;
      seenRemoval = tick;
      flows = flows.filter((f) => !v.removedIds.includes(f.id));
    });
  });

  // The filter was applied (typed, a chip removed, or set from outside such as the headers view).
  let seenApply = untrack(() => v.applyTick);
  $effect(() => {
    const tick = v.applyTick;
    untrack(() => {
      if (tick === seenApply) return;
      seenApply = tick;
      reload();
    });
  });

  // Tags changed on the server (a menu, the selection bar, the detail panel): patch the rows that are loaded.
  let seenTag = untrack(() => v.tagTick);
  $effect(() => {
    const tick = v.tagTick;
    untrack(() => {
      if (tick === seenTag || !v.tagChange) return;
      seenTag = tick;
      const { ids, add, remove } = v.tagChange;
      const set = new Set(ids);
      const low = (t: string) => t.toLowerCase();
      flows = flows.map((f) => {
        if (!set.has(f.id)) return f;
        const kept = f.tags.filter((t) => !remove.some((r) => low(r) === low(t)));
        for (const a of add) if (!kept.some((t) => low(t) === low(a))) kept.push(a);
        return { ...f, tags: kept };
      });
    });
  });

  // ---- columns, sorting, highlights, bulk tags
  const colItems = $derived<MenuItem[]>([
    { kind: 'heading', label: 'Columns' },
    ...COLS.map((c): MenuItem => ({
      label: c.title === '#' ? 'Number' : c.title,
      checked: cols.includes(c.key),
      disabled: !!c.required,
      run: () => v.setCols(cols.includes(c.key) ? cols.filter((k) => k !== c.key) : [...cols, c.key]),
    })),
  ]);
  const sortLabel = (k: ColKey): 'ascending' | 'descending' | 'none' => {
    const s = colOf(k).sort;
    return s && v.sort.key === s ? (v.sort.asc ? 'ascending' : 'descending') : 'none';
  };
  function sortBy(k: ColKey) {
    const s = colOf(k).sort;
    if (s) v.setSort(nextSort(v.sort, s));
  }
  let tagging = $state(false);
  let tagText = $state('');
  let tagBox = $state<HTMLInputElement | undefined>();
  async function addTag(e: Event) {
    e.preventDefault();
    const t = tagText.trim();
    if (!t || !(await changeTags(v.ids, [t], []))) return;
    tagText = '';
    tagging = false;
  }
  /** Set (or with null clear) the highlight colour of the selection. */
  const highlight = (c: (typeof HL_COLORS)[number] | null) => changeTags(v.ids, c ? [HL_PREFIX + c] : [], HL_COLORS.filter((x) => x !== c).map((x) => HL_PREFIX + x));

  // ---- context menu

  function menuFor(): MenuItem[] {
    const ctx = currentCtx();
    const c = (id: string, label?: string): MenuItem | null => {
      const cmd = commands.find(id);
      if (!cmd || !commands.isEnabled(cmd, ctx)) return null;
      return { label: label ?? cmd.title, hint: cmd.keys ? format(cmd.keys) : undefined, run: () => void commands.run(id, ctx) };
    };
    return tidyMenu([
      { kind: 'heading', label: 'Send to' }, c('flow.repeater', 'Repeater'), c('flow.intruder', 'Intruder'),
      c('flow.organize', 'Organizer'),
      c('flow.decoder.request', 'Decoder: request'), c('flow.decoder.response', 'Decoder: response'),
      c('flow.comparer.request.a', 'Comparer: request as A'), c('flow.comparer.request.b', 'Comparer: request as B'),
      c('flow.comparer.response.a', 'Comparer: response as A'), c('flow.comparer.response.b', 'Comparer: response as B'),
      { kind: 'sep' }, { kind: 'heading', label: 'Copy' },
      c('flow.copy-url', 'URL'), c('flow.copy-curl', 'as cURL'), c('flow.copy-curl-powershell', 'as PowerShell'),
      c('flow.snippet.python', 'as Python'), c('flow.snippet.javascript', 'as JavaScript'), c('flow.snippet.go', 'as Go'),
      { label: 'Keep cookies and authorization values', checked: prefs.exportSecrets, run: () => prefs.setExportSecrets(!prefs.exportSecrets) }, c('flow.copy-request', 'Request'), c('flow.copy-response', 'Response'),
      ...(canEdit ? [{ kind: 'sep' } as MenuItem, { kind: 'heading', label: 'Highlight' } as MenuItem, ...HL_COLORS.map((c): MenuItem => ({ label: c[0]!.toUpperCase() + c.slice(1), run: () => void highlight(c) })), { label: 'No highlight', run: () => void highlight(null) } as MenuItem, { label: 'Add a tag…', run: () => { tagging = true; setTimeout(() => tagBox?.focus(), 0); } } as MenuItem] : []),
      { kind: 'sep' }, { kind: 'heading', label: 'Scope' }, c('flow.scope.include', 'Add host to scope'), c('flow.scope.exclude', 'Exclude host from scope'),
      { kind: 'sep' }, { kind: 'heading', label: 'Engage' }, c('flow.findings', 'Comments, scripts and references'), c('flow.analyse-host', 'Analyse this host…'), c('flow.csrf-poc', 'CSRF proof of concept…'), c('flow.csrf-poc-auto', 'CSRF proof of concept, auto-submit…'),
      { kind: 'sep' }, c('flow.export-har', 'Export as HAR…'), c('flow.delete', 'Delete'),
    ]);
  }

  function onContext(e: MouseEvent) {
    const rowEl = (e.target as HTMLElement).closest<HTMLElement>('[role="option"]');
    let x = e.clientX;
    let y = e.clientY;
    if (rowEl) {
      const f = shown[Number(rowEl.id.replace('hist-row-', ''))];
      if (f && !selSet.has(f.id)) v.select([f.id], f.id);
    } else {
      // The menu key or Shift+F10 on the focused list: open it at the active row.
      const at = document.getElementById(`hist-row-${activeIndex}`)?.getBoundingClientRect() ?? root?.getBoundingClientRect();
      if (!at || v.ids.length === 0) return;
      x = at.left + 24;
      y = at.bottom;
    }
    e.preventDefault();
    contextMenu.show(menuFor(), x, y, 'Request actions');
  }

  // ---- drag: a selection carries its ids and nothing else

  function onDragStart(e: DragEvent, f: FlowSummary) {
    if (!selSet.has(f.id)) v.select([f.id], f.id);
    const ids = v.ids;
    const dt = e.dataTransfer;
    if (!dt) return;
    dt.setData(FLOW_DND, JSON.stringify({ ids }));
    dt.setData('text/plain', ids.map((i) => `#${i}`).join(' '));
    dt.effectAllowed = 'copy';
    const ghost = document.createElement('div');
    ghost.className = 'drag-ghost';
    ghost.textContent = `${ids.length} request${ids.length === 1 ? '' : 's'}`;
    document.body.appendChild(ghost);
    dt.setDragImage(ghost, 0, 0);
    setTimeout(() => ghost.remove(), 0);
  }

  function statusClass(s: number | null): string {
    if (s === null) return 'st-none';
    return s >= 500 ? 'st-5' : s >= 400 ? 'st-4' : s >= 300 ? 'st-3' : 'st-2';
  }

  const knownMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
  const methodClass = (m: string) => `m-${knownMethods.includes(m) ? m : 'other'}`;

  /** The host as shown in a row: the port only when it is not the scheme's default. */
  function hostLabel(f: FlowSummary): string {
    const def = (f.scheme === 'https' && f.port === 443) || (f.scheme === 'http' && f.port === 80);
    return def ? f.host : `${f.host}:${f.port}`;
  }

  /** One glyph per thing worth noticing on a row; the tooltip spells them out. */
  function marks(f: FlowSummary): { glyphs: string; title: string } {
    const g: string[] = [];
    const t: string[] = [];
    if (f.edited) { g.push('✎'); t.push('edited'); }
    if (f.status === 101) { g.push('⇄'); t.push('WebSocket'); }
    if (f.note) { g.push('¶'); t.push('has a note'); }
    const tg = plainTags(f.tags);
    if (tg.length) { g.push('#'); t.push(`tags: ${tg.join(', ')}`); }
    return { glyphs: g.join(''), title: t.join(', ') };
  }

  function onWindowKey(e: KeyboardEvent) {
    const t = e.target as HTMLElement | null;
    const typing = isTyping(e);
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    // The panel stays mounted while hidden, so only react when this panel is the one on screen.
    if (!panel.visible || !root) return;
    if (e.key === '/') {
      e.preventDefault();
      bar?.focus();
    } else if (e.key === ' ' && t?.getAttribute('role') === 'listbox' && root.contains(t)) {
      e.preventDefault();
      paused = !paused;
      follow();
    } else if (e.key === 'Escape' && v.selected.length > 1 && root.contains(t)) {
      v.select(v.selectedId !== null ? [v.selectedId] : []);
    }
  }

  onMount(() => {
    reload();
    const off = session.on((e) => {
      if (e.type === 'reload') {
        reload();
        return;
      }
      if (e.type !== 'flow') return;
      if (simpleFilter) {
        if (!matchesFlow(filter, e.flow)) return;
        if (held.length < 5000) held = [e.flow, ...held];
        follow();
      } else {
        unmatched++;
      }
    });
    return () => {
      off();
      clearTimeout(openTimer);
    };
  });
</script>

<svelte:window onkeydown={onWindowKey} />

<div class="hist" bind:this={root}>
  <FilterBar bind:this={bar}>
    {#if waiting}<button type="button" onclick={() => { flush(); list?.scrollToTop(); }}>{waiting} new</button>{/if}
    <button type="button" class:active={paused} aria-pressed={paused} title="Hold new requests back so the list stays still (Space)" onclick={() => { paused = !paused; follow(); }}>
      {paused ? 'Paused' : 'Following'}
    </button>
  </FilterBar>

  {#if v.selected.length > 1}
    <div class="selbar" role="region" aria-label="Selection">
      <strong class="tnum">{v.selected.length} selected</strong>
      {#if canEdit}<button onclick={() => commands.run('flow.repeater')}>Send to Repeater</button>{/if}
      {#if canEdit}<button onclick={() => { tagging = true; setTimeout(() => tagBox?.focus(), 0); }}>Tag…</button>{/if}
      <button onclick={() => commands.run('flow.copy-url')}>Copy URLs</button>
      <button onclick={() => commands.run('flow.export-har')}>Export HAR</button>
      {#if canEdit}<button class="danger" onclick={deleteSelected}>Delete</button>{/if}
      <span class="spacer"></span>
      <button class="ghost" onclick={() => v.select(v.selectedId !== null ? [v.selectedId] : [])}>Clear selection</button>
    </div>
  {/if}

  {#if tagging}
    <form class="selbar" onsubmit={addTag} aria-label="Add a tag">
      <input aria-label="Tag for {v.ids.length} request{v.ids.length === 1 ? '' : 's'}" placeholder="Tag for {v.ids.length} request{v.ids.length === 1 ? '' : 's'}" maxlength="64" bind:value={tagText} bind:this={tagBox} onkeydown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); tagging = false; } }} />
      <button class="primary">Add tag</button>
      <button type="button" onclick={() => (tagging = false)}>Cancel</button>
    </form>
  {/if}
  <div class="table" use:css={{ '--row-h': `${ROW_H}px`, '--cols': gridCols }}>
    <div class="head-wrap">
      <div class="row head" role="row">
        {#each cols as k (k)}
          {@const c = colOf(k)}
          {#if c.sort}
            <span class="c-{k}" role="columnheader" aria-sort={sortLabel(k)}>
              <button type="button" class="sorter" title="Sort by {c.title}" onclick={() => sortBy(k)}>{c.title}{#if sortLabel(k) !== 'none'}<span aria-hidden="true">{v.sort.asc ? ' ▲' : ' ▼'}</span>{/if}</button>
            </span>
          {:else}
            <span class="c-{k}" role="columnheader" title={k === 'marks' ? 'Marks: edited, WebSocket, note, tags' : undefined}>{k === 'marks' ? '' : c.title}</span>
          {/if}
        {/each}
        <span class="c-pick"><Menu label="Columns" title="Choose the columns" items={colItems} /></span>
      </div>
    </div>
    <div class="body" role="presentation" onpointerenter={() => (hovering = true)} onpointerleave={() => { hovering = false; follow(); }} oncontextmenu={onContext}>
      <VirtualList
        bind:this={list}
        items={shown}
        rowHeight={ROW_H}
        key={(f) => f.id}
        label="HTTP history"
        idPrefix="hist"
        multi
        {activeIndex}
        onNearEnd={more}
        onTop={follow}
        onSelect={moveTo}
        onSelectAll={selectAll}
        onDelete={deleteSelected}
        onActivate={(i) => open(shown[i]!)}
      >
        {#snippet row(f: FlowSummary, i: number)}
          {@const mk = marks(f)}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <div
            class="row"
            id="hist-row-{i}"
            role="option"
            aria-selected={selSet.has(f.id)}
            class:active={selSet.has(f.id)}
            class:focus={v.selectedId === f.id}
            class:oos={!f.in_scope}
            data-hl={highlightOf(f.tags) ?? undefined}
            title={flowUrl(f)}
            draggable="true"
            ondragstart={(e) => onDragStart(e, f)}
            onclick={(e) => onRowClick(e, f, i)}
            tabindex="-1"
          >
            {#each cols as k (k)}
              {#if k === 'id'}<span class="c-id tnum">{f.id}</span>
              {:else if k === 'method'}<span class="c-method {methodClass(f.method)}">{f.method}</span>
              {:else if k === 'marks'}<span class="c-marks" title={mk.title}>{mk.glyphs}</span>
              {:else if k === 'host'}<span class="c-host">{hostLabel(f)}</span>
              {:else if k === 'path'}<span class="c-path">{f.path}</span>
              {:else if k === 'status'}<span class="c-status tnum {statusClass(f.status ?? null)}">{f.error ? '✕ error' : (f.status ?? '…')}</span>
              {:else if k === 'length'}<span class="c-length tnum">{fmtSize(f.response_len ?? 0)}</span>
              {:else if k === 'mime'}<span class="c-mime">{f.mime ?? ''}</span>
              {:else if k === 'time'}<span class="c-time tnum">{fmtTime(f.started_ms)}</span>
              {:else if k === 'duration'}<span class="c-duration tnum">{f.duration_ms == null ? '' : `${f.duration_ms} ms`}</span>
              {:else if k === 'source'}<span class="c-source">{f.source}</span>
              {:else if k === 'tags'}<span class="c-tags">{plainTags(f.tags).join(', ')}</span>
              {/if}
            {/each}
          </div>
        {/snippet}
      </VirtualList>
    </div>
  </div>
</div>

<style>
  .hist { display: flex; flex-direction: column; flex: 1; min-height: 0; container-type: inline-size; }
  .table { display: flex; flex-direction: column; flex: 1; min-height: 0; }
  .body { flex: 1; min-height: 0; }
  .selbar { display: flex; align-items: center; gap: .4rem; padding: .2rem .5rem; background: var(--surface-sel); border-bottom: 1px solid var(--border-subtle); }
  /* The header reserves the same scrollbar gutter as the list below it, so their columns always line up. */
  .head-wrap { overflow-y: hidden; scrollbar-gutter: stable; background: var(--surface-1); border-bottom: 1px solid var(--border-subtle); }
  /* The columns come from --cols (the chooser); the last track is the header's Columns button. */
  .row { display: grid; grid-template-columns: var(--cols) 4.8rem; gap: .5rem; align-items: center; height: var(--row-h); width: 100%; padding: 0 .5rem; text-align: left; font-family: var(--font-mono); font-size: var(--fs-data); cursor: default; }
  .row > span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .row.head { font-family: var(--font-ui); font-size: var(--fs-xs); font-weight: 600; color: var(--text-2); text-transform: uppercase; letter-spacing: .04em; }
  .row:not(.head):hover { background: var(--surface-2); }
  .row.active { background: var(--surface-sel); }
  .row.focus { box-shadow: inset 2px 0 0 var(--accent); }
  .row.oos { color: var(--text-2); }
  .row[data-hl='red'] { background: color-mix(in srgb, var(--bad) 20%, transparent); }
  .row[data-hl='orange'] { background: color-mix(in srgb, var(--warn) 22%, transparent); }
  .row[data-hl='yellow'] { background: color-mix(in srgb, #e6c200 20%, transparent); }
  .row[data-hl='green'] { background: color-mix(in srgb, var(--ok) 20%, transparent); }
  .row[data-hl='blue'] { background: color-mix(in srgb, var(--info) 20%, transparent); }
  .row[data-hl='purple'] { background: color-mix(in srgb, #9b6bd6 22%, transparent); }
  .row.active[data-hl] { background: var(--surface-sel); box-shadow: inset 4px 0 0 var(--text-2); }
  .sorter { background: none; border: 0; padding: 0; font: inherit; color: inherit; text-transform: inherit; letter-spacing: inherit; cursor: pointer; }
  .sorter:hover { color: var(--text-1); }
  .c-pick { overflow: visible !important; text-align: right; }
  .c-marks { color: var(--text-2); letter-spacing: .1em; }
  .c-method { font-weight: 600; }
  .st-2 { color: var(--st-2xx); } .st-3 { color: var(--st-3xx); }
  .st-4 { color: var(--st-4xx); font-weight: 600; } .st-5, .st-none { color: var(--st-5xx); font-weight: 600; }
</style>
