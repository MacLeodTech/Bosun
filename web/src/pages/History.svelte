<script lang="ts">
  // The request list. Opening a request is the flow-detail panel's job: this panel only sets `historyView.openId`.
  import { onMount, untrack } from 'svelte';
  import { api, qs } from '../lib/api';
  import { css } from '../lib/style';
  import { historyView as v } from '../lib/historyView.svelte';
  import { session } from '../lib/session.svelte';
  import { flowUrl, fmtSize, fmtTime } from '../lib/bytes';
  import { usePanel } from '../lib/panelctx';
  import { workspace } from '../lib/workspace.svelte';
  import type { FlowSummary } from '../lib/types';
  import VirtualList from '../components/VirtualList.svelte';

  /** Row height in px: the one source for the list maths and the row CSS (--row-h). */
  const ROW_H = 22;

  const panel = usePanel();
  let flows = $state<FlowSummary[]>([]);
  let loadingMore = false;
  let exhausted = false;

  // Live tail. New flows are shown at once only when that moves nothing under the user: the list is at the top, the
  // pointer is not over it, and the tail is not paused. Otherwise they wait here and "N new" shows them.
  let held = $state<FlowSummary[]>([]);
  /** New flows that can't be matched on this side (a text search is active), so showing them means reloading. */
  let unmatched = $state(0);
  let paused = $state(false);
  let hovering = false;
  let list = $state<{ scrollToTop(): void; atTop(): boolean } | undefined>();
  let searchBox = $state<HTMLInputElement | undefined>();
  const waiting = $derived(held.length + unmatched);
  const simpleFilter = $derived(!v.text);
  const activeIndex = $derived(v.selectedId === null ? -1 : flows.findIndex((f) => f.id === v.selectedId));

  function params(extra: Record<string, number | undefined> = {}) {
    return qs({ text: v.text, host: v.host, methods: v.methods, status_min: v.statusMin, status_max: v.statusMax, in_scope_only: v.inScopeOnly, hide_ext: v.hideExt, limit: 500, ...extra });
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
      const next = await api.get<FlowSummary[]>(`/flows${params({ before: flows[flows.length - 1]!.id })}`);
      if (!next.length) exhausted = true;
      flows = [...flows, ...next];
    } finally {
      loadingMore = false;
    }
  }

  function matches(f: FlowSummary): boolean {
    if (v.host && !f.host.includes(v.host.toLowerCase())) return false;
    if (v.methods && !v.methods.toUpperCase().split(',').map((m) => m.trim()).includes(f.method)) return false;
    if (v.statusMin !== undefined && (f.status ?? 0) < v.statusMin) return false;
    if (v.statusMax !== undefined && (f.status ?? 0) > v.statusMax) return false;
    if (v.inScopeOnly && !f.in_scope) return false;
    const ext = f.path.split('?')[0]!.split('.').pop()?.toLowerCase() ?? '';
    if (v.hideExt && v.hideExt.split(',').map((e) => e.trim().toLowerCase()).includes(ext)) return false;
    return true;
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
    v.selectedId = f.id;
    v.openId = f.id;
    // Opening a request on purpose brings the detail panel up if it was closed.
    workspace.reveal('flow', 'history');
  }

  /** Arrow-key movement: highlight at once, load the detail once the user stops for a moment. */
  function moveTo(i: number) {
    const f = flows[i];
    if (!f) return;
    v.selectedId = f.id;
    clearTimeout(openTimer);
    openTimer = setTimeout(() => (v.openId = f.id), 90);
  }

  // A flow was deleted in the detail panel.
  let seenRemoval = untrack(() => v.removedTick);
  $effect(() => {
    const tick = v.removedTick;
    untrack(() => {
      if (tick === seenRemoval) return;
      seenRemoval = tick;
      flows = flows.filter((f) => !v.removedIds.includes(f.id));
    });
  });

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
    if (f.tags?.length) { g.push('#'); t.push(`tags: ${f.tags.join(', ')}`); }
    return { glyphs: g.join(''), title: t.join(', ') };
  }

  function onWindowKey(e: KeyboardEvent) {
    const t = e.target as HTMLElement | null;
    const typing = !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    // The panel stays mounted while hidden, so only react when this panel is the one on screen.
    if (!panel.visible || !root) return;
    if (e.key === '/') {
      e.preventDefault();
      searchBox?.focus();
    } else if (e.key === ' ' && t?.getAttribute('role') === 'listbox' && root.contains(t)) {
      e.preventDefault();
      paused = !paused;
      follow();
    }
  }

  let root = $state<HTMLElement | undefined>();

  onMount(() => {
    reload();
    const off = session.on((e) => {
      if (e.type === 'reload') {
        reload();
        return;
      }
      if (e.type !== 'flow') return;
      if (simpleFilter) {
        if (!matches(e.flow)) return;
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
  <form class="toolbar" onsubmit={(e) => { e.preventDefault(); reload(); }}>
    <input class="grow" placeholder="Search requests and responses   ( / )" aria-label="Search requests and responses" bind:value={v.text} bind:this={searchBox} />
    <input placeholder="host" aria-label="Host contains" bind:value={v.host} size="14" />
    <input placeholder="GET,POST" aria-label="Methods" bind:value={v.methods} size="9" />
    <input type="number" placeholder="min" aria-label="Lowest status" bind:value={v.statusMin} class="num" />
    <input type="number" placeholder="max" aria-label="Highest status" bind:value={v.statusMax} class="num" />
    <input placeholder="hide extensions" aria-label="Hide extensions" bind:value={v.hideExt} size="16" title="Comma-separated extensions to hide" />
    <label><input type="checkbox" bind:checked={v.inScopeOnly} /> in scope</label>
    <button class="primary">Filter</button>
    <span class="spacer"></span>
    {#if waiting}<button type="button" onclick={() => { flush(); list?.scrollToTop(); }}>{waiting} new</button>{/if}
    <button type="button" class:active={paused} aria-pressed={paused} title="Hold new requests back so the list stays still (Space)" onclick={() => { paused = !paused; follow(); }}>
      {paused ? 'Paused' : 'Following'}
    </button>
  </form>

  <div class="table" use:css={{ '--row-h': `${ROW_H}px` }}>
    <div class="head-wrap">
      <div class="row head">
        <span class="c-id">#</span><span class="c-m">Method</span><span class="c-mk" title="Marks: edited, WebSocket, note, tags"></span><span class="c-host">Host</span><span class="c-path">Path</span>
        <span class="c-st">Status</span><span class="c-len">Length</span><span class="c-mime">MIME</span><span class="c-t">Time</span>
      </div>
    </div>
    <div class="body" role="presentation" onpointerenter={() => (hovering = true)} onpointerleave={() => { hovering = false; follow(); }}>
      <VirtualList
        bind:this={list}
        items={flows}
        rowHeight={ROW_H}
        key={(f) => f.id}
        label="HTTP history"
        idPrefix="hist"
        {activeIndex}
        onNearEnd={more}
        onTop={follow}
        onSelect={moveTo}
        onActivate={(i) => open(flows[i]!)}
      >
        {#snippet row(f: FlowSummary, i: number)}
          {@const mk = marks(f)}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <div
            class="row"
            id="hist-row-{i}"
            role="option"
            aria-selected={v.selectedId === f.id}
            class:active={v.selectedId === f.id}
            class:oos={!f.in_scope}
            title={flowUrl(f)}
            onclick={() => open(f)}
            tabindex="-1"
          >
            <span class="c-id tnum">{f.id}</span>
            <span class="c-m {methodClass(f.method)}">{f.method}</span>
            <span class="c-mk" title={mk.title}>{mk.glyphs}</span>
            <span class="c-host">{hostLabel(f)}</span>
            <span class="c-path">{f.path}</span>
            <span class="c-st tnum {statusClass(f.status ?? null)}">{f.error ? '✕ error' : (f.status ?? '…')}</span>
            <span class="c-len tnum">{fmtSize(f.response_len ?? 0)}</span>
            <span class="c-mime">{f.mime ?? ''}</span>
            <span class="c-t tnum">{fmtTime(f.started_ms)}</span>
          </div>
        {/snippet}
      </VirtualList>
    </div>
  </div>
</div>

<style>
  .hist { display: flex; flex-direction: column; flex: 1; min-height: 0; }
  .table { display: flex; flex-direction: column; flex: 1; min-height: 0; }
  .body { flex: 1; min-height: 0; }
  /* The header reserves the same scrollbar gutter as the list below it, so their columns always line up. */
  .head-wrap { overflow-y: hidden; scrollbar-gutter: stable; background: var(--surface-1); border-bottom: 1px solid var(--border-subtle); }
  .row { display: grid; grid-template-columns: 3.5rem 4rem 2.6rem 14rem 1fr 4.8rem 5rem 5.5rem 6.5rem; gap: .5rem; align-items: center; height: var(--row-h); width: 100%; padding: 0 .5rem; text-align: left; font-family: var(--font-mono); font-size: var(--fs-data); cursor: default; }
  .row > span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .row.head { font-family: var(--font-ui); font-size: var(--fs-xs); font-weight: 600; color: var(--text-2); text-transform: uppercase; letter-spacing: .04em; }
  .row:not(.head):hover { background: var(--surface-2); }
  .row.active { background: var(--surface-sel); box-shadow: inset 2px 0 0 var(--accent); }
  .row.oos { color: var(--text-2); }
  .c-mk { color: var(--text-2); letter-spacing: .1em; }
  .c-m { font-weight: 600; }
  .st-2 { color: var(--st-2xx); } .st-3 { color: var(--st-3xx); }
  .st-4 { color: var(--st-4xx); font-weight: 600; } .st-5, .st-none { color: var(--st-5xx); font-weight: 600; }
  .num { width: 4.5rem; }
</style>
