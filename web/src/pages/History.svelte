<script lang="ts">
  import { onMount } from 'svelte';
  import { api, qs } from '../lib/api';
  import { css } from '../lib/style';
  import { historyView as v } from '../lib/historyView.svelte';
  import { session } from '../lib/session.svelte';
  import { b64ToBytes, bytesToB64, bytesToText, flowUrl, fmtSize, fmtTime } from '../lib/bytes';
  import { bodyUrl, loadMore, loadPart, type Loaded, type PartName } from '../lib/flowbody';
  import type { FlowMeta, FlowSummary, WsMessage } from '../lib/types';
  import VirtualList from '../components/VirtualList.svelte';
  import MessageView from '../components/MessageView.svelte';

  /** Row height in px: the one source for the list maths and the row CSS (--row-h). */
  const ROW_H = 22;

  let flows = $state<FlowSummary[]>([]);
  let selected = $state<FlowMeta | null>(null);
  let req = $state<Loaded | null>(null);
  let resp = $state<Loaded | null>(null);
  let loadError = $state('');
  let wsMessages = $state<WsMessage[]>([]);
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

  // Which stored messages the two panes show: the current ones, or what the client and server first sent.
  function parts(tab: 'messages' | 'original'): [PartName, PartName] {
    if (tab === 'messages' || !selected) return ['request', 'response'];
    return [selected.original_request ? 'original-request' : 'request', selected.original_response ? 'original-response' : 'response'];
  }

  let opening = 0;
  async function loadPanes() {
    const m = selected;
    if (!m) return;
    const ticket = ++opening;
    loadError = '';
    try {
      const tab = v.detailTab === 'original' ? 'original' : 'messages';
      const [rp, sp] = parts(tab);
      const info = (p: PartName) => (p === 'request' ? m.request : p === 'response' ? m.response : p === 'original-request' ? m.original_request : m.original_response);
      const [a, b] = await Promise.all([
        loadPart(m, rp, info(rp)!),
        info(sp) ? loadPart(m, sp, info(sp)!) : Promise.resolve(null),
      ]);
      if (ticket !== opening) return;
      req = a;
      resp = b;
    } catch (e) {
      if (ticket === opening) loadError = e instanceof Error ? e.message : String(e);
    }
  }

  async function loadNext(which: 'req' | 'resp', decoded: boolean) {
    const m = selected;
    const cur = which === 'req' ? req : resp;
    if (!m || !cur) return;
    const [rp, sp] = parts(v.detailTab === 'original' ? 'original' : 'messages');
    try {
      const next = await loadMore(m, which === 'req' ? rp : sp, cur, decoded);
      if (which === 'req') req = next;
      else resp = next;
    } catch (e) {
      loadError = e instanceof Error ? e.message : String(e);
    }
  }

  const toB64 = (l: Loaded | null) => (l ? bytesToB64(join(l.head, l.body)) : null);
  function join(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  let openTicket = 0;
  let openTimer: ReturnType<typeof setTimeout> | undefined;

  /** Open a flow in the detail panes. */
  async function open(f: { id: number }) {
    clearTimeout(openTimer);
    const ticket = ++openTicket;
    v.selectedId = f.id;
    let m: FlowMeta;
    try {
      m = await api.get<FlowMeta>(`/flows/${f.id}`);
    } catch {
      // Gone (deleted, or another project): nothing to show.
      if (ticket === openTicket) {
        v.selectedId = null;
        selected = null;
      }
      return;
    }
    if (ticket !== openTicket) return;
    selected = m;
    wsMessages = [];
    req = null;
    resp = null;
    if (v.detailTab === 'original' && !(m.original_request || m.original_response)) v.detailTab = 'messages';
    if (v.detailTab === 'ws' && m.status !== 101) v.detailTab = 'messages';
    await loadPanes();
    if (ticket === openTicket && m.status === 101) wsMessages = await api.get<WsMessage[]>(`/flows/${f.id}/ws`);
  }

  /** Arrow-key movement: highlight at once, load the detail once the user stops for a moment. */
  function moveTo(i: number) {
    const f = flows[i];
    if (!f) return;
    v.selectedId = f.id;
    clearTimeout(openTimer);
    openTimer = setTimeout(() => open(f), 90);
  }

  function setTab(t: 'messages' | 'original' | 'ws') {
    v.detailTab = t;
    if (t !== 'ws') loadPanes();
  }

  /** Hand the request to the Repeater page, which picks it up from session storage. */
  function toRepeater() {
    const m = selected;
    const r = req;
    if (!m || !r) return;
    if (r.body.length < r.bodyLen) {
      loadError = 'This request body is too large to open in the Repeater here.';
      return;
    }
    const d = bytesToText(join(r.head, r.body));
    const inbox = JSON.parse(sessionStorage.getItem('bosun.repeater.inbox') ?? '[]');
    inbox.push({ scheme: m.scheme, host: m.host, port: m.port, request: d.text, mode: d.mode });
    sessionStorage.setItem('bosun.repeater.inbox', JSON.stringify(inbox));
    location.hash = '#repeater';
  }

  async function saveNote() {
    if (!selected) return;
    await api.patch(`/flows/${selected.id}`, { note: selected.note ?? '', tags: selected.tags });
  }

  async function remove() {
    if (!selected) return;
    const id = selected.id;
    await api.del('/flows', { ids: [id] });
    flows = flows.filter((f) => f.id !== id);
    selected = null;
    v.selectedId = null;
  }

  async function copyUrl() {
    if (selected) await navigator.clipboard.writeText(flowUrl(selected));
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
    if (f.tags?.length) { g.push('#'); t.push(`tags: ${f.tags.join(', ')}`); }
    return { glyphs: g.join(''), title: t.join(', ') };
  }

  function onWindowKey(e: KeyboardEvent) {
    const t = e.target as HTMLElement | null;
    const typing = !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === '/') {
      e.preventDefault();
      searchBox?.focus();
    } else if (e.key === ' ' && t?.getAttribute('role') === 'listbox') {
      e.preventDefault();
      paused = !paused;
      follow();
    }
  }

  onMount(() => {
    reload().then(() => {
      if (v.selectedId !== null) open({ id: v.selectedId });
    });
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

<div class="layout" use:css={{ '--row-h': `${ROW_H}px` }}>
  <div class="table">
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

  {#if selected}
    <div class="detail">
      <div class="toolbar">
        <div class="seg">
          <button class:active={v.detailTab === 'messages'} onclick={() => setTab('messages')}>Request / Response</button>
          {#if selected.original_request || selected.original_response}
            <button class:active={v.detailTab === 'original'} onclick={() => setTab('original')}>Original (before edits)</button>
          {/if}
          {#if selected.status === 101}
            <button class:active={v.detailTab === 'ws'} onclick={() => setTab('ws')}>WebSocket ({wsMessages.length})</button>
          {/if}
        </div>
        <span class="url" title={flowUrl(selected)}>{flowUrl(selected)}</span>
        <span class="spacer"></span>
        <button onclick={copyUrl}>Copy URL</button>
        {#if session.can('tester')}<button onclick={toRepeater} title="Open this request in the Repeater">Send to Repeater</button>{/if}
        {#if session.can('tester')}<button onclick={remove}>Delete</button>{/if}
      </div>
      {#if selected.error}<p class="error pad">{selected.error}</p>{/if}
      {#if v.detailTab === 'ws'}
        <div class="ws">
          {#each wsMessages as m (m.id)}
            <div class="wsm" class:out={m.direction === 'client_to_server'}>
              <span class="small muted">{fmtTime(m.time_ms)} {m.direction === 'client_to_server' ? '→' : '←'} op {m.opcode}{m.truncated ? ' (truncated)' : ''}</span>
              <pre>{bytesToText(b64ToBytes(m.payload)).text}</pre>
            </div>
          {/each}
        </div>
      {:else}
        <div class="pair">
          {#key `${selected.id}-${v.detailTab}`}
            {@const names = parts(v.detailTab === 'original' ? 'original' : 'messages')}
            <MessageView
              title="Request"
              role="request"
              raw={toB64(req)}
              rawRemaining={req ? req.bodyLen - req.body.length : 0}
              onMore={(d) => loadNext('req', d)}
              downloadHref={bodyUrl(selected.id, names[0])}
            />
            <MessageView
              title={selected.response_truncated ? 'Response (truncated)' : 'Response'}
              role="response"
              raw={toB64(resp)}
              decodedBody={resp?.decoded ? bytesToB64(resp.decoded) : null}
              rawRemaining={resp ? resp.bodyLen - resp.body.length : 0}
              decodedMore={resp?.decodedMore ?? false}
              onMore={(d) => loadNext('resp', d)}
              downloadHref={resp ? bodyUrl(selected.id, names[1]) : ''}
            />
          {/key}
        </div>
      {/if}
      {#if resp?.note}<p class="small muted pad">{resp.note}</p>{/if}
      {#if loadError}<p class="error pad">{loadError}</p>{/if}
      {#if session.can('tester')}
        <div class="toolbar">
          <input class="grow" placeholder="Note" aria-label="Note" bind:value={selected.note} onchange={saveNote} />
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .layout { display: grid; grid-template-rows: minmax(8rem, 1fr) minmax(12rem, 1.4fr); flex: 1; min-height: 0; }
  .table { display: flex; flex-direction: column; min-height: 0; border-bottom: 1px solid var(--border-subtle); }
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
  .detail { display: flex; flex-direction: column; min-height: 0; }
  .pair { display: grid; grid-template-columns: 1fr 1fr; flex: 1; min-height: 0; }
  .pair > :global(*) { border-right: 1px solid var(--border-subtle); }
  .url { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-2); }
  .num { width: 4.5rem; }
  .ws { overflow: auto; flex: 1; padding: .5rem; }
  .wsm { border-left: 3px solid var(--info); padding-left: .5rem; margin-bottom: .4rem; }
  .wsm.out { border-color: var(--accent); }
  .wsm pre { margin: 0; white-space: pre-wrap; word-break: break-all; }
  .pad { padding: 0 .5rem; }
</style>
