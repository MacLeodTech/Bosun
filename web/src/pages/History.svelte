<script lang="ts">
  import { onMount } from 'svelte';
  import { api, qs } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { b64ToBytes, bytesToText, flowUrl, fmtSize, fmtTime } from '../lib/bytes';
  import type { FlowDetail, FlowSummary, WsMessage } from '../lib/types';
  import VirtualList from '../components/VirtualList.svelte';
  import MessageView from '../components/MessageView.svelte';

  let flows = $state<FlowSummary[]>([]);
  let selected = $state<FlowDetail | null>(null);
  let wsMessages = $state<WsMessage[]>([]);
  let detailTab = $state<'messages' | 'original' | 'ws'>('messages');
  let pending = $state(0);
  let loadingMore = false;
  let exhausted = false;

  let text = $state('');
  let host = $state('');
  let methods = $state('');
  let statusMin = $state<number | undefined>();
  let statusMax = $state<number | undefined>();
  let inScopeOnly = $state(false);
  let hideExt = $state('png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,css');
  const simpleFilter = $derived(!text);

  function params(extra: Record<string, number | undefined> = {}) {
    return qs({ text, host, methods, status_min: statusMin, status_max: statusMax, in_scope_only: inScopeOnly, hide_ext: hideExt, limit: 500, ...extra });
  }

  async function reload() {
    pending = 0;
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
    if (host && !f.host.includes(host.toLowerCase())) return false;
    if (methods && !methods.toUpperCase().split(',').map((m) => m.trim()).includes(f.method)) return false;
    if (statusMin !== undefined && (f.status ?? 0) < statusMin) return false;
    if (statusMax !== undefined && (f.status ?? 0) > statusMax) return false;
    if (inScopeOnly && !f.in_scope) return false;
    const ext = f.path.split('?')[0]!.split('.').pop()?.toLowerCase() ?? '';
    if (hideExt && hideExt.split(',').map((e) => e.trim().toLowerCase()).includes(ext)) return false;
    return true;
  }

  async function open(f: FlowSummary) {
    selected = await api.get<FlowDetail>(`/flows/${f.id}`);
    detailTab = 'messages';
    wsMessages = [];
    if (f.status === 101) wsMessages = await api.get<WsMessage[]>(`/flows/${f.id}/ws`);
  }

  async function saveNote() {
    if (!selected) return;
    await api.patch(`/flows/${selected.summary.id}`, { note: selected.summary.note ?? '', tags: selected.summary.tags });
  }

  async function remove() {
    if (!selected) return;
    const id = selected.summary.id;
    await api.del('/flows', { ids: [id] });
    flows = flows.filter((f) => f.id !== id);
    selected = null;
  }

  async function copyUrl() {
    if (selected) await navigator.clipboard.writeText(flowUrl(selected.summary));
  }

  function statusClass(s: number | null): string {
    if (s === null) return 'st-none';
    return s >= 500 ? 'st-5' : s >= 400 ? 'st-4' : s >= 300 ? 'st-3' : 'st-2';
  }

  onMount(() => {
    reload();
    return session.on((e) => {
      if (e.type !== 'flow') return;
      if (simpleFilter) {
        if (matches(e.flow)) flows = [e.flow, ...flows];
      } else {
        pending++;
      }
    });
  });
</script>

<form class="toolbar" onsubmit={(e) => { e.preventDefault(); reload(); }}>
  <input class="grow" placeholder="Search requests and responses" bind:value={text} />
  <input placeholder="host" bind:value={host} size="14" />
  <input placeholder="GET,POST" bind:value={methods} size="9" />
  <input type="number" placeholder="min" bind:value={statusMin} class="num" />
  <input type="number" placeholder="max" bind:value={statusMax} class="num" />
  <input placeholder="hide extensions" bind:value={hideExt} size="16" title="Comma-separated extensions to hide" />
  <label><input type="checkbox" bind:checked={inScopeOnly} /> in scope</label>
  <button class="primary">Filter</button>
  {#if pending}<button type="button" onclick={reload}>{pending} new</button>{/if}
</form>

<div class="layout">
  <div class="table">
    <div class="row head">
      <span class="c-id">#</span><span class="c-m">Method</span><span class="c-host">Host</span><span class="c-path">Path</span>
      <span class="c-st">Status</span><span class="c-len">Length</span><span class="c-mime">MIME</span><span class="c-t">Time</span>
    </div>
    <div class="body">
      <VirtualList items={flows} onNearEnd={more}>
        {#snippet row(f: FlowSummary)}
          <button class="row" class:active={selected?.summary.id === f.id} class:oos={!f.in_scope} onclick={() => open(f)}>
            <span class="c-id">{f.id}</span>
            <span class="c-m">{f.method}</span>
            <span class="c-host">{f.scheme}://{f.host}{(f.scheme === 'https' && f.port === 443) || (f.scheme === 'http' && f.port === 80) ? '' : ':' + f.port}</span>
            <span class="c-path">{f.path}</span>
            <span class="c-st {statusClass(f.status)}">{f.error ? 'error' : (f.status ?? '…')}</span>
            <span class="c-len">{fmtSize(f.response_len)}</span>
            <span class="c-mime">{f.mime ?? ''}</span>
            <span class="c-t">{fmtTime(f.started_ms)}</span>
          </button>
        {/snippet}
      </VirtualList>
    </div>
  </div>

  {#if selected}
    <div class="detail">
      <div class="toolbar">
        <div class="seg">
          <button class:active={detailTab === 'messages'} onclick={() => (detailTab = 'messages')}>Request / Response</button>
          {#if selected.original_request || selected.original_response}
            <button class:active={detailTab === 'original'} onclick={() => (detailTab = 'original')}>Original (before edits)</button>
          {/if}
          {#if selected.summary.status === 101}
            <button class:active={detailTab === 'ws'} onclick={() => (detailTab = 'ws')}>WebSocket ({wsMessages.length})</button>
          {/if}
        </div>
        <span class="url" title={flowUrl(selected.summary)}>{flowUrl(selected.summary)}</span>
        <span class="spacer"></span>
        <button onclick={copyUrl}>Copy URL</button>
        {#if session.can('tester')}<button onclick={remove}>Delete</button>{/if}
      </div>
      {#if selected.summary.error}<p class="error pad">{selected.summary.error}</p>{/if}
      {#if detailTab === 'ws'}
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
          {#key `${selected.summary.id}-${detailTab}`}
            <MessageView title="Request" raw={detailTab === 'original' ? (selected.original_request ?? selected.request) : selected.request} />
            <MessageView
              title={selected.response_truncated ? 'Response (truncated)' : 'Response'}
              raw={detailTab === 'original' ? (selected.original_response ?? selected.response) : selected.response}
              decodedBody={detailTab === 'original' ? null : selected.response_body_decoded}
            />
          {/key}
        </div>
      {/if}
      {#if selected.decode_note}<p class="small muted pad">{selected.decode_note}</p>{/if}
      {#if session.can('tester')}
        <div class="toolbar">
          <input class="grow" placeholder="Note" bind:value={selected.summary.note} onchange={saveNote} />
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .layout { display: grid; grid-template-rows: minmax(8rem, 1fr) minmax(12rem, 1.4fr); flex: 1; min-height: 0; }
  .layout:has(.detail) { grid-template-rows: minmax(8rem, 1fr) minmax(12rem, 1.4fr); }
  .table { display: flex; flex-direction: column; min-height: 0; border-bottom: 1px solid var(--line); }
  .body { flex: 1; min-height: 0; }
  .row { display: grid; grid-template-columns: 4.5rem 4.5rem 16rem 1fr 4rem 5.5rem 9rem 7rem; gap: .5rem; align-items: center; height: 24px; width: 100%; padding: 0 .5rem; border: 0; border-radius: 0; text-align: left; background: transparent; }
  .row > span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .row.head { font-weight: 600; background: var(--bg2); border-bottom: 1px solid var(--line); }
  .row:not(.head):hover { background: var(--hover); }
  .row.active { background: var(--sel); }
  .row.oos { color: var(--muted); }
  .st-2 { color: var(--ok); } .st-3 { color: var(--info); } .st-4 { color: var(--warn); } .st-5, .st-none { color: var(--bad); }
  .detail { display: flex; flex-direction: column; min-height: 0; }
  .pair { display: grid; grid-template-columns: 1fr 1fr; flex: 1; min-height: 0; }
  .pair > :global(*) { border-right: 1px solid var(--line); }
  .url { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); }
  .num { width: 4.5rem; }
  .ws { overflow: auto; flex: 1; padding: .5rem; }
  .wsm { border-left: 3px solid var(--info); padding-left: .5rem; margin-bottom: .4rem; }
  .wsm.out { border-color: var(--accent); }
  .wsm pre { margin: 0; white-space: pre-wrap; word-break: break-all; }
  .pad { padding: 0 .5rem; }
</style>
