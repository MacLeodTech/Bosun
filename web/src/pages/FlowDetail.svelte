<script lang="ts">
  // The open flow: its request and response, WebSocket messages and note. A panel of its own so it can sit beside,
  // below or apart from the History list. It follows `historyView.openId`.
  import { untrack } from 'svelte';
  import { api } from '../lib/api';
  import { historyView as v } from '../lib/historyView.svelte';
  import { session } from '../lib/session.svelte';
  import { workspace } from '../lib/workspace.svelte';
  import { b64ToBytes, bytesToB64, bytesToText, flowUrl, fmtTime } from '../lib/bytes';
  import { bodyUrl, loadMore, loadPart, type Loaded, type PartName } from '../lib/flowbody';
  import type { FlowMeta, WsMessage } from '../lib/types';
  import MessageView from '../components/MessageView.svelte';

  let selected = $state<FlowMeta | null>(null);
  let req = $state<Loaded | null>(null);
  let resp = $state<Loaded | null>(null);
  let loadError = $state('');
  let wsMessages = $state<WsMessage[]>([]);

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

  let ticketNo = 0;
  /** Load a flow into the panes, or clear them. */
  async function load(id: number | null) {
    const ticket = ++ticketNo;
    if (id === null) {
      selected = null;
      req = null;
      resp = null;
      wsMessages = [];
      return;
    }
    let m: FlowMeta;
    try {
      m = await api.get<FlowMeta>(`/flows/${id}`);
    } catch {
      // Gone (deleted, or another project): nothing to show.
      if (ticket === ticketNo) {
        v.selectedId = null;
        v.openId = null;
      }
      return;
    }
    if (ticket !== ticketNo) return;
    selected = m;
    wsMessages = [];
    req = null;
    resp = null;
    if (v.detailTab === 'original' && !(m.original_request || m.original_response)) v.detailTab = 'messages';
    if (v.detailTab === 'ws' && m.status !== 101) v.detailTab = 'messages';
    await loadPanes();
    if (ticket === ticketNo && m.status === 101) wsMessages = await api.get<WsMessage[]>(`/flows/${id}/ws`);
  }

  $effect(() => {
    const id = v.openId;
    untrack(() => load(id));
  });

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
    // Repeater may already be mounted in the background: tell it, then bring it forward.
    window.dispatchEvent(new Event('bosun:repeater-inbox'));
    workspace.open('repeater');
    history.replaceState(null, '', '#repeater');
  }

  async function saveNote() {
    if (!selected) return;
    await api.patch(`/flows/${selected.id}`, { note: selected.note ?? '', tags: selected.tags });
  }

  async function remove() {
    if (!selected) return;
    const id = selected.id;
    await api.del('/flows', { ids: [id] });
    v.remove([id]);
  }

  async function copyUrl() {
    if (selected) await navigator.clipboard.writeText(flowUrl(selected));
  }
</script>

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
{:else}
  <p class="empty muted">Select a request in HTTP history to see it here.</p>
{/if}

<style>
  .detail { display: flex; flex-direction: column; flex: 1; min-height: 0; container-type: inline-size; }
  .pair { display: grid; grid-template-columns: 1fr 1fr; flex: 1; min-height: 0; }
  .pair > :global(*) { border-right: 1px solid var(--border-subtle); min-width: 0; min-height: 0; }
  /* In a narrow panel the two messages stack instead of squeezing. */
  @container (max-width: 760px) {
    .pair { grid-template-columns: 1fr; grid-template-rows: 1fr 1fr; }
    .pair > :global(*) { border-right: 0; border-bottom: 1px solid var(--border-subtle); }
  }
  .url { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-2); }
  .ws { overflow: auto; flex: 1; padding: .5rem; }
  .wsm { border-left: 3px solid var(--info); padding-left: .5rem; margin-bottom: .4rem; }
  .wsm.out { border-color: var(--accent); }
  .wsm pre { margin: 0; white-space: pre-wrap; word-break: break-all; }
  .pad { padding: 0 .5rem; }
  .empty { padding: 1rem; margin: 0; }
</style>
