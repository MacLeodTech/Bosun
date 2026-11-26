<script lang="ts">
  import { isTyping } from '../lib/typing';
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { usePanel } from '../lib/panelctx';
  import type { InterceptItem, InterceptSettings, InterceptSummary } from '../lib/types';
  import type { components } from '../lib/api-types';
  import MessageView from '../components/MessageView.svelte';

  const panel = usePanel();
  let settings = $state<InterceptSettings>({ requests: false, responses: false, in_scope_only: true });
  type ResponseFilter = components['schemas']['ResponseFilter'];
  let filter = $state<ResponseFilter>({ statuses: [], mime_contains: [], only_if_request_held: false });
  const list = (v: string) => v.split(',').map((x) => x.trim()).filter(Boolean);

  async function saveFilter(next: ResponseFilter) {
    try {
      filter = await api.put<ResponseFilter>('/intercept/response-filter', next);
      error = '';
    } catch (e) {
      error = String(e);
    }
  }
  let queue = $state<InterceptSummary[]>([]);
  let current = $state<InterceptItem | null>(null);
  let edited: string | null = null;
  let error = $state('');
  const canEdit = $derived(session.can('tester'));

  async function refresh() {
    queue = await api.get<InterceptSummary[]>('/intercept/queue');
    if (!current || !queue.some((q) => q.id === current!.id)) await select(queue[0]?.id);
  }

  async function select(id: number | undefined) {
    edited = null;
    current = id === undefined ? null : await api.get<InterceptItem>(`/intercept/queue/${id}`).catch(() => null);
  }

  async function save(next: InterceptSettings) {
    try {
      settings = await api.put<InterceptSettings>('/intercept', next);
    } catch (e) {
      error = String(e);
    }
  }

  async function decide(action: 'forward' | 'drop') {
    if (!current) return;
    const id = current.id;
    try {
      await api.post(`/intercept/queue/${id}`, action === 'forward' ? { action, raw: edited } : { action });
    } catch (e) {
      error = String(e);
    }
    queue = queue.filter((q) => q.id !== id);
    await select(queue[0]?.id);
  }

  async function forwardAll() {
    await api.post('/intercept/forward-all');
    await refresh();
  }

  // F forwards, D drops, Shift+F forwards everything held, Ctrl+Enter forwards from inside the editor. Plain letters
  // are ignored while typing in a field.
  function onKey(e: KeyboardEvent) {
    // The panel stays mounted in the background: a hidden Intercept must never act on a key meant for another panel.
    if (!canEdit || !panel.visible) return;
    const typing = isTyping(e);
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      if (current) decide('forward');
      return;
    }
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    const k = e.key.toLowerCase();
    if (k === 'f' && e.shiftKey) {
      e.preventDefault();
      if (queue.length) forwardAll();
    } else if (k === 'f') {
      e.preventDefault();
      if (current) decide('forward');
    } else if (k === 'd') {
      e.preventDefault();
      if (current) decide('drop');
    }
  }

  onMount(() => {
    api.get<InterceptSettings>('/intercept').then((s) => (settings = s));
    api.get<ResponseFilter>('/intercept/response-filter').then((f) => (filter = f));
    refresh();
    return session.on((e) => {
      if (e.type === 'reload') {
        api.get<InterceptSettings>('/intercept').then((s) => (settings = s));
        refresh();
      } else if (e.type === 'intercept_queued') {
        queue = [...queue, e.item];
        if (!current) select(e.item.id);
      } else if (e.type === 'intercept_refused') {
        error = e.reason;
      } else if (e.type === 'intercept_resolved') {
        queue = queue.filter((q) => q.id !== e.id);
        if (current?.id === e.id) select(queue[0]?.id);
      }
    });
  });
</script>

<svelte:window onkeydown={onKey} />

<div class="toolbar">
  <label><input type="checkbox" checked={settings.requests} disabled={!canEdit} onchange={(e) => save({ ...settings, requests: e.currentTarget.checked })} /> Intercept requests</label>
  <label><input type="checkbox" checked={settings.responses} disabled={!canEdit} onchange={(e) => save({ ...settings, responses: e.currentTarget.checked })} /> Intercept responses</label>
  <label><input type="checkbox" checked={settings.in_scope_only} disabled={!canEdit} onchange={(e) => save({ ...settings, in_scope_only: e.currentTarget.checked })} /> Only in-scope</label>
  <label>Auto-forward after <input type="number" min="0" max="3600" class="num" value={settings.timeout_secs ?? 0} disabled={!canEdit} onchange={(e) => save({ ...settings, timeout_secs: Number(e.currentTarget.value) || null })} /> s (0 = hold)</label>
</div>
{#if settings.responses}
  <div class="toolbar" aria-label="Response filter">
    <span class="muted">Hold only responses where</span>
    <label>status <input class="txt" placeholder="5xx, 404" aria-label="Status filter" value={(filter.statuses ?? []).join(', ')} disabled={!canEdit} onchange={(e) => saveFilter({ ...filter, statuses: list(e.currentTarget.value) })} /></label>
    <label>MIME <input class="txt" placeholder="json, html" aria-label="MIME filter" value={(filter.mime_contains ?? []).join(', ')} disabled={!canEdit} onchange={(e) => saveFilter({ ...filter, mime_contains: list(e.currentTarget.value) })} /></label>
    <label>header has <input class="txt" aria-label="Header filter" value={filter.header_contains ?? ''} disabled={!canEdit} onchange={(e) => saveFilter({ ...filter, header_contains: e.currentTarget.value || null })} /></label>
    <label>body has <input class="txt" aria-label="Body filter" value={filter.body_contains ?? ''} disabled={!canEdit} onchange={(e) => saveFilter({ ...filter, body_contains: e.currentTarget.value || null })} /></label>
    <label><input type="checkbox" checked={filter.only_if_request_held} disabled={!canEdit} onchange={(e) => saveFilter({ ...filter, only_if_request_held: e.currentTarget.checked })} /> request was held</label>
  </div>
{/if}
{#if error}<p class="error">{error}</p>{/if}
<div class="split">
  <ul class="list">
    {#each queue as q (q.id)}
      <li>
        <button class:active={current?.id === q.id} onclick={() => select(q.id)}>
          <span class="badge">{q.phase}</span> {q.method} {q.url} {q.status ?? ''}
        </button>
      </li>
    {:else}
      <li class="muted pad">Nothing held. {settings.requests || settings.responses ? 'Waiting for traffic…' : 'Interception is off.'}</li>
    {/each}
  </ul>
  <div class="pane">
    <div class="toolbar actions">
      <button class="primary" aria-label="Forward" aria-keyshortcuts="F" disabled={!current || !canEdit} onclick={() => decide('forward')}>Forward <kbd>F</kbd></button>
      <button aria-label="Drop" aria-keyshortcuts="D" disabled={!current || !canEdit} onclick={() => decide('drop')}>Drop <kbd>D</kbd></button>
      <span class="spacer"></span>
      <button aria-label="Forward all ({queue.length})" aria-keyshortcuts="Shift+F" disabled={!queue.length || !canEdit} onclick={forwardAll}>Forward all ({queue.length}) <kbd>Shift+F</kbd></button>
    </div>
    {#if current}
      {#key current.id}
        <MessageView role="intercept" raw={current.raw} editable={canEdit} onEdit={(b) => (edited = b)} title={`${current.phase} #${current.flow_id}`} />
      {/key}
    {/if}
  </div>
</div>

<style>
  .split { display: grid; grid-template-columns: minmax(16rem, 1fr) 3fr; flex: 1; min-height: 0; }
  .list { list-style: none; margin: 0; padding: 0; overflow: auto; border-right: 1px solid var(--border-subtle); }
  .list button { width: 100%; text-align: left; border-radius: 0; background: transparent; font-family: var(--font-mono); font-size: var(--fs-data); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .pane { min-height: 0; display: flex; flex-direction: column; }
  .pad { padding: 1rem; }
  .txt { width: 9rem; }
  .list button:hover:not(:disabled) { background: var(--surface-2); border-color: transparent; }
  .list button.active { background: var(--surface-sel); }
</style>
