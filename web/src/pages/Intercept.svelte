<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import type { InterceptItem, InterceptSettings, InterceptSummary } from '../lib/types';
  import MessageView from '../components/MessageView.svelte';

  let settings = $state<InterceptSettings>({ requests: false, responses: false, in_scope_only: true });
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

  onMount(() => {
    api.get<InterceptSettings>('/intercept').then((s) => (settings = s));
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

<div class="toolbar">
  <label><input type="checkbox" checked={settings.requests} disabled={!canEdit} onchange={(e) => save({ ...settings, requests: e.currentTarget.checked })} /> Intercept requests</label>
  <label><input type="checkbox" checked={settings.responses} disabled={!canEdit} onchange={(e) => save({ ...settings, responses: e.currentTarget.checked })} /> Intercept responses</label>
  <label><input type="checkbox" checked={settings.in_scope_only} disabled={!canEdit} onchange={(e) => save({ ...settings, in_scope_only: e.currentTarget.checked })} /> Only in-scope</label>
  <label>Auto-forward after <input type="number" min="0" max="3600" class="num" value={settings.timeout_secs ?? 0} disabled={!canEdit} onchange={(e) => save({ ...settings, timeout_secs: Number(e.currentTarget.value) || null })} /> s (0 = hold)</label>
  <span class="spacer"></span>
  <button class="primary" disabled={!current || !canEdit} onclick={() => decide('forward')}>Forward</button>
  <button disabled={!current || !canEdit} onclick={() => decide('drop')}>Drop</button>
  <button disabled={!queue.length || !canEdit} onclick={() => api.post('/intercept/forward-all').then(refresh)}>Forward all ({queue.length})</button>
</div>
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
    {#if current}
      {#key current.id}
        <MessageView raw={current.raw} editable={canEdit} onEdit={(b) => (edited = b)} title={`${current.phase} #${current.flow_id}`} />
      {/key}
    {/if}
  </div>
</div>

<style>
  .split { display: grid; grid-template-columns: minmax(16rem, 1fr) 3fr; flex: 1; min-height: 0; }
  .list { list-style: none; margin: 0; padding: 0; overflow: auto; border-right: 1px solid var(--line); }
  .list button { width: 100%; text-align: left; border: 0; border-radius: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .pane { min-height: 0; display: flex; flex-direction: column; }
  .pad { padding: 1rem; }
</style>
