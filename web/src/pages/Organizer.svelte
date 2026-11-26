<script lang="ts">
  // The Organizer: requests kept for follow-up, each with a status and a note. Saving one stores no copy; it points at
  // the flow in the history (and goes when that flow is deleted). Everything from the target is shown as text.
  import { onMount, untrack } from 'svelte';
  import { api } from '../lib/api';
  import { fmtTime, flowUrl } from '../lib/bytes';
  import { historyView } from '../lib/historyView.svelte';
  import { inbox } from '../lib/inbox.svelte';
  import { session } from '../lib/session.svelte';
  import { toasts } from '../lib/toasts.svelte';
  import { workspace } from '../lib/workspace.svelte';
  import type { components } from '../lib/api-types';

  type Item = components['schemas']['OrganizerItem'];
  type Status = components['schemas']['OrganizerStatus'];

  const STATUSES: { id: Status; label: string }[] = [
    { id: 'todo', label: 'To do' },
    { id: 'in_progress', label: 'In progress' },
    { id: 'done', label: 'Done' },
    { id: 'ignored', label: 'Ignored' },
  ];
  const labelOf = (s: Status) => STATUSES.find((x) => x.id === s)?.label ?? s;

  let items = $state<Item[]>([]);
  let show = $state<'all' | Status>('all');
  let loaded = $state(false);
  const canEdit = $derived(session.can('tester'));
  const shown = $derived(show === 'all' ? items : items.filter((i) => i.status === show));
  const counts = $derived(Object.fromEntries(STATUSES.map((s) => [s.id, items.filter((i) => i.status === s.id).length])) as Record<Status, number>);

  async function load() {
    try {
      items = await api.get<Item[]>('/organizer');
    } catch (e) {
      toasts.push({ text: `Could not load the Organizer: ${e instanceof Error ? e.message : e}` });
    }
    loaded = true;
  }

  onMount(() => {
    load();
    return session.on((e) => { if (e.type === 'reload') load(); });
  });

  // Something was saved to the Organizer from the History menu.
  let seen = untrack(() => inbox.organizerTick);
  $effect(() => {
    const t = inbox.organizerTick;
    untrack(() => {
      if (t === seen) return;
      seen = t;
      load();
    });
  });

  async function change(i: Item, body: { status?: Status; note?: string }) {
    try {
      await api.patch(`/organizer/${i.id}`, body);
      items = items.map((x) => (x.id === i.id ? { ...x, ...body } : x));
    } catch (e) {
      toasts.push({ text: `Could not save: ${e instanceof Error ? e.message : e}` });
      load();
    }
  }

  async function remove(i: Item) {
    try {
      await api.del(`/organizer/${i.id}`);
      items = items.filter((x) => x.id !== i.id);
    } catch (e) {
      toasts.push({ text: `Could not remove it: ${e instanceof Error ? e.message : e}` });
    }
  }

  /** Show the request in the History detail panel. */
  function open(i: Item) {
    historyView.select([i.flow_id], i.flow_id);
    historyView.openId = i.flow_id;
    workspace.reveal('flow', 'organizer');
  }
</script>

<div class="toolbar">
  <label class="small" for="org-status">Show</label>
  <select id="org-status" bind:value={show}>
    <option value="all">All ({items.length})</option>
    {#each STATUSES as s (s.id)}<option value={s.id}>{s.label} ({counts[s.id]})</option>{/each}
  </select>
  <span class="spacer"></span>
  <span class="muted small">Save requests from History: right-click, then “Save to Organizer”.</span>
</div>
<div class="scroll">
  <table class="grid">
    <thead><tr><th>Status</th><th>Request</th><th>Response</th><th>Note</th><th>Saved</th><th></th></tr></thead>
    <tbody>
      {#each shown as i (i.id)}
        <tr>
          <td>
            <select value={i.status} disabled={!canEdit} aria-label="Status of request {i.flow_id}" onchange={(e) => change(i, { status: e.currentTarget.value as Status })}>
              {#each STATUSES as s (s.id)}<option value={s.id}>{s.label}</option>{/each}
            </select>
          </td>
          <td class="req" title={flowUrl(i.flow)}><span class="m">{i.flow.method}</span> {i.flow.host}{i.flow.path}</td>
          <td class="tnum">{i.flow.error ? 'error' : (i.flow.status ?? '…')}</td>
          <td>
            <textarea rows="1" maxlength="10000" disabled={!canEdit} aria-label="Note for request {i.flow_id}" value={i.note} placeholder={canEdit ? 'Note' : ''} onchange={(e) => change(i, { note: e.currentTarget.value })}></textarea>
          </td>
          <td class="tnum muted">{fmtTime(i.added_ms)}</td>
          <td class="acts">
            <button onclick={() => open(i)} aria-label="Open request {i.flow_id}">Open</button>
            {#if canEdit}<button onclick={() => remove(i)} aria-label="Remove request {i.flow_id} from the Organizer">Remove</button>{/if}
          </td>
        </tr>
      {:else}
        <tr><td colspan="6" class="muted">{loaded ? (items.length ? `Nothing is ${labelOf(show as Status).toLowerCase()}.` : 'Nothing saved yet.') : 'Loading…'}</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .scroll { overflow: auto; flex: 1; }
  .req { font-family: var(--font-mono); font-size: var(--fs-data); max-width: 28rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .m { font-weight: 600; }
  textarea { width: 100%; min-width: 12rem; resize: vertical; font: inherit; }
  .acts { white-space: nowrap; }
</style>
