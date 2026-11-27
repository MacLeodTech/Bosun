<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { fmtTime } from '../lib/bytes';

  interface Entry { id: number; name: string; kind: string; hint: string; created_ms: number; updated_ms: number }
  const KINDS = ['password', 'token', 'api_key', 'auth_config', 'client_cert_password', 'oast_key', 'other'];

  let entries = $state<Entry[]>([]);
  let form = $state({ name: '', kind: 'token', secret: '' });
  let editing = $state<number | null>(null);
  let replacement = $state('');
  let note = $state('');
  let error = $state('');

  async function run(f: () => Promise<unknown>, ok = '') {
    error = '';
    note = '';
    try {
      await f();
      note = ok;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function load() {
    entries = (await api.get<{ entries: Entry[] }>('/vault')).entries;
  }

  const add = () =>
    run(async () => {
      await api.post('/vault', form);
      form = { name: '', kind: 'token', secret: '' };
      await load();
    }, 'Stored. The secret is sealed and will not be shown again.');
  const replace = (id: number) =>
    run(async () => {
      await api.patch(`/vault/${id}`, { secret: replacement });
      editing = null;
      replacement = '';
      await load();
    }, 'Secret replaced.');
  const remove = (id: number) => run(async () => { await api.del(`/vault/${id}`); await load(); }, 'Deleted.');

  onMount(() => { void run(load); });
</script>

<div class="vault">
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if note}<p class="ok" role="status">{note}</p>{/if}

  <h2>Credential vault</h2>
  <p class="small muted">Named secrets for scans and tools to refer to by name. They are stored sealed with the data key and are never sent back to this page: you see a masked hint only.</p>
  <table class="grid" aria-label="Vault entries"><tbody>
    {#each entries as e (e.id)}
      <tr>
        <td>{e.name}</td>
        <td class="small muted">{e.kind}</td>
        <td><code>{e.hint}</code></td>
        <td class="small muted">added {fmtTime(e.created_ms)}</td>
        {#if session.can('admin')}
          <td>
            {#if editing === e.id}
              <form class="row" onsubmit={(ev) => { ev.preventDefault(); replace(e.id); }}>
                <input type="password" aria-label="New secret for {e.name}" autocomplete="off" bind:value={replacement} required />
                <button>Save</button>
                <button type="button" onclick={() => { editing = null; replacement = ''; }}>Cancel</button>
              </form>
            {:else}
              <button aria-label="Replace secret of {e.name}" onclick={() => { editing = e.id; replacement = ''; }}>Replace</button>
              <button aria-label="Delete {e.name}" onclick={() => remove(e.id)}>Delete</button>
            {/if}
          </td>
        {/if}
      </tr>
    {:else}
      <tr><td class="muted">The vault is empty.</td></tr>
    {/each}
  </tbody></table>
  {#if session.can('admin')}
    <form class="row" onsubmit={(e) => { e.preventDefault(); add(); }}>
      <input placeholder="name" aria-label="Vault entry name" bind:value={form.name} required maxlength="100" />
      <select aria-label="Vault entry kind" bind:value={form.kind}>
        {#each KINDS as k (k)}<option value={k}>{k}</option>{/each}
      </select>
      <input type="password" placeholder="secret" aria-label="Vault entry secret" autocomplete="off" bind:value={form.secret} required />
      <button class="primary">Add to vault</button>
    </form>
  {/if}
</div>

<style>
  .vault { overflow: auto; padding: 1rem 1.5rem; flex: 1; max-width: 70rem; }
  h2 { font-size: 1.05rem; color: var(--accent); margin: 0 0 .5rem; }
  .row { display: flex; gap: .5rem; align-items: center; margin: .5rem 0; flex-wrap: wrap; }
</style>
