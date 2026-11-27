<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';

  interface VaultEntry { id: number; name: string; kind: string; hint: string }
  interface Cell { identity: string; verdict: string; status: number | null; similarity: number; error: string | null }
  interface Row { label: string; owner: string; cells: Cell[]; skipped: string | null }
  interface Finding { kind: string; label: string; owner: string; identity: string; status: number | null }
  interface Result { rows: Row[]; findings: Finding[] }
  interface Account { name: string; header: string; value: string; vaultId: string; prefix: string }

  let accounts = $state<Account[]>([
    { name: 'alice', header: 'Cookie', value: '', vaultId: '', prefix: '' },
    { name: 'bob', header: 'Cookie', value: '', vaultId: '', prefix: '' },
  ]);
  // One probe per line: `flow-id owner [allowed,allowed] [label]`.
  let probeText = $state('');
  let vault = $state<VaultEntry[]>([]);
  let result = $state<Result | null>(null);
  let busy = $state(false);
  let error = $state('');

  const KIND: Record<string, string> = {
    broken_access_control: 'Broken access control',
    missing_authentication: 'No login needed',
  };

  function probes() {
    return probeText
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [id, owner, allowed, ...label] = l.split(/\s+/);
        return {
          flow_id: Number(id),
          owner,
          allowed: allowed && allowed !== '-' ? allowed.split(',') : [],
          label: label.join(' ') || undefined,
        };
      });
  }

  async function run() {
    error = '';
    result = null;
    busy = true;
    try {
      const identities = accounts
        .filter((a) => a.name.trim())
        .map((a) =>
          a.vaultId
            ? { name: a.name.trim(), vault: [{ vault_id: Number(a.vaultId), header: a.header, prefix: a.prefix }] }
            : { name: a.name.trim(), headers: a.value ? [[a.header, a.value]] : [] },
        );
      result = await api.post<Result>('/auth-matrix', { identities, probes: probes() });
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  const cellOf = (r: Row, who: string) => r.cells.find((c) => c.identity === who);
  const columns = $derived(result ? [...new Set(result.rows.flatMap((r) => r.cells.map((c) => c.identity)))] : []);

  onMount(async () => {
    try {
      vault = (await api.get<{ entries: VaultEntry[] }>('/vault')).entries;
    } catch {
      vault = [];
    }
  });
</script>

<div class="matrix">
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <h2>Authorisation matrix</h2>
  <p class="small muted">
    Replays recorded requests as each account and as nobody, and compares each answer with the owner's. An account
    that gets the same answer and is not the owner or listed as allowed has reached something it should not. Every
    request goes through the scope gate.
  </p>

  <h3>Accounts</h3>
  {#each accounts as a, i (i)}
    <div class="row">
      <input aria-label="Account {i + 1} name" placeholder="name" bind:value={a.name} />
      <input aria-label="Account {i + 1} header" placeholder="header" bind:value={a.header} />
      <input aria-label="Account {i + 1} value" placeholder="header value" autocomplete="off" bind:value={a.value} disabled={!!a.vaultId} />
      <select aria-label="Account {i + 1} vault entry" bind:value={a.vaultId}>
        <option value="">value typed here</option>
        {#each vault as v (v.id)}<option value={String(v.id)}>vault: {v.name}</option>{/each}
      </select>
      {#if a.vaultId}<input aria-label="Account {i + 1} prefix" placeholder="prefix, e.g. Bearer " bind:value={a.prefix} />{/if}
      <button aria-label="Remove account {i + 1}" onclick={() => accounts.splice(i, 1)}>Remove</button>
    </div>
  {/each}
  <button onclick={() => accounts.push({ name: '', header: 'Cookie', value: '', vaultId: '', prefix: '' })} disabled={accounts.length >= 20}>Add account</button>

  <h3>Requests</h3>
  <p class="small muted">One per line: <code>flow-id owner [allowed,allowed|-] [label]</code>. Use the flow ids from History.</p>
  <textarea aria-label="Probes" rows="5" bind:value={probeText} placeholder="12 alice - order 1"></textarea>
  <div class="row">
    <button class="primary" onclick={run} disabled={busy || !session.can('tester') || !probeText.trim()}>
      {busy ? 'Running…' : 'Run matrix'}
    </button>
  </div>

  {#if result}
    <h3>Findings ({result.findings.length})</h3>
    {#if result.findings.length === 0}
      <p class="muted">No account reached something it should not.</p>
    {:else}
      <ul aria-label="Matrix findings">
        {#each result.findings as f, i (i)}
          <li><strong>{KIND[f.kind] ?? f.kind}</strong>: {f.identity === 'anonymous' ? 'nobody' : f.identity} got {f.owner}'s answer to {f.label} (status {f.status ?? '?'})</li>
        {/each}
      </ul>
    {/if}
    <table class="grid" aria-label="Matrix results">
      <thead><tr><th>Request</th><th>Owner</th>{#each columns as c (c)}<th>{c}</th>{/each}</tr></thead>
      <tbody>
        {#each result.rows as r, i (i)}
          <tr>
            <td>{r.label}</td>
            <td>{r.owner}</td>
            {#if r.skipped}
              <td class="muted" colspan={columns.length}>{r.skipped}</td>
            {:else}
              {#each columns as c (c)}
                {@const cell = cellOf(r, c)}
                <td class:bad={cell?.verdict === 'same'}>{cell ? `${cell.verdict}${cell.status ? ` ${cell.status}` : ''}` : ''}</td>
              {/each}
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .matrix { overflow: auto; padding: 1rem 1.5rem; flex: 1; max-width: 70rem; }
  h2 { font-size: 1.05rem; color: var(--accent); margin: 0 0 .5rem; }
  h3 { font-size: .95rem; margin: 1rem 0 .4rem; }
  .row { display: flex; gap: .5rem; align-items: center; margin: .4rem 0; flex-wrap: wrap; }
  textarea { width: 100%; font-family: var(--mono, monospace); }
  td.bad { color: var(--danger, #c0392b); font-weight: 600; }
</style>
