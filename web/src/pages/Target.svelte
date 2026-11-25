<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import type { ScopeRule, ScopeSpec, SiteMapEntry } from '../lib/types';

  let entries = $state<SiteMapEntry[]>([]);
  let scope = $state<ScopeSpec>({ include: [], exclude: [] });
  let filter = $state('');
  let open = $state<Record<string, boolean>>({});
  let error = $state('');
  let msg = $state('');
  const canEdit = $derived(session.can('tester'));

  const origins = $derived.by(() => {
    const m = new Map<string, SiteMapEntry[]>();
    for (const e of entries) {
      if (filter && !e.host.includes(filter)) continue;
      const def = (e.scheme === 'http' && e.port === 80) || (e.scheme === 'https' && e.port === 443);
      const key = `${e.scheme}://${e.host}${def ? '' : ':' + e.port}`;
      const list = m.get(key) ?? [];
      list.push(e);
      m.set(key, list);
    }
    return [...m.entries()];
  });

  async function load() {
    [entries, scope] = await Promise.all([api.get<SiteMapEntry[]>('/sitemap'), api.get<ScopeSpec>('/scope')]);
    scope.include ??= [];
    scope.exclude ??= [];
  }

  async function save() {
    error = '';
    msg = '';
    const clean = (rs: ScopeRule[]) =>
      rs.filter((r) => r.host.trim()).map((r) => ({ host: r.host.trim(), scheme: r.scheme || null, port: r.port || null, path: r.path || null, allow_private: !!r.allow_private }));
    try {
      scope = await api.put<ScopeSpec>('/scope', { include: clean(scope.include), exclude: clean(scope.exclude) });
      msg = 'Scope saved.';
      entries = await api.get<SiteMapEntry[]>('/sitemap');
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  function addHost(host: string) {
    if (!scope.include.some((r) => r.host === host)) scope.include = [...scope.include, { host }];
    save();
  }

  onMount(load);
</script>

<div class="cols">
  <section class="map">
    <div class="toolbar">
      <strong>Site map</strong>
      <input placeholder="filter hosts" aria-label="Filter hosts" bind:value={filter} />
      <span class="spacer"></span>
      <button onclick={load}>Refresh</button>
    </div>
    <div class="scroll">
      {#each origins as [origin, list] (origin)}
        <div class="origin">
          <button class="link" class:oos={!list.some((e) => e.in_scope)} onclick={() => (open[origin] = !open[origin])}>
            {open[origin] ? '▾' : '▸'} {origin} <span class="muted small">({list.length})</span>
          </button>
          {#if canEdit && !list.some((e) => e.in_scope)}
            <button class="small" onclick={() => addHost(list[0]!.host)}>Add to scope</button>
          {/if}
        </div>
        {#if open[origin]}
          <table class="grid small">
            <tbody>
              {#each list as e (e.path)}
                <tr class:oos={!e.in_scope}>
                  <td class="mono">{e.path}</td><td>{e.methods.join(', ')}</td><td>{e.last_status ?? ''}</td><td>{e.count}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      {:else}
        <p class="muted pad">Nothing recorded yet. Browse through the proxy.</p>
      {/each}
    </div>
  </section>

  <section class="scope">
    <div class="toolbar">
      <strong>Scope</strong>
      <span class="spacer"></span>
      {#if canEdit}<button class="primary" onclick={save}>Save</button>{/if}
    </div>
    <div class="scroll pad">
      <p class="small muted">
        Active tools only ever send to in-scope targets. Empty include list means nothing is in scope.
        Host patterns: <code>example.com</code>, or <code>*.example.com</code> for one sub-domain level. Path is a regex. Tools refuse a host that resolves to this machine (loopback, link-local, cloud metadata) unless the rule ticks Allow local.
      </p>
      {#if error}<p class="error">{error}</p>{/if}
      {#if msg}<p class="ok">{msg}</p>{/if}
      {#each [['include', 'Include'], ['exclude', 'Exclude']] as const as [kind, label] (kind)}
        <h3>{label}</h3>
        <table class="grid">
          <thead><tr><th>Scheme</th><th>Host</th><th>Port</th><th>Path regex</th><th title="Let this rule reach this machine's own addresses (loopback, link-local, the server's networks)">Allow local</th><th></th></tr></thead>
          <tbody>
            {#each scope[kind] as r, i (i)}
              <tr>
                <td>
                  <select bind:value={r.scheme} disabled={!canEdit} aria-label="{label} rule {i + 1}: scheme">
                    <option value={null}>any</option><option value="http">http</option><option value="https">https</option>
                  </select>
                </td>
                <td><input bind:value={r.host} disabled={!canEdit} class="mono" aria-label="{label} rule {i + 1}: host" /></td>
                <td><input type="number" bind:value={r.port} disabled={!canEdit} class="num" aria-label="{label} rule {i + 1}: port" /></td>
                <td><input bind:value={r.path} disabled={!canEdit} class="mono" aria-label="{label} rule {i + 1}: path regex" /></td>
                <td><input type="checkbox" bind:checked={r.allow_private} disabled={!canEdit} aria-label="{label} rule {i + 1}: allow local addresses" /></td>
                <td>{#if canEdit}<button aria-label="Remove {kind} rule {i + 1}" onclick={() => (scope[kind] = scope[kind].filter((_, j) => j !== i))}>Remove</button>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if canEdit}<button class="small" onclick={() => (scope[kind] = [...scope[kind], { host: '' }])}>Add {kind} rule</button>{/if}
      {/each}
    </div>
  </section>
</div>

<style>
  .cols { display: grid; grid-template-columns: 1.3fr 1fr; flex: 1; min-height: 0; }
  section { display: flex; flex-direction: column; min-height: 0; border-right: 1px solid var(--line); }
  .scroll { overflow: auto; flex: 1; }
  .origin { display: flex; gap: .5rem; align-items: center; padding: .1rem .5rem; }
  .link { border: 0; background: none; text-align: left; flex: 1; }
  .oos { color: var(--muted); }
  .pad { padding: .5rem; }
  .num { width: 5rem; }
  td input:not([type='checkbox']):not(.num) { width: 100%; }
</style>
