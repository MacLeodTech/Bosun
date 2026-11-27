<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import type { MapKind, MapRule, MatchRule, RuleTarget } from '../lib/types';

  const targets: [RuleTarget, string][] = [
    ['request_header', 'Request header'], ['request_body', 'Request body'], ['request_first_line', 'Request first line'],
    ['response_header', 'Response header'], ['response_body', 'Response body'], ['response_first_line', 'Response first line'],
  ];
  const kinds: [MapKind, string][] = [['map_local', 'Map Local'], ['map_remote', 'Map Remote'], ['throttle', 'Throttle']];
  let rules = $state<MatchRule[]>([]);
  let msg = $state('');
  let error = $state('');
  let maps = $state<MapRule[]>([]);
  let mapMsg = $state('');
  let mapError = $state('');
  const canEdit = $derived(session.can('tester'));
  // Map Local serves files from the machine the engine runs on, so changing a list that has one needs an admin.
  const canEditMaps = $derived(session.can(maps.some((m) => m.kind === 'map_local') ? 'admin' : 'tester'));

  onMount(async () => {
    rules = await api.get<MatchRule[]>('/rules');
    maps = await api.get<MapRule[]>('/map-rules');
  });

  function add() {
    rules = [...rules, { enabled: true, target: 'request_header', match: '', replace: '', regex: false, comment: '', operation: '' }];
  }

  function addMap() {
    maps = [...maps, { enabled: true, kind: 'throttle', host: '', path_prefix: '', directory: '', target: '', latency_ms: 500, bytes_per_sec: 0, comment: '' }];
  }

  function num(v: unknown): number {
    const n = Math.floor(Number(v));
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  async function save() {
    error = '';
    msg = '';
    try {
      rules = await api.put<MatchRule[]>('/rules', rules);
      msg = 'Saved. The rules apply to new traffic.';
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function saveMaps() {
    mapError = '';
    mapMsg = '';
    try {
      maps = await api.put<MapRule[]>('/map-rules', maps.map((m) => ({ ...m, latency_ms: num(m.latency_ms), bytes_per_sec: num(m.bytes_per_sec) })));
      mapMsg = 'Saved. The rules apply to new requests.';
    } catch (e) {
      mapError = e instanceof Error ? e.message : String(e);
    }
  }
</script>

<div class="toolbar">
  <span class="muted small">Header rules: empty match adds the replacement as a new header; empty replacement removes matching header lines. A body rule with a GraphQL operation name fires only on that operation.</span>
  <span class="spacer"></span>
  {#if canEdit}<button onclick={add}>Add rule</button><button class="primary" onclick={save}>Save</button>{/if}
</div>
{#if error}<p class="error">{error}</p>{/if}
{#if msg}<p class="ok">{msg}</p>{/if}
<div class="scroll">
  <table class="grid">
    <thead><tr><th>On</th><th>Where</th><th>Match</th><th>Replace</th><th>Regex</th><th>GraphQL operation</th><th>Comment</th><th></th></tr></thead>
    <tbody>
      {#each rules as r, i (i)}
        <tr>
          <td><input type="checkbox" bind:checked={r.enabled} disabled={!canEdit} aria-label="Rule {i + 1}: enabled" /></td>
          <td>
            <select bind:value={r.target} disabled={!canEdit} aria-label="Rule {i + 1}: where it applies">
              {#each targets as [v, l] (v)}<option value={v}>{l}</option>{/each}
            </select>
          </td>
          <td><input bind:value={r.match} disabled={!canEdit} class="mono" aria-label="Rule {i + 1}: match" /></td>
          <td><input bind:value={r.replace} disabled={!canEdit} class="mono" aria-label="Rule {i + 1}: replace with" /></td>
          <td><input type="checkbox" bind:checked={r.regex} disabled={!canEdit} aria-label="Rule {i + 1}: match is a regular expression" /></td>
          <td>
            {#if r.target === 'request_body' || r.target === 'response_body'}
              <input bind:value={r.operation} disabled={!canEdit} class="mono" placeholder="any body" aria-label="Rule {i + 1}: only on this GraphQL operation name" />
            {/if}
          </td>
          <td><input bind:value={r.comment} disabled={!canEdit} aria-label="Rule {i + 1}: comment" /></td>
          <td>{#if canEdit}<button aria-label="Remove rule {i + 1}" onclick={() => (rules = rules.filter((_, j) => j !== i))}>Remove</button>{/if}</td>
        </tr>
      {:else}
        <tr><td colspan="8" class="muted">No rules.</td></tr>
      {/each}
    </tbody>
  </table>

  <div class="toolbar">
    <strong>Map Local, Map Remote and throttle</strong>
    <span class="muted small">First matching Map rule answers; first matching throttle shapes. A Map Remote target must be in scope. Map Local reads only inside its directory.</span>
    <span class="spacer"></span>
    {#if canEditMaps}<button onclick={addMap}>Add map rule</button><button class="primary" onclick={saveMaps}>Save map rules</button>{/if}
  </div>
  {#if mapError}<p class="error">{mapError}</p>{/if}
  {#if mapMsg}<p class="ok">{mapMsg}</p>{/if}
  <table class="grid">
    <thead><tr><th>On</th><th>Kind</th><th>Host</th><th>Path prefix</th><th>Directory, target or limits</th><th>Comment</th><th></th></tr></thead>
    <tbody>
      {#each maps as m, i (i)}
        <tr>
          <td><input type="checkbox" bind:checked={m.enabled} disabled={!canEditMaps} aria-label="Map rule {i + 1}: enabled" /></td>
          <td>
            <select bind:value={m.kind} disabled={!canEditMaps} aria-label="Map rule {i + 1}: kind">
              {#each kinds as [v, l] (v)}<option value={v}>{l}</option>{/each}
            </select>
          </td>
          <td><input bind:value={m.host} disabled={!canEditMaps} class="mono" placeholder="any, or *.example.com" aria-label="Map rule {i + 1}: host" /></td>
          <td><input bind:value={m.path_prefix} disabled={!canEditMaps} class="mono" placeholder="/" aria-label="Map rule {i + 1}: path prefix" /></td>
          <td>
            {#if m.kind === 'map_local'}
              <input bind:value={m.directory} disabled={!canEditMaps} class="mono" placeholder="/path/to/directory" aria-label="Map rule {i + 1}: directory" />
            {:else if m.kind === 'map_remote'}
              <input bind:value={m.target} disabled={!canEditMaps} class="mono" placeholder="https://staging.example.com" aria-label="Map rule {i + 1}: target origin" />
            {:else}
              <span class="limits">
                <input type="number" min="0" bind:value={m.latency_ms} disabled={!canEditMaps} aria-label="Map rule {i + 1}: latency in milliseconds" /> ms
                <input type="number" min="0" bind:value={m.bytes_per_sec} disabled={!canEditMaps} aria-label="Map rule {i + 1}: bytes a second (0 is unlimited)" /> B/s
              </span>
            {/if}
          </td>
          <td><input bind:value={m.comment} disabled={!canEditMaps} aria-label="Map rule {i + 1}: comment" /></td>
          <td>{#if canEditMaps}<button aria-label="Remove map rule {i + 1}" onclick={() => (maps = maps.filter((_, j) => j !== i))}>Remove</button>{/if}</td>
        </tr>
      {:else}
        <tr><td colspan="7" class="muted">No map rules.</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .scroll { overflow: auto; flex: 1; }
  td input:not([type='checkbox']) { width: 100%; }
  .limits { display: flex; gap: 0.4rem; align-items: center; }
  .limits input { width: 7rem; }
</style>
