<script lang="ts">
  // Host analysis: the distinct endpoints and parameters of one host across the whole history, with counts. The
  // server does the counting (`/analysis`); every name, path and value is the target's text and is only shown as text.
  import { onMount, untrack } from 'svelte';
  import { api } from '../lib/api';
  import { inbox } from '../lib/inbox.svelte';
  import { searchHistory } from '../lib/flowactions';
  import { toasts } from '../lib/toasts.svelte';
  import type { components } from '../lib/api-types';
  import type { SiteMapEntry } from '../lib/types';

  type Report = components['schemas']['HostAnalysis'];

  let origins = $state<string[]>([]);
  let pick = $state('');
  let report = $state<Report | null>(null);
  let error = $state('');
  let busy = $state(false);
  let text = $state('');
  let seq = 0;

  const key = (host: string, port: number) => `${host}:${port}`;
  const endpoints = $derived((report?.endpoints ?? []).filter((e) => !text || `${e.method} ${e.path} ${e.params.join(' ')}`.toLowerCase().includes(text.toLowerCase())));
  const params = $derived((report?.params ?? []).filter((p) => !text || `${p.name} ${p.values.join(' ')}`.toLowerCase().includes(text.toLowerCase())));

  async function run(origin: string) {
    const i = origin.lastIndexOf(':');
    if (i < 1) return;
    const mine = ++seq;
    busy = true;
    error = '';
    try {
      const r = await api.get<Report>(`/analysis?host=${encodeURIComponent(origin.slice(0, i))}&port=${origin.slice(i + 1)}`);
      if (mine === seq) report = r;
    } catch (e) {
      if (mine !== seq) return;
      report = null;
      error = e instanceof Error ? e.message : String(e);
    }
    if (mine === seq) busy = false;
  }

  onMount(async () => {
    try {
      const sm = await api.get<SiteMapEntry[]>('/sitemap');
      origins = [...new Set(sm.map((e) => key(e.host, e.port)))].sort();
    } catch (e) {
      toasts.push({ text: `Could not list the hosts: ${e instanceof Error ? e.message : e}` });
    }
  });

  // "Analyse this host" puts the host here; take it once.
  $effect(() => {
    const want = inbox.analysis;
    if (!want) return;
    inbox.analysis = null;
    const k = key(want.host, want.port);
    untrack(() => {
      if (!origins.includes(k)) origins = [...origins, k].sort();
      pick = k;
      void run(k);
    });
  });

  const status = (e: { statuses: { status: number; count: number }[] }) => e.statuses.map((s) => `${s.status}×${s.count}`).join(' ');
</script>

<div class="toolbar">
  <label class="small" for="an-host">Host</label>
  <select id="an-host" bind:value={pick} onchange={() => run(pick)}>
    <option value="" disabled>Choose a host</option>
    {#each origins as o (o)}<option value={o}>{o}</option>{/each}
  </select>
  <input type="search" aria-label="Filter the analysis" placeholder="Filter" bind:value={text} />
  <span class="spacer"></span>
  {#if report}<span class="small">{report.requests} requests read</span>{/if}
</div>
<div class="scroll">
  {#if error}
    <p class="pad" role="alert">{error}</p>
  {:else if !report}
    <p class="muted pad">{busy ? 'Loading…' : 'Choose a host, or use “Analyse this host” on a request in the history.'}</p>
  {:else}
    {#if report.capped}<p class="muted pad">The host has more requests than were read; this covers the newest ones.</p>{/if}
    {#if report.truncated}<p class="muted pad">There were more endpoints or parameters than are listed.</p>{/if}
    <h3 class="pad">Endpoints ({report.endpoints.length})</h3>
    <table class="grid" aria-label="Endpoints">
      <thead><tr><th>Method</th><th>Path</th><th>Requests</th><th>Responses</th><th>Parameters</th><th></th></tr></thead>
      <tbody>
        {#each endpoints as e (e.method + ' ' + e.path)}
          <tr>
            <td class="nowrap">{e.method}</td>
            <td class="val">{e.path}</td>
            <td class="num">{e.count}</td>
            <td class="nowrap">{status(e)}</td>
            <td class="val">{e.params.join(', ')}</td>
            <td><button onclick={() => searchHistory(e.path.replace(/\{(n|uuid|hex)\}.*$/, ''))} aria-label="Search the history for {e.path}">History</button></td>
          </tr>
        {:else}
          <tr><td colspan="6" class="muted">{report.endpoints.length ? 'Nothing matches.' : 'No requests recorded for this host.'}</td></tr>
        {/each}
      </tbody>
    </table>
    <h3 class="pad">Parameters ({report.params.length})</h3>
    <table class="grid" aria-label="Parameters">
      <thead><tr><th>Where</th><th>Name</th><th>Requests</th><th>Endpoints</th><th>Example values</th></tr></thead>
      <tbody>
        {#each params as p (p.where + ' ' + p.name)}
          <tr>
            <td class="nowrap">{p.where}</td>
            <td class="val">{p.name}</td>
            <td class="num">{p.count}</td>
            <td class="num">{p.endpoints}</td>
            <td class="val">{p.values.join(' · ')}{p.more_values ? ' · …' : ''}</td>
          </tr>
        {:else}
          <tr><td colspan="5" class="muted">{report.params.length ? 'Nothing matches.' : 'No parameters seen.'}</td></tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .scroll { overflow: auto; flex: 1; }
  .pad { padding: .5rem .75rem; margin: 0; }
  h3 { font-size: var(--fs-ui); color: var(--text-muted); }
  .val { font-family: var(--font-mono); font-size: var(--fs-data); white-space: pre-wrap; overflow-wrap: anywhere; max-width: 40rem; }
  .nowrap { white-space: nowrap; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
</style>
