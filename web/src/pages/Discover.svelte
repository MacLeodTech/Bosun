<script lang="ts">
  // Content and parameter discovery: forced browsing of paths and parameter names from a wordlist.
  // The server does the work (`/discover/runs`): every request goes through the scope gate, and only the hits are
  // recorded in the history. It learns what "not found" looks like first, so a site that answers 200 to everything
  // gives no hits. Everything from the target is shown as text.
  import { onDestroy } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import type { components } from '../lib/api-types';

  type Detail = components['schemas']['DiscoverDetail'];

  const canSend = $derived(session.can('tester'));
  const LABELS: Record<Detail['state'], string> = { running: 'Running', done: 'Done', stopped: 'Stopped', failed: 'Failed' };

  let url = $state('http://');
  let mode = $state<'paths' | 'params'>('paths');
  let words = $state('');
  let extensions = $state('');
  let depth = $state(2);
  let limit = $state(5000);
  let error = $state('');
  let status = $state<Detail | null>(null);
  let timer: ReturnType<typeof setInterval> | undefined;

  const fail = (e: unknown) => { error = e instanceof Error ? e.message : String(e); };
  const running = $derived(status?.state === 'running');
  const stopTimer = () => { clearInterval(timer); timer = undefined; };
  const lines = (s: string) => s.split(/[\s,]+/).filter(Boolean);

  async function poll(id: number) {
    try {
      const d = await api.get<Detail>(`/discover/runs/${id}`);
      status = d;
      if (d.state !== 'running') stopTimer();
    } catch (e) {
      stopTimer();
      fail(e);
    }
  }

  async function start() {
    error = '';
    status = null;
    try {
      const i = await api.post<{ id: number }>('/discover/runs', {
        base: url.trim(), mode, words: lines(words), extensions: mode === 'paths' ? lines(extensions) : [],
        max_depth: depth, max_requests: limit,
      });
      status = { id: i.id, state: 'running', results: [], directories: [], noise: 0, truncated: false } as unknown as Detail;
      timer = setInterval(() => void poll(i.id), 1000);
      await poll(i.id);
    } catch (e) {
      fail(e);
    }
  }

  async function stop() {
    if (!status) return;
    try { await api.post(`/discover/runs/${status.id}/stop`); } catch (e) { fail(e); }
  }

  onDestroy(stopTimer);
</script>

<div class="toolbar">
  <select aria-label="What to find" bind:value={mode}>
    <option value="paths">Paths</option>
    <option value="params">Parameters</option>
  </select>
  <input class="mono grow" aria-label="Base URL" placeholder={mode === 'paths' ? 'https://host/app/' : 'https://host/page'} bind:value={url} />
  {#if mode === 'paths'}
    <label class="small">Depth <input class="num" type="number" min="0" max="10" aria-label="Depth" bind:value={depth} /></label>
  {/if}
  <label class="small">Requests <input class="num" type="number" min="10" max="200000" aria-label="Request limit" bind:value={limit} /></label>
  <button class="primary" data-testid="discover-start" disabled={!canSend || running || url.trim().length < 8} onclick={start}>Start</button>
  <button data-testid="discover-stop" disabled={!running} onclick={stop}>Stop</button>
</div>
<div class="toolbar">
  <input class="mono grow" aria-label="Words" placeholder="words, separated by spaces or commas (empty: the built-in list)" bind:value={words} />
  {#if mode === 'paths'}
    <input class="mono" aria-label="Extensions" placeholder="extensions: php bak" bind:value={extensions} />
  {/if}
</div>
{#if error}<p class="error" role="alert">{error}</p>{/if}

<div class="body">
  {#if status}
    <p class="small pad" role="status" data-testid="discover-state">
      {LABELS[status.state]}: {status.requests ?? 0} requests, {status.results.length} found{#if status.noise}, {status.noise} dropped as a wildcard{/if}{#if status.truncated}, stopped at the request limit{/if}.
      {#if status.error}<span class="bad">{status.error}</span>{/if}
    </p>
  {:else}
    <p class="small muted pad">Tries each word against the base URL. Names that cannot exist are requested first to learn what "not found" looks like here, so a page that answers 200 to everything is not reported. Every request goes through the scope gate; only the hits are recorded in the history.</p>
  {/if}
  {#if status && status.results.length}
    <table class="grid" aria-label="Found" data-testid="discover-hits">
      <thead><tr><th>Status</th><th>URL</th><th>Size</th><th>Type</th><th>Note</th><th>Cluster</th></tr></thead>
      <tbody>
        {#each status.results as h, i (i)}
          <tr>
            <td class="tnum" class:bad={h.status >= 500}>{h.status}</td>
            <td class="mono">{h.url}{#if h.location} → {h.location}{/if}</td>
            <td class="tnum">{h.bytes}</td>
            <td>{h.content_type ?? ''}</td>
            <td>{h.note ?? ''}</td>
            <td class="tnum">{h.cluster}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .body { flex: 1; min-height: 0; overflow: auto; display: flex; flex-direction: column; }
  .num { width: 5rem; }
  .bad { color: var(--bad); }
</style>
