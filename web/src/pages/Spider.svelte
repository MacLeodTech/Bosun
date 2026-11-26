<script lang="ts">
  // The spider: crawl a site from a start URL, following links, GET forms, robots.txt and sitemaps inside the scope.
  // The server does the crawling (`/crawl/crawls`): every request goes through the scope gate and is recorded in the
  // history (source `crawler`), so the pages also show up in the site map. POST forms are sent only when ticked.
  // Everything from the target is shown as text.
  // Progress arrives as `crawl_*` events on the event stream; a slow poll stays on as a fallback in case the stream
  // is down. The page list is fetched incrementally (`from`), so an event only says "there is more".
  import { onDestroy } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import type { components } from '../lib/api-types';

  type Detail = components['schemas']['CrawlDetail'];
  type Page = components['schemas']['CrawlPage'];

  const canSend = $derived(session.can('tester'));
  const LABELS: Record<Detail['state'], string> = { running: 'Crawling', done: 'Done', stopped: 'Stopped', failed: 'Failed' };

  let url = $state('http://');
  let depth = $state(5);
  let maxPages = $state(1000);
  let robots = $state(true);
  let sitemap = $state(true);
  let postForms = $state(false);
  let error = $state('');
  let status = $state<Detail | null>(null);
  let pages = $state<Page[]>([]);
  let timer: ReturnType<typeof setInterval> | undefined;

  const fail = (e: unknown) => { error = e instanceof Error ? e.message : String(e); };
  const running = $derived(status?.state === 'running');

  let polling = false;
  let again = false;
  const stopTimer = () => { clearInterval(timer); timer = undefined; };

  async function poll(id: number) {
    // One fetch at a time; an event that arrives meanwhile asks for another.
    if (polling) { again = true; return; }
    polling = true;
    try {
      const d = await api.get<Detail>(`/crawl/crawls/${id}?from=${pages.length}`);
      pages = pages.concat(d.results);
      status = { ...d, results: [] };
      if (d.state !== 'running') stopTimer();
    } catch (e) {
      stopTimer();
      fail(e);
    } finally {
      polling = false;
      if (again) { again = false; if (status?.state === 'running') void poll(id); }
    }
  }

  const off = session.on((e) => {
    if (e.type === 'reload' && status) void poll(status.id);
    else if ((e.type === 'crawl_progress' || e.type === 'crawl_done') && status && e.id === status.id) void poll(e.id);
  });

  async function start() {
    error = '';
    pages = [];
    status = null;
    try {
      const i = await api.post<{ id: number }>('/crawl/crawls', {
        start: [url.trim()], max_depth: depth, max_pages: maxPages, respect_robots: robots, use_sitemap: sitemap, submit_post_forms: postForms,
      });
      status = { id: i.id, state: 'running' } as Detail;
      timer = setInterval(() => void poll(i.id), 5000);
      await poll(i.id);
    } catch (e) {
      fail(e);
    }
  }

  async function stop() {
    if (!status) return;
    try { await api.post(`/crawl/crawls/${status.id}/stop`); } catch (e) { fail(e); }
  }

  onDestroy(() => { stopTimer(); off(); });
</script>

<div class="toolbar">
  <input class="mono grow" aria-label="Start URL" placeholder="https://host/" bind:value={url} />
  <label class="small">Depth <input class="num" type="number" min="0" max="100" aria-label="Depth" bind:value={depth} /></label>
  <label class="small">Pages <input class="num" type="number" min="1" max="20000" aria-label="Page limit" bind:value={maxPages} /></label>
  <button class="primary" data-testid="spider-start" disabled={!canSend || running || url.trim().length < 8} onclick={start}>Start</button>
  <button data-testid="spider-stop" disabled={!running} onclick={stop}>Stop</button>
</div>
<div class="toolbar">
  <label class="small"><input type="checkbox" bind:checked={robots} /> Respect robots.txt</label>
  <label class="small"><input type="checkbox" bind:checked={sitemap} /> Read sitemaps</label>
  <label class="small"><input type="checkbox" aria-label="Submit POST forms" bind:checked={postForms} /> Submit POST forms (can change data)</label>
</div>
{#if error}<p class="error" role="alert">{error}</p>{/if}

<div class="body">
  {#if status}
    <p class="small pad" role="status" data-testid="spider-state">
      {LABELS[status.state]}: {status.pages} pages, {status.requests} requests, {status.out_of_scope.length} links outside the scope{#if status.truncated}, stopped at the page limit{/if}.
      {#if status.error}<span class="bad">{status.error}</span>{/if}
    </p>
  {:else}
    <p class="small muted pad">Follows links, GET forms, robots.txt and sitemaps from the start URL. Every request goes through the scope gate, so nothing outside the scope is requested, and is recorded in the history.</p>
  {/if}
  {#if pages.length}
    <table class="grid" aria-label="Pages" data-testid="spider-pages">
      <thead><tr><th>Status</th><th>Method</th><th>URL</th><th>Title</th><th>Depth</th><th>Found on</th></tr></thead>
      <tbody>
        {#each pages as p, i (i)}
          <tr>
            <td class="tnum" class:bad={!p.status || p.status >= 400}>{p.status ?? p.error ?? ''}</td>
            <td>{p.method}</td>
            <td class="mono">{p.url}</td>
            <td>{p.title ?? ''}</td>
            <td class="tnum">{p.depth}</td>
            <td class="mono">{p.found_on ?? ''}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
  {#if status && status.out_of_scope.length}
    <h4>Outside the scope (not requested)</h4>
    <ul class="mono" data-testid="spider-out">{#each status.out_of_scope as u (u)}<li>{u}</li>{/each}</ul>
  {/if}
  {#if status && status.forms.length}
    <h4>Forms</h4>
    <ul class="mono">{#each status.forms as f, i (i)}<li>{f.method} {f.action} ({f.fields.map((x) => x.name).join(', ')})</li>{/each}</ul>
  {/if}
</div>

<style>
  .body { flex: 1; min-height: 0; overflow: auto; display: flex; flex-direction: column; }
  .num { width: 5rem; }
  h4 { margin: .8rem .5rem .3rem; }
  ul { margin: .2rem 0; padding-left: 1.7rem; }
  .bad { color: var(--bad); }
</style>
