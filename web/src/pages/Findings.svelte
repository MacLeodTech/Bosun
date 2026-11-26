<script lang="ts">
  // Findings: what the open request's response holds that is worth a look (comments, scripts, links, forms, URLs,
  // quoted paths) and the parameters of the request. The server finds them (`/flows/{id}/engage`); every value is the
  // target's text and is only ever shown as text, never as markup or as a link that this page follows.
  import { api } from '../lib/api';
  import { historyView } from '../lib/historyView.svelte';
  import { downloadCsrfPoc } from '../lib/flowactions';
  import { toasts } from '../lib/toasts.svelte';
  import type { components } from '../lib/api-types';

  type Report = components['schemas']['EngageReport'];
  type Kind = components['schemas']['FindingKind'];

  const KINDS: { id: Kind; label: string }[] = [
    { id: 'comment', label: 'Comment' },
    { id: 'inline_script', label: 'Inline script' },
    { id: 'script_src', label: 'Script file' },
    { id: 'link', label: 'Link' },
    { id: 'form_action', label: 'Form action' },
    { id: 'resource', label: 'Resource' },
    { id: 'url', label: 'URL' },
    { id: 'path', label: 'Path' },
  ];
  const labelOf = (k: Kind) => KINDS.find((x) => x.id === k)?.label ?? k;

  let report = $state<Report | null>(null);
  let forId = $state<number | null>(null);
  let error = $state('');
  let kind = $state<'all' | Kind>('all');
  let text = $state('');

  const id = $derived(historyView.openId ?? historyView.selectedId);
  const findings = $derived(
    (report?.findings ?? []).filter((f) => (kind === 'all' || f.kind === kind) && (!text || f.value.toLowerCase().includes(text.toLowerCase()))),
  );
  const counts = $derived(Object.fromEntries(KINDS.map((k) => [k.id, (report?.findings ?? []).filter((f) => f.kind === k.id).length])) as Record<Kind, number>);

  $effect(() => {
    const want = id;
    if (want === null) {
      report = null;
      forId = null;
      return;
    }
    let live = true;
    error = '';
    api
      .get<Report>(`/flows/${want}/engage`)
      .then((r) => {
        if (!live) return;
        report = r;
        forId = want;
      })
      .catch((e) => {
        if (!live) return;
        report = null;
        forId = null;
        error = e instanceof Error ? e.message : String(e);
      });
    return () => {
      live = false;
    };
  });

  async function copy(v: string) {
    try {
      await navigator.clipboard.writeText(v);
      toasts.push({ text: 'Copied.' });
    } catch {
      toasts.push({ text: 'The browser did not allow copying.' });
    }
  }
</script>

<div class="toolbar">
  {#if forId !== null}<span class="small">Request {forId}</span>{/if}
  <label class="small" for="fd-kind">Show</label>
  <select id="fd-kind" bind:value={kind}>
    <option value="all">All ({report?.findings.length ?? 0})</option>
    {#each KINDS as k (k.id)}{#if counts[k.id]}<option value={k.id}>{k.label} ({counts[k.id]})</option>{/if}{/each}
  </select>
  <input type="search" aria-label="Filter findings" placeholder="Filter" bind:value={text} />
  <span class="spacer"></span>
  {#if forId !== null}
    <button onclick={() => downloadCsrfPoc(forId!, false)} title="Save an HTML page that sends this request from a browser signed in to the target">CSRF proof of concept</button>
  {/if}
</div>
<div class="scroll">
  {#if id === null}
    <p class="muted pad">Select a request in the history.</p>
  {:else if error}
    <p class="pad" role="alert">{error}</p>
  {:else if !report}
    <p class="muted pad">Loading…</p>
  {:else}
    {#if report.undecoded}<p class="muted pad">The response could not be decoded ({report.undecoded}), so only its request is shown.</p>{/if}
    {#if report.truncated}<p class="muted pad">Only the first part of a large body was scanned.</p>{/if}
    <table class="grid">
      <thead><tr><th>Kind</th><th>Value</th><th></th></tr></thead>
      <tbody>
        {#each findings as f, n (n)}
          <tr>
            <td class="nowrap">{labelOf(f.kind)}</td>
            <td class="val">{f.value}</td>
            <td><button onclick={() => copy(f.value)} aria-label="Copy this {labelOf(f.kind).toLowerCase()}">Copy</button></td>
          </tr>
        {:else}
          <tr><td colspan="3" class="muted">{report.findings.length ? 'Nothing matches.' : 'Nothing found in the response.'}</td></tr>
        {/each}
      </tbody>
    </table>
    <h3 class="pad">Parameters</h3>
    <table class="grid" aria-label="Parameters">
      <thead><tr><th>Where</th><th>Name</th><th>Value</th></tr></thead>
      <tbody>
        {#each report.params as p, n (n)}
          <tr><td class="nowrap">{p.where}</td><td class="val">{p.name}</td><td class="val">{p.value}</td></tr>
        {:else}
          <tr><td colspan="3" class="muted">The request has no parameters.</td></tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .scroll { overflow: auto; flex: 1; }
  .pad { padding: .5rem .75rem; margin: 0; }
  h3 { font-size: var(--fs-ui); color: var(--text-muted); }
  .val { font-family: var(--font-mono); font-size: var(--fs-data); white-space: pre-wrap; overflow-wrap: anywhere; max-width: 60rem; }
  .nowrap { white-space: nowrap; }
</style>
