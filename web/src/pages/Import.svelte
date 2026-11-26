<script lang="ts">
  // Import: request definitions from a file become Repeater tabs. Nothing is sent. The preview and the file's text
  // are shown as plain text only; the server parses, and saves only when "Import" is pressed.
  import { api, ApiError } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import type { components } from '../lib/api-types';

  type Reply = components['schemas']['ImportReply'];
  type Fmt = components['schemas']['ImportBody']['format'];

  const FORMATS: { id: Fmt; label: string }[] = [
    { id: 'openapi', label: 'OpenAPI / Swagger (JSON or YAML)' },
    { id: 'graphql', label: 'GraphQL introspection result (JSON)' },
    { id: 'postman', label: 'Postman collection' },
    { id: 'har', label: 'HAR (requests, optionally responses)' },
    { id: 'urls', label: 'URL list (one per line)' },
    { id: 'burp', label: 'Burp XML export (requests, optionally responses)' },
  ];
  const MAX = 32 * 1024 * 1024;

  let format = $state<Fmt>('openapi');
  let content = $state('');
  let baseUrl = $state('');
  let liveUrl = $state('');
  let storeResponses = $state(false);
  let fileName = $state('');
  let preview = $state<Reply | null>(null);
  let done = $state<Reply | null>(null);
  let error = $state('');
  let busy = $state(false);
  const canImport = $derived(session.can('tester'));
  // A GraphQL endpoint URL fetches the introspection live (through the scope gate): no file needed.
  const live = $derived(format === 'graphql' && liveUrl.trim().length > 0);
  const ready = $derived(live || content.length > 0);

  async function pick(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    if (!f) return;
    if (f.size > MAX) { error = 'The file is larger than 32 MiB.'; return; }
    content = await f.text();
    fileName = f.name;
    reset();
  }
  function reset() { preview = null; done = null; error = ''; }

  async function run(dry: boolean) {
    busy = true; error = ''; done = null;
    try {
      const r = await api.post<Reply>('/import', {
        format, content: live ? '' : content, base_url: baseUrl.trim() || null, dry_run: dry,
        introspection_url: live ? liveUrl.trim() : null, store_responses: storeResponses,
      });
      if (dry) preview = r;
      else {
        done = r; preview = null;
        // Repeater tabs now exist in the project: the Repeater reads them again.
        window.dispatchEvent(new Event('bosun:repeater-reload'));
      }
    } catch (e) {
      preview = null;
      error = e instanceof ApiError ? e.message : 'The import failed.';
    } finally { busy = false; }
  }
</script>

<div class="toolbar">
  <label class="small">Format
    <select bind:value={format} onchange={reset} aria-label="Import format">
      {#each FORMATS as f (f.id)}<option value={f.id}>{f.label}</option>{/each}
    </select>
  </label>
  <label class="small">Base URL
    <input class="mono" bind:value={baseUrl} oninput={reset} placeholder="https://api.example.com (needed for GraphQL)" aria-label="Base URL" />
  </label>
  {#if format === 'graphql'}
    <label class="small">Fetch from
      <input class="mono" bind:value={liveUrl} oninput={reset} placeholder="https://api.example.com/graphql (in scope)" aria-label="Introspection URL" />
    </label>
  {/if}
  {#if format === 'har' || format === 'burp'}
    <label class="small"><input type="checkbox" bind:checked={storeResponses} onchange={reset} aria-label="Store responses" /> Store responses as flows</label>
  {/if}
  <label class="small">File <input type="file" onchange={pick} aria-label="Import file" /></label>
</div>
{#if error}<p class="error" role="alert">{error}</p>{/if}

<div class="body">
  <textarea class="code edit" spellcheck="false" bind:value={content} oninput={reset} aria-label="Import text" placeholder={fileName ? '' : 'Paste the file here, or pick one above'}></textarea>
  <div class="toolbar">
    <button disabled={!ready || busy || !canImport} onclick={() => run(true)}>Preview</button>
    <button class="primary" disabled={!ready || busy || !canImport || !preview || preview.parsed === 0} onclick={() => run(false)}>Import</button>
    <span class="small muted">Nothing is sent, except the introspection query to a Fetch from URL (scope gate applies). Imports are saved as Repeater tabs.</span>
  </div>
  {#if preview}
    <section class="pad" aria-label="Import preview">
      <p><b>{preview.parsed}</b> requests found{#if preview.dropped} ({preview.dropped} dropped by the per-import limit){/if}.</p>
      <p class="small">Hosts the requests go to: <span class="mono">{preview.hosts.join(', ') || 'none'}</span></p>
      <p class="small muted">Check the scope (Target) before sending any of them: only in-scope hosts can be sent from the Repeater.</p>
      {#each preview.notes as n (n)}<p class="small muted">{n}</p>{/each}
      <pre class="code out">{preview.requests.join('\n')}</pre>
    </section>
  {/if}
  {#if done}
    <p class="pad" role="status">Imported {done.added} of {done.parsed} requests as Repeater tabs{#if done.not_added}; {done.not_added} did not fit{/if}{#if done.responses_stored}; {done.responses_stored} responses stored as flows{/if}.</p>
  {/if}
</div>

<style>
  .body { flex: 1; min-height: 0; overflow: auto; display: flex; flex-direction: column; }
  .edit { min-height: 8rem; resize: vertical; border: 0; background: var(--bg); padding: .5rem; }
  .out { margin: 0; padding: .5rem; max-height: 16rem; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
