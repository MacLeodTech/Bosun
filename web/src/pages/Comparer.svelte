<script lang="ts">
  // The Comparer: a word or byte diff of any two texts, computed by the server (`/comparer/diff`). The pieces are
  // shown as text, never as HTML. The +/- markers mean colour is not the only signal.
  import { api } from '../lib/api';
  import { inbox } from '../lib/inbox.svelte';
  import { bytesToB64, textToBytes } from '../lib/bytes';
  import type { components } from '../lib/api-types';

  type Result = components['schemas']['DiffResult'];
  type Level = components['schemas']['DiffLevel'];

  let a = $state('');
  let b = $state('');
  let level = $state<Level>('words');
  let result = $state<Result | null>(null);
  let error = $state('');
  let busy = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let seq = 0;

  const bytesA = $derived(textToBytes(a, 'utf8'));
  const bytesB = $derived(textToBytes(b, 'utf8'));
  const dec = new TextDecoder('utf-8');

  interface Piece { kind: 'equal' | 'delete' | 'insert'; text: string }
  const pieces = $derived.by((): Piece[] => {
    if (!result) return [];
    return result.ops.map((o) => ({
      kind: o.kind,
      text: o.kind === 'insert'
        ? dec.decode(bytesB.subarray(o.b_start, o.b_start + o.len))
        : dec.decode(bytesA.subarray(o.a_start, o.a_start + o.len)),
    }));
  });

  // "Send to Comparer" fills a side; take what is waiting.
  $effect(() => {
    const m = inbox.comparer;
    if (!m) return;
    inbox.comparer = null;
    if (m.a !== undefined) a = m.a;
    if (m.b !== undefined) b = m.b;
    schedule();
  });

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(run, 300);
  }

  async function run() {
    const mine = ++seq;
    error = '';
    busy = true;
    try {
      const r = await api.post<Result>('/comparer/diff', { a: bytesToB64(bytesA), b: bytesToB64(bytesB), level });
      if (mine === seq) result = r;
    } catch (e) {
      if (mine === seq) { error = e instanceof Error ? e.message : String(e); result = null; }
    } finally {
      if (mine === seq) busy = false;
    }
  }

  function swap() { [a, b] = [b, a]; schedule(); }
</script>

<div class="toolbar">
  <select bind:value={level} onchange={run} aria-label="Compare by"><option value="words">Words</option><option value="bytes">Bytes</option></select>
  <button onclick={swap}>Swap sides</button>
  <button onclick={run} disabled={busy}>{busy ? 'Comparing…' : 'Compare'}</button>
  <span class="spacer"></span>
  {#if result}
    <span class="small" role="status">{result.changed_bytes} of {result.equal_bytes + result.changed_bytes} bytes differ{#if result.coarse}. These are too different or too large to compare piece by piece, so the result is coarse{/if}.</span>
  {/if}
</div>
{#if error}<p class="error" role="alert">{error}</p>{/if}

<div class="panes">
  <textarea class="code edit" spellcheck="false" placeholder="Left" bind:value={a} oninput={schedule} aria-label="Left side"></textarea>
  <textarea class="code edit" spellcheck="false" placeholder="Right" bind:value={b} oninput={schedule} aria-label="Right side"></textarea>
</div>
<div class="code out" aria-label="Differences">
  {#if result}{#each pieces as p, i (i)}{#if p.kind === 'equal'}<span>{p.text}</span>{:else if p.kind === 'delete'}<del class="del" title="Only on the left">−{p.text}</del>{:else}<ins class="ins" title="Only on the right">+{p.text}</ins>{/if}{/each}{:else}<span class="muted">Type or paste two texts to compare them.</span>{/if}
</div>

<style>
  .panes { display: grid; grid-template-columns: 1fr 1fr; min-height: 8rem; height: 35%; border-bottom: 1px solid var(--line); }
  .edit { resize: none; border: 0; background: var(--bg); padding: .5rem; min-width: 0; }
  .edit:first-child { border-right: 1px solid var(--line); }
  .out { flex: 1; min-height: 0; overflow: auto; padding: .5rem; white-space: pre-wrap; overflow-wrap: anywhere; }
  .del { background: color-mix(in srgb, var(--bad) 25%, transparent); text-decoration: none; }
  .ins { background: color-mix(in srgb, var(--ok, #2a7) 25%, transparent); text-decoration: none; }
</style>
