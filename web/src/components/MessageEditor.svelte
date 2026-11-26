<script lang="ts">
  // The editor for a raw request: text (CodeMirror) or bytes (hex), with pretty-print for a JSON, XML or HTML body.
  // `text` is what the person edits; `mode` says how its characters map to bytes (UTF-8, or Latin-1 when the
  // original was not UTF-8). A hex edit can change bytes that text cannot hold, so it hands back both.
  import RawEditor from './RawEditor.svelte';
  import HexEditor from './HexEditor.svelte';
  import { bytesToText, wireBytes, type TextMode } from '../lib/bytes';
  import { detectLang, contentTypeOf, splitText } from '../lib/highlight';
  import { pretty } from '../lib/pretty';

  let { text, mode, label, readOnly = false, onchange }: {
    text: string;
    mode: TextMode;
    label: string;
    readOnly?: boolean;
    onchange?: (text: string, mode: TextMode) => void;
  } = $props();

  let view = $state<'text' | 'hex'>('text');
  let note = $state('');

  const bytes = $derived(wireBytes(text, mode));
  const parts = $derived(splitText(text.replace(/\r\n/g, '\n')));
  const tidy = $derived(parts.sep ? pretty(parts.body, detectLang(contentTypeOf(parts.head), parts.body)) : null);

  function hex(b: Uint8Array) {
    const d = bytesToText(b);
    onchange?.(d.text, d.mode);
  }
  function prettify() {
    if (tidy === null) return;
    onchange?.(`${parts.head}\n\n${tidy}`, mode);
    note = 'Body re-indented. Content-Length is not changed: use "Update Content-Length" when you send.';
  }
</script>

<div class="medit">
  <div class="bar small">
    <div class="seg">
      <button class:active={view === 'text'} aria-pressed={view === 'text'} onclick={() => (view = 'text')}>text</button>
      <button class:active={view === 'hex'} aria-pressed={view === 'hex'} onclick={() => (view = 'hex')}>hex</button>
    </div>
    {#if view === 'text'}
      <button class="ghost small" disabled={readOnly || tidy === null} title="Re-indent a JSON, XML or HTML body (shown as text, never rendered)" onclick={prettify}>pretty-print body</button>
    {/if}
    {#if mode === 'latin1'}<span class="badge" title="The message is not valid UTF-8; each character here is one byte.">binary</span>{/if}
    <span class="muted">{bytes.length} bytes</span>
    {#if note}<span class="muted" role="status">{note}</span>{/if}
  </div>
  {#if view === 'text'}
    <RawEditor value={text} {label} {readOnly} onchange={(t) => onchange?.(t, mode)} />
  {:else}
    <HexEditor {bytes} {label} onchange={hex} />
  {/if}
</div>

<style>
  .medit { flex: 1; min-height: 0; min-width: 0; display: flex; flex-direction: column; }
  .bar { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; padding: .2rem .4rem; border-bottom: 1px solid var(--border-subtle); }
</style>
