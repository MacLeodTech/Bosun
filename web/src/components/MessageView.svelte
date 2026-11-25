<script lang="ts">
  // Shows one HTTP message. Target content is hostile: it is only ever shown as text, or rendered in a fully
  // sandboxed iframe (no scripts, opaque origin, and it inherits this page's CSP).
  import { prefs, type PaneRole, type MessageViewMode } from '../lib/prefs.svelte';
  import { b64ToBytes, bytesToText, fmtSize, hexDump, splitMessage, textToBytes, bytesToB64, type TextMode } from '../lib/bytes';

  let {
    raw,
    decodedBody = null,
    editable = false,
    onEdit,
    title = '',
    rawRemaining = 0,
    decodedMore = false,
    onMore,
    downloadHref = '',
    role,
  }: {
    raw: string | null;
    decodedBody?: string | null;
    editable?: boolean;
    onEdit?: (b64: string) => void;
    title?: string;
    /** Bytes of the stored body that are not loaded yet. */
    rawRemaining?: number;
    /** The decoded body goes on past what is loaded. */
    decodedMore?: boolean;
    /** Load the next page of the stored body (false) or of the decoded one (true). */
    onMore?: (decoded: boolean) => void;
    /** Where the whole body can be downloaded from. */
    downloadHref?: string;
    /** Which kind of pane this is; its view (raw, headers, ...) is remembered per kind. */
    role?: PaneRole;
  } = $props();

  let localView = $state<MessageViewMode>('raw');
  const view = $derived(editable ? 'raw' : role ? prefs.view[role] : localView);
  function setView(v: MessageViewMode) {
    if (role) prefs.setView(role, v);
    else localView = v;
  }
  let showDecoded = $state(true);

  const bytes = $derived(raw ? b64ToBytes(raw) : new Uint8Array());
  const parts = $derived(splitMessage(bytes));
  const decoded = $derived(decodedBody ? b64ToBytes(decodedBody) : null);
  const text = $derived.by(() => {
    if (decoded && showDecoded && !editable) {
      const head = bytesToText(parts.head).text;
      return { text: head + '\r\n\r\n' + bytesToText(decoded).text, mode: 'utf8' as TextMode };
    }
    return bytesToText(bytes);
  });
  const headers = $derived(
    bytesToText(parts.head)
      .text.split(/\r?\n/)
      .slice(1)
      .map((l) => {
        const i = l.indexOf(':');
        return i < 0 ? [l, ''] : [l.slice(0, i), l.slice(i + 1).trim()];
      }),
  );
  const renderBody = $derived(bytesToText(decoded ?? parts.body).text);

  let draft = $state('');
  $effect(() => {
    draft = text.text;
  });

  function input(e: Event) {
    draft = (e.currentTarget as HTMLTextAreaElement).value;
    onEdit?.(bytesToB64(textToBytes(draft, text.mode)));
  }
</script>

<div class="msg">
  <div class="msg-bar">
    {#if title}<strong>{title}</strong>{/if}
    <div class="seg">
      {#each ['raw', 'headers', 'hex', 'render'] as const as v (v)}
        <button class:active={view === v} onclick={() => setView(v)} disabled={editable && v !== 'raw'}>{v}</button>
      {/each}
    </div>
    {#if decoded && !editable}
      <label class="small"><input type="checkbox" bind:checked={showDecoded} /> decoded body</label>
    {/if}
    {#if text.mode === 'latin1'}<span class="badge">binary</span>{/if}
    {#if downloadHref}<a class="small" href={downloadHref} download>download body</a>{/if}
  </div>
  {#if raw === null}
    <div class="empty">No message.</div>
  {:else if view === 'raw'}
    {#if editable}
      <textarea class="code" spellcheck="false" value={draft} oninput={input}></textarea>
    {:else}
      <pre class="code">{text.text}</pre>
    {/if}
  {:else if view === 'headers'}
    <div class="scroll">
      <table class="kv">
        <tbody>
          {#each headers as [k, v], i (i)}
            <tr><td>{k}</td><td>{v}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else if view === 'hex'}
    <pre class="code">{hexDump(bytes)}</pre>
  {:else}
    <iframe class="render" title="Rendered response (sandboxed, no scripts)" sandbox="" referrerpolicy="no-referrer" srcdoc={renderBody}></iframe>
  {/if}
  {#if onMore && ((decoded && showDecoded && !editable) ? decodedMore : rawRemaining > 0)}
    <div class="more">
      <span class="small muted">
        {#if decoded && showDecoded && !editable}Showing the first part of the decoded body.{:else}{fmtSize(rawRemaining)} of the body not loaded.{/if}
      </span>
      <button class="small" onclick={() => onMore(!!(decoded && showDecoded && !editable))}>Load more</button>
    </div>
  {/if}
</div>

<style>
  .msg { display: flex; flex-direction: column; min-height: 0; height: 100%; }
  .msg-bar { display: flex; gap: .6rem; align-items: center; padding: .25rem .4rem; border-bottom: 1px solid var(--line); }
  .code { flex: 1; margin: 0; overflow: auto; padding: .5rem; white-space: pre-wrap; word-break: break-all; }
  textarea.code { resize: none; border: 0; background: var(--bg2); color: var(--fg); }
  .scroll { overflow: auto; flex: 1; }
  .render { flex: 1; border: 0; background: #fff; }
  .empty { padding: 1rem; color: var(--muted); }
  .more { display: flex; gap: .6rem; align-items: center; padding: .25rem .5rem; border-top: 1px solid var(--line); }
</style>
