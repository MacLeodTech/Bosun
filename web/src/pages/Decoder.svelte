<script lang="ts">
  // The Decoder: turn a text or a message body through a chain of encoders and decoders. The work is done by the
  // server (`/decoder/apply`, `/decoder/smart`); nothing here is rendered as HTML, only shown as text.
  import { api } from '../lib/api';
  import { inbox } from '../lib/inbox.svelte';
  import { b64ToBytes, bytesToB64, bytesToText, fmtSize, hexDump, textToBytes } from '../lib/bytes';
  import type { components } from '../lib/api-types';

  type Op = components['schemas']['Op'];
  type Reply = components['schemas']['DecodeReply'];

  const OPS: { id: Op; label: string; group: string }[] = [
    { id: 'url_decode', label: 'URL decode', group: 'Decode' },
    { id: 'url_decode_form', label: 'URL decode (form, + is space)', group: 'Decode' },
    { id: 'html_decode', label: 'HTML decode', group: 'Decode' },
    { id: 'base64_decode', label: 'Base64 decode', group: 'Decode' },
    { id: 'base64url_decode', label: 'Base64url decode', group: 'Decode' },
    { id: 'hex_decode', label: 'Hex decode', group: 'Decode' },
    { id: 'unicode_unescape', label: 'Unicode unescape (\\u00e9)', group: 'Decode' },
    { id: 'gzip_decode', label: 'gzip decompress', group: 'Decode' },
    { id: 'deflate_decode', label: 'deflate decompress', group: 'Decode' },
    { id: 'brotli_decode', label: 'Brotli decompress', group: 'Decode' },
    { id: 'zstd_decode', label: 'Zstandard decompress', group: 'Decode' },
    { id: 'jwt_decode', label: 'JWT decode', group: 'Decode' },
    { id: 'protobuf_decode', label: 'Protobuf to text (no schema)', group: 'Decode' },
    { id: 'grpc_decode', label: 'gRPC frames to text', group: 'Decode' },
    { id: 'graphql_decode', label: 'GraphQL query and variables', group: 'Decode' },
    { id: 'url_encode', label: 'URL encode', group: 'Encode' },
    { id: 'html_encode', label: 'HTML encode', group: 'Encode' },
    { id: 'base64_encode', label: 'Base64 encode', group: 'Encode' },
    { id: 'base64url_encode', label: 'Base64url encode', group: 'Encode' },
    { id: 'hex_encode', label: 'Hex encode', group: 'Encode' },
    { id: 'unicode_escape', label: 'Unicode escape', group: 'Encode' },
    { id: 'protobuf_encode', label: 'Text to protobuf', group: 'Encode' },
    { id: 'grpc_encode', label: 'Text to gRPC frames', group: 'Encode' },
    { id: 'gzip_encode', label: 'gzip compress', group: 'Encode' },
    { id: 'deflate_encode', label: 'deflate (zlib) compress', group: 'Encode' },
    { id: 'brotli_encode', label: 'Brotli compress', group: 'Encode' },
    { id: 'zstd_encode', label: 'Zstandard compress', group: 'Encode' },
    { id: 'md5', label: 'MD5', group: 'Hash' },
    { id: 'sha1', label: 'SHA-1', group: 'Hash' },
    { id: 'sha256', label: 'SHA-256', group: 'Hash' },
    { id: 'sha512', label: 'SHA-512', group: 'Hash' },
  ];
  const label = (op: Op) => OPS.find((o) => o.id === op)?.label ?? op;
  const groups = ['Decode', 'Encode', 'Hash'];
  const MAX_STEPS = 16;

  let input = $state('');
  let chain = $state<Op[]>([]);
  let pick = $state<Op>('url_decode');
  let reply = $state<Reply | null>(null);
  let error = $state('');
  let busy = $state(false);
  let hex = $state(false);
  let seq = 0;

  // "Send to Decoder" puts text here; take it once.
  $effect(() => {
    const m = inbox.decoder;
    if (!m) return;
    inbox.decoder = null;
    input = m.text;
    reply = null;
  });

  const inputBytes = () => textToBytes(input, 'utf8');

  async function run() {
    const mine = ++seq;
    error = '';
    if (!chain.length) { reply = null; return; }
    busy = true;
    try {
      const r = await api.post<Reply>('/decoder/apply', { input: bytesToB64(inputBytes()), ops: chain });
      if (mine === seq) reply = r;
    } catch (e) {
      if (mine === seq) error = e instanceof Error ? e.message : String(e);
    } finally {
      if (mine === seq) busy = false;
    }
  }

  async function smart() {
    const mine = ++seq;
    error = '';
    busy = true;
    try {
      const r = await api.post<Reply>('/decoder/smart', { input: bytesToB64(inputBytes()) });
      if (mine !== seq) return;
      chain = r.steps.map((s) => s.op);
      reply = r;
    } catch (e) {
      if (mine === seq) error = e instanceof Error ? e.message : String(e);
    } finally {
      if (mine === seq) busy = false;
    }
  }

  function add() { if (chain.length < MAX_STEPS) { chain = [...chain, pick]; void run(); } }
  function remove(i: number) { chain = chain.filter((_, k) => k !== i); void run(); }
  function clear() { chain = []; reply = null; error = ''; seq++; }

  function show(output: string): string {
    const bytes = b64ToBytes(output);
    if (hex) return hexDump(bytes);
    const d = bytesToText(bytes);
    return d.mode === 'utf8' ? d.text : `(not valid UTF-8, shown as Latin-1)\n${d.text}`;
  }

  /** Use a step's output as the new input and drop the steps up to it. */
  function useAsInput(i: number) {
    const s = reply?.steps[i];
    if (!s || s.truncated) return;
    const d = bytesToText(b64ToBytes(s.output));
    input = d.text;
    chain = chain.slice(i + 1);
    void run();
  }
</script>

<div class="toolbar">
  <select bind:value={pick} aria-label="Step to add">
    {#each groups as g (g)}
      <optgroup label={g}>{#each OPS.filter((o) => o.group === g) as o (o.id)}<option value={o.id}>{o.label}</option>{/each}</optgroup>
    {/each}
  </select>
  <button onclick={add} disabled={chain.length >= MAX_STEPS}>Add step</button>
  <button onclick={smart} disabled={!input || busy} title="Guess the layers (URL, Base64, hex, gzip, ...) and peel them off">Smart decode</button>
  <button onclick={clear} disabled={!chain.length && !input}>Clear steps</button>
  <span class="spacer"></span>
  <label class="small"><input type="checkbox" bind:checked={hex} /> Show as hex</label>
</div>
{#if error}<p class="error" role="alert">{error}</p>{/if}

<div class="body">
  <div class="block">
    <div class="small muted pad">Input ({fmtSize(inputBytes().length)})</div>
    <textarea class="code edit" spellcheck="false" bind:value={input} oninput={() => void run()} aria-label="Decoder input"></textarea>
  </div>

  {#each chain as op, i (i + op)}
    {@const s = reply?.steps[i]}
    <div class="block">
      <div class="toolbar small">
        <b>{i + 1}. {label(op)}</b>
        {#if s}<span class="muted">{fmtSize(s.size)}{#if s.truncated}, first {fmtSize(b64ToBytes(s.output).length)} shown{/if}</span>{/if}
        <span class="spacer"></span>
        <button disabled={!s || s.truncated} onclick={() => useAsInput(i)} title="Make this output the input and drop the steps up to here">Use as input</button>
        <button onclick={() => remove(i)} aria-label={`Remove step ${i + 1}`}>Remove</button>
      </div>
      {#if s}
        <pre class="code out">{show(s.output)}</pre>
      {:else if reply?.error && reply.error.step === i}
        <p class="error" role="alert">{reply.error.message}</p>
      {:else if reply?.error && reply.error.step < i}
        <p class="small muted pad">Not run: an earlier step failed.</p>
      {:else if busy}
        <p class="small muted pad">Working…</p>
      {/if}
    </div>
  {/each}
  {#if !chain.length}
    <p class="small muted pad">Add a step, or use Smart decode. Up to {MAX_STEPS} steps; each output is limited to 4 MiB.</p>
  {/if}
</div>

<style>
  .body { flex: 1; min-height: 0; overflow: auto; display: flex; flex-direction: column; }
  .block { border-bottom: 1px solid var(--line); display: flex; flex-direction: column; }
  .edit { min-height: 8rem; resize: vertical; border: 0; background: var(--bg); padding: .5rem; }
  .out { margin: 0; padding: .5rem; max-height: 16rem; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
