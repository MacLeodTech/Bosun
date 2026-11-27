<script lang="ts">
  // The editor for a raw request: text (CodeMirror) or bytes (hex), with pretty-print for a JSON, XML or HTML body.
  // `text` is what the person edits; `mode` says how its characters map to bytes (UTF-8, or Latin-1 when the
  // original was not UTF-8). A hex edit can change bytes that text cannot hold, so it hands back both.
  import RawEditor from './RawEditor.svelte';
  import HexEditor from './HexEditor.svelte';
  import { api } from '../lib/api';
  import { b64ToBytes, bytesToB64, bytesToText, splitMessage, textToBytes, wireBytes, type TextMode } from '../lib/bytes';
  import { grpcSteps, requestPath } from '../lib/protoview';
  import { protoSchema } from '../lib/protoschema.svelte';
  import { detectLang, contentTypeOf, splitText } from '../lib/highlight';
  import { pretty } from '../lib/pretty';

  let { text, mode, label, readOnly = false, onchange }: {
    text: string;
    mode: TextMode;
    label: string;
    readOnly?: boolean;
    onchange?: (text: string, mode: TextMode) => void;
  } = $props();

  let want = $state<'text' | 'hex' | 'decoded'>('text');
  let note = $state('');

  const bytes = $derived(wireBytes(text, mode));
  const parts = $derived(splitText(text.replace(/\r\n/g, '\n')));
  const tidy = $derived(parts.sep ? pretty(parts.body, detectLang(contentTypeOf(parts.head), parts.body)) : null);

  // A gRPC body is binary frames. "decoded" shows them as text (field names too, with a project schema), and turns
  // an edit back into frames, so the request can be changed field by field.
  protoSchema.ensure();
  const steps = $derived(grpcSteps(contentTypeOf(parts.head) ?? ''));
  const view = $derived(want === 'decoded' && !steps ? 'text' : want);
  let decoded = $state('');
  let decodeNote = $state('');
  // The body (and schema) the decoded text stands for, so our own edit does not decode itself again.
  let shownFor = '';
  const bodyOf = (b: Uint8Array) => splitMessage(b).body;
  /** A head with no body yet: it may already end in the blank line (splitMessage needs a byte after it). */
  function withBlankLine(b: Uint8Array): Uint8Array {
    const n = b.length;
    const crlf = n >= 4 && b[n - 4] === 13 && b[n - 3] === 10 && b[n - 2] === 13 && b[n - 1] === 10;
    const lf = n >= 2 && b[n - 2] === 10 && b[n - 1] === 10;
    return crlf || lf ? b : new Uint8Array([...b, 13, 10, 13, 10]);
  }

  $effect(() => {
    if (view !== 'decoded' || !steps) return;
    const body = bodyOf(bytes);
    const key = `${bytesToB64(body)}\0${protoSchema.source}`;
    if (key === shownFor) return;
    const ops = steps.decode;
    const extra = protoSchema.forCall(requestPath(parts.head), false);
    let live = true;
    decodeNote = '';
    if (body.length > (1 << 20)) { decoded = ''; decodeNote = 'The body is too large to edit as text.'; return; }
    api
      .post<{ steps: { output: string }[]; error: { message: string } | null }>('/decoder/apply', { input: bytesToB64(body), ops, ...extra })
      .then((r) => {
        if (!live) return;
        shownFor = key;
        if (r.error) { decoded = ''; decodeNote = r.error.message; return; }
        decoded = bytesToText(b64ToBytes(r.steps[ops.length - 1]!.output)).text;
      })
      .catch((e) => { if (live) decodeNote = e instanceof Error ? e.message : String(e); });
    return () => (live = false);
  });

  let encodeTimer: ReturnType<typeof setTimeout> | undefined;
  let encodeSeq = 0;
  function editDecoded(t: string) {
    decoded = t;
    clearTimeout(encodeTimer);
    const mine = ++encodeSeq;
    encodeTimer = setTimeout(async () => {
      if (!steps) return;
      try {
        const r = await api.post<{ steps: { output: string }[]; error: { message: string } | null }>('/decoder/apply', {
          input: bytesToB64(textToBytes(t, 'utf8')), ops: steps.encode, ...protoSchema.forCall(requestPath(parts.head), false),
        });
        if (mine !== encodeSeq) return;
        if (r.error) { decodeNote = r.error.message; return; }
        const body = b64ToBytes(r.steps[steps.encode.length - 1]!.output);
        // Keep the head as it is, with the blank line after it; Content-Length is the Repeater's "Update Content-Length".
        const cur = bytes;
        const cut = cur.length - bodyOf(cur).length;
        const prefix = cut === cur.length ? withBlankLine(cur) : cur.subarray(0, cut);
        const all = new Uint8Array(prefix.length + body.length);
        all.set(prefix);
        all.set(body, prefix.length);
        shownFor = `${bytesToB64(body)}\0${protoSchema.source}`;
        decodeNote = '';
        const d = bytesToText(all);
        onchange?.(d.text, d.mode);
      } catch (e) {
        if (mine === encodeSeq) decodeNote = e instanceof Error ? e.message : String(e);
      }
    }, 300);
  }

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
      <button class:active={view === 'text'} aria-pressed={view === 'text'} onclick={() => (want = 'text')}>text</button>
      <button class:active={view === 'hex'} aria-pressed={view === 'hex'} onclick={() => (want = 'hex')}>hex</button>
      {#if steps}
        <button class:active={view === 'decoded'} aria-pressed={view === 'decoded'} title="The gRPC messages as text: edit a field and the frames are rebuilt" onclick={() => (want = 'decoded')}>gRPC</button>
      {/if}
    </div>
    {#if view === 'text'}
      <button class="ghost small" disabled={readOnly || tidy === null} title="Re-indent a JSON, XML or HTML body (shown as text, never rendered)" onclick={prettify}>pretty-print body</button>
    {/if}
    {#if mode === 'latin1'}<span class="badge" title="The message is not valid UTF-8; each character here is one byte.">binary</span>{/if}
    <span class="muted">{bytes.length} bytes</span>
    {#if note}<span class="muted" role="status">{note}</span>{/if}
    {#if decodeNote && view === 'decoded'}<span class="error small" role="alert">{decodeNote}</span>{/if}
  </div>
  {#if view === 'decoded'}
    <RawEditor value={decoded} label={`${label} (gRPC messages)`} {readOnly} onchange={editDecoded} />
  {:else if view === 'text'}
    <RawEditor value={text} {label} {readOnly} onchange={(t) => onchange?.(t, mode)} />
  {:else}
    <HexEditor {bytes} {label} onchange={hex} />
  {/if}
</div>

<style>
  .medit { flex: 1; min-height: 0; min-width: 0; display: flex; flex-direction: column; }
  .bar { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; padding: .2rem .4rem; border-bottom: 1px solid var(--border-subtle); }
</style>
