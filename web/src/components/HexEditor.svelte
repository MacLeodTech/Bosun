<script lang="ts">
  // Edit a message as bytes: rows of 16 hex pairs beside the same bytes as ASCII. What is typed is read back as hex
  // (spaces and line breaks are free); anything that is not hex is reported and the bytes stay as they were, so a
  // half-typed edit never changes what is sent. Past HEX_EDIT_MAX bytes it is read-only.
  import { asciiRows, formatHex, hexProblem, HEX_EDIT_MAX, parseHex } from '../lib/hex';

  let { bytes, label, onchange }: { bytes: Uint8Array; label: string; onchange?: (b: Uint8Array) => void } = $props();

  const tooBig = $derived(bytes.length > HEX_EDIT_MAX);
  let draft = $state('');
  let problem = $state('');
  let focused = false;

  // New bytes from outside replace the draft, unless the person is in the middle of typing here.
  $effect(() => {
    const shown = formatHex(bytes);
    if (!focused) { draft = shown; problem = ''; }
  });

  function input(e: Event) {
    draft = (e.currentTarget as HTMLTextAreaElement).value;
    const parsed = parseHex(draft);
    if (parsed) { problem = ''; onchange?.(parsed); } else problem = hexProblem(draft);
  }
  function blur() {
    focused = false;
    const parsed = parseHex(draft);
    if (parsed) draft = formatHex(parsed); // tidy into rows once typing stops
  }

  const rows = $derived(Math.max(1, draft.split('\n').length));
  const ascii = $derived(asciiRows(parseHex(draft) ?? bytes).join('\n'));
</script>

<div class="hexed">
  {#if tooBig}<p class="small muted pad">This message is over {HEX_EDIT_MAX / 1024} KiB: shown here, but not editable as hex.</p>{/if}
  {#if problem}<p class="error small pad" role="status">{problem}</p>{/if}
  <div class="grid">
    <textarea
      class="code hexin" spellcheck="false" aria-label={label} readonly={tooBig} value={draft}
      {rows} wrap="off" oninput={input} onfocus={() => (focused = true)} onblur={blur}
    ></textarea>
    <pre class="code asc" aria-hidden="true">{ascii}</pre>
  </div>
</div>

<style>
  .hexed { flex: 1; min-height: 0; display: flex; flex-direction: column; overflow: auto; background: var(--surface-1); }
  .grid { display: flex; align-items: flex-start; gap: 1rem; padding: .4rem .5rem; }
  .hexin { width: 48ch; resize: none; overflow: hidden; border: 0; background: transparent; color: var(--text-1); padding: 0; line-height: 1.4; }
  .asc { margin: 0; color: var(--text-2); line-height: 1.4; user-select: text; }
  .pad { padding: .25rem .5rem; margin: 0; }
</style>
