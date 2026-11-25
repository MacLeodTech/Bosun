<script lang="ts">
  // A unified line diff with the changed words marked inside changed lines. Unchanged stretches are folded away
  // (click to open them). The +/- gutter means colour is never the only signal.
  import { diffLines, diffWords } from '../lib/diff';

  let { a, b, label, context = 3 }: { a: string; b: string; label: string; context?: number } = $props();

  interface Part { t: string; w: boolean }
  interface Row { kind: 'same' | 'add' | 'del'; old: number | null; now: number | null; parts: Part[] }
  type Item = { row: Row } | { fold: number; from: number; count: number };

  const MAX_ROWS = 4000;
  /** Pairing changed lines for word diffs is quadratic in nothing, but long lines make it slow; skip past this. */
  const WORD_LINE_MAX = 2000;

  const rows = $derived.by((): Row[] => {
    const ops = diffLines(a, b);
    const out: Row[] = [];
    let o = 1;
    let n = 1;
    for (let i = 0; i < ops.length; ) {
      const op = ops[i]!;
      if (op.kind === 'same') {
        out.push({ kind: 'same', old: o++, now: n++, parts: [{ t: op.text, w: false }] });
        i++;
        continue;
      }
      // A run of removals followed by a run of additions: pair them up to mark the words that changed.
      let j = i;
      const dels: string[] = [];
      while (j < ops.length && ops[j]!.kind === 'del') dels.push(ops[j++]!.text);
      const adds: string[] = [];
      while (j < ops.length && ops[j]!.kind === 'add') adds.push(ops[j++]!.text);
      const pairs = Math.min(dels.length, adds.length);
      const dParts: Part[][] = dels.map((t) => [{ t, w: false }]);
      const aParts: Part[][] = adds.map((t) => [{ t, w: false }]);
      for (let k = 0; k < pairs; k++) {
        if (dels[k]!.length > WORD_LINE_MAX || adds[k]!.length > WORD_LINE_MAX) continue;
        const w = diffWords(dels[k]!, adds[k]!);
        dParts[k] = w.filter((x) => x.kind !== 'add').map((x) => ({ t: x.text, w: x.kind === 'del' }));
        aParts[k] = w.filter((x) => x.kind !== 'del').map((x) => ({ t: x.text, w: x.kind === 'add' }));
      }
      dels.forEach((_, k) => out.push({ kind: 'del', old: o++, now: null, parts: dParts[k]! }));
      adds.forEach((_, k) => out.push({ kind: 'add', old: null, now: n++, parts: aParts[k]! }));
      i = j;
    }
    return out;
  });

  const added = $derived(rows.filter((r) => r.kind === 'add').length);
  const removed = $derived(rows.filter((r) => r.kind === 'del').length);

  /** Folds that the user has opened, by the index of the first folded row. */
  let opened = $state<Set<number>>(new Set());
  $effect(() => {
    rows;
    opened = new Set();
  });

  const items = $derived.by((): Item[] => {
    const out: Item[] = [];
    let i = 0;
    while (i < rows.length && out.length < MAX_ROWS) {
      if (rows[i]!.kind !== 'same') {
        out.push({ row: rows[i++]! });
        continue;
      }
      let j = i;
      while (j < rows.length && rows[j]!.kind === 'same') j++;
      const atStart = i === 0;
      const atEnd = j === rows.length;
      const keepHead = atStart ? 0 : context;
      const keepTail = atEnd ? 0 : context;
      const hidden = j - i - keepHead - keepTail;
      if (hidden > 1 && !opened.has(i)) {
        for (let k = i; k < i + keepHead; k++) out.push({ row: rows[k]! });
        out.push({ fold: i, from: i + keepHead, count: hidden });
        for (let k = j - keepTail; k < j; k++) out.push({ row: rows[k]! });
      } else {
        for (let k = i; k < j; k++) out.push({ row: rows[k]! });
      }
      i = j;
    }
    return out;
  });

  function open(i: number) {
    opened = new Set([...opened, i]);
  }
</script>

<div class="diff">
  <div class="sum small muted">
    {#if added + removed === 0}No differences.{:else}{added} added, {removed} removed.{/if}
  </div>
  <div class="rows code" role="group" aria-label={label}>
    {#each items as it, i (i)}
      {#if 'fold' in it}
        <button class="fold" onclick={() => open(it.fold)}>⋯ {it.count} unchanged lines</button>
      {:else}
        {@const r = it.row}
        <div class="r {r.kind}">
          <span class="no" aria-hidden="true">{r.old ?? ''}</span>
          <span class="no" aria-hidden="true">{r.now ?? ''}</span>
          <span class="mark" aria-hidden="true">{r.kind === 'add' ? '+' : r.kind === 'del' ? '−' : ' '}</span>
          <span class="t">{#each r.parts as p, k (k)}<span class:w={p.w}>{p.t}</span>{/each}</span>
          {#if r.kind !== 'same'}<span class="sr">{r.kind === 'add' ? 'added' : 'removed'}</span>{/if}
        </div>
      {/if}
    {/each}
  </div>
</div>

<style>
  .diff { display: flex; flex-direction: column; flex: 1; min-height: 0; min-width: 0; }
  .sum { padding: .15rem .5rem; border-bottom: 1px solid var(--border-subtle); }
  .rows { flex: 1; overflow: auto; font-family: var(--font-mono); font-size: var(--fs-data); line-height: 18px; }
  .r { display: flex; min-height: 18px; width: max-content; min-width: 100%; }
  .no { flex: none; width: 4.5ch; padding-right: .5ch; text-align: right; color: var(--text-2); user-select: none; }
  .mark { flex: none; width: 2ch; text-align: center; color: var(--text-2); user-select: none; }
  .t { white-space: pre; padding-right: 1ch; }
  .r.add { background: var(--df-add-bg); }
  .r.del { background: var(--df-del-bg); }
  .r.add .w { background: var(--df-add-word); }
  .r.del .w { background: var(--df-del-word); }
  .fold { display: block; width: 100%; text-align: left; background: var(--surface-1); border: 0; border-radius: 0; color: var(--text-2); padding: 0 .6rem; font-family: var(--font-mono); font-size: var(--fs-xs); line-height: 18px; }
  .fold:hover:not(:disabled) { color: var(--text-1); border: 0; }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
</style>
