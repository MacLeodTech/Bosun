<script lang="ts">
  // Read-only text with line numbers, colour, find, and (for long bodies) windowing: only the lines on screen are in
  // the DOM, so a 256 KiB body scrolls as smoothly as a short one. Every line is rendered as spans from tokens;
  // target content never goes in as markup.
  import { tick } from 'svelte';
  import type { Line } from '../lib/highlight';
  import { css } from '../lib/style';

  let { lines, label, wrap = true }: { lines: Line[]; label: string; wrap?: boolean } = $props();

  const ROW = 18;
  const OVERSCAN = 20;
  /** Past this many lines wrapping is switched off, because rows then have fixed height and can be windowed. */
  const WRAP_MAX = 3000;
  const MAX_MATCHES = 5000;

  const windowed = $derived(!wrap || lines.length > WRAP_MAX);
  let scroller = $state<HTMLElement | undefined>();
  let top = $state(0);
  let height = $state(400);
  const first = $derived(windowed ? Math.max(0, Math.floor(top / ROW) - OVERSCAN) : 0);
  const last = $derived(windowed ? Math.min(lines.length, Math.ceil((top + height) / ROW) + OVERSCAN) : lines.length);
  const shown = $derived(lines.slice(first, last));
  const gutter = $derived(`${String(lines.length).length + 1}ch`);

  // ---- find
  let findOpen = $state(false);
  let query = $state('');
  let cur = $state(0);
  let findBox = $state<HTMLInputElement | undefined>();
  interface Hit { line: number; from: number; to: number }

  const plain = $derived(lines.map((l) => l.map((t) => t.t).join('')));
  const hits = $derived.by((): Hit[] => {
    const q = query.toLowerCase();
    if (!findOpen || !q) return [];
    const out: Hit[] = [];
    for (let i = 0; i < plain.length && out.length < MAX_MATCHES; i++) {
      const hay = plain[i]!.toLowerCase();
      let at = hay.indexOf(q);
      while (at >= 0 && out.length < MAX_MATCHES) {
        out.push({ line: i, from: at, to: at + q.length });
        at = hay.indexOf(q, at + q.length);
      }
    }
    return out;
  });
  const byLine = $derived.by(() => {
    const m = new Map<number, { h: Hit; i: number }[]>();
    hits.forEach((h, i) => {
      const a = m.get(h.line);
      if (a) a.push({ h, i });
      else m.set(h.line, [{ h, i }]);
    });
    return m;
  });
  $effect(() => {
    // A new query starts from the first match.
    query;
    cur = 0;
  });

  interface Seg { t: string; c: string; hit: 0 | 1 | 2 }
  /** A line's tokens, split where search matches begin and end (1 = a match, 2 = the current match). */
  function segs(line: Line, idx: number): Seg[] {
    const ranges = byLine.get(idx);
    if (!ranges) return line.map((t) => ({ t: t.t, c: t.c, hit: 0 as const }));
    const out: Seg[] = [];
    let pos = 0;
    for (const tk of line) {
      let a = 0;
      const end = pos + tk.t.length;
      for (const { h, i } of ranges) {
        if (h.to <= pos || h.from >= end) continue;
        const s = Math.max(h.from, pos) - pos;
        const e = Math.min(h.to, end) - pos;
        if (s > a) out.push({ t: tk.t.slice(a, s), c: tk.c, hit: 0 });
        out.push({ t: tk.t.slice(s, e), c: tk.c, hit: i === cur ? 2 : 1 });
        a = e;
      }
      if (a < tk.t.length) out.push({ t: tk.t.slice(a), c: tk.c, hit: 0 });
      pos = end;
    }
    return out;
  }

  async function reveal(line: number) {
    if (!scroller) return;
    if (windowed) {
      scroller.scrollTop = Math.max(0, line * ROW - height / 2);
    } else {
      await tick();
      scroller.querySelector(`[data-line="${line}"]`)?.scrollIntoView({ block: 'center' });
    }
  }

  function step(delta: number) {
    if (!hits.length) return;
    cur = (cur + delta + hits.length) % hits.length;
    reveal(hits[cur]!.line);
  }

  async function openFind() {
    findOpen = true;
    await tick();
    findBox?.focus();
    findBox?.select();
  }

  function closeFind() {
    findOpen = false;
    scroller?.focus();
  }

  function onFindKey(e: KeyboardEvent) {
    if (e.key === 'Enter') {
      e.preventDefault();
      step(e.shiftKey ? -1 : 1);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      closeFind();
    }
  }

  function onKey(e: KeyboardEvent) {
    // The browser's own find cannot see lines that are not in the DOM, so Ctrl+F here searches the whole text.
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      openFind();
    }
  }

  export function find() {
    return openFind();
  }
</script>

<div class="wrap">
  {#if findOpen}
    <div class="findbar">
      <input aria-label="Find in message" placeholder="Find" bind:value={query} bind:this={findBox} onkeydown={onFindKey} />
      <span class="small muted tnum" role="status">{query ? (hits.length ? `${cur + 1} of ${hits.length}${hits.length >= MAX_MATCHES ? '+' : ''}` : 'no matches') : ''}</span>
      <button class="ghost" aria-label="Previous match" onclick={() => step(-1)}>↑</button>
      <button class="ghost" aria-label="Next match" onclick={() => step(1)}>↓</button>
      <button class="ghost" aria-label="Close find" onclick={closeFind}>×</button>
    </div>
  {/if}
  <div
    class="code"
    class:windowed
    role="textbox"
    aria-readonly="true"
    aria-multiline="true"
    aria-label={label}
    tabindex="0"
    bind:this={scroller}
    bind:clientHeight={height}
    onscroll={(e) => (top = e.currentTarget.scrollTop)}
    onkeydown={onKey}
    use:css={{ '--row': `${ROW}px`, '--gw': gutter }}
  >
    <div class="sizer" use:css={{ '--total': windowed ? `${lines.length * ROW}px` : 'auto' }}>
      <div class="win" use:css={{ '--y': `${first * ROW}px` }}>
        {#each shown as line, i (first + i)}
          {@const n = first + i}
          <div class="ln-row" data-line={n}>
            <span class="ln" aria-hidden="true">{n + 1}</span>
            <span class="txt">{#each segs(line, n) as s, k (k)}<span class="sx-{s.c || 'none'}" class:hit={s.hit > 0} class:cur={s.hit === 2}>{s.t}</span>{/each}</span>
          </div>
        {/each}
      </div>
    </div>
  </div>
</div>

<style>
  .wrap { display: flex; flex-direction: column; flex: 1; min-height: 0; min-width: 0; }
  .findbar { display: flex; gap: .3rem; align-items: center; padding: .2rem .4rem; border-bottom: 1px solid var(--border-subtle); background: var(--surface-1); }
  .findbar input { width: 14rem; }
  .code { flex: 1; min-height: 0; overflow: auto; margin: 0; font-family: var(--font-mono); font-size: var(--fs-data); line-height: var(--row); font-variant-ligatures: none; }
  .code:focus-visible { outline-offset: -2px; }
  .sizer { position: relative; min-width: 100%; width: max-content; }
  .windowed .sizer { height: var(--total); }
  .windowed .win { position: absolute; left: 0; right: 0; top: 0; transform: translateY(var(--y)); }
  .ln-row { display: flex; min-height: var(--row); }
  .windowed .ln-row { height: var(--row); white-space: pre; }
  .ln { flex: none; position: sticky; left: 0; z-index: 1; width: var(--gw); padding-right: .6ch; text-align: right; color: var(--text-2); background: var(--surface-0); user-select: none; }
  .txt { flex: 1; min-width: 0; padding-left: .5ch; white-space: pre-wrap; word-break: break-all; }
  .windowed .txt { white-space: pre; word-break: normal; }
  .sx-key { color: var(--sx-key); } .sx-string { color: var(--sx-string); } .sx-number { color: var(--sx-number); }
  .sx-bool { color: var(--sx-bool); } .sx-punct { color: var(--sx-punct); } .sx-hname { color: var(--sx-hname); }
  .sx-hvalue { color: var(--sx-hvalue); } .sx-tag { color: var(--sx-tag); } .sx-attr { color: var(--sx-attr); }
  .sx-comment { color: var(--sx-comment); font-style: italic; }
  .hit { background: color-mix(in srgb, var(--warn) 35%, transparent); border-radius: 2px; }
  .hit.cur { background: color-mix(in srgb, var(--accent) 60%, transparent); outline: 1px solid var(--accent); }
</style>
