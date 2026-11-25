<script lang="ts">
  import { css } from '../../lib/style';
  import { MIN_SIZE, nudge, type Split } from '../../lib/layout';
  import { workspace } from '../../lib/workspace.svelte';
  import DockNode from './DockNode.svelte';

  let { split }: { split: Split } = $props();
  let el = $state<HTMLElement | undefined>();
  const horizontal = $derived(split.dir === 'row');

  function startResize(e: PointerEvent, i: number) {
    if (e.button !== 0 || !el) return;
    e.preventDefault();
    const handle = e.currentTarget as HTMLElement;
    handle.setPointerCapture(e.pointerId);
    const total = (horizontal ? el.clientWidth : el.clientHeight) || 1;
    const start = horizontal ? e.clientX : e.clientY;
    const sizes = [...split.sizes];
    const move = (ev: PointerEvent) => {
      const d = ((horizontal ? ev.clientX : ev.clientY) - start) / total;
      workspace.resize(split.id, nudge(sizes, i, d));
    };
    const up = () => {
      handle.removeEventListener('pointermove', move);
      handle.removeEventListener('pointerup', up);
      handle.removeEventListener('pointercancel', up);
    };
    handle.addEventListener('pointermove', move);
    handle.addEventListener('pointerup', up);
    handle.addEventListener('pointercancel', up);
  }

  function onKey(e: KeyboardEvent, i: number) {
    const grow = horizontal ? 'ArrowRight' : 'ArrowDown';
    const shrink = horizontal ? 'ArrowLeft' : 'ArrowUp';
    const step = e.shiftKey ? 0.1 : 0.02;
    if (e.key === grow) workspace.resize(split.id, nudge(split.sizes, i, step));
    else if (e.key === shrink) workspace.resize(split.id, nudge(split.sizes, i, -step));
    else if (e.key === 'Home') workspace.resize(split.id, nudge(split.sizes, i, -1));
    else if (e.key === 'End') workspace.resize(split.id, nudge(split.sizes, i, 1));
    else if (e.key === 'Enter') equalise(i);
    else return;
    e.preventDefault();
  }

  /** The two panels beside a divider take an equal share of what they have together. */
  function equalise(i: number) {
    const sizes = [...split.sizes];
    const both = sizes[i]! + sizes[i + 1]!;
    sizes[i] = both / 2;
    sizes[i + 1] = both / 2;
    workspace.resize(split.id, sizes);
  }
</script>

<div class="split" class:horiz={horizontal} bind:this={el}>
  {#each split.children as child, i (child.id)}
    {#if i > 0}
      <!-- A focusable separator is the ARIA "window splitter" widget; svelte's a11y lint only knows it as static. -->
      <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
      <div
        class="sep"
        role="separator"
        tabindex="0"
        aria-label="Resize panels"
        aria-orientation={horizontal ? 'vertical' : 'horizontal'}
        aria-valuemin={Math.round(MIN_SIZE * 100)}
        aria-valuemax={100 - Math.round(MIN_SIZE * 100)}
        aria-valuenow={Math.round(split.sizes[i - 1]! * 100)}
        onpointerdown={(e) => startResize(e, i - 1)}
        ondblclick={() => equalise(i - 1)}
        onkeydown={(e) => onKey(e, i - 1)}
      ></div>
    {/if}
    <div class="cell" use:css={{ '--grow': String(split.sizes[i]) }}>
      <DockNode node={child} />
    </div>
  {/each}
</div>

<style>
  .split { display: flex; flex-direction: column; flex: 1; min-width: 0; min-height: 0; }
  .split.horiz { flex-direction: row; }
  .cell { flex: var(--grow) 1 0; min-width: 0; min-height: 0; display: flex; flex-direction: column; }
  /* A 5px hit area drawn as a 1px line. */
  .sep { flex: none; position: relative; background: var(--border-subtle); z-index: 2; }
  .split.horiz > .sep { width: 1px; cursor: col-resize; }
  .split:not(.horiz) > .sep { height: 1px; cursor: row-resize; }
  .sep::before { content: ''; position: absolute; }
  .split.horiz > .sep::before { inset: 0 -2px; }
  .split:not(.horiz) > .sep::before { inset: -2px 0; }
  .sep:hover, .sep:focus-visible { background: var(--accent); }
  .sep:focus-visible { outline: none; }
</style>
