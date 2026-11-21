<script lang="ts" generics="T">
  // A fixed-row-height virtual list: only visible rows exist in the DOM, so history with millions of rows stays fast.
  import type { Snippet } from 'svelte';
  import { css } from '../lib/style';

  let {
    items,
    rowHeight = 24,
    row,
    onNearEnd,
  }: { items: T[]; rowHeight?: number; row: Snippet<[T, number]>; onNearEnd?: () => void } = $props();

  let scrollTop = $state(0);
  let viewport = $state(400);
  const overscan = 10;
  const start = $derived(Math.max(0, Math.floor(scrollTop / rowHeight) - overscan));
  const end = $derived(Math.min(items.length, Math.ceil((scrollTop + viewport) / rowHeight) + overscan));
  const visible = $derived(items.slice(start, end));

  function onScroll(e: Event) {
    const el = e.currentTarget as HTMLElement;
    scrollTop = el.scrollTop;
    if (onNearEnd && el.scrollTop + el.clientHeight > el.scrollHeight - rowHeight * 20) onNearEnd();
  }
</script>

<div class="vl" onscroll={onScroll} bind:clientHeight={viewport}>
  <div use:css={{ height: `${items.length * rowHeight}px` }} class="vl-inner">
    <div use:css={{ transform: `translateY(${start * rowHeight}px)` }}>
      {#each visible as item, i (start + i)}
        {@render row(item, start + i)}
      {/each}
    </div>
  </div>
</div>

<style>
  .vl { overflow-y: auto; height: 100%; position: relative; }
  .vl-inner { position: relative; }
</style>
