<script lang="ts" generics="T">
  // A fixed-row-height virtual list: only visible rows exist in the DOM, so history with millions of rows stays fast.
  // The list itself takes focus and handles the keys (rows are not individual tab stops): ArrowUp/Down, j/k, PageUp/Down,
  // Home/End move the active row, Enter activates it. The parent owns which row is active.
  import type { Snippet } from 'svelte';
  import { css } from '../lib/style';

  let {
    items,
    rowHeight = 24,
    row,
    onNearEnd,
    key,
    activeIndex = -1,
    onSelect,
    onSelectAll,
    onDelete,
    multi = false,
    onActivate,
    onTop,
    label = 'List',
    idPrefix = 'vl',
  }: {
    items: T[];
    rowHeight?: number;
    row: Snippet<[T, number]>;
    onNearEnd?: () => void;
    /** A stable key per item. Without it rows are keyed by position, which re-creates them on every scroll step. */
    key?: (item: T) => string | number;
    /** The active row, or -1. */
    activeIndex?: number;
    /** The user moved to this row with the keyboard. `extend` is true when Shift was held (grow the selection). */
    onSelect?: (index: number, extend: boolean) => void;
    /** Ctrl+A, when the list allows several selected rows. */
    onSelectAll?: () => void;
    /** The Delete key. */
    onDelete?: () => void;
    /** Rows can be selected together: tells assistive technology, and enables Shift+arrows and Ctrl+A. */
    multi?: boolean;
    /** Enter on the active row. */
    onActivate?: (index: number) => void;
    /** The list was scrolled back to the top. */
    onTop?: () => void;
    label?: string;
    /** Rows should have the id `${idPrefix}-row-${index}`: the list points aria-activedescendant at it. */
    idPrefix?: string;
  } = $props();

  let scrollTop = $state(0);
  let viewport = $state(400);
  let el = $state<HTMLElement | null>(null);
  const overscan = 10;
  const start = $derived(Math.max(0, Math.floor(scrollTop / rowHeight) - overscan));
  const end = $derived(Math.min(items.length, Math.ceil((scrollTop + viewport) / rowHeight) + overscan));
  const visible = $derived(items.slice(start, end));

  function onScroll(e: Event) {
    const t = e.currentTarget as HTMLElement;
    scrollTop = t.scrollTop;
    if (onTop && t.scrollTop <= rowHeight) onTop();
    if (onNearEnd && t.scrollTop + t.clientHeight > t.scrollHeight - rowHeight * 20) onNearEnd();
  }

  /** Scroll so row `i` is fully visible, moving as little as possible. */
  export function scrollToIndex(i: number) {
    if (!el || i < 0) return;
    const top = i * rowHeight;
    if (top < el.scrollTop) el.scrollTop = top;
    else if (top + rowHeight > el.scrollTop + el.clientHeight) el.scrollTop = top + rowHeight - el.clientHeight;
  }

  export function scrollToTop() {
    if (el) el.scrollTop = 0;
  }

  /** True when the list is scrolled to (or within a row of) the top, where new rows can be shown without moving anything. */
  export function atTop(): boolean {
    return !el || el.scrollTop <= rowHeight;
  }

  $effect(() => {
    scrollToIndex(activeIndex);
  });

  function onKey(e: KeyboardEvent) {
    if (multi && (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'a') {
      e.preventDefault();
      onSelectAll?.();
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === 'Delete' && onDelete) {
      e.preventDefault();
      onDelete();
      return;
    }
    const page = Math.max(1, Math.floor(viewport / rowHeight) - 1);
    const cur = activeIndex < 0 ? -1 : activeIndex;
    let next: number | null = null;
    switch (e.key) {
      case 'ArrowDown': case 'j': next = cur + 1; break;
      case 'ArrowUp': case 'k': next = cur < 0 ? 0 : cur - 1; break;
      case 'PageDown': next = cur + page; break;
      case 'PageUp': next = cur - page; break;
      case 'Home': next = 0; break;
      case 'End': next = items.length - 1; break;
      case 'Enter':
        if (cur >= 0) {
          e.preventDefault();
          onActivate?.(cur);
        }
        return;
      default: return;
    }
    e.preventDefault();
    if (!items.length) return;
    next = Math.min(items.length - 1, Math.max(0, next));
    if (next !== activeIndex) onSelect?.(next, multi && e.shiftKey);
    if (e.key === 'End') onNearEnd?.();
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div
  class="vl"
  role="listbox"
  tabindex="0"
  aria-label={label}
  aria-multiselectable={multi || undefined}
  aria-activedescendant={activeIndex >= 0 ? `${idPrefix}-row-${activeIndex}` : undefined}
  onscroll={onScroll}
  onkeydown={onKey}
  bind:clientHeight={viewport}
  bind:this={el}
>
  <div use:css={{ height: `${items.length * rowHeight}px` }} class="vl-inner">
    <div use:css={{ transform: `translateY(${start * rowHeight}px)` }}>
      {#each visible as item, i (key ? key(item) : start + i)}
        {@render row(item, start + i)}
      {/each}
    </div>
  </div>
</div>

<style>
  /* The gutter is reserved even without a scrollbar, so a header placed above with the same setting never drifts. */
  .vl { overflow-y: auto; scrollbar-gutter: stable; height: 100%; position: relative; outline-offset: -2px; }
  .vl-inner { position: relative; }
</style>
