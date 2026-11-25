<script lang="ts">
  // A button that opens a menu under it.
  import type { MenuItem } from '../lib/menu';
  import MenuList from './MenuList.svelte';

  let { label, items, title = '' }: { label: string; items: MenuItem[]; title?: string } = $props();
  let open = $state(false);
  let host = $state<HTMLElement | undefined>();
  let trigger = $state<HTMLButtonElement | undefined>();

  function close(refocus = true) {
    open = false;
    if (refocus) trigger?.focus();
  }
  function onWindowPointer(e: PointerEvent) {
    if (open && host && !host.contains(e.target as globalThis.Node)) close(false);
  }
</script>

<svelte:window onpointerdown={onWindowPointer} />

<span class="host" bind:this={host}>
  <button type="button" class="ghost" bind:this={trigger} aria-haspopup="menu" aria-expanded={open} {title} onclick={() => (open = !open)}>{label} ▾</button>
  {#if open}
    <div class="pop"><MenuList {items} {label} onclose={close} /></div>
  {/if}
</span>

<style>
  .host { position: relative; display: inline-block; }
  .pop { position: absolute; right: 0; top: 100%; margin-top: 2px; z-index: 50; }
</style>
