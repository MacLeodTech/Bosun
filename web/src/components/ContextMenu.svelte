<script lang="ts">
  // Draws the open context menu (see lib/contextmenu.svelte.ts) at the pointer, kept inside the window.
  import { tick } from 'svelte';
  import { contextMenu } from '../lib/contextmenu.svelte';
  import { css } from '../lib/style';
  import MenuList from './MenuList.svelte';

  let host = $state<HTMLElement | undefined>();
  let pos = $state({ x: 0, y: 0 });

  $effect(() => {
    const m = contextMenu.open;
    if (!m) return;
    pos = { x: m.x, y: m.y };
    tick().then(() => {
      if (!host) return;
      const r = host.getBoundingClientRect();
      pos = { x: Math.max(4, Math.min(m.x, innerWidth - r.width - 4)), y: Math.max(4, m.y + r.height > innerHeight - 4 ? m.y - r.height : m.y) };
    });
  });

  function outside(e: PointerEvent) {
    if (contextMenu.open && host && !host.contains(e.target as globalThis.Node)) contextMenu.close(false);
  }
</script>

<svelte:window onpointerdown={outside} onresize={() => contextMenu.close(false)} onblur={() => contextMenu.close(false)} />

{#if contextMenu.open}
  {@const m = contextMenu.open}
  <div class="cm" bind:this={host} use:css={{ '--x': `${pos.x}px`, '--y': `${pos.y}px` }}>
    <MenuList items={m.items} label={m.label} onclose={() => contextMenu.close()} />
  </div>
{/if}

<style>
  .cm { position: fixed; left: var(--x); top: var(--y); z-index: 60; }
</style>
