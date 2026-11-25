<script lang="ts">
  import { css } from '../../lib/style';
  import { workspace } from '../../lib/workspace.svelte';
  import { dockDrag } from '../../lib/dockdrag.svelte';
  import { panels } from '../../lib/panels';
  import DockNode from './DockNode.svelte';

  let el = $state<HTMLElement | undefined>();
  $effect(() => {
    dockDrag.registerDock(el ?? null);
    return () => dockDrag.registerDock(null);
  });

  // The highlight is positioned relative to the dock, so it is computed from viewport rectangles here.
  const hl = $derived.by(() => {
    const t = dockDrag.target;
    const d = el?.getBoundingClientRect();
    if (!t || !d) return null;
    return { '--l': `${t.rect.left - d.left}px`, '--t': `${t.rect.top - d.top}px`, '--w': `${t.rect.width}px`, '--h': `${t.rect.height}px` };
  });
</script>

<div class="dock" bind:this={el}>
  {#if workspace.root}
    <DockNode node={workspace.root} />
  {:else}
    <div class="empty">
      <p>No panels are open.</p>
      <p class="actions">
        {#each panels.slice(0, 4) as p (p.id)}
          <button onclick={() => workspace.open(p.id)}>{p.title}</button>
        {/each}
        <button class="primary" onclick={() => workspace.reset()}>Reset layout</button>
      </p>
    </div>
  {/if}
  {#if dockDrag.active && hl}
    <div class="drop" use:css={hl}></div>
  {/if}
</div>
{#if dockDrag.active}
  <div class="ghost" use:css={{ '--x': `${dockDrag.x}px`, '--y': `${dockDrag.y}px` }}>{dockDrag.label}</div>
{/if}

<style>
  .dock { position: relative; display: flex; flex: 1; min-height: 0; min-width: 0; }
  .empty { margin: auto; text-align: center; color: var(--text-2); }
  .empty .actions { display: flex; gap: .4rem; justify-content: center; }
  .drop { position: absolute; left: var(--l); top: var(--t); width: var(--w); height: var(--h); z-index: 30; pointer-events: none; background: color-mix(in srgb, var(--accent) 18%, transparent); border: 1px solid var(--accent); }
  .ghost { position: fixed; left: calc(var(--x) + 12px); top: calc(var(--y) + 8px); z-index: 40; pointer-events: none; padding: .1rem .5rem; background: var(--surface-2); border: 1px solid var(--border-strong); border-radius: var(--radius); font-size: var(--fs-sm); }
</style>
