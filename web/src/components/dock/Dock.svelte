<script lang="ts">
  import { css } from '../../lib/style';
  import { workspace } from '../../lib/workspace.svelte';
  import { session } from '../../lib/session.svelte';
  import { dockDrag } from '../../lib/dockdrag.svelte';
  import { panels } from '../../lib/panels';
  import { sendToRepeater } from '../../lib/flowactions';
  import { toasts } from '../../lib/toasts.svelte';
  import DockNode from './DockNode.svelte';

  let el = $state<HTMLElement | undefined>();
  $effect(() => {
    dockDrag.registerDock(el ?? null);
    return () => dockDrag.registerDock(null);
  });

  /** Dragging requests over the dock: the Repeater opens where they are dropped, and gets one tab per request. */
  const FLOW_DND = 'application/x-bosun-flow';
  const carries = (e: DragEvent) => !!e.dataTransfer && [...e.dataTransfer.types].includes(FLOW_DND);

  function onDragOver(e: DragEvent) {
    if (!carries(e)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
    dockDrag.flowOver = true;
    dockDrag.target = dockDrag.locate(e.clientX, e.clientY, '');
  }

  function onDragLeave(e: DragEvent) {
    if (!dockDrag.flowOver || (e.relatedTarget && el?.contains(e.relatedTarget as globalThis.Node))) return;
    dockDrag.flowOver = false;
    dockDrag.target = null;
  }

  function onDrop(e: DragEvent) {
    if (!carries(e)) return;
    e.preventDefault();
    const t = dockDrag.target ?? dockDrag.locate(e.clientX, e.clientY, '');
    dockDrag.flowOver = false;
    dockDrag.target = null;
    let ids: number[] = [];
    try {
      const data = JSON.parse(e.dataTransfer?.getData(FLOW_DND) ?? '{}');
      ids = Array.isArray(data.ids) ? data.ids.filter((n: unknown): n is number => Number.isInteger(n) && (n as number) > 0).slice(0, 200) : [];
    } catch {
      // Not ours after all.
    }
    if (!ids.length) return;
    if (!session.can('tester')) {
      toasts.push({ text: 'Sending requests to the Repeater needs the tester role.' });
      return;
    }
    // Open (or move) the Repeater where it was dropped, then hand it the requests by id.
    workspace.openAt('repeater', t?.groupId ?? null, t?.zone === 'center' || !t ? 'center' : t.zone, t?.index);
    void sendToRepeater(ids);
  }

  // The highlight is positioned relative to the dock, so it is computed from viewport rectangles here.
  const hl = $derived.by(() => {
    const t = dockDrag.target;
    const d = el?.getBoundingClientRect();
    if (!t || !d) return null;
    return { '--l': `${t.rect.left - d.left}px`, '--t': `${t.rect.top - d.top}px`, '--w': `${t.rect.width}px`, '--h': `${t.rect.height}px` };
  });
</script>

<!-- Requests are dropped on the dock itself; the drop point picks the pane, so there is nothing to focus. -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="dock" bind:this={el} ondragover={onDragOver} ondragleave={onDragLeave} ondrop={onDrop}>
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
  {#if (dockDrag.active || dockDrag.flowOver) && hl}
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
