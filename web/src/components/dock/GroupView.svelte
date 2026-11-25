<script lang="ts">
  // One tab stack: the tab strip and the panels. Every panel stays mounted while its tab is in the background
  // (hidden, not removed), so a half-typed request or a scroll position is still there when the tab comes back.
  import { tick } from 'svelte';
  import type { Group } from '../../lib/layout';
  import { workspace } from '../../lib/workspace.svelte';
  import { dockDrag } from '../../lib/dockdrag.svelte';
  import { contextMenu } from '../../lib/contextmenu.svelte';
  import { windows } from '../../lib/windows.svelte';
  import type { MenuItem } from '../../lib/menu';
  import { panelById } from '../../lib/panels';
  import PanelHost from './PanelHost.svelte';

  let { group }: { group: Group } = $props();
  let strip = $state<HTMLElement | undefined>();
  let body = $state<HTMLElement | undefined>();

  $effect(() => {
    if (strip && body) return dockDrag.registerGroup(group.id, strip, body);
  });

  const focused = $derived(workspace.focused === group.id);
  const maximized = $derived(workspace.maximized === group.id);
  const title = (panel: string) => panelById(panel)?.title ?? panel;

  async function refocus(tabId: string) {
    await tick();
    document.getElementById(`tab-${tabId}`)?.focus();
  }

  function onTabKey(e: KeyboardEvent, id: string, i: number) {
    const n = group.tabs.length;
    if (e.altKey && e.shiftKey && e.key.startsWith('Arrow')) {
      e.preventDefault();
      workspace.moveDirection(id, e.key === 'ArrowLeft' ? 'left' : e.key === 'ArrowRight' ? 'right' : e.key === 'ArrowUp' ? 'up' : 'down');
      refocus(id);
      return;
    }
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    let to = -1;
    if (e.key === 'ArrowRight') to = (i + 1) % n;
    else if (e.key === 'ArrowLeft') to = (i - 1 + n) % n;
    else if (e.key === 'Home') to = 0;
    else if (e.key === 'End') to = n - 1;
    else if (e.key === 'Delete') {
      e.preventDefault();
      workspace.close(id);
      return;
    }
    if (to < 0) return;
    e.preventDefault();
    const next = group.tabs[to]!.id;
    workspace.select(next);
    refocus(next);
  }

  function tabMenu(id: string): MenuItem[] {
    return [
      { label: 'Close', run: () => workspace.close(id) },
      { kind: 'sep' },
      { label: 'Move left', run: () => workspace.moveDirection(id, 'left'), hint: 'Alt+Shift+←' },
      { label: 'Move right', run: () => workspace.moveDirection(id, 'right'), hint: 'Alt+Shift+→' },
      { label: 'Move up', run: () => workspace.moveDirection(id, 'up'), hint: 'Alt+Shift+↑' },
      { label: 'Move down', run: () => workspace.moveDirection(id, 'down'), hint: 'Alt+Shift+↓' },
      { kind: 'sep' },
      { label: maximized ? 'Restore pane size' : 'Maximise pane', run: () => workspace.toggleMaximize(group.id) },
      ...(windows.isPopout ? [] : [{ kind: 'sep' } as MenuItem, { label: 'Move to a new window', run: () => windows.popOut(id) }]),
    ];
  }

  function onTabContext(e: MouseEvent, id: string) {
    e.preventDefault();
    workspace.select(id);
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    // From the keyboard the event has no pointer position: open under the tab.
    const fromKey = e.clientX === 0 && e.clientY === 0;
    contextMenu.show(tabMenu(id), fromKey ? r.left : e.clientX, fromKey ? r.bottom : e.clientY, 'Tab actions');
  }

  function onClick(id: string) {
    if (dockDrag.justDragged) return;
    workspace.select(id);
  }
</script>

<div class="group" class:focused class:max={maximized} data-group={group.id}>
  <div class="strip" bind:this={strip} role="tablist" aria-label="Panels" tabindex="-1" ondblclick={() => workspace.toggleMaximize(group.id)}>
    {#each group.tabs as t, i (t.id)}
      {@const def = panelById(t.panel)}
      {@const n = def?.badge?.() ?? 0}
      {@const active = group.active === t.id}
      <div class="tab" class:active role="presentation">
        <button
          class="label"
          role="tab"
          id="tab-{t.id}"
          aria-selected={active}
          aria-controls="pane-{t.id}"
          aria-keyshortcuts="Alt+Shift+ArrowLeft Alt+Shift+ArrowRight Alt+Shift+ArrowUp Alt+Shift+ArrowDown Delete"
          tabindex={active ? 0 : -1}
          onclick={() => onClick(t.id)}
          onkeydown={(e) => onTabKey(e, t.id, i)}
          onpointerdown={(e) => dockDrag.begin(e, t.id, title(t.panel))}
          oncontextmenu={(e) => onTabContext(e, t.id)}
          onauxclick={(e) => { if (e.button === 1) { e.preventDefault(); workspace.close(t.id); } }}
        >{title(t.panel)}{#if n}<span class="count">{n}</span>{/if}</button>
        <button class="x" tabindex="-1" aria-label="Close {title(t.panel)}" onclick={() => workspace.close(t.id)}>×</button>
      </div>
    {/each}
    <span class="fill"></span>
    <button class="x max" tabindex="-1" aria-label={maximized ? 'Restore panel size' : 'Maximise this pane'} title={maximized ? 'Restore (double-click the tab bar)' : 'Maximise (double-click the tab bar)'} onclick={() => workspace.toggleMaximize(group.id)}>{maximized ? '❐' : '□'}</button>
  </div>
  <!-- The group is the drop target; focus follows the pointer so the next opened panel lands where the user is working. -->
  <div class="body" bind:this={body} role="presentation" onpointerdowncapture={() => workspace.focus(group.id)}>
    {#each group.tabs as t (t.id)}
      <div class="pane" role="tabpanel" id="pane-{t.id}" aria-labelledby="tab-{t.id}" hidden={group.active !== t.id}>
        <PanelHost panel={t.panel} visible={group.active === t.id} />
      </div>
    {/each}
  </div>
</div>

<style>
  .group { display: flex; flex-direction: column; flex: 1; min-width: 0; min-height: 0; background: var(--surface-0); }
  .group.max { position: absolute; inset: 0; z-index: 20; }
  .strip { display: flex; align-items: stretch; height: 26px; flex: none; background: var(--surface-1); border-bottom: 1px solid var(--border-subtle); overflow: hidden; }
  .tab { display: flex; align-items: stretch; border-right: 1px solid var(--border-subtle); color: var(--text-2); position: relative; }
  .tab.active { background: var(--surface-0); color: var(--text-1); box-shadow: inset 0 -1px 0 var(--surface-0); }
  .group.focused .tab.active::before { content: ''; position: absolute; left: 0; right: 0; top: 0; height: 2px; background: var(--accent); }
  .tab button { background: none; border: 0; border-radius: 0; color: inherit; padding: 0 .6rem; white-space: nowrap; }
  .tab button.label { cursor: default; }
  .tab:hover:not(.active) { background: var(--surface-2); }
  .x { background: none; border: 0; border-radius: 0; color: var(--text-2); padding: 0 .4rem; line-height: 1; }
  .tab .x { padding: 0 .35rem 0 0; opacity: 0; }
  .tab:hover .x, .tab.active .x, .tab:focus-within .x { opacity: 1; }
  .x:hover { color: var(--text-1); background: none; border: 0; }
  .fill { flex: 1; }
  .count { margin-left: .4rem; background: var(--accent); color: var(--on-accent); border-radius: 8px; padding: 0 .4rem; font-size: var(--fs-xs); }
  .body { position: relative; display: flex; flex-direction: column; flex: 1; min-height: 0; min-width: 0; }
  .pane { display: flex; flex-direction: column; flex: 1; min-height: 0; min-width: 0; overflow: auto; }
  .pane[hidden] { display: none; }
</style>
