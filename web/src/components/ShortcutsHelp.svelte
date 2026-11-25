<script lang="ts">
  // Every shortcut in one place: the registry's, the ones that only work inside one widget, and a report of any
  // that collide with each other or with something the browser keeps for itself.
  import { commands } from '../lib/commands.svelte';
  import { conflicts, format } from '../lib/shortcuts';
  import { shell } from '../lib/shell.svelte';

  let dlg = $state<HTMLDialogElement | undefined>();

  $effect(() => {
    if (!dlg) return;
    if (shell.help && !dlg.open) dlg.showModal();
    else if (!shell.help && dlg.open) dlg.close();
  });

  /** Keys that work only inside one widget. */
  const scoped: { area: string; rows: [string, string][] }[] = [
    { area: 'History list', rows: [['j / k, ↑ / ↓', 'Move the selection'], ['Shift+↑ / ↓', 'Extend the selection'], ['Ctrl+A', 'Select all'], ['Enter', 'Open the request'], ['Space', 'Pause or follow new requests'], ['/', 'Filter'], ['Delete', 'Delete (with undo)'], ['Shift+F10', 'Context menu']] },
    { area: 'Intercept', rows: [['F', 'Forward'], ['D', 'Drop'], ['Shift+F', 'Forward all'], ['Ctrl+Enter', 'Forward from the editor']] },
    { area: 'Tabs', rows: [['← / →, Home, End', 'Move between tabs'], ['Delete', 'Close the tab'], ['Alt+Shift+arrows', 'Move the tab to a neighbouring pane']] },
    { area: 'Dividers', rows: [['← → ↑ ↓', 'Resize (Shift for larger steps)'], ['Enter', 'Equal sizes']] },
    { area: 'Message', rows: [['Ctrl+F', 'Find in this message']] },
    { area: 'Anywhere', rows: [['?', 'This list']] },
  ];

  const groups = $derived.by(() => {
    const m = new Map<string, { title: string; keys: string }[]>();
    for (const c of commands.all) {
      if (!c.keys) continue;
      const g = m.get(c.group) ?? [];
      g.push({ title: c.title, keys: c.keys });
      m.set(c.group, g);
    }
    return [...m.entries()];
  });
  const report = $derived(conflicts(commands.bindings()));
  const problems = $derived(report.duplicates.length + report.reserved.length + report.invalid.length);
</script>

<dialog bind:this={dlg} aria-labelledby="help-title" onclose={() => (shell.help = false)}>
  {#if shell.help}
    <div class="head">
      <h2 id="help-title">Keyboard shortcuts</h2>
      <button class="ghost" aria-label="Close" onclick={() => (shell.help = false)}>×</button>
    </div>
    <p class="muted small">Ctrl+K opens the command palette, which can do everything below and more.</p>
    <div class="cols">
      {#each groups as [group, rows] (group)}
        <section>
          <h3>{group}</h3>
          <dl>{#each rows as r (r.title)}<dt>{r.title}</dt><dd><kbd>{format(r.keys)}</kbd></dd>{/each}</dl>
        </section>
      {/each}
      {#each scoped as s (s.area)}
        <section>
          <h3>{s.area}</h3>
          <dl>{#each s.rows as [k, what] (k)}<dt>{what}</dt><dd><kbd>{k}</kbd></dd>{/each}</dl>
        </section>
      {/each}
    </div>
    <h3>Conflicts</h3>
    {#if problems === 0}
      <p class="muted small">None: no two commands share a key, and none uses a key the browser keeps.</p>
    {:else}
      <ul class="small">
        {#each report.duplicates as d (d.keys)}<li>{d.keys} is used by {d.ids.join(', ')}.</li>{/each}
        {#each report.reserved as r (r.id)}<li>{r.id} uses {r.keys}, which the browser keeps ({r.why}); it may not reach this page.</li>{/each}
        {#each report.invalid as r (r.id)}<li>{r.id} has a key that cannot be read: {r.keys}.</li>{/each}
      </ul>
    {/if}
  {/if}
</dialog>

<style>
  dialog { width: min(46rem, 94vw); max-height: 86vh; overflow: auto; padding: .75rem 1rem 1rem; color: var(--text-1); background: var(--surface-1); border: 1px solid var(--border-strong); border-radius: var(--radius); }
  dialog::backdrop { background: rgb(0 0 0 / .45); }
  .head { display: flex; align-items: center; justify-content: space-between; }
  h2 { margin: 0; font-size: var(--fs-md); }
  h3 { margin: .8rem 0 .25rem; font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: .04em; color: var(--text-2); }
  .cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); gap: 0 1.5rem; }
  dl { display: grid; grid-template-columns: 1fr auto; gap: .15rem .6rem; margin: 0; }
  dt { color: var(--text-1); }
  dd { margin: 0; text-align: right; }
  ul { margin: 0; padding-left: 1.1rem; }
</style>
