<script lang="ts">
  // Ctrl+K. One box, four modes by first character: commands and panels (default, or ">"), a request by number ("#"),
  // a host or text to look for in History ("/"), and panels only ("@"). A native <dialog>, so focus stays inside it.
  import { tick } from 'svelte';
  import { api } from '../lib/api';
  import { commands, currentCtx } from '../lib/commands.svelte';
  import { fuzzy } from '../lib/fuzzy';
  import { searchHistory } from '../lib/flowactions';
  import { historyView as v } from '../lib/historyView.svelte';
  import { panels } from '../lib/panels';
  import { format } from '../lib/shortcuts';
  import { shell } from '../lib/shell.svelte';
  import { withTerm } from '../lib/query';
  import { workspace } from '../lib/workspace.svelte';
  import type { SiteMapEntry } from '../lib/types';

  interface Item { key: string; label: string; group: string; keys?: string; idx: number[]; run: () => void }

  let dlg = $state<HTMLDialogElement | undefined>();
  let input = $state<HTMLInputElement | undefined>();
  let text = $state('');
  let active = $state(0);
  let hosts = $state<string[]>([]);

  $effect(() => {
    if (!dlg) return;
    if (shell.palette && !dlg.open) {
      text = shell.paletteStart;
      active = 0;
      dlg.showModal();
      tick().then(() => input?.focus());
      if (!hosts.length) {
        api.get<SiteMapEntry[]>('/sitemap').then((es) => (hosts = [...new Set(es.map((e) => e.host))].sort())).catch(() => {});
      }
    } else if (!shell.palette && dlg.open) dlg.close();
  });

  const mode = $derived(text[0] === '#' || text[0] === '/' || text[0] === '@' || text[0] === '>' ? text[0] : '');
  const q = $derived(mode ? text.slice(1).trim() : text.trim());

  function openFlow(id: number) {
    v.select([id], id);
    v.openId = id;
    workspace.reveal('flow', 'history');
  }

  function rank(list: Omit<Item, 'idx'>[], query: string): Item[] {
    if (!query) return list.map((i) => ({ ...i, idx: [] }));
    const out: (Item & { s: number })[] = [];
    for (const i of list) {
      const m = fuzzy(query, i.label);
      if (m) out.push({ ...i, idx: m.idx, s: m.score });
    }
    return out.sort((a, b) => b.s - a.s);
  }

  const items = $derived.by((): Item[] => {
    const ctx = currentCtx();
    const panelItems = panels.map((p) => ({ key: `p:${p.id}`, label: `Open ${p.title}`, group: 'Panels', run: () => workspace.open(p.id) }));
    const userLayouts = Object.keys(workspace.presets).sort().map((n) => ({ key: `u:${n}`, label: `Layout: ${n}`, group: 'Layout', run: () => workspace.applyUser(n) }));
    if (mode === '#') {
      return /^\d+$/.test(q) ? [{ key: 'flow', label: `Open request #${Number(q)}`, group: 'Requests', idx: [], run: () => openFlow(Number(q)) }] : [];
    }
    if (mode === '/') {
      if (!q) return [];
      const hostMatches = rank(hosts.map((h) => ({ key: `h:${h}`, label: h, group: 'Hosts', run: () => v.setQuery(withTerm(v.query, 'host', h)) })), q).slice(0, 8);
      return [
        ...hostMatches.map((h) => ({ ...h, label: `Filter History by host ${h.label}`, idx: [] })),
        { key: 'search', label: `Search History for “${q}”`, group: 'History', idx: [], run: () => searchHistory(q) },
      ];
    }
    if (mode === '@') return rank(panelItems, q.replace(/^open\s+/i, '')).slice(0, 50);
    const cmds = commands.enabled(ctx).map((c) => ({ key: `c:${c.id}`, label: c.title, group: c.group, keys: c.keys, run: () => void commands.run(c.id, ctx) }));
    // Panel-opening commands exist in both the registry and the panel list; show each once.
    const seen = new Set(cmds.map((c) => c.label));
    const all = [...cmds, ...panelItems.filter((p) => !seen.has(p.label)), ...userLayouts];
    if (!q) {
      const order = new Map(commands.recent.map((id, i) => [`c:${id}`, i]));
      return all
        .map((i) => ({ ...i, idx: [] as number[] }))
        .sort((a, b) => (order.get(a.key) ?? 99) - (order.get(b.key) ?? 99) || a.group.localeCompare(b.group))
        .slice(0, 50);
    }
    return rank(all, q).slice(0, 50);
  });

  $effect(() => {
    items;
    active = 0;
  });

  function run(i: Item | undefined) {
    if (!i) return;
    shell.palette = false;
    // Let the dialog close and give focus back first, so a command that moves focus (or opens a dialog) wins.
    setTimeout(() => i.run(), 0);
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') active = items.length ? (active + 1) % items.length : 0;
    else if (e.key === 'ArrowUp') active = items.length ? (active - 1 + items.length) % items.length : 0;
    else if (e.key === 'Enter') run(items[active]);
    else return;
    e.preventDefault();
    tick().then(() => document.getElementById(`pal-opt-${active}`)?.scrollIntoView({ block: 'nearest' }));
  }

  const hint = $derived(
    mode === '#' ? 'Type a request number, e.g. #1234' : mode === '/' && !q ? 'Type a host or some text to find in History' : mode === '@' ? 'Panels' : 'Commands, panels and layouts',
  );
</script>

<!-- A click on the dim area outside the box closes it. -->
<dialog bind:this={dlg} aria-label="Command palette" onclose={() => (shell.palette = false)} onclick={(e) => { if (e.target === dlg) shell.palette = false; }}>
  {#if shell.palette}
    <div class="box">
      <input
        bind:this={input}
        bind:value={text}
        role="combobox"
        aria-label="Command palette"
        aria-expanded="true"
        aria-controls="pal-list"
        aria-activedescendant={items.length ? `pal-opt-${active}` : undefined}
        placeholder="Type a command…   # request   / host or text   @ panel"
        autocomplete="off"
        spellcheck="false"
        onkeydown={onKey}
      />
      <div class="hint small muted">{hint}</div>
      <div class="list" id="pal-list" role="listbox" aria-label="Results">
        {#each items as it, i (it.key)}
          <!-- Keyboard use is on the input (aria-activedescendant); the click is for the mouse. -->
          <div id="pal-opt-{i}" class="opt" class:active={i === active} role="option" aria-selected={i === active} tabindex="-1" onclick={() => run(it)} onkeydown={null} onpointermove={() => (active = i)}>
            <span class="grp small muted">{it.group}</span>
            <span class="lbl">{#each [...it.label] as ch, k (k)}<span class:m={it.idx.includes(k)}>{ch}</span>{/each}</span>
            {#if it.keys}<kbd>{format(it.keys)}</kbd>{/if}
          </div>
        {:else}
          <div class="none muted">Nothing matches.</div>
        {/each}
      </div>
    </div>
  {/if}
</dialog>

<style>
  dialog { position: fixed; top: 12vh; margin: 0 auto; width: min(520px, 94vw); padding: 0; color: var(--text-1); background: var(--surface-1); border: 1px solid var(--border-strong); border-radius: var(--radius); box-shadow: 0 12px 32px rgb(0 0 0 / .4); }
  dialog::backdrop { background: rgb(0 0 0 / .35); }
  .box { display: flex; flex-direction: column; max-height: 62vh; }
  input { margin: .5rem; padding: .35rem .5rem; font-size: var(--fs-md); }
  .hint { padding: 0 .7rem .3rem; }
  .list { overflow-y: auto; border-top: 1px solid var(--border-subtle); }
  .opt { display: flex; align-items: center; gap: .6rem; padding: .25rem .7rem; cursor: default; }
  .opt.active { background: var(--surface-sel); }
  .grp { width: 4.5rem; flex: none; }
  .lbl { flex: 1; min-width: 0; white-space: pre; overflow: hidden; text-overflow: ellipsis; }
  .lbl .m { color: var(--accent); font-weight: 600; }
  .none { padding: .6rem .7rem; }
</style>
