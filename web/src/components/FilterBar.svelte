<script lang="ts">
  // One line for every History filter: `host:example.com method:POST status:4xx scope:in -ext:css login`. Enter
  // applies it; each recognised term shows as a chip that removes itself. Filters can be saved by name.
  import type { Snippet } from 'svelte';
  import { historyView as v } from '../lib/historyView.svelte';
  import { parseQuery, removeChip } from '../lib/query';
  import type { MenuItem } from '../lib/menu';
  import Menu from './Menu.svelte';

  let { children }: { children?: Snippet } = $props();

  const KEY = 'bosun.filters.v1';
  interface Saved { name: string; query: string }
  function read(): Saved[] {
    try {
      const x = JSON.parse(localStorage.getItem(KEY) ?? '[]');
      return Array.isArray(x) ? x.filter((s): s is Saved => typeof s?.name === 'string' && typeof s?.query === 'string').slice(0, 50) : [];
    } catch {
      return [];
    }
  }
  let saved = $state<Saved[]>(read());
  let saving = $state(false);
  let name = $state('');
  let box = $state<HTMLInputElement | undefined>();
  let nameBox = $state<HTMLInputElement | undefined>();

  const applied = $derived(parseQuery(v.query));
  const draft = $derived(parseQuery(v.draft));
  const dirty = $derived(v.draft.trim() !== v.query.trim());

  function persist() {
    try {
      localStorage.setItem(KEY, JSON.stringify(saved));
    } catch {
      // A saved filter is never worth an error.
    }
  }

  function apply(e?: Event) {
    e?.preventDefault();
    v.setQuery(v.draft.trim());
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      if (dirty) v.draft = v.query;
      else box?.blur();
    }
  }

  function save(e: Event) {
    e.preventDefault();
    const n = name.trim();
    if (!n) return;
    saved = [...saved.filter((s) => s.name !== n), { name: n, query: v.query }];
    persist();
    saving = false;
    name = '';
  }

  const items = $derived<MenuItem[]>([
    ...(saved.length
      ? [{ kind: 'heading', label: 'Saved filters' } as MenuItem, ...saved.map((s): MenuItem => ({ label: s.name, hint: s.query.length > 28 ? s.query.slice(0, 27) + '…' : s.query, run: () => v.setQuery(s.query) }))]
      : [{ kind: 'heading', label: 'No saved filters yet' } as MenuItem]),
    { kind: 'sep' },
    {
      label: 'Save the applied filter as…',
      run: async () => {
        saving = true;
        setTimeout(() => nameBox?.focus(), 0);
      },
    },
    ...saved.map((s): MenuItem => ({ label: `Delete “${s.name}”`, run: () => { saved = saved.filter((x) => x !== s); persist(); } })),
  ]);

  export function focus() {
    box?.focus();
    box?.select();
  }

  const short = (s: string) => (s.length > 26 ? s.slice(0, 25) + '…' : s);
</script>

<div class="bar">
  <form class="toolbar" onsubmit={apply}>
    <input
      class="grow"
      aria-label="Filter"
      aria-describedby={draft.errors.length ? 'filter-errors' : undefined}
      placeholder="host: method: status: scope: -ext: or text   ( / )"
      bind:value={v.draft}
      bind:this={box}
      onkeydown={onKey}
      spellcheck="false"
      autocomplete="off"
    />
    <button class={dirty ? 'primary' : ''}>Apply</button>
    <Menu label="Saved" title="Saved filters" items={items} />
    <span class="spacer"></span>
    {@render children?.()}
  </form>
  {#if saving}
    <form class="toolbar saver" onsubmit={save}>
      <input aria-label="Name for this filter" placeholder="Name for this filter" bind:value={name} bind:this={nameBox} maxlength="60" />
      <button class="primary">Save</button>
      <button type="button" onclick={() => (saving = false)}>Cancel</button>
    </form>
  {/if}
  {#if applied.chips.length || draft.errors.length}
    <div class="chips">
      {#each applied.chips as c (c.start + ':' + c.label)}
        <span class="chip {c.key}" title={c.label}>
          {short(c.label)}
          <button class="x" aria-label="Remove {short(c.label)}" onclick={() => v.setQuery(removeChip(v.query, c))}>×</button>
        </span>
      {/each}
      {#if draft.errors.length}
        <span id="filter-errors" class="errs small">{draft.errors.join(' · ')}</span>
      {/if}
    </div>
  {/if}
</div>

<style>
  .bar { border-bottom: 1px solid var(--border-subtle); }
  .bar .toolbar { border-bottom: 0; }
  .saver { padding-top: 0; }
  .chips { display: flex; flex-wrap: wrap; gap: .3rem; padding: 0 .5rem .3rem; align-items: center; }
  .chip { display: inline-flex; align-items: center; gap: .15rem; padding: 0 .2rem 0 .5rem; background: var(--surface-2); border: 1px solid var(--border-subtle); border-radius: 10px; font-family: var(--font-mono); font-size: var(--fs-xs); }
  .chip.host { color: var(--info); } .chip.method { color: var(--m-post); } .chip.status { color: var(--warn); }
  .chip.scope { color: var(--ok); } .chip.ext { color: var(--text-2); }
  .x { background: none; border: 0; padding: 0 .3rem; line-height: 1; color: var(--text-2); }
  .x:hover:not(:disabled) { color: var(--text-1); border: 0; }
  .errs { color: var(--bad); }
</style>
