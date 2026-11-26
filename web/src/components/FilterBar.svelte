<script lang="ts">
  // One line for every History filter: `host:example.com (login or signup) -ext:css tag:x`. The server owns the
  // grammar (docs/query-language.md): this bar asks it what the line means, draws a chip for each recognised term
  // and shows its mistakes. Enter applies a line that has none. Filters can be saved by name for the whole project.
  import { onMount, tick, type Snippet } from 'svelte';
  import { api, qs } from '../lib/api';
  import { historyView as v } from '../lib/historyView.svelte';
  import { parseQuery } from '../lib/query';
  import { applyCompletion, byteToIndex, complete, remember } from '../lib/querybar';
  import { session } from '../lib/session.svelte';
  import { toasts } from '../lib/toasts.svelte';
  import type { MenuItem } from '../lib/menu';
  import Menu from './Menu.svelte';

  let { children }: { children?: Snippet } = $props();

  interface Saved { name: string; query: string }
  interface Check { q: string; terms: { key: string; label: string; start: number; end: number }[]; errors: { message: string; start: number; end: number }[] }

  const PAST_KEY = 'bosun.pastQueries.v1';
  function readPast(): string[] {
    try {
      const x = JSON.parse(localStorage.getItem(PAST_KEY) ?? '[]');
      return Array.isArray(x) ? x.filter((s): s is string => typeof s === 'string').slice(0, 25) : [];
    } catch {
      return [];
    }
  }

  let saved = $state<Saved[]>([]);
  let past = $state<string[]>(readPast());
  let saving = $state(false);
  let name = $state('');
  let box = $state<HTMLInputElement | undefined>();
  let nameBox = $state<HTMLInputElement | undefined>();
  const canSave = $derived(session.can('tester'));

  // What the server says about the applied line and about the draft. Until an answer for the current text arrives,
  // the local parser's chips stand in, so the bar never flashes empty (and still works if the server is slow).
  let appliedCheck = $state<Check | undefined>();
  let draftCheck = $state<Check | undefined>();
  let refused = $state<Check | undefined>();
  const dirty = $derived(v.draft.trim() !== v.query.trim());

  async function check(q: string): Promise<Check | undefined> {
    try {
      const r = await api.get<{ terms: Check['terms']; errors: Check['errors'] }>(`/flows/query${qs({ q })}`);
      return { q, ...r };
    } catch {
      return undefined;
    }
  }

  $effect(() => {
    const q = v.query;
    check(q).then((c) => {
      if (c && q === v.query) appliedCheck = c;
    });
  });

  let timer: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    const q = v.draft;
    clearTimeout(timer);
    if (q.trim() === v.query.trim()) {
      draftCheck = undefined;
      return;
    }
    timer = setTimeout(() => check(q).then((c) => { if (c && q === v.draft) draftCheck = c; }), 200);
    return () => clearTimeout(timer);
  });

  const errors = $derived(refused && refused.q === v.draft ? refused.errors : draftCheck && draftCheck.q === v.draft ? draftCheck.errors : []);
  /** Messages with the offending text, so a long line says which part is wrong. */
  const errorText = $derived(errors.map((e) => {
    const bit = v.draft.slice(byteToIndex(v.draft, e.start), byteToIndex(v.draft, e.end));
    return bit && bit.length < 40 ? `${e.message} (“${bit}”)` : e.message;
  }));

  const chips = $derived.by(() => {
    if (appliedCheck && appliedCheck.q === v.query) {
      return appliedCheck.terms.map((t) => ({ key: t.key, label: t.label, start: byteToIndex(v.query, t.start), end: byteToIndex(v.query, t.end) }));
    }
    return parseQuery(v.query).chips;
  });

  onMount(() => {
    load();
    // A different project has different saved filters.
    return session.on((e) => { if (e.type === 'reload') load(); });
  });

  async function load() {
    try {
      saved = await api.get<Saved[]>('/saved-filters');
    } catch {
      saved = [];
    }
  }

  /** Apply `q` if the server finds nothing wrong with it; otherwise say what is wrong and change nothing. */
  async function commit(q: string): Promise<boolean> {
    const c = await check(q.trim());
    if (c && c.errors.length) {
      refused = { ...c, q };
      return false;
    }
    refused = undefined;
    v.setQuery(q.trim());
    past = remember(past, q);
    try {
      localStorage.setItem(PAST_KEY, JSON.stringify(past));
    } catch {
      // A remembered query is never worth an error.
    }
    return true;
  }

  function apply(e?: Event) {
    e?.preventDefault();
    commit(v.draft);
  }

  function removeChip(c: { start: number; end: number }) {
    const q = (v.query.slice(0, c.start) + ' ' + v.query.slice(c.end)).replace(/\s+/g, ' ').trim();
    commit(q);
  }

  // ---- completion
  let caret = $state(0);
  let focused = $state(false);
  let dismissed = $state(false);
  let active = $state(-1);
  const comp = $derived(complete(v.draft, caret));
  const open = $derived(focused && !dismissed && comp.items.length > 0);

  function sync() {
    caret = box?.selectionStart ?? v.draft.length;
  }
  async function accept(i: number) {
    const s = comp.items[i];
    if (!s) return;
    const r = applyCompletion(v.draft, comp, s);
    v.draft = r.line;
    active = -1;
    // Keys end in a colon, so the value list follows at once; a finished value closes the list.
    // Wait for the input to hold the new text before placing the caret in it.
    await tick();
    box?.focus();
    box?.setSelectionRange(r.caret, r.caret);
    caret = r.caret;
  }

  function onKey(e: KeyboardEvent) {
    if (open) {
      if (e.key === 'ArrowDown') { e.preventDefault(); active = (active + 1) % comp.items.length; return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); active = (active - 1 + comp.items.length) % comp.items.length; return; }
      if ((e.key === 'Tab' && !e.shiftKey) || (e.key === 'Enter' && active >= 0)) { e.preventDefault(); accept(active < 0 ? 0 : active); return; }
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); dismissed = true; return; }
    }
    if (e.key === 'Escape') {
      if (dirty) v.draft = v.query;
      else box?.blur();
    }
  }

  function onInput() {
    dismissed = false;
    active = -1;
    refused = undefined;
    sync();
  }

  async function save(e: Event) {
    e.preventDefault();
    const n = name.trim();
    if (!n) return;
    const next = [...saved.filter((s) => s.name !== n), { name: n, query: v.query }];
    try {
      saved = await api.put<Saved[]>('/saved-filters', next);
      saving = false;
      name = '';
    } catch (err) {
      toasts.push({ text: `Could not save the filter: ${err instanceof Error ? err.message : err}` });
    }
  }

  async function remove(s: Saved) {
    try {
      saved = await api.put<Saved[]>('/saved-filters', saved.filter((x) => x.name !== s.name));
    } catch (err) {
      toasts.push({ text: `Could not delete the filter: ${err instanceof Error ? err.message : err}` });
    }
  }

  const trim = (s: string, n = 28) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
  const items = $derived<MenuItem[]>([
    ...(saved.length
      ? [{ kind: 'heading', label: 'Saved filters' } as MenuItem, ...saved.map((s): MenuItem => ({ label: s.name, hint: trim(s.query), run: () => v.setQuery(s.query) }))]
      : [{ kind: 'heading', label: 'No saved filters yet' } as MenuItem]),
    { kind: 'sep' },
    ...(canSave ? [{ label: 'Save the applied filter as…', run: () => { saving = true; setTimeout(() => nameBox?.focus(), 0); } } as MenuItem] : []),
    ...(canSave ? saved.map((s): MenuItem => ({ label: `Delete “${s.name}”`, run: () => remove(s) })) : []),
    ...(past.length
      ? [{ kind: 'sep' } as MenuItem, { kind: 'heading', label: 'Recent' } as MenuItem, ...past.slice(0, 10).map((q): MenuItem => ({ label: trim(q, 40), run: () => v.setQuery(q) }))]
      : []),
  ]);

  export function focus() {
    box?.focus();
    box?.select();
  }

  const short = (s: string) => (s.length > 26 ? s.slice(0, 25) + '…' : s);
</script>

<div class="bar">
  <form class="toolbar" onsubmit={apply}>
    <span class="field grow">
      <input
        class="grow"
        role="combobox"
        aria-label="Filter"
        aria-expanded={open}
        aria-controls={open ? 'filter-suggest' : undefined}
        aria-autocomplete="list"
        aria-activedescendant={open && active >= 0 ? `filter-opt-${active}` : undefined}
        aria-describedby={errorText.length ? 'filter-errors' : undefined}
        aria-invalid={errorText.length > 0}
        placeholder="host: method: status: tag: header: or text, with or / not / ( )   ( / )"
        bind:value={v.draft}
        bind:this={box}
        onkeydown={onKey}
        oninput={onInput}
        onkeyup={sync}
        onclick={sync}
        onfocus={() => { focused = true; sync(); }}
        onblur={() => (focused = false)}
        spellcheck="false"
        autocomplete="off"
      />
      {#if open}
        <ul class="suggest" id="filter-suggest" role="listbox" aria-label="Suggestions">
          {#each comp.items as s, i (s.insert)}
            <!-- mousedown keeps the focus in the input; a click would blur it first -->
            <li id="filter-opt-{i}" role="option" aria-selected={i === active} class:on={i === active} onmousedown={(e) => { e.preventDefault(); accept(i); }}>
              <span>{s.label}</span><span class="h">{s.hint}</span>
            </li>
          {/each}
        </ul>
      {/if}
    </span>
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
  {#if chips.length || errorText.length}
    <div class="chips">
      {#each chips as c (c.start + ':' + c.label)}
        <span class="chip {c.key}" title={c.label}>
          {short(c.label)}
          <button class="x" aria-label="Remove {short(c.label)}" onclick={() => removeChip(c)}>×</button>
        </span>
      {/each}
      {#if errorText.length}
        <span id="filter-errors" class="errs small" role="alert">{errorText.join(' · ')}</span>
      {/if}
    </div>
  {/if}
</div>

<style>
  .bar { border-bottom: 1px solid var(--border-subtle); }
  .bar .toolbar { border-bottom: 0; }
  .saver { padding-top: 0; }
  .field { position: relative; display: flex; }
  .suggest { position: absolute; left: 0; top: 100%; z-index: 60; margin: 2px 0 0; padding: .15rem; list-style: none; min-width: 16rem; background: var(--surface-1, var(--surface-2)); border: 1px solid var(--border-subtle); border-radius: 4px; box-shadow: 0 4px 12px rgb(0 0 0 / .25); }
  .suggest li { display: flex; justify-content: space-between; gap: 1rem; padding: .15rem .5rem; font-family: var(--font-mono); font-size: var(--fs-xs); cursor: pointer; border-radius: 3px; }
  .suggest li.on, .suggest li:hover { background: var(--surface-2); outline: 1px solid var(--border-subtle); }
  .suggest .h { color: var(--text-2); }
  .chips { display: flex; flex-wrap: wrap; gap: .3rem; padding: 0 .5rem .3rem; align-items: center; }
  .chip { display: inline-flex; align-items: center; gap: .15rem; padding: 0 .2rem 0 .5rem; background: var(--surface-2); border: 1px solid var(--border-subtle); border-radius: 10px; font-family: var(--font-mono); font-size: var(--fs-xs); }
  .chip.host { color: var(--info); } .chip.method { color: var(--m-post); } .chip.status { color: var(--warn); }
  .chip.scope { color: var(--ok); } .chip.ext { color: var(--text-2); }
  .x { background: none; border: 0; padding: 0 .3rem; line-height: 1; color: var(--text-2); }
  .x:hover:not(:disabled) { color: var(--text-1); border: 0; }
  .errs { color: var(--bad); }
</style>
