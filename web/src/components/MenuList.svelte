<script lang="ts">
  // A list of menu items with the keyboard behaviour of a menu: arrows, Home/End, Enter, Escape. Used by the
  // button-triggered Menu and (later) by context menus.
  import { onMount } from 'svelte';
  import type { MenuItem } from '../lib/menu';

  let { items, label, onclose }: { items: MenuItem[]; label: string; onclose: () => void } = $props();
  let list = $state<HTMLElement | undefined>();

  const buttons = () => [...(list?.querySelectorAll<HTMLButtonElement>('button[role^="menuitem"]:not(:disabled)') ?? [])];

  onMount(() => buttons()[0]?.focus());

  function onKey(e: KeyboardEvent) {
    const bs = buttons();
    const at = bs.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === 'ArrowDown') bs[(at + 1) % bs.length]?.focus();
    else if (e.key === 'ArrowUp') bs[(at - 1 + bs.length) % bs.length]?.focus();
    else if (e.key === 'Home') bs[0]?.focus();
    else if (e.key === 'End') bs[bs.length - 1]?.focus();
    else if (e.key === 'Escape' || e.key === 'Tab') {
      if (e.key === 'Escape') e.preventDefault();
      onclose();
      return;
    } else return;
    e.preventDefault();
  }

  function pick(it: Extract<MenuItem, { label: string; run: () => void }>) {
    onclose();
    it.run();
  }
</script>

<div class="menu" role="menu" aria-label={label} tabindex="-1" bind:this={list} onkeydown={onKey}>
  {#each items as it, i (i)}
    {#if it.kind === 'sep'}
      <div class="sep" role="separator"></div>
    {:else if it.kind === 'heading'}
      <div class="heading" role="presentation">{it.label}</div>
    {:else}
      <button
        role={it.checked !== undefined ? 'menuitemradio' : 'menuitem'}
        aria-checked={it.checked}
        disabled={it.disabled}
        tabindex="-1"
        onclick={() => pick(it)}
      >
        <span class="tick" aria-hidden="true">{it.checked ? '✓' : ''}</span>
        <span class="text">{it.label}</span>
        {#if it.hint}<span class="hint">{it.hint}</span>{/if}
      </button>
    {/if}
  {/each}
</div>

<style>
  .menu { min-width: 14rem; padding: .25rem 0; background: var(--surface-1); border: 1px solid var(--border-strong); border-radius: var(--radius); box-shadow: 0 6px 18px rgb(0 0 0 / .28); }
  button { display: flex; align-items: center; gap: .4rem; width: 100%; text-align: left; background: none; border: 0; border-radius: 0; padding: .25rem .6rem .25rem .3rem; }
  button:hover:not(:disabled), button:focus-visible { background: var(--surface-sel); border: 0; outline: none; }
  .tick { width: 1rem; text-align: center; color: var(--accent); }
  .text { flex: 1; }
  .hint { color: var(--text-2); font-size: var(--fs-xs); }
  .sep { height: 1px; margin: .25rem 0; background: var(--border-subtle); }
  .heading { padding: .2rem .6rem; font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: .04em; color: var(--text-2); }
</style>
