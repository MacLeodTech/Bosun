<script lang="ts">
  import { toasts } from '../lib/toasts.svelte';
</script>

<div class="toasts" role="status" aria-live="polite">
  {#each toasts.list as t (t.id)}
    <div class="toast">
      <span>{t.text}</span>
      {#if t.action}<button class="link" onclick={() => toasts.act(t.id)}>{t.action.label}</button>{/if}
      <button class="ghost" aria-label="Dismiss" onclick={() => toasts.dismiss(t.id)}>×</button>
    </div>
  {/each}
</div>

<style>
  .toasts { position: fixed; left: .75rem; bottom: 30px; z-index: 55; display: flex; flex-direction: column; gap: .3rem; max-width: 28rem; pointer-events: none; }
  .toast { display: flex; align-items: center; gap: .6rem; padding: .3rem .4rem .3rem .7rem; background: var(--surface-2); border: 1px solid var(--border-strong); border-radius: var(--radius); box-shadow: 0 4px 14px rgb(0 0 0 / .3); pointer-events: auto; }
  .toast span { flex: 1; }
  .link { background: none; border: 0; color: var(--accent); font-weight: 600; padding: 0 .3rem; }
  .link:hover:not(:disabled) { text-decoration: underline; border: 0; }
</style>
