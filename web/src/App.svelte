<script lang="ts">
  import { onMount } from 'svelte';
  import { session } from './lib/session.svelte';
  import Auth from './pages/Auth.svelte';
  import History from './pages/History.svelte';
  import Intercept from './pages/Intercept.svelte';
  import Rules from './pages/Rules.svelte';
  import Target from './pages/Target.svelte';
  import Settings from './pages/Settings.svelte';

  type Page = 'intercept' | 'history' | 'rules' | 'target' | 'settings';
  const pages: [Page, string][] = [
    ['intercept', 'Intercept'], ['history', 'HTTP history'], ['rules', 'Match & replace'], ['target', 'Target'], ['settings', 'Settings'],
  ];
  const fromHash = (): Page => {
    const h = location.hash.slice(1) as Page;
    return pages.some(([p]) => p === h) ? h : 'history';
  };
  let page = $state<Page>(fromHash());
  let held = $state(0);

  function go(p: Page) {
    page = p;
    history.replaceState(null, '', `#${p}`);
  }

  onMount(() => {
    session.init();
    return session.on((e) => {
      if (e.type === 'intercept_state') held = e.requests + e.responses;
    });
  });
</script>

{#if !session.ready}
  <div class="loading">Loading…</div>
{:else if !session.me}
  <Auth />
{:else}
  <div class="app">
    <header>
      <span class="brand">Bosun</span>
      <nav>
        {#each pages as [p, label] (p)}
          <button class:active={page === p} onclick={() => go(p)}>
            {label}{#if p === 'intercept' && held}<span class="count">{held}</span>{/if}
          </button>
        {/each}
      </nav>
      <span class="spacer"></span>
      <span class="dot" class:on={session.connected} title={session.connected ? 'Live' : 'Reconnecting…'}></span>
      <span class="small muted">{session.me.user.username} ({session.me.user.role})</span>
      <button onclick={() => session.logout()}>Sign out</button>
    </header>
    <main>
      {#if page === 'intercept'}<Intercept />
      {:else if page === 'history'}<History />
      {:else if page === 'rules'}<Rules />
      {:else if page === 'target'}<Target />
      {:else}<Settings />{/if}
    </main>
  </div>
{/if}

<style>
  .app { display: flex; flex-direction: column; height: 100vh; }
  header { display: flex; align-items: center; gap: .75rem; padding: .3rem .75rem; background: var(--bg2); border-bottom: 1px solid var(--line); }
  .brand { font-weight: 700; color: var(--accent); letter-spacing: .02em; }
  nav { display: flex; gap: .15rem; }
  nav button { border: 0; background: none; padding: .35rem .7rem; }
  nav button.active { background: var(--sel); }
  main { flex: 1; display: flex; flex-direction: column; min-height: 0; }
  .count { margin-left: .35rem; background: var(--accent); color: #000; border-radius: 8px; padding: 0 .4rem; font-size: .75rem; }
  .dot { width: .55rem; height: .55rem; border-radius: 50%; background: var(--bad); }
  .dot.on { background: var(--ok); }
  .loading { padding: 2rem; color: var(--muted); }
</style>
