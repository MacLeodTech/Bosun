<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from './lib/api';
  import { session } from './lib/session.svelte';
  import Auth from './pages/Auth.svelte';
  import History from './pages/History.svelte';
  import Intercept from './pages/Intercept.svelte';
  import Rules from './pages/Rules.svelte';
  import Target from './pages/Target.svelte';
  import Settings from './pages/Settings.svelte';
  import Projects from './pages/Projects.svelte';
  import Repeater from './pages/Repeater.svelte';

  type Page = 'intercept' | 'history' | 'repeater' | 'rules' | 'target' | 'projects' | 'settings';
  const pages: [Page, string][] = [
    ['intercept', 'Intercept'], ['history', 'HTTP history'], ['repeater', 'Repeater'], ['rules', 'Match & replace'], ['target', 'Target'], ['projects', 'Projects'], ['settings', 'Settings'],
  ];
  const fromHash = (): Page => {
    const h = location.hash.slice(1) as Page;
    return pages.some(([p]) => p === h) ? h : 'history';
  };
  let page = $state<Page>(fromHash());
  let held = $state(0);
  /** Bumped when another project is opened, so every page starts over with the new project's data. */
  let generation = $state(0);
  let project = $state<string>('');
  let lost = $state<{ n: number; error: string } | null>(null);

  function go(p: Page) {
    page = p;
    history.replaceState(null, '', `#${p}`);
  }

  async function loadProject() {
    try {
      const l = await api.get<{ current: { name?: string | null; temporary: boolean } }>('/projects');
      project = l.current.temporary ? 'temporary project' : (l.current.name ?? '');
    } catch {
      // Not signed in yet.
    }
  }

  $effect(() => {
    if (session.me) loadProject();
  });

  onMount(() => {
    session.init();
    const onHash = () => { page = fromHash(); };
    window.addEventListener('hashchange', onHash);
    const off = session.on((e) => {
      if (e.type === 'reload') {
        api.get<{ requests: boolean; responses: boolean }>('/intercept').then((s: { requests: boolean; responses: boolean }) => (held = (s.requests ? 1 : 0) + (s.responses ? 1 : 0)));
      } else if (e.type === 'project_switched') {
        generation++;
        project = e.temporary ? 'temporary project' : (e.name ?? '');
        held = 0;
      } else if (e.type === 'intercept_state') held = (e.requests ? 1 : 0) + (e.responses ? 1 : 0);
      else if (e.type === 'recorder_failed') lost = { n: (lost?.n ?? 0) + e.lost, error: e.error };
    });
    return () => {
      off();
      window.removeEventListener('hashchange', onHash);
    };
  });
</script>

{#if !session.ready}
  <div class="loading">Loading…</div>
{:else if !session.me}
  <Auth />
{:else}
  <div class="app">
    <header>
      <span class="brand"><img src="/apple-touch-icon.png" alt="" width="24" height="24" />Bosun</span>
      <nav>
        {#each pages as [p, label] (p)}
          <button class:active={page === p} onclick={() => go(p)}>
            {label}{#if p === 'intercept' && held}<span class="count">{held}</span>{/if}
          </button>
        {/each}
      </nav>
      <span class="spacer"></span>
      {#if project}<span class="small muted" title="The open project">{project}</span>{/if}
      <span class="dot" class:on={session.connected} title={session.connected ? 'Live' : 'Reconnecting…'}></span>
      <span class="small muted">{session.me.user.username} ({session.me.user.role})</span>
      <button onclick={() => session.logout()}>Sign out</button>
    </header>
    {#if lost}
      <div class="lost" role="alert">
        History could not be saved: {lost.n} item{lost.n === 1 ? '' : 's'} lost ({lost.error}).
        <button onclick={() => (lost = null)}>Dismiss</button>
      </div>
    {/if}
    <main>
      {#key generation}
        {#if page === 'intercept'}<Intercept />
        {:else if page === 'history'}<History />
        {:else if page === 'repeater'}<Repeater />
        {:else if page === 'rules'}<Rules />
        {:else if page === 'target'}<Target />
        {:else if page === 'projects'}<Projects />
        {:else}<Settings />{/if}
      {/key}
    </main>
  </div>
{/if}

<style>
  .app { display: flex; flex-direction: column; height: 100vh; }
  header { display: flex; align-items: center; gap: .75rem; padding: .3rem .75rem; background: var(--bg2); border-bottom: 1px solid var(--line); }
  .brand { display: inline-flex; align-items: center; gap: .45rem; font-weight: 700; color: var(--accent); letter-spacing: .02em; }
  .brand img { border-radius: 5px; }
  nav { display: flex; gap: .15rem; }
  nav button { border: 0; background: none; padding: .35rem .7rem; }
  nav button.active { background: var(--sel); }
  main { flex: 1; display: flex; flex-direction: column; min-height: 0; }
  .count { margin-left: .35rem; background: var(--accent); color: #000; border-radius: 8px; padding: 0 .4rem; font-size: .75rem; }
  .dot { width: .55rem; height: .55rem; border-radius: 50%; background: var(--bad); }
  .dot.on { background: var(--ok); }
  .lost { padding: .35rem .75rem; background: var(--bad); color: #000; display: flex; gap: .75rem; align-items: center; }
  .loading { padding: 2rem; color: var(--muted); }
</style>
