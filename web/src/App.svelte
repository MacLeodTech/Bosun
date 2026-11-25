<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from './lib/api';
  import { session } from './lib/session.svelte';
  import { theme } from './lib/theme.svelte';
  import { historyView } from './lib/historyView.svelte';
  import { shell } from './lib/shell.svelte';
  import { workspace, builtinPresets } from './lib/workspace.svelte';
  import { panels } from './lib/panels';
  import { isPanelId } from './lib/panelids';
  import type { MenuItem } from './lib/menu';
  import Auth from './pages/Auth.svelte';
  import Dock from './components/dock/Dock.svelte';
  import Menu from './components/Menu.svelte';
  import StatusBar from './components/StatusBar.svelte';
  import LayoutDialog from './components/LayoutDialog.svelte';

  /** Show a panel and record it in the address, so a link or a reload opens the same one. */
  function go(p: string) {
    workspace.open(p);
    history.replaceState(null, '', `#${p}`);
  }

  const fromHash = () => {
    const h = location.hash.slice(1);
    return isPanelId(h) ? h : null;
  };

  async function loadProject() {
    try {
      const l = await api.get<{ current: { name?: string | null; temporary: boolean } }>('/projects');
      shell.project = l.current.temporary ? 'temporary project' : (l.current.name ?? '');
    } catch {
      // Not signed in yet.
    }
  }

  $effect(() => {
    if (session.me) loadProject();
  });

  const layoutItems = $derived<MenuItem[]>([
    { kind: 'heading', label: 'Layouts' },
    ...builtinPresets.map((p): MenuItem => ({ label: p.label, hint: p.hint.split(',')[0], checked: workspace.applied === p.id, run: () => workspace.apply(p.id) })),
    ...(Object.keys(workspace.presets).length
      ? [{ kind: 'sep' } as MenuItem, ...Object.keys(workspace.presets).sort().map((n): MenuItem => ({ label: n, checked: workspace.applied === n, run: () => workspace.applyUser(n) }))]
      : []),
    { kind: 'sep' },
    { label: 'Save or manage layouts…', run: () => (shell.layoutDialog = true) },
    { label: 'Reset layout', run: () => workspace.reset() },
  ]);

  onMount(() => {
    session.init();
    // A link such as #repeater opens that panel.
    const initial = fromHash();
    if (initial) workspace.open(initial);
    const onHash = () => {
      const p = fromHash();
      if (p) workspace.open(p);
    };
    window.addEventListener('hashchange', onHash);
    const off = session.on((e) => {
      if (e.type === 'reload') {
        api.get<{ requests: boolean; responses: boolean }>('/intercept').then((s: { requests: boolean; responses: boolean }) => (shell.held = (s.requests ? 1 : 0) + (s.responses ? 1 : 0)));
      } else if (e.type === 'project_switched') {
        shell.generation++;
        historyView.reset();
        shell.project = e.temporary ? 'temporary project' : (e.name ?? '');
        shell.held = 0;
      } else if (e.type === 'intercept_state') shell.held = (e.requests ? 1 : 0) + (e.responses ? 1 : 0);
      else if (e.type === 'recorder_failed') shell.lost = { n: (shell.lost?.n ?? 0) + e.lost, error: e.error };
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
      <nav aria-label="Open a panel">
        {#each panels as p (p.id)}
          {@const n = p.badge?.() ?? 0}
          <button class:active={workspace.isActive(p.id)} onclick={() => go(p.id)}>
            {p.title}{#if n}<span class="count">{n}</span>{/if}
          </button>
        {/each}
      </nav>
      <span class="spacer"></span>
      <Menu label="Layout" title="Arrange the panels" items={layoutItems} />
      <button class="ghost" title="Colour theme: system, dark or light" onclick={() => theme.cycle()}>Theme: {theme.pref}</button>
      <span class="small muted">{session.me.user.username} ({session.me.user.role})</span>
      <button onclick={() => session.logout()}>Sign out</button>
    </header>
    {#if shell.lost}
      <div class="lost" role="alert">
        History could not be saved: {shell.lost.n} item{shell.lost.n === 1 ? '' : 's'} lost ({shell.lost.error}).
        <button onclick={() => (shell.lost = null)}>Dismiss</button>
      </div>
    {/if}
    <main>
      <Dock />
    </main>
    <StatusBar />
  </div>
  <LayoutDialog />
{/if}

<style>
  .app { display: flex; flex-direction: column; height: 100vh; }
  header { display: flex; align-items: center; gap: .6rem; padding: .2rem .6rem; background: var(--surface-1); border-bottom: 1px solid var(--border-subtle); }
  .brand { display: inline-flex; align-items: center; gap: .45rem; font-weight: 700; color: var(--accent); letter-spacing: .02em; }
  .brand img { border-radius: 5px; }
  nav { display: flex; gap: .15rem; flex-wrap: wrap; }
  nav button { background: none; padding: .3rem .65rem; }
  nav button:hover:not(:disabled) { background: var(--surface-2); border-color: transparent; }
  nav button.active { background: var(--surface-sel); box-shadow: inset 0 -2px 0 var(--accent); }
  main { flex: 1; display: flex; min-height: 0; }
  .count { margin-left: .35rem; background: var(--accent); color: var(--on-accent); border-radius: 8px; padding: 0 .4rem; font-size: .75rem; }
  .lost { padding: .3rem .75rem; background: var(--bad); color: var(--on-accent); display: flex; gap: .75rem; align-items: center; }
  .loading { padding: 2rem; color: var(--muted); }
</style>
