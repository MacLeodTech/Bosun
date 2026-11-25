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
  import { commands, currentCtx } from './lib/commands.svelte';
  import { registerBuiltins } from './lib/builtin';
  import { buildHash, parseHash } from './lib/deeplink';
  import type { MenuItem } from './lib/menu';
  import Auth from './pages/Auth.svelte';
  import Dock from './components/dock/Dock.svelte';
  import Menu from './components/Menu.svelte';
  import StatusBar from './components/StatusBar.svelte';
  import LayoutDialog from './components/LayoutDialog.svelte';
  import CommandPalette from './components/CommandPalette.svelte';
  import ShortcutsHelp from './components/ShortcutsHelp.svelte';
  import ContextMenu from './components/ContextMenu.svelte';
  import Toasts from './components/Toasts.svelte';

  /** Show a panel and record it in the address, so a link or a reload opens the same one. */
  function go(p: string) {
    workspace.open(p);
    history.replaceState(null, '', buildHash(p, historyView.openId));
  }

  /** Open what an address names: a panel, and a request in it. */
  function followHash() {
    const link = parseHash(location.hash, isPanelId);
    if (!link.panel) return;
    if (link.flow !== null && link.flow !== historyView.openId) {
      historyView.select([link.flow], link.flow);
      historyView.openId = link.flow;
      workspace.reveal('flow', 'history');
    }
    workspace.open(link.panel);
  }

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

  // The address follows the open request: #history?flow=1234.
  $effect(() => {
    const id = historyView.openId;
    if (!session.me) return;
    const cur = parseHash(location.hash, isPanelId).panel ?? 'history';
    const next = buildHash(cur, id);
    if (location.hash !== next) history.replaceState(null, '', next);
  });

  /** Plain keys belong to whatever has focus; commands with a modifier work from anywhere that is not a text field. */
  function onKey(e: KeyboardEvent) {
    if (e.defaultPrevented || !session.me) return;
    const t = e.target as HTMLElement | null;
    const typing = !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
    // An open dialog (palette, help, layouts) owns the keyboard.
    if (document.querySelector('dialog[open]')) return;
    if (e.key === '?' && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      shell.help = true;
      return;
    }
    const ctx = currentCtx();
    const c = commands.forEvent(e, ctx, typing);
    if (!c) return;
    e.preventDefault();
    void commands.run(c.id, ctx);
  }

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
    const unregister = registerBuiltins();
    // A link such as #repeater, or #history?flow=12, opens that panel and request.
    followHash();
    window.addEventListener('hashchange', followHash);
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
      unregister();
      window.removeEventListener('hashchange', followHash);
    };
  });
</script>

<svelte:window onkeydown={onKey} />

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
      <button class="ghost" title="Command palette (Ctrl+K)" onclick={() => { shell.paletteStart = ''; shell.palette = true; }}>Commands <kbd>Ctrl+K</kbd></button>
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
  <CommandPalette />
  <ShortcutsHelp />
  <ContextMenu />
  <Toasts />
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
