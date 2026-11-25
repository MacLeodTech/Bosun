<script lang="ts">
  // Always-visible facts: the open project, the intercept state, the open request and the live connection.
  import { session } from '../lib/session.svelte';
  import { shell } from '../lib/shell.svelte';
  import { historyView } from '../lib/historyView.svelte';
  import { workspace } from '../lib/workspace.svelte';
</script>

<footer>
  <span title="The open project">{shell.project || 'no project'}</span>
  <span class="sep" aria-hidden="true">·</span>
  <span class:warn={shell.held > 0}>Intercept {shell.held ? `on (${shell.held})` : 'off'}</span>
  {#if historyView.openId !== null}
    <span class="sep" aria-hidden="true">·</span>
    <span class="tnum">Request #{historyView.openId}</span>
  {/if}
  <span class="spacer"></span>
  {#if workspace.notice}<span class="warn" role="status">{workspace.notice}</span>{/if}
  {#if workspace.applied}<span class="muted" title="The layout applied last">Layout: {workspace.applied}</span>{/if}
  <span class="dot" class:on={session.connected} aria-hidden="true"></span>
  <span>{session.connected ? 'Live' : 'Reconnecting…'}</span>
</footer>

<style>
  footer { display: flex; align-items: center; gap: .5rem; flex: none; height: 22px; padding: 0 .6rem; background: var(--surface-1); border-top: 1px solid var(--border-subtle); font-size: var(--fs-xs); color: var(--text-2); }
  .sep { opacity: .5; }
  .warn { color: var(--warn); }
  .dot { width: .5rem; height: .5rem; border-radius: 50%; background: var(--bad); }
  .dot.on { background: var(--ok); }
</style>
