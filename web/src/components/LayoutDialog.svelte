<script lang="ts">
  // Save, rename, delete, export and import layouts. A native <dialog>, so focus is trapped and Escape closes it.
  import { builtinPresets, workspace } from '../lib/workspace.svelte';
  import { shell } from '../lib/shell.svelte';

  let dlg = $state<HTMLDialogElement | undefined>();
  let name = $state('');
  let renaming = $state<string | null>(null);
  let renameTo = $state('');
  let importText = $state('');
  let message = $state('');
  let failed = $state(false);

  $effect(() => {
    if (!dlg) return;
    if (shell.layoutDialog && !dlg.open) {
      message = '';
      dlg.showModal();
    } else if (!shell.layoutDialog && dlg.open) dlg.close();
  });

  const names = $derived(Object.keys(workspace.presets).sort((a, b) => a.localeCompare(b)));
  const exported = $derived(workspace.exportJson());

  function say(ok: boolean, text: string) {
    failed = !ok;
    message = text;
  }

  function save(e: Event) {
    e.preventDefault();
    if (workspace.saveAs(name)) {
      say(true, `Saved “${name.trim()}”.`);
      name = '';
    } else say(false, 'Give the layout a name (60 characters at most).');
  }

  function rename(e: Event) {
    e.preventDefault();
    if (renaming && workspace.rename(renaming, renameTo)) renaming = null;
    else say(false, 'That name is empty, too long or already used.');
  }

  function doImport() {
    const r = workspace.importJson(importText);
    if ('error' in r) say(false, r.error);
    else {
      say(true, `Imported ${r.added} layout${r.added === 1 ? '' : 's'}.`);
      importText = '';
    }
  }

  async function onFile(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    if (!f) return;
    if (f.size > 1_000_000) return say(false, 'That file is too large to be a layout file.');
    importText = await f.text();
    doImport();
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(exported);
      say(true, 'Copied.');
    } catch {
      say(false, 'Copying was blocked; select the text and copy it by hand.');
    }
  }

  function download() {
    const url = URL.createObjectURL(new Blob([exported], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'bosun-layouts.json';
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

<dialog bind:this={dlg} aria-labelledby="layout-title" onclose={() => (shell.layoutDialog = false)}>
  {#if shell.layoutDialog}
    <div class="head">
      <h2 id="layout-title">Layouts</h2>
      <button class="ghost" aria-label="Close" onclick={() => (shell.layoutDialog = false)}>×</button>
    </div>

    <h3>Built in</h3>
    <ul>
      {#each builtinPresets as p (p.id)}
        <li>
          <span><b>{p.label}</b> <span class="muted small">{p.hint}</span></span>
          <button onclick={() => { workspace.apply(p.id); shell.layoutDialog = false; }}>Apply</button>
        </li>
      {/each}
    </ul>

    <h3>Yours</h3>
    <ul>
      {#each names as n (n)}
        <li>
          {#if renaming === n}
            <form class="inline" onsubmit={rename}>
              <input aria-label="New name" bind:value={renameTo} maxlength="60" />
              <button class="primary">Rename</button>
              <button type="button" onclick={() => (renaming = null)}>Cancel</button>
            </form>
          {:else}
            <span>{n}</span>
            <span class="actions">
              <button onclick={() => { workspace.applyUser(n); shell.layoutDialog = false; }}>Apply</button>
              <button onclick={() => { renaming = n; renameTo = n; }}>Rename</button>
              <button class="danger" onclick={() => workspace.remove(n)}>Delete</button>
            </span>
          {/if}
        </li>
      {:else}
        <li class="muted">Nothing saved yet.</li>
      {/each}
    </ul>
    <form class="inline" onsubmit={save}>
      <input aria-label="Name for the current layout" placeholder="Name for the current layout" bind:value={name} maxlength="60" />
      <button class="primary">Save current layout</button>
    </form>

    <h3>Share</h3>
    <div class="inline">
      <button onclick={copy}>Copy my layouts</button>
      <button onclick={download}>Download as file</button>
    </div>
    <textarea aria-label="Paste layouts to import" placeholder="Paste exported layouts here" rows="3" bind:value={importText}></textarea>
    <div class="inline">
      <button onclick={doImport} disabled={!importText.trim()}>Import pasted text</button>
      <label class="file">Import from file…<input type="file" accept=".json,application/json" onchange={onFile} /></label>
    </div>

    <p class="msg" class:bad={failed} role="status">{message}</p>
    <div class="foot">
      <button onclick={() => { workspace.reset(); shell.layoutDialog = false; }}>Reset layout</button>
    </div>
  {/if}
</dialog>

<style>
  dialog { width: min(34rem, 92vw); max-height: 86vh; overflow: auto; padding: .75rem 1rem 1rem; color: var(--text-1); background: var(--surface-1); border: 1px solid var(--border-strong); border-radius: var(--radius); }
  dialog::backdrop { background: rgb(0 0 0 / .45); }
  .head { display: flex; align-items: center; justify-content: space-between; }
  h2 { margin: 0; font-size: var(--fs-md); }
  h3 { margin: .9rem 0 .3rem; font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: .04em; color: var(--text-2); }
  ul { list-style: none; margin: 0; padding: 0; }
  li { display: flex; align-items: center; justify-content: space-between; gap: .5rem; padding: .2rem 0; border-bottom: 1px solid var(--border-subtle); }
  .actions { display: flex; gap: .3rem; }
  .inline { display: flex; gap: .4rem; align-items: center; margin-top: .4rem; }
  .inline input { flex: 1; }
  textarea { width: 100%; margin-top: .4rem; background: var(--surface-0); border: 1px solid var(--border-subtle); border-radius: var(--radius); font-family: var(--font-mono); font-size: var(--fs-data); resize: vertical; }
  .file { position: relative; cursor: pointer; background: var(--surface-2); border: 1px solid transparent; border-radius: var(--radius); padding: .2rem .6rem; }
  .file:hover, .file:focus-within { border-color: var(--border-strong); }
  .file input { position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; }
  .msg { min-height: 1.2em; margin: .6rem 0 0; color: var(--ok); }
  .msg.bad { color: var(--bad); }
  .foot { display: flex; justify-content: flex-end; margin-top: .4rem; }
</style>
