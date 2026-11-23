<script lang="ts">
  import { onMount } from 'svelte';
  import { api, upload } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { fmtSize, fmtTime } from '../lib/bytes';
  import type { ProjectList } from '../lib/types';

  let list = $state<ProjectList | null>(null);
  let msg = $state('');
  let error = $state('');
  let newName = $state('');
  let importName = $state('');
  let importFile = $state<File | null>(null);
  let openAfter = $state(true);
  let renaming = $state<{ from: string; to: string } | null>(null);
  const admin = $derived(session.can('admin'));
  const enc = encodeURIComponent;

  async function load() {
    list = await api.get<ProjectList>('/projects');
  }
  onMount(() => {
    load().catch((e) => (error = String(e)));
    // The list changes when another user switches or when we do.
    return session.on((e) => {
      if (e.type === 'project_switched') load().catch(() => {});
    });
  });

  async function run(f: () => Promise<unknown>, ok = '') {
    error = '';
    msg = '';
    try {
      await f();
      msg = ok;
      await load();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  const create = () =>
    run(async () => {
      await api.post('/projects', { name: newName, open: openAfter });
      newName = '';
    }, 'Project created.');
  const open = (n: string) => run(() => api.post(`/projects/${enc(n)}/open`), `Opened ${n}.`);
  const close = () => run(() => api.post('/projects/close'), 'Closed. A temporary project is open; it is gone when you open another.');
  const backup = (n: string) =>
    run(async () => {
      const b = await api.post<{ path: string }>(`/projects/${enc(n)}/backup`);
      msg = `Backup saved on the engine's machine: ${b.path}`;
    });
  const remove = (n: string) => {
    if (confirm(`Delete project "${n}" and everything recorded in it? This cannot be undone.`)) return run(() => api.del(`/projects/${enc(n)}`), `Deleted ${n}.`);
  };
  const rename = () =>
    run(async () => {
      if (!renaming) return;
      await api.post(`/projects/${enc(renaming.from)}/rename`, { name: renaming.to });
      renaming = null;
    }, 'Renamed.');
  const doImport = () =>
    run(async () => {
      if (!importFile) throw new Error('Choose a project file first.');
      await upload(`/projects/import?name=${enc(importName)}&open=${openAfter}`, importFile);
      importFile = null;
      importName = '';
    }, 'Imported. The file was checked and its content copied into a new project.');
  function chosen(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0] ?? null;
    importFile = f;
    if (f && !importName) importName = f.name.replace(/\.(bosun|db|sqlite)$/i, '').replace(/[^A-Za-z0-9 ._-]/g, '_').slice(0, 64);
  }
</script>

<div class="toolbar">
  {#if list}
    <span>
      Open: <strong>{list.current.temporary ? 'temporary project' : list.current.name}</strong>
      {#if list.current.external}<span class="muted small">(opened by path; not managed here)</span>{/if}
      {#if list.current.temporary}<span class="muted small">kept in memory only</span>{/if}
    </span>
  {/if}
  <span class="spacer"></span>
  {#if admin && list && !list.current.temporary}<button onclick={close}>Close project</button>{/if}
</div>
{#if error}<p class="error">{error}</p>{/if}
{#if msg}<p class="ok">{msg}</p>{/if}
<div class="scroll">
  {#if list}
    <table class="grid">
      <thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead>
      <tbody>
        {#each list.projects as p (p.name)}
          <tr>
            <td>
              {#if renaming?.from === p.name}
                <input bind:value={renaming.to} aria-label="New name" />
                <button onclick={rename}>Save</button><button onclick={() => (renaming = null)}>Cancel</button>
              {:else}
                {p.name}{#if p.current}<span class="count">open</span>{/if}
              {/if}
            </td>
            <td>{fmtSize(p.size_bytes)}</td>
            <td>{p.modified_ms ? fmtTime(p.modified_ms) : ''}</td>
            <td>
              {#if admin}
                {#if !p.current}<button onclick={() => open(p.name)}>Open</button>{/if}
                <a class="btn" href={`/api/v1/projects/${enc(p.name)}/export`} download={`${p.name}.bosun`}>Export</a>
                <button onclick={() => backup(p.name)}>Back up</button>
                {#if !p.current}
                  <button onclick={() => (renaming = { from: p.name, to: p.name })}>Rename</button>
                  <button onclick={() => remove(p.name)}>Delete</button>
                {/if}
              {/if}
            </td>
          </tr>
        {:else}
          <tr><td colspan="4" class="muted">No saved projects yet. What you capture now is kept in memory only; create a project to keep it.</td></tr>
        {/each}
      </tbody>
    </table>
    {#if admin}
      <h3>New project</h3>
      <div class="row">
        <input bind:value={newName} placeholder="Name" aria-label="Project name" />
        <button class="primary" onclick={create} disabled={!newName}>Create</button>
        <label><input type="checkbox" bind:checked={openAfter} /> open it</label>
      </div>
      <h3>Import a project file</h3>
      <p class="muted small">
        The file is never opened as it is: it is checked, and only its recorded content is copied into a new project. Projects can hold
        credentials captured from targets; import only files you trust the origin of.
      </p>
      <div class="row">
        <input type="file" accept=".bosun,.db,.sqlite" onchange={chosen} aria-label="Project file" />
        <input bind:value={importName} placeholder="Name" aria-label="Name for the imported project" />
        <button class="primary" onclick={doImport} disabled={!importFile || !importName}>Import</button>
      </div>
    {/if}
  {/if}
</div>

<style>
  .row { display: flex; gap: .5rem; align-items: center; padding: .25rem .5rem; }
  h3 { margin: 1rem .5rem .25rem; }
  .count { margin-left: .5rem; background: var(--accent); color: #000; border-radius: 8px; padding: 0 .4rem; font-size: .75rem; }
  a.btn { display: inline-block; padding: .25rem .6rem; border: 1px solid var(--line); border-radius: 4px; color: inherit; text-decoration: none; background: var(--bg2); }
</style>
