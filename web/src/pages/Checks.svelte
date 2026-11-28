<script lang="ts">
  // Checks: the project's own passive checks, written in the YAML check language. They run in the passive scanner
  // beside the built-in ones and show up in the Issues panel. A check is data (matchers over recorded traffic): it
  // cannot run code or send anything. The server validates the text and says what is wrong; it is only ever shown
  // as text here.
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { toasts } from '../lib/toasts.svelte';
  import type { components } from '../lib/api-types';

  type Check = components['schemas']['CheckView'];
  type Validation = components['schemas']['CheckValidation'];

  const TEMPLATE = `version: 1
id: my-check
info:
  name: What this check reports
  severity: low        # info, low, medium or high
  description: Why it matters.
  remediation: How to fix it.
passive:
  matchers:
    - type: word
      part: body       # body, header or all
      words: ["text to look for"]
`;

  let checks = $state<Check[]>([]);
  let loaded = $state(false);
  /** null: the editor is closed; 0: a new check; otherwise the row being edited. */
  let editing = $state<number | null>(null);
  let yaml = $state('');
  let problem = $state('');
  let okNote = $state('');
  let busy = $state(false);
  const canEdit = $derived(session.can('tester'));

  async function load() {
    checks = (await api.get<{ checks: Check[] }>('/checks')).checks;
    loaded = true;
  }
  onMount(load);

  const fail = (e: unknown) => (e instanceof Error ? e.message : String(e));

  function create() {
    editing = 0;
    yaml = TEMPLATE;
    problem = '';
    okNote = '';
  }
  function edit(c: Check) {
    editing = c.id;
    yaml = c.yaml;
    problem = '';
    okNote = '';
  }
  function close() {
    editing = null;
    problem = '';
    okNote = '';
  }

  async function validate() {
    problem = '';
    okNote = '';
    try {
      const v = await api.post<Validation>('/checks/validate', { yaml });
      if (v.valid) okNote = `Valid: ${v.name} (${v.check_id}).`;
      else problem = v.error ?? 'Not valid.';
    } catch (e) {
      problem = fail(e);
    }
  }

  async function save() {
    problem = '';
    okNote = '';
    busy = true;
    try {
      if (editing === 0) await api.post('/checks', { yaml });
      else await api.put(`/checks/${editing}`, { yaml });
      toasts.push({ text: 'Saved. It applies to new traffic now; rescan to apply it to recorded traffic.' });
      close();
      await load();
    } catch (e) {
      problem = fail(e);
    } finally {
      busy = false;
    }
  }

  async function toggle(c: Check) {
    try {
      await api.patch(`/checks/${c.id}`, { enabled: !c.enabled });
      await load();
    } catch (e) {
      toasts.push({ text: `Could not change the check: ${fail(e)}` });
    }
  }

  async function remove(c: Check) {
    if (!confirm(`Delete the check ${c.check_id}? Issues it already found stay.`)) return;
    try {
      await api.del(`/checks/${c.id}`);
      if (editing === c.id) close();
      await load();
    } catch (e) {
      toasts.push({ text: `Could not delete the check: ${fail(e)}` });
    }
  }

  async function rescan() {
    try {
      await api.post('/issues/rescan', {});
      toasts.push({ text: 'Every request is queued for the scanner again.' });
    } catch (e) {
      toasts.push({ text: `Could not rescan: ${fail(e)}` });
    }
  }
</script>

<div class="toolbar">
  <span class="muted small">Your own passive checks. Findings appear in the Issues panel.</span>
  <span class="spacer"></span>
  {#if canEdit}
    <button onclick={create}>Add check</button>
    <button onclick={rescan} title="Scan the whole history again with the current checks">Rescan history</button>
  {/if}
</div>
<div class="body">
  <div class="scroll">
    <table class="grid">
      <thead><tr><th>On</th><th>Rule id</th><th>Name</th><th>Severity</th><th></th></tr></thead>
      <tbody>
        {#each checks as c (c.id)}
          <tr>
            <td><input type="checkbox" checked={c.enabled} disabled={!canEdit} onchange={() => toggle(c)} aria-label="{c.check_id}: enabled" /></td>
            <td class="mono">{c.check_id}</td>
            <td>{c.name}</td>
            <td>{c.severity || 'does not load'}</td>
            <td>
              {#if canEdit}
                <button onclick={() => edit(c)} aria-label="Edit {c.check_id}">Edit</button>
                <button onclick={() => remove(c)} aria-label="Delete {c.check_id}">Delete</button>
              {/if}
            </td>
          </tr>
        {:else}
          <tr><td colspan="5" class="muted">{loaded ? 'No custom checks.' : 'Loading...'}</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if editing !== null}
    <div class="editor">
      <label for="check-yaml" class="small muted">{editing === 0 ? 'New check' : 'Edit check'} (YAML)</label>
      <textarea id="check-yaml" class="mono" spellcheck="false" bind:value={yaml}></textarea>
      {#if problem}<p class="error" role="alert">{problem}</p>{/if}
      {#if okNote}<p class="ok">{okNote}</p>{/if}
      <div class="toolbar">
        <button onclick={validate}>Validate</button>
        <button class="primary" onclick={save} disabled={busy}>Save</button>
        <button onclick={close}>Cancel</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .body { display: flex; flex-direction: column; flex: 1; min-height: 0; }
  .scroll { overflow: auto; flex: 1; min-height: 6rem; }
  .editor { display: flex; flex-direction: column; gap: 0.4rem; padding: 0.5rem; border-top: 1px solid var(--border, #444); flex: 1; min-height: 0; }
  textarea { flex: 1; min-height: 10rem; width: 100%; resize: none; }
</style>
