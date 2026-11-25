<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import type { MatchRule, RuleTarget } from '../lib/types';

  const targets: [RuleTarget, string][] = [
    ['request_header', 'Request header'], ['request_body', 'Request body'], ['request_first_line', 'Request first line'],
    ['response_header', 'Response header'], ['response_body', 'Response body'], ['response_first_line', 'Response first line'],
  ];
  let rules = $state<MatchRule[]>([]);
  let msg = $state('');
  let error = $state('');
  const canEdit = $derived(session.can('tester'));

  onMount(async () => {
    rules = await api.get<MatchRule[]>('/rules');
  });

  function add() {
    rules = [...rules, { enabled: true, target: 'request_header', match: '', replace: '', regex: false, comment: '' }];
  }

  async function save() {
    error = '';
    msg = '';
    try {
      rules = await api.put<MatchRule[]>('/rules', rules);
      msg = 'Saved. The rules apply to new traffic.';
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }
</script>

<div class="toolbar">
  <span class="muted small">Header rules: empty match adds the replacement as a new header; empty replacement removes matching header lines.</span>
  <span class="spacer"></span>
  {#if canEdit}<button onclick={add}>Add rule</button><button class="primary" onclick={save}>Save</button>{/if}
</div>
{#if error}<p class="error">{error}</p>{/if}
{#if msg}<p class="ok">{msg}</p>{/if}
<div class="scroll">
  <table class="grid">
    <thead><tr><th>On</th><th>Where</th><th>Match</th><th>Replace</th><th>Regex</th><th>Comment</th><th></th></tr></thead>
    <tbody>
      {#each rules as r, i (i)}
        <tr>
          <td><input type="checkbox" bind:checked={r.enabled} disabled={!canEdit} aria-label="Rule {i + 1}: enabled" /></td>
          <td>
            <select bind:value={r.target} disabled={!canEdit} aria-label="Rule {i + 1}: where it applies">
              {#each targets as [v, l] (v)}<option value={v}>{l}</option>{/each}
            </select>
          </td>
          <td><input bind:value={r.match} disabled={!canEdit} class="mono" aria-label="Rule {i + 1}: match" /></td>
          <td><input bind:value={r.replace} disabled={!canEdit} class="mono" aria-label="Rule {i + 1}: replace with" /></td>
          <td><input type="checkbox" bind:checked={r.regex} disabled={!canEdit} aria-label="Rule {i + 1}: match is a regular expression" /></td>
          <td><input bind:value={r.comment} disabled={!canEdit} aria-label="Rule {i + 1}: comment" /></td>
          <td>{#if canEdit}<button aria-label="Remove rule {i + 1}" onclick={() => (rules = rules.filter((_, j) => j !== i))}>Remove</button>{/if}</td>
        </tr>
      {:else}
        <tr><td colspan="7" class="muted">No rules.</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .scroll { overflow: auto; flex: 1; }
  td input:not([type='checkbox']) { width: 100%; }
</style>
