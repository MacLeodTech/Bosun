<script lang="ts">
  // Issues: what the passive scanner found in recorded traffic. The scanner reads flows after the proxy has stored
  // them (it never sits on the traffic path), so a long history takes a while to work through; the count of flows it
  // has not read yet is shown. Everything here is the target's text or the scanner's own, shown only as text.
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { fmtTime } from '../lib/bytes';
  import { b64ToBytes } from '../lib/bytes';
  import { concat, loadPart, type PartName } from '../lib/flowbody';
  import { historyView } from '../lib/historyView.svelte';
  import { session } from '../lib/session.svelte';
  import { toasts } from '../lib/toasts.svelte';
  import { workspace } from '../lib/workspace.svelte';
  import type { FlowMeta } from '../lib/types';
  import type { components } from '../lib/api-types';

  type Issue = components['schemas']['Issue'];
  type List = components['schemas']['IssueList'];
  type Status = components['schemas']['IssueStatus'];
  type Severity = components['schemas']['Severity'];
  type Evidence = components['schemas']['Evidence'];

  const STATUSES: { id: Status; label: string }[] = [
    { id: 'new', label: 'New' },
    { id: 'confirmed', label: 'Confirmed' },
    { id: 'false_positive', label: 'False positive' },
  ];
  const SEVERITIES: Severity[] = ['high', 'medium', 'low', 'info'];
  const RANK: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0 };
  const statusLabel = (s: Status) => STATUSES.find((x) => x.id === s)?.label ?? s;

  let issues = $state<Issue[]>([]);
  let rules = $state<string[]>([]);
  let pending = $state(0);
  let loaded = $state(false);
  let status = $state<'all' | Status>('all');
  let severity = $state<'all' | Severity>('all');
  let rule = $state('all');
  let text = $state('');
  let group = $state<'none' | 'rule' | 'host' | 'severity'>('none');
  let selectedId = $state<number | null>(null);

  const canEdit = $derived(session.can('tester'));
  const shown = $derived(
    issues
      .filter(
        (i) =>
          (status === 'all' || i.status === status) &&
          (severity === 'all' || i.severity === severity) &&
          (rule === 'all' || i.rule === rule) &&
          (!text || `${i.title} ${i.host} ${i.path} ${i.detail}`.toLowerCase().includes(text.toLowerCase())),
      )
      .sort((a, b) => RANK[b.severity] - RANK[a.severity] || b.last_seen_ms - a.last_seen_ms),
  );
  const groups = $derived.by(() => {
    if (group === 'none') return [{ key: '', items: shown }];
    const by = new Map<string, Issue[]>();
    for (const i of shown) {
      const k = group === 'rule' ? i.title : group === 'host' ? `${i.scheme}://${i.host}:${i.port}` : i.severity;
      by.set(k, [...(by.get(k) ?? []), i]);
    }
    return [...by.entries()].map(([key, items]) => ({ key, items }));
  });
  const selected = $derived(issues.find((i) => i.id === selectedId) ?? null);

  async function load() {
    try {
      const r = await api.get<List>('/issues?limit=5000');
      issues = r.issues;
      rules = r.rules;
      pending = r.pending;
    } catch (e) {
      toasts.push({ text: `Could not load the issues: ${e instanceof Error ? e.message : e}` });
    }
    loaded = true;
  }

  onMount(() => {
    load();
    // New findings arrive as the scanner works, so look again every few seconds.
    const t = setInterval(load, 5000);
    const off = session.on((e) => {
      if (e.type === 'reload') load();
    });
    return () => {
      clearInterval(t);
      off();
    };
  });

  async function setStatus(i: Issue, s: Status) {
    try {
      await api.patch(`/issues/${i.id}`, { status: s });
      issues = issues.map((x) => (x.id === i.id ? { ...x, status: s } : x));
    } catch (e) {
      toasts.push({ text: `Could not save: ${e instanceof Error ? e.message : e}` });
      load();
    }
  }

  let reportFormat = $state('html');

  /** Saves a report of all issues as a file (never opened here: it has target content in it). */
  async function saveReport() {
    try {
      const r = await fetch(`/api/v1/issues/report?format=${encodeURIComponent(reportFormat)}`, { credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const url = URL.createObjectURL(new Blob([await r.arrayBuffer()], { type: 'application/octet-stream' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `bosun-report.${reportFormat === 'junit' ? 'xml' : reportFormat === 'markdown' ? 'md' : reportFormat}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      toasts.push({ text: 'Report saved. Secrets in it are redacted.' });
    } catch (e) {
      toasts.push({ text: `Could not save the report: ${e instanceof Error ? e.message : e}` });
    }
  }

  async function rescan() {
    try {
      await api.post('/issues/rescan', {});
      toasts.push({ text: 'Every request is queued for the scanner again.' });
      load();
    } catch (e) {
      toasts.push({ text: `Could not rescan: ${e instanceof Error ? e.message : e}` });
    }
  }

  function open(i: Issue) {
    if (i.flow_id == null) return;
    historyView.select([i.flow_id], i.flow_id);
    historyView.openId = i.flow_id;
    workspace.reveal('flow', 'issues');
  }

  // The evidence: the text around each highlighted range, from the stored message.
  interface Excerpt {
    part: string;
    before: string;
    hit: string;
    after: string;
    note: string;
  }
  let excerpts = $state<Excerpt[]>([]);
  let excerptNote = $state('');
  const CONTEXT = 160;
  const dec = new TextDecoder('utf-8', { fatal: false });

  function cut(bytes: Uint8Array, ev: Evidence, part: string): Excerpt {
    const s = Math.min(ev.start, bytes.length);
    const e = Math.min(Math.max(ev.end, s), bytes.length);
    if (e <= s) return { part, before: '', hit: '', after: '', note: 'This part of the message is not loaded here; open the request.' };
    const a = Math.max(0, s - CONTEXT);
    const b = Math.min(bytes.length, e + CONTEXT);
    return {
      part,
      before: (a > 0 ? '… ' : '') + dec.decode(bytes.subarray(a, s)),
      hit: dec.decode(bytes.subarray(s, Math.min(e, s + 2000))),
      after: dec.decode(bytes.subarray(e, b)) + (b < bytes.length ? ' …' : ''),
      note: '',
    };
  }

  $effect(() => {
    const i = selected;
    excerpts = [];
    excerptNote = '';
    if (!i) return;
    if (i.flow_id == null) {
      excerptNote = 'The request this was found in has been deleted.';
      return;
    }
    if (!i.evidence.length) {
      excerptNote = 'Nothing to highlight: the problem is something the response lacks.';
      return;
    }
    let live = true;
    const id = i.flow_id;
    (async () => {
      try {
        const meta = await api.get<FlowMeta>(`/flows/${id}`);
        const loaded = new Map<string, Uint8Array>();
        const out: Excerpt[] = [];
        for (const ev of i.evidence) {
          const part: PartName = ev.part === 'request' ? 'request' : 'response';
          const info = meta[part];
          if (!info) continue;
          if (!loaded.has(part)) {
            const l = await loadPart(meta, part, info);
            loaded.set(part, concat(b64ToBytes(info.head), l.body));
          }
          out.push(cut(loaded.get(part)!, ev, part));
        }
        if (live) excerpts = out;
      } catch (e) {
        if (live) excerptNote = `Could not load the evidence: ${e instanceof Error ? e.message : e}`;
      }
    })();
    return () => {
      live = false;
    };
  });
</script>

<div class="toolbar">
  <label class="small" for="iss-status">Status</label>
  <select id="iss-status" bind:value={status}>
    <option value="all">All</option>
    {#each STATUSES as s (s.id)}<option value={s.id}>{s.label}</option>{/each}
  </select>
  <label class="small" for="iss-sev">Severity</label>
  <select id="iss-sev" bind:value={severity}>
    <option value="all">All</option>
    {#each SEVERITIES as s (s)}<option value={s}>{s}</option>{/each}
  </select>
  <label class="small" for="iss-rule">Check</label>
  <select id="iss-rule" bind:value={rule}>
    <option value="all">All</option>
    {#each rules as r (r)}<option value={r}>{r}</option>{/each}
  </select>
  <label class="small" for="iss-group">Group by</label>
  <select id="iss-group" bind:value={group}>
    <option value="none">Nothing</option>
    <option value="rule">Issue type</option>
    <option value="host">Host</option>
    <option value="severity">Severity</option>
  </select>
  <input class="grow" type="search" placeholder="Search issues" aria-label="Search issues" bind:value={text} />
  <span class="muted small" aria-live="polite">
    {shown.length} of {issues.length}{#if pending > 0}; {pending} request{pending === 1 ? '' : 's'} still to scan{/if}
  </span>
  <select aria-label="Report format" bind:value={reportFormat}>
    <option value="html">HTML</option>
    <option value="json">JSON</option>
    <option value="sarif">SARIF</option>
    <option value="junit">JUnit</option>
    <option value="markdown">Markdown</option>
  </select>
  <button onclick={saveReport} title="Save a report of all issues, secrets redacted">Save report</button>
  {#if canEdit}<button onclick={rescan} title="Scan the whole history again with the current checks">Rescan</button>{/if}
</div>
<div class="body">
  <div class="scroll">
    <table class="grid">
      <thead><tr><th>Severity</th><th>Confidence</th><th>Issue</th><th>Where</th><th>Seen</th><th>Status</th></tr></thead>
      {#each groups as g (g.key)}
        <tbody>
          {#if group !== 'none'}
            <tr class="group"><th colspan="6">{g.key} <span class="muted">({g.items.length})</span></th></tr>
          {/if}
          {#each g.items as i (i.id)}
            <tr class:sel={i.id === selectedId} class:fp={i.status === 'false_positive'} onclick={() => (selectedId = i.id)}>
              <td class="sev {i.severity}">{i.severity}</td>
              <td>{i.confidence}</td>
              <td>
                <button class="link" aria-label="Show issue: {i.title}" onclick={(e) => { e.stopPropagation(); selectedId = i.id; }}>{i.title}</button>
              </td>
              <td class="where" title="{i.scheme}://{i.host}:{i.port}{i.path}">{i.host}{i.path}</td>
              <td class="tnum">{i.count}×</td>
              <td>{statusLabel(i.status)}</td>
            </tr>
          {/each}
        </tbody>
      {:else}
        <tbody><tr><td colspan="6" class="muted">{loaded ? (issues.length ? 'No issue matches these filters.' : pending > 0 ? 'Scanning…' : 'No issues found yet.') : 'Loading…'}</td></tr></tbody>
      {/each}
    </table>
  </div>
  {#if selected}
    <section class="detail" aria-label="Issue details">
      <h3>{selected.title}</h3>
      <p class="muted small">
        <span class="sev {selected.severity}">{selected.severity}</span> severity, {selected.confidence} confidence.
        Seen in {selected.count} request{selected.count === 1 ? '' : 's'}, first {fmtTime(selected.first_seen_ms)}, last {fmtTime(selected.last_seen_ms)}.
      </p>
      <p>{selected.detail}</p>
      <h4>Remediation</h4>
      <p>{selected.remediation}</p>
      <p class="small">
        {#each selected.cwe as c (c)}<span class="badge">CWE-{c}</span>{' '}{/each}
        {#each selected.owasp as o (o)}<span class="badge">{o}</span>{' '}{/each}
      </p>
      <h4>Evidence</h4>
      {#each excerpts as x, n (n)}
        <pre class="ev" aria-label="Evidence in the {x.part}">{x.before}<mark>{x.hit}</mark>{x.after}{#if x.note}{x.note}{/if}</pre>
      {/each}
      {#if excerptNote}<p class="muted small">{excerptNote}</p>{/if}
      <div class="acts">
        <button onclick={() => open(selected)} disabled={selected.flow_id == null}>Open request</button>
        {#if canEdit}
          {#each STATUSES.filter((s) => s.id !== selected.status) as s (s.id)}
            <button onclick={() => setStatus(selected, s.id)}>Mark {s.label.toLowerCase()}</button>
          {/each}
        {/if}
      </div>
    </section>
  {/if}
</div>

<style>
  .body { display: flex; flex-direction: column; flex: 1; min-height: 0; }
  .scroll { overflow: auto; flex: 1; min-height: 6rem; }
  .detail { overflow: auto; max-height: 55%; border-top: 1px solid var(--border-subtle); padding: .4rem .75rem; }
  h3 { margin: .2rem 0; }
  h4 { margin: .6rem 0 .2rem; }
  .sev { font-weight: 600; text-transform: capitalize; }
  .sev.high { color: var(--bad); }
  .sev.medium { color: var(--warn); }
  .sev.low { color: var(--info); }
  .sev.info { color: var(--text-2); }
  .where { font-family: var(--font-mono); font-size: var(--fs-data); max-width: 24rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .group th { text-align: left; background: var(--surface-sel); }
  tr.sel { background: var(--surface-sel); }
  tr.fp { opacity: .6; }
  .link { background: none; border: 0; padding: 0; color: inherit; text-decoration: underline; cursor: pointer; font: inherit; text-align: left; }
  .ev { font-family: var(--font-mono); font-size: var(--fs-data); white-space: pre-wrap; overflow-wrap: anywhere; border: 1px solid var(--border-subtle); padding: .4rem; margin: .3rem 0; }
  .ev mark { background: var(--warn); color: var(--on-accent); }
  .acts { display: flex; gap: .4rem; flex-wrap: wrap; margin: .5rem 0; }
</style>
