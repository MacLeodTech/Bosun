<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { workspace } from '../lib/workspace.svelte';
  import { historyView } from '../lib/historyView.svelte';
  import { css } from '../lib/style';
  import VirtualList from '../components/VirtualList.svelte';
  import { bytesToText, b64ToBytes } from '../lib/bytes';
  import type { components } from '../lib/api-types';
  import {
    ATTACK_TYPES, OPS, autoMark, blankOptions, blankProc, blankSet, clearMarks, countPositions, filterRows, markSelection,
    optionsBody, requestB64, rowsToCsv, setBody, sortRows,
    type AttackInfo, type AttackType, type GrepMatchUi, type OptionsUi, type ProcKind, type Row, type SetUi, type SortKey,
  } from '../lib/intruder';

  type S = components['schemas'];

  const INBOX = 'bosun.intruder.inbox';
  const INBOX_EVENT = 'bosun:intruder-inbox';
  const canRun = $derived(session.can('tester'));

  let scheme = $state<'http' | 'https'>('https');
  let host = $state('');
  let port = $state(443);
  let request = $state('GET / HTTP/1.1\nHost: \n\n');
  let attackType = $state<AttackType>('sniper');
  let sets = $state<SetUi[]>([blankSet()]);
  let matchRules = $state<GrepMatchUi[]>([]);
  let extractRules = $state<string[]>([]);
  let options = $state<OptionsUi>(blankOptions());
  let name = $state('');
  let editor = $state<HTMLTextAreaElement | null>(null);

  let error = $state('');
  let note = $state('');
  let busy = $state(false);
  let plan = $state<S['PlanReply'] | null>(null);

  let attacks = $state<AttackInfo[]>([]);
  let current = $state<number | null>(null);
  let rows = $state.raw<Row[]>([]);
  let loadedFor = $state<number | null>(null);
  let sortKey = $state<SortKey>('index');
  let asc = $state(true);
  let filter = $state('');
  let activeRow = $state(-1);
  /** The labels of the grep rules of the shown attack, for the column heads. */
  let matchLabels = $state<string[]>([]);
  let extractLabels = $state<string[]>([]);

  const positions = $derived(countPositions(request));
  const setCount = $derived(attackType === 'sniper' || attackType === 'battering_ram' ? 1 : Math.max(1, positions));
  const info = $derived(attacks.find((a) => a.id === current) ?? null);
  const shown = $derived(sortRows(filterRows(rows, filter), sortKey, asc));
  const cols = $derived(6 + matchLabels.length + extractLabels.length);

  // One payload set per position for pitchfork and cluster bomb, one set otherwise.
  $effect(() => {
    const n = setCount;
    if (sets.length < n) sets = [...sets, ...Array.from({ length: n - sets.length }, blankSet)];
  });

  function takeInbox() {
    try {
      const raw = sessionStorage.getItem(INBOX);
      if (!raw) return;
      sessionStorage.removeItem(INBOX);
      const it = JSON.parse(raw) as { scheme: 'http' | 'https'; host: string; port: number; request: string };
      scheme = it.scheme; host = it.host; port = it.port;
      request = autoMark(it.request.replace(/\r\n/g, '\n'));
      plan = null; error = ''; note = '';
    } catch { /* a bad inbox is dropped */ }
  }

  async function loadAttacks() {
    try {
      attacks = (await api.get<S['AttackList']>('/intruder/attacks')).attacks;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function show(id: number) {
    current = id;
    rows = [];
    loadedFor = null;
    try {
      const detail = await api.get<S['AttackDetail']>(`/intruder/attacks/${id}`);
      const cfg = (detail.config ?? {}) as { greps?: S['Greps'] };
      matchLabels = (cfg.greps?.matches ?? []).map((m) => m.pattern);
      extractLabels = (cfg.greps?.extracts ?? []).map((m) => m.pattern);
      const all: Row[] = [];
      for (let off = 0; off < 1_000_000; off += 5000) {
        const r = await api.get<S['ResultsReply']>(`/intruder/attacks/${id}/results?offset=${off}&limit=5000`);
        all.push(...r.rows);
        if (r.rows.length < 5000) break;
        if (current !== id) return;
      }
      if (current !== id) return;
      rows = all;
      loadedFor = id;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  onMount(() => {
    takeInbox();
    window.addEventListener(INBOX_EVENT, takeInbox);
    void loadAttacks();
    let pending: Row[] = [];
    let timer: ReturnType<typeof setTimeout> | undefined;
    const flush = () => {
      timer = undefined;
      if (pending.length) { rows = rows.concat(pending); pending = []; }
    };
    const off = session.on((e) => {
      if (e.type === 'reload') { void loadAttacks(); if (current != null) void show(current); return; }
      if (e.type === 'intruder_state') {
        const i = attacks.findIndex((a) => a.id === e.attack_id);
        if (i < 0) { void loadAttacks(); return; }
        attacks[i] = { ...attacks[i]!, state: e.state, total: e.total, done: e.done, skipped: e.skipped, errors: e.errors, error: e.error ?? null };
        return;
      }
      if (e.type === 'intruder_result' && e.attack_id === current && loadedFor === current) {
        pending.push({
          index: e.index, position: e.position ?? null, payloads: e.payloads, status: e.status ?? null, length: e.length,
          time_ms: e.time_ms, flow_id: e.flow_id ?? null, error: e.error ?? null, matches: e.matches, extracts: e.extracts, attempts: e.attempts,
        });
        timer ??= setTimeout(flush, 150);
      }
    });
    return () => { window.removeEventListener(INBOX_EVENT, takeInbox); off(); clearTimeout(timer); };
  });

  // ---- positions

  function addMarks() {
    if (!editor) return;
    const m = markSelection(request, editor.selectionStart, editor.selectionEnd);
    request = m.text;
    const el = editor;
    setTimeout(() => { el.focus(); el.setSelectionRange(m.start, m.end); }, 0);
  }

  // ---- building the request

  function greps(): S['Greps'] {
    return {
      matches: matchRules.filter((m) => m.pattern).map((m) => ({ pattern: m.pattern, regex: m.regex, case_insensitive: m.caseInsensitive })),
      extracts: extractRules.filter((p) => p).map((pattern) => ({ pattern })),
    };
  }

  function body(): S['StartBody'] {
    return {
      attack_type: attackType,
      host: host.trim(),
      port,
      scheme,
      request: requestB64(request),
      payload_sets: sets.slice(0, setCount).map(setBody),
      options: optionsBody(options),
      greps: greps(),
      name: name.trim() || null,
    };
  }

  async function preview() {
    error = ''; note = ''; busy = true;
    try {
      plan = await api.post<S['PlanReply']>('/intruder/plan', body());
    } catch (e) {
      plan = null;
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function start() {
    error = ''; note = ''; busy = true;
    try {
      const a = await api.post<AttackInfo>('/intruder/attacks', body());
      await loadAttacks();
      sortKey = 'index'; asc = true;
      await show(a.id);
      note = `Attack ${a.id} started.`;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function stop() {
    if (current == null) return;
    try {
      await api.post(`/intruder/attacks/${current}/stop`);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function remove() {
    if (current == null || !confirm('Delete this attack and its results? The recorded requests stay in the history.')) return;
    try {
      await api.del(`/intruder/attacks/${current}`);
      current = null; rows = []; loadedFor = null;
      await loadAttacks();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  /** Put an earlier attack's request back into the form. */
  async function reuse() {
    if (current == null) return;
    try {
      const d = await api.get<S['AttackDetail']>(`/intruder/attacks/${current}`);
      scheme = d.scheme as 'http' | 'https'; host = d.host; port = d.port;
      request = bytesToText(b64ToBytes(d.request)).text.replace(/\r\n/g, '\n');
      note = 'Request loaded. The payload sets stay as they are in the form.';
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  // ---- results

  function sortBy(k: SortKey) {
    if (sortKey === k) asc = !asc;
    else { sortKey = k; asc = k === 'payload' || k === 'index'; }
  }
  const arrow = (k: SortKey) => (sortKey === k ? (asc ? ' ▲' : ' ▼') : '');

  function openFlow(id: number) {
    historyView.select([id], id);
    historyView.openId = id;
    workspace.reveal('flow', 'intruder');
  }

  function save(text: string, file: string, type: string) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = document.createElement('a');
    a.href = url; a.download = file;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }
  const exportCsv = () => save(rowsToCsv(shown, matchLabels, extractLabels), `bosun-intruder-${current}.csv`, 'text/csv');
  const exportJson = () => save(JSON.stringify({ attack: info, rows: shown }, null, 2), `bosun-intruder-${current}.json`, 'application/json');

  /** Load payloads from a file on this machine, into a list set. */
  async function loadFile(set: SetUi, e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const f = input.files?.[0];
    if (!f) return;
    if (f.size > 8 * 1024 * 1024) { error = 'That file is over 8 MiB.'; input.value = ''; return; }
    set.list = await f.text();
    input.value = '';
  }

  const pct = (a: AttackInfo) => (a.total > 0 ? Math.min(100, Math.round(((a.done + a.skipped) / a.total) * 100)) : 0);
  const running = $derived(info?.state === 'running');
</script>

<div class="page">
  <section class="setup">
    <div class="toolbar">
      <label>Scheme
        <select bind:value={scheme} onchange={() => (port = scheme === 'https' ? 443 : 80)} disabled={!canRun}>
          <option value="https">https</option><option value="http">http</option>
        </select>
      </label>
      <label class="grow">Host <input class="code" bind:value={host} spellcheck="false" placeholder="example.com" disabled={!canRun} aria-label="Host" /></label>
      <label>Port <input type="number" min="1" max="65535" bind:value={port} disabled={!canRun} aria-label="Port" /></label>
      <label>Type
        <select bind:value={attackType} disabled={!canRun} aria-label="Attack type">
          {#each ATTACK_TYPES as t (t.id)}<option value={t.id}>{t.label}</option>{/each}
        </select>
      </label>
      <label>Name <input bind:value={name} maxlength="200" placeholder="optional" disabled={!canRun} aria-label="Attack name" /></label>
    </div>
    <p class="muted small hint">{ATTACK_TYPES.find((t) => t.id === attackType)?.help} Positions are marked with § around the text to replace.</p>

    <div class="toolbar">
      <button disabled={!canRun} onclick={addMarks} title="Put § around the selected text">Add §</button>
      <button disabled={!canRun} onclick={() => (request = autoMark(request))} title="Mark query parameter and form values">Auto §</button>
      <button disabled={!canRun} onclick={() => (request = clearMarks(request))}>Clear §</button>
      <span class="muted small tnum" data-testid="intruder-positions">{positions} position{positions === 1 ? '' : 's'}</span>
    </div>
    <textarea class="code edit" bind:this={editor} bind:value={request} spellcheck="false" disabled={!canRun} aria-label="Request with positions"></textarea>

    {#each sets.slice(0, setCount) as set, i (i)}
      <fieldset>
        <legend>Payload set{setCount > 1 ? ` ${i + 1} (position ${i + 1})` : ''}</legend>
        <div class="toolbar">
          <label>Source
            <select bind:value={set.source} disabled={!canRun} aria-label="Payload source {i + 1}">
              <option value="list">List</option><option value="numbers">Numbers</option><option value="brute_force">Brute force</option>
              <option value="null">Null payloads</option><option value="case_changes">Case changes</option>
            </select>
          </label>
          {#if set.source === 'numbers'}
            <label>From <input type="number" bind:value={set.from} /></label>
            <label>To <input type="number" bind:value={set.to} /></label>
            <label>Step <input type="number" bind:value={set.step} /></label>
            <label>Base <select bind:value={set.base}><option value="decimal">decimal</option><option value="hex">hex</option></select></label>
            <label>Digits <input type="number" min="0" max="64" bind:value={set.digits} /></label>
          {:else if set.source === 'brute_force'}
            <label class="grow">Characters <input class="code" bind:value={set.charset} /></label>
            <label>Min <input type="number" min="0" max="16" bind:value={set.minLen} /></label>
            <label>Max <input type="number" min="1" max="16" bind:value={set.maxLen} /></label>
          {:else if set.source === 'null'}
            <label>Count <input type="number" min="1" bind:value={set.count} aria-label="Null payload count {i + 1}" /></label>
          {:else}
            <label class="filebtn">Load file… <input type="file" onchange={(e) => loadFile(set, e)} /></label>
          {/if}
        </div>
        {#if set.source === 'list' || set.source === 'case_changes'}
          <textarea class="code list" bind:value={set.list} spellcheck="false" disabled={!canRun} placeholder="One payload per line" aria-label="Payloads {i + 1}"></textarea>
        {/if}
        {#each set.processing as p, j (j)}
          <div class="toolbar proc">
            <select bind:value={p.type} aria-label="Rule type">
              <option value="prefix">Add prefix</option><option value="suffix">Add suffix</option><option value="encode">Encode or hash</option>
              <option value="replace_regex">Replace (regex)</option><option value="skip_if_matches">Skip if it matches</option>
            </select>
            {#if p.type === 'prefix' || p.type === 'suffix'}
              <input class="code grow" bind:value={p.value} aria-label="Text" />
            {:else if p.type === 'encode'}
              <select bind:value={p.op} aria-label="Operation">{#each OPS as o (o.id)}<option value={o.id}>{o.label}</option>{/each}</select>
            {:else}
              <input class="code grow" bind:value={p.pattern} placeholder="regex" aria-label="Pattern" />
              {#if p.type === 'replace_regex'}<input class="code grow" bind:value={p.replacement} placeholder="replacement" aria-label="Replacement" />{/if}
            {/if}
            <button class="ghost" onclick={() => set.processing.splice(j, 1)} aria-label="Remove rule">Remove</button>
          </div>
        {/each}
        <div class="toolbar">
          <select onchange={(e) => { const v = e.currentTarget.value as ProcKind; if (v) set.processing.push(blankProc(v)); e.currentTarget.value = ''; }} aria-label="Add a processing rule" disabled={!canRun}>
            <option value="">Add processing rule…</option>
            <option value="prefix">Add prefix</option><option value="suffix">Add suffix</option><option value="encode">Encode or hash</option>
            <option value="replace_regex">Replace (regex)</option><option value="skip_if_matches">Skip if it matches</option>
          </select>
        </div>
      </fieldset>
    {/each}

    <fieldset>
      <legend>Grep</legend>
      {#each matchRules as m, i (i)}
        <div class="toolbar">
          <span class="muted small">Match</span>
          <input class="code grow" bind:value={m.pattern} aria-label="Match text {i + 1}" />
          <label><input type="checkbox" bind:checked={m.regex} /> regex</label>
          <label><input type="checkbox" bind:checked={m.caseInsensitive} /> ignore case</label>
          <button class="ghost" onclick={() => matchRules.splice(i, 1)}>Remove</button>
        </div>
      {/each}
      {#each extractRules as _, i (i)}
        <div class="toolbar">
          <span class="muted small">Extract</span>
          <input class="code grow" bind:value={extractRules[i]} placeholder="regex; the first group is kept" aria-label="Extract pattern {i + 1}" />
          <button class="ghost" onclick={() => extractRules.splice(i, 1)}>Remove</button>
        </div>
      {/each}
      <div class="toolbar">
        <button disabled={!canRun} onclick={() => matchRules.push({ pattern: '', regex: false, caseInsensitive: true })}>Add match rule</button>
        <button disabled={!canRun} onclick={() => extractRules.push('')}>Add extract rule</button>
      </div>
    </fieldset>

    <fieldset>
      <legend>Options</legend>
      <div class="toolbar">
        <label>Concurrency <input type="number" min="1" max="64" bind:value={options.concurrency} aria-label="Concurrency" /></label>
        <label>Delay (ms) <input type="number" min="0" bind:value={options.delayMs} aria-label="Delay" /></label>
        <label>Retries <input type="number" min="0" max="10" bind:value={options.retries} aria-label="Retries" /></label>
        <label>Max requests <input type="number" min="1" bind:value={options.maxRequests} placeholder="all" aria-label="Maximum requests" /></label>
        <label>Timeout (s) <input type="number" min="1" bind:value={options.timeoutSecs} aria-label="Timeout" /></label>
        <label><input type="checkbox" bind:checked={options.updateContentLength} /> update Content-Length</label>
        <label><input type="checkbox" bind:checked={options.verifyTls} /> verify TLS</label>
      </div>
      <p class="muted small">Requests go through the scope gate: the host must be in scope, and the per-host rate limit applies on top of these settings.</p>
    </fieldset>

    <div class="toolbar">
      <button disabled={!canRun || busy || !host.trim()} onclick={preview}>Preview</button>
      <button class="primary" disabled={!canRun || busy || !host.trim()} onclick={start} data-testid="intruder-start">Start attack</button>
      {#if plan}<span class="tnum small" data-testid="intruder-plan">{plan.total} requests, {plan.positions} position{plan.positions === 1 ? '' : 's'}</span>{/if}
    </div>
    {#if plan?.preview.length}
      <ul class="preview small code">
        {#each plan.preview as p (p.index)}<li>{p.index + 1}: {p.payloads.join(' | ')}</li>{/each}
      </ul>
    {/if}
    {#if !canRun}<p class="muted">Running attacks needs the tester role.</p>{/if}
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    {#if note}<p class="muted small" role="status">{note}</p>{/if}
  </section>

  <section class="results">
    <div class="toolbar">
      <label>Attack
        <select value={current ?? ''} onchange={(e) => { const v = e.currentTarget.value; if (v) void show(Number(v)); }} aria-label="Attack">
          <option value="">{attacks.length ? 'Choose an attack…' : 'No attacks yet'}</option>
          {#each attacks as a (a.id)}<option value={a.id}>{a.id}. {a.name} ({a.state})</option>{/each}
        </select>
      </label>
      {#if info}
        <progress max="100" value={pct(info)} aria-label="Progress"></progress>
        <span class="tnum small" data-testid="intruder-state">{info.state}: {info.done} of {info.total}{info.errors ? `, ${info.errors} failed` : ''}{info.skipped ? `, ${info.skipped} skipped` : ''}</span>
        {#if info.error}<span class="error small">{info.error}</span>{/if}
        <button disabled={!canRun || !running} onclick={stop}>Stop</button>
        <button disabled={!canRun || running} class="danger" onclick={remove}>Delete</button>
        <button disabled={!canRun} onclick={reuse}>Load request</button>
      {/if}
      <span class="spacer"></span>
      <input class="grow" bind:value={filter} placeholder="Filter: words, status:404, length:>1000, time:>500, match, error" aria-label="Filter results" />
      <button disabled={!shown.length} onclick={exportCsv}>Export CSV</button>
      <button disabled={!shown.length} onclick={exportJson}>Export JSON</button>
    </div>

    {#if current != null}
      <div class="grid head" role="row" use:css={{ '--cols': String(cols) }}>
        <button class="ghost" onclick={() => sortBy('index')}>#{arrow('index')}</button>
        <button class="ghost" onclick={() => sortBy('payload')}>Payload{arrow('payload')}</button>
        <button class="ghost" onclick={() => sortBy('status')}>Status{arrow('status')}</button>
        <button class="ghost" onclick={() => sortBy('length')}>Length{arrow('length')}</button>
        <button class="ghost" onclick={() => sortBy('time')}>Time (ms){arrow('time')}</button>
        <span>Flow</span>
        {#each matchLabels as l, i (i)}<button class="ghost" title={l} onclick={() => sortBy(`match:${i}`)}>Match {i + 1}{arrow(`match:${i}`)}</button>{/each}
        {#each extractLabels as l, i (i)}<button class="ghost" title={l} onclick={() => sortBy(`extract:${i}`)}>Extract {i + 1}{arrow(`extract:${i}`)}</button>{/each}
      </div>
      <div class="list" data-testid="intruder-results">
        <VirtualList items={shown} rowHeight={24} label="Attack results" idPrefix="intruder" key={(r) => r.index} activeIndex={activeRow} onSelect={(i) => (activeRow = i)} onActivate={(i) => { const f = shown[i]?.flow_id; if (f != null) openFlow(f); }}>
          {#snippet row(r: Row, i: number)}
            <div class="grid body" role="option" aria-selected={i === activeRow} id="intruder-row-{i}" class:sel={i === activeRow} class:bad={r.status == null} use:css={{ '--cols': String(cols) }} onclick={() => (activeRow = i)} onkeydown={() => {}} tabindex="-1">
              <span class="tnum">{r.index + 1}</span>
              <span class="code cut" title={r.payloads.join(' | ')}>{r.payloads.join(' | ')}</span>
              <span class="tnum">{r.status ?? (r.error ? 'error' : '')}</span>
              <span class="tnum">{r.length}</span>
              <span class="tnum">{r.time_ms}</span>
              <span>{#if r.flow_id != null}<button class="ghost link" onclick={() => openFlow(r.flow_id!)}>#{r.flow_id}</button>{:else}<span class="muted cut" title={r.error ?? ''}>{r.error ?? ''}</span>{/if}</span>
              {#each matchLabels as _, k (k)}<span>{r.matches[k] ? '✓' : ''}</span>{/each}
              {#each extractLabels as _, k (k)}<span class="code cut" title={r.extracts[k] ?? ''}>{r.extracts[k] ?? ''}</span>{/each}
            </div>
          {/snippet}
        </VirtualList>
      </div>
      <p class="muted small count tnum">{shown.length} of {rows.length} shown</p>
    {/if}
  </section>
</div>

<style>
  .page { display: flex; flex-direction: column; height: 100%; overflow: auto; }
  .setup { padding-bottom: .5rem; border-bottom: 1px solid var(--border-subtle); }
  .results { display: flex; flex-direction: column; min-height: 22rem; flex: 1; }
  .list { flex: 1; min-height: 12rem; display: flex; flex-direction: column; }
  .list :global(.vl) { flex: 1; }
  .hint { margin: .2rem .5rem; }
  label { display: inline-flex; gap: .3rem; align-items: center; }
  label.grow { flex: 1; }
  label.grow input { flex: 1; }
  fieldset { margin: .4rem .5rem; border: 1px solid var(--border-subtle); border-radius: var(--radius); }
  textarea.edit { width: calc(100% - 1rem); margin: 0 .5rem; height: 12rem; resize: vertical; box-sizing: border-box; }
  textarea.list { width: 100%; height: 7rem; resize: vertical; box-sizing: border-box; }
  .preview { margin: .2rem .5rem; padding-left: 1.2rem; }
  .proc { padding-left: 0; }
  .filebtn input { max-width: 14rem; }
  .grid { display: grid; grid-template-columns: 4rem minmax(8rem, 2fr) 5rem 6rem 6rem 8rem repeat(calc(var(--cols) - 6), minmax(6rem, 1fr)); align-items: center; gap: .4rem; padding: 0 .5rem; height: 24px; }
  .grid.head { font-weight: 600; border-bottom: 1px solid var(--border-subtle); }
  .grid.head button { text-align: left; padding: 0 .2rem; }
  .grid.body.sel { background: var(--surface-sel); }
  .grid.body.bad { color: var(--bad); }
  .cut { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  button.link { padding: 0 .2rem; text-decoration: underline; }
  .count { margin: .2rem .5rem; }
</style>
