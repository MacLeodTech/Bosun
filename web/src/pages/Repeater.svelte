<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { b64ToBytes, bytesToB64, bytesToText, textToBytes, wireBytes, type TextMode } from '../lib/bytes';
  import { diffLines, type Op } from '../lib/diff';
  import DiffView from '../components/DiffView.svelte';
  import { stashForIntruder } from '../lib/flowactions';
  import { workspace } from '../lib/workspace.svelte';
  import MessageEditor from '../components/MessageEditor.svelte';
  import type { RepeaterSendBody, RepeaterSendReply, RepeaterSendResult, RepeaterWsBody, RepeaterWsReply } from '../lib/types';

  type Mode = 'sequential' | 'parallel' | 'single_packet';
  interface Sent { at: number; results: RepeaterSendResult[]; text: string[]; ws?: RepeaterWsReply }
  /** A frame to send on a WebSocket tab. The payload is text (UTF-8) or, when `hex`, hex digits. */
  interface WsFrame { opcode: number; fin: boolean; rsv: number; mask: string; payload: string; hex: boolean }
  interface Tab {
    kind: 'http' | 'ws'; frames: WsFrame[]; listenMs: number;
    id: number; scheme: 'http' | 'https'; host: string; port: number; protocol: 'http1' | 'h2';
    request: string; mode: TextMode; updateLength: boolean; verifyTls: boolean; follow: boolean;
    count: number; sendMode: Mode; history: Sent[]; shown: number;
  }

  const INBOX = 'bosun.repeater.inbox';
  const INBOX_EVENT = 'bosun:repeater-inbox';
  const RELOAD_EVENT = 'bosun:repeater-reload';
  const canSend = $derived(session.can('tester'));

  let tabs = $state<Tab[]>([]);
  let active = $state(0);
  let next = 1;
  let error = $state('');
  let busy = $state(false);
  let allowOut = $state(false);
  let showDiff = $state(false);

  const tab = $derived(tabs.find((t) => t.id === active) ?? null);

  function blank(): Tab {
    return {
      id: next++, kind: 'http', frames: [], listenMs: 1500, scheme: 'https', host: '', port: 443, protocol: 'http1',
      request: 'GET / HTTP/1.1\r\nHost: \r\n\r\n', mode: 'utf8', updateLength: false, verifyTls: false,
      follow: false, count: 1, sendMode: 'sequential', history: [], shown: 0,
    };
  }

  // Tabs are saved in the open project (requests and options, not responses), so they come back with it and move
  // with it. Saving waits for typing to settle, and never runs before the saved tabs have been read, so an empty
  // page cannot overwrite what the project holds.
  let loaded = false;
  let saveTimer: ReturnType<typeof setTimeout> | undefined;
  let saveFailed = $state(false);

  $effect(() => {
    const doc = { tabs: tabs.map((t) => ({ ...t, history: [], shown: 0 })), active, next };
    const body = JSON.stringify(doc);
    if (!loaded || !canSend) return;
    clearTimeout(saveTimer);
    saveTimer = setTimeout(async () => {
      try { await api.put('/repeater/tabs', JSON.parse(body)); saveFailed = false; } catch { saveFailed = true; }
    }, 600);
  });

  onMount(() => {
    // The panel stays mounted in the background, so requests sent from History arrive as an event, not a mount.
    window.addEventListener(INBOX_EVENT, takeInbox);
    window.addEventListener(RELOAD_EVENT, start);
    start();
    // Another project is open: its tabs replace these.
    const off = session.on((e) => { if (e.type === 'reload') start(); });
    return () => { window.removeEventListener(INBOX_EVENT, takeInbox); window.removeEventListener(RELOAD_EVENT, start); off(); clearTimeout(saveTimer); };
  });

  async function start() {
    loaded = false;
    clearTimeout(saveTimer);
    tabs = [];
    try {
      const saved = await api.get<{ tabs: Tab[]; active: number; next: number }>('/repeater/tabs');
      if (saved.tabs.length) {
        tabs = saved.tabs.map((t) => ({ ...blank(), ...t, history: [], shown: 0 }));
        active = tabs.some((t) => t.id === saved.active) ? saved.active : tabs[0]!.id;
        next = Math.max(saved.next, ...tabs.map((t) => t.id + 1));
      }
    } catch { /* no access to the saved tabs: start fresh */ }
    loaded = true;
    takeInbox();
    if (!tabs.length) { const t = blank(); tabs = [t]; active = t.id; }
    try { allowOut = (await api.get<{ allow_out_of_scope: boolean }>('/repeater/settings')).allow_out_of_scope; } catch { /* viewer without access */ }
  }

  /** Requests sent here from the history page. */
  function takeInbox() {
    // Until the saved tabs are in, requests wait in the inbox: loading them would replace what was added here.
    if (!loaded) return;
    try {
      const inbox = JSON.parse(sessionStorage.getItem(INBOX) ?? '[]') as Partial<Tab>[];
      sessionStorage.removeItem(INBOX);
      for (const i of inbox) { const t = { ...blank(), ...i }; tabs = [...tabs, t]; active = t.id; }
    } catch { /* ignore */ }
  }

  function addTab() { const t = blank(); tabs = [...tabs, t]; active = t.id; }
  function closeTab(id: number) {
    tabs = tabs.filter((t) => t.id !== id);
    if (!tabs.length) addTab();
    else if (active === id) active = tabs[0]!.id;
  }
  function setScheme(t: Tab, s: 'http' | 'https') {
    if ((t.scheme === 'http' && t.port === 80) || (t.scheme === 'https' && t.port === 443)) t.port = s === 'http' ? 80 : 443;
    t.scheme = s;
  }

  async function toggleOut() {
    error = '';
    try {
      allowOut = (await api.put<{ allow_out_of_scope: boolean }>('/repeater/settings', { allow_out_of_scope: !allowOut })).allow_out_of_scope;
    } catch (e) { error = e instanceof Error ? e.message : String(e); }
  }

  /** The editor holds text; what is sent is those characters as bytes (Latin-1 when the original was not UTF-8). */
  const requestBytes = (t: Tab) => wireBytes(t.request, t.mode);

  const respText = (r: RepeaterSendResult) => bytesToText(b64ToBytes(r.response)).text;

  const OPCODES: [number, string][] = [[1, 'text'], [2, 'binary'], [0, 'continuation'], [8, 'close'], [9, 'ping'], [10, 'pong']];
  function addFrame() { tab?.frames.push({ opcode: 1, fin: true, rsv: 0, mask: 'random', payload: '', hex: false }); }
  function frameBytes(f: WsFrame): Uint8Array {
    if (f.hex) {
      const d = f.payload.replace(/\s+/g, '');
      if (d.length % 2 || /[^0-9a-fA-F]/.test(d)) throw new Error('a frame payload is not valid hex');
      return Uint8Array.from(d.match(/../g) ?? [], (h) => parseInt(h, 16));
    }
    return textToBytes(f.payload, 'utf8');
  }

  async function sendWs(t: Tab) {
    const body: RepeaterWsBody = {
      scheme: t.scheme, host: t.host.trim(), port: t.port, request: bytesToB64(requestBytes(t)),
      verify_tls: t.verifyTls, listen_ms: t.listenMs,
      frames: t.frames.map((f) => ({ opcode: f.opcode, fin: f.fin, rsv: f.rsv, mask: f.mask.trim() || 'random', payload: bytesToB64(frameBytes(f)) })),
    };
    const reply = await api.post<RepeaterWsReply>('/repeater/ws', body);
    const text = b64ToBytes(reply.response);
    t.history = [...t.history, { at: Date.now(), results: [], text: [bytesToText(text).text], ws: reply }].slice(-30);
    t.shown = t.history.length - 1;
  }

  /** Hand this tab's request to the Intruder, to mark positions in. */
  function toIntruder() {
    const t = tab;
    if (!t || t.kind !== 'http') return;
    stashForIntruder({ scheme: t.scheme, host: t.host.trim(), port: t.port, request: t.request });
    workspace.open('intruder');
  }

  async function send() {
    const t = tab;
    if (!t) return;
    error = '';
    busy = true;
    try {
      if (t.kind === 'ws') { await sendWs(t); return; }
      const body: RepeaterSendBody = {
        scheme: t.scheme, host: t.host.trim(), port: t.port, request: bytesToB64(requestBytes(t)),
        protocol: t.protocol, update_content_length: t.updateLength, verify_tls: t.verifyTls,
        follow_redirects: t.follow, count: t.count, mode: t.sendMode,
      };
      const reply = await api.post<RepeaterSendReply>('/repeater/send', body);
      t.history = [...t.history, { at: Date.now(), results: reply.results, text: reply.results.map(respText) }].slice(-30);
      t.shown = t.history.length - 1;
    } catch (e) { error = e instanceof Error ? e.message : String(e); } finally { busy = false; }
  }

  const sent = $derived(tab?.history[tab.shown] ?? null);
  const prev = $derived(tab && tab.shown > 0 ? tab.history[tab.shown - 1]! : null);
  const diff = $derived.by((): Op[] | null => {
    if (!showDiff || !sent || !prev) return null;
    return diffLines(prev.text[0] ?? '', sent.text[0] ?? '');
  });
  const changed = $derived(diff ? diff.filter((d) => d.kind !== 'same').length : 0);

  function summary(r: RepeaterSendResult): string {
    if (r.refused) return 'refused';
    return r.status ? String(r.status) : 'no response';
  }
  const ms = (r: RepeaterSendResult) => (r.timings ? `${r.timings.total_ms} ms` : '');
  // A race shows as differing answers: how many distinct (status, length) pairs a group produced.
  function distinct(s: Sent): number {
    return new Set(s.results.map((r) => `${r.status}:${r.response.length}`)).size;
  }
</script>

<div class="toolbar">
  <div class="seg tabs">
    {#each tabs as t (t.id)}
      <button class:active={t.id === active} onclick={() => (active = t.id)}>{t.host || 'new'}<span class="x" role="presentation" onclick={(e) => { e.stopPropagation(); closeTab(t.id); }}>×</span></button>
    {/each}
  </div>
  <button onclick={addTab}>+</button>
  <span class="spacer"></span>
  <label class="small" title="Off by default. Goes back off when a project is opened. Audited."><input type="checkbox" checked={allowOut} disabled={!canSend} onchange={toggleOut} /> Allow out-of-scope targets</label>
</div>
{#if error}<p class="error">{error}</p>{/if}
{#if saveFailed}<p class="error" role="status">The tabs could not be saved in the project.</p>{/if}

{#if tab}
  <div class="toolbar">
    <select bind:value={tab.kind} aria-label="Kind"><option value="http">HTTP</option><option value="ws">WebSocket</option></select>
    <select bind:value={tab.scheme} onchange={() => setScheme(tab!, tab!.scheme)} aria-label="Scheme"><option>http</option><option>https</option></select>
    <input class="grow mono" placeholder="host" bind:value={tab.host} aria-label="Host" />
    <input class="port mono" type="number" min="1" max="65535" bind:value={tab.port} aria-label="Port" />
    {#if tab.kind === 'http'}<select bind:value={tab.protocol} aria-label="Protocol"><option value="http1">HTTP/1.1</option><option value="h2">HTTP/2</option></select>{/if}
    {#if tab.kind === 'http'}<button disabled={!canSend || !tab.host.trim()} title="Mark positions in this request and attack them with payloads" onclick={toIntruder}>Send to Intruder</button>{/if}
    <button class="primary" disabled={!canSend || busy || !tab.host.trim()} onclick={send}>{busy ? 'Sending…' : 'Send'}</button>
  </div>
  {#if tab.kind === 'http'}
  <div class="toolbar small">
    <label><input type="checkbox" bind:checked={tab.updateLength} /> Update Content-Length</label>
    <label><input type="checkbox" bind:checked={tab.verifyTls} /> Verify certificate</label>
    <label><input type="checkbox" bind:checked={tab.follow} disabled={tab.protocol === 'h2'} /> Follow redirects</label>
    <span class="spacer"></span>
    <label>Send <input class="count" type="number" min="1" max="100" bind:value={tab.count} aria-label="Count" /> time(s)</label>
    <select bind:value={tab.sendMode} aria-label="Mode">
      <option value="sequential">one after another</option>
      <option value="parallel">all at once</option>
      <option value="single_packet" disabled={tab.protocol !== 'h2'}>single packet (HTTP/2)</option>
    </select>
  </div>
  {:else}
  <div class="toolbar small">
    <label><input type="checkbox" bind:checked={tab.verifyTls} /> Verify certificate</label>
    <span class="spacer"></span>
    <label>Listen <input class="count" type="number" min="0" max="10000" step="100" bind:value={tab.listenMs} aria-label="Listen time" /> ms after the last frame</label>
  </div>
  {/if}
  <div class="panes">
    <div class="pane">
      <div class="small muted pad">Request: sent as written. In the text view line endings become CRLF; the hex view is exact.</div>
      {#key tab.id}
        <MessageEditor text={tab.request} mode={tab.mode} label="Request" onchange={(t, m) => { const x = tab!; x.request = t; x.mode = m; }} />
      {/key}
      {#if tab.kind === 'ws'}
        <div class="frames">
          <div class="toolbar small"><b>Frames</b> <span class="muted">sent in order once the server answers 101</span><span class="spacer"></span><button onclick={addFrame}>Add frame</button></div>
          {#each tab.frames as f, i (i)}
            <div class="toolbar small frame">
              <select bind:value={f.opcode} aria-label="Frame {i + 1} type">
                {#each OPCODES as [n, name] (n)}<option value={n}>{name}</option>{/each}
              </select>
              <label><input type="checkbox" bind:checked={f.fin} /> FIN</label>
              <label>RSV <input class="count" type="number" min="0" max="7" bind:value={f.rsv} aria-label="Frame {i + 1} reserved bits" /></label>
              <label>mask <input class="mask mono" bind:value={f.mask} aria-label="Frame {i + 1} mask" title="random, none, or eight hex digits" /></label>
              <label><input type="checkbox" bind:checked={f.hex} /> hex</label>
              <input class="grow mono" placeholder={f.hex ? '48 65 6c 6c 6f' : 'payload'} bind:value={f.payload} aria-label="Frame {i + 1} payload" />
              <button class="ghost" aria-label="Remove frame {i + 1}" onclick={() => tab!.frames.splice(i, 1)}>×</button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
    <div class="pane">
      <div class="toolbar small">
        {#if tab.history.length}
          <button disabled={tab.shown === 0} onclick={() => tab && tab.shown--}>‹</button>
          <span>send {tab.shown + 1} of {tab.history.length}</span>
          <button disabled={tab.shown >= tab.history.length - 1} onclick={() => tab && tab.shown++}>›</button>
          {#if prev}<label><input type="checkbox" bind:checked={showDiff} /> Diff with previous{#if diff} ({changed} changed){/if}</label>{/if}
        {:else}<span class="muted">Nothing sent yet.</span>{/if}
      </div>
      {#if sent?.ws}
        {@const w = sent.ws}
        <div class="small pad">
          <b class:bad={w.status !== 101}>{w.refused ? 'refused' : (w.status ?? 'no response')}</b>
          {#if w.closed_by_server}· the server closed the connection{/if}
          {#if w.in_scope === false}· <span class="bad">out of scope</span>{/if}
          {#if w.flow_id}· <a href={`#history`}>flow {w.flow_id}</a>{/if}
        </div>
        {#if w.error}<p class="error">{w.error}</p>{/if}
        <div class="out wsframes" role="log" aria-label="WebSocket frames">
          {#each w.frames as f, i (i)}
            <div class="wsf" class:in={f.direction === 'server_to_client'}>
              <span class="dir">{f.direction === 'client_to_server' ? '→' : '←'}</span>
              <span class="op">{OPCODES.find((o) => o[0] === f.opcode)?.[1] ?? `opcode ${f.opcode}`}{f.fin ? '' : ' (more)'}{f.rsv ? ` rsv ${f.rsv}` : ''}{f.direction === 'client_to_server' && !f.masked ? ' unmasked' : ''}</span>
              <span class="pl mono">{bytesToText(b64ToBytes(f.payload)).text}</span>
            </div>
          {:else}<span class="muted">No frames.</span>{/each}
        </div>
        <pre class="code out hs">{sent.text[0] ?? ''}</pre>
      {:else if sent}
        {#if sent.results.length > 1}
          <div class="small pad" role="status">
            {sent.results.length} results, {distinct(sent)} different (status, size) pair{distinct(sent) === 1 ? '' : 's'}.
            {#each sent.results as r, i (i)}<span class="chip" class:bad={!r.status}>{r.index}{r.hop ? '.' + r.hop : ''}: {summary(r)}</span>{/each}
          </div>
        {/if}
        {#each sent.results.slice(0, 1) as r (r.index + ':' + r.hop)}
          <div class="small pad">
            <b class:bad={!r.status}>{summary(r)}</b> {ms(r)}
            {#if r.reused}· reused connection{/if}
            {#if r.tls}· {r.tls.version}{#if r.tls.alpn} {r.tls.alpn}{/if}{/if}
            {#if r.peer}· {r.peer}{/if}
            {#if r.in_scope === false}· <span class="bad">out of scope</span>{/if}
            {#if r.truncated}· <span class="bad">cut off at the size limit</span>{/if}
            {#if r.flow_id}· <a href={`#history`}>flow {r.flow_id}</a>{/if}
          </div>
          {#if r.error}<p class="error">{r.error}</p>{/if}
          {#if r.timings}
            <div class="small muted pad">dns {r.timings.dns_ms} · connect {r.timings.connect_ms}{#if r.timings.tls_ms != null} · tls {r.timings.tls_ms}{/if}{#if r.timings.first_byte_ms != null} · first byte {r.timings.first_byte_ms}{/if} · total {r.timings.total_ms} ms</div>
          {/if}
        {/each}
        {#if diff && prev}
          <div class="out diffbox"><DiffView a={prev.text[0] ?? ''} b={sent.text[0] ?? ''} label="Difference from the previous send" /></div>
        {:else}
          <pre class="code out">{sent.text[0] ?? ''}</pre>
        {/if}
      {/if}
    </div>
  </div>
{/if}

<style>
  .diffbox { display: flex; flex-direction: column; min-height: 8rem; max-height: 60vh; border-top: 1px solid var(--border-subtle); }
  .tabs button { display: inline-flex; gap: .4rem; align-items: center; }
  .x { opacity: .6; }
  .x:hover { opacity: 1; color: var(--bad); }
  .port { width: 5rem; }
  .mask { width: 8rem; }
  .frames { border-top: 1px solid var(--border-subtle); overflow: auto; max-height: 40%; }
  .frame { flex-wrap: nowrap; }
  .wsframes { flex: 1; min-height: 3rem; }
  .wsf { display: flex; gap: .5rem; padding: .1rem 0; white-space: pre-wrap; word-break: break-all; }
  .wsf.in .dir { color: var(--ok); }
  .dir { color: var(--info); }
  .op { color: var(--text-2); white-space: nowrap; }
  .hs { flex: 0 1 30%; border-top: 1px solid var(--border-subtle); }
  .count { width: 4rem; }
  .panes { flex: 1; display: grid; grid-template-columns: 1fr 1fr; min-height: 0; }
  .pane { display: flex; flex-direction: column; min-height: 0; min-width: 0; border-right: 1px solid var(--line); }
  .out { flex: 1; margin: 0; padding: .5rem; overflow: auto; white-space: pre-wrap; word-break: break-all; }
  .pad { padding: .25rem .5rem; }
  .chip { margin-left: .4rem; padding: 0 .35rem; border: 1px solid var(--line); border-radius: 8px; }
  .bad { color: var(--bad); }
</style>
