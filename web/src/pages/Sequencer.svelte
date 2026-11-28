<script lang="ts">
  // The Sequencer: how random are a set of tokens? Tokens are pasted (one per line) or captured live by sending a
  // request again and again (through the server, so the scope gate and the rate limit apply). The analysis is done
  // by the server (`/sequencer/analyze`); everything here is shown as text.
  import { onDestroy } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { bytesToB64, wireBytes } from '../lib/bytes';
  import { css } from '../lib/style';
  import type { components } from '../lib/api-types';

  type Analysis = components['schemas']['Analysis'];
  type Status = components['schemas']['CaptureStatus'];
  type Verdict = Analysis['verdict'];

  const canSend = $derived(session.can('tester'));
  const VERDICTS: Record<Verdict, string> = { excellent: 'Excellent', good: 'Good', poor: 'Poor', not_random: 'Not random' };
  const MIN_TOKENS = 20;

  let mode = $state<'live' | 'manual'>('live');
  let scheme = $state<'http' | 'https'>('http');
  let host = $state('');
  let port = $state(80);
  let request = $state('GET / HTTP/1.1\r\nHost: \r\n\r\n');
  let kind = $state<'header' | 'cookie' | 'regex'>('cookie');
  let where = $state('');
  let count = $state(200);
  let delay = $state(0);
  let tokensText = $state('');
  let error = $state('');
  let result = $state<Analysis | null>(null);
  let status = $state<Status | null>(null);
  let busy = $state(false);
  let captured = $state<string[]>([]);
  let timer: ReturnType<typeof setInterval> | undefined;

  const tokenList = () => tokensText.split(/\r?\n/).filter((l) => l.length > 0);
  const fail = (e: unknown) => { error = e instanceof Error ? e.message : String(e); };

  async function analyse(tokens: string[]) {
    error = '';
    busy = true;
    try {
      result = await api.post<Analysis>('/sequencer/analyze', { tokens });
    } catch (e) {
      result = null;
      fail(e);
    } finally {
      busy = false;
    }
  }

  function source() {
    return kind === 'header' ? { kind, name: where } : kind === 'cookie' ? { kind, name: where } : { kind, pattern: where };
  }

  async function poll(id: number) {
    try {
      const s = await api.get<Status>(`/sequencer/capture/${id}?from=${captured.length}`);
      captured = captured.concat(s.tokens);
      status = { ...s, tokens: [] };
      if (s.state !== 'running') {
        clearInterval(timer);
        timer = undefined;
        if (captured.length >= MIN_TOKENS) await analyse(captured);
        else if (s.state !== 'failed') error = `Only ${captured.length} tokens came back; ${MIN_TOKENS} are needed.`;
      }
    } catch (e) {
      clearInterval(timer);
      timer = undefined;
      fail(e);
    }
  }

  async function start() {
    error = '';
    result = null;
    captured = [];
    status = null;
    try {
      const { id } = await api.post<{ id: number }>('/sequencer/capture', {
        scheme, host, port, request: bytesToB64(wireBytes(request, 'utf8')), source: source(), count, delay_ms: delay,
      });
      status = { id, state: 'running', target: `${scheme}://${host}:${port}`, count, sent: 0, extracted: 0, missing: 0, errors: 0, last_error: null, tokens: [], from: 0 };
      timer = setInterval(() => void poll(id), 400);
    } catch (e) {
      fail(e);
    }
  }

  async function stop() {
    if (!status) return;
    try { await api.post(`/sequencer/capture/${status.id}/stop`); } catch (e) { fail(e); }
  }

  /** Move what was captured into the manual list, to keep, edit or analyse again. */
  function toManual() {
    tokensText = captured.join('\n');
    mode = 'manual';
  }

  function download() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'bosun-sequencer.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  onDestroy(() => clearInterval(timer));

  const running = $derived(status?.state === 'running');
  const bits = (n: number) => n.toFixed(1);
  const pct = (n: number, of: number) => `${of > 0 ? Math.min(100, (100 * n) / of) : 0}%`;
</script>

<div class="toolbar">
  <div class="seg" role="group" aria-label="Token source">
    <button class:active={mode === 'live'} onclick={() => (mode = 'live')}>Live capture</button>
    <button class:active={mode === 'manual'} onclick={() => (mode = 'manual')}>Manual load</button>
  </div>
  <span class="spacer"></span>
  {#if result}<button onclick={download}>Export JSON</button>{/if}
</div>
{#if error}<p class="error" role="alert">{error}</p>{/if}

<div class="body">
  {#if mode === 'live'}
    <div class="toolbar">
      <select bind:value={scheme} aria-label="Scheme" onchange={() => (port = scheme === 'https' ? 443 : 80)}>
        <option value="http">http</option><option value="https">https</option>
      </select>
      <input class="mono grow" placeholder="host" aria-label="Host" bind:value={host} />
      <input class="mono num" type="number" min="1" max="65535" aria-label="Port" bind:value={port} />
    </div>
    <textarea class="code req" spellcheck="false" aria-label="Request" bind:value={request}></textarea>
    <div class="toolbar">
      <select bind:value={kind} aria-label="Token location">
        <option value="cookie">Set-Cookie named</option>
        <option value="header">Response header</option>
        <option value="regex">Body regex (group 1)</option>
      </select>
      <input class="mono grow" aria-label="Name or pattern" placeholder={kind === 'regex' ? '"csrf":"([^"]+)"' : kind === 'header' ? 'X-Token' : 'sessionid'} bind:value={where} />
      <label class="small">Count <input class="num" type="number" min="1" max="5000" aria-label="Count" bind:value={count} /></label>
      <label class="small">Pause (ms) <input class="num" type="number" min="0" max="10000" aria-label="Pause" bind:value={delay} /></label>
      <button class="primary" disabled={!canSend || running || !host || !where} onclick={start}>Start capture</button>
      <button disabled={!running} onclick={stop}>Stop</button>
    </div>
    {#if status}
      <p class="small pad" role="status">
        {status.state === 'running' ? 'Capturing' : status.state === 'done' ? 'Done' : status.state === 'stopped' ? 'Stopped' : 'Failed'}:
        sent {status.sent} of {status.count}, {status.extracted} tokens{#if status.missing}, {status.missing} without a token{/if}{#if status.errors}, {status.errors} errors{/if}.
        {#if status.last_error}<span class="bad">{status.last_error}</span>{/if}
        {#if captured.length && !running}<button class="ghost" onclick={toManual}>Edit as list</button>{/if}
      </p>
    {:else}
      <p class="small muted pad">The request is sent again and again to the host (up to 5,000 times) and the token is taken from each response. Every request goes through the scope gate and is recorded in the history.</p>
    {/if}
  {:else}
    <textarea class="code req" spellcheck="false" aria-label="Tokens" placeholder="One token per line (at least {MIN_TOKENS})" bind:value={tokensText}></textarea>
    <div class="toolbar">
      <span class="small muted">{tokenList().length} tokens</span>
      <button class="primary" disabled={busy || tokenList().length < MIN_TOKENS} onclick={() => analyse(tokenList())}>Analyse</button>
    </div>
  {/if}

  {#if result}
    {@const r = result}
    <section class="result" aria-label="Result">
      <p class="verdict">
        <span class="badge v-{r.verdict}" data-verdict={r.verdict}>{VERDICTS[r.verdict]}</span>
        <b>{bits(r.entropy_bits)} effective bits</b>
        <span class="muted">of {bits(r.capacity_bits)} possible, {r.tokens} tokens ({r.unique} different), length {r.min_length === r.max_length ? r.min_length : `${r.min_length} to ${r.max_length}`}, {r.charset_size} characters</span>
      </p>
      {#if !r.reliable}<p class="small muted">Fewer than 100 tokens: treat the result as a hint.</p>{/if}
      <ul class="reasons">{#each r.reasons as why (why)}<li>{why}</li>{/each}</ul>

      <h4>FIPS 140-2</h4>
      {#if r.fips}
        <table class="grid" aria-label="FIPS 140-2">
          <thead><tr><th>Block</th><th>Monobit</th><th>Poker</th><th>Runs</th><th>Long run</th></tr></thead>
          <tbody>
            {#each r.fips.blocks as b, i (i)}
              <tr>
                <td>{i + 1}</td>
                {#each [b.monobit, b.poker, b.runs, b.long_run] as t, k (k)}
                  <td class:bad={!t.pass} title={t.limit}>{t.pass ? 'pass' : 'FAIL'} <span class="muted">{k === 1 ? t.value.toFixed(2) : t.value}</span></td>
                {/each}
              </tr>
            {/each}
          </tbody>
        </table>
        <p class="small muted">{r.fips.blocks_passed} of {r.fips.blocks.length} blocks of 20,000 bits passed.</p>
      {:else}
        <p class="small muted">{r.bit_stream_len} bits: 20,000 are needed. Use more or longer tokens.</p>
      {/if}

      <h4>Bit level</h4>
      <p class="small muted">{r.bit_positions} bit positions; {r.biased_bits} are off one half by more than chance allows.</p>

      <h4>Character level</h4>
      <table class="grid" aria-label="Positions">
        <thead><tr><th>Pos</th><th>Distinct</th><th>Top</th><th>Entropy</th><th></th></tr></thead>
        <tbody>
          {#each r.positions as p (p.position)}
            <tr>
              <td class="tnum">{p.position + 1}</td>
              <td class="tnum">{p.distinct}</td>
              <td class="mono">{JSON.stringify(p.top_char)} {Math.round(p.top_share * 100)}%</td>
              <td class="tnum">{bits(p.entropy_bits)}</td>
              <td class="barcell"><span class="bar" use:css={{ width: pct(p.entropy_bits, Math.max(1, Math.log2(Math.max(2, p.distinct)))) }}></span></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}
</div>

<style>
  .body { flex: 1; min-height: 0; overflow: auto; display: flex; flex-direction: column; }
  .req { min-height: 7rem; resize: vertical; border: 0; border-bottom: 1px solid var(--border-subtle); background: var(--surface-0); padding: .5rem; }
  .num { width: 6rem; }
  .result { padding: .5rem; }
  h4 { margin: .8rem 0 .3rem; }
  .verdict { display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; margin: 0 0 .4rem; }
  .v-excellent, .v-good { color: var(--ok); border-color: var(--ok); }
  .v-poor { color: var(--warn, var(--bad)); border-color: var(--warn, var(--bad)); }
  .v-not_random { color: var(--bad); border-color: var(--bad); }
  .bad { color: var(--bad); }
  .reasons { margin: .2rem 0; padding-left: 1.2rem; }
  .barcell { width: 40%; }
  .bar { display: block; height: .6rem; background: var(--accent); border-radius: 2px; }
</style>
