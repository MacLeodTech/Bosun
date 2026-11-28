<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';

  interface Status { enabled: boolean; enrolling: boolean; recovery_codes_left: number; required: boolean; setup_required: boolean }
  interface Enrolment { secret: string; otpauth_uri: string }

  /** `onchange` runs after the factor is turned on or off (the page refreshes what depends on it). */
  let { onchange = () => {}, forced = false }: { onchange?: () => void; forced?: boolean } = $props();

  let status = $state<Status | null>(null);
  let enrolment = $state<Enrolment | null>(null);
  let recovery = $state<string[]>([]);
  let code = $state('');
  let offCode = $state('');
  let error = $state('');
  let note = $state('');

  async function load() {
    status = await api.get<Status>('/auth/totp');
  }

  async function run(f: () => Promise<void>, ok = '') {
    error = '';
    note = '';
    try {
      await f();
      note = ok;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  const start = () =>
    run(async () => {
      enrolment = await api.post<Enrolment>('/auth/totp/enroll');
      await load();
    });
  const confirm = () =>
    run(async () => {
      const r = await api.post<{ recovery_codes: string[] }>('/auth/totp/confirm', { code: code.trim() });
      recovery = r.recovery_codes;
      enrolment = null;
      code = '';
      await load();
      // When setup is forced the page waits for "Continue", so the recovery codes are not hidden unread.
      if (!forced) onchange();
    }, 'Second factor is on.');
  const turnOff = () =>
    run(async () => {
      await api.post('/auth/totp/disable', { code: offCode.trim() });
      offCode = '';
      recovery = [];
      await load();
      onchange();
    }, 'Second factor is off.');
  const newCodes = () =>
    run(async () => {
      const r = await api.post<{ recovery_codes: string[] }>('/auth/totp/recovery-codes', { code: offCode.trim() });
      recovery = r.recovery_codes;
      offCode = '';
      await load();
    }, 'New recovery codes made; the old ones no longer work.');

  onMount(() => void load().catch((e) => (error = e instanceof Error ? e.message : String(e))));
</script>

<div class="totp">
  {#if error}<p class="error">{error}</p>{/if}
  {#if note}<p class="ok">{note}</p>{/if}
  {#if status}
    {#if status.enabled}
      <p>A second factor is <strong>on</strong>. Recovery codes left: {status.recovery_codes_left}.</p>
      <form class="row" onsubmit={(e) => { e.preventDefault(); turnOff(); }}>
        <input aria-label="Code to confirm" placeholder="current code" bind:value={offCode} autocomplete="one-time-code" required />
        <button>Turn off second factor</button>
        <button type="button" onclick={newCodes}>New recovery codes</button>
      </form>
    {:else if enrolment}
      <p class="small">Add this secret to an authenticator app (type it in, or use the URI), then enter the code it shows.</p>
      <p>Secret <code class="sel" data-testid="totp-secret">{enrolment.secret}</code></p>
      <p class="small muted">URI <code class="sel" data-testid="totp-uri">{enrolment.otpauth_uri}</code></p>
      <form class="row" onsubmit={(e) => { e.preventDefault(); confirm(); }}>
        <input aria-label="Authentication code" placeholder="6-digit code" bind:value={code} autocomplete="one-time-code" inputmode="numeric" required />
        <button class="primary">Confirm and turn on</button>
      </form>
    {:else}
      <p class="small muted">Ask for a code from an authenticator app after the password. Not asked for single sign-on or the desktop app's own sign-in.</p>
      <div class="row"><button class="primary" onclick={start}>Set up second factor</button></div>
    {/if}
    {#if recovery.length}
      <p class="ok">Recovery codes (shown once; each works once, in place of a code):</p>
      <ul class="recovery" aria-label="Recovery codes">
        {#each recovery as r (r)}<li><code class="sel">{r}</code></li>{/each}
      </ul>
      {#if forced}<button class="primary" onclick={onchange}>I have saved these codes: continue</button>{/if}
    {/if}
  {/if}
</div>

<style>
  .row { display: flex; gap: .5rem; align-items: center; margin: .5rem 0; flex-wrap: wrap; }
  .sel { user-select: all; }
  .recovery { columns: 2; max-width: 24rem; padding-left: 1.2rem; }
</style>
