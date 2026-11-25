<script lang="ts">
  import { api, login, setup } from '../lib/api';
  import { session } from '../lib/session.svelte';

  // The setup code may arrive in the URL fragment (never sent to the server); take it and clear it.
  const fromHash = new URLSearchParams(location.hash.slice(1)).get('setup') ?? '';
  if (fromHash) history.replaceState(null, '', location.pathname);

  let code = $state(fromHash);
  let username = $state('');
  let password = $state('');
  let confirm = $state('');
  let error = $state('');
  let busy = $state(false);
  // Single sign-on: offered when the server has it configured. With Edge SSO the first click goes through the
  // sign-in proxy; if that was refused (sso_error), the button falls back to the provider's own sign-in.
  let sso = $state<{ name: string; login: string; edge: string | null } | null>(null);
  const ssoError = new URLSearchParams(location.search).get('sso_error') ?? '';
  if (ssoError) {
    error = ssoError;
    history.replaceState(null, '', location.pathname);
  }
  api.get<{ sso: { name: string; login: string; edge: string | null } | null }>('/auth/sso').then((r) => (sso = r.sso)).catch(() => {});

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (session.setupRequired && password !== confirm) {
      error = 'The passwords do not match.';
      return;
    }
    busy = true;
    try {
      const me = session.setupRequired ? await setup(code.trim(), username, password) : await login(username, password);
      session.signedIn(me);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
      password = '';
      confirm = '';
    }
  }
</script>

<div class="auth">
  <form onsubmit={submit}>
    <h1><img src="/branding.jpg" alt="Bosun: fast web security proxy and scanner" /></h1>
    {#if session.setupRequired}
      <p class="muted">First run: create the admin account. The setup code is printed by <code>bosun serve</code>.</p>
      <label>Setup code <input bind:value={code} autocomplete="off" required /></label>
    {/if}
    <label>Username <input bind:value={username} autocomplete="username" required /></label>
    <label>Password
      <input type="password" bind:value={password} autocomplete={session.setupRequired ? 'new-password' : 'current-password'} required minlength={session.setupRequired ? 12 : 1} />
    </label>
    {#if session.setupRequired}
      <label>Confirm password <input type="password" bind:value={confirm} autocomplete="new-password" required /></label>
      <p class="small muted">At least 12 characters.</p>
    {/if}
    {#if error}<p class="error">{error}</p>{/if}
    <button class="primary" disabled={busy}>{session.setupRequired ? 'Create admin' : 'Sign in'}</button>
    {#if sso && !session.setupRequired}
      <a class="sso" href={sso.edge && !ssoError ? sso.edge : sso.login}>
        {sso.edge && !ssoError ? 'Continue with Edge SSO' : `Sign in with ${sso.name}`}
      </a>
    {/if}
  </form>
</div>

<style>
  .auth { display: grid; place-items: center; height: 100vh; }
  form { display: flex; flex-direction: column; gap: .7rem; width: 22rem; padding: 2rem; background: var(--bg2); border: 1px solid var(--line); border-radius: 8px; }
  h1 { margin: 0 0 .5rem; line-height: 0; }
  h1 img { width: 100%; height: auto; border-radius: 6px; }
  .sso { text-align: center; padding: .5rem; border: 1px solid var(--line); border-radius: 6px; }
  label { display: flex; flex-direction: column; gap: .25rem; }
</style>
