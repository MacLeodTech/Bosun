<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';
  import { fmtTime } from '../lib/bytes';
  import type { ApiToken, AuditEntry, Role, User } from '../lib/types';

  interface ProxyInfo { listen: string; http2: boolean; invisible: boolean; verify_upstream_tls: boolean; auth_required: boolean; tools_stopped: boolean; tls_passthrough: string[] }
  interface CaInfo { fingerprint_sha256: string; spki_sha256: string }

  let proxy = $state<ProxyInfo | null>(null);
  let ca = $state<CaInfo | null>(null);
  let tokens = $state<ApiToken[]>([]);
  let users = $state<User[]>([]);
  let audit = $state<AuditEntry[]>([]);
  let newToken = $state('');
  let shownToken = $state('');
  let note = $state('');
  let error = $state('');
  let pw = $state({ current: '', next: '' });
  let nu = $state<{ username: string; password: string; role: Role }>({ username: '', password: '', role: 'tester' });

  async function run(f: () => Promise<unknown>, ok = '') {
    error = '';
    note = '';
    try {
      await f();
      note = ok;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function load() {
    [proxy, ca, tokens] = await Promise.all([api.get<ProxyInfo>('/proxy'), api.get<CaInfo>('/ca'), api.get<ApiToken[]>('/tokens')]);
    if (session.can('admin')) [users, audit] = await Promise.all([api.get<User[]>('/users'), api.get<AuditEntry[]>('/audit')]);
  }

  const launch = () => run(async () => { await api.post('/browser/launch'); }, 'Browser started.');
  const stop = (stopped: boolean) => run(async () => { await api.put('/tools/stop', { stopped }); await load(); });
  const createToken = () =>
    run(async () => {
      const r = await api.post<{ token: string }>('/tokens', { name: newToken });
      shownToken = r.token;
      newToken = '';
      tokens = await api.get<ApiToken[]>('/tokens');
    });
  const deleteToken = (id: number) => run(async () => { await api.del(`/tokens/${id}`); tokens = await api.get<ApiToken[]>('/tokens'); });
  const changePw = () =>
    run(async () => {
      await api.post('/auth/password', { current: pw.current, new: pw.next });
      pw = { current: '', next: '' };
    }, 'Password changed. Other sessions were signed out.');
  const addUser = () =>
    run(async () => {
      await api.post('/users', nu);
      nu = { username: '', password: '', role: 'tester' };
      await load();
    }, 'User created.');
  const delUser = (id: number) => run(async () => { await api.del(`/users/${id}`); await load(); });

  onMount(load);
</script>

<div class="settings">
  {#if error}<p class="error">{error}</p>{/if}
  {#if note}<p class="ok">{note}</p>{/if}

  <section>
    <h2>Proxy</h2>
    {#if proxy}
      <p>Listening on <code>{proxy.listen}</code>{proxy.auth_required ? ' (authentication required)' : ''}. HTTP/2 {proxy.http2 ? 'on' : 'off'}; upstream TLS verification {proxy.verify_upstream_tls ? 'on' : 'off'}.</p>
      {#if session.can('tester')}
        <div class="row">
          <button class="primary" onclick={launch}>Open browser</button>
          <span class="small muted">Starts a Chromium with its own profile, already using this proxy and trusting this CA (only when the UI runs on loopback).</span>
        </div>
        <div class="row">
          {#if proxy.tools_stopped}
            <span class="badge bad">All tool traffic stopped</span><button onclick={() => stop(false)}>Resume</button>
          {:else}
            <button class="danger" onclick={() => stop(true)}>Stop all tool traffic</button>
          {/if}
        </div>
      {/if}
    {/if}
  </section>

  <section>
    <h2>Certificate authority</h2>
    {#if ca}
      <p class="small">SHA-256 <code>{ca.fingerprint_sha256}</code></p>
      <p><a href="/api/v1/ca/cert.pem" download>Download CA certificate (PEM)</a> or browse to <code>http://bosun/</code> through the proxy.</p>
      <p class="small muted">This CA is unique to this install. Install it only in a separate browser profile, never system-wide; anyone with the data key could impersonate any site to a device that trusts it.</p>
    {/if}
  </section>

  <section>
    <h2>API tokens</h2>
    <p class="small muted">For scripts and the CLI: send <code>Authorization: Bearer &lt;token&gt;</code>. A token has your role.</p>
    {#if shownToken}<p class="ok">New token (shown once): <code class="sel">{shownToken}</code></p>{/if}
    <table class="grid"><tbody>
      {#each tokens as t (t.id)}
        <tr><td>{t.name}</td><td class="small muted">created {new Date(t.created_ms).toLocaleString()}</td><td class="small muted">{t.last_used_ms ? 'used ' + new Date(t.last_used_ms).toLocaleString() : 'never used'}</td><td><button onclick={() => deleteToken(t.id)}>Revoke</button></td></tr>
      {/each}
    </tbody></table>
    <form class="row" onsubmit={(e) => { e.preventDefault(); createToken(); }}>
      <input placeholder="token name" bind:value={newToken} required maxlength="64" /><button>Create token</button>
    </form>
  </section>

  <section>
    <h2>Password</h2>
    <form class="row" onsubmit={(e) => { e.preventDefault(); changePw(); }}>
      <input type="password" placeholder="current" bind:value={pw.current} autocomplete="current-password" required />
      <input type="password" placeholder="new (12+ characters)" bind:value={pw.next} autocomplete="new-password" minlength="12" required />
      <button>Change</button>
    </form>
  </section>

  {#if session.can('admin')}
    <section>
      <h2>Users</h2>
      <table class="grid"><tbody>
        {#each users as u (u.id)}
          <tr><td>{u.username}</td><td>{u.role}</td><td>{#if u.id !== session.me?.user.id}<button onclick={() => delUser(u.id)}>Delete</button>{/if}</td></tr>
        {/each}
      </tbody></table>
      <form class="row" onsubmit={(e) => { e.preventDefault(); addUser(); }}>
        <input placeholder="username" bind:value={nu.username} required />
        <input type="password" placeholder="password (12+)" bind:value={nu.password} minlength="12" autocomplete="new-password" required />
        <select bind:value={nu.role}><option value="viewer">viewer</option><option value="tester">tester</option><option value="admin">admin</option></select>
        <button>Add user</button>
      </form>
    </section>
    <section>
      <h2>Audit log</h2>
      <div class="audit">
        <table class="grid small"><tbody>
          {#each audit as a (a.id)}
            <tr><td>{new Date(a.time_ms).toLocaleDateString()} {fmtTime(a.time_ms)}</td><td>{a.username ?? '-'}</td><td>{a.action}</td><td>{a.detail}</td><td class="muted">{a.remote ?? ''}</td></tr>
          {/each}
        </tbody></table>
      </div>
    </section>
  {/if}
</div>

<style>
  .settings { overflow: auto; padding: 1rem 1.5rem; flex: 1; max-width: 70rem; }
  section { margin-bottom: 1.5rem; }
  h2 { font-size: 1.05rem; color: var(--accent); margin: 0 0 .5rem; }
  .row { display: flex; gap: .5rem; align-items: center; margin: .5rem 0; flex-wrap: wrap; }
  .audit { max-height: 20rem; overflow: auto; }
  .sel { user-select: all; }
</style>
