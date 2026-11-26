<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { session } from '../lib/session.svelte';

  interface Listener {
    id: number;
    primary: boolean;
    addr: string;
    invisible: boolean;
    tls_passthrough: string[];
    allow_clients: string[];
    max_connections?: number | null;
    auth_required: boolean;
    auth?: { username: string } | null;
    accepted: number;
  }
  interface Live {
    max_request_body: number;
    record_body_limit: number;
    max_buffered_response: number;
    record_out_of_scope: boolean;
    upstream_timeout_secs: number;
    header_timeout_secs: number;
    http2: boolean;
    max_connections: number;
  }

  let listeners = $state<Listener[]>([]);
  let live = $state<Live | null>(null);
  let restart = $state<string[]>([]);
  let error = $state('');
  let note = $state('');
  const admin = $derived(session.can('admin'));

  let form = $state({ addr: '127.0.0.1:8081', invisible: false, passthrough: '', allow: '', cap: '', user: '', password: '' });

  const lines = (s: string) => s.split(/[\s,]+/).filter(Boolean);

  async function load() {
    listeners = await api.get<Listener[]>('/proxy/listeners');
    const c = await api.get<{ live: Live; restart_required: string[] }>('/proxy/config');
    live = c.live;
    restart = c.restart_required;
  }

  async function run(f: () => Promise<unknown>, ok = '') {
    error = '';
    note = '';
    try {
      await f();
      note = ok;
      await load();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  const spec = (l: Pick<Listener, 'addr' | 'invisible' | 'tls_passthrough' | 'allow_clients' | 'max_connections'>, user = '', password = '') => ({
    addr: l.addr,
    invisible: l.invisible,
    tls_passthrough: l.tls_passthrough,
    allow_clients: l.allow_clients,
    max_connections: l.max_connections ?? null,
    auth: user ? { username: user, password } : null,
  });

  const add = () =>
    run(async () => {
      await api.post('/proxy/listeners', spec({ addr: form.addr, invisible: form.invisible, tls_passthrough: lines(form.passthrough), allow_clients: lines(form.allow), max_connections: form.cap ? Number(form.cap) : null }, form.user, form.password));
      form = { ...form, passthrough: '', allow: '', cap: '', user: '', password: '', invisible: false };
    }, 'Listener started.');
  const toggleInvisible = (l: Listener) =>
    run(() => api.put(`/proxy/listeners/${l.id}`, spec({ ...l, invisible: !l.invisible }, l.auth_required ? (l.auth?.username ?? '') : '', '')), 'Listener changed.');
  const remove = (l: Listener) => run(() => api.del(`/proxy/listeners/${l.id}`), 'Listener stopped.');
  const saveLive = () => run(async () => { if (live) await api.put('/proxy/config', live); }, 'Saved; in effect now.');

  onMount(() => { load().catch((e) => { error = e instanceof Error ? e.message : String(e); }); });
</script>

<div data-testid="listeners">
  <h3>Listeners</h3>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if note}<p class="ok">{note}</p>{/if}
  <table class="grid"><tbody>
    {#each listeners as l (l.id)}
      <tr data-testid="listener-row">
        <td><code>{l.addr}</code>{l.primary ? ' (configured)' : ''}</td>
        <td class="small muted">{l.auth_required ? 'auth' : 'no auth'}{l.invisible ? ', invisible' : ''}{l.tls_passthrough.length ? `, ${l.tls_passthrough.length} pass-through` : ''}{l.allow_clients.length ? `, only ${l.allow_clients.join(' ')}` : ''}{l.max_connections ? `, max ${l.max_connections} connections` : ''}</td>
        <td class="small muted">{l.accepted} connections</td>
        <td>
          {#if admin}
            <button onclick={() => toggleInvisible(l)}>{l.invisible ? 'Turn invisible off' : 'Turn invisible on'}</button>
            {#if !l.primary}<button onclick={() => remove(l)}>Stop</button>{/if}
          {/if}
        </td>
      </tr>
    {/each}
  </tbody></table>
  {#if admin}
    <form class="row" onsubmit={(e) => { e.preventDefault(); add(); }}>
      <input aria-label="Listener address" bind:value={form.addr} required />
      <input aria-label="Pass-through hosts" placeholder="pass-through hosts" bind:value={form.passthrough} />
      <input aria-label="Allowed client networks" placeholder="allowed networks (CIDR)" bind:value={form.allow} />
      <input type="number" min="1" aria-label="Listener connection cap" placeholder="max connections" bind:value={form.cap} />
      <input aria-label="Proxy user name" placeholder="user" bind:value={form.user} />
      <input type="password" aria-label="Proxy password" placeholder="password (12+)" bind:value={form.password} autocomplete="new-password" />
      <label class="small"><input type="checkbox" bind:checked={form.invisible} /> invisible</label>
      <button>Add listener</button>
    </form>
    <p class="small muted">A listener not on loopback needs credentials or allowed networks. Changes apply at once; no restart.</p>
  {/if}

  {#if live}
    <h3>Live settings</h3>
    <form class="row" onsubmit={(e) => { e.preventDefault(); saveLive(); }}>
      <label class="small">Max connections <input type="number" min="1" bind:value={live.max_connections} disabled={!admin} /></label>
      <label class="small">Upstream timeout (s) <input type="number" min="1" bind:value={live.upstream_timeout_secs} disabled={!admin} /></label>
      <label class="small">Header timeout (s) <input type="number" min="1" bind:value={live.header_timeout_secs} disabled={!admin} /></label>
      <label class="small"><input type="checkbox" bind:checked={live.http2} disabled={!admin} /> HTTP/2</label>
      <label class="small"><input type="checkbox" bind:checked={live.record_out_of_scope} disabled={!admin} /> record out-of-scope</label>
      {#if admin}<button>Save</button>{/if}
    </form>
    <p class="small muted">These need a restart (edit the config file): {restart.join(', ')}.</p>
  {/if}
</div>
