import { api, onUnauthorizedDo, setCsrf } from './api';
import type { Me, ProxyEvent, Role } from './types';

const rank: Record<Role, number> = { viewer: 0, tester: 1, admin: 2 };

class Session {
  me = $state<Me | null>(null);
  ready = $state(false);
  setupRequired = $state(false);
  connected = $state(false);
  private ws: WebSocket | null = null;
  private listeners = new Set<(e: ProxyEvent) => void>();
  private retry = 0;
  /** Where the event stream stood when we last heard from it, so a reconnect can ask for what it missed. */
  private epoch: string | null = null;
  private seq = 0;

  async init() {
    onUnauthorizedDo(() => this.clear());
    try {
      const st = await api.get<{ setup_required: boolean }>('/status');
      this.setupRequired = st.setup_required;
      if (!st.setup_required) {
        const me = await api.get<Me>('/auth/me');
        this.signedIn(me);
      }
    } catch {
      // Not signed in.
    } finally {
      this.ready = true;
    }
  }

  signedIn(me: Me) {
    setCsrf(me.csrf);
    this.me = me;
    this.setupRequired = false;
    this.connect();
  }

  clear() {
    this.me = null;
    setCsrf(null);
    this.ws?.close();
    this.ws = null;
  }

  async logout() {
    try {
      await api.post('/auth/logout');
    } finally {
      this.clear();
    }
  }

  can(role: Role): boolean {
    return !!this.me && rank[this.me.user.role] >= rank[role];
  }

  on(f: (e: ProxyEvent) => void): () => void {
    this.listeners.add(f);
    return () => this.listeners.delete(f);
  }

  private connect() {
    if (this.ws || !this.me) return;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const resume = this.epoch ? `?since=${this.seq}&epoch=${this.epoch}` : '';
    const ws = new WebSocket(`${proto}//${location.host}/api/v1/events${resume}`);
    this.ws = ws;
    ws.onopen = () => {
      this.connected = true;
      this.retry = 0;
    };
    ws.onmessage = (m) => {
      let e: ProxyEvent;
      try {
        e = JSON.parse(String(m.data)) as ProxyEvent;
      } catch {
        return;
      }
      const seq = (e as { seq?: unknown }).seq;
      if (typeof seq === 'number') this.seq = seq;
      if (e.type === 'hello') {
        // Another run of the engine: what we hold may be stale.
        const stale = this.epoch !== null && this.epoch !== e.epoch;
        this.epoch = e.epoch;
        this.seq = e.seq;
        if (stale) for (const l of this.listeners) l({ type: 'reload' });
      }
      for (const l of this.listeners) l(e);
      // Another project is open: what pages hold is from the old one, so they fetch it all again.
      if (e.type === 'project_switched') for (const l of this.listeners) l({ type: 'reload' });
    };
    ws.onclose = () => {
      this.connected = false;
      if (this.ws === ws) this.ws = null;
      if (this.me) {
        this.retry = Math.min(this.retry + 1, 6);
        setTimeout(() => this.connect(), 500 * 2 ** this.retry);
      }
    };
  }
}

export const session = new Session();
