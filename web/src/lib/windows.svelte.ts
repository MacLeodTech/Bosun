// Pop-out windows at run time: opening one, keeping the windows' selection in step, and bringing a pop-out's panels
// back to the main window when it closes. See popout.ts for what travels between windows (ids only).

import { historyView as v } from './historyView.svelte';
import { tabs } from './layout';
import { CHANNEL, idFromKey, newWindowId, parseMsg, popoutHash, windowKey, type Msg } from './popout';
import { toasts } from './toasts.svelte';
import { POPOUT_ID, seedWindow, takeWindow, workspace } from './workspace.svelte';
import { panelById } from './panels';

const HEARTBEAT_MS = 1000;
/** A pop-out that has been silent this long is treated as closed. */
const SILENT_MS = 4500;
const POLL_MS = 500;

/** This window's own id, so it can tell its messages from other windows'. */
const SELF = POPOUT_ID ?? newWindowId();

interface Known {
  ref: Window | null;
  lastSeen: number;
  /** The window has been told what is selected (done when it first says it is alive). */
  greeted: boolean;
}

class Windows {
  /** Pop-outs the main window knows about (opened by it, or found in storage at startup). */
  private known = new Map<string, Known>();
  private chan: BroadcastChannel | null = null;
  private applying = false;
  private lastSelect = '';

  get isPopout(): boolean {
    return POPOUT_ID !== null;
  }

  private send(m: Msg) {
    try {
      this.chan?.postMessage(m);
    } catch {
      // A closing page may not be able to post; the other side times out instead.
    }
  }

  /** Start sharing the selection, and (main window) watching pop-outs or (pop-out) saying it is alive. */
  start(): () => void {
    if (typeof BroadcastChannel === 'undefined') return () => {};
    this.chan = new BroadcastChannel(CHANNEL);
    this.chan.onmessage = (e) => {
      const m = parseMsg(e.data);
      if (m) this.receive(m);
    };
    const timers: ReturnType<typeof setInterval>[] = [];
    if (this.isPopout) {
      timers.push(setInterval(() => this.send({ type: 'alive', id: SELF }), HEARTBEAT_MS));
      this.send({ type: 'alive', id: SELF });
    } else {
      // Pop-outs left over from before this page loaded: give them a moment to say they are alive.
      for (let i = 0; i < localStorage.length; i++) {
        const id = idFromKey(localStorage.key(i) ?? '');
        if (id) this.known.set(id, { ref: null, lastSeen: Date.now(), greeted: false });
      }
      timers.push(setInterval(() => this.sweep(), POLL_MS));
    }
    return () => {
      timers.forEach(clearInterval);
      this.chan?.close();
      this.chan = null;
    };
  }

  // ---- selection

  /** Call from an effect that reads the selection: tells the other windows when it changes here. */
  broadcastSelection() {
    const m: Msg = { type: 'select', from: SELF, selected: [...v.selected], selectedId: v.selectedId, openId: v.openId };
    const sig = JSON.stringify([m.selected, m.selectedId, m.openId]);
    if (this.applying || sig === this.lastSelect) return;
    this.lastSelect = sig;
    this.send(m);
  }

  private receive(m: Msg) {
    if (m.type === 'select') {
      if (m.from === SELF) return;
      this.lastSelect = JSON.stringify([m.selected, m.selectedId, m.openId]);
      this.applying = true;
      v.selected = m.selected;
      v.selectedId = m.selectedId;
      v.openId = m.openId;
      queueMicrotask(() => (this.applying = false));
    } else if (!this.isPopout) {
      if (m.type === 'alive') {
        let k = this.known.get(m.id);
        if (!k && localStorage.getItem(windowKey(m.id))) {
          k = { ref: null, lastSeen: Date.now(), greeted: false };
          this.known.set(m.id, k);
        }
        if (k) {
          k.lastSeen = Date.now();
          if (!k.greeted) {
            // A window that has just opened knows nothing yet: tell it what is selected here.
            k.greeted = true;
            this.send({ type: 'select', from: SELF, selected: [...v.selected], selectedId: v.selectedId, openId: v.openId });
          }
        }
      } else if (m.type === 'return') this.absorb(m.id);
    }
  }

  // ---- main window: opening, watching, taking back

  /** Move a tab into a window of its own. */
  popOut(tabId: string) {
    const root = workspace.root;
    if (this.isPopout || !root) return;
    const tab = tabs(root).find((t) => t.id === tabId);
    if (!tab) return;
    const id = newWindowId();
    if (!seedWindow(id, tab.panel)) {
      toasts.push({ text: 'Could not store the new window’s layout.' });
      return;
    }
    const url = `${location.pathname}${popoutHash(id)}`;
    const ref = window.open(url, `bosun-${id}`, 'popup=yes,width=1100,height=760');
    if (!ref) {
      // Blocked by the browser, or not allowed by the host (the desktop app has no pop-out windows).
      takeWindow(id);
      toasts.push({ text: 'A new window could not be opened. The browser may have blocked it, and the desktop app does not support pop-out windows.', ms: 8000 });
      return;
    }
    workspace.close(tabId);
    this.known.set(id, { ref, lastSeen: Date.now(), greeted: false });
    toasts.push({ text: `${panelById(tab.panel)?.title ?? tab.panel} moved to a new window.` });
  }

  /** A pop-out is gone or has handed its panels back: reopen them here. */
  private absorb(id: string) {
    this.known.delete(id);
    const panels = takeWindow(id);
    for (const p of panels) if (!workspace.isOpen(p)) workspace.open(p);
    if (panels.length) toasts.push({ text: 'A pop-out window was closed; its panels are back here.' });
  }

  private sweep() {
    const now = Date.now();
    for (const [id, k] of this.known) {
      const closed = k.ref ? k.ref.closed : now - k.lastSeen > SILENT_MS;
      const silent = now - k.lastSeen > SILENT_MS * 2;
      if (closed || silent) this.absorb(id);
    }
  }

  // ---- pop-out window: handing back

  /** Pop-out: tell the main window to take these panels back, then close. */
  returnToMain() {
    if (!this.isPopout) return;
    workspace.flush();
    this.send({ type: 'return', id: SELF });
    // If no main window answers (it was closed), the layout is simply left; closing is still right.
    setTimeout(() => window.close(), 150);
  }
}

export const windows = new Windows();
