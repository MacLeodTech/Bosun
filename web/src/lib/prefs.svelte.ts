// Small UI preferences that outlive a page switch and a reload (localStorage). Failures to read or write are ignored:
// a preference is never worth an error.

export type MessageViewMode = 'raw' | 'pretty' | 'headers' | 'hex' | 'render';
export type PaneRole = 'request' | 'response' | 'intercept';

const KEY = 'bosun.prefs.v1';
const modes: MessageViewMode[] = ['raw', 'pretty', 'headers', 'hex', 'render'];

interface Stored { view?: Partial<Record<PaneRole, MessageViewMode>>; wrap?: boolean; exportSecrets?: boolean }

function read(): Stored {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Stored;
    return typeof v === 'object' && v ? v : {};
  } catch {
    return {};
  }
}

class Prefs {
  private stored = read();
  /** Which view each kind of message pane shows (raw, pretty, headers, hex, render), so it stops resetting per flow. */
  view = $state<Record<PaneRole, MessageViewMode>>({
    request: pick(this.stored.view?.request),
    response: pick(this.stored.view?.response),
    intercept: pick(this.stored.view?.intercept),
  });
  /** Long lines wrap in the message viewer (very long bodies are shown unwrapped regardless). */
  wrap = $state(this.stored.wrap !== false);

  /** Copies and exports keep cookies and authorization values. Off unless the person asks (docs: WP-77). */
  exportSecrets = $state(this.stored.exportSecrets === true);

  setExportSecrets(on: boolean) {
    this.exportSecrets = on;
    this.save();
  }

  setView(role: PaneRole, mode: MessageViewMode) {
    this.view[role] = mode;
    this.save();
  }

  setWrap(on: boolean) {
    this.wrap = on;
    this.save();
  }

  private save() {
    try {
      localStorage.setItem(KEY, JSON.stringify({ view: { ...this.view }, wrap: this.wrap, exportSecrets: this.exportSecrets }));
    } catch {
      // Ignore.
    }
  }
}

function pick(v: unknown): MessageViewMode {
  return modes.includes(v as MessageViewMode) ? (v as MessageViewMode) : 'raw';
}

export const prefs = new Prefs();
