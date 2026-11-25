// One registry of things the user can do. The palette, the keyboard shortcuts, the context menus and the help overlay
// are all views onto it, so a new tool registers its commands once and appears in all of them.
//
// A command receives ids only (never message bodies): anything it needs it fetches from the API, where the scope gate,
// the audit log and the role checks apply. `when` is a convenience for hiding what cannot work; it is not the check.

import { historyView } from './historyView.svelte';
import { canonical, matches, parseKeys, type Key } from './shortcuts';

export interface Ctx {
  /** The selected flows (or the focused one). */
  flows: number[];
  focus: number | null;
}

export interface Command {
  id: string;
  title: string;
  /** Shown in the palette and the help overlay: "Panels", "Layout", "Request", ... */
  group: string;
  /** "Ctrl+K". Leave out for a command that is palette-only. */
  keys?: string;
  /** Fire the shortcut even while typing in a field. Off by default so ordinary typing is never hijacked. */
  anywhere?: boolean;
  when?: (c: Ctx) => boolean;
  run: (c: Ctx) => void | Promise<void>;
}

const RECENT_KEY = 'bosun.recent.v1';
const RECENT_MAX = 12;

function readRecent(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]');
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').slice(0, RECENT_MAX) : [];
  } catch {
    return [];
  }
}

export function currentCtx(): Ctx {
  return { flows: historyView.ids, focus: historyView.selectedId };
}

class Commands {
  private list = $state.raw<Command[]>([]);
  /** Ids of the commands used last, newest first. */
  recent = $state<string[]>(readRecent());
  private keyCache = new Map<string, Key | null>();

  get all(): Command[] {
    return this.list;
  }

  /** Add commands (replacing any with the same id). Returns a function that removes them again. */
  register(cmds: Command[]): () => void {
    const ids = new Set(cmds.map((c) => c.id));
    this.list = [...this.list.filter((c) => !ids.has(c.id)), ...cmds];
    return () => {
      this.list = this.list.filter((c) => !ids.has(c.id) || !cmds.includes(c));
    };
  }

  find(id: string): Command | undefined {
    return this.list.find((c) => c.id === id);
  }

  isEnabled(c: Command, ctx: Ctx): boolean {
    return !c.when || c.when(ctx);
  }

  enabled(ctx: Ctx): Command[] {
    return this.list.filter((c) => this.isEnabled(c, ctx));
  }

  async run(id: string, ctx: Ctx = currentCtx()): Promise<boolean> {
    const c = this.find(id);
    if (!c || !this.isEnabled(c, ctx)) return false;
    this.recent = [id, ...this.recent.filter((r) => r !== id)].slice(0, RECENT_MAX);
    try {
      localStorage.setItem(RECENT_KEY, JSON.stringify(this.recent));
    } catch {
      // A recent list is never worth an error.
    }
    await c.run(ctx);
    return true;
  }

  /** The enabled command whose shortcut this event is, if any. */
  forEvent(e: KeyboardEvent, ctx: Ctx, typing: boolean): Command | undefined {
    for (const c of this.list) {
      if (!c.keys || (typing && !c.anywhere) || !this.isEnabled(c, ctx)) continue;
      let k = this.keyCache.get(c.keys);
      if (k === undefined) {
        k = parseKeys(c.keys);
        this.keyCache.set(c.keys, k);
      }
      if (k && matches(e, k)) return c;
    }
    return undefined;
  }

  /** Every binding, for the conflict report. */
  bindings() {
    return this.list.filter((c) => c.keys).map((c) => ({ id: c.id, keys: c.keys! }));
  }

  canonicalKeys(c: Command): string {
    const k = c.keys ? parseKeys(c.keys) : null;
    return k ? canonical(k) : '';
  }
}

export const commands = new Commands();
