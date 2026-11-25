// The dock's state: which panels are open and how they are arranged. The tree and every operation on it live in
// layout.ts (pure and tested); this class holds the current tree, remembers it, and keeps the presets.
//
// Stored in localStorage under `bosun.workspace.v1`, per browser profile. Anything read back goes through
// `validate`, and a layout that fails it is replaced by Triage rather than trusted.

import {
  activate, addTab, findGroup, group, groupOfTab, groups, moveTab, moveTabDirection, newId, removeTab, setSizes, split, tab, tabs, validate,
  type Dir, type Node, type Zone,
} from './layout';
import { isPanelId } from './panelids';

const KEY = 'bosun.workspace.v1';

export type BuiltinPreset = 'triage' | 'intercept' | 'focus';
export const builtinPresets: { id: BuiltinPreset; label: string; hint: string }[] = [
  { id: 'triage', label: 'Triage', hint: 'History on the left, the open request on the right' },
  { id: 'intercept', label: 'Intercept', hint: 'The intercept queue on top, History below' },
  { id: 'focus', label: 'Focus', hint: 'Everything open in one tabbed pane' },
];

function builtin(id: BuiltinPreset, open: string[] = []): Node {
  switch (id) {
    case 'triage':
      return split('row', [group([tab('history')]), group([tab('flow')])], [0.5, 0.5]);
    case 'intercept':
      return split('col', [group([tab('intercept')]), split('row', [group([tab('history')]), group([tab('flow')])], [0.5, 0.5])], [0.6, 0.4]);
    case 'focus': {
      const ids = open.length ? open : ['history'];
      return group(ids.map((p) => tab(p)));
    }
  }
}

/** A copy of a layout with fresh node ids, so applying a preset never shares ids with the live tree. */
function reid(n: Node): Node {
  return n.kind === 'group'
    ? { ...n, id: newId('g'), tabs: n.tabs.map((t) => ({ ...t })) }
    : { ...n, id: newId('s'), sizes: [...n.sizes], children: n.children.map(reid) };
}

class Workspace {
  /** null when every panel is closed. */
  root = $state.raw<Node | null>(null);
  /** The group the user last worked in: where a newly opened panel goes. */
  focused = $state('');
  /** A group shown over the whole dock (the others stay mounted underneath). */
  maximized = $state<string | null>(null);
  /** Layouts the user saved, by name. */
  presets = $state.raw<Record<string, Node>>({});
  /** Set when a stored layout was rejected, so the shell can say so. */
  notice = $state('');
  /** Name of the preset applied last, if the layout has not been changed since. */
  applied = $state('');

  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor() {
    this.load();
    // The save is debounced while a divider is dragged; make sure a pending one is not lost on reload or close.
    window.addEventListener('pagehide', () => this.flush());
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') this.flush();
    });
  }

  // ---- reading

  /** Whether a panel has a tab, and whether that tab is the visible one in its group. */
  isOpen(panel: string): boolean {
    return !!this.root && tabs(this.root).some((t) => t.panel === panel);
  }
  isActive(panel: string): boolean {
    return !!this.root && groups(this.root).some((g) => g.tabs.some((t) => t.panel === panel && g.active === t.id));
  }

  // ---- persistence

  private load() {
    let ok = false;
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) {
        const data = JSON.parse(raw);
        const root = data?.version === 1 ? validate(data.root, isPanelId) : null;
        if (root) {
          this.root = root;
          ok = true;
        } else {
          this.notice = 'The saved layout was not valid, so the default layout is shown.';
          console.warn('bosun: discarded an invalid saved layout');
        }
        const presets: Record<string, Node> = {};
        if (data && typeof data.presets === 'object' && data.presets !== null) {
          for (const [name, p] of Object.entries(data.presets as Record<string, unknown>)) {
            const v = validate(p, isPanelId);
            if (v && name.length <= 60) presets[name] = v;
          }
        }
        this.presets = presets;
      }
    } catch {
      // Unreadable storage: start from the default.
    }
    if (!ok) this.root = builtin('triage');
    this.focused = (this.root && groups(this.root)[0]?.id) || '';
  }

  private save() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.flush(), 150);
  }

  private flush() {
    if (this.timer === undefined) return;
    clearTimeout(this.timer);
    this.timer = undefined;
    try {
      localStorage.setItem(KEY, JSON.stringify({ version: 1, root: this.root, presets: this.presets }));
    } catch {
      // Storage may be full or blocked; the layout then lasts until reload.
    }
  }

  private set(root: Node | null, keepApplied = false) {
    this.root = root;
    if (!keepApplied) this.applied = '';
    if (this.maximized && (!root || !findGroup(root, this.maximized))) this.maximized = null;
    if (root && !findGroup(root, this.focused)) this.focused = groups(root)[0]?.id ?? '';
    this.save();
  }

  // ---- panels

  focus(groupId: string) {
    this.focused = groupId;
  }

  /** Show a panel: bring its tab forward if it is open, otherwise add a tab to the focused group. */
  open(panel: string) {
    if (!isPanelId(panel)) return;
    const root = this.root;
    if (!root) {
      const g = group([tab(panel)]);
      this.set(g);
      this.focused = g.id;
      return;
    }
    const existing = tabs(root).find((t) => t.panel === panel);
    if (existing) {
      this.set(activate(root, existing.id), true);
      this.focused = groupOfTab(root, existing.id)?.id ?? this.focused;
      return;
    }
    this.set(addTab(root, tab(panel), this.focused));
  }

  /**
   * Make sure `panel` is on screen without covering `beside`: if it is closed it opens as a split to the right of
   * `beside`, and if it is a hidden tab in the same group as `beside` it is left alone.
   */
  reveal(panel: string, beside: string) {
    const root = this.root;
    if (!root || !isPanelId(panel)) return;
    const mine = tabs(root).find((t) => t.panel === panel);
    const anchor = tabs(root).find((t) => t.panel === beside);
    if (mine) {
      const gm = groupOfTab(root, mine.id);
      if (gm && anchor && groupOfTab(root, anchor.id)?.id === gm.id) return;
      this.set(activate(root, mine.id), true);
      return;
    }
    if (!anchor) return this.open(panel);
    const g = groupOfTab(root, anchor.id)!;
    this.set(moveTab(addTab(root, tab(panel), g.id), panel, g.id, 'right'));
  }

  close(tabId: string) {
    if (!this.root) return;
    this.set(removeTab(this.root, tabId));
  }

  select(tabId: string) {
    if (!this.root) return;
    this.set(activate(this.root, tabId), true);
    const g = groupOfTab(this.root, tabId);
    if (g) this.focused = g.id;
  }

  move(tabId: string, groupId: string | null, zone: Zone, index?: number) {
    if (!this.root) return;
    const next = moveTab(this.root, tabId, groupId, zone, index);
    if (next === this.root) return;
    this.set(next);
    const g = groupOfTab(next, tabId);
    if (g) this.focused = g.id;
  }

  moveDirection(tabId: string, dir: Dir) {
    if (!this.root) return;
    const next = moveTabDirection(this.root, tabId, dir);
    if (next === this.root) return;
    this.set(next);
    const g = groupOfTab(next, tabId);
    if (g) this.focused = g.id;
  }

  resize(splitId: string, sizes: number[]) {
    if (!this.root) return;
    this.set(setSizes(this.root, splitId, sizes), true);
  }

  toggleMaximize(groupId: string) {
    this.maximized = this.maximized === groupId ? null : groupId;
  }

  // ---- presets

  apply(id: BuiltinPreset) {
    const open = this.root ? tabs(this.root).map((t) => t.panel) : [];
    this.set(reid(builtin(id, open)));
    this.applied = id;
  }

  applyUser(name: string) {
    const p = this.presets[name];
    if (!p) return;
    this.set(reid(p));
    this.applied = name;
  }

  reset() {
    this.set(reid(builtin('triage')));
    this.applied = 'triage';
    this.notice = '';
  }

  saveAs(name: string): boolean {
    const n = name.trim();
    if (!n || n.length > 60 || !this.root) return false;
    this.presets = { ...this.presets, [n]: reid(this.root) };
    this.applied = n;
    this.save();
    return true;
  }

  rename(from: string, to: string): boolean {
    const n = to.trim();
    if (!n || n.length > 60 || !this.presets[from] || (n !== from && this.presets[n])) return false;
    const next: Record<string, Node> = {};
    for (const [k, v] of Object.entries(this.presets)) next[k === from ? n : k] = v;
    this.presets = next;
    this.save();
    return true;
  }

  remove(name: string) {
    const { [name]: _gone, ...rest } = this.presets;
    this.presets = rest;
    this.save();
  }

  /** The user's presets as JSON, to copy or download. */
  exportJson(): string {
    return JSON.stringify({ version: 1, presets: this.presets }, null, 2);
  }

  /** Add presets from JSON made by `exportJson`. Returns how many were added, or an error message. */
  importJson(text: string): { added: number } | { error: string } {
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      return { error: 'That is not valid JSON.' };
    }
    const src = (data as { version?: unknown; presets?: unknown } | null);
    if (!src || src.version !== 1 || typeof src.presets !== 'object' || src.presets === null) return { error: 'That is not a Bosun layout file.' };
    const next = { ...this.presets };
    let added = 0;
    for (const [name, p] of Object.entries(src.presets as Record<string, unknown>)) {
      const v = validate(p, isPanelId);
      if (v && name.trim() && name.length <= 60) {
        next[name.trim()] = reid(v);
        added++;
      }
    }
    if (!added) return { error: 'No valid layouts were found in that file.' };
    this.presets = next;
    this.save();
    return { added };
  }
}

export const workspace = new Workspace();
