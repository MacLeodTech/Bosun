// The dock layout as plain data, and every operation on it as a pure function. No Svelte and no DOM in here, so
// it can be tested on its own (web/tests/layout.test.ts) and a bad stored layout can never reach the renderer
// without passing `validate`.
//
// Invariants that hold after `normalize` (and so after every operation here):
//   - a group has at least one tab and `active` names one of them;
//   - a split has at least two children, and `sizes` has one positive entry per child, summing to 1;
//   - a split never has a child split with the same direction (those are merged);
//   - tab ids and group ids are unique across the tree.

export interface Tab { id: string; panel: string }
export interface Group { kind: 'group'; id: string; active: string; tabs: Tab[] }
export interface Split { kind: 'split'; id: string; dir: 'row' | 'col'; sizes: number[]; children: Node[] }
export type Node = Group | Split;

/** Where a dragged tab lands on a group: as a tab in it, or beside it as a new split. */
export type Zone = 'center' | 'left' | 'right' | 'top' | 'bottom';
export type Dir = 'left' | 'right' | 'up' | 'down';

/** The smallest share of a split a child may be resized to. */
export const MIN_SIZE = 0.06;
const MAX_DEPTH = 12;
const MAX_TABS = 64;

let counter = 0;
export function newId(prefix: string): string {
  counter++;
  return `${prefix}${Date.now().toString(36)}${counter.toString(36)}${Math.floor(Math.random() * 1296).toString(36)}`;
}

export function group(tabs: Tab[], active?: string): Group {
  return { kind: 'group', id: newId('g'), active: active ?? tabs[0]!.id, tabs };
}
export function split(dir: 'row' | 'col', children: Node[], sizes?: number[]): Split {
  return { kind: 'split', id: newId('s'), dir, sizes: sizes ?? children.map(() => 1 / children.length), children };
}
export const tab = (panel: string, id: string = panel): Tab => ({ id, panel });

// ---------------------------------------------------------------------------------------------------------------
// Queries

export function groups(n: Node): Group[] {
  return n.kind === 'group' ? [n] : n.children.flatMap(groups);
}
export function tabs(n: Node): Tab[] {
  return groups(n).flatMap((g) => g.tabs);
}
export function findGroup(n: Node, id: string): Group | undefined {
  return groups(n).find((g) => g.id === id);
}
export function groupOfTab(n: Node, tabId: string): Group | undefined {
  return groups(n).find((g) => g.tabs.some((t) => t.id === tabId));
}
export function findSplit(n: Node, id: string): Split | undefined {
  if (n.kind === 'group') return undefined;
  if (n.id === id) return n;
  for (const c of n.children) {
    const r = findSplit(c, id);
    if (r) return r;
  }
  return undefined;
}

// ---------------------------------------------------------------------------------------------------------------
// Normalising

function sizesFor(count: number, sizes: number[]): number[] {
  const ok = sizes.length === count && sizes.every((s) => Number.isFinite(s) && s > 0);
  const raw = ok ? sizes : Array.from({ length: count }, () => 1);
  const total = raw.reduce((a, b) => a + b, 0);
  return raw.map((s) => s / total);
}

/** Drop empty groups, collapse one-child splits, merge same-direction nesting and renormalise sizes. */
export function normalize(n: Node): Node | null {
  if (n.kind === 'group') {
    if (n.tabs.length === 0) return null;
    return n.tabs.some((t) => t.id === n.active) ? n : { ...n, active: n.tabs[0]!.id };
  }
  const kids: { node: Node; size: number }[] = [];
  n.children.forEach((c, i) => {
    const m = normalize(c);
    if (!m) return;
    const size = n.sizes[i] ?? 1 / n.children.length;
    if (m.kind === 'split' && m.dir === n.dir) {
      // Same direction as the parent: its children join the parent, sharing the space it had.
      m.children.forEach((g, j) => kids.push({ node: g, size: size * m.sizes[j]! }));
    } else {
      kids.push({ node: m, size });
    }
  });
  if (kids.length === 0) return null;
  if (kids.length === 1) return kids[0]!.node;
  return { ...n, children: kids.map((k) => k.node), sizes: sizesFor(kids.length, kids.map((k) => k.size)) };
}

function mapNode(n: Node, f: (g: Group) => Group): Node {
  if (n.kind === 'group') return f(n);
  return { ...n, children: n.children.map((c) => mapNode(c, f)) };
}

// ---------------------------------------------------------------------------------------------------------------
// Operations. Each returns a new tree (or the same one when there is nothing to do) and never mutates its input.

export function activate(root: Node, tabId: string): Node {
  return mapNode(root, (g) => (g.tabs.some((t) => t.id === tabId) && g.active !== tabId ? { ...g, active: tabId } : g));
}

/** Add a tab to a group (the first one if `groupId` is absent or unknown) and make it the active tab. */
export function addTab(root: Node, t: Tab, groupId?: string): Node {
  const target = (groupId && findGroup(root, groupId)) || groups(root)[0];
  if (!target) return group([t]);
  return mapNode(root, (g) => (g.id === target.id ? { ...g, tabs: [...g.tabs, t], active: t.id } : g));
}

export function removeTab(root: Node, tabId: string): Node | null {
  const next = mapNode(root, (g) => {
    if (!g.tabs.some((t) => t.id === tabId)) return g;
    const rest = g.tabs.filter((t) => t.id !== tabId);
    // Closing the active tab activates its neighbour, as every tabbed UI does.
    const at = g.tabs.findIndex((t) => t.id === tabId);
    const active = g.active === tabId ? (rest[Math.min(at, rest.length - 1)]?.id ?? '') : g.active;
    return { ...g, tabs: rest, active };
  });
  return normalize(next);
}

function splitAround(target: Node, moving: Tab, zone: Exclude<Zone, 'center'>): Split {
  const fresh = group([moving]);
  const first = zone === 'left' || zone === 'top';
  const dir = zone === 'left' || zone === 'right' ? 'row' : 'col';
  return split(dir, first ? [fresh, target] : [target, fresh], [0.5, 0.5]);
}

function replaceGroup(n: Node, id: string, f: (g: Group) => Node): Node {
  if (n.kind === 'group') return n.id === id ? f(n) : n;
  return { ...n, children: n.children.map((c) => replaceGroup(c, id, f)) };
}

/**
 * Move a tab. `groupId` is the target group; `null` targets the whole window, so an edge zone makes a full-width or
 * full-height split at the root. `index` places a `center` drop among the target's tabs.
 */
export function moveTab(root: Node, tabId: string, groupId: string | null, zone: Zone, index?: number): Node {
  const src = groupOfTab(root, tabId);
  const moving = src?.tabs.find((t) => t.id === tabId);
  if (!src || !moving) return root;
  if (groupId === null && zone === 'center') return root;
  if (tabs(root).length === 1) return root;
  const target = groupId === null ? undefined : findGroup(root, groupId);
  if (groupId !== null && !target) return root;
  // A lone tab dropped on the edge of its own group has nowhere to go.
  if (target && target.id === src.id && zone !== 'center' && src.tabs.length === 1) return root;

  // Take the tab out first, but leave its (possibly now empty) group in place so the target still exists.
  const without = mapNode(root, (g) => {
    if (g.id !== src.id) return g;
    const rest = g.tabs.filter((t) => t.id !== tabId);
    return { ...g, tabs: rest, active: g.active === tabId ? (rest[0]?.id ?? '') : g.active };
  });

  let placed: Node;
  if (groupId === null) {
    if (zone === 'center') return root;
    const base = normalize(without) ?? group([]);
    placed = splitAround(base, moving, zone);
  } else if (zone === 'center') {
    placed = replaceGroup(without, groupId, (g) => {
      // `index` counts positions in the tab list as it was before the removal above.
      const oldAt = src.id === g.id ? src.tabs.findIndex((t) => t.id === tabId) : -1;
      const want = index ?? g.tabs.length + (oldAt >= 0 ? 1 : 0);
      const slot = Math.max(0, Math.min(oldAt >= 0 && oldAt < want ? want - 1 : want, g.tabs.length));
      const ts = [...g.tabs.slice(0, slot), moving, ...g.tabs.slice(slot)];
      return { ...g, tabs: ts, active: moving.id };
    });
  } else {
    placed = replaceGroup(without, groupId, (g) => splitAround(g, moving, zone as Exclude<Zone, 'center'>));
  }
  return normalize(placed) ?? root;
}

/** Set the sizes of one split from a drag or key press. Sizes are clamped to MIN_SIZE and renormalised. */
export function setSizes(root: Node, splitId: string, sizes: number[]): Node {
  const s = findSplit(root, splitId);
  if (!s || sizes.length !== s.sizes.length) return root;
  const out = sizesFor(sizes.length, sizes.map((v) => Math.max(MIN_SIZE, v)));
  const rec = (n: Node): Node => (n.kind === 'group' ? n : n.id === splitId ? { ...n, sizes: out } : { ...n, children: n.children.map(rec) });
  return rec(root);
}

/** Move the divider after child `i` by `delta` (a fraction of the split), taking space from the neighbour. */
export function nudge(sizes: number[], i: number, delta: number): number[] {
  const out = [...sizes];
  const a = out[i];
  const b = out[i + 1];
  if (a === undefined || b === undefined) return out;
  const d = Math.max(MIN_SIZE - a, Math.min(b - MIN_SIZE, delta));
  out[i] = a + d;
  out[i + 1] = b - d;
  return out;
}

/** The group next to `groupId` in a direction, found through the tree, or undefined at the edge of the window. */
export function neighbour(root: Node, groupId: string, dir: Dir): Group | undefined {
  const path: { split: Split; index: number }[] = [];
  const walk = (n: Node): boolean => {
    if (n.kind === 'group') return n.id === groupId;
    for (let i = 0; i < n.children.length; i++) {
      path.push({ split: n, index: i });
      if (walk(n.children[i]!)) return true;
      path.pop();
    }
    return false;
  };
  if (!walk(root)) return undefined;
  const wantDir = dir === 'left' || dir === 'right' ? 'row' : 'col';
  const forward = dir === 'right' || dir === 'down';
  for (let k = path.length - 1; k >= 0; k--) {
    const { split: s, index } = path[k]!;
    if (s.dir !== wantDir) continue;
    const sib = s.children[index + (forward ? 1 : -1)];
    if (!sib) continue;
    // Enter the sibling from the side we came from: its nearest group.
    let n: Node = sib;
    while (n.kind === 'split') n = n.dir === wantDir ? (forward ? n.children[0]! : n.children[n.children.length - 1]!) : n.children[0]!;
    return n;
  }
  return undefined;
}

/** Keyboard alternative to dragging: move a tab into the neighbouring group, or split off a new one at the edge. */
export function moveTabDirection(root: Node, tabId: string, dir: Dir): Node {
  const src = groupOfTab(root, tabId);
  if (!src) return root;
  const next = neighbour(root, src.id, dir);
  if (next) return moveTab(root, tabId, next.id, 'center');
  const zone: Zone = dir === 'up' ? 'top' : dir === 'down' ? 'bottom' : dir;
  return moveTab(root, tabId, src.id, zone);
}

// ---------------------------------------------------------------------------------------------------------------
// Validation of anything read from storage or an imported file.

/** Returns a clean layout or null. `known` says whether a panel id is one this build has. */
export function validate(input: unknown, known: (panel: string) => boolean): Node | null {
  const tabIds = new Set<string>();
  const nodeIds = new Set<string>();
  let tabCount = 0;
  const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
  const str = (x: unknown): x is string => typeof x === 'string' && x.length > 0 && x.length <= 80;

  const rec = (x: unknown, depth: number): Node | null => {
    if (depth > MAX_DEPTH || !isObj(x) || !str(x.id) || nodeIds.has(x.id)) return null;
    if (x.kind === 'group') {
      if (!Array.isArray(x.tabs)) return null;
      nodeIds.add(x.id);
      const ts: Tab[] = [];
      for (const t of x.tabs) {
        if (!isObj(t) || !str(t.id) || !str(t.panel) || !known(t.panel) || tabIds.has(t.id)) return null;
        if (++tabCount > MAX_TABS) return null;
        tabIds.add(t.id);
        ts.push({ id: t.id, panel: t.panel });
      }
      return { kind: 'group', id: x.id, tabs: ts, active: typeof x.active === 'string' ? x.active : (ts[0]?.id ?? '') };
    }
    if (x.kind === 'split') {
      if ((x.dir !== 'row' && x.dir !== 'col') || !Array.isArray(x.children) || !Array.isArray(x.sizes)) return null;
      nodeIds.add(x.id);
      const kids: Node[] = [];
      for (const c of x.children) {
        const k = rec(c, depth + 1);
        if (!k) return null;
        kids.push(k);
      }
      const sizes = x.sizes.map((s) => (typeof s === 'number' ? s : NaN));
      return { kind: 'split', id: x.id, dir: x.dir, children: kids, sizes };
    }
    return null;
  };
  const tree = rec(input, 0);
  return tree ? normalize(tree) : null;
}
