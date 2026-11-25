// Run with `npm test` (node's built-in runner, types stripped). Covers the layout model's invariants, with a seeded
// random walk over every operation standing in for a property test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  addTab, groups, group, moveTab, moveTabDirection, neighbour, normalize, nudge, removeTab, setSizes, split, tab, tabs, validate,
  MIN_SIZE, type Node, type Split,
} from '../src/lib/layout.ts';

const known = (p: string) => ['a', 'b', 'c', 'd', 'e'].includes(p);

/** Every invariant from the top of layout.ts; returns a description of the first one broken. */
function broken(n: Node, seenTabs = new Set<string>(), seenNodes = new Set<string>()): string | null {
  if (seenNodes.has(n.id)) return `duplicate node id ${n.id}`;
  seenNodes.add(n.id);
  if (n.kind === 'group') {
    if (n.tabs.length === 0) return 'empty group';
    if (!n.tabs.some((t) => t.id === n.active)) return 'active tab not in group';
    for (const t of n.tabs) {
      if (seenTabs.has(t.id)) return `duplicate tab ${t.id}`;
      seenTabs.add(t.id);
    }
    return null;
  }
  if (n.children.length < 2) return 'split with fewer than two children';
  if (n.sizes.length !== n.children.length) return 'sizes do not match children';
  const sum = n.sizes.reduce((a, b) => a + b, 0);
  if (Math.abs(sum - 1) > 1e-9) return `sizes sum to ${sum}`;
  if (n.sizes.some((s) => !(s > 0))) return 'non-positive size';
  for (const c of n.children) {
    if (c.kind === 'split' && c.dir === n.dir) return 'same-direction nested split';
    const b = broken(c, seenTabs, seenNodes);
    if (b) return b;
  }
  return null;
}

function sample(): Node {
  return split('row', [group([tab('a'), tab('b')]), split('col', [group([tab('c')]), group([tab('d')])])], [0.6, 0.4]);
}
const groupWith = (n: Node, tabId: string) => groups(n).find((g) => g.tabs.some((t) => t.id === tabId))!;

test('sample layout is valid', () => assert.equal(broken(sample()), null));

test('closing the last tab of a group removes the group and collapses the split', () => {
  const r = removeTab(sample(), 'c')!;
  assert.equal(broken(r), null);
  assert.deepEqual(tabs(r).map((t) => t.id).sort(), ['a', 'b', 'd']);
  assert.equal(groups(r).length, 2);
});

test('closing every tab leaves null', () => {
  let r: Node | null = sample();
  for (const id of ['a', 'b', 'c', 'd']) r = r && removeTab(r, id);
  assert.equal(r, null);
});

test('closing the active tab activates its neighbour', () => {
  const g = group([tab('a'), tab('b'), tab('c')], 'b');
  const r = removeTab(g, 'b') as typeof g;
  assert.equal(r.active, 'c');
});

test('moving a tab to the right edge of another group keeps every tab', () => {
  const s = sample();
  const r = moveTab(s, 'a', groupWith(s, 'd').id, 'right');
  assert.equal(broken(r), null);
  assert.deepEqual(tabs(r).map((t) => t.id).sort(), ['a', 'b', 'c', 'd']);
});

test('a lone tab dropped on its own edge does nothing', () => {
  const s = sample();
  assert.equal(moveTab(s, 'c', groupWith(s, 'c').id, 'left'), s);
});

test('a window-edge drop makes a root split', () => {
  const r = moveTab(sample(), 'c', null, 'bottom');
  assert.equal(broken(r), null);
  assert.equal(r.kind, 'split');
  assert.equal((r as Split).dir, 'col');
});

test('reordering inside a group', () => {
  const s = group([tab('a'), tab('b'), tab('c')]);
  const r = moveTab(s, 'a', s.id, 'center', 3) as typeof s;
  assert.deepEqual(r.tabs.map((t) => t.id), ['b', 'c', 'a']);
  const r2 = moveTab(r, 'a', s.id, 'center', 0) as typeof s;
  assert.deepEqual(r2.tabs.map((t) => t.id), ['a', 'b', 'c']);
  const r3 = moveTab(s, 'c', s.id, 'center', 1) as typeof s;
  assert.deepEqual(r3.tabs.map((t) => t.id), ['a', 'c', 'b']);
  const r4 = moveTab(s, 'a', s.id, 'center') as typeof s;
  assert.deepEqual(r4.tabs.map((t) => t.id), ['b', 'c', 'a']);
});

test('nudge keeps the minimum and the total', () => {
  const out = nudge([0.5, 0.5], 0, 10);
  assert.ok(Math.abs(out[0]! + out[1]! - 1) < 1e-12);
  assert.ok(out[1]! >= MIN_SIZE - 1e-12);
  const back = nudge([0.5, 0.5], 0, -10);
  assert.ok(back[0]! >= MIN_SIZE - 1e-12);
});

test('setSizes clamps and renormalises', () => {
  const s = sample() as Split;
  const r = setSizes(s, s.id, [0, 5]) as Split;
  assert.equal(broken(r), null);
  assert.ok(r.sizes[0]! > 0);
});

test('neighbour and keyboard moves', () => {
  const s = sample();
  const ab = groupWith(s, 'a');
  const c = groupWith(s, 'c');
  assert.equal(neighbour(s, ab.id, 'right')!.id, c.id);
  assert.equal(neighbour(s, ab.id, 'left'), undefined);
  assert.equal(neighbour(s, c.id, 'down')!.tabs[0]!.id, 'd');
  const moved = moveTabDirection(s, 'a', 'right');
  assert.equal(broken(moved), null);
  const edge = moveTabDirection(s, 'a', 'left');
  assert.equal(broken(edge), null);
  assert.equal(groups(edge).length, 4);
});

test('validate accepts a good layout and rejects bad ones', () => {
  const s = sample();
  assert.ok(validate(JSON.parse(JSON.stringify(s)), known));
  assert.equal(validate(null, known), null);
  assert.equal(validate({ kind: 'group', id: 'x', tabs: [{ id: 'q', panel: 'zzz' }], active: 'q' }, known), null);
  assert.equal(validate({ kind: 'group', id: 'x', tabs: [{ id: 'q', panel: 'a' }, { id: 'q', panel: 'b' }], active: 'q' }, known), null);
  assert.equal(validate({ kind: 'weird', id: 'x' }, known), null);
  // Bad sizes are repaired rather than trusted.
  const bad = JSON.parse(JSON.stringify(s));
  bad.sizes = [NaN, -1];
  const fixed = validate(bad, known);
  assert.ok(fixed && broken(fixed) === null);
  // Absurd nesting is refused.
  let deep: unknown = { kind: 'group', id: 'leaf', tabs: [{ id: 't', panel: 'a' }], active: 't' };
  for (let i = 0; i < 40; i++) {
    deep = { kind: 'split', id: `n${i}`, dir: i % 2 ? 'row' : 'col', sizes: [1, 1], children: [deep, { kind: 'group', id: `l${i}`, tabs: [{ id: `t${i}`, panel: 'b' }], active: `t${i}` }] };
  }
  assert.equal(validate(deep, known), null);
});

test('normalize merges same-direction nesting', () => {
  const inner = split('row', [group([tab('b')]), group([tab('c')])]);
  const outer = split('row', [group([tab('a')]), inner], [0.5, 0.5]);
  const n = normalize(outer) as Split;
  assert.equal(n.children.length, 3);
  assert.equal(broken(n), null);
  assert.ok(Math.abs(n.sizes[1]! - 0.25) < 1e-9);
});

// Seeded random walk: whatever sequence of operations runs, the invariants hold and no tab is lost or duplicated.
function rng(seed: number) {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32);
}

test('random operations never break the invariants', () => {
  const zones = ['center', 'left', 'right', 'top', 'bottom'] as const;
  const dirs = ['left', 'right', 'up', 'down'] as const;
  for (let seed = 1; seed <= 60; seed++) {
    const r = rng(seed);
    const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;
    let root: Node = group([tab('a')]);
    const live = new Set(['a']);
    let next = 0;
    for (let step = 0; step < 120; step++) {
      const op = Math.floor(r() * 5);
      if (op === 0 && live.size < 12) {
        const id = `t${next++}`;
        live.add(id);
        root = addTab(root, tab('b', id), pick(groups(root)).id);
      } else if (op === 1 && live.size > 1) {
        const id = pick([...live]);
        const out = removeTab(root, id);
        if (out) {
          root = out;
          live.delete(id);
        }
      } else if (op === 2) {
        const id = pick([...live]);
        const toRoot = r() < 0.2;
        root = moveTab(root, id, toRoot ? null : pick(groups(root)).id, pick(zones), Math.floor(r() * 5));
      } else if (op === 3) {
        root = moveTabDirection(root, pick([...live]), pick(dirs));
      } else if (root.kind === 'split') {
        root = setSizes(root, root.id, root.sizes.map(() => r() * 2));
      }
      const b = broken(root);
      assert.equal(b, null, `seed ${seed} step ${step}: ${b}`);
      assert.deepEqual(tabs(root).map((t) => t.id).sort(), [...live].sort(), `seed ${seed} step ${step}: tabs changed`);
      assert.ok(validate(JSON.parse(JSON.stringify(root)), () => true), `seed ${seed} step ${step}: does not round-trip`);
    }
  }
});
