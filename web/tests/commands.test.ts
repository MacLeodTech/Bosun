// The pure parts of Phase 3: the filter query, shortcut matching and conflict report, fuzzy scoring, cURL.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_QUERY, matchesFlow, parseQuery, removeChip, withTerm, withText } from '../src/lib/query.ts';
import { canonical, conflicts, format, matches, parseKeys } from '../src/lib/shortcuts.ts';
import { fuzzy } from '../src/lib/fuzzy.ts';
import { buildCurl } from '../src/lib/curl.ts';

function rng(seed: number) {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32);
}

// ---- query

test('every kind of term lands in the structured filter', () => {
  const p = parseQuery('host:Example.com method:get,post status:400-499 scope:in -ext:PNG,css login "two words"');
  assert.deepEqual(p.errors, []);
  assert.equal(p.filter.host, 'example.com');
  assert.equal(p.filter.methods, 'GET,POST');
  assert.equal(p.filter.statusMin, 400);
  assert.equal(p.filter.statusMax, 499);
  assert.equal(p.filter.inScopeOnly, true);
  assert.equal(p.filter.hideExt, 'png,css');
  assert.equal(p.filter.text, 'login two words');
  assert.equal(p.chips.length, 7);
});

test('status forms', () => {
  const s = (v: string) => { const f = parseQuery(`status:${v}`).filter; return [f.statusMin, f.statusMax]; };
  assert.deepEqual(s('404'), [404, 404]);
  assert.deepEqual(s('4xx'), [400, 499]);
  assert.deepEqual(s('>=500'), [500, undefined]);
  assert.deepEqual(s('>500'), [501, undefined]);
  assert.deepEqual(s('<400'), [undefined, 399]);
  assert.deepEqual(s('<=400'), [undefined, 400]);
  assert.equal(parseQuery('status:abc').errors.length, 1);
  assert.equal(parseQuery('status:500-400').errors.length, 1);
});

test('bad terms are reported, not thrown, and unknown keys are plain text', () => {
  assert.equal(parseQuery('scope:out').errors.length, 1);
  assert.equal(parseQuery('ext:png').errors.length, 1);
  assert.equal(parseQuery('-host:x').errors.length, 1);
  assert.equal(parseQuery('method:').errors.length, 1);
  assert.equal(parseQuery('method:"G E T"').errors.length, 1);
  const p = parseQuery('foo:bar');
  assert.equal(p.filter.text, 'foo:bar');
  assert.deepEqual(p.errors, []);
});

test('the default query hides the usual static extensions', () => {
  const f = parseQuery(DEFAULT_QUERY).filter;
  assert.ok(f.hideExt.split(',').includes('woff2'));
  assert.equal(f.text, '');
});

test('removing a chip and setting terms', () => {
  const q = 'host:a.com status:4xx login';
  const p = parseQuery(q);
  assert.equal(removeChip(q, p.chips[0]!), 'status:4xx login');
  assert.equal(removeChip(q, p.chips[2]!), 'host:a.com status:4xx');
  assert.equal(withTerm(q, 'host', 'b.com'), 'status:4xx login host:b.com');
  assert.equal(withTerm('', 'status', '404'), 'status:404');
  assert.equal(withText(q, 'X-Test: yes'), 'host:a.com status:4xx "X-Test: yes"');
  assert.equal(withText('login', ''), '');
  assert.equal(parseQuery(withText('', 'a b')).filter.text, 'a b');
});

test('parseQuery is total on random input', () => {
  const alphabet = ['host:', 'status:', '-ext:', '"', ' ', 'a', '4xx', ',', '-', ':', '>=', '5', 'scope:in', 'm:', '\\', '\n'];
  for (let seed = 1; seed <= 400; seed++) {
    const r = rng(seed);
    let q = '';
    for (let i = 0; i < Math.floor(r() * 30); i++) q += alphabet[Math.floor(r() * alphabet.length)];
    const p = parseQuery(q);
    for (const c of p.chips) assert.ok(c.start >= 0 && c.end <= q.length && c.start < c.end, `chip range ${seed}`);
    removeChip(q, p.chips[0] ?? { key: 'text', label: '', start: 0, end: 0 });
  }
});

test('matchesFlow applies the structured filter', () => {
  const f = parseQuery('host:ex method:GET status:2xx scope:in -ext:png').filter;
  const base = { host: 'www.example.com', method: 'GET', status: 200, in_scope: true, path: '/a.js?x=1' };
  assert.ok(matchesFlow(f, base));
  assert.ok(!matchesFlow(f, { ...base, host: 'other.org' }));
  assert.ok(!matchesFlow(f, { ...base, method: 'POST' }));
  assert.ok(!matchesFlow(f, { ...base, status: 404 }));
  assert.ok(!matchesFlow(f, { ...base, in_scope: false }));
  assert.ok(!matchesFlow(f, { ...base, path: '/logo.png?v=2' }));
});

// ---- shortcuts

test('parseKeys and matches', () => {
  const k = parseKeys('Ctrl+Shift+S')!;
  assert.deepEqual(k, { ctrl: true, shift: true, alt: false, key: 's' });
  const ev = (o: object) => ({ key: '', code: '', ctrlKey: false, metaKey: false, shiftKey: false, altKey: false, ...o });
  assert.ok(matches(ev({ key: 'S', ctrlKey: true, shiftKey: true }), k));
  assert.ok(matches(ev({ key: 's', metaKey: true, shiftKey: true }), k), 'Cmd counts as Ctrl');
  assert.ok(!matches(ev({ key: 's', ctrlKey: true }), k), 'Shift must match');
  assert.ok(!matches(ev({ key: 's', ctrlKey: true, shiftKey: true, altKey: true }), k), 'extra modifier');
  const digit = parseKeys('Alt+1')!;
  assert.ok(matches(ev({ key: '¡', code: 'Digit1', altKey: true }), digit), 'a digit matches by physical key');
  assert.equal(parseKeys('Ctrl+'), null);
  assert.equal(parseKeys('Hyper+K'), null);
  assert.deepEqual(parseKeys('Ctrl+\\'), { ctrl: true, shift: false, alt: false, key: '\\' });
  assert.equal(canonical(parseKeys('shift+ctrl+K')!), 'ctrl+shift+k');
  assert.equal(format('Alt+Shift+ArrowLeft'), 'Alt+Shift+←');
});

test('the conflict report finds duplicates, browser-reserved keys and unreadable specs', () => {
  const c = conflicts([
    { id: 'a', keys: 'Ctrl+K' }, { id: 'b', keys: 'ctrl+k' }, { id: 'c', keys: 'Ctrl+Shift+I' }, { id: 'd', keys: 'Ctrl+R' }, { id: 'e', keys: 'Bogus+X' }, { id: 'f', keys: 'F5' },
  ]);
  assert.deepEqual(c.duplicates, [{ keys: 'ctrl+k', ids: ['a', 'b'] }]);
  assert.deepEqual(c.reserved.map((r) => r.id).sort(), ['c', 'f']);
  assert.deepEqual(c.invalid, [{ id: 'e', keys: 'Bogus+X' }]);
});

// ---- fuzzy

test('fuzzy: order is required, substrings win, word starts help', () => {
  assert.equal(fuzzy('zq', 'HTTP history'), null);
  assert.equal(fuzzy('hy', 'history')?.idx.length, 2);
  const sub = fuzzy('hist', 'Open HTTP history')!;
  const scattered = fuzzy('hist', 'He is struck')!;
  assert.ok(sub.score > scattered.score);
  const start = fuzzy('rep', 'Repeater')!;
  const mid = fuzzy('rep', 'Prepare')!;
  assert.ok(start.score > mid.score);
  assert.deepEqual(fuzzy('', 'anything'), { score: 0, idx: [] });
  assert.deepEqual(fuzzy('ope', 'Open')!.idx, [0, 1, 2]);
});

test('fuzzy never throws and its indices are in range and increasing', () => {
  const r = rng(99);
  const chars = 'abc de-/#@ éX';
  for (let i = 0; i < 500; i++) {
    const mk = (n: number) => Array.from({ length: n }, () => chars[Math.floor(r() * chars.length)]).join('');
    const text = mk(Math.floor(r() * 30));
    const m = fuzzy(mk(Math.floor(r() * 5)), text);
    if (m) {
      assert.ok(m.idx.every((x, k) => x >= 0 && x < text.length && (k === 0 || x > m.idx[k - 1]!)));
    }
  }
});

// ---- curl

test('buildCurl', () => {
  const c = buildCurl('POST /a?b=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nX-It\'s: yes', "it's", 'https')!;
  assert.ok(c.startsWith("curl -i -X POST 'https://example.com/a?b=1'"));
  assert.ok(c.includes("-H 'Content-Type: text/plain'"));
  assert.ok(!c.includes('Content-Length') && !c.includes('Host:'));
  assert.ok(c.includes(`-H 'X-It'\\''s: yes'`));
  assert.ok(c.includes(`--data-binary 'it'\\''s'`));
  assert.equal(buildCurl('GET / HTTP/1.1\r\nHost: x', '', 'https', true), null);
  assert.equal(buildCurl('GET / HTTP/1.1', '', 'https'), null);
  assert.equal(buildCurl('nonsense', '', 'https'), null);
  assert.equal(buildCurl('GET / HTTP/1.1\r\nHost: x', 'x'.repeat(70_000), 'https'), null);
});

// ---- deep links

import { buildHash, parseHash } from '../src/lib/deeplink.ts';

test('deep links: panel and request, and nothing else', () => {
  const isPanel = (p: string) => ['history', 'repeater'].includes(p);
  assert.deepEqual(parseHash('#history?flow=1234', isPanel), { panel: 'history', flow: 1234 });
  assert.deepEqual(parseHash('#repeater', isPanel), { panel: 'repeater', flow: null });
  assert.deepEqual(parseHash('#setup=abc', isPanel), { panel: null, flow: null });
  assert.deepEqual(parseHash('#history?flow=abc', isPanel), { panel: 'history', flow: null });
  assert.deepEqual(parseHash('#history?flow=12&x=1', isPanel), { panel: 'history', flow: null });
  assert.deepEqual(parseHash('#nope?flow=1', isPanel), { panel: null, flow: null });
  assert.deepEqual(parseHash('', isPanel), { panel: null, flow: null });
  assert.equal(buildHash('history', 5), '#history?flow=5');
  assert.equal(buildHash('repeater', null), '#repeater');
  assert.deepEqual(parseHash(buildHash('history', 99), isPanel), { panel: 'history', flow: 99 });
});

// ---- pop-out windows

import { idFromKey, isWindowId, parseMsg, parsePopout, popoutHash, windowKey } from '../src/lib/popout.ts';

test('pop-out addresses, keys and ids', () => {
  assert.equal(parsePopout('#/popout/abc123def'), 'abc123def');
  assert.equal(parsePopout(popoutHash('Ab-_9xyz')), 'Ab-_9xyz');
  for (const bad of ['#/popout/', '#/popout/ab', '#/popout/a b c d', '#/popout/../x', '#history', '', '#/popout/abcd/extra', '#/popout/abcd?x=1']) assert.equal(parsePopout(bad), null, bad);
  assert.equal(isWindowId('abcd'), true);
  assert.equal(isWindowId('abc'), false);
  assert.equal(isWindowId('x'.repeat(41)), false);
  assert.equal(isWindowId(5), false);
  assert.equal(idFromKey(windowKey('abc12345')), 'abc12345');
  assert.equal(idFromKey('bosun.workspace.v1'), null);
  assert.equal(idFromKey('bosun.window.ab.v1'), null);
});

test('only well-formed messages get through, and they carry ids only', () => {
  const ok = parseMsg({ type: 'select', from: 'abcd1234', selected: [1, 2], selectedId: 2, openId: null });
  assert.deepEqual(ok, { type: 'select', from: 'abcd1234', selected: [1, 2], selectedId: 2, openId: null });
  assert.deepEqual(parseMsg({ type: 'alive', id: 'abcd1234' }), { type: 'alive', id: 'abcd1234' });
  assert.deepEqual(parseMsg({ type: 'return', id: 'abcd1234', extra: '<script>' }), { type: 'return', id: 'abcd1234' });
  for (const bad of [null, 5, 'x', [], {}, { type: 'select' }, { type: 'select', from: 'abcd1234', selected: [1.5], selectedId: null, openId: null },
    { type: 'select', from: 'abcd1234', selected: [-1], selectedId: null, openId: null }, { type: 'select', from: 'abcd1234', selected: [1], selectedId: 'x', openId: null },
    { type: 'select', from: 'abcd1234', selected: new Array(6000).fill(1), selectedId: null, openId: null }, { type: 'alive', id: 'no' }, { type: 'other', id: 'abcd1234' }]) {
    assert.equal(parseMsg(bad), null, JSON.stringify(bad)?.slice(0, 60));
  }
});
