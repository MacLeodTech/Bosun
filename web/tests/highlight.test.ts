// The tokeniser, the pretty-printer and the diff all read untrusted text, so they are held to three rules here:
// they never throw, the tokens rejoin to the input, and they take linear time (a pathological input stays fast).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectLang, highlight, highlightMessage, lex, MAX_LINE, contentTypeOf, type Lang } from '../src/lib/highlight.ts';
import { pretty, prettyJson } from '../src/lib/pretty.ts';
import { diffLines, diffWords } from '../src/lib/diff.ts';

const LANGS: Lang[] = ['http', 'json', 'html', 'xml', 'form', 'js', 'plain'];

function rng(seed: number) {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32);
}
const ALPHABET = ['<', '>', '/', '"', "'", '\\', '{', '}', '[', ']', ':', ',', '=', '&', '-', '!', '?', ' ', '\n', '\r', '\t', 'a', 'b', 'z', '0', '9', '.', 'e', '*', '`', '$', '%', 'é', '€', '\u0000', 'script', '<script>', '</script>', '<!--', '-->', 'true', 'HTTP/1.1', 'Host: x'];
function junk(r: () => number, len: number): string {
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[Math.floor(r() * ALPHABET.length)];
  return s;
}

test('every lexer is total and lossless on random input', () => {
  for (let seed = 1; seed <= 300; seed++) {
    const r = rng(seed);
    const text = junk(r, Math.floor(r() * 120));
    for (const lang of LANGS) {
      const toks = lex(text, lang);
      assert.equal(toks.map((t) => t.t).join(''), text, `${lang} seed ${seed}`);
      assert.ok(toks.every((t) => t.t.length > 0), `${lang} seed ${seed}: empty token`);
    }
  }
});

test('highlight never throws and keeps the text (minus carriage returns)', () => {
  for (let seed = 1; seed <= 200; seed++) {
    const r = rng(seed * 7);
    const text = junk(r, Math.floor(r() * 200));
    for (const lang of LANGS) {
      const lines = highlight(text, lang);
      const joined = lines.map((l) => l.map((t) => t.t).join('')).join('\n');
      // Only a carriage return right before a line break (or at the very end) is dropped from the display.
      assert.equal(joined, text.replace(/\r(?=\n|$)/g, ''), `${lang} seed ${seed}`);
      assert.ok(lines.length >= 1);
    }
  }
});

test('pathological inputs stay fast', () => {
  const cases = [
    '<'.repeat(200_000),
    '<a '.repeat(60_000),
    '"'.repeat(200_000),
    '\\'.repeat(200_000),
    '<!--'.repeat(50_000),
    '<script>'.repeat(20_000),
    '{"a":'.repeat(40_000),
    'x'.repeat(500_000),
    '\n'.repeat(200_000),
  ];
  for (const text of cases) {
    for (const lang of LANGS) {
      const t0 = performance.now();
      highlight(text, lang);
      const dt = performance.now() - t0;
      assert.ok(dt < 1500, `${lang} on ${JSON.stringify(text.slice(0, 12))}…: ${dt.toFixed(0)} ms`);
    }
  }
});

test('a very long line is shown plain', () => {
  const lines = highlight('{"k":"' + 'x'.repeat(MAX_LINE + 10) + '"}', 'json');
  assert.equal(lines.length, 1);
  assert.equal(lines[0]!.length, 1);
});

test('json tokens: keys, strings, numbers, booleans', () => {
  const t = lex('{"a": [1, -2.5e3, true, null, "s"]}', 'json').filter((x) => x.c);
  assert.deepEqual(t.map((x) => x.c + ':' + x.t), ['punct:{', 'key:"a"', 'punct::', 'punct:[', 'number:1', 'punct:,', 'number:-2.5e3', 'punct:,', 'bool:true', 'punct:,', 'bool:null', 'punct:,', 'string:"s"', 'punct:]', 'punct:}']);
});

test('an unterminated string stops at the line break instead of swallowing the rest', () => {
  const t = lex('{"a": "oops\n"b": 1}', 'json');
  assert.ok(t.some((x) => x.c === 'key' && x.t === '"b"'));
});

test('http: request line, status line and headers', () => {
  const req = lex('GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\nX: y', 'http').filter((x) => x.c);
  assert.deepEqual(req.map((x) => x.c), ['tag', 'string', 'punct', 'hname', 'punct', 'hvalue', 'hname', 'punct', 'hvalue']);
  const res = lex('HTTP/1.1 404 Not Found\r\nA: b', 'http').filter((x) => x.c);
  assert.deepEqual(res.map((x) => x.c), ['punct', 'number', 'hname', 'punct', 'hvalue']);
});

test('html: tags, attributes, comments, and script is not markup', () => {
  const t = lex('<a href="x" b>t</a><!-- c --><script>var a = "</b>";</script>', 'html');
  const cls = (c: string) => t.filter((x) => x.c === c).map((x) => x.t);
  assert.deepEqual(cls('tag').slice(0, 2), ['a', 'a']);
  assert.deepEqual(cls('attr'), ['href', 'b']);
  assert.deepEqual(cls('comment'), ['<!-- c -->']);
  assert.ok(cls('string').includes('"</b>"'));
});

test('detectLang and contentTypeOf', () => {
  assert.equal(detectLang('application/json; charset=utf-8', ''), 'json');
  assert.equal(detectLang('text/html', ''), 'html');
  assert.equal(detectLang('image/svg+xml', ''), 'xml');
  assert.equal(detectLang(null, '  {"a":1}'), 'json');
  assert.equal(detectLang(null, 'hello'), 'plain');
  assert.equal(detectLang('image/png', '{'), 'plain');
  assert.equal(contentTypeOf('GET / HTTP/1.1\r\nContent-Type: text/html\r\nX: y'), 'text/html');
  assert.equal(contentTypeOf('GET / HTTP/1.1'), null);
});

test('highlightMessage separates head and body', () => {
  const m = highlightMessage('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"a":1}');
  assert.equal(m.lang, 'json');
  assert.equal(m.lines.length, 4);
  assert.deepEqual(m.lines[2], []);
});

test('prettyJson re-indents without changing literals, and refuses what is not balanced', () => {
  assert.equal(prettyJson('{"a":[1,2],"b":{},"c":12345678901234567890}'), '{\n  "a": [\n    1,\n    2\n  ],\n  "b": {},\n  "c": 12345678901234567890\n}');
  assert.equal(prettyJson('{"a":1'), null);
  assert.equal(prettyJson('}'), null);
  assert.equal(prettyJson(''), null);
});

test('pretty never throws and its output has the same tokens for JSON', () => {
  for (let seed = 1; seed <= 200; seed++) {
    const r = rng(seed * 13);
    const text = junk(r, Math.floor(r() * 150));
    for (const lang of ['json', 'html', 'xml'] as const) {
      const p = pretty(text, lang);
      if (lang === 'json' && p !== null) {
        // Literals (strings, keys, numbers) must be untouched; only whitespace outside them may differ.
        const strip = (s: string) => lex(s, 'json').map((t) => (t.c === '' ? t.t.replace(/\s+/g, '') : t.t)).join('');
        assert.equal(strip(p), strip(text));
      }
    }
  }
});

test('pretty markup indents nested tags and leaves pre alone', () => {
  const p = pretty('<div><p>hi <b>there</b></p><br><pre>a\n  b</pre></div>', 'html')!;
  assert.equal(p, '<div>\n  <p>\n    hi\n    <b>\n      there\n    </b>\n  </p>\n  <br>\n  <pre>a\n  b</pre>\n</div>');
});

// ---- diff

/** Applying the script must give both inputs back. */
function check(a: string, b: string) {
  const ops = diffLines(a, b);
  assert.equal(ops.filter((o) => o.kind !== 'add').map((o) => o.text).join('\n'), a);
  assert.equal(ops.filter((o) => o.kind !== 'del').map((o) => o.text).join('\n'), b);
  return ops;
}

test('diffLines: simple cases', () => {
  assert.deepEqual(check('a\nb\nc', 'a\nb\nc').map((o) => o.kind), ['same', 'same', 'same']);
  assert.deepEqual(check('a\nb\nc', 'a\nx\nc').map((o) => o.kind), ['same', 'del', 'add', 'same']);
  assert.deepEqual(check('', 'a').map((o) => o.kind), ['del', 'add']);
  check('a\nb', '');
  check('x', 'x');
});

test('diffLines reconstructs both sides on random input, including past the edit bound', () => {
  for (let seed = 1; seed <= 150; seed++) {
    const r = rng(seed * 31);
    const pool = ['a', 'b', 'c', 'd', 'e', ''];
    const mk = (n: number) => Array.from({ length: n }, () => pool[Math.floor(r() * pool.length)]).join('\n');
    check(mk(Math.floor(r() * 40)), mk(Math.floor(r() * 40)));
  }
  const big = (seed: number) => {
    const r = rng(seed);
    return Array.from({ length: 5000 }, () => String(Math.floor(r() * 1e6))).join('\n');
  };
  const t0 = performance.now();
  check(big(1), big(2));
  assert.ok(performance.now() - t0 < 3000, 'bounded');
});

test('diffLines finds a minimal edit script on a known case', () => {
  const ops = check('a\nb\nc\nd\ne', 'a\nc\nd\nx\ne');
  assert.equal(ops.filter((o) => o.kind !== 'same').length, 2);
});

test('diffWords marks only the words that changed', () => {
  const ops = diffWords('GET /a HTTP/1.1', 'GET /b HTTP/1.1');
  assert.deepEqual(ops.filter((o) => o.kind !== 'same').map((o) => o.kind + ':' + o.text), ['del:a', 'add:b']);
});
