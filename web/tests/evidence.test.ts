// Evidence byte ranges to line marks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { marks } from '../src/lib/evidence.ts';

const enc = new TextEncoder();

test('a range inside a line becomes one mark', () => {
  const t = 'HTTP/1.1 200 OK\r\nX: y\r\n\r\nhello secret world';
  const at = t.indexOf('secret');
  assert.deepEqual(marks(enc.encode(t), t, true, [{ start: at, end: at + 6 }]), [{ line: 3, from: 6, to: 12 }]);
});

test('multi-byte text before the range shifts it by characters, not bytes', () => {
  const t = 'é\n\nab';
  const b = enc.encode(t);
  assert.deepEqual(marks(b, t, true, [{ start: b.length - 1, end: b.length }]), [{ line: 2, from: 1, to: 2 }]);
});

test('a range across lines is split per line, and ranges past the loaded bytes are dropped', () => {
  const t = 'ab\ncd';
  const b = enc.encode(t);
  assert.deepEqual(marks(b, t, true, [{ start: 1, end: 5 }]), [
    { line: 0, from: 1, to: 2 },
    { line: 1, from: 0, to: 2 },
  ]);
  assert.deepEqual(marks(b, t, true, [{ start: 9, end: 12 }]), []);
});
