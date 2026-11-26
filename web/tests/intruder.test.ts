// The pure parts of the Intruder page: the API body the form makes, position markers, sorting, filtering, CSV.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  blankProc, blankSet, clearMarks, countPositions, csvCell, filterRows, markSelection, requestB64, rowsToCsv, setBody,
  setFromBody, sortRows, type Row,
} from '../src/lib/intruder.ts';

const row = (i: number, o: Partial<Row> = {}): Row => ({
  index: i, position: null, payloads: [`p${i}`], status: 200, length: 100 + i, time_ms: 10 * i, flow_id: i + 1, error: null,
  matches: [false], extracts: [null], attempts: 1, ...o,
});

test('markers wrap the selection, count in pairs and clear again', () => {
  const m = markSelection('GET /abc HTTP/1.1', 5, 8);
  assert.equal(m.text, 'GET /§abc§ HTTP/1.1');
  assert.equal(countPositions(m.text), 1);
  assert.equal(countPositions('§a§ §b§ §c'), 2);
  assert.equal(clearMarks(m.text), 'GET /abc HTTP/1.1');
  // A caret with nothing selected makes an empty position.
  assert.equal(markSelection('ab', 1, 1).text, 'a§§b');
});

test('the request goes out as CRLF text in base64, UTF-8 for markers', () => {
  assert.equal(atob(requestB64('GET / HTTP/1.1\nHost: x\n\n')), 'GET / HTTP/1.1\r\nHost: x\r\n\r\n');
  // text that already has CRLF is left alone
  assert.equal(atob(requestB64('a\r\nb\n')), 'a\r\nb\n');
  assert.equal(atob(requestB64('§')), '\xc2\xa7');
});

test('a payload set becomes the API shape and back', () => {
  const s = blankSet();
  s.list = 'a\n\nb\r\nc\n';
  s.processing = [{ ...blankProc('prefix'), value: 'x' }, { ...blankProc('encode'), op: 'sha256' }, { ...blankProc('replace_regex'), pattern: 'a', replacement: 'b' }, { ...blankProc('skip_if_matches'), pattern: '^z' }];
  const b = setBody(s);
  assert.deepEqual(b.source, { type: 'list', items: ['a', 'b', 'c'] });
  assert.deepEqual(b.processing, [
    { type: 'prefix', value: 'x' }, { type: 'encode', op: 'sha256' },
    { type: 'replace_regex', pattern: 'a', replacement: 'b' }, { type: 'skip_if_matches', pattern: '^z' },
  ]);
  assert.deepEqual(setFromBody(b).processing.map((p) => p.type), ['prefix', 'encode', 'replace_regex', 'skip_if_matches']);
  const n = { ...blankSet(), source: 'numbers' as const, from: 5, to: 9, step: 2, base: 'hex' as const, digits: 3 };
  assert.deepEqual(setBody(n).source, { type: 'numbers', from: 5, to: 9, step: 2, base: 'hex', min_digits: 3 });
  assert.equal(setFromBody(setBody(n)).digits, 3);
  assert.deepEqual(setBody({ ...blankSet(), source: 'null', count: 4 }).source, { type: 'null', count: 4 });
});

test('sorting is stable on the request number, in both directions', () => {
  const rows = [row(0, { status: 404 }), row(1), row(2, { status: 404 }), row(3, { status: null })];
  assert.deepEqual(sortRows(rows, 'status', true).map((r) => r.index), [3, 1, 0, 2]);
  assert.deepEqual(sortRows(rows, 'status', false).map((r) => r.index), [2, 0, 1, 3]);
  assert.deepEqual(sortRows(rows, 'length', false).map((r) => r.index), [3, 2, 1, 0]);
  const m = [row(0), row(1, { matches: [true] })];
  assert.deepEqual(sortRows(m, 'match:0', false).map((r) => r.index), [1, 0]);
  assert.deepEqual(sortRows([row(0, { extracts: ['b'] }), row(1, { extracts: ['a'] })], 'extract:0', true).map((r) => r.index), [1, 0]);
});

test('the filter narrows by words and by field', () => {
  const rows = [row(0, { payloads: ['admin'], status: 200 }), row(1, { payloads: ['root'], status: 404, length: 5000 }), row(2, { status: null, error: 'refused' }), row(3, { matches: [true], extracts: ['token9'] })];
  const f = (q: string) => filterRows(rows, q).map((r) => r.index);
  assert.deepEqual(f(''), [0, 1, 2, 3]);
  assert.deepEqual(f('ADMIN'), [0]);
  assert.deepEqual(f('status:404'), [1]);
  assert.deepEqual(f('length:>1000'), [1]);
  assert.deepEqual(f('length:<=100'), [0]);
  assert.deepEqual(f('match'), [3]);
  assert.deepEqual(f('error'), [2]);
  assert.deepEqual(f('token9 match'), [3]);
  assert.deepEqual(f('root status:200'), []);
});

test('CSV quotes what needs it and defuses formulas', () => {
  assert.equal(csvCell('a,b'), '"a,b"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"');
  assert.equal(csvCell('-1+2'), "'-1+2");
  assert.equal(csvCell(5), '5');
  assert.equal(csvCell(null), '');
  const csv = rowsToCsv([row(0, { matches: [true], extracts: ['=x'] })], ['needle'], ['tok']);
  assert.equal(csv.split('\r\n')[0], 'request,position,payloads,status,length,time_ms,flow,error,match: needle,extract: tok');
  assert.equal(csv.split('\r\n')[1], "1,,p0,200,100,0,1,,yes,'=x");
});
