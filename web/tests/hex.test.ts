import { test } from 'node:test';
import assert from 'node:assert/strict';
import { asciiRows, formatHex, hexProblem, parseHex } from '../src/lib/hex.ts';
import { bytesToText, textToBytes, wireBytes } from '../src/lib/bytes.ts';

test('hex rows round-trip every byte value', () => {
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.deepEqual(parseHex(formatHex(all)), all);
  assert.equal(formatHex(all).split('\n').length, 16);
  assert.equal(formatHex(new Uint8Array()), '');
  assert.deepEqual(parseHex(''), new Uint8Array());
});

test('the parser ignores whitespace and refuses everything else', () => {
  assert.deepEqual(parseHex(' 47 45\n54\t20 '), Uint8Array.from([0x47, 0x45, 0x54, 0x20]));
  assert.deepEqual(parseHex('4745'), Uint8Array.from([0x47, 0x45]));
  assert.equal(parseHex('474'), null);
  assert.equal(parseHex('0x47'), null);
  assert.equal(parseHex('4g'), null);
  assert.match(hexProblem('4g'), /"g".*position 2/);
  assert.match(hexProblem('474'), /left over/);
  assert.equal(hexProblem('47 45'), '');
});

test('ascii rows show printable bytes and dots', () => {
  assert.deepEqual(asciiRows(Uint8Array.from([0x47, 0x00, 0x7f, 0x20, 0xff])), ['G.. .']);
  assert.equal(asciiRows(new Uint8Array(33)).length, 3);
});

test('wire bytes: lone LF becomes CRLF, existing CRLF is left alone, Latin-1 keeps its bytes', () => {
  const enc = (s: string) => new TextDecoder().decode(wireBytes(s, 'utf8'));
  assert.equal(enc('GET / HTTP/1.1\nHost: x\n\n'), 'GET / HTTP/1.1\r\nHost: x\r\n\r\n');
  assert.equal(enc('a\r\nb\nc'), 'a\r\nb\nc');
  const raw = Uint8Array.from([0x41, 0xe9, 0xff, 0x0a]);
  const { text, mode } = bytesToText(raw);
  assert.equal(mode, 'latin1');
  assert.deepEqual(textToBytes(text, mode), raw);
  assert.deepEqual(wireBytes(text, mode), Uint8Array.from([0x41, 0xe9, 0xff, 0x0d, 0x0a]));
});
