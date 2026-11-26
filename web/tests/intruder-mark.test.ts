// Auto-marking positions in a request.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { autoMark } from '../src/lib/intruder.ts';

test('auto-marking takes query values and urlencoded form values, and nothing else', () => {
  assert.equal(autoMark('GET /a?x=1&y=two HTTP/1.1\nHost: h\n\n'), 'GET /a?x=§1§&y=§two§ HTTP/1.1\nHost: h\n\n');
  const form = 'POST /l HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nu=admin&p=secret';
  assert.equal(autoMark(form), 'POST /l HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nu=§admin§&p=§secret§');
  // JSON bodies are left alone, and marking twice does not double the markers.
  const json = 'POST /l HTTP/1.1\nContent-Type: application/json\n\n{"a":"b=c"}';
  assert.equal(autoMark(json), json);
  assert.equal(autoMark(autoMark('GET /?q=1 HTTP/1.1\n\n')), 'GET /?q=§1§ HTTP/1.1\n\n');
});
