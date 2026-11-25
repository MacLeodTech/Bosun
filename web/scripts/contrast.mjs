// Fails when a text token is below 4.5:1 against the surfaces it is drawn on, in either theme.
// Reads web/src/tokens.css (two blocks: dark and light), so there is nothing to keep in step by hand.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const css = readFileSync(fileURLToPath(new URL('../src/tokens.css', import.meta.url)), 'utf8');

function block(selectorStart) {
  const i = css.indexOf(selectorStart);
  if (i < 0) throw new Error(`tokens.css: no block starting ${selectorStart}`);
  const body = css.slice(css.indexOf('{', i) + 1, css.indexOf('}', i));
  const out = {};
  for (const m of body.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) out[m[1]] = m[2];
  return out;
}

const themes = { dark: block(":root[data-theme='dark']"), light: block(":root[data-theme='light']") };

const lum = (hex) => {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = c.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a, b) => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

const surfaces = ['surface-0', 'surface-1', 'surface-2', 'surface-sel'];
const text = ['text-1', 'text-2', 'accent', 'ok', 'info', 'warn', 'bad',
  'm-get', 'm-post', 'm-put', 'm-patch', 'm-delete', 'm-other',
  'st-2xx', 'st-3xx', 'st-4xx', 'st-5xx', 'st-err'];
const pairs = [...text.flatMap((t) => surfaces.map((s) => [t, s])), ['on-accent', 'accent']];

let failed = 0;
for (const [name, t] of Object.entries(themes)) {
  for (const [fg, bg] of pairs) {
    if (!t[fg] || !t[bg]) throw new Error(`${name}: token --${fg} or --${bg} missing`);
    const r = ratio(t[fg], t[bg]);
    if (r < 4.5) {
      failed++;
      console.error(`${name}: --${fg} on --${bg} is ${r.toFixed(2)}:1 (needs 4.5)`);
    }
  }
}
if (failed) {
  console.error(`${failed} contrast failure(s)`);
  process.exit(1);
}
console.log('contrast ok');
