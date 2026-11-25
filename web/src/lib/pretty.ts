// Display-only re-indentation of JSON, HTML and XML. The stored bytes are never changed: this builds a different text
// to look at. It works on the lexer's tokens rather than parsing, so literals (a 20-digit integer, say) are shown
// exactly as they were sent, and malformed input gives `null` ("leave it alone") instead of an exception.
import { lexJson, scanHtml, MAX_HIGHLIGHT, type Lang } from './highlight.ts';

const INDENT = '  ';
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
/** Whitespace is meaningful inside these, so they are copied through unchanged. */
const VERBATIM = new Set(['pre', 'textarea']);

export function prettyJson(text: string): string | null {
  if (text.length > MAX_HIGHLIGHT) return null;
  const toks = lexJson(text).filter((t) => !(t.c === '' && /^\s+$/.test(t.t)));
  if (!toks.length) return null;
  const out: string[] = [];
  let depth = 0;
  let line = '';
  const flush = () => {
    out.push(INDENT.repeat(Math.max(depth, 0)) + line);
    line = '';
  };
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    if (t.c === 'punct' && (t.t === '{' || t.t === '[')) {
      const next = toks[i + 1];
      if (next && next.c === 'punct' && next.t === (t.t === '{' ? '}' : ']')) {
        line += t.t + next.t;
        i++;
        continue;
      }
      line += t.t;
      flush();
      depth++;
    } else if (t.c === 'punct' && (t.t === '}' || t.t === ']')) {
      if (line) flush();
      depth--;
      if (depth < 0) return null;
      line = t.t;
    } else if (t.c === 'punct' && t.t === ',') {
      line += ',';
      flush();
    } else if (t.c === 'punct' && t.t === ':') {
      line += ': ';
    } else {
      line += t.t;
    }
  }
  if (line) flush();
  return depth === 0 ? out.join('\n') : null;
}

export function prettyMarkup(text: string, xml: boolean): string | null {
  if (text.length > MAX_HIGHLIGHT) return null;
  const chunks = scanHtml(text);
  if (!chunks.length) return null;
  const out: string[] = [];
  let depth = 0;
  const pad = () => INDENT.repeat(depth);
  const raw = (c: (typeof chunks)[number]) => c.tokens.map((t) => t.t).join('');
  for (let i = 0; i < chunks.length; i++) {
    const c = chunks[i]!;
    if (c.kind === 'text') {
      const t = raw(c).replace(/\s+/g, ' ').trim();
      if (t) out.push(pad() + t);
    } else if (c.kind === 'raw') {
      const lines = raw(c).replace(/^\s*\n|\s+$/g, '').split('\n');
      const lead = Math.min(...lines.filter((l) => l.trim()).map((l) => /^\s*/.exec(l)![0].length), Infinity);
      for (const l of lines) out.push(pad() + INDENT + (l.trim() ? l.slice(Number.isFinite(lead) ? lead : 0) : ''));
    } else if (c.kind === 'open' && !xml && VERBATIM.has(c.name)) {
      // Copy everything up to the matching close tag on one line, untouched.
      let s = raw(c);
      let j = i + 1;
      while (j < chunks.length && !(chunks[j]!.kind === 'close' && chunks[j]!.name === c.name)) s += raw(chunks[j++]!);
      if (j < chunks.length) s += raw(chunks[j]!);
      out.push(pad() + s);
      i = j;
    } else if (c.kind === 'close') {
      depth = Math.max(0, depth - 1);
      out.push(pad() + raw(c));
    } else if (c.kind === 'open') {
      out.push(pad() + raw(c));
      if (xml || !VOID.has(c.name)) depth++;
    } else {
      out.push(pad() + raw(c));
    }
  }
  return out.join('\n');
}

/** The pretty form of a body, or null when there is none for this language or the body is not well formed. */
export function pretty(text: string, lang: Lang): string | null {
  if (lang === 'json') return prettyJson(text);
  if (lang === 'html') return prettyMarkup(text, false);
  if (lang === 'xml') return prettyMarkup(text, true);
  return null;
}
