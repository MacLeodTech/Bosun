// Syntax highlighting without {@html}: a small tokeniser that returns plain data. The viewer renders each token as a
// <span class="sx-...">, so target content never reaches the DOM as markup.
//
// The input is hostile, so the lexers are built to three rules, all checked by web/tests/highlight.test.ts:
//   - total: no input makes them throw;
//   - lossless: the tokens of a text always join back to exactly that text;
//   - linear: every loop advances, and nothing backtracks over the input.

export type Cls = '' | 'key' | 'string' | 'number' | 'bool' | 'punct' | 'hname' | 'hvalue' | 'tag' | 'attr' | 'comment';
export interface Token { t: string; c: Cls }
export type Line = Token[];
export type Lang = 'http' | 'json' | 'html' | 'xml' | 'form' | 'js' | 'plain';

/** Past this many characters a body is shown without colour (and the viewer says so). */
export const MAX_HIGHLIGHT = 1 << 20;
/** A line longer than this is shown plain, so one minified line cannot create tens of thousands of elements. */
export const MAX_LINE = 20_000;
const MAX_ATTR_VALUE = 8192;

const isWs = (c: string | undefined) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f';
const isDigit = (c: string | undefined) => c !== undefined && c >= '0' && c <= '9';
const isWordStart = (c: string | undefined) => c !== undefined && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_' || c === '$');
const isWord = (c: string | undefined) => isWordStart(c) || isDigit(c);

function push(out: Token[], t: string, c: Cls) {
  if (!t) return;
  const last = out[out.length - 1];
  if (last && last.c === c && c === '') last.t += t;
  else out.push({ t, c });
}

// ---- JSON -----------------------------------------------------------------------------------------------------

export function lexJson(s: string): Token[] {
  const out: Token[] = [];
  const n = s.length;
  let i = 0;
  while (i < n) {
    const ch = s[i]!;
    if (isWs(ch)) {
      let j = i + 1;
      while (j < n && isWs(s[j])) j++;
      push(out, s.slice(i, j), '');
      i = j;
    } else if (ch === '"') {
      let j = i + 1;
      while (j < n) {
        const d = s[j];
        if (d === '\\') j += 2;
        else if (d === '"') {
          j++;
          break;
        } else if (d === '\n') break;
        else j++;
      }
      if (j > n) j = n;
      let k = j;
      while (k < n && (s[k] === ' ' || s[k] === '\t')) k++;
      push(out, s.slice(i, j), s[k] === ':' ? 'key' : 'string');
      i = j;
    } else if (ch === '-' || isDigit(ch)) {
      let j = i + 1;
      while (j < n && (isDigit(s[j]) || s[j] === '.' || s[j] === 'e' || s[j] === 'E' || s[j] === '+' || s[j] === '-')) j++;
      push(out, s.slice(i, j), 'number');
      i = j;
    } else if (isWordStart(ch)) {
      let j = i + 1;
      while (j < n && isWord(s[j])) j++;
      const w = s.slice(i, j);
      push(out, w, w === 'true' || w === 'false' || w === 'null' ? 'bool' : '');
      i = j;
    } else if ('{}[],:'.includes(ch)) {
      push(out, ch, 'punct');
      i++;
    } else {
      push(out, ch, '');
      i++;
    }
  }
  return out;
}

// ---- JavaScript (a light pass: strings, comments, numbers, keywords) ----------------------------------------------

const KEYWORDS = new Set([
  'var', 'let', 'const', 'function', 'return', 'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue', 'new',
  'this', 'typeof', 'instanceof', 'in', 'of', 'try', 'catch', 'finally', 'throw', 'class', 'extends', 'import', 'export',
  'default', 'async', 'await', 'yield', 'void', 'delete', 'true', 'false', 'null', 'undefined',
]);

export function lexJs(s: string): Token[] {
  const out: Token[] = [];
  const n = s.length;
  let i = 0;
  while (i < n) {
    const ch = s[i]!;
    const nx = s[i + 1];
    if (isWs(ch)) {
      let j = i + 1;
      while (j < n && isWs(s[j])) j++;
      push(out, s.slice(i, j), '');
      i = j;
    } else if (ch === '/' && nx === '/') {
      let j = i + 2;
      while (j < n && s[j] !== '\n') j++;
      push(out, s.slice(i, j), 'comment');
      i = j;
    } else if (ch === '/' && nx === '*') {
      const e = s.indexOf('*/', i + 2);
      const j = e < 0 ? n : e + 2;
      push(out, s.slice(i, j), 'comment');
      i = j;
    } else if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1;
      while (j < n) {
        const d = s[j];
        if (d === '\\') j += 2;
        else if (d === ch) {
          j++;
          break;
        } else if (d === '\n' && ch !== '`') break;
        else j++;
      }
      if (j > n) j = n;
      push(out, s.slice(i, j), 'string');
      i = j;
    } else if (isDigit(ch)) {
      let j = i + 1;
      while (j < n && (isWord(s[j]) || s[j] === '.')) j++;
      push(out, s.slice(i, j), 'number');
      i = j;
    } else if (isWordStart(ch)) {
      let j = i + 1;
      while (j < n && isWord(s[j])) j++;
      const w = s.slice(i, j);
      push(out, w, KEYWORDS.has(w) ? 'tag' : '');
      i = j;
    } else if ('{}()[];,.'.includes(ch)) {
      push(out, ch, 'punct');
      i++;
    } else {
      push(out, ch, '');
      i++;
    }
  }
  return out;
}

// ---- URL-encoded forms -------------------------------------------------------------------------------------------

export function lexForm(s: string): Token[] {
  const out: Token[] = [];
  const n = s.length;
  let i = 0;
  let name = true;
  while (i < n) {
    const ch = s[i]!;
    if (ch === '=' && name) {
      push(out, ch, 'punct');
      name = false;
      i++;
    } else if (ch === '&') {
      push(out, ch, 'punct');
      name = true;
      i++;
    } else if (ch === '\n' || ch === '\r') {
      push(out, ch, '');
      name = true;
      i++;
    } else {
      let j = i + 1;
      while (j < n && s[j] !== '&' && s[j] !== '\n' && s[j] !== '\r' && !(name && s[j] === '=')) j++;
      push(out, s.slice(i, j), name ? 'key' : 'string');
      i = j;
    }
  }
  return out;
}

// ---- HTML and XML ------------------------------------------------------------------------------------------------

export interface Chunk {
  kind: 'open' | 'close' | 'self' | 'decl' | 'comment' | 'text' | 'raw';
  name: string;
  tokens: Token[];
}

const isTagStart = (c: string | undefined) => c !== undefined && (isWordStart(c) || c === '/' || c === '!' || c === '?');

/** Scan one tag starting at `s[i] === '<'`. Always consumes at least the `<`. */
function scanTag(s: string, i: number): { end: number; chunk: Chunk } {
  const n = s.length;
  const tokens: Token[] = [];
  if (s[i + 1] === '!' || s[i + 1] === '?') {
    const e = s.indexOf('>', i + 2);
    const end = e < 0 ? n : e + 1;
    push(tokens, s.slice(i, end), 'tag');
    return { end, chunk: { kind: 'decl', name: '', tokens } };
  }
  push(tokens, '<', 'punct');
  let j = i + 1;
  const closing = s[j] === '/';
  if (closing) {
    push(tokens, '/', 'punct');
    j++;
  }
  let k = j;
  while (k < n && !isWs(s[k]) && s[k] !== '/' && s[k] !== '>') k++;
  const name = s.slice(j, k);
  push(tokens, name, 'tag');
  j = k;
  let self = false;
  let afterEq = false;
  while (j < n && s[j] !== '>') {
    const ch = s[j]!;
    if (isWs(ch)) {
      let e = j + 1;
      while (e < n && isWs(s[e])) e++;
      push(tokens, s.slice(j, e), '');
      j = e;
    } else if (ch === '/') {
      self = s[j + 1] === '>';
      push(tokens, '/', 'punct');
      j++;
    } else if (ch === '=') {
      push(tokens, '=', 'punct');
      afterEq = true;
      j++;
    } else if (ch === '"' || ch === "'") {
      const e = s.indexOf(ch, j + 1);
      if (e >= 0 && e - j <= MAX_ATTR_VALUE) {
        push(tokens, s.slice(j, e + 1), 'string');
        j = e + 1;
      } else {
        push(tokens, ch, '');
        j++;
      }
      afterEq = false;
    } else {
      let e = j + 1;
      while (e < n && !isWs(s[e]) && s[e] !== '=' && s[e] !== '/' && s[e] !== '>' && s[e] !== '"' && s[e] !== "'") e++;
      push(tokens, s.slice(j, e), afterEq ? 'string' : 'attr');
      afterEq = false;
      j = e;
    }
  }
  if (j < n) {
    push(tokens, '>', 'punct');
    j++;
  }
  const kind = closing ? 'close' : self ? 'self' : 'open';
  return { end: j, chunk: { kind, name: name.toLowerCase(), tokens } };
}

export function scanHtml(s: string): Chunk[] {
  const out: Chunk[] = [];
  const n = s.length;
  let i = 0;
  while (i < n) {
    if (s.startsWith('<!--', i)) {
      const e = s.indexOf('-->', i + 4);
      const end = e < 0 ? n : e + 3;
      out.push({ kind: 'comment', name: '', tokens: [{ t: s.slice(i, end), c: 'comment' }] });
      i = end;
    } else if (s[i] === '<' && isTagStart(s[i + 1])) {
      const { end, chunk } = scanTag(s, i);
      out.push(chunk);
      i = end;
      if (chunk.kind === 'open' && (chunk.name === 'script' || chunk.name === 'style')) {
        // The body of script and style is not markup: it runs to the matching close tag.
        const re = new RegExp(`</${chunk.name}`, 'gi');
        re.lastIndex = i;
        const m = re.exec(s);
        const stop = m ? m.index : n;
        if (stop > i) {
          const raw = s.slice(i, stop);
          out.push({ kind: 'raw', name: chunk.name, tokens: chunk.name === 'script' ? lexJs(raw) : [{ t: raw, c: '' }] });
        }
        i = stop;
      }
    } else {
      let j = i + 1;
      while (j < n && s[j] !== '<') j++;
      out.push({ kind: 'text', name: '', tokens: [{ t: s.slice(i, j), c: '' }] });
      i = j;
    }
  }
  return out;
}

export function lexHtml(s: string): Token[] {
  const out: Token[] = [];
  for (const c of scanHtml(s)) for (const t of c.tokens) push(out, t.t, t.c);
  return out;
}

// ---- HTTP start line and headers ---------------------------------------------------------------------------------

export function lexHttpHead(s: string): Token[] {
  const out: Token[] = [];
  const lines = s.split('\n');
  lines.forEach((line, idx) => {
    if (idx > 0) push(out, '\n', '');
    if (idx === 0) startLine(out, line);
    else headerLine(out, line);
  });
  return out;
}

function startLine(out: Token[], line: string) {
  const a = line.indexOf(' ');
  if (a < 0) return push(out, line, '');
  const first = line.slice(0, a);
  if (first.startsWith('HTTP/')) {
    // Response: HTTP/1.1 200 OK
    push(out, first, 'punct');
    push(out, ' ', '');
    const b = line.indexOf(' ', a + 1);
    const code = b < 0 ? line.slice(a + 1) : line.slice(a + 1, b);
    push(out, code, 'number');
    if (b >= 0) push(out, line.slice(b), '');
    return;
  }
  // Request: GET /path HTTP/1.1
  push(out, first, 'tag');
  push(out, ' ', '');
  const b = line.lastIndexOf(' ');
  if (b > a) {
    push(out, line.slice(a + 1, b), 'string');
    push(out, ' ', '');
    push(out, line.slice(b + 1), 'punct');
  } else {
    push(out, line.slice(a + 1), 'string');
  }
}

function headerLine(out: Token[], line: string) {
  const c = line.indexOf(':');
  if (c <= 0 || /\s/.test(line.slice(0, c))) return push(out, line, '');
  push(out, line.slice(0, c), 'hname');
  push(out, ':', 'punct');
  let k = c + 1;
  while (k < line.length && (line[k] === ' ' || line[k] === '\t')) k++;
  push(out, line.slice(c + 1, k), '');
  push(out, line.slice(k), 'hvalue');
}

// ---- Entry points ------------------------------------------------------------------------------------------------

export function lex(text: string, lang: Lang): Token[] {
  switch (lang) {
    case 'json': return lexJson(text);
    case 'html':
    case 'xml': return lexHtml(text);
    case 'form': return lexForm(text);
    case 'js': return lexJs(text);
    case 'http': return lexHttpHead(text);
    default: return text ? [{ t: text, c: '' }] : [];
  }
}

/** Split tokens into display lines. A carriage return before a line break is not shown. */
export function toLines(tokens: Token[]): Line[] {
  const lines: Line[] = [[]];
  for (const tk of tokens) {
    let rest = tk.t;
    for (;;) {
      const nl = rest.indexOf('\n');
      const cur = lines[lines.length - 1]!;
      if (nl < 0) {
        if (rest) cur.push({ t: rest, c: tk.c });
        break;
      }
      if (nl > 0) cur.push({ t: rest.slice(0, nl), c: tk.c });
      lines.push([]);
      rest = rest.slice(nl + 1);
    }
  }
  for (const line of lines) {
    const last = line[line.length - 1];
    if (last && last.t.endsWith('\r')) {
      last.t = last.t.slice(0, -1);
      if (!last.t) line.pop();
    }
  }
  return lines;
}

const lineLength = (l: Line) => l.reduce((a, t) => a + t.t.length, 0);

/** Highlighted lines for a text. Over the size cap, or for a line over the line cap, the text is shown plain. */
export function highlight(text: string, lang: Lang): Line[] {
  const lines = toLines(text.length > MAX_HIGHLIGHT ? lex(text, 'plain') : lex(text, lang));
  return lines.map((l) => (lineLength(l) > MAX_LINE ? [{ t: l.map((t) => t.t).join(''), c: '' as Cls }] : l));
}

/** Pick a language from a Content-Type value, falling back to what the body looks like. */
export function detectLang(contentType: string | null, body: string): Lang {
  const ct = (contentType ?? '').toLowerCase();
  if (ct.includes('json')) return 'json';
  if (ct.includes('html')) return 'html';
  if (ct.includes('xml') || ct.includes('svg')) return 'xml';
  if (ct.includes('x-www-form-urlencoded')) return 'form';
  if (ct.includes('javascript') || ct.includes('ecmascript')) return 'js';
  if (ct && !ct.startsWith('text/plain') && !ct.includes('octet-stream')) return 'plain';
  const head = body.slice(0, 256).trimStart().toLowerCase();
  if (head.startsWith('{') || head.startsWith('[')) return 'json';
  if (head.startsWith('<!doctype html') || head.startsWith('<html')) return 'html';
  if (head.startsWith('<?xml') || head.startsWith('<')) return 'xml';
  return 'plain';
}

/** The Content-Type value in the head of an HTTP message, if there is one. */
export function contentTypeOf(head: string): string | null {
  const m = /^content-type:[ \t]*([^\r\n]*)/im.exec(head);
  return m ? m[1]!.trim() : null;
}

/** Split a message's text at its first blank line. `sep` says whether there was one. */
export function splitText(text: string): { head: string; body: string; sep: boolean } {
  const m = /\r?\n\r?\n/.exec(text);
  return m ? { head: text.slice(0, m.index), body: text.slice(m.index + m[0].length), sep: true } : { head: text, body: '', sep: false };
}

/** Lines for a whole message: the head, a blank line, then the body in the language its Content-Type names. */
export function highlightMessage(text: string): { lines: Line[]; lang: Lang; body: string } {
  const { head, body, sep } = splitText(text);
  const lang = detectLang(contentTypeOf(head), body);
  const headLines = highlight(head, 'http');
  if (!sep) return { lines: headLines, lang, body };
  return { lines: [...headLines, [], ...highlight(body, lang)], lang, body };
}
