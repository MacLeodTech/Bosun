// Keyboard shortcuts as data: parse "Ctrl+Shift+S", match a KeyboardEvent against it, show it, and report conflicts
// (two commands on one key, or a key the browser or the desktop shell keeps for itself).

export interface Key { ctrl: boolean; shift: boolean; alt: boolean; key: string }

const ALIASES: Record<string, string> = { esc: 'escape', del: 'delete', return: 'enter', space: ' ', up: 'arrowup', down: 'arrowdown', left: 'arrowleft', right: 'arrowright' };

/** "Ctrl+Shift+S" to a Key; null when it has no key or an unknown modifier. Ctrl also stands for Cmd. */
export function parseKeys(spec: string): Key | null {
  const parts = spec.split('+').map((p) => p.trim());
  // A literal "+" key is written "Ctrl++": the split leaves an empty last part.
  const last = spec.endsWith('++') ? '+' : parts[parts.length - 1]!;
  const mods = spec.endsWith('++') ? parts.slice(0, -2) : parts.slice(0, -1);
  const k: Key = { ctrl: false, shift: false, alt: false, key: '' };
  for (const m of mods) {
    const l = m.toLowerCase();
    if (l === 'ctrl' || l === 'cmd' || l === 'meta') k.ctrl = true;
    else if (l === 'shift') k.shift = true;
    else if (l === 'alt' || l === 'option') k.alt = true;
    else return null;
  }
  if (!last) return null;
  const l = last.toLowerCase();
  k.key = ALIASES[l] ?? l;
  return k;
}

export const canonical = (k: Key) => [k.ctrl ? 'ctrl' : '', k.alt ? 'alt' : '', k.shift ? 'shift' : '', k.key].filter(Boolean).join('+');

interface KeyEventLike { key: string; code?: string; ctrlKey: boolean; metaKey: boolean; shiftKey: boolean; altKey: boolean }

/** Whether an event is exactly this key and these modifiers. Digits also match by physical key, for Alt+1 on a Mac. */
export function matches(e: KeyEventLike, k: Key): boolean {
  if ((e.ctrlKey || e.metaKey) !== k.ctrl || e.shiftKey !== k.shift || e.altKey !== k.alt) return false;
  if (e.key.toLowerCase() === k.key) return true;
  return /^[0-9]$/.test(k.key) && e.code === `Digit${k.key}`;
}

/** What to show for a spec, e.g. "Ctrl+Shift+S". */
export function format(spec: string): string {
  return spec.replace(/\bArrow(Up|Down|Left|Right)\b/g, (_, d: string) => ({ Up: '↑', Down: '↓', Left: '←', Right: '→' })[d]!);
}

/** Keys that a browser (or the desktop webview) handles before the page sees them, and what they do. */
export const RESERVED: Record<string, string> = {
  'ctrl+t': 'new browser tab', 'ctrl+w': 'close browser tab', 'ctrl+n': 'new browser window', 'ctrl+shift+n': 'new private window',
  'ctrl+shift+t': 'reopen closed tab', 'ctrl+shift+w': 'close browser window', 'ctrl+tab': 'next browser tab', 'ctrl+l': 'address bar',
  'ctrl+shift+i': 'developer tools', 'ctrl+shift+j': 'developer console', 'ctrl+shift+c': 'inspect element', 'f5': 'reload', 'f11': 'full screen',
  'f12': 'developer tools', 'ctrl+q': 'quit browser', 'alt+arrowleft': 'browser back', 'alt+arrowright': 'browser forward', 'alt+f4': 'close window',
};

export interface Binding { id: string; keys: string }
export interface Conflicts {
  /** Several commands on the same key. */
  duplicates: { keys: string; ids: string[] }[];
  /** Commands on a key the browser keeps. */
  reserved: { id: string; keys: string; why: string }[];
  /** A spec that could not be read. */
  invalid: { id: string; keys: string }[];
}

export function conflicts(bindings: Binding[]): Conflicts {
  const by = new Map<string, string[]>();
  const out: Conflicts = { duplicates: [], reserved: [], invalid: [] };
  for (const b of bindings) {
    const k = parseKeys(b.keys);
    if (!k) {
      out.invalid.push({ id: b.id, keys: b.keys });
      continue;
    }
    const c = canonical(k);
    by.set(c, [...(by.get(c) ?? []), b.id]);
    const why = RESERVED[c];
    if (why) out.reserved.push({ id: b.id, keys: b.keys, why });
  }
  for (const [keys, ids] of by) if (ids.length > 1) out.duplicates.push({ keys, ids });
  return out;
}
