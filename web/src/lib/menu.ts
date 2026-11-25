// Items for a menu (the header's Layout menu now, context menus later).
export type MenuItem =
  | { kind?: 'item'; label: string; run: () => void; disabled?: boolean; checked?: boolean; hint?: string }
  | { kind: 'heading'; label: string }
  | { kind: 'sep' };

/** Drop what would look wrong: separators at the ends or doubled, and headings with nothing under them. */
export function tidyMenu(items: (MenuItem | null | undefined | false)[]): MenuItem[] {
  const real = items.filter((i): i is MenuItem => !!i);
  const out: MenuItem[] = [];
  for (let k = 0; k < real.length; k++) {
    const it = real[k]!;
    if (it.kind === 'heading') {
      const next = real[k + 1];
      if (!next || next.kind === 'heading' || next.kind === 'sep') continue;
    }
    if (it.kind === 'sep' && (!out.length || out[out.length - 1]!.kind === 'sep')) continue;
    out.push(it);
  }
  while (out.length && out[out.length - 1]!.kind === 'sep') out.pop();
  return out;
}
