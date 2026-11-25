// Addresses of the form `#<panel>` or `#<panel>?flow=<id>`, so a link or a reload opens the same panel and request.
// Anything else (such as the first-run `#setup=...` link) is not ours and parses to nothing.

export interface Link { panel: string | null; flow: number | null }

export function parseHash(hash: string, isPanel: (id: string) => boolean): Link {
  const h = hash.replace(/^#/, '');
  const q = h.indexOf('?');
  const name = q < 0 ? h : h.slice(0, q);
  const panel = isPanel(name) ? name : null;
  let flow: number | null = null;
  if (panel && q >= 0) {
    const m = /^flow=(\d{1,12})$/.exec(h.slice(q + 1));
    if (m) flow = Number(m[1]);
  }
  return { panel, flow };
}

export function buildHash(panel: string, flow: number | null): string {
  return `#${panel}${flow !== null ? `?flow=${flow}` : ''}`;
}
