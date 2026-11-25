// Pop-out windows: how they are named, found in the address, and stored. Pure, so it can be tested.
//
// A pop-out is this same app at `#/popout/<id>`, opened with window.open. It is same-origin, so it shares the session
// cookie, fetches its own CSRF token and opens its own event stream. Windows talk over a BroadcastChannel, and what
// they say is only ever flow ids, panel names and window ids.

const ID = /^[A-Za-z0-9_-]{4,40}$/;

export const CHANNEL = 'bosun-workspace';
export const KEY_PREFIX = 'bosun.window.';

export function isWindowId(s: unknown): s is string {
  return typeof s === 'string' && ID.test(s);
}

/** The id in `#/popout/<id>`, or null when this is the main window. */
export function parsePopout(hash: string): string | null {
  const m = /^#\/popout\/([^/?#]+)$/.exec(hash);
  return m && isWindowId(m[1]) ? m[1] : null;
}

export const popoutHash = (id: string) => `#/popout/${id}`;
export const windowKey = (id: string) => `${KEY_PREFIX}${id}.v1`;

/** The window id inside a storage key made by `windowKey`, or null for any other key. */
export function idFromKey(key: string): string | null {
  const m = /^bosun\.window\.([A-Za-z0-9_-]{4,40})\.v1$/.exec(key);
  return m ? m[1]! : null;
}

export type Msg =
  | { type: 'select'; from: string; selected: number[]; selectedId: number | null; openId: number | null }
  | { type: 'alive'; id: string }
  | { type: 'return'; id: string };

const ids = (x: unknown): x is number[] => Array.isArray(x) && x.length <= 5000 && x.every((n) => Number.isInteger(n) && n > 0);

/** A message from the channel, if it is one of ours and well formed; anything else is dropped. */
export function parseMsg(x: unknown): Msg | null {
  if (typeof x !== 'object' || x === null) return null;
  const m = x as Record<string, unknown>;
  if (m.type === 'select' && isWindowId(m.from) && ids(m.selected)) {
    const one = (v: unknown) => (v === null || (Number.isInteger(v) && (v as number) > 0) ? (v as number | null) : undefined);
    const selectedId = one(m.selectedId);
    const openId = one(m.openId);
    if (selectedId === undefined || openId === undefined) return null;
    return { type: 'select', from: m.from, selected: m.selected, selectedId, openId };
  }
  if ((m.type === 'alive' || m.type === 'return') && isWindowId(m.id)) return { type: m.type, id: m.id };
  return null;
}

/** A fresh id for a window (or for the main window's own messages). */
export function newWindowId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  return [...bytes].map((b) => b.toString(36).padStart(2, '0')).join('').slice(0, 14);
}
