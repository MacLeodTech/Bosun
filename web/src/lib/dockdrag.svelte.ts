// Dragging a tab onto a group. Pointer events rather than HTML5 drag and drop: no browser drag image, the same
// behaviour in every browser and the desktop webview, and the drop zones can be drawn exactly where they act.
//
// Each group registers its tab strip and body here; while a drag runs, the pointer position is turned into a
// target (a group and a zone, or the window edge) and a rectangle to highlight.

import { groupOfTab, type Zone } from './layout';
import { workspace } from './workspace.svelte';

interface Rect { left: number; top: number; width: number; height: number }
export interface DropTarget {
  /** null: the whole window. */
  groupId: string | null;
  zone: Zone;
  index?: number;
  /** What to highlight, in viewport coordinates. */
  rect: Rect;
}

const THRESHOLD = 4;
/** How close to the dock's own edge (px) a drop counts as a window-edge drop. */
const WINDOW_EDGE = 18;
/** How close to a group's edge (fraction of its size) a drop splits it instead of joining it. */
const GROUP_EDGE = 0.27;

class DockDrag {
  active = $state(false);
  label = $state('');
  x = $state(0);
  y = $state(0);
  target = $state<DropTarget | null>(null);
  /** Set for a moment after a drag ends, so the click that follows the release does not activate a tab. */
  justDragged = false;

  private dock: HTMLElement | null = null;
  private groups = new Map<string, { strip: HTMLElement; body: HTMLElement }>();

  registerDock(el: HTMLElement | null) {
    this.dock = el;
  }
  registerGroup(id: string, strip: HTMLElement, body: HTMLElement) {
    this.groups.set(id, { strip, body });
    return () => {
      if (this.groups.get(id)?.strip === strip) this.groups.delete(id);
    };
  }

  /** Called on pointerdown on a tab. The drag starts once the pointer has moved a few pixels. */
  begin(e: PointerEvent, tabId: string, label: string) {
    if (e.button !== 0) return;
    const sx = e.clientX;
    const sy = e.clientY;
    const startPointer = e.pointerId;
    const cleanup = () => {
      window.removeEventListener('pointermove', move, true);
      window.removeEventListener('pointerup', up, true);
      window.removeEventListener('pointercancel', cancel, true);
      window.removeEventListener('keydown', key, true);
    };
    const finish = (drop: boolean) => {
      cleanup();
      if (this.active) {
        this.justDragged = true;
        setTimeout(() => (this.justDragged = false), 0);
        const t = this.target;
        if (drop && t) workspace.move(tabId, t.groupId, t.zone, t.index);
      }
      this.active = false;
      this.target = null;
    };
    const move = (ev: PointerEvent) => {
      if (ev.pointerId !== startPointer) return;
      if (!this.active) {
        if (Math.hypot(ev.clientX - sx, ev.clientY - sy) < THRESHOLD) return;
        this.active = true;
        this.label = label;
      }
      this.x = ev.clientX;
      this.y = ev.clientY;
      this.target = this.locate(ev.clientX, ev.clientY, tabId);
    };
    const up = (ev: PointerEvent) => {
      if (ev.pointerId === startPointer) finish(true);
    };
    const cancel = () => finish(false);
    const key = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape' && this.active) {
        ev.preventDefault();
        ev.stopPropagation();
        finish(false);
      }
    };
    window.addEventListener('pointermove', move, true);
    window.addEventListener('pointerup', up, true);
    window.addEventListener('pointercancel', cancel, true);
    window.addEventListener('keydown', key, true);
  }

  private locate(x: number, y: number, tabId: string): DropTarget | null {
    const root = workspace.root;
    const dock = this.dock?.getBoundingClientRect();
    if (!root || !dock || x < dock.left || x > dock.right || y < dock.top || y > dock.bottom) return null;
    const own = groupOfTab(root, tabId);
    const onlyTab = !!own && own.tabs.length === 1;

    // The window edge wins, so a full-width split is always reachable even over a group's own edge.
    const dl = x - dock.left, dr = dock.right - x, dt = y - dock.top, db = dock.bottom - y;
    const near = Math.min(dl, dr, dt, db);
    if (near <= WINDOW_EDGE) {
      const zone: Zone = near === dl ? 'left' : near === dr ? 'right' : near === dt ? 'top' : 'bottom';
      if (!(workspaceHasSingleTab(root))) {
        const w = zone === 'left' || zone === 'right';
        const rect: Rect = {
          left: zone === 'right' ? dock.left + dock.width * 0.6 : dock.left,
          top: zone === 'bottom' ? dock.top + dock.height * 0.6 : dock.top,
          width: w ? dock.width * 0.4 : dock.width,
          height: w ? dock.height : dock.height * 0.4,
        };
        return { groupId: null, zone, rect };
      }
    }

    for (const [id, { strip, body }] of this.groups) {
      const s = strip.getBoundingClientRect();
      const b = body.getBoundingClientRect();
      const inStrip = x >= s.left && x <= s.right && y >= s.top && y <= s.bottom;
      const inBody = x >= b.left && x <= b.right && y >= b.top && y <= b.bottom;
      if (!inStrip && !inBody) continue;
      const mine = id === own?.id;
      if (inStrip) {
        const els = [...strip.querySelectorAll<HTMLElement>('[role="tab"]')];
        const index = els.filter((el) => {
          const r = el.getBoundingClientRect();
          return r.left + r.width / 2 < x;
        }).length;
        if (mine && onlyTab) return null;
        return { groupId: id, zone: 'center', index, rect: { left: s.left, top: s.top, width: s.width, height: s.height } };
      }
      const fx = (x - b.left) / b.width, fy = (y - b.top) / b.height;
      const d = [fx, 1 - fx, fy, 1 - fy];
      const m = Math.min(...d);
      const full: Rect = { left: b.left, top: s.top, width: b.width, height: b.bottom - s.top };
      if (m >= GROUP_EDGE) return mine && onlyTab ? null : { groupId: id, zone: 'center', rect: full };
      const zone: Zone = m === d[0] ? 'left' : m === d[1] ? 'right' : m === d[2] ? 'top' : 'bottom';
      if (mine && onlyTab) return null;
      const horiz = zone === 'left' || zone === 'right';
      return {
        groupId: id,
        zone,
        rect: {
          left: zone === 'right' ? b.left + b.width / 2 : b.left,
          top: zone === 'bottom' ? b.top + b.height / 2 : s.top,
          width: horiz ? b.width / 2 : b.width,
          height: horiz ? b.bottom - s.top : (b.bottom - s.top) / 2,
        },
      };
    }
    return null;
  }
}

function workspaceHasSingleTab(root: NonNullable<typeof workspace.root>): boolean {
  let n = 0;
  const walk = (x: typeof root): void => {
    if (x.kind === 'group') n += x.tabs.length;
    else x.children.forEach(walk);
  };
  walk(root);
  return n <= 1;
}

export const dockDrag = new DockDrag();
