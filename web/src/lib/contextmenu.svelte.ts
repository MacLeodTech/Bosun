// The one open context menu, if any. `ContextMenu.svelte` (mounted once in App) draws it.
import { tidyMenu, type MenuItem } from './menu';

class ContextMenuState {
  open = $state<{ x: number; y: number; items: MenuItem[]; label: string } | null>(null);
  /** What had focus before, so closing the menu with the keyboard puts focus back. */
  opener: HTMLElement | null = null;

  show(items: MenuItem[], x: number, y: number, label: string) {
    const real = tidyMenu(items);
    if (!real.some((i) => i.kind !== 'sep' && i.kind !== 'heading')) return;
    this.opener = document.activeElement as HTMLElement | null;
    this.open = { x, y, items: real, label };
  }

  close(refocus = true) {
    this.open = null;
    if (refocus) this.opener?.focus();
    this.opener = null;
  }
}

export const contextMenu = new ContextMenuState();
