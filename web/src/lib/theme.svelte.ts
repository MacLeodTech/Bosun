// Theme preference: "system" follows the OS, "dark" and "light" force one. The choice is kept in localStorage.
// CSS only knows data-theme="dark|light" (see tokens.css), so "system" is resolved here.

export type ThemePref = 'system' | 'dark' | 'light';
const KEY = 'bosun.theme';
const order: ThemePref[] = ['system', 'dark', 'light'];

function read(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'dark' || v === 'light' || v === 'system' ? v : 'system';
  } catch {
    return 'system';
  }
}

class Theme {
  pref = $state<ThemePref>(read());
  private mql = window.matchMedia('(prefers-color-scheme: light)');

  constructor() {
    this.apply();
    this.mql.addEventListener('change', () => this.apply());
  }

  private apply() {
    const resolved = this.pref === 'system' ? (this.mql.matches ? 'light' : 'dark') : this.pref;
    document.documentElement.dataset.theme = resolved;
  }

  cycle() {
    this.pref = order[(order.indexOf(this.pref) + 1) % order.length]!;
    try {
      localStorage.setItem(KEY, this.pref);
    } catch {
      // Storage may be unavailable; the choice then lasts until reload.
    }
    this.apply();
  }
}

export const theme = new Theme();
