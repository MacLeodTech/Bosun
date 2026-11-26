// What the History panels show, kept outside the components so it survives a panel being closed and reopened, and so
// the list, the flow-detail panel and the command palette agree on what is selected and open.

import { DEFAULT_QUERY } from './query';
import { normalizeCols, type ColKey, type SortKey } from './histcols';

const COLS_KEY = 'bosun.history.columns.v1';
function readCols(): ColKey[] {
  try {
    return normalizeCols(JSON.parse(localStorage.getItem(COLS_KEY) ?? 'null'));
  } catch {
    return normalizeCols(null);
  }
}

export type DetailTab = 'messages' | 'original' | 'diff' | 'ws';

class HistoryView {
  /** The filter line as typed (not applied until Enter). */
  draft = $state(DEFAULT_QUERY);
  /** The filter line that is applied: what the list shows. */
  query = $state(DEFAULT_QUERY);
  /** The focused row (follows the arrow keys at once). Always one of `selected` unless nothing is selected. */
  selectedId = $state<number | null>(null);
  /** Every selected row, in the order they were picked. */
  selected = $state.raw<number[]>([]);
  /** The end of a shift-range that stays put while the other end moves. */
  anchorId = $state<number | null>(null);
  /** The flow the detail panel loads. Trails `selectedId` while the user is still moving through the list. */
  openId = $state<number | null>(null);
  /** Scanner evidence to highlight in the open flow's messages (set when an issue is opened from the Issues panel). */
  evidence = $state.raw<{ flowId: number; ranges: { part: 'request' | 'response'; start: number; end: number }[] } | null>(null);
  detailTab = $state<DetailTab>('messages');
  /** Flows deleted for good, for the list to drop. `removedTick` changes on each deletion. */
  removedIds = $state.raw<number[]>([]);
  removedTick = $state(0);
  /** Flows hidden during the undo window of a delete; they are removed on the server only when it passes. */
  pending = $state.raw<number[]>([]);
  /** The columns shown, in table order. A preference of this browser. */
  cols = $state<ColKey[]>(readCols());
  /** What the list is ordered by. The id, newest first, is the live view; anything else is a snapshot. */
  sort = $state<{ key: SortKey; asc: boolean }>({ key: 'id', asc: false });
  /** Tags just changed on the server: the list patches its rows instead of reloading. */
  tagChange = $state.raw<{ ids: number[]; add: string[]; remove: string[] } | null>(null);
  tagTick = $state(0);
  /** Bumped when something outside the list changes the filter and wants it applied. */
  applyTick = $state(0);

  /** Set the filter line and apply it. */
  setQuery(q: string) {
    this.draft = q;
    this.query = q;
    this.applyTick++;
  }

  setCols(cols: ColKey[]) {
    this.cols = normalizeCols(cols);
    try {
      localStorage.setItem(COLS_KEY, JSON.stringify(this.cols));
    } catch {
      // A column choice is never worth an error.
    }
  }

  setSort(s: { key: SortKey; asc: boolean }) {
    this.sort = s;
    this.applyTick++;
  }

  tagged(ids: number[], add: string[], remove: string[]) {
    this.tagChange = { ids, add, remove };
    this.tagTick++;
  }

  /** The flows commands act on: the selection, or the focused row when nothing is picked. */
  get ids(): number[] {
    return this.selected.length ? this.selected : this.selectedId !== null ? [this.selectedId] : [];
  }

  select(ids: number[], focus: number | null = ids[ids.length - 1] ?? null) {
    this.selected = ids;
    this.selectedId = focus;
    if (ids.length <= 1) this.anchorId = focus;
  }

  hide(ids: number[]) {
    this.pending = [...new Set([...this.pending, ...ids])];
    this.selected = this.selected.filter((i) => !ids.includes(i));
    if (this.selectedId !== null && ids.includes(this.selectedId)) this.selectedId = this.selected[this.selected.length - 1] ?? null;
    if (this.openId !== null && ids.includes(this.openId)) this.openId = null;
  }

  unhide(ids: number[]) {
    this.pending = this.pending.filter((i) => !ids.includes(i));
  }

  /** Deleted on the server: drop them from the list for good. */
  remove(ids: number[]) {
    this.removedIds = ids;
    this.removedTick++;
    this.unhide(ids);
    this.selected = this.selected.filter((i) => !ids.includes(i));
    if (this.selectedId !== null && ids.includes(this.selectedId)) this.selectedId = null;
    if (this.openId !== null && ids.includes(this.openId)) this.openId = null;
  }

  /** Another project was opened: nothing here refers to it. */
  reset() {
    this.selected = [];
    this.selectedId = null;
    this.anchorId = null;
    this.openId = null;
    this.pending = [];
    this.detailTab = 'messages';
  }
}

export const historyView = new HistoryView();
