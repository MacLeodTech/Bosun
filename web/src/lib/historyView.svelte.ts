// What the History panels show, kept outside the components so it survives a panel being closed and reopened, and so
// the list and the flow-detail panel (two separate panels in the dock) agree on what is open.

export type DetailTab = 'messages' | 'original' | 'ws';

class HistoryView {
  text = $state('');
  host = $state('');
  methods = $state('');
  statusMin = $state<number | undefined>();
  statusMax = $state<number | undefined>();
  inScopeOnly = $state(false);
  hideExt = $state('png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,css');
  /** The highlighted row. Follows the arrow keys at once. */
  selectedId = $state<number | null>(null);
  /** The flow the detail panel loads. Trails `selectedId` while the user is still moving through the list. */
  openId = $state<number | null>(null);
  detailTab = $state<DetailTab>('messages');
  /** Flows deleted from the detail panel, for the list to drop. `removedTick` changes on each deletion. */
  removedIds = $state<number[]>([]);
  removedTick = $state(0);

  remove(ids: number[]) {
    this.removedIds = ids;
    this.removedTick++;
    if (this.selectedId !== null && ids.includes(this.selectedId)) this.selectedId = null;
    if (this.openId !== null && ids.includes(this.openId)) this.openId = null;
  }

  /** Another project was opened: nothing here refers to it. */
  reset() {
    this.selectedId = null;
    this.openId = null;
    this.detailTab = 'messages';
  }
}

export const historyView = new HistoryView();
