// What the History page shows, kept outside the component so it survives a trip to another page and back.
// (The page is torn down on every tab switch; the dock work in Phase 1 will make that unnecessary.)

export type DetailTab = 'messages' | 'original' | 'ws';

class HistoryView {
  text = $state('');
  host = $state('');
  methods = $state('');
  statusMin = $state<number | undefined>();
  statusMax = $state<number | undefined>();
  inScopeOnly = $state(false);
  hideExt = $state('png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,css');
  /** The open flow, reopened when the page comes back. */
  selectedId = $state<number | null>(null);
  detailTab = $state<DetailTab>('messages');

  /** Another project was opened: nothing here refers to it. */
  reset() {
    this.selectedId = null;
    this.detailTab = 'messages';
  }
}

export const historyView = new HistoryView();
