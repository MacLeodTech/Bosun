// A panel stays mounted while its tab is in the background. Anything a panel does on its own (a window-level key
// handler, for one) must check that it is the one on screen. The dock puts a `{ visible }` object in context.
import { getContext, setContext } from 'svelte';

const KEY = Symbol('bosun.panel');
export interface PanelCtx { readonly visible: boolean }

export function providePanel(ctx: PanelCtx) {
  setContext(KEY, ctx);
}

/** The panel this component sits in. Outside the dock (a test, say) it counts as visible. */
export function usePanel(): PanelCtx {
  return getContext<PanelCtx | undefined>(KEY) ?? { visible: true };
}
