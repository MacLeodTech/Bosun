// The ids of the panels, kept apart from the registry (panels.ts) so the workspace store can validate a saved layout
// without importing every page component (which would be an import cycle: pages open panels through the store).
export const PANEL_IDS = ['intercept', 'history', 'flow', 'repeater', 'rules', 'target', 'projects', 'settings'] as const;
export type PanelId = (typeof PANEL_IDS)[number];
export const isPanelId = (id: string): id is PanelId => (PANEL_IDS as readonly string[]).includes(id);
