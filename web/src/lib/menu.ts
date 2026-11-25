// Items for a menu (the header's Layout menu now, context menus later).
export type MenuItem =
  | { kind?: 'item'; label: string; run: () => void; disabled?: boolean; checked?: boolean; hint?: string }
  | { kind: 'heading'; label: string }
  | { kind: 'sep' };
