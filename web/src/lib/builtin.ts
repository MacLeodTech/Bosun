// The commands that ship with the UI. A tool panel registers its own the same way (`commands.register([...])`), and
// removes them when it goes. Commands that need a panel which does not exist yet (Decoder, Compare) are simply absent.

import { api } from './api';
import { commands, type Command } from './commands.svelte';
import { copyAsCurl, copyMessage, copyRequestAs, copyUrls, deleteFlows, exportHar, saveToOrganizer, scopeHosts, sendToComparer, sendToDecoder, sendToRepeater } from './flowactions';
import { SNIPPETS } from './export';
import { panels } from './panels';
import { prefs } from './prefs.svelte';
import { session } from './session.svelte';
import { shell } from './shell.svelte';
import { theme } from './theme.svelte';
import { windows } from './windows.svelte';
import { builtinPresets, workspace } from './workspace.svelte';
import type { InterceptSettings } from './types';

const tester = () => session.can('tester');
const hasFlows = (c: { flows: number[] }) => c.flows.length > 0;

export function registerBuiltins(): () => void {
  const list: Command[] = [];

  // Panels: open one, and Alt+1..9 to go to the nth pane.
  for (const p of panels) {
    list.push({ id: `panel.open.${p.id}`, title: `Open ${p.title}`, group: 'Panels', run: () => workspace.open(p.id) });
  }
  for (let n = 1; n <= 9; n++) {
    list.push({ id: `pane.focus.${n}`, title: `Focus pane ${n}`, group: 'Panels', keys: `Alt+${n}`, anywhere: true, when: () => workspace.groupCount() >= n, run: () => workspace.focusGroup(n - 1) });
  }

  // Layout.
  for (const p of builtinPresets) {
    list.push({ id: `layout.preset.${p.id}`, title: `Layout: ${p.label}`, group: 'Layout', run: () => workspace.apply(p.id) });
  }
  list.push(
    { id: 'layout.reset', title: 'Layout: reset to the default', group: 'Layout', run: () => workspace.reset() },
    { id: 'layout.manage', title: 'Layout: save or manage layouts', group: 'Layout', run: () => { shell.layoutDialog = true; } },
    { id: 'layout.split-right', title: 'Move this tab into a pane on the right', group: 'Layout', keys: 'Ctrl+\\', anywhere: true, run: () => workspace.moveActive('right') },
    { id: 'layout.move-left', title: 'Move this tab left', group: 'Layout', keys: 'Alt+Shift+ArrowLeft', anywhere: true, run: () => workspace.moveActive('left') },
    { id: 'layout.move-right', title: 'Move this tab right', group: 'Layout', keys: 'Alt+Shift+ArrowRight', anywhere: true, run: () => workspace.moveActive('right') },
    { id: 'layout.move-up', title: 'Move this tab up', group: 'Layout', keys: 'Alt+Shift+ArrowUp', anywhere: true, run: () => workspace.moveActive('up') },
    { id: 'layout.move-down', title: 'Move this tab down', group: 'Layout', keys: 'Alt+Shift+ArrowDown', anywhere: true, run: () => workspace.moveActive('down') },
    {
      id: 'layout.maximize',
      title: 'Maximise or restore this pane',
      group: 'Layout',
      keys: 'Ctrl+Shift+\\',
      anywhere: true,
      run: () => {
        const g = workspace.root && workspace.focused;
        if (g) workspace.toggleMaximize(g);
      },
    },
    {
      id: 'window.popout',
      title: 'Move this tab to a new window',
      group: 'Layout',
      when: () => !windows.isPopout && workspace.activeTabId() !== null,
      run: () => {
        const t = workspace.activeTabId();
        if (t) windows.popOut(t);
      },
    },
    { id: 'window.return', title: 'Return this window to the main window', group: 'Layout', when: () => windows.isPopout, run: () => windows.returnToMain() },
    { id: 'layout.close-tab', title: 'Close this tab', group: 'Layout', run: () => { const t = workspace.activeTabId(); if (t) workspace.close(t); } },
  );

  // General.
  list.push(
    { id: 'palette.open', title: 'Command palette', group: 'General', keys: 'Ctrl+K', anywhere: true, run: () => { shell.paletteStart = ''; shell.palette = true; } },
    { id: 'help.shortcuts', title: 'Keyboard shortcuts', group: 'General', run: () => { shell.help = true; } },
    { id: 'theme.cycle', title: 'Change the colour theme', group: 'General', run: () => theme.cycle() },
    {
      id: 'intercept.toggle',
      title: 'Turn request interception on or off',
      group: 'Intercept',
      keys: 'Ctrl+Alt+I',
      anywhere: true,
      when: tester,
      run: async () => {
        const s = await api.get<InterceptSettings>('/intercept');
        await api.put('/intercept', { ...s, requests: !s.requests });
      },
    },
    {
      id: 'history.focus-filter',
      title: 'Focus the History filter',
      group: 'History',
      run: () => {
        workspace.open('history');
        setTimeout(() => document.querySelector<HTMLInputElement>('input[aria-label="Filter"]')?.focus(), 0);
      },
    },
  );

  // Requests: these act on the selected flows (ids only).
  list.push(
    {
      id: 'flow.repeater',
      title: 'Send to Repeater',
      group: 'Request',
      keys: 'Ctrl+R',
      when: (c) => tester() && hasFlows(c),
      run: async (c) => {
        await sendToRepeater(c.flows);
        workspace.open('repeater');
      },
    },
    ...(['request', 'response'] as const).map((part): Command => ({
      id: `flow.decoder.${part}`,
      title: `Send ${part} to Decoder`,
      group: 'Request',
      when: (c) => c.focus !== null,
      run: async (c) => {
        if (await sendToDecoder(c.focus!, part)) workspace.open('decoder');
      },
    })),
    ...(['request', 'response'] as const).flatMap((part) =>
      (['a', 'b'] as const).map((side): Command => ({
        id: `flow.comparer.${part}.${side}`,
        title: `Send ${part} to Comparer as ${side.toUpperCase()}`,
        group: 'Request',
        when: (c) => c.focus !== null,
        run: async (c) => {
          if (await sendToComparer(c.focus!, part, side)) workspace.open('comparer');
        },
      })),
    ),
    { id: 'flow.organize', title: 'Save to Organizer', group: 'Request', when: (c) => tester() && hasFlows(c), run: (c) => saveToOrganizer(c.flows) },
    { id: 'flow.copy-curl-powershell', title: 'Copy as PowerShell command', group: 'Request', when: (c) => c.focus !== null, run: (c) => copyRequestAs(c.focus!, 'curl-powershell') },
    ...SNIPPETS.map((sn): Command => ({ id: `flow.snippet.${sn.id}`, title: `Copy as ${sn.label}`, group: 'Request', when: (c) => c.focus !== null, run: (c) => copyRequestAs(c.focus!, sn.id) })),
    { id: 'flow.export-har', title: 'Export requests as HAR', group: 'Request', when: hasFlows, run: (c) => exportHar(c.flows) },
    { id: 'export.secrets', title: 'Toggle keeping cookies and authorization values in copies and exports', group: 'Request', run: () => prefs.setExportSecrets(!prefs.exportSecrets) },
    { id: 'flow.copy-url', title: 'Copy URL', group: 'Request', when: hasFlows, run: (c) => copyUrls(c.flows) },
    { id: 'flow.copy-curl', title: 'Copy as cURL', group: 'Request', when: (c) => c.focus !== null, run: (c) => copyAsCurl(c.focus!) },
    { id: 'flow.copy-request', title: 'Copy request', group: 'Request', when: (c) => c.focus !== null, run: (c) => copyMessage(c.focus!, 'request') },
    { id: 'flow.copy-response', title: 'Copy response', group: 'Request', when: (c) => c.focus !== null, run: (c) => copyMessage(c.focus!, 'response') },
    { id: 'flow.scope.include', title: 'Add host to scope', group: 'Request', keys: 'Ctrl+Shift+S', when: (c) => tester() && hasFlows(c), run: (c) => scopeHosts(c.flows, 'include') },
    { id: 'flow.scope.exclude', title: 'Exclude host from scope', group: 'Request', when: (c) => tester() && hasFlows(c), run: (c) => scopeHosts(c.flows, 'exclude') },
    { id: 'flow.delete', title: 'Delete requests', group: 'Request', when: (c) => tester() && hasFlows(c), run: (c) => deleteFlows(c.flows) },
  );

  return commands.register(list);
}
