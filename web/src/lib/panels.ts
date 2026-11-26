// The panel registry: every kind of panel the dock can host. Adding a tool is one entry here (plus its component).
import type { Component } from 'svelte';
import History from '../pages/History.svelte';
import FlowDetail from '../pages/FlowDetail.svelte';
import Intercept from '../pages/Intercept.svelte';
import Repeater from '../pages/Repeater.svelte';
import Decoder from '../pages/Decoder.svelte';
import Comparer from '../pages/Comparer.svelte';
import Findings from '../pages/Findings.svelte';
import Organizer from '../pages/Organizer.svelte';
import Rules from '../pages/Rules.svelte';
import Target from '../pages/Target.svelte';
import Projects from '../pages/Projects.svelte';
import Settings from '../pages/Settings.svelte';
import { shell } from './shell.svelte';

export interface PanelDef {
  id: string;
  title: string;
  component: Component;
  /** A number shown on the tab and the launcher button; 0 shows nothing. */
  badge?: () => number;
}

/** In launcher order. All panels are singletons for now: one tab per kind. */
export const panels: PanelDef[] = [
  { id: 'intercept', title: 'Intercept', component: Intercept, badge: () => shell.held },
  { id: 'history', title: 'HTTP history', component: History },
  { id: 'flow', title: 'Request / response', component: FlowDetail },
  { id: 'repeater', title: 'Repeater', component: Repeater },
  { id: 'organizer', title: 'Organizer', component: Organizer },
  { id: 'findings', title: 'Findings', component: Findings },
  { id: 'decoder', title: 'Decoder', component: Decoder },
  { id: 'comparer', title: 'Comparer', component: Comparer },
  { id: 'rules', title: 'Match & replace', component: Rules },
  { id: 'target', title: 'Target', component: Target },
  { id: 'projects', title: 'Projects', component: Projects },
  { id: 'settings', title: 'Settings', component: Settings },
];

export const panelById = (id: string): PanelDef | undefined => panels.find((p) => p.id === id);
