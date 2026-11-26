// Things you can do to flows by id. Every action fetches what it needs from the API by id, so the scope gate, the
// audit log and the role checks still apply, and no target content is kept in the page beyond what is shown.

import { api } from './api';
import { bytesToText, flowUrl } from './bytes';
import { buildCurl } from './curl';
import { concat, loadPart, type PartName } from './flowbody';
import { historyView as v } from './historyView.svelte';
import { inbox } from './inbox.svelte';
import { toasts } from './toasts.svelte';
import { withText } from './query';
import { workspace } from './workspace.svelte';
import type { FlowMeta, ScopeRule, ScopeSpec } from './types';

/** More than this at once is almost certainly a slip, and each one is a request to the server. */
const MAX_BULK = 20;

const fetchMeta = (id: number) => api.get<FlowMeta>(`/flows/${id}`);
const say = (text: string): void => {
  toasts.push({ text });
};
const fail = (e: unknown) => say(e instanceof Error ? e.message : String(e));

async function copy(text: string, what: string) {
  try {
    await navigator.clipboard.writeText(text);
    say(`Copied ${what}.`);
  } catch {
    say('Copying was blocked by the browser.');
  }
}

/** The text of one stored message, if the whole of it fits in the first page. */
async function messageText(meta: FlowMeta, part: 'request' | 'response') {
  const info = part === 'request' ? meta.request : meta.response;
  if (!info) return null;
  const l = await loadPart(meta, part as PartName, info);
  const d = bytesToText(concat(l.head, l.body));
  return { ...d, complete: l.body.length >= l.bodyLen, head: l.head, body: l.body };
}

export async function copyUrls(ids: number[]) {
  try {
    const metas = await Promise.all(ids.slice(0, MAX_BULK).map(fetchMeta));
    await copy(metas.map(flowUrl).join('\n'), metas.length === 1 ? 'the URL' : `${metas.length} URLs`);
  } catch (e) {
    fail(e);
  }
}

export async function copyAsCurl(id: number) {
  try {
    const m = await fetchMeta(id);
    const t = await messageText(m, 'request');
    if (!t || !t.complete) return say('This request is too large to turn into a cURL command.');
    const parts = bytesToText(t.head).text;
    const body = bytesToText(t.body);
    const cmd = buildCurl(parts, body.text, m.scheme, body.mode !== 'utf8');
    if (!cmd) return say('This request cannot be written as a cURL command (binary or very large body).');
    await copy(cmd, 'the cURL command');
  } catch (e) {
    fail(e);
  }
}

export async function copyMessage(id: number, part: 'request' | 'response') {
  try {
    const t = await messageText(await fetchMeta(id), part);
    if (!t) return say(`This flow has no ${part}.`);
    await copy(t.text, `the ${part}${t.complete ? '' : ' (the first part)'}`);
  } catch (e) {
    fail(e);
  }
}

/** Open the Repeater with one tab per request. The Repeater picks them up from session storage. */
export async function sendToRepeater(ids: number[]) {
  const take = ids.slice(0, MAX_BULK);
  if (ids.length > take.length) say(`Sending the first ${MAX_BULK} of ${ids.length} requests.`);
  const inbox = JSON.parse(sessionStorage.getItem('bosun.repeater.inbox') ?? '[]') as unknown[];
  let sent = 0;
  for (const id of take) {
    try {
      const m = await fetchMeta(id);
      const t = await messageText(m, 'request');
      if (!t || !t.complete) {
        say(`Request ${id} is too large to open in the Repeater here.`);
        continue;
      }
      inbox.push({ scheme: m.scheme, host: m.host, port: m.port, request: t.text, mode: t.mode });
      sent++;
    } catch (e) {
      fail(e);
    }
  }
  if (!sent) return;
  sessionStorage.setItem('bosun.repeater.inbox', JSON.stringify(inbox));
  // Repeater may already be mounted in the background: tell it, then bring it forward.
  window.dispatchEvent(new Event('bosun:repeater-inbox'));
}

const cleanRules = (rs: ScopeRule[] | undefined) =>
  (rs ?? []).filter((r) => r.host.trim()).map((r) => ({ host: r.host.trim(), scheme: r.scheme || null, port: r.port || null, path: r.path || null, allow_private: !!r.allow_private }));

/** Add the hosts of these flows to the scope's include or exclude list. */
export async function scopeHosts(ids: number[], which: 'include' | 'exclude') {
  try {
    const hosts = [...new Set((await Promise.all(ids.slice(0, MAX_BULK).map(fetchMeta))).map((m) => m.host))];
    const scope = await api.get<ScopeSpec>('/scope');
    const next = { include: cleanRules(scope.include), exclude: cleanRules(scope.exclude) };
    const added = hosts.filter((h) => !next[which].some((r) => r.host === h));
    next[which] = [...next[which], ...added.map((host) => ({ host, scheme: null, port: null, path: null, allow_private: false }))];
    if (!added.length) return say(`Already in the ${which} list.`);
    await api.put('/scope', next);
    say(`Added ${added.join(', ')} to the scope ${which} list.`);
    v.applyTick++;
  } catch (e) {
    fail(e);
  }
}

/**
 * Delete flows with a window to change your mind: they disappear from the list at once, and the server is asked only
 * when the toast times out. Closing the page inside the window leaves them stored.
 */
export function deleteFlows(ids: number[]) {
  if (!ids.length) return;
  v.hide(ids);
  const n = ids.length;
  toasts.push({
    text: `Deleted ${n} request${n === 1 ? '' : 's'}.`,
    ms: 5000,
    action: { label: 'Undo', run: () => v.unhide(ids) },
    onExpire: async () => {
      try {
        await api.del('/flows', { ids });
        v.remove(ids);
      } catch (e) {
        v.unhide(ids);
        fail(e);
      }
    },
  });
}

/** Put text in the History filter and apply it. */
export function searchHistory(text: string) {
  v.setQuery(withText(v.query, text));
  workspace.open('history');
}

/** Add and remove tags on flows (the server does it in one step). Returns whether it worked. */
export async function changeTags(ids: number[], add: string[], remove: string[]): Promise<boolean> {
  if (!ids.length) return false;
  try {
    await api.post('/flows/tags', { ids, add, remove });
    v.tagged(ids, add, remove);
    return true;
  } catch (e) {
    fail(e);
    return false;
  }
}

/** The text of one message's body, for the Decoder or the Comparer. */
async function bodyText(id: number, part: 'request' | 'response'): Promise<string | null> {
  const t = await messageText(await fetchMeta(id), part);
  if (!t) {
    say(`This flow has no ${part}.`);
    return null;
  }
  if (!t.complete) say(`The ${part} is large: only its first part was sent.`);
  const b = bytesToText(t.body);
  // A body with nothing in it (a GET, say) is the headers' business: send the whole message instead.
  return b.text || t.text;
}

/** Put a message body in the Decoder's input. The caller opens the panel. */
export async function sendToDecoder(id: number, part: 'request' | 'response'): Promise<boolean> {
  try {
    const text = await bodyText(id, part);
    if (text === null) return false;
    inbox.toDecoder(text);
    return true;
  } catch (e) {
    fail(e);
    return false;
  }
}

/** Put a message in one side of the Comparer. The caller opens the panel. */
export async function sendToComparer(id: number, part: 'request' | 'response', side: 'a' | 'b'): Promise<boolean> {
  try {
    // The whole message, headers and body, since comparing two requests usually means comparing their headers.
    const t = await messageText(await fetchMeta(id), part);
    if (!t) {
      say(`This flow has no ${part}.`);
      return false;
    }
    if (!t.complete) say(`The ${part} is large: only its first part was sent.`);
    inbox.toComparer(side, t.text);
    return true;
  } catch (e) {
    fail(e);
    return false;
  }
}

/** Keep requests in the Organizer for follow-up. */
export async function saveToOrganizer(ids: number[]): Promise<void> {
  try {
    const r = await api.post<{ added: number }>('/organizer', { flow_ids: ids.slice(0, 1000) });
    inbox.organizerTick++;
    say(r.added ? `Saved ${r.added} request${r.added === 1 ? '' : 's'} to the Organizer.` : 'Already in the Organizer.');
  } catch (e) {
    fail(e);
  }
}
