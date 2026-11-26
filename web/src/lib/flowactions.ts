// Things you can do to flows by id. Every action fetches what it needs from the API by id, so the scope gate, the
// audit log and the role checks still apply, and no target content is kept in the page beyond what is shown.

import { api } from './api';
import { b64ToBytes, bytesToText, flowUrl } from './bytes';
import { parseRequest, toCurl, toHar, toSnippet, type HarInput, type HarMessage, type Snippet } from './export';
import { prefs } from './prefs.svelte';
import { concat, fetchRange, loadPart, type PartName } from './flowbody';
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

const redactNote = () => (prefs.exportSecrets ? '' : ' (cookie and authorization values replaced by REDACTED)');

/** Copy one request as a command or a code snippet. Secrets are redacted unless the person has asked to keep them. */
export async function copyRequestAs(id: number, kind: 'curl' | 'curl-powershell' | Snippet) {
  try {
    const m = await fetchMeta(id);
    const t = await messageText(m, 'request');
    if (!t || !t.complete) return say('This request is too large to copy as code.');
    const body = bytesToText(t.body);
    const r = parseRequest(bytesToText(t.head).text, body.text, m.scheme, body.mode !== 'utf8');
    if (!r) return say('This request cannot be written as code (a binary or very large body).');
    const secrets = prefs.exportSecrets;
    const text = kind === 'curl' ? toCurl(r, 'posix', secrets) : kind === 'curl-powershell' ? toCurl(r, 'powershell', secrets) : toSnippet(r, kind, secrets);
    const what = kind === 'curl' ? 'the cURL command' : kind === 'curl-powershell' ? 'the PowerShell command' : `the ${kind} snippet`;
    await copy(text, what + redactNote());
  } catch (e) {
    fail(e);
  }
}

export const copyAsCurl = (id: number) => copyRequestAs(id, 'curl');

/** How much of one body goes into a HAR file, and how many flows at once. */
const HAR_BODY_CAP = 2 * 1024 * 1024;
const HAR_MAX_FLOWS = 500;

async function harMessage(meta: FlowMeta, part: 'request' | 'response', info: FlowMeta['request']): Promise<HarMessage> {
  const decoded = part === 'response' && !!meta.response_encoding;
  let body: Uint8Array = new Uint8Array();
  if (info.body_len > 0) {
    try {
      body = (await fetchRange(meta.id, part, 0, HAR_BODY_CAP, decoded)).bytes;
    } catch {
      // A decoded view can be missing (an unknown encoding): fall back to the stored bytes.
      body = (await fetchRange(meta.id, part, 0, HAR_BODY_CAP, false)).bytes;
    }
  }
  return { head: bytesToText(b64ToBytes(info.head)).text, body, bodySize: info.body_len > body.length && !decoded ? info.body_len : undefined };
}

/** Save the flows as a HAR file (bodies over 2 MiB are cut). */
export async function exportHar(ids: number[]) {
  const take = ids.slice(0, HAR_MAX_FLOWS);
  if (ids.length > take.length) say(`Exporting the first ${HAR_MAX_FLOWS} of ${ids.length} requests.`);
  try {
    const entries: HarInput[] = [];
    for (let i = 0; i < take.length; i += 6) {
      const batch = await Promise.all(
        take.slice(i, i + 6).map(async (id): Promise<HarInput> => {
          const m = await fetchMeta(id);
          return {
            startedMs: m.started_ms,
            durationMs: m.duration_ms ?? null,
            url: flowUrl(m),
            method: m.method,
            httpVersion: m.http_version,
            request: await harMessage(m, 'request', m.request),
            response: m.response ? await harMessage(m, 'response', m.response) : null,
            status: m.status ?? null,
          };
        }),
      );
      entries.push(...batch);
    }
    const har = toHar(entries, prefs.exportSecrets);
    const blob = new Blob([JSON.stringify(har, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bosun-${entries.length}-requests.har`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
    say(`Saved ${entries.length} request${entries.length === 1 ? '' : 's'} as a HAR file${redactNote()}.`);
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
