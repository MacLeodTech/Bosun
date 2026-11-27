<script lang="ts">
  // Shows one HTTP message. Target content is hostile: it is only ever shown as text (tokens rendered as spans, never
  // as markup), or rendered in a fully sandboxed iframe (no scripts, opaque origin, and it inherits this page's CSP).
  import { prefs, type PaneRole, type MessageViewMode } from '../lib/prefs.svelte';
  import { theme } from '../lib/theme.svelte';
  import { b64ToBytes, bytesToText, fmtSize, hexDump, splitMessage, wireBytes, bytesToB64, type TextMode } from '../lib/bytes';
  import { contentTypeOf, detectLang, highlight, splitText, MAX_HIGHLIGHT } from '../lib/highlight';
  import { pretty } from '../lib/pretty';
  import { parseRequest, toCurl } from '../lib/export';
  import { api } from '../lib/api';
  import { marks, type Range } from '../lib/evidence';
  import CodeView from './CodeView.svelte';
  import MessageEditor from './MessageEditor.svelte';

  let {
    raw,
    decodedBody = null,
    editable = false,
    onEdit,
    title = '',
    rawRemaining = 0,
    decodedMore = false,
    onMore,
    downloadHref = '',
    role,
    scheme = '',
    onFilterHeader,
    evidence = [],
  }: {
    raw: string | null;
    decodedBody?: string | null;
    editable?: boolean;
    onEdit?: (b64: string) => void;
    title?: string;
    /** Bytes of the stored body that are not loaded yet. */
    rawRemaining?: number;
    /** The decoded body goes on past what is loaded. */
    decodedMore?: boolean;
    /** Load the next page of the stored body (false) or of the decoded one (true). */
    onMore?: (decoded: boolean) => void;
    /** Where the whole body can be downloaded from. */
    downloadHref?: string;
    /** Which kind of pane this is; its view (raw, headers, ...) is remembered per kind. */
    role?: PaneRole;
    /** The request's scheme, which "copy as cURL" needs (a message does not carry it). */
    scheme?: string;
    /** Called with a header's name and value to filter the history by it. */
    onFilterHeader?: (name: string, value: string) => void;
    /** Byte ranges of the stored message to highlight (the passive scanner's evidence). */
    evidence?: Range[];
  } = $props();

  let localView = $state<MessageViewMode>('raw');
  const chosen = $derived(editable ? 'raw' : role ? prefs.view[role] : localView);
  function setView(v: MessageViewMode) {
    if (role) prefs.setView(role, v);
    else localView = v;
  }
  let showDecoded = $state(true);
  let code = $state<{ find(): void } | undefined>();
  let note = $state('');

  const bytes = $derived(raw ? b64ToBytes(raw) : new Uint8Array());
  const parts = $derived(splitMessage(bytes));
  const decoded = $derived(decodedBody ? b64ToBytes(decodedBody) : null);
  const text = $derived.by(() => {
    if (decoded && showDecoded && !editable) {
      const head = bytesToText(parts.head).text;
      return { text: head + '\r\n\r\n' + bytesToText(decoded).text, mode: 'utf8' as TextMode };
    }
    return bytesToText(bytes);
  });
  const split = $derived(splitText(text.text));
  const lang = $derived(detectLang(contentTypeOf(split.head), split.body));
  // gRPC and GraphQL bodies are decoded by the server's codec (the same one the Decoder uses), so the view and the
  // rules agree on what an operation is. The result replaces the "pretty" text for those messages.
  const ct = $derived((contentTypeOf(split.head) ?? '').toLowerCase());
  const protoOps = $derived.by((): string[] | null => {
    if (editable) return null;
    if (/^application\/grpc-web-text/.test(ct)) return ['base64_decode', 'grpc_decode'];
    if (/^application\/grpc/.test(ct)) return ['grpc_decode'];
    if (ct.includes('json') && /^\s*[[{][\s\S]{0,4096}"(query|operationName)"\s*:/.test(split.body)) return ['graphql_decode'];
    return null;
  });
  let protoText = $state<string | null>(null);
  $effect(() => {
    const ops = protoOps;
    const body = decoded ?? parts.body;
    protoText = null;
    if (!ops || !body.length || body.length > (1 << 20)) return;
    let live = true;
    api
      .post<{ steps: { output: string }[]; error: unknown }>('/decoder/apply', { input: bytesToB64(body), ops })
      .then((r) => {
        const last = r.steps[ops.length - 1];
        if (live && !r.error && last) protoText = bytesToText(b64ToBytes(last.output)).text;
      })
      .catch(() => {});
    return () => (live = false);
  });
  const prettyBody = $derived(editable ? null : (protoText ?? pretty(split.body, lang)));
  // "pretty" quietly shows the raw text when there is nothing to re-indent, so the choice sticks across messages.
  const view = $derived<MessageViewMode>(chosen === 'pretty' && !prettyBody ? 'raw' : chosen);
  const oversize = $derived(text.text.length > MAX_HIGHLIGHT);

  const lines = $derived.by(() => {
    const body = view === 'pretty' && prettyBody ? prettyBody : split.body;
    const head = highlight(split.head, 'http');
    // The blank line between head and body is shown; an empty body adds nothing after it.
    return split.sep ? (body ? [...head, [], ...highlight(body, protoText && view === 'pretty' ? 'plain' : lang)] : [...head, []]) : head;
  });
  // Evidence positions are into the stored bytes, so they only line up with the raw text as stored.
  const evidenceMarks = $derived(
    evidence.length && view === 'raw' && !(decoded && showDecoded && !editable) ? marks(bytes, text.text, text.mode === 'utf8', evidence) : [],
  );
  const shownText = $derived(view === 'pretty' && prettyBody ? `${split.head}\r\n\r\n${prettyBody}` : text.text);

  const headers = $derived(
    bytesToText(parts.head)
      .text.split(/\r?\n/)
      .slice(1)
      .filter((l) => l.length)
      .map((l) => {
        const i = l.indexOf(':');
        return i < 0 ? [l, ''] : [l.slice(0, i), l.slice(i + 1).trim()];
      }),
  );
  const renderBody = $derived(bytesToText(decoded ?? parts.body).text);

  /** The body to show in the render view, with the page told which colour scheme this UI is in. */
  const srcdoc = $derived.by(() => {
    // Only a <meta>: the CSP bars inline <style>, and a doctype must stay first or the page falls into quirks mode.
    const meta = `<meta name="color-scheme" content="${theme.resolved}">`;
    const d = /^\s*<!doctype[^>]*>/i.exec(renderBody);
    return d ? d[0] + meta + renderBody.slice(d[0].length) : meta + renderBody;
  });

  let draft = $state('');
  let draftMode = $state<TextMode>('utf8');
  $effect(() => {
    draft = text.text;
    draftMode = text.mode;
  });

  function edited(t: string, m: TextMode) {
    draft = t;
    draftMode = m;
    onEdit?.(bytesToB64(wireBytes(t, m)));
  }

  async function copy(what: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      note = `Copied ${what}.`;
    } catch {
      note = 'Copying was blocked by the browser.';
    }
    setTimeout(() => (note = ''), 2500);
  }

  /** A cURL command for this request. Only for text bodies of a size a command line can hold. */
  const curl = $derived.by(() => {
    const r = role === 'request' && raw ? parseRequest(split.head, split.body, scheme, text.mode !== 'utf8') : null;
    return r ? toCurl(r, 'posix', prefs.exportSecrets) : null;
  });

  const modes = $derived((['raw', ...(prettyBody ? ['pretty'] : []), 'headers', 'hex', 'render'] as MessageViewMode[]));
</script>

<div class="msg">
  <div class="msg-bar">
    {#if title}<strong>{title}</strong>{/if}
    <div class="seg">
      {#each modes as v (v)}
        <button class:active={view === v} onclick={() => setView(v)} disabled={editable && v !== 'raw'}>{v}</button>
      {/each}
    </div>
    {#if decoded && !editable}
      <label class="small"><input type="checkbox" bind:checked={showDecoded} /> decoded body</label>
    {/if}
    {#if text.mode === 'latin1'}<span class="badge">binary</span>{/if}
    <span class="spacer"></span>
    {#if note}<span class="small muted" role="status">{note}</span>{/if}
    {#if raw !== null && !editable && (view === 'raw' || view === 'pretty')}
      <button class="ghost small" aria-pressed={prefs.wrap} title="Wrap long lines" onclick={() => prefs.setWrap(!prefs.wrap)}>wrap</button>
      <button class="ghost small" title="Find in this message (Ctrl+F)" onclick={() => code?.find()}>find</button>
    {/if}
    {#if raw !== null && !editable}
      <button class="ghost small" title="Copy the whole message" onclick={() => copy('message', shownText)}>copy</button>
      {#if curl}<button class="ghost small" title="Copy this request as a cURL command (cookie and authorization values are replaced unless you keep them: right-click a request in History)" onclick={() => copy('cURL command', curl)}>cURL</button>{/if}
    {/if}
    {#if downloadHref}<a class="small" href={downloadHref} download>download body</a>{/if}
  </div>
  {#if raw === null}
    <div class="empty">No message.</div>
  {:else if view === 'raw' || view === 'pretty'}
    {#if editable}
      <MessageEditor text={draft} mode={draftMode} label={title || 'Message'} onchange={edited} />
    {:else}
      {#if oversize}<div class="small muted pad">Large message: shown without colour.</div>{/if}
      <CodeView bind:this={code} {lines} wrap={prefs.wrap} label={title || 'Message'} marks={evidenceMarks} />
    {/if}
  {:else if view === 'headers'}
    <div class="scroll">
      <table class="kv">
        <tbody>
          {#each headers as [k, v], i (i)}
            <tr>
              <td>{k}</td>
              <td>{v}</td>
              <td class="acts">
                <button class="ghost small" aria-label="Copy value of {k}" title="Copy the value" onclick={() => copy(k!, v!)}>copy</button>
                {#if onFilterHeader}<button class="ghost small" aria-label="Filter history by {k}" title="Show history entries with this header" onclick={() => onFilterHeader(k!, v!)}>filter</button>{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else if view === 'hex'}
    <pre class="code hex">{hexDump(bytes)}</pre>
  {:else}
    <iframe class="render" title="Rendered response (sandboxed, no scripts)" sandbox="" referrerpolicy="no-referrer" {srcdoc}></iframe>
  {/if}
  {#if onMore && ((decoded && showDecoded && !editable) ? decodedMore : rawRemaining > 0)}
    <div class="more">
      <span class="small muted">
        {#if decoded && showDecoded && !editable}Showing the first part of the decoded body.{:else}{fmtSize(rawRemaining)} of the body not loaded.{/if}
      </span>
      <button class="small" onclick={() => onMore(!!(decoded && showDecoded && !editable))}>Load more</button>
    </div>
  {/if}
</div>

<style>
  .msg { display: flex; flex-direction: column; min-height: 0; height: 100%; }
  .msg-bar { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; padding: .2rem .4rem; border-bottom: 1px solid var(--border-subtle); }
  .code { flex: 1; margin: 0; overflow: auto; padding: .5rem; white-space: pre-wrap; word-break: break-all; }
  .scroll { overflow: auto; flex: 1; }
  .acts { white-space: nowrap; text-align: right; width: 1%; }
  /* The page inside is told the UI's colour scheme (see srcdoc), so a page without its own colours is not a white slab. */
  .render { flex: 1; border: 0; }
  .empty { padding: 1rem; color: var(--text-2); }
  .pad { padding: .15rem .5rem; }
  .more { display: flex; gap: .6rem; align-items: center; padding: .25rem .5rem; border-top: 1px solid var(--border-subtle); }
  button[aria-pressed='true'] { background: var(--surface-sel); }
</style>
