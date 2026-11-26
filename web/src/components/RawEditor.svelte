<script lang="ts">
  // The raw message editor: CodeMirror 6 with HTTP highlighting from our own lexers (highlight.ts), line numbers,
  // undo and redo.
  //
  // CSP: CodeMirror adds its styles as a <style> element, which `style-src 'self'` blocks. In a shadow root its
  // style module uses a constructed stylesheet instead, which the policy does not govern, so the editor lives in
  // one and the CSP stays as it is (no nonce, no 'unsafe-inline'). The page's own CSS does not reach into a shadow
  // root, so the editor's look is set here from the same design tokens (custom properties inherit through it).
  //
  // Target content is only ever text in the document and class names on spans: it is never markup.
  import { onMount } from 'svelte';
  import { EditorState, RangeSetBuilder } from '@codemirror/state';
  import { Decoration, EditorView, ViewPlugin, drawSelection, highlightActiveLine, keymap, lineNumbers, type DecorationSet, type ViewUpdate } from '@codemirror/view';
  import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
  import { highlightMessage, MAX_HIGHLIGHT } from '../lib/highlight';

  let { value, label, readOnly = false, onchange }: {
    value: string;
    label: string;
    readOnly?: boolean;
    onchange?: (text: string) => void;
  } = $props();

  let host = $state<HTMLElement | undefined>();
  let view: EditorView | undefined;
  /** The text last handed to or taken from the editor, with line endings as the editor holds them. */
  let current = '';
  const norm = (s: string) => s.replace(/\r\n?/g, '\n');

  const marks = {
    key: Decoration.mark({ class: 'sx-key' }), string: Decoration.mark({ class: 'sx-string' }),
    number: Decoration.mark({ class: 'sx-number' }), bool: Decoration.mark({ class: 'sx-bool' }),
    punct: Decoration.mark({ class: 'sx-punct' }), hname: Decoration.mark({ class: 'sx-hname' }),
    hvalue: Decoration.mark({ class: 'sx-hvalue' }), tag: Decoration.mark({ class: 'sx-tag' }),
    attr: Decoration.mark({ class: 'sx-attr' }), comment: Decoration.mark({ class: 'sx-comment' }),
  } as const;

  function colour(text: string): DecorationSet {
    const b = new RangeSetBuilder<Decoration>();
    if (text.length > MAX_HIGHLIGHT) return b.finish();
    let pos = 0;
    const { lines } = highlightMessage(text);
    for (let i = 0; i < lines.length; i++) {
      for (const t of lines[i]!) {
        const m = t.c ? marks[t.c] : null;
        if (m && t.t.length) b.add(pos, pos + t.t.length, m);
        pos += t.t.length;
      }
      pos += 1; // the line break
    }
    return b.finish();
  }

  const highlighter = ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;
      constructor(v: EditorView) { this.decorations = colour(v.state.doc.toString()); }
      update(u: ViewUpdate) { if (u.docChanged) this.decorations = colour(u.state.doc.toString()); }
    },
    { decorations: (p) => p.decorations },
  );

  const theme = EditorView.theme({
    '&': { flex: '1 1 0', minHeight: '0', backgroundColor: 'var(--surface-1)', color: 'var(--text-1)', fontFamily: 'var(--font-mono)', fontSize: 'var(--fs-data)' },
    '&.cm-focused': { outline: '1px solid var(--focus-ring)' },
    '.cm-scroller': { fontFamily: 'inherit', lineHeight: '1.4', overflow: 'auto' },
    '.cm-content': { caretColor: 'var(--text-1)', padding: '.4rem 0' },
    '.cm-cursor': { borderLeftColor: 'var(--text-1)' },
    '.cm-gutters': { backgroundColor: 'var(--surface-0)', color: 'var(--text-2)', border: 'none' },
    '.cm-activeLine': { backgroundColor: 'var(--surface-2)' },
    '.cm-activeLineGutter': { backgroundColor: 'var(--surface-2)' },
    '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': { backgroundColor: 'var(--surface-sel)' },
    '.sx-key': { color: 'var(--sx-key)' }, '.sx-string': { color: 'var(--sx-string)' },
    '.sx-number': { color: 'var(--sx-number)' }, '.sx-bool': { color: 'var(--sx-bool)' },
    '.sx-punct': { color: 'var(--sx-punct)' }, '.sx-hname': { color: 'var(--sx-hname)' },
    '.sx-hvalue': { color: 'var(--sx-hvalue)' }, '.sx-tag': { color: 'var(--sx-tag)' },
    '.sx-attr': { color: 'var(--sx-attr)' }, '.sx-comment': { color: 'var(--sx-comment)', fontStyle: 'italic' },
  });

  onMount(() => {
    const shadow = host!.attachShadow({ mode: 'open' });
    current = norm(value);
    view = new EditorView({
      root: shadow,
      parent: shadow,
      state: EditorState.create({
        doc: current,
        extensions: [
          lineNumbers(), history(), drawSelection(), highlightActiveLine(), highlighter, theme,
          // Tab is left to move focus (no indentWithTab), so the editor is not a keyboard trap.
          keymap.of([...defaultKeymap, ...historyKeymap]),
          EditorState.readOnly.of(readOnly),
          EditorView.editable.of(!readOnly),
          EditorView.contentAttributes.of({ 'aria-label': label, 'aria-multiline': 'true', role: 'textbox', spellcheck: 'false' }),
          EditorView.updateListener.of((u) => {
            if (!u.docChanged) return;
            current = u.state.doc.toString();
            onchange?.(current);
          }),
        ],
      }),
    });
    return () => { view?.destroy(); view = undefined; };
  });

  // A change from outside (another tab, a hex edit, pretty-print) replaces the document.
  $effect(() => {
    const next = norm(value);
    if (view && next !== current) {
      current = next;
      view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: next } });
    }
  });
</script>

<div class="host" bind:this={host}></div>

<style>
  .host { flex: 1; min-height: 0; min-width: 0; display: flex; flex-direction: column; }
</style>
