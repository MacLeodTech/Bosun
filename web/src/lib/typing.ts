/**
 * Whether a key event came from something the person is typing into. Window-level shortcuts must stay out of the
 * way then. The raw editor lives in a shadow root, where `event.target` is the host element and not the editable
 * node inside it, so the real target is read from the event's composed path.
 */
export function isTyping(e: Event): boolean {
  const t = (e.composedPath()[0] ?? e.target) as HTMLElement | null;
  return !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || !!t.isContentEditable);
}
