// Text on its way to the Decoder or the Comparer ("Send to ..."). It waits here until the panel takes it, so it works
// whether or not that panel is open yet. Only text moves: the panels show it as text, never as markup.

class Inbox {
  decoder = $state<{ text: string } | null>(null);
  comparer = $state<{ a?: string; b?: string } | null>(null);

  /** Bumped when requests were saved to the Organizer, so its panel reloads. */
  organizerTick = $state(0);

  toDecoder(text: string) {
    this.decoder = { text };
  }

  toComparer(side: 'a' | 'b', text: string) {
    this.comparer = { ...this.comparer, [side]: text };
  }
}

export const inbox = new Inbox();
