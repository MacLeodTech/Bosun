// Short messages at the bottom of the window. A toast can carry one action (Undo), and can run something when it
// expires without the action being taken: that is how delete works, the server is only asked after the undo window.

export interface Toast {
  id: number;
  text: string;
  action?: { label: string; run: () => void };
  /** Runs when the toast times out (not when it is dismissed by its action). */
  onExpire?: () => void;
  ms: number;
}

class Toasts {
  list = $state<Toast[]>([]);
  private next = 1;
  private timers = new Map<number, ReturnType<typeof setTimeout>>();

  push(t: { text: string; action?: Toast['action']; onExpire?: () => void; ms?: number }): number {
    const toast: Toast = { id: this.next++, text: t.text, action: t.action, onExpire: t.onExpire, ms: t.ms ?? 4000 };
    this.list = [...this.list, toast].slice(-4);
    this.timers.set(toast.id, setTimeout(() => this.expire(toast.id), toast.ms));
    return toast.id;
  }

  /** Take the action's button: the toast goes away without expiring. */
  act(id: number) {
    const t = this.list.find((x) => x.id === id);
    if (!t) return;
    this.drop(id);
    t.action?.run();
  }

  private expire(id: number) {
    const t = this.list.find((x) => x.id === id);
    this.drop(id);
    t?.onExpire?.();
  }

  /** Close now. A pending expiry still runs, so a delete cannot be skipped by clicking the cross. */
  dismiss(id: number) {
    this.timers.get(id) && clearTimeout(this.timers.get(id));
    this.expire(id);
  }

  private drop(id: number) {
    clearTimeout(this.timers.get(id));
    this.timers.delete(id);
    this.list = this.list.filter((x) => x.id !== id);
  }
}

export const toasts = new Toasts();
