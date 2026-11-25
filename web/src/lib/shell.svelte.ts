// State of the application shell that panels, the header and the status bar all read.

class Shell {
  /** Intercept queues that are switched on (shown as a count on the Intercept tab). */
  held = $state(0);
  /** Bumped when another project is opened: every panel remounts with the new project's data. */
  generation = $state(0);
  project = $state('');
  lost = $state<{ n: number; error: string } | null>(null);
  /** The Layouts dialog is open. */
  layoutDialog = $state(false);
}

export const shell = new Shell();
