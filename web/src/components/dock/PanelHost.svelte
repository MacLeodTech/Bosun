<script lang="ts">
  // Mounts one panel's component and tells it whether it is the one on screen. The key restarts the panel when
  // another project is opened.
  import { providePanel } from '../../lib/panelctx';
  import { panelById } from '../../lib/panels';
  import { shell } from '../../lib/shell.svelte';

  let { panel, visible }: { panel: string; visible: boolean } = $props();
  providePanel({
    get visible() {
      return visible;
    },
  });
  const def = $derived(panelById(panel));
</script>

{#if def}
  {#key shell.generation}
    {@const C = def.component}
    <C />
  {/key}
{/if}
