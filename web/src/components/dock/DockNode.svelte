<script lang="ts">
  import type { Node } from '../../lib/layout';
  import GroupView from './GroupView.svelte';
  import SplitView from './SplitView.svelte';

  let { node }: { node: Node } = $props();
</script>

{#if node.kind === 'group'}
  <GroupView group={node} />
{:else}
  <SplitView split={node} />
{/if}
