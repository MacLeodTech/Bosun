// The CSP forbids style attributes, so dynamic sizes are set through the CSSOM (which CSP allows) via this
// action instead of `style=`/`style:` in markup.

export function css(node: HTMLElement, props: Record<string, string>) {
  const apply = (p: Record<string, string>) => {
    for (const [k, v] of Object.entries(p)) node.style.setProperty(k, v);
  };
  apply(props);
  return { update: apply };
}
