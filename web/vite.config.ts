import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// The UI is served under a strict CSP (no inline script or style), so the build must not emit any.
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  server: {
    // `npm run dev` against a running `bosun serve` on the default port.
    proxy: { '/api': { target: 'http://127.0.0.1:8090', ws: true } },
  },
});
