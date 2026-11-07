import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

import { fixturesPlugin } from './fixtures/plugin.ts';

// The compose front of the local stack (deploy/compose). `npm run dev` proxies the API and the sign-in to it,
// so the browser sees one origin, like the control plane.
const stack = process.env.IPSO_STACK_URL ?? 'http://localhost:8080';

export default defineConfig(({ mode }) => ({
  plugins: [react(), ...(mode === 'fixtures' ? [fixturesPlugin()] : [])],
  build: {
    // The api role embeds this directory (internal/webapp). Nothing is inlined into the page or the styles,
    // so the content security policy needs no data: source for scripts or styles.
    outDir: '../internal/webapp/dist/app',
    emptyOutDir: true,
    sourcemap: false,
    assetsInlineLimit: 0,
    target: 'es2023',
    modulePreload: { polyfill: false },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: mode === 'fixtures' ? undefined : { '/v1': stack, '/auth': stack },
  },
}));
