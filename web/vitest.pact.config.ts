import { defineConfig } from 'vitest/config';

// The consumer contract (ADR-0091) runs in Node: pact-js starts a mock provider and writes
// ../api/pacts/ipso-web-ipso-server.json.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['pact/**/*.pact.test.ts'],
    testTimeout: 30_000,
  },
});
