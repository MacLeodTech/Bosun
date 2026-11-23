import { defineConfig } from '@playwright/test';
import { UI_PORT } from './ports';

// The suite drives a real `bosun serve` (binary from BOSUN_BIN, default the debug build) with a throw-away data
// directory, plus a small "hostile" target the proxy talks to. One worker: the tests share one engine and one
// account, and run in file order.
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 7_000 },
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  globalSetup: './global-setup.ts',
  use: {
    baseURL: `http://127.0.0.1:${UI_PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
