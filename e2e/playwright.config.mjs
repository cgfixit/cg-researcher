// Starts the Rust mock model and a throwaway `cg-researcher serve`, then runs
// the UI specs in Chromium and WebKit (Safari's engine; not Safari itself).
import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';
import os from 'node:os';

const root = path.resolve(import.meta.dirname, '..');
const bin = process.env.CG_BIN || path.join(root, 'target/debug/cg-researcher');
const mock = process.env.CG_MOCK_BIN || path.join(root, 'target/debug/examples/mock_llm');
const home = process.env.CG_E2E_HOME || path.join(os.tmpdir(), 'cg-e2e-home');
process.env.CG_BIN = bin;
process.env.CG_E2E_HOME = home;

export default defineConfig({
  testDir: '.',
  testMatch: /.*\.spec\.mjs/,
  fullyParallel: false,
  workers: 1, // one server, one rate limiter
  retries: 0, // a flaky spec must fail visibly, not pass on the second try
  // The browser launch is a worker fixture, so it is charged to the FIRST test of each
  // project. WebKit's cold start on a fresh CI runner has eaten the default 30 s budget
  // (main @ dfdd773: page.goto timed out in the first WebKit spec, the other 17 passed).
  timeout: 60_000,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: { baseURL: 'http://127.0.0.1:8797', trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  webServer: [
    { command: `"${mock}" 127.0.0.1:11434`, url: 'http://127.0.0.1:11434/v1/models', reuseExistingServer: false, timeout: 30_000 },
    { command: `"${path.join(root, 'e2e/start-server.sh')}"`, url: 'http://127.0.0.1:8797/health', reuseExistingServer: false, timeout: 60_000 },
  ],
});
