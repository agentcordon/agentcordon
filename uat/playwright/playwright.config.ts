import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.UAT_SERVER_URL || 'http://127.0.0.1:13140';

// UAT_BROWSER picks the engine. Chromium is the default, so `./uat/run.sh`
// with nothing set runs exactly what it always ran; the other two exist so a
// rendering difference between engines (a positioned table row as containing
// block, say) is caught by the suite rather than by a user.
const BROWSERS = {
  chromium: devices['Desktop Chrome'],
  firefox: devices['Desktop Firefox'],
  webkit: devices['Desktop Safari'],
} as const;

const browserName = (process.env.UAT_BROWSER || 'chromium') as keyof typeof BROWSERS;
if (!(browserName in BROWSERS)) {
  throw new Error(
    `UAT_BROWSER=${process.env.UAT_BROWSER}: expected one of ${Object.keys(BROWSERS).join(', ')}`,
  );
}

export default defineConfig({
  testDir: './tests',
  // The scenarios are an ordered story (S1 login -> S9 restart); they share
  // server state and must not be interleaved.
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  timeout: 180_000,
  expect: { timeout: 20_000 },
  reporter: [
    ['list'],
    ['html', { outputFolder: 'report', open: 'never' }],
    ['json', { outputFile: 'report/results.json' }],
  ],
  outputDir: 'test-results',
  use: {
    baseURL,
    headless: true,
    ignoreHTTPSErrors: true,
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    actionTimeout: 20_000,
    navigationTimeout: 30_000,
  },
  projects: [
    {
      name: browserName,
      use: { ...BROWSERS[browserName] },
    },
  ],
});
