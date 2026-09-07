import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli, docker, waitForServerHealthy } from './helpers/docker';
import { login, shot } from './helpers/ui';

/**
 * S9 — Restart persistence.
 *
 * Documented behaviour: README.md § "Production deployment" — persist
 * AGTCRDN_MASTER_SECRET and mount a data volume; docker-compose.yml ships
 * `restart: unless-stopped` and a named `agentcordon-data` volume, so a
 * restart is an expected, routine event.
 */
test.describe('S9 restart persistence', () => {
  test('the server restarts cleanly', async () => {
    const r = docker(['restart', UAT.server], { timeout: 180_000 });
    expect(r.code, r.out).toBe(0);
    await waitForServerHealthy(180_000);
  });

  test('login still works after the restart', async ({ page }, testInfo) => {
    await login(page);
    await expect(page.locator('div.content-header h2')).toHaveText('Dashboard');
    await shot(page, testInfo, 's9-dashboard-after-restart');
  });

  test('the credential still decrypts: the proxy call works again', async () => {
    // The broker re-reaches the server on its own; retry briefly while it does.
    let last = '';
    for (let i = 0; i < 10; i += 1) {
      const r = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo']);
      last = r.out;
      if (r.code === 0 && r.out.includes('HTTP 200')) {
        expect(r.out).toContain('"authorization":"[REDACTED]"');
        return;
      }
      await new Promise((res) => setTimeout(res, 3000));
    }
    throw new Error(`proxy never recovered after the restart. Last output:\n${last}`);
  });

  test('the credential and the workspace survived the restart in the UI', async ({ page }, testInfo) => {
    await login(page);
    await page.goto('/credentials');
    await expect(
      page.locator(`tr.cred-row[aria-label="${UAT.credentialName}"]`),
    ).toBeVisible();
    await page.goto('/workspaces');
    await expect(
      page.locator(`tr.ws-row[aria-label="${UAT.workspaceName}"]`),
    ).toBeVisible();
    await shot(page, testInfo, 's9-workspaces-after-restart');
  });
});
