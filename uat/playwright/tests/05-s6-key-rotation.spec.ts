import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli } from './helpers/docker';
import { login, shot } from './helpers/ui';

/**
 * S6 — Master-key re-seal.
 *
 * Documented step: docs/master-key.md § "Key Rotation / POST
 * /api/v1/admin/rotate-key" and § "Procedure" step 4 —
 * "Call POST /api/v1/admin/rotate-key as an admin. Check that `errors` is
 * empty and that `re_encrypted_count` equals `total_credentials`."
 *
 * Settings carries the control (D4), so the documented step is a button an
 * admin presses; the report it renders is what the runbook says to check.
 */
test.describe('S6 key rotation', () => {
  test('Settings offers a master-key re-seal, and it reports every credential re-sealed with no errors (docs/master-key.md § "Procedure" step 4)', async ({ page }, testInfo) => {
    await login(page);
    await page.goto('/settings');
    await shot(page, testInfo, 's6-settings-page');

    const reseal = page.locator('#reseal-btn');
    await expect(reseal).toBeVisible({ timeout: 30_000 });
    await reseal.click();

    // It confirms first.
    const dialog = page.locator('.modal', { has: page.locator('#reseal-confirm') });
    await expect(dialog).toBeVisible();

    const rotated = page.waitForResponse(
      (r) => r.url().includes('/api/v1/admin/rotate-key') && r.request().method() === 'POST',
      { timeout: 60_000 },
    );
    await page.locator('#reseal-confirm').click();
    const resp = await rotated;
    expect(resp.status(), await resp.text()).toBe(200);

    const report = (await resp.json()).data;
    expect(report.errors, JSON.stringify(report)).toEqual([]);
    expect(report.re_encrypted_count).toBeGreaterThanOrEqual(1);
    expect(report.re_encrypted_count).toBe(report.total_credentials);
    expect(report.history_re_encrypted_count).toBe(report.total_history_entries);
    expect(report).toHaveProperty('key_version');

    // The page shows the same numbers the runbook tells the admin to check.
    const card = page.locator('.card', { has: page.locator('#reseal-btn') });
    await expect(card).toContainText(
      `${report.re_encrypted_count} of ${report.total_credentials}`,
      { timeout: 30_000 },
    );
    await expect(card).toContainText(
      `${report.history_re_encrypted_count} of ${report.total_history_entries}`,
    );
    await expect(card.locator('span.pill', { hasText: 'None' })).toBeVisible();
    await shot(page, testInfo, 's6-reseal-report');
  });

  test('the credential still works through the proxy after the re-seal', async () => {
    const r = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo']);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain('HTTP 200');
    expect(r.out).toContain('"authorization":"[REDACTED]"');
  });
});
