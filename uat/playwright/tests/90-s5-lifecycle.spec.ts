import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli } from './helpers/docker';
import { apiFromPage, login, shot } from './helpers/ui';
import { need } from './helpers/state';

/**
 * S5 — Workspace lifecycle.
 *
 * Documented behaviour:
 *   README.md § "Why AgentCordon" — "Revocation: One-click disable in
 *     dashboard, agents lose access instantly".
 *   docs/workspace-enrollment.md § "Workspace Data Model" — status is
 *     "Pending, Active, Disabled, or Revoked ... Disabled is reversible;
 *     Revoked is final."
 *   docs/system-architecture.md § API table — "POST /{id}/revoke (final;
 *     revokes clients and tokens in one transaction)".
 *
 * Every step here is a button on the workspace detail page: Disable, Enable,
 * and Revoke (the last behind a confirmation that spells out that revocation is
 * final). The only raw API call left is the one that proves revocation stuck —
 * re-enabling afterwards must answer 409, and the UI no longer offers Enable.
 *
 * This scenario runs last because revocation is final.
 */
test.describe('S5 workspace lifecycle', () => {
  test('disabling the workspace from the dashboard stops the proxy (README: "One-click disable in dashboard, agents lose access instantly")', async ({ page }, testInfo) => {
    await login(page);
    await page.goto(`/workspaces/${need('workspaceId')}`);

    const toggle = page.locator('button', { hasText: /^(Disable|Enable)$/ }).first();
    await expect(toggle).toHaveText('Disable', { timeout: 30_000 });
    await shot(page, testInfo, 's5-workspace-active');

    const put = page.waitForResponse(
      (r) => r.url().includes(`/api/v1/workspaces/${need('workspaceId')}`) && r.request().method() === 'PUT',
      { timeout: 30_000 },
    );
    await toggle.click();
    // Disabling takes access away from every agent holding this identity, so it
    // asks first (uat/artifacts/reviews/UI-REVIEW-live.md M14). Enabling gives access back and
    // does not.
    const confirm = page.locator('#ac-confirm');
    await expect(confirm).toBeVisible();
    await expect(confirm).toContainText('lose access');
    await page.click('#ac-confirm-ok');
    expect((await put).status()).toBe(200);
    // The shared dialog resets once closed; a hidden button still named
    // "Disable" would shadow the real toggle for any query by name.
    await expect(page.locator('#ac-confirm')).toBeHidden();
    await expect(page.locator('#ac-confirm-ok')).toHaveText('Confirm');
    await expect(toggle).toHaveText('Enable', { timeout: 30_000 });
    await shot(page, testInfo, 's5-workspace-disabled');

    const r = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo']);
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toMatch(/forbidden|unauthorized|denied|401|403/i);
    expect(r.out).not.toContain(UAT.credentialSecret);
  });

  test('re-enabling it from the dashboard restores the proxy', async ({ page }) => {
    await login(page);
    await page.goto(`/workspaces/${need('workspaceId')}`);

    const toggle = page.locator('button', { hasText: /^(Disable|Enable)$/ }).first();
    await expect(toggle).toHaveText('Enable', { timeout: 30_000 });
    await toggle.click();
    await expect(toggle).toHaveText('Disable', { timeout: 30_000 });

    let ok = false;
    let last = '';
    for (let i = 0; i < 10 && !ok; i += 1) {
      const r = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo']);
      last = r.out;
      ok = r.code === 0 && r.out.includes('HTTP 200');
      if (!ok) await new Promise((res) => setTimeout(res, 2000));
    }
    expect(ok, `proxy did not recover after re-enable. Last output:\n${last}`).toBe(true);
  });

  test('revoking the workspace from its Revoke button is final: the proxy is refused permanently and re-enabling answers 409', async ({ page }, testInfo) => {
    await login(page);
    await page.goto(`/workspaces/${need('workspaceId')}`);

    // The detail page's own Revoke control (D3). It is final, so it lives in
    // the header's overflow menu rather than beside Disable
    // (uat/artifacts/reviews/DESIGN-REVIEW.md §2.1).
    await page.locator('.detail-header-actions .overflow-menu-btn').click();
    const revokeBtn = page.locator('#ws-revoke-btn');
    await expect(revokeBtn).toBeVisible({ timeout: 30_000 });
    await revokeBtn.click();

    // It confirms first, and the confirmation says what revocation costs.
    const dialog = page.locator('.modal', { has: page.locator('#ws-revoke-confirm') });
    await expect(dialog).toBeVisible();
    const dialogText = await dialog.innerText();
    expect(dialogText, dialogText).toMatch(/final/i);
    expect(dialogText, dialogText).toMatch(/register/i);

    const revoked = page.waitForResponse(
      (r) =>
        r.url().includes(`/api/v1/workspaces/${need('workspaceId')}/revoke`) &&
        r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.locator('#ws-revoke-confirm').click();
    const revoke = await revoked;
    expect(revoke.status(), await revoke.text()).toBe(200);
    expect((await revoke.json()).data.revoked).toBe(true);

    // The page reflects it: the pill reads Revoked, Enable is refused, and the
    // Revoke button is gone.
    await expect(page.locator('span.pill', { hasText: 'Revoked' }).first()).toBeVisible({
      timeout: 30_000,
    });
    const toggle = page.locator('button', { hasText: /^(Disable|Enable)$/ }).first();
    await expect(toggle).toBeDisabled();
    await page.locator('.detail-header-actions .overflow-menu-btn').click();
    await expect(revokeBtn).toBeHidden();

    const r = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo']);
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).not.toContain(UAT.credentialSecret);

    // Documented: revocation is final.
    const reEnable = await apiFromPage(page, 'PUT', `/api/v1/workspaces/${need('workspaceId')}`, {
      enabled: true,
    });
    expect(reEnable.status).toBe(409);
    expect(JSON.stringify(reEnable.body)).toMatch(/revoked/i);

    await page.goto('/workspaces');
    await shot(page, testInfo, 's5-workspace-revoked');
  });
});
