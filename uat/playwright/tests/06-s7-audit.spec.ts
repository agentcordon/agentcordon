import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli } from './helpers/docker';
import { apiFromPage, login, shot } from './helpers/ui';
import { need, writeState } from './helpers/state';

/**
 * S7 — Audit trail, read from the admin UI.
 *
 * Documented step: README.md § "Why AgentCordon" — "Every credential access
 * logged with correlation IDs, SOC/IR ready"; docs/index.md § "Key
 * Capabilities" — "Every credential vend, policy decision, and tool call is
 * logged with correlation IDs". The audit page is at /audit.
 */
test.describe('S7 audit', () => {
  test('the audit page lists a vend event for uat-ws with the target URL in its detail', async ({ page }, testInfo) => {
    await login(page);

    const auditResponse = page.waitForResponse(
      (r) => r.url().includes('/api/v1/audit?limit=') && r.request().method() === 'GET',
      { timeout: 30_000 },
    );
    await page.goto('/audit');
    const audit = await auditResponse;
    expect(audit.status()).toBe(200);
    const events = (await audit.json()).data;

    const vends = events.filter((e: any) => e.event_type === 'credential_vended');
    expect(vends.length, 'expected at least one credential_vended row').toBeGreaterThan(0);

    const forWorkspace = vends.filter((e: any) => e.workspace_name === UAT.workspaceName);
    expect(forWorkspace.length, 'expected a vend row attributed to uat-ws').toBeGreaterThan(0);

    const withTarget = forWorkspace.find(
      (e: any) => e.metadata && String(e.metadata.target_url).startsWith('http://upstream:8080/'),
    );
    expect(withTarget, JSON.stringify(forWorkspace[0])).toBeTruthy();
    expect(withTarget.metadata.credential_name).toBe(UAT.credentialName);
    expect(withTarget.decision).toBe('permit');
    expect(withTarget.action).toBe('vend_credential');

    // And it is visible in the rendered table.
    await expect(page.locator('table.audit-tbl')).toBeVisible();
    await expect(
      page.locator('td.audit-col-type span.pill', { hasText: 'Credential Vended' }).first(),
    ).toBeVisible();
    await expect(
      page.locator('td.audit-col-principal', { hasText: UAT.workspaceName }).first(),
    ).toBeVisible();
    // The API serves CSV, JSONL and syslog; the page used to expose one of
    // them behind a button called "Export CSV" (uat/artifacts/reviews/DESIGN-REVIEW.md 1.17).
    const exportMenu = page.locator('.content-header .overflow-menu');
    await exportMenu.locator('button', { hasText: 'Export' }).click();
    const items = exportMenu.locator('[role="menu"] [role="menuitem"]');
    await expect(items).toHaveCount(3);
    await expect(items.nth(0)).toHaveText('CSV');
    await expect(items.nth(1)).toHaveText('JSONL');
    await expect(items.nth(2)).toHaveText('Syslog');
    await page.keyboard.press('Escape');

    await shot(page, testInfo, 's7-audit-list');
    writeState({ vendEventId: withTarget.id });

    // Expanding the row by clicking it works, and shows the target URL.
    await page.locator('tr.audit-row').first().click();
    await expect(page.locator('tr.audit-detail-row:visible')).toHaveCount(1);
    await shot(page, testInfo, 's7-audit-row-expanded');
  });

  test('deep-linking /audit/{id} expands that event and keeps the URL [D1]', async ({ page }, testInfo) => {
    await login(page);
    const id = need('vendEventId');

    // The route exists (GET /audit/{id}) and clicking a row pushes exactly
    // this URL, so it is what a user copies and shares.
    await page.goto(`/audit/${id}`);
    await expect(page.locator('table.audit-tbl')).toBeVisible();

    await expect(page.locator('tr.audit-detail-row:visible')).toHaveCount(1, { timeout: 30_000 });
    await shot(page, testInfo, 's7-audit-deeplink-expanded');

    const pathname = await page.evaluate(() => window.location.pathname);
    expect(
      pathname,
      'the address bar must still name the event that is open ' +
        '(the template used to carry `x-data="auditListPage()" x-init="init()"`, so Alpine ran ' +
        'init() twice and the second call toggled the row shut again and pushed /audit)',
    ).toBe(`/audit/${id}`);
  });

  test('a URL-pattern refusal is written to the audit trail as credential_vend_denied [D2]', async ({ page }) => {
    await login(page);

    const before = await apiFromPage(page, 'GET', '/api/v1/audit?limit=500');
    const beforeIds = new Set(before.body.data.map((e: any) => e.id));

    const refused = cli(['proxy', UAT.credentialName, 'GET', 'http://evil.example/blocked-probe']);
    expect(refused.code).not.toBe(0);

    // Give the server a moment to write the row.
    await new Promise((r) => setTimeout(r, 2000));
    const after = await apiFromPage(page, 'GET', '/api/v1/audit?limit=500');
    const added = after.body.data.filter((e: any) => !beforeIds.has(e.id));

    // README § "Features" ("Every vend, policy decision and token operation
    // is an append-only row with a correlation id") and docs/index.md
    // § "Key capabilities" / Full audit trail. The refusal used
    // to return from check_vend_target() before Cedar ran and before any
    // emission, so a URL-pattern denial — the enforcement boundary this
    // release added — left no trail at all while a Cedar denial did. This
    // assertion goes red again the moment that early return stops auditing.
    const denial = added.find((e: any) => e.event_type === 'credential_vend_denied');
    expect(
      denial,
      `a refused vend must write a credential_vend_denied row; rows added: ${JSON.stringify(
        added.map((e: any) => e.event_type),
      )}`,
    ).toBeTruthy();

    expect(denial.action).toBe('vend_credential');
    expect(denial.decision).toBe('forbid');
    expect(denial.workspace_name).toBe(UAT.workspaceName);
    expect(denial.metadata.credential_name).toBe(UAT.credentialName);
    // The row names what was asked for, which is what makes it usable in an
    // investigation.
    expect(denial.metadata.target_url).toBe('http://evil.example/blocked-probe');
    expect(denial.metadata.target_method).toBe('GET');
    expect(denial.metadata.allowed_url_pattern).toBe(UAT.credentialPattern);
    expect(denial.correlation_id, JSON.stringify(denial)).toBeTruthy();
    // Nothing about the secret may appear in an audit row.
    expect(JSON.stringify(denial)).not.toContain(UAT.credentialSecret);
  });
});
