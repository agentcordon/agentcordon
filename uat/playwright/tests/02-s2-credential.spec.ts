import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { apiFromPage, login, shot } from './helpers/ui';
import { need, writeState } from './helpers/state';

/**
 * S2 — Create a credential, entirely through the admin UI.
 *
 * Documented steps:
 *   README.md § "Why AgentCordon" / "Features" — the vault and the
 *     `allowed_url_pattern` restriction are admin-UI concerns.
 *   docs/credential-encryption.md § "Credential fields" documents
 *     `allowed_url_pattern` as "SSRF mitigation -- restricts which URLs this
 *     credential can be used against".
 *   docs/credential-encryption.md § "Vaults" — "Pick it from the Vault select
 *     on Credentials -> Add Credential. Leave it on `default` if you are not
 *     sure", and "Omitted on create means the system default vault".
 *   docs/cli-reference.md § "agentcordon credentials" — the workspace side.
 *
 * The admin UI carries a first-class "Allowed URL pattern" input and a Vault
 * select on /credentials/new, so no raw API call is needed for this scenario.
 */
const DEFAULT_VAULT_ID = '00000000-0000-0000-0000-000000000001';
test.describe('S2 credential', () => {
  test('an admin creates a generic credential with an allowed URL pattern from /credentials/new', async ({ page }, testInfo) => {
    await login(page);

    await page.goto('/credentials');
    await shot(page, testInfo, 's2-credentials-empty');

    await page.click('a[href="/credentials/new"]');
    await page.waitForURL('**/credentials/new');

    // "Blank / Start from scratch" is the generic template; it is selected by
    // default but click it so the scenario mirrors what a user does.
    await page.click('button.template-card:has-text("Blank")');

    // The Type picker names the `credential_type` the docs, the CLI and the
    // API name, not a vocabulary of its own: `generic` used to read "API Key",
    // directly above the two types that really are API keys
    // (uat/artifacts/fresh-user-docker.md F-7).
    await expect(page.locator('#cred-type option')).toHaveText([
      /^generic — /,
      /^api_key_header — /,
      /^api_key_query — /,
      /^aws — /,
      /^oauth2_client_credentials — /,
    ]);

    // `transform_name` is documented and had no field on either form
    // (uat/artifacts/fresh-user-native.md Finding 5). It is offered for
    // `generic`, the one type with a choice, and its default is `bearer`.
    const transform = page.locator('#cred-transform');
    await expect(transform).toBeVisible();
    await expect(transform.locator('option')).toHaveText([
      /^bearer — /,
      /^basic-auth — /,
      /^identity — /,
    ]);
    expect(await transform.inputValue()).toBe('bearer');
    // Every other type fixes its own injection, so the control goes away.
    await page.selectOption('#cred-type', 'aws');
    await expect(transform).toBeHidden();
    await page.selectOption('#cred-type', 'generic');
    await expect(transform).toBeVisible();

    await page.fill('#cred-name', UAT.credentialName);
    await page.fill('#cred-service', 'upstream');
    await page.fill('#cred-field-secret_value', UAT.credentialSecret);
    await page.fill('#cred-url-pattern', UAT.credentialPattern);

    // The Vault select is populated from GET /api/v1/vaults and offers the
    // system default, which the doc tells the reader to leave alone. Left
    // untouched, the form submits that vault's id.
    const vaultSelect = page.locator('#cred-vault');
    await expect(vaultSelect).toBeVisible();
    await expect(vaultSelect.locator('option')).toHaveText([/default/]);
    expect(await vaultSelect.inputValue()).toBe(DEFAULT_VAULT_ID);

    await shot(page, testInfo, 's2-new-credential-form');

    // The form navigates to the new credential on success, which tears down
    // the response body — assert on the status here and on the stored fields
    // from the detail page's own API call below.
    const createResponse = page.waitForResponse(
      (r) => r.url().endsWith('/api/v1/credentials') && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.click('button[type="submit"]:has-text("Store Credential")');
    const created = await createResponse;
    expect(created.status()).toBe(200);

    await page.waitForURL(/\/credentials\/[0-9a-f-]{36}$/, { timeout: 30_000 });
    const credentialId = page.url().split('/').pop()!;
    writeState({ credentialId });

    const detail = await apiFromPage(page, 'GET', `/api/v1/credentials/${credentialId}`);
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.data.name).toBe(UAT.credentialName);
    expect(detail.body.data.allowed_url_pattern).toBe(UAT.credentialPattern);
    expect(detail.body.data.credential_type).toBe('generic');
    // The Transform select's value is submitted as `transform_name`.
    expect(detail.body.data.transform_name).toBe('bearer');
    // The owner reaches it by policy, so the page offers every control.
    expect(detail.body.data.access).toBe('full');
    // A vault is a row: the credential names it by id and carries the display
    // name for showing.
    expect(detail.body.data.vault_id).toBe(DEFAULT_VAULT_ID);
    expect(detail.body.data.vault_name).toBe('default');

    await expect(page.locator('body')).toContainText(UAT.credentialPattern);
    await shot(page, testInfo, 's2-credential-detail');
  });

  test('the credential appears on the API-backed credentials list page', async ({ page }, testInfo) => {
    await login(page);

    const listResponse = page.waitForResponse(
      (r) => r.url().endsWith('/api/v1/credentials') && r.request().method() === 'GET',
      { timeout: 30_000 },
    );
    await page.goto('/credentials');
    const list = await listResponse;
    expect(list.status()).toBe(200);
    const names = (await list.json()).data.map((c: any) => c.name);
    expect(names).toContain(UAT.credentialName);

    await expect(
      page.locator(`tr.cred-row[aria-label="${UAT.credentialName}"]`),
    ).toBeVisible();
    // The row names the type the docs name, not a label invented for the UI.
    await expect(
      page.locator(`tr.cred-row[aria-label="${UAT.credentialName}"] .cred-type-cell`),
    ).toContainText('generic');
    await shot(page, testInfo, 's2-credentials-list');
  });

  /*
   * `/credentials/{id}` is the credential, on every viewport. It used to render
   * the split-pane list with that row selected, and the CSS hid the pane below
   * 768 px — so a link copied from a desktop showed a phone the list and
   * nothing else, until a second route and a redirect were bolted on
   * (uat/artifacts/reviews/UI-REVIEW-live.md M4, uat/artifacts/reviews/UI-REVIEW-static.md J1). One page needs
   * neither (uat/artifacts/reviews/DESIGN-REVIEW.md §2.3); `/view` is kept as a redirect to it.
   */
  test('the canonical credential deep link shows the credential on a phone', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.setViewportSize({ width: 390, height: 844 });

    const credentialId = need('credentialId');
    await page.goto(`/credentials/${credentialId}/view`);

    // The old link redirects to the canonical page, which is the one every
    // viewport reads.
    await page.waitForURL(`**/credentials/${credentialId}`, { timeout: 30_000 });
    await expect(page.locator('h2.page-title')).toHaveText('Credential Details');
    await expect(page.locator('div.detail-header h3').first()).toHaveText(UAT.credentialName, {
      timeout: 30_000,
    });
    // Created / Owner / ID are one small line under the title now, with the
    // uuid copyable rather than a titled row (uat/artifacts/reviews/DESIGN-REVIEW.md 1.6).
    await expect(page.locator('.detail-meta-line')).toBeVisible();
    await expect(
      page.locator('.detail-meta-line button[aria-label="Copy credential ID"]'),
    ).toBeVisible();
    await shot(page, testInfo, 's2-credential-deeplink-mobile');
  });

  test('no admin page asks the browser for something the server does not serve', async ({
    page,
  }) => {
    // Every admin page load logged one `Failed to load resource: 404` in the
    // console — `/favicon.ico`, which a browser asks for on its own
    // (uat/artifacts/fresh-user-docker.md F-18).
    await login(page);

    const missing: string[] = [];
    page.on('response', (r) => {
      // Static assets only: an API 404 is a route's own answer about a row,
      // not a page asking for a file that is not there.
      if (r.status() === 404 && !new URL(r.url()).pathname.startsWith('/api/')) {
        missing.push(`${r.request().method()} ${new URL(r.url()).pathname}`);
      }
    });

    for (const path of ['/dashboard', '/credentials', '/audit', '/settings']) {
      await page.goto(path);
      // The shell holds an SSE stream open, so `networkidle` never arrives.
      await page.waitForTimeout(1_000);
    }

    expect(missing, 'pages asked for files the server answers 404 for').toEqual([]);
  });
});
