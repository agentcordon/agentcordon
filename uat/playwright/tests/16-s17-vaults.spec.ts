import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { readDoc } from './helpers/docs';
import { apiFromPage, login, loginAs, logout, shot } from './helpers/ui';
import { need, writeState } from './helpers/state';

/**
 * S17 — Vaults, end to end, and the provider-client controls an operator is
 * and is not offered.
 *
 * Every step below is one the shipped docs tell a reader to take.
 *
 * Documented steps (docs/credential-encryption.md § "Vaults"):
 *   "Create a vault | Type a name in New vault name and press Create vault.
 *    Or, while storing a credential, press New vault next to the Vault select
 *    on Credentials -> Add Credential"
 *   "Put a credential in a vault | Pick it from the Vault select on
 *    Credentials -> Add Credential"
 *   "Move a credential | Open the credential, press Edit, choose another vault
 *    from the Vault select, then Save"
 *   "Rename a vault | Rename on its row in Settings -> Vaults"
 *   "Share a vault, read-only | Share on its row, pick the user, press Share.
 *    The user must already exist -- an administrator creates one under
 *    Settings -> Users -> Add User"
 *   "Stop sharing | Revoke next to that user in the vault's share list"
 *   "Delete a vault | Delete on its row. Delete is disabled while the vault
 *    still holds credentials -- move them out first"
 *   § "Who may do what": sharing is the owner's act and nobody else's; a read
 *    share "grants nothing else: no secret reveal, no edit, no delete, no
 *    re-share".
 *
 * Documented steps (docs/granting-mcp-server-access.md, and
 * docs/upgrading.md § "Upgrading from 0.3.x"): provider-client writes need
 * `manage_oauth_provider_clients` (admins), an operator still sees the
 * listing, and deleting a client anything still authenticates with answers
 * 409 naming both counts.
 *
 * Runs after S12/S13, which is what puts a provider client with dependents on
 * the install, and before S9's restart.
 */

const DEFAULT_VAULT_ID = '00000000-0000-0000-0000-000000000001';

/**
 * The Settings row for a vault, addressed by the vault's id.
 *
 * Not by the name: renaming replaces the name cell with an input, and an
 * input's value is not text content, so a name-matched row vanishes mid-edit.
 */
function vaultRow(page: import('@playwright/test').Page, vaultId: string) {
  return page.locator(`#vaults-table tbody[data-vault-id="${vaultId}"]`);
}

test.describe('S17 vaults', () => {
  test('an admin creates the colleague and the operator under Settings -> Users -> Add User', async ({
    page,
  }, testInfo) => {
    await login(page);

    // The doc that sends the reader here.
    expect(readDoc('docs/credential-encryption.md')).toContain(
      '**Add User** in the **User Management** section of Settings',
    );

    for (const [username, password, role] of [
      [UAT.shareUsername, UAT.sharePassword, 'viewer'],
      [UAT.operatorUsername, UAT.operatorPassword, 'operator'],
    ]) {
      await page.goto('/settings');
      await page.click('a[href="/settings/users/new"]');
      await page.waitForURL('**/settings/users/new');
      await page.fill('#user-username', username);
      await page.fill('#user-password', password);
      await page.selectOption('#user-role', role);

      const created = page.waitForResponse(
        (r) => r.url().endsWith('/api/v1/users') && r.request().method() === 'POST',
        { timeout: 30_000 },
      );
      await page.click('button[type="submit"]:has-text("Create User")');
      expect((await created).status()).toBeLessThan(300);
    }
    await shot(page, testInfo, 's17-users-created');

    // Their ids, for asserting the share list names the right person. Read
    // from the page's own session, the way the Settings page reads it.
    const users = await apiFromPage(page, 'GET', '/api/v1/users');
    expect(users.status, JSON.stringify(users.body)).toBe(200);
    const find = (n: string) =>
      users.body.data.find((u: any) => u.username === n);
    expect(find(UAT.shareUsername), 'the colleague was created').toBeTruthy();
    expect(find(UAT.operatorUsername), 'the operator was created').toBeTruthy();
    writeState({
      shareUserId: find(UAT.shareUsername).id,
      operatorUserId: find(UAT.operatorUsername).id,
    });
  });

  test('an admin creates a vault from the New Credential form and stores a credential in it', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto('/credentials/new');
    await page.click('button.template-card:has-text("Blank")');

    // "press New vault next to the Vault select on Credentials -> Add
    // Credential".
    await page.click('#cred-vault-new-btn');
    await page.fill('#cred-vault-new-name', UAT.vaultName);
    const vaultCreated = page.waitForResponse(
      (r) => r.url().endsWith('/api/v1/vaults') && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.click('#cred-vault-new-create');
    const vaultResponse = await vaultCreated;
    expect(vaultResponse.status()).toBe(200);
    const vaultId = (await vaultResponse.json()).data.id;
    expect(vaultId).not.toBe(DEFAULT_VAULT_ID);
    writeState({ vaultId });

    // The form selects the vault it just made, by id.
    expect(await page.locator('#cred-vault').inputValue()).toBe(vaultId);
    await shot(page, testInfo, 's17-new-vault-selected');

    await page.fill('#cred-name', UAT.vaultCredentialName);
    await page.fill('#cred-service', 'upstream');
    await page.fill('#cred-field-secret_value', UAT.vaultCredentialSecret);

    const credCreated = page.waitForResponse(
      (r) => r.url().endsWith('/api/v1/credentials') && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.click('button[type="submit"]:has-text("Store Credential")');
    expect((await credCreated).status()).toBe(200);
    await page.waitForURL(/\/credentials\/[0-9a-f-]{36}$/, { timeout: 30_000 });
    const credentialId = page.url().split('/').pop()!;
    writeState({ vaultCredentialId: credentialId });

    const detail = await apiFromPage(
      page,
      'GET',
      `/api/v1/credentials/${credentialId}`,
    );
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.data.vault_id).toBe(vaultId);
    expect(detail.body.data.vault_name).toBe(UAT.vaultName);

    // The detail page shows the vault by name, and the list filters by it.
    await expect(page.locator('body')).toContainText(UAT.vaultName);
    await page.goto('/credentials');
    await page.selectOption('#cred-vault-filter', vaultId);
    await expect(
      page.locator(`tr.cred-row[aria-label="${UAT.vaultCredentialName}"]`),
    ).toBeVisible();
    await expect(
      page.locator(`tr.cred-row[aria-label="${UAT.credentialName}"]`),
    ).toHaveCount(0);
    await shot(page, testInfo, 's17-credentials-filtered-by-vault');
  });

  test('the owner renames the vault from Settings -> Vaults', async ({ page }, testInfo) => {
    await login(page);
    await page.goto('/settings');

    const row = vaultRow(page, need('vaultId'));
    await expect(row).toBeVisible();
    await expect(row).toContainText(UAT.vaultName);
    await row.locator('.vault-rename-btn').click();
    await row.locator('.vault-rename-input').fill(UAT.vaultRenamed);

    const renamed = page.waitForResponse(
      (r) => /\/api\/v1\/vaults\/[0-9a-f-]{36}$/.test(r.url()) && r.request().method() === 'PATCH',
      { timeout: 30_000 },
    );
    await row.locator('button:has-text("Save")').click();
    expect((await renamed).status()).toBe(200);

    await expect(row).toContainText(UAT.vaultRenamed);
    await shot(page, testInfo, 's17-vault-renamed');
  });

  test('the owner shares the vault read-only with the colleague, and the share list names them', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto('/settings');

    const row = vaultRow(page, need('vaultId'));
    await row.locator('.vault-share-btn').click();
    // `select.vault-share-user`, not `.vault-share-user`: the control is a
    // picker when the caller may list users and a plain id field when they may
    // not, and both are in the DOM with one hidden. An admin gets the picker.
    await row.locator('select.vault-share-user').selectOption({ label: UAT.shareUsername });

    const shared = page.waitForResponse(
      (r) => r.url().includes('/shares') && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await row.locator('.vault-share-submit').click();
    const shareResponse = await shared;
    expect(shareResponse.status()).toBe(200);
    // `read` is the only level the control offers and the only one the API keeps.
    expect((await shareResponse.json()).data.permission_level).toBe('read');

    await expect(row.locator('.vault-share-row')).toContainText(UAT.shareUsername);
    await shot(page, testInfo, 's17-vault-shared');
  });

  test('the colleague sees the shared vault and its credential, and no secret, edit or re-share', async ({
    page,
  }, testInfo) => {
    await loginAs(page, UAT.shareUsername, UAT.sharePassword);

    // The vault appears, marked with who shared it.
    await page.goto('/settings');
    const row = vaultRow(page, need('vaultId'));
    await expect(row).toBeVisible();
    await expect(row).toContainText(UAT.vaultRenamed);
    await expect(row).toContainText('Shared by');
    await expect(row).toContainText(UAT.rootUsername);
    // Nothing that writes: not the owner, so no rename, share or delete, and
    // a viewer is offered no way to create a vault either.
    await expect(row.locator('.vault-rename-btn')).toBeHidden();
    await expect(row.locator('.vault-share-btn')).toBeHidden();
    await expect(row.locator('.overflow-menu')).toBeHidden();
    await expect(row.locator('.vault-delete-btn')).toBeHidden();
    await expect(page.locator('#vault-create-btn')).toHaveCount(0);
    await shot(page, testInfo, 's17-colleague-sees-shared-vault');

    // The credential in it is visible by name — and nothing more.
    await page.goto('/credentials');
    await expect(
      page.locator(`tr.cred-row[aria-label="${UAT.vaultCredentialName}"]`),
    ).toBeVisible();
    await page.click(`tr.cred-row[aria-label="${UAT.vaultCredentialName}"]`);
    // The row is a link to the credential's own page, not a selection into a
    // pane (uat/artifacts/reviews/DESIGN-REVIEW.md §2.3).
    await page.waitForURL(/\/credentials\/[0-9a-f-]{36}$/, { timeout: 30_000 });
    await expect(page.locator('.detail-card-narrow')).toContainText(
      UAT.vaultCredentialName,
    );
    await expect(page.locator('body')).not.toContainText(
      UAT.vaultCredentialSecret,
    );

    // "It grants nothing else": the pane says so and offers none of the four
    // controls the server would refuse. The recipient used to be shown Reveal
    // Secret, Edit, Delete and Grant Permissions, click one, and get a silent
    // failure in the console (uat/artifacts/fresh-user-native.md Finding 7).
    const pane = page.locator('.detail-card-narrow');
    await expect(pane.locator('#cred-shared-read-notice')).toBeVisible();
    await expect(
      pane.locator('.detail-header-actions button:has-text("Edit")'),
    ).toBeHidden();
    await expect(
      pane.locator('.detail-header-actions button:has-text("Delete")'),
    ).toBeHidden();
    await expect(pane.locator('button:has-text("Reveal Secret")')).toBeHidden();
    await expect(page.locator('.grant-card')).toBeHidden();
    await shot(page, testInfo, 's17-colleague-sees-credential');

    // The API says the same thing, and says why the controls are missing.
    const credentialId = need('vaultCredentialId');
    const shared = await apiFromPage(
      page,
      'GET',
      `/api/v1/credentials/${credentialId}`,
    );
    expect(shared.status, JSON.stringify(shared.body)).toBe(200);
    expect(shared.body.data.access).toBe('shared_read');

    // Reveal is refused — with 403 and the policy's own sentence, not a 404
    // for a credential this same caller just read (docker F-13).
    const reveal = await apiFromPage(
      page,
      'POST',
      `/api/v1/credentials/${credentialId}/reveal`,
    );
    expect(
      reveal.status,
      `a read share must be refused the secret, not told it is missing: ${JSON.stringify(reveal.body)}`,
    ).toBe(403);
    expect(reveal.body.error.message).toBe('access denied by policy');
    expect(JSON.stringify(reveal.body)).not.toContain(UAT.vaultCredentialSecret);

    // "no re-share": the API refuses it, and the page never offered the
    // control — checked above. Probing the endpoint is what proves the refusal
    // is the product's, not the template's.
    const vaultId = need('vaultId');
    const reshare = await apiFromPage(page, 'POST', `/api/v1/vaults/${vaultId}/shares`, {
      user_id: need('operatorUserId'),
      permission: 'read',
    });
    expect(
      reshare.status,
      `re-sharing someone else's vault must be refused: ${JSON.stringify(reshare.body)}`,
    ).toBe(403);
  });

  test('the owner revokes the share, and the colleague stops seeing the vault', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto('/settings');

    const row = vaultRow(page, need('vaultId'));
    await row.locator('.vault-share-btn').click();
    await expect(row.locator('.vault-share-row')).toContainText(UAT.shareUsername);

    const revoked = page.waitForResponse(
      (r) => r.url().includes('/shares/') && r.request().method() === 'DELETE',
      { timeout: 30_000 },
    );
    await row.locator('.vault-share-revoke').click();
    expect((await revoked).status()).toBe(200);
    await expect(row.locator('.vault-share-row')).toHaveCount(0);
    await shot(page, testInfo, 's17-vault-share-revoked');

    await logout(page);
    await loginAs(page, UAT.shareUsername, UAT.sharePassword);
    await page.goto('/settings');
    await expect(vaultRow(page, need('vaultId'))).toHaveCount(0);
    await page.goto('/credentials');
    await expect(
      page.locator(`tr.cred-row[aria-label="${UAT.vaultCredentialName}"]`),
    ).toHaveCount(0);
  });

  test('deleting the non-empty vault is refused, and the reason is on the control', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto('/settings');

    const row = vaultRow(page, need('vaultId'));
    await expect(row.locator('td').nth(1)).toHaveText('1');

    // The doc: "Delete is disabled while the vault still holds credentials --
    // move them out first". The control says so before it is pressed. It is a
    // destructive action, so it sits in the row's overflow menu
    // (uat/artifacts/reviews/DESIGN-REVIEW.md §2.1).
    await row.locator('.overflow-menu-btn').click();
    const del = row.locator('.vault-delete-btn');
    await expect(del).toBeVisible();
    await expect(del).toBeDisabled();
    await expect(del).toHaveAttribute(
      'title',
      /still holds 1 credential\(s\); move or delete them first/,
    );
    await shot(page, testInfo, 's17-vault-delete-disabled');

    // And the server would refuse it too, with the same reason — so the
    // disabled control is a courtesy, not the enforcement.
    const attempt = await apiFromPage(
      page,
      'DELETE',
      `/api/v1/vaults/${need('vaultId')}`,
    );
    expect(attempt.status, JSON.stringify(attempt.body)).toBe(409);
    expect(attempt.body.error.message).toContain('move or delete them first');
  });

  test('the owner moves the credential back to the default vault and deletes the empty one', async ({
    page,
  }, testInfo) => {
    await login(page);

    // "Open the credential, press Edit, choose another vault from the Vault
    // select, then Save".
    await page.goto(`/credentials/${need('vaultCredentialId')}`);
    await page.click('.detail-header-actions button:has-text("Edit")');
    await page.selectOption('#cred-vault-select', DEFAULT_VAULT_ID);

    const moved = page.waitForResponse(
      (r) => r.url().includes('/api/v1/credentials/') && r.request().method() === 'PUT',
      { timeout: 30_000 },
    );
    await page.click('.detail-header-actions button:has-text("Save")');
    const moveResponse = await moved;
    expect(moveResponse.status()).toBe(200);
    expect((await moveResponse.json()).data.vault_id).toBe(DEFAULT_VAULT_ID);
    await shot(page, testInfo, 's17-credential-moved-to-default');

    // Now the vault is empty, so Delete is offered.
    await page.goto('/settings');
    const row = vaultRow(page, need('vaultId'));
    await expect(row.locator('td').nth(1)).toHaveText('0');
    await row.locator('.overflow-menu-btn').click();
    const del = row.locator('.vault-delete-btn');
    await expect(del).toBeEnabled();
    await del.click();

    await expect(page.locator('#vault-delete-modal')).toBeVisible();
    const deleted = page.waitForResponse(
      (r) => /\/api\/v1\/vaults\/[0-9a-f-]{36}$/.test(r.url()) && r.request().method() === 'DELETE',
      { timeout: 30_000 },
    );
    await page.click('#vault-delete-confirm');
    expect((await deleted).status()).toBe(200);

    await expect(vaultRow(page, need('vaultId'))).toHaveCount(0);
    await shot(page, testInfo, 's17-vault-deleted');

    // The credential survived the vault it used to be in.
    const detail = await apiFromPage(
      page,
      'GET',
      `/api/v1/credentials/${need('vaultCredentialId')}`,
    );
    expect(detail.status).toBe(200);
    expect(detail.body.data.vault_name).toBe('default');
  });

  test('the default vault is offered no rename, share or delete', async ({ page }) => {
    await login(page);
    await page.goto('/settings');

    const row = vaultRow(page, DEFAULT_VAULT_ID);
    await expect(row).toBeVisible();
    await expect(row).toContainText('default');
    for (const control of ['.vault-rename-btn', '.vault-share-btn', '.vault-delete-btn']) {
      await expect(row.locator(control)).toBeHidden();
    }
  });
});

test.describe('S17 provider clients are admin-only to change', () => {
  test('an operator sees the provider-client listing without the add, edit or delete controls', async ({
    page,
  }, testInfo) => {
    await loginAs(page, UAT.operatorUsername, UAT.operatorPassword);
    await page.goto('/settings');

    // The listing stays: an operator has to see which client an origin uses.
    await expect(page.locator('#opc-clients-table')).toBeVisible();
    await shot(page, testInfo, 's17-operator-provider-clients');

    for (const control of [
      '#opc-add-btn',
      '#opc-new-client-form',
      '#opc-delete-modal',
      '.opc-delete',
      '.opc-reregister',
      '.opc-toggle',
    ]) {
      await expect(page.locator(control)).toHaveCount(0);
    }
    // The listing still says which client each origin uses, and whether it is
    // enabled — just not through a control that writes.
    await expect(page.locator('#opc-clients-table tbody tr').first()).toContainText(
      'Admins only',
    );

    // And the API refuses the write regardless of what the page renders.
    const clients = await apiFromPage(page, 'GET', '/api/v1/oauth-provider-clients');
    expect(clients.status, JSON.stringify(clients.body)).toBe(200);
    const first = clients.body.data[0];
    expect(first, 'S12 left at least one provider client behind').toBeTruthy();
    const refused = await apiFromPage(
      page,
      'DELETE',
      `/api/v1/oauth-provider-clients/${first.id}`,
    );
    expect(
      refused.status,
      `an operator must not delete a provider client: ${JSON.stringify(refused.body)}`,
    ).toBe(403);
  });

  test('an admin has every provider-client control', async ({ page }, testInfo) => {
    await login(page);
    await page.goto('/settings');

    await expect(page.locator('#opc-clients-table')).toBeVisible();
    await expect(page.locator('#opc-add-btn')).toBeVisible();
    await shot(page, testInfo, 's17-admin-provider-clients');
  });

  test('deleting a provider client with dependents is refused in the UI, naming both counts', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto('/settings');
    await expect(page.locator('#opc-clients-table')).toBeVisible();

    // S12 installed OAuth2 MCP servers and delegated credentials against these
    // clients, so at least one of them has dependents. Walk the rows through
    // the page's own Delete control until the server refuses one; a client the
    // server would let go is left alone, because pressing Delete on it would
    // really delete it.
    const rows = await page.locator('#opc-clients-table tbody tr').count();
    expect(rows, 'S12 left provider clients behind').toBeGreaterThan(0);

    let refusal: string | null = null;
    for (let i = 0; i < rows && refusal === null; i++) {
      const row = page.locator('#opc-clients-table tbody tr').nth(i);
      await row.locator('.opc-delete').click();
      await expect(page.locator('#opc-delete-modal')).toBeVisible();

      const attempt = page.waitForResponse(
        (r) =>
          r.url().includes('/api/v1/oauth-provider-clients/') &&
          r.request().method() === 'DELETE',
        { timeout: 30_000 },
      );
      await page.locator('#opc-delete-modal button:has-text("Delete")').click();
      const response = await attempt;

      if (response.status() === 409) {
        refusal = (await response.json()).error.message;
        // The page shows the server's reason instead of claiming success.
        await expect(page.locator('#opc-delete-error')).toBeVisible();
        await expect(page.locator('#opc-delete-error')).toContainText(
          'is still in use',
        );
        await shot(page, testInfo, 's17-provider-client-delete-refused');
        await page.keyboard.press('Escape');
      } else {
        throw new Error(
          `provider client row ${i} answered HTTP ${response.status()} — every client S12 ` +
            'left behind should still have dependents; deleting one is not something this ' +
            'scenario may do',
        );
      }
    }

    // The refusal names both counts, as docs/upgrading.md says it does.
    expect(refusal, 'a provider client with dependents refused the delete').toBeTruthy();
    expect(refusal!).toMatch(/OAuth2 credential\(s\)/);
    expect(refusal!).toMatch(/MCP server\(s\)/);
  });
});
