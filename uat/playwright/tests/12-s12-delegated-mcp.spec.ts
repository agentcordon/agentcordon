import { test, expect, Page } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli, sleep } from './helpers/docker';
import { apiFromPage, expectOk, login, shot } from './helpers/ui';
import { need, readState, writeState } from './helpers/state';
import { callersOtherThanTheServer, idpLog, mcpLog, until } from './helpers/mocks';

/**
 * S12 — A delegated credential (`oauth2_user_authorization`) obtained by
 * provisioning an OAuth2 MCP server from the marketplace.
 *
 * Documented steps:
 *   docs/granting-mcp-server-access.md § "Step 1 / Option C: Provision via
 *     OAuth2 flow": "The server returns an authorize_url. After the user
 *     completes the OAuth2 consent flow, the callback at
 *     GET /api/v1/mcp-servers/oauth/callback handles token exchange,
 *     credential creation, and MCP server provisioning automatically."
 *     (The admin UI's marketplace does exactly this; no curl needed.)
 *   docs/granting-mcp-server-access.md § "Credential Placeholders in Headers":
 *     "For OAuth2 credentials (oauth2_user_authorization type) ... If the
 *     provider rotates the refresh token, the new value is persisted."
 *   docs/granting-mcp-server-access.md § "Step 5 — Call the MCP Tool":
 *     agentcordon mcp-servers / mcp-tools / mcp-call
 *   CHANGELOG [Unreleased] § Security: "Brokers no longer hold provider
 *     secrets ... The server now runs the refresh_token and client_credentials
 *     exchanges itself ... and seals only the short-lived access token."
 *
 * Both provider-client paths are covered: dynamic client registration
 * (RFC 7591) against the IdP listener that publishes a registration endpoint,
 * and a hand-configured provider client against the listener that does not.
 */

/** Open the marketplace card for a template and press its primary button. */
async function installFromMarketplace(page: Page, cardText: string): Promise<void> {
  await page.goto('/mcp-servers/marketplace');
  const card = page.locator('.marketplace-card', { hasText: cardText });
  await expect(card).toBeVisible();
  await card.click();
  const dialog = page.locator('[role="dialog"][aria-labelledby="install-modal-title"]');
  await expect(dialog).toBeVisible();
  const workspace = page.locator('#install-workspace');
  if (await workspace.isVisible().catch(() => false)) {
    await workspace.selectOption({ label: UAT.workspaceName }).catch(async () => {
      // Fall back to the id if the option label is rendered differently.
      await workspace.selectOption(need('workspaceId'));
    });
  }
  await page.locator('.modal-actions .btn-primary').click();
}

test.describe('S12 delegated MCP credential', () => {
  test('a provider without dynamic client registration sends the admin to Settings (manual provider client)', async ({
    page,
  }, testInfo) => {
    await login(page);
    await installFromMarketplace(page, 'UAT Mock MCP (OAuth, manual provider client)');

    const error = page.locator('.install-form-error');
    await expect(error).toBeVisible({ timeout: 30_000 });
    const message = (await error.textContent()) || '';
    expect(message).toContain('Dynamic Client Registration');
    expect(message).toContain('OAuth Provider Clients');
    await shot(page, testInfo, 's12-no-dcr-sends-admin-to-settings');
  });

  test('the admin configures that provider client by hand under Settings > OAuth Provider Clients', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto('/settings');
    await shot(page, testInfo, 's12-settings-oauth-provider-clients');

    // Reveal the create form. The button sits next to the section heading.
    const addButton = page
      .locator('button', { hasText: /Add Client/i })
      .first();
    await addButton.click();

    await page.fill('#opc-label', 'uat-oauth-manual');
    await page.fill('#opc-as-url', UAT.idpNoDcrUrl);
    await page.fill('#opc-authorize', `${UAT.idpNoDcrUrl}/authorize`);
    await page.fill('#opc-token', `${UAT.idpNoDcrUrl}/token`);
    await page.fill('#opc-client-id', UAT.oauthManualClientId);
    await page.fill('#opc-client-secret', UAT.oauthManualClientSecret);
    await page.fill('#opc-scopes', 'uat.read');
    await shot(page, testInfo, 's12-manual-provider-client-form');

    const created = page.waitForResponse(
      (r) =>
        r.url().includes('/api/v1/oauth-provider-clients') &&
        r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.locator('form:has(#opc-client-id) button[type="submit"]').click();
    const response = await created;
    await expectOk(page, response, 'creating the OAuth provider client');

    const list = await apiFromPage(page, 'GET', '/api/v1/oauth-provider-clients');
    expect(list.status, JSON.stringify(list.body)).toBe(200);
    const row = list.body.data.find(
      (c: any) => c.authorization_server_url === UAT.idpNoDcrUrl,
    );
    expect(row, JSON.stringify(list.body.data)).toBeTruthy();
    expect(row.registration_source).toBe('manual');
    expect(row.client_id).toBe(UAT.oauthManualClientId);
    expect(JSON.stringify(list.body)).not.toContain(UAT.oauthManualClientSecret);
    await shot(page, testInfo, 's12-manual-provider-client-saved');
  });

  test('the admin consents at the provider and lands back on the admin UI (manual provider client)', async ({
    page,
  }, testInfo) => {
    test.setTimeout(240_000);
    await login(page);
    await installFromMarketplace(page, 'UAT Mock MCP (OAuth, manual provider client)');

    // The UI navigates the browser to the provider's authorize endpoint.
    await page.waitForURL(new RegExp(`^${UAT.idpNoDcrUrl}/authorize`), { timeout: 60_000 });
    await expect(page.locator('#consent-client-id')).toHaveText(UAT.oauthManualClientId);
    await expect(page.locator('#consent-pkce')).toHaveText('S256');
    await expect(page.locator('#consent-redirect-uri')).toHaveText(
      `${UAT.baseUrl}/api/v1/mcp-servers/oauth/callback`,
    );
    await shot(page, testInfo, 's12-provider-consent-page-manual');

    await page.click('#approve');
    await page.waitForURL(/\/mcp-servers\?oauth=success/, { timeout: 60_000 });
    await shot(page, testInfo, 's12-manual-install-success');

    const servers = await apiFromPage(page, 'GET', '/api/v1/mcp-servers');
    expect(servers.status, JSON.stringify(servers.body)).toBe(200);
    const installed = servers.body.data.find((s: any) => s.name === 'uat-oauth-manual');
    expect(installed, JSON.stringify(servers.body.data)).toBeTruthy();
    expect(installed.auth_method).toBe('oauth2');
    writeState({ mcpManualId: installed.id });
  });

  test('the same flow with dynamic client registration: the SERVER registers a client at the provider', async ({
    page,
  }, testInfo) => {
    test.setTimeout(240_000);
    await login(page);

    const registrationsBefore = (await idpLog()).filter((e) => e.kind === 'register').length;

    await installFromMarketplace(page, 'UAT Mock MCP (OAuth, dynamic registration)');
    await page.waitForURL(new RegExp(`^${UAT.idpUrl}/authorize`), { timeout: 60_000 });
    await shot(page, testInfo, 's12-provider-consent-page-dcr');
    await page.click('#approve');
    await page.waitForURL(/\/mcp-servers\?oauth=success/, { timeout: 60_000 });
    await shot(page, testInfo, 's12-dcr-install-success');

    const entries = await idpLog();
    const registrations = entries.filter((e) => e.kind === 'register');
    expect(registrations.length).toBe(registrationsBefore + 1);
    const registration = registrations[registrations.length - 1];
    expect(registration.remote_addr, 'DCR must be performed by the server').toBe('127.0.0.1');
    expect(registration.redirect_uris).toEqual([
      `${UAT.baseUrl}/api/v1/mcp-servers/oauth/callback`,
    ]);

    const servers = await apiFromPage(page, 'GET', '/api/v1/mcp-servers');
    const installed = servers.body.data.find((s: any) => s.name === 'uat-oauth-dcr');
    expect(installed, JSON.stringify(servers.body.data)).toBeTruthy();
    writeState({ mcpDcrId: installed.id });

    // The provider client the server created is visible to the admin.
    const clients = await apiFromPage(page, 'GET', '/api/v1/oauth-provider-clients');
    const dcrRow = clients.body.data.find(
      (c: any) => c.authorization_server_url === UAT.idpUrl,
    );
    expect(dcrRow, JSON.stringify(clients.body.data)).toBeTruthy();
    expect(dcrRow.registration_source).toBe('dcr');
  });

  test('the delegated credential holds the refresh token and never leaves the server', async ({
    page,
  }) => {
    await login(page);
    const creds = await apiFromPage(page, 'GET', '/api/v1/credentials');
    const delegated = creds.body.data.filter(
      (c: any) => c.credential_type === 'oauth2_user_authorization',
    );
    expect(delegated.length, JSON.stringify(creds.body.data.map((c: any) => c.name))).toBe(2);
    for (const c of delegated) {
      expect(c.metadata.oauth2_token_url).toMatch(/^http:\/\/127\.0\.0\.1:900[01]\/token$/);
      expect(c.metadata.authorization_server_url).toMatch(/^http:\/\/127\.0\.0\.1:900[01]$/);
      expect(c.transform_name).toBe('bearer');
    }
    writeState({ delegatedCredentialNames: delegated.map((c: any) => c.name) });
  });

  test('agentcordon mcp-servers / mcp-tools / mcp-call whoami answer with the delegated subject (docs/granting-mcp-server-access.md § "Step 5")', async () => {
    const servers = cli(['mcp-servers']);
    expect(servers.code, servers.out).toBe(0);
    expect(servers.out).toContain('uat-oauth-dcr');
    expect(servers.out).toContain('uat-oauth-manual');

    const tools = cli(['mcp-tools']);
    expect(tools.code, tools.out).toBe(0);
    expect(tools.out).toContain('whoami');
    expect(tools.out).toContain('echo');

    for (const server of ['uat-oauth-dcr', 'uat-oauth-manual']) {
      const r = cli(['mcp-call', server, 'whoami']);
      expect(r.code, `${server}: ${r.out}`).toBe(0);
      expect(r.out, `${server}: ${r.out}`).toContain(UAT.idpSubject);
      expect(r.out).toMatch(/authorization_code|refresh_token/);
      // The agent must never see a raw access token; the mock MCP server only
      // ever reports fingerprints, and the CLI must not print one either.
      expect(r.out, 'a raw access token must not reach the caller').not.toContain('uat_at_');
    }

    // The broker presented a bearer to the upstream MCP server.
    const seen = (await mcpLog()).filter(
      (e) => e.mount === 'oauth' && e.rpc_method === 'tools/call',
    );
    expect(seen.length).toBeGreaterThanOrEqual(2);
    for (const e of seen) {
      expect(e.auth_seen.authorization?.scheme).toBe('Bearer');
      expect(e.auth_seen.authorization?.value_fingerprint).toMatch(/^sha256:/);
    }
  });

  test('only the server ever talks to the token endpoint, and the refresh token rotates', async () => {
    test.setTimeout(300_000);

    const before = await idpLog();
    expect(
      callersOtherThanTheServer(before),
      'the broker must never call the provider token endpoint',
    ).toEqual([]);

    const rotationsBefore = before.filter((e) => e.kind === 'refresh_rotated').length;

    // The mock IdP issues 100s access tokens; the server treats a cached token
    // as expired 30s early and the broker re-syncs when its cached upstream
    // token is within 60s of expiry, so a call after ~75s forces a refresh.
    await sleep(75_000);
    const r = cli(['mcp-call', 'uat-oauth-dcr', 'whoami']);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain(UAT.idpSubject);

    const rotations = await until(
      'the provider to rotate a refresh token',
      async () => {
        const entries = await idpLog();
        const found = entries.filter((e) => e.kind === 'refresh_rotated');
        return found.length > rotationsBefore ? found : null;
      },
      150_000,
      5_000,
    );

    const rotation = rotations[rotations.length - 1];
    expect(rotation.remote_addr, 'the refresh must be executed by the server').toBe('127.0.0.1');
    expect(rotation.old_refresh_token).not.toBe(rotation.new_refresh_token);
    expect(rotation.generation).toBeGreaterThanOrEqual(2);

    const after = await idpLog();
    expect(callersOtherThanTheServer(after)).toEqual([]);
    // Every refresh_token exchange carried the provider client's secret, which
    // only the server holds.
    for (const e of after.filter((x) => x.kind === 'token' && x.grant_type === 'refresh_token')) {
      expect(e.remote_addr).toBe('127.0.0.1');
    }

    // The rotated refresh token was persisted: the tool still works afterwards.
    const again = cli(['mcp-call', 'uat-oauth-dcr', 'whoami']);
    expect(again.code, again.out).toBe(0);
    expect(again.out).toContain(UAT.idpSubject);
  });

  test('the rotation is visible in the audit trail (CredentialSecretRotated)', async ({ page }) => {
    await login(page);
    const audit = await apiFromPage(
      page,
      'GET',
      '/api/v1/audit?event_type=credential_secret_rotated&limit=50',
    );
    expect(audit.status, JSON.stringify(audit.body)).toBe(200);

    // docs/credential-encryption.md § "Audit Trail" lists CredentialSecretRotated,
    // and CHANGELOG [Unreleased] says a rotated refresh token is persisted
    // "with a history row and a CredentialSecretRotated audit event". The
    // previous test made the provider rotate one, so a row naming that
    // rotation must be here.
    const rows = audit.body.data.filter((e: any) =>
      JSON.stringify(e).includes('oauth2_refresh_token_rotated'),
    );
    expect(
      rows.length,
      `expected a credential_secret_rotated row for the refresh-token rotation; got ${JSON.stringify(
        audit.body.data,
      ).slice(0, 800)}`,
    ).toBeGreaterThan(0);

    const row = rows[0];
    expect(row.event_type).toBe('credential_secret_rotated');
    expect(
      readState().delegatedCredentialNames,
      'the delegated credentials must have been recorded by an earlier test',
    ).toBeTruthy();
    // The row must never carry a token value.
    expect(JSON.stringify(row)).not.toMatch(/uat_rt_|uat_at_/);
  });

  test('an RFC 9728 resource whose authorization server is on another origin is accepted [D9]', async ({
    page,
  }, testInfo) => {
    test.setTimeout(240_000);
    await login(page);

    // RFC 9728 § 2 exists precisely so a resource server can delegate to an
    // authorization server it does not host. The "RFC 9728 shape" template
    // points oauth2_resource_url at the MCP RESOURCE server
    // (http://127.0.0.1:9100), whose protected-resource document names the
    // IdP on a different origin (http://127.0.0.1:9000). Discovery used to
    // call validate_endpoint_origin(resource_url, ...) for the authorize,
    // token and registration endpoints and refuse this arrangement outright,
    // which made every deployment whose MCP server and IdP are separate hosts
    // unreachable. It must now follow authorization_servers[0].
    //
    // Runs last in this file so it cannot consume the dynamic registration
    // the DCR test above counts: the provider client for this IdP origin
    // already exists by now, and re-using it is the correct behaviour.
    await installFromMarketplace(page, 'UAT Mock MCP (OAuth, RFC 9728 shape)');

    // No refusal: the install proceeds all the way to the provider's own
    // authorize endpoint, on the other origin.
    await expect(page.locator('.install-form-error')).toBeHidden();
    await page.waitForURL(new RegExp(`^${UAT.idpUrl}/authorize`), { timeout: 60_000 });
    await shot(page, testInfo, 's12-rfc9728-cross-origin-accepted');

    const authorizeUrl = new URL(page.url());
    // The authorization request went to the IdP's origin, not the resource's.
    expect(authorizeUrl.origin).toBe(new URL(UAT.idpUrl).origin);
    expect(authorizeUrl.origin).not.toBe(new URL(UAT.mcpUrl).origin);
    // ...and it is a real, PKCE-protected authorization request built by the
    // server, not a stub.
    expect(authorizeUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorizeUrl.searchParams.get('code_challenge')).toBeTruthy();
    expect(authorizeUrl.searchParams.get('redirect_uri')).toBe(
      `${UAT.baseUrl}/api/v1/mcp-servers/oauth/callback`,
    );
    expect(authorizeUrl.searchParams.get('state')).toBeTruthy();

    // Discovery reached the authorization server the *resource* named: the
    // mock IdP recorded an authorize request carrying the client the server
    // registered with it. (The authorize request itself is the browser's, so
    // its remote_addr is the host, not the server -- the server-side half of
    // the flow is asserted by the DCR and token-endpoint scenarios above,
    // which require remote_addr 127.0.0.1.)
    const idp = await idpLog();
    const authorizes = idp.filter((e) => e.kind === 'authorize');
    expect(
      authorizes.length,
      'the IdP must have seen an authorize request for the RFC 9728 install',
    ).toBeGreaterThan(0);
    expect(authorizes[authorizes.length - 1].client_id).toBe(
      authorizeUrl.searchParams.get('client_id'),
    );

    // Abandon the consent: this scenario is about discovery, and completing
    // it would add a third delegated credential the later assertions count.
    await page.goto('/mcp-servers');
  });
});
