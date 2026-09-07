import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli, sleep } from './helpers/docker';
import { apiFromPage, expectOk, login, shot } from './helpers/ui';
import { recordFinding, writeState } from './helpers/state';
import { callersOtherThanTheServer, idpLog, tokenCalls } from './helpers/mocks';

/**
 * S11 — An application credential (`oauth2_client_credentials`).
 *
 * Documented steps:
 *   docs/credential-encryption.md § "Credential Types / OAuth2 Client
 *     Credentials": "Fields: oauth2_client_id, oauth2_token_endpoint, optional
 *     oauth2_scopes ... Performs client_credentials grant at vend time".
 *   docs/cli-reference.md § "Credential Types and Transforms":
 *     `oauth2_client_credentials` -> "Client credentials grant, then Bearer".
 *   README.md § "Quick Start / 4. Use credentials" (`agentcordon proxy`).
 *   CHANGELOG [Unreleased] § Security: "Vend exchanges client-credentials apps
 *     on the server ... the broker injects it as a bearer" and "The broker
 *     never calls a token endpoint."
 *
 * Everything an admin does happens on /credentials/new. The mock IdP records
 * the address of every token-endpoint caller, which is what makes "the SERVER
 * made the exchange, not the broker" an observation rather than an assumption.
 */

async function createClientCredential(
  page: any,
  testInfo: any,
  opts: {
    name: string;
    clientId: string;
    clientSecret: string;
    tokenEndpoint: string;
    pattern: string;
    screenshot?: string;
  },
): Promise<string> {
  await page.goto('/credentials/new');
  await page.click('button.template-card:has-text("Blank")');
  await expect(page.locator('#cred-type')).toBeVisible();
  await page.selectOption('#cred-type', 'oauth2_client_credentials');

  await expect(page.locator('#cred-field-oauth2_client_id')).toBeVisible();
  await page.fill('#cred-field-oauth2_client_id', opts.clientId);
  await page.fill('#cred-field-oauth2_token_endpoint', opts.tokenEndpoint);
  await page.fill('#cred-field-secret_value', opts.clientSecret);
  await page.fill('#cred-field-oauth2_scopes', 'uat.read');

  await page.fill('#cred-name', opts.name);
  await page.fill('#cred-service', 'uat-idp');
  await page.fill('#cred-url-pattern', opts.pattern);
  if (opts.screenshot) await shot(page, testInfo, opts.screenshot);

  const created = page.waitForResponse(
    (r: any) => r.url().endsWith('/api/v1/credentials') && r.request().method() === 'POST',
    { timeout: 30_000 },
  );
  await page.click('button[type="submit"]:has-text("Store Credential")');
  const response = await created;
  await expectOk(page, response, `storing ${opts.name}`);

  await page.waitForURL(/\/credentials\/[0-9a-f-]{36}$/, { timeout: 30_000 });
  return page.url().split('/').pop()!;
}

test.describe('S11 application credential (oauth2_client_credentials)', () => {
  test('an admin stores an oauth2_client_credentials credential from /credentials/new (docs/credential-encryption.md § "OAuth2 Client Credentials")', async ({
    page,
  }, testInfo) => {
    await login(page);

    const id = await createClientCredential(page, testInfo, {
      name: UAT.oauthCcName,
      clientId: UAT.oauthCcClientId,
      clientSecret: UAT.oauthCcClientSecret,
      tokenEndpoint: `${UAT.idpUrl}/token`,
      pattern: UAT.oauthCcPattern,
      screenshot: 's11-oauth2-client-credentials-form',
    });
    writeState({ oauthCcCredentialId: id });

    const detail = await apiFromPage(page, 'GET', `/api/v1/credentials/${id}`);
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.data.credential_type).toBe('oauth2_client_credentials');
    expect(detail.body.data.allowed_url_pattern).toBe(UAT.oauthCcPattern);
    expect(detail.body.data.metadata.oauth2_client_id).toBe(UAT.oauthCcClientId);
    expect(detail.body.data.metadata.oauth2_token_endpoint).toBe(`${UAT.idpUrl}/token`);
    // The client secret is the encrypted material and must not come back.
    expect(JSON.stringify(detail.body)).not.toContain(UAT.oauthCcClientSecret);
    await shot(page, testInfo, 's11-oauth2-credential-detail');

    // The same form with the short-lived client, for the expiry step below.
    const shortId = await createClientCredential(page, testInfo, {
      name: UAT.oauthCcShortName,
      clientId: UAT.oauthCcShortClientId,
      clientSecret: UAT.oauthCcShortClientSecret,
      tokenEndpoint: `${UAT.idpUrl}/token`,
      pattern: UAT.oauthCcPattern,
    });
    writeState({ oauthCcShortCredentialId: shortId });
  });

  test('a plain-HTTP token endpoint on any host but localhost is refused, and the form says so (create.rs: "oauth2_token_endpoint must use HTTPS")', async ({
    page,
  }, testInfo) => {
    await login(page);

    // Driven through the same /credentials/new form a new user would use --
    // fill it in with a provider that is only reachable over plain HTTP and
    // press Store Credential. No raw API call: the refusal under test is
    // what the admin SEES, not what the endpoint returns.
    await page.goto('/credentials/new');
    await page.click('button.template-card:has-text("Blank")');
    await expect(page.locator('#cred-type')).toBeVisible();
    await page.selectOption('#cred-type', 'oauth2_client_credentials');
    await expect(page.locator('#cred-field-oauth2_client_id')).toBeVisible();
    await page.fill('#cred-field-oauth2_client_id', UAT.oauthCcClientId);
    await page.fill('#cred-field-oauth2_token_endpoint', 'http://idp.example.test/token');
    await page.fill('#cred-field-secret_value', 'irrelevant');
    await page.fill('#cred-name', 'uat-app-token-rejected');
    await page.fill('#cred-service', 'uat-idp');

    const refused = page.waitForResponse(
      (r: any) => r.url().endsWith('/api/v1/credentials') && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.click('button[type="submit"]:has-text("Store Credential")');
    const response = await refused;
    expect(response.status()).toBe(400);
    expect(JSON.stringify(await response.json())).toContain('HTTPS');

    // The user stays on the form and is told why.
    const toast = page.locator('.toast-error').first();
    await expect(toast).toBeVisible();
    await expect(toast).toContainText(/HTTPS/i);
    expect(page.url()).toContain('/credentials/new');
    await shot(page, testInfo, 's11-plain-http-token-endpoint-refused');

    recordFinding({
      scenario: 'S11',
      title:
        'An OAuth2 provider reachable only over plain HTTP cannot be used unless it is literally on localhost, and no document says so',
      doc: 'docs/credential-encryption.md § "Credential Types / OAuth2 Client Credentials" says only "Validates token endpoint is HTTPS (except localhost in dev)"; README § Configuration and docs/cli-reference.md § "Credential Types and Transforms" say nothing',
      detail:
        'crates/server/src/routes/admin_api/credentials/create.rs:169-183 accepts http:// only when the host string is exactly "localhost", "127.0.0.1" or "::1". A provider on a private network or a Docker service name is refused with "oauth2_token_endpoint must use HTTPS" and no hint about the loopback exemption. The refusal itself is correct hardening; the gap is that the one escape hatch is documented as a parenthesis.',
      workaround:
        'The UAT mock IdP runs inside the server container\'s network namespace so the token endpoint really is http://127.0.0.1:9000/token from the server\'s point of view. Labelled workaround; see uat/README.md § Known concessions.',
    });
  });

  test('the proxied call reaches the upstream with a bearer the SERVER exchanged (CHANGELOG: "Vend exchanges client-credentials apps on the server")', async () => {
    const before = tokenCalls(await idpLog(), 'client_credentials').length;

    const r = cli(['proxy', UAT.oauthCcName, 'GET', 'http://upstream:8080/oauth-api']);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain('HTTP 200');
    // The mock upstream asked the IdP who the token belongs to.
    expect(r.out).toContain('"grant":"client_credentials"');
    expect(r.out).toContain(`"subject":"${UAT.oauthCcClientId}"`);
    // Neither the client secret nor the access token may reach the caller in
    // the clear: the injected Authorization header comes back redacted.
    expect(r.out).not.toContain(UAT.oauthCcClientSecret);

    const entries = await idpLog();
    const exchanges = tokenCalls(entries, 'client_credentials').filter(
      (e) => e.client_id === UAT.oauthCcClientId,
    );
    expect(exchanges.length, JSON.stringify(exchanges)).toBeGreaterThanOrEqual(before + 1);
    // The exchange was made by the AgentCordon server: the mock IdP shares the
    // server container's network namespace, so a server-side call arrives from
    // 127.0.0.1 and anything else (the broker, the CLI) does not.
    for (const e of exchanges) {
      expect(e.remote_addr, JSON.stringify(e)).toBe('127.0.0.1');
      expect(e.has_client_secret, JSON.stringify(e)).toBe(true);
    }
    expect(
      callersOtherThanTheServer(entries),
      'no component other than the server may call the token endpoint',
    ).toEqual([]);
  });

  test('DEFECT: a second call inside the token lifetime exchanges again — the upstream token cache never caches', async () => {
    const count = async () =>
      tokenCalls(await idpLog(), 'client_credentials').filter(
        (e) => e.client_id === UAT.oauthCcClientId,
      ).length;

    const before = await count();
    const r = cli(['proxy', UAT.oauthCcName, 'GET', 'http://upstream:8080/oauth-api']);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain('HTTP 200');
    const after = await count();

    if (after > before) {
      recordFinding({
        scenario: 'S11',
        title:
          'The upstream OAuth2 access-token cache never caches: OAuth2TokenManager holds a bare DashMap and is deep-copied every time AppState is cloned, so every vend and every MCP sync performs a fresh token exchange at the provider',
        doc: 'crates/core/src/oauth2/token_manager.rs documents the opposite ("DashMap is Clone via an internal Arc, so cloning the manager shares the same cache across handlers"); CHANGELOG [Unreleased] § Security describes the server exchanging and sealing "the short-lived access token"',
        detail:
          `dashmap 6.1.0's Clone impl (dashmap/src/lib.rs:95-111) copies every shard into a new map; it does not share an Arc. OAuth2TokenManager { client, cache: DashMap<..> } derives Clone, CredentialService holds one by value, Services holds CredentialService by value, and AppState holds Services by value — and axum clones AppState for every request. Each request therefore gets a private snapshot of the cache, writes to it, and drops it. AppState::new already hands Services a clone (crates/server/src/state.rs:209) and keeps another (state.rs:218), so the two are separate caches before a single request arrives. Measured: two successive \`agentcordon proxy\` calls seconds apart against a credential whose token lives 120s produced ${after - before} extra client_credentials exchange(s) at the provider (${before} -> ${after}). ` +
          'Consequences: every credential vend and every 30s MCP sync hits the provider token endpoint (latency, rate limits, and for oauth2_user_authorization a refresh-token ROTATION per sync — this run watched the refresh token rotate on essentially every sync tick, so a single failed persist would strand the credential). EXPIRY_BUFFER_SECS and the per-credential single-flight mutex are equally inert.',
      });
    }

    expect(
      after,
      'a cached access token should have been reused within its lifetime',
    ).toBe(before);
  });

  test('a short-lived application token is re-exchanged and keeps working past its lifetime', async () => {
    test.setTimeout(240_000);
    const count = async () =>
      tokenCalls(await idpLog(), 'client_credentials').filter(
        (e) => e.client_id === UAT.oauthCcShortClientId,
      ).length;

    const first = cli(['proxy', UAT.oauthCcShortName, 'GET', 'http://upstream:8080/oauth-api']);
    expect(first.code, first.out).toBe(0);
    const afterFirst = await count();
    expect(afterFirst).toBeGreaterThanOrEqual(1);

    // The short-lived client's tokens live 40s and the server treats a cached
    // token as expired 30s early, so ~15s is past the cached window.
    await sleep(15_000);

    const second = cli(['proxy', UAT.oauthCcShortName, 'GET', 'http://upstream:8080/oauth-api']);
    expect(second.code, second.out).toBe(0);
    expect(second.out).toContain('HTTP 200');
    expect(await count(), 'a fresh exchange should have happened server-side').toBeGreaterThan(
      afterFirst,
    );

    expect(callersOtherThanTheServer(await idpLog())).toEqual([]);
  });

  test('a target outside the credential\'s allowed_url_pattern is refused (S16: enforcement for the OAuth type)', async () => {
    const r = cli(['proxy', UAT.oauthCcName, 'GET', 'http://upstream:8080/echo']);
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toMatch(/url_pattern_denied|forbidden|403/i);
    expect(r.out).not.toContain(UAT.oauthCcClientSecret);
  });
});
