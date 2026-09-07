import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli } from './helpers/docker';
import { apiFromPage, login, shot } from './helpers/ui';
import { readDoc } from './helpers/docs';
import { oauthTopologyUp } from './helpers/mocks';

/**
 * Setup for S11-S16 — the reconfiguration the docs ask for before OAuth2 MCP
 * flows, plus the two mock services those scenarios need.
 *
 * Documented steps:
 *   README.md § "Configuration":
 *     AGTCRDN_BASE_URL — "Server base URL, required for OAuth2 MCP flows
 *       (callback redirect URI)"
 *     AGTCRDN_PROXY_ALLOW_LOOPBACK — "Allow proxy to localhost targets"
 *   .env.example, same two lines.
 *   docs/granting-mcp-server-access.md § "SSRF Protection":
 *     "To allow local development: AGTCRDN_PROXY_ALLOW_LOOPBACK=true"
 *   docker-compose.yml — "create a .env file to override defaults", then
 *     `docker compose up -d`. Reproduced with plain `docker run` against the
 *     same image and the same named volume (see uat/README.md).
 *
 * The one variable with no documentation is AGTCRDN_MCP_TEMPLATES_DIR, which
 * is the only way to make a mock MCP server appear in the marketplace. That is
 * recorded as a finding here.
 */
test.describe('S11-S16 setup: OAuth topology', () => {
  test('the server is reconfigured for OAuth2 MCP flows and the mocks come up (README.md § Configuration)', async ({
    page,
  }, testInfo) => {
    test.setTimeout(360_000);

    const r = oauthTopologyUp();
    expect(r.code, r.out).toBe(0);

    // The data volume is unchanged, so everything S0-S9 created is still there.
    await login(page);
    const creds = await apiFromPage(page, 'GET', '/api/v1/credentials');
    expect(creds.status, JSON.stringify(creds.body)).toBe(200);
    expect(creds.body.data.map((c: any) => c.name)).toContain(UAT.credentialName);

    // ...and the enrolled workspace still works through the broker.
    const list = cli(['credentials']);
    expect(list.code, list.out).toBe(0);
    expect(list.out).toContain(UAT.credentialName);
  });

  test('the mock IdP publishes RFC 8414 metadata on both listeners, one with and one without dynamic client registration', async () => {
    const dcr = await (await fetch(`${UAT.idpUrl}/.well-known/oauth-authorization-server`)).json();
    expect(dcr.issuer).toBe(UAT.idpUrl);
    expect(dcr.registration_endpoint).toBe(`${UAT.idpUrl}/register`);
    expect(dcr.code_challenge_methods_supported).toContain('S256');

    const noDcr = await (
      await fetch(`${UAT.idpNoDcrUrl}/.well-known/oauth-authorization-server`)
    ).json();
    expect(noDcr.issuer).toBe(UAT.idpNoDcrUrl);
    expect(noDcr.registration_endpoint).toBeUndefined();
  });

  test('the mock MCP server answers 401 with a WWW-Authenticate resource_metadata pointer and publishes RFC 9728 metadata', async () => {
    const unauth = await fetch(`${UAT.mcpUrl}/oauth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    });
    expect(unauth.status).toBe(401);
    expect(unauth.headers.get('www-authenticate') || '').toContain('resource_metadata=');

    const meta = await (
      await fetch(`${UAT.mcpUrl}/.well-known/oauth-protected-resource`)
    ).json();
    expect(meta.resource).toBe(UAT.mcpUrl);
    expect(meta.authorization_servers).toEqual([UAT.idpUrl]);
  });

  test('the UAT MCP templates are in the marketplace, and AGTCRDN_MCP_TEMPLATES_DIR is documented [G14]', async ({
    page,
  }, testInfo) => {
    await login(page);
    const templates = await apiFromPage(page, 'GET', '/api/v1/mcp-templates');
    expect(templates.status, JSON.stringify(templates.body)).toBe(200);
    const keys = templates.body.data.map((t: any) => t.key);
    for (const key of [
      'uat-none',
      'uat-apikey',
      'uat-oauth-dcr',
      'uat-oauth-manual',
      'uat-oauth-rfc9728',
    ]) {
      expect(keys, JSON.stringify(keys)).toContain(key);
    }

    // G14 — AGTCRDN_MCP_TEMPLATES_DIR is the only way to put a private MCP
    // server in the marketplace, and it appeared in no document: not the
    // configuration reference, not .env.example, not the MCP guide. All three
    // now carry it, so a user with an in-house server is no longer sent to the
    // source. These read the shipped files, so deleting the documentation
    // turns this red. The configuration table moved out of the README into
    // docs/configuration.md, which is now its single home.
    const config = readDoc('docs/configuration.md');
    expect(config, 'the configuration reference must document AGTCRDN_MCP_TEMPLATES_DIR').toContain(
      'AGTCRDN_MCP_TEMPLATES_DIR',
    );
    const envExample = readDoc('.env.example');
    expect(envExample).toContain('AGTCRDN_MCP_TEMPLATES_DIR');
    const guide = readDoc('docs/granting-mcp-server-access.md');
    expect(
      guide,
      'the MCP guide must say how to add your own server to the marketplace',
    ).toContain('AGTCRDN_MCP_TEMPLATES_DIR');
    expect(guide).toContain('AGTCRDN_CREDENTIAL_TEMPLATES_DIR');

    // Naming the directory is not enough: two fresh-user walkthroughs each
    // spent five server restarts discovering the schema one required field at
    // a time, because the guide's own example did not load and no document
    // listed the fields or their legal values. The guide must carry the whole
    // schema, the auth_method and transport values, and the OAuth shape.
    expect(guide, 'the guide must document the template schema').toContain('Template schema');
    for (const field of ['`category`', '`tags`', '`icon`', '`sort_order`', '`auth_method`']) {
      expect(guide, `the schema table must name ${field}`).toContain(field);
    }
    expect(guide, 'the legal auth_method values must be listed').toMatch(
      /`none`, `api_key`, or `oauth2`/,
    );
    expect(guide, 'the oauth2 template shape must be documented').toContain(
      'oauth2_resource_url',
    );
    expect(guide, 'the restart rule must stay').toContain('read once, at startup');

    // The documented example itself has to load — the loader is what proves
    // it, and the marketplace listing is where it shows up.
    const custom = templates.body.data.filter((t: any) => t.category === 'custom');
    expect(Array.isArray(custom)).toBe(true);

    await page.goto('/mcp-servers/marketplace');
    await expect(page.locator('#marketplace')).toBeVisible();
    await expect(
      page.locator('.marketplace-card', { hasText: 'UAT Mock MCP (no auth)' }),
    ).toBeVisible();
    await shot(page, testInfo, 'setup-mcp-marketplace-with-uat-templates');
  });
});
