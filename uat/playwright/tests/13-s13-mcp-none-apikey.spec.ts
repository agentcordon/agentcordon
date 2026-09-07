import { test, expect, Page } from '@playwright/test';
import * as crypto from 'crypto';
import { UAT } from './helpers/env';
import { cli } from './helpers/docker';
import { apiFromPage, expectOk, login, shot } from './helpers/ui';
import { need, writeState } from './helpers/state';
import { mcpLog } from './helpers/mocks';

/**
 * S13 — MCP servers with auth `none` and `api_key`.
 *
 * Documented steps:
 *   docs/granting-mcp-server-access.md § "Step 1 / Option A: Provision from the
 *     catalog (recommended)" — "creates the MCP server record, optionally
 *     creates or links a credential, and runs best-effort tool discovery
 *     automatically". The admin UI's marketplace is that endpoint.
 *   § "Step 4 — Set Up Credentials (if needed)": "Credentials can be provided
 *     during provisioning (secret_value or credential_id fields)".
 *   § "Step 2 — Default Policy: Same-Owner Access": no extra policy is needed
 *     when the admin who provisions also owns the workspace.
 *   § "Step 5 — Call the MCP Tool": agentcordon mcp-servers / mcp-tools /
 *     mcp-call.
 *   docs/cli-reference.md § "agentcordon mcp-call" (--arg K=V).
 */

const apiKeyFingerprint =
  'sha256:' + crypto.createHash('sha256').update(UAT.mcpApiKey).digest('hex').slice(0, 16);

async function openInstallModal(page: Page, cardText: string) {
  await page.goto('/mcp-servers/marketplace');
  const card = page.locator('.marketplace-card', { hasText: cardText });
  await expect(card).toBeVisible();
  await card.click();
  const dialog = page.locator('[role="dialog"][aria-labelledby="install-modal-title"]');
  await expect(dialog).toBeVisible();
  const workspace = page.locator('#install-workspace');
  if (await workspace.isVisible().catch(() => false)) {
    await workspace.selectOption({ label: UAT.workspaceName }).catch(async () => {
      await workspace.selectOption(need('workspaceId'));
    });
  }
  return dialog;
}

test.describe('S13 MCP auth none and api_key', () => {
  test('an admin installs the no-auth MCP server from the marketplace and tools are discovered', async ({
    page,
  }, testInfo) => {
    await login(page);
    await openInstallModal(page, 'UAT Mock MCP (no auth)');
    await shot(page, testInfo, 's13-install-modal-none');

    const provisioned = page.waitForResponse(
      (r) => r.url().includes('/api/v1/mcp-servers/provision') && r.request().method() === 'POST',
      { timeout: 60_000 },
    );
    await page.locator('.modal-actions .btn-primary').click();
    const response = await provisioned;
    await expectOk(page, response, 'provisioning the MCP server');

    await page.waitForURL(/\/mcp-servers/, { timeout: 30_000 });
    const servers = await apiFromPage(page, 'GET', '/api/v1/mcp-servers');
    const installed = servers.body.data.find((s: any) => s.name === 'uat-none');
    expect(installed, JSON.stringify(servers.body.data)).toBeTruthy();
    expect(installed.auth_method).toBe('none');
    expect(installed.enabled).toBe(true);
    writeState({ mcpNoneId: installed.id });

    // Tool discovery ran during provisioning: the mock MCP server saw the
    // server's initialize / notifications/initialized / tools/list handshake.
    const handshake = (await mcpLog()).filter((e) => e.mount === 'none');
    expect(handshake.map((e) => e.rpc_method)).toContain('initialize');
    expect(handshake.map((e) => e.rpc_method)).toContain('tools/list');

    await page.goto(`/mcp-servers/${installed.id}`);
    await expect(page.locator('body')).toContainText('echo');
    await shot(page, testInfo, 's13-mcp-none-detail');
  });

  test('discovered MCP tools keep their description and their input schema [D11]', async ({
    page,
  }) => {
    await login(page);
    const detail = await apiFromPage(page, 'GET', `/api/v1/mcp-servers/${need('mcpNoneId')}`);
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    const tools = detail.body.data.tools || [];
    const echo = tools.find((t: any) => t.name === 'echo');
    expect(echo, JSON.stringify(detail.body.data)).toBeTruthy();

    // The detail endpoint used to synthesise its tool list from
    // `allowed_tools` (names only) with `description: None` hardcoded, and
    // McpTool deserialised snake_case `input_schema` while the MCP spec's
    // tools/list sends camelCase `inputSchema` — so a discovered schema was
    // dropped on the floor and neither an admin nor an agent could find out
    // what a tool takes. Both halves are asserted here: drop the serde alias
    // or go back to rebuilding the list from names and this goes red.
    expect(typeof echo.description, JSON.stringify(echo)).toBe('string');
    expect(echo.description.length, JSON.stringify(echo)).toBeGreaterThan(10);
    expect(echo.description).toContain('Echo');
    expect(echo.input_schema, JSON.stringify(echo)).toBeTruthy();
    expect(echo.input_schema.type).toBe('object');
    expect(Object.keys(echo.input_schema.properties || {})).toContain('hello');

    const whoami = tools.find((t: any) => t.name === 'whoami');
    expect(whoami, JSON.stringify(tools)).toBeTruthy();
    expect(typeof whoami.description, JSON.stringify(whoami)).toBe('string');
    expect(whoami.description.length, JSON.stringify(whoami)).toBeGreaterThan(10);

    // The same metadata reaches the agent through the documented CLI, which is
    // the whole point: `mcp-call --arg k=v` needs the argument names. Compared
    // against what the API returned rather than against a copy of the mock's
    // text, so the two halves of the product have to agree.
    const cliTools = cli(['mcp-tools']);
    expect(cliTools.code, cliTools.out).toBe(0);
    expect(cliTools.out, cliTools.out).toContain(echo.description);
  });

  test('an admin installs the API-key MCP server, supplying the key in the install form', async ({
    page,
  }, testInfo) => {
    await login(page);
    const dialog = await openInstallModal(page, 'UAT Mock MCP (API key)');

    const mode = page.locator('#install-credential');
    if (await mode.isVisible().catch(() => false)) {
      await mode.selectOption('new').catch(() => undefined);
    }
    await expect(page.locator('#install-secret')).toBeVisible();
    await page.fill('#install-secret', UAT.mcpApiKey);
    await shot(page, testInfo, 's13-install-modal-apikey');

    const provisioned = page.waitForResponse(
      (r) => r.url().includes('/api/v1/mcp-servers/provision') && r.request().method() === 'POST',
      { timeout: 60_000 },
    );
    await page.locator('.modal-actions .btn-primary').click();
    const response = await provisioned;
    await expectOk(page, response, 'provisioning the MCP server');

    const servers = await apiFromPage(page, 'GET', '/api/v1/mcp-servers');
    const installed = servers.body.data.find((s: any) => s.name === 'uat-apikey');
    expect(installed, JSON.stringify(servers.body.data)).toBeTruthy();
    expect(installed.auth_method).toBe('api_key');
    expect(installed.required_credentials?.length).toBe(1);
    writeState({ mcpApiKeyId: installed.id });

    // The key must not be readable back through the API.
    const creds = await apiFromPage(page, 'GET', '/api/v1/credentials');
    expect(JSON.stringify(creds.body)).not.toContain(UAT.mcpApiKey);
    await shot(page, testInfo, 's13-mcp-apikey-installed');
  });

  test('agentcordon mcp-call echo works on both servers and the API key is injected, never printed', async () => {
    const none = cli(['mcp-call', 'uat-none', 'echo', '--arg', 'hello=world']);
    expect(none.code, none.out).toBe(0);
    expect(none.out).toContain('world');
    expect(none.out).toMatch(/\\?"mount\\?"\s*:\s*\\?"none/);

    const apikey = cli(['mcp-call', 'uat-apikey', 'echo', '--arg', 'hello=world']);
    expect(apikey.code, apikey.out).toBe(0);
    expect(apikey.out).toContain('world');
    expect(apikey.out).toMatch(/\\?"mount\\?"\s*:\s*\\?"apikey/);
    // The mock MCP server reports only a fingerprint of whatever credential it
    // was given; the fingerprint proves the real key arrived.
    expect(apikey.out, apikey.out).toContain(apiKeyFingerprint);
    expect(apikey.out, 'the raw API key must never reach the caller').not.toContain(
      UAT.mcpApiKey,
    );

    // The key reached the upstream, in whichever of the two forms the mock
    // accepts (Authorization: Bearer, or X-API-Key).
    const calls = (await mcpLog()).filter(
      (e) => e.mount === 'apikey' && e.rpc_method === 'tools/call',
    );
    expect(calls.length).toBeGreaterThanOrEqual(1);
    const last = calls[calls.length - 1];
    const presented =
      last.auth_seen.authorization?.value_fingerprint ||
      last.auth_seen.x_api_key?.value_fingerprint;
    expect(presented, JSON.stringify(last.auth_seen)).toBe(apiKeyFingerprint);
  });

  test('the documented api_key_header credential type is accepted and injects its custom header [D12]', async ({
    page,
  }) => {
    await login(page);

    // docs/credential-encryption.md § "Credential Types / API Key (Header)"
    // and docs/cli-reference.md § "Credential Types and Transforms" document
    // `api_key_header` -> `<header_name>: <value>`, and the broker implements
    // it — but KNOWN_CREDENTIAL_TYPES did not list it, so
    // POST /api/v1/credentials answered 400 and the type could not be created
    // at all. Take it out of KNOWN_CREDENTIAL_TYPES again and this goes red.
    //
    // LABELLED WORKAROUND: this creates the credential with a POST issued
    // from the signed-in page rather than from /credentials/new, because the
    // form has the type in its select and no field to type the secret into —
    // see the next test, which is the open half of D12.
    const created = await apiFromPage(page, 'POST', '/api/v1/credentials', {
      name: 'uat-apikey-header',
      service: 'upstream',
      secret_value: UAT.mcpApiKey,
      credential_type: 'api_key_header',
      metadata: { header_name: 'X-Api-Key' },
      allowed_url_pattern: 'http://upstream:8080/*',
    });
    expect(created.status, JSON.stringify(created.body)).toBe(200);
    expect(created.body.data.credential_type).toBe('api_key_header');
    expect(created.body.data.metadata.header_name).toBe('X-Api-Key');
    expect(JSON.stringify(created.body)).not.toContain(UAT.mcpApiKey);

    // The broker injects it as the named header, not as a bearer. The mock
    // upstream echoes every header it received, lowercased.
    const proxied = cli(['proxy', 'uat-apikey-header', 'GET', 'http://upstream:8080/echo']);
    expect(proxied.code, proxied.out).toBe(0);
    expect(proxied.out).toContain('HTTP 200');
    expect(proxied.out.toLowerCase()).toContain('"x-api-key"');
    expect(proxied.out.toLowerCase()).not.toContain('"authorization"');
    expect(proxied.out, 'the injected key must be redacted on the way back').not.toContain(
      UAT.mcpApiKey,
    );
  });

  test('an admin can create an api_key_header credential from /credentials/new [D12]', async ({
    page,
  }, testInfo) => {

    await login(page);
    await page.goto('/credentials/new');
    await page.click('button.template-card:has-text("Blank")');
    await page.locator('#cred-type').selectOption('api_key_header');
    await shot(page, testInfo, 's13-apikey-header-credential-form');

    await expect(
      page.locator('#cred-field-secret_value'),
      'the form must offer somewhere to type the API key',
    ).toBeVisible({ timeout: 5_000 });
  });

  test('an api_key MCP server is authenticated with the custom header the docs describe, not a bearer [D12]', async () => {

    const calls = (await mcpLog()).filter(
      (e) => e.mount === 'apikey' && e.rpc_method === 'tools/call',
    );
    expect(calls.length).toBeGreaterThanOrEqual(1);
    const last = calls[calls.length - 1];
    expect(
      last.auth_seen.x_api_key?.value_fingerprint,
      `the key arrived as ${JSON.stringify(last.auth_seen)}`,
    ).toBe(apiKeyFingerprint);
    expect(last.auth_seen.authorization).toBeUndefined();
  });

  test('a tool that echoes its raw Authorization header back has the injected key redacted before the caller sees it (docs/system-architecture.md, core crate `proxy/` row: "leak scanning") [REVIEW-1]', async () => {
    // The mock MCP server's `echo_raw_auth` tool deliberately leaks whatever
    // credential it was handed. The broker injected that credential, so the
    // broker must scrub it from the tool result: an agent can never learn a
    // secret by asking an upstream to repeat it.
    const r = cli(['mcp-call', 'uat-apikey', 'echo_raw_auth']);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain('[REDACTED]');
    expect(r.out, 'the injected API key must be redacted from tool results').not.toContain(
      UAT.mcpApiKey,
    );

    // The upstream really did receive the key: only the caller-facing copy was
    // scrubbed. Read in whichever form the template asks for — the uat-apikey
    // template declares `api_key_header: X-API-Key`, so that is what the mock
    // sees; a template with no placement would still send a bearer.
    const calls = (await mcpLog()).filter(
      (e) => e.mount === 'apikey' && e.rpc_method === 'tools/call',
    );
    const last = calls[calls.length - 1];
    const presented =
      last.auth_seen.authorization?.value_fingerprint ||
      last.auth_seen.x_api_key?.value_fingerprint;
    expect(presented, JSON.stringify(last.auth_seen)).toBe(apiKeyFingerprint);
  });

  test('a tool that does not exist is reported as an error, not silently swallowed (docs/cli-reference.md § "agentcordon mcp-call")', async () => {
    const r = cli(['mcp-call', 'uat-none', 'nonexistent_tool']);
    expect(r.out).toMatch(/tool not found|error/i);
  });

  test('the install modal calls its confirm button "Install", the word the docs use', async ({
    page,
  }) => {
    // docs/granting-mcp-server-access.md § Step 1 says "click **Install**" for
    // both No Auth and API Key. The modal used to say "Add to workspace" for a
    // template the user was already connected to, so neither a reader nor an
    // automation found the control the docs name.
    await login(page);
    for (const card of ['UAT Mock MCP (no auth)', 'UAT Mock MCP (API key)']) {
      const dialog = await openInstallModal(page, card);
      await expect(dialog.locator('.modal-actions .btn-primary')).toHaveText(/^\s*Install\s*$/);
      await page.keyboard.press('Escape');
    }
  });

  test('the MCP list names the workspaces a server is bound to, not "No workspaces"', async ({
    page,
  }, testInfo) => {
    // The binding lives in the mcp_server_workspaces junction. The list API
    // reported only the legacy `workspace_id` (null since the consolidation),
    // so the Workspaces column read "No workspaces" for every bound server.
    await login(page);

    const list = await apiFromPage(page, 'GET', '/api/v1/mcp-servers');
    const row = list.body.data.find((s: any) => s.id === need('mcpNoneId'));
    expect(row, JSON.stringify(list.body.data)).toBeTruthy();
    expect(row.installed_workspaces, JSON.stringify(row)).toBeTruthy();
    expect(row.installed_workspaces.map((w: any) => w.name)).toContain(UAT.workspaceName);

    // The docs claim this route; it used to answer 405 Allow: POST.
    const bindings = await apiFromPage(
      page,
      'GET',
      `/api/v1/mcp-servers/${need('mcpNoneId')}/workspaces`,
    );
    expect(bindings.status, JSON.stringify(bindings.body)).toBe(200);
    expect(bindings.body.data.map((w: any) => w.name)).toContain(UAT.workspaceName);

    await page.goto('/mcp-servers');
    const tableRow = page.locator('tbody tr', { hasText: 'uat-none' }).first();
    await expect(tableRow).toContainText(UAT.workspaceName);
    await expect(tableRow).not.toContainText('No workspaces');
    await shot(page, testInfo, 's13-mcp-list-workspaces');
  });

  test('the detail page offers Rediscover tools, and it repopulates the tool list', async ({
    page,
  }, testInfo) => {
    // Install-time discovery is best-effort. A server installed while its
    // upstream was unreachable had no tools and no way back but delete and
    // reinstall (uat/artifacts/fresh-user-docker.md F-11).
    await login(page);
    await page.goto(`/mcp-servers/${need('mcpNoneId')}`);

    const button = page.locator('[data-testid="rediscover-tools"]');
    await expect(button).toBeVisible();
    await shot(page, testInfo, 's13-rediscover-tools');

    const discovered = page.waitForResponse(
      (r) => r.url().includes('/discover-tools') && r.request().method() === 'POST',
      { timeout: 60_000 },
    );
    await button.click();
    const response = await discovered;
    await expectOk(page, response, 'rediscovering tools');
    expect((await response.json()).data.tool_count).toBeGreaterThan(0);

    await expect(page.locator('body')).toContainText('echo');
  });
});
