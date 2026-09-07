import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import { ARTIFACTS, UAT } from './helpers/env';
import { callersOtherThanTheServer, idpLog } from './helpers/mocks';
import { cli, cliIn, docker, readFileInContainer, sh, waitFor } from './helpers/docker';
import { apiFromPage, login, shot } from './helpers/ui';
import { need, readState, recordFinding, writeState } from './helpers/state';

/**
 * S16 — Enforcement across the credential and MCP types.
 *
 * Documented claims under test:
 *   docs/credential-encryption.md § "allowed_url_pattern": "SSRF mitigation --
 *     restricts which URLs this credential can be used against". (Exercised
 *     for `generic` in S4, for `oauth2_client_credentials` in S11 and for
 *     `aws` in S14; re-asserted here as one table.)
 *   docs/granting-mcp-server-access.md § "Security Considerations", row 4:
 *     "Disabled servers blocked -- Forbid rules in the default policy (4b)
 *     prevent all mcp_tool_call and mcp_list_tools actions on disabled
 *     servers."
 *   § "Sharing with additional workspaces": "Provisioning binds the MCP to
 *     exactly one workspace ... removing a binding stops sync for that
 *     workspace", i.e. a workspace that is not bound cannot call it.
 *   § "Step 2 — Default Policy: Same-Owner Access" (policy 3a).
 */
test.describe('S16 enforcement across types', () => {
  test('every credential type refuses a target outside its allowed_url_pattern', async () => {
    const cases: Array<[string, string]> = [
      [UAT.credentialName, 'http://evil.example/x'],
      [UAT.oauthCcName, 'http://upstream:8080/echo'],
      [UAT.awsName, 'http://evil.example/x'],
    ];
    const refusals: string[] = [];
    for (const [name, url] of cases) {
      const r = cli(['proxy', name, 'GET', url]);
      expect(r.code, `${name} -> ${url}: ${r.out}`).not.toBe(0);
      expect(r.out, `${name} -> ${url}`).toMatch(/url_pattern_denied|forbidden|403/i);
      refusals.push(`${name} -> ${url}: ${r.out.trim().split('\n')[0]}`);
    }
    writeState({ s16Refusals: refusals });
  });

  test('an admin unticks Enabled on the MCP server detail page; the MCP stops answering, and ticking it back restores it (docs/granting-mcp-server-access.md § "Security Considerations", row 4)', async ({
    page,
  }, testInfo) => {
    test.setTimeout(240_000);
    await login(page);
    const id = need('mcpNoneId');
    await page.goto(`/mcp-servers/${id}`);
    await expect(page.locator('body')).toContainText('uat-none');
    await shot(page, testInfo, 's16-mcp-detail-before-disable');

    // The documented immediate-revocation gesture, performed as an admin
    // performs it. Enabled is no longer an edit-mode checkbox: it is the
    // Disable/Enable button in the detail header, confirmed by the shared
    // dialog (uat/artifacts/reviews/DESIGN-REVIEW.md 1.14). No raw API call; the PUT below is
    // the page's own, observed as it goes.
    const setEnabled = async (want: boolean) => {
      const toggle = page.locator('[data-testid="mcp-toggle"]');
      await expect(toggle).toHaveText(want ? 'Enable' : 'Disable');
      const saved = page.waitForResponse(
        (r: any) =>
          r.url().includes(`/api/v1/mcp-servers/${id}`) && r.request().method() === 'PUT',
        { timeout: 30_000 },
      );
      await toggle.click();
      // Disable and Enable both confirm through the shared dialog.
      await expect(page.locator('#ac-confirm')).toBeVisible();
      await page.click('#ac-confirm-ok');
      return saved;
    };

    const disabled = await setEnabled(false);
    expect(disabled.status(), 'the Save the admin UI sends must be accepted').toBeLessThan(300);
    await page.reload();
    await expect(
      page.locator('.detail-row:has-text("Status") .pill').first(),
    ).toHaveText('Disabled');
    await shot(page, testInfo, 's16-mcp-detail-disabled');

    // "Disabled servers blocked -- Forbid rules in the default policy (4b)
    // prevent all mcp_tool_call and mcp_list_tools actions on disabled
    // servers." The broker caches the workspace's MCP set, so the refusal
    // arrives on the next sync at the latest.
    const refusal = await waitFor(
      'the disabled MCP server to stop answering tool calls',
      () => {
        const r = cli(['mcp-call', 'uat-none', 'echo', '--arg', 'hello=disabled']);
        return r.code !== 0 ? r : null;
      },
      120_000,
      5_000,
    );
    expect(refusal.out, refusal.out).toMatch(/denied|forbidden|403|not found/i);
    writeState({ s16DisabledRefusal: refusal.out.trim().split('\n')[0] });

    // ...and ticking it back restores the server, so the rest of the scenario
    // has something to share.
    const reenabled = await setEnabled(true);
    expect(reenabled.status()).toBeLessThan(300);
    await page.reload();
    await expect(
      page.locator('.detail-row:has-text("Status") .pill').first(),
    ).toHaveText('Active');
    await shot(page, testInfo, 's16-mcp-detail-re-enabled');

    const restored = await waitFor(
      'the re-enabled MCP server to answer again',
      () => {
        const r = cli(['mcp-call', 'uat-none', 'echo', '--arg', 'hello=re-enabled']);
        return r.code === 0 ? r : null;
      },
      120_000,
      5_000,
    );
    expect(restored.out).toContain('re-enabled');
  });

  test('a second workspace is enrolled the documented way (docs/workspace-enrollment.md § "Flow 1")', async ({
    page,
  }, testInfo) => {
    test.setTimeout(240_000);

    const mk = sh(UAT.cli, `mkdir -p ${UAT.workspace2Dir}`);
    expect(mk.code, mk.out).toBe(0);

    // The three-command story end to end: `agentcordon init` alone installs
    // the skill *and* enrolls. It blocks while polling for the approval, so
    // it is started detached with its output redirected -- the terminal
    // equivalent of leaving it running while you go to the browser.
    docker([
      'exec',
      '-d',
      '-w',
      UAT.workspace2Dir,
      UAT.cli,
      'sh',
      '-c',
      `agentcordon init --server-url http://server:3140 --name ${UAT.workspace2Name} ` +
        `> /home/uat/register2.log 2>&1`,
    ]);

    const log = await waitFor(
      'the second init to print its user code',
      () => {
        const text = readFileInContainer(UAT.cli, '/home/uat/register2.log');
        return /one-time code: (\S+)/.test(text) ? text : null;
      },
      120_000,
      1000,
    );
    // Everything `init` does before the device flow is in the same log: the
    // identity, the skill, and which server it is enrolling with.
    expect(log).toContain('AgentCordon skill:');
    expect(log).toContain('Enrolling with http://server:3140');
    const pkHash = /sha256:([0-9a-f]{64})/.exec(log)![1];
    const userCode = /one-time code: (\S+)/.exec(log)![1];

    await login(page);
    await page.goto(`/activate?user_code=${userCode}`);
    await expect(page.locator('p.activate-desc strong')).toHaveText(UAT.workspace2Name);
    await expect(page.locator('p.activate-keyhash code')).toHaveText(`sha256:${pkHash}`);
    await shot(page, testInfo, 's16-activate-second-workspace');
    await page.click('button.btn-approve');
    await page.waitForURL('**/activate/success', { timeout: 30_000 });

    // The two lines `init` ends on: what was registered where, and the one
    // command that proves it worked.
    const done = await waitFor(
      'the second init to report success',
      () => {
        const text = readFileInContainer(UAT.cli, '/home/uat/register2.log');
        return text.includes('Registered as') ? text : null;
      },
      120_000,
      1000,
    );
    expect(done).toContain(
      `Registered as ${UAT.workspace2Name} at http://server:3140.`,
    );
    expect(done).toContain('Try: agentcordon credentials');

    // Find the new workspace the way an admin does: open /workspaces and
    // click its row. The row is a link to /workspaces/{id}, which is where the
    // id for the rest of the scenario comes from.
    await page.goto('/workspaces');
    const row = page.locator(`tr.ws-row[aria-label="${UAT.workspace2Name}"]`);
    await expect(row).toBeVisible({ timeout: 30_000 });
    await row.click();
    await page.waitForURL(/\/workspaces\/[0-9a-f-]{36}$/, { timeout: 30_000 });
    const workspace2Id = page.url().split('/').pop()!;
    await shot(page, testInfo, 's16-second-workspace-detail');
    writeState({ workspace2Id });
  });

  test('the second workspace, bound to no MCP server, cannot list or call one', async () => {
    const servers = cliIn(UAT.workspace2Dir, ['mcp-servers']);
    expect(servers.code, servers.out).toBe(0);
    expect(servers.out, servers.out).not.toContain('uat-none');
    expect(servers.out, servers.out).not.toContain('uat-apikey');
    expect(servers.out, servers.out).not.toContain('uat-oauth-dcr');

    const call = cliIn(UAT.workspace2Dir, ['mcp-call', 'uat-none', 'echo', '--arg', 'hello=world']);
    expect(call.code, call.out).not.toBe(0);
    expect(call.out, call.out).toMatch(/not found|denied|forbidden|no such/i);
    // Nothing about the other workspace's MCP servers may leak.
    expect(call.out).not.toContain(UAT.mcpApiKey);
  });

  test('DOC GAP: the request body the guide shows for an MCP workspace binding is rejected', async ({
    page,
  }) => {
    await login(page);
    const id = need('mcpNoneId');
    const workspace2Id = need('workspace2Id');

    // This IS the step under test, not a workaround for a missing button:
    // docs/granting-mcp-server-access.md tells a reader to POST to this
    // endpoint, and the only body shape it ever shows for an MCP workspace
    // binding is `workspace_id`. Issuing exactly that is how the gap is
    // measured. The binding itself is made through the UI in the next test.
    const documented = await apiFromPage(page, 'POST', `/api/v1/mcp-servers/${id}/workspaces`, {
      workspace_id: workspace2Id,
    });
    expect(documented.status, JSON.stringify(documented.body)).toBeGreaterThanOrEqual(400);
    recordFinding({
      scenario: 'S16',
      title:
        'The share-with-workspace endpoint takes `workspace_ids` (an array); the only body shape the docs ever show for an MCP workspace binding is `workspace_id`',
      doc: 'docs/granting-mcp-server-access.md § "Sharing with additional workspaces" (names POST /api/v1/mcp-servers/{id}/workspaces with no body at all) and § "Step 3 / Option A", whose adjacent permissions example posts {"workspace_id": "...", "permission": "..."}; the API reference table gives no request schema for any of these routes',
      detail: `POST /api/v1/mcp-servers/{id}/workspaces with {"workspace_id": "<uuid>"} answered HTTP ${
        documented.status
      }: ${JSON.stringify(documented.body).slice(
        0,
        300,
      )}. The admin UI's own Share modal sends {"workspace_ids": ["<uuid>", ...]}, which works. A reader following the guide has no way to discover that.`,
      workaround:
        'None needed for the scenario: the binding is made through the admin UI\'s "Share with workspace" modal in the next test. This probe exists only to measure the documented shape.',
    });
  });

  test('an admin shares the MCP with the second workspace from the Workspaces tab, then unshares it; the last binding cannot be removed', async ({
    page,
  }, testInfo) => {
    test.setTimeout(360_000);
    await login(page);
    const id = need('mcpNoneId');

    // --- share, through the modal the detail page offers -------------------
    await page.goto(`/mcp-servers/${id}`);
    // The Workspaces and Permissions tabs merged into one Access tab
    // (uat/artifacts/reviews/DESIGN-REVIEW.md 1.14).
    await page.click('button.tab-btn:has-text("Access")');
    await page.click('[data-testid="share-with-workspace"]');
    const modal = page.locator('.mcp-share-modal');
    await expect(modal).toBeVisible();
    await modal
      .locator(`label.mcp-share-row:has(span:text-is("${UAT.workspace2Name}")) input[type="checkbox"]`)
      .check();
    await shot(page, testInfo, 's16-share-modal');

    const sharedResponse = page.waitForResponse(
      (r: any) =>
        r.url().endsWith(`/api/v1/mcp-servers/${id}/workspaces`) &&
        r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.click('[data-testid="share-submit"]');
    const shared = await sharedResponse;
    expect(shared.status()).toBeLessThan(300);
    await expect(
      page.locator(`.mcp-ws-table a.cred-name:text-is("${UAT.workspace2Name}")`),
    ).toBeVisible();
    await shot(page, testInfo, 's16-shared-with-second-workspace');

    // The broker's MCP cache refreshes on a tick or on a cache miss; a call
    // that misses re-syncs on demand.
    const call = await waitFor(
      'the second workspace to reach the shared MCP server',
      () => {
        const r = cliIn(UAT.workspace2Dir, [
          'mcp-call',
          'uat-none',
          'echo',
          '--arg',
          'hello=shared',
        ]);
        return r.code === 0 ? r : null;
      },
      180_000,
      5_000,
    );
    expect(call.out).toContain('shared');

    // --- unshare, with the row's own control ------------------------------
    // The row's control asks through the shared confirm dialog, not a native one.
    const unshareResponse = page.waitForResponse(
      (r: any) =>
        r.url().includes(`/api/v1/mcp-servers/${id}/workspaces/`) &&
        r.request().method() === 'DELETE',
      { timeout: 30_000 },
    );
    await page
      .locator(`.mcp-ws-table tr:has(a.cred-name:text-is("${UAT.workspace2Name}")) button.btn-ghost`)
      .click();
    await expect(page.locator('#ac-confirm')).toBeVisible();
    await page.click('#ac-confirm-ok');
    const unshare = await unshareResponse;
    expect(unshare.status()).toBeLessThan(300);
    await expect(
      page.locator(`.mcp-ws-table a.cred-name:text-is("${UAT.workspace2Name}")`),
    ).toHaveCount(0);

    // ...and the second workspace loses access again once the broker re-syncs.
    await waitFor(
      'the second workspace to lose access after unsharing',
      () => {
        const r = cliIn(UAT.workspace2Dir, ['mcp-call', 'uat-none', 'echo', '--arg', 'hello=gone']);
        return r.code !== 0 ? r : null;
      },
      180_000,
      5_000,
    );

    // --- the last binding is refused, and the UI says why ------------------
    // docs/granting-mcp-server-access.md § "Sharing with additional
    // workspaces": "Can't remove the last binding".
    // The row's control asks through the shared confirm dialog, not a native one.
    const lastResponse = page.waitForResponse(
      (r: any) =>
        r.url().includes(`/api/v1/mcp-servers/${id}/workspaces/`) &&
        r.request().method() === 'DELETE',
      { timeout: 30_000 },
    );
    await page
      .locator(`.mcp-ws-table tr:has(a.cred-name:text-is("${UAT.workspaceName}")) button.btn-ghost`)
      .click();
    await expect(page.locator('#ac-confirm')).toBeVisible();
    await page.click('#ac-confirm-ok');
    const last = await lastResponse;
    expect(last.status()).toBe(409);
    await expect(page.locator('.toast-error').first()).toBeVisible();
    await expect(
      page.locator(`.mcp-ws-table a.cred-name:text-is("${UAT.workspaceName}")`),
    ).toBeVisible();
    await shot(page, testInfo, 's16-last-binding-refused');

    expect(readState().s16Refusals).toBeTruthy();
  });

  /**
   * Last chance to read the mocks: they live in the server container's network
   * namespace, and the next spec (S9) restarts that container, which leaves
   * them running but unreachable. Snapshot their request logs into artifacts
   * while they are still answering.
   */
  test('the mocks\' request logs are snapshotted before the S9 restart takes their namespace away', async () => {
    fs.mkdirSync(ARTIFACTS, { recursive: true });
    const wanted: Array<[string, string]> = [
      ['idp-log.json', `${UAT.idpUrl}/_uat/log`],
      ['idp-tokens.json', `${UAT.idpUrl}/_uat/tokens`],
      ['mcp-log.json', `${UAT.mcpUrl}/_uat/log`],
    ];
    for (const [name, url] of wanted) {
      const response = await fetch(url);
      expect(response.ok, `${url} -> HTTP ${response.status}`).toBe(true);
      fs.writeFileSync(path.join(ARTIFACTS, name), await response.text());
    }

    // Sanity: the IdP log must show the whole OAuth story and nothing from the
    // broker.
    const entries = await idpLog();
    expect(entries.filter((e) => e.kind === 'register').length).toBe(1);
    expect(entries.filter((e) => e.kind === 'refresh_rotated').length).toBeGreaterThan(0);
    expect(callersOtherThanTheServer(entries)).toEqual([]);
  });
});
