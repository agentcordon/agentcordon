import { test, expect, Page } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli, cliIn, waitFor } from './helpers/docker';
import { apiFromPage, expectOk, login, shot } from './helpers/ui';
import { readDoc } from './helpers/docs';
import { need, recordFinding, writeState } from './helpers/state';
import {
  callTool,
  listTools,
  mcpServe,
  resultText,
  toolNames,
  toolResult,
} from './helpers/mcpserve';
import * as fs from 'fs';
import * as path from 'path';

/**
 * S20 — remote MCP gating, per tool, on both the CLI path and the MCP surface.
 *
 * Documented steps:
 *   docs/granting-mcp-server-access.md § "Step 3 — Create a Cedar Policy for
 *     Cross-Owner Access", § "Sharing with more workspaces", § "API Reference".
 *   docs/admin-ui.md § "MCP Servers" — the Access tab, its Grant/Deny control.
 *   docs/authorization-and-cedar-policy.md § "Actions", § "Context Fields by
 *     Action" (`mcp_tool_call` takes `tool_name`).
 *   docs/cli-reference.md § "agentcordon mcp-call", § "agentcordon mcp-serve".
 *
 * The gate under test is the per-tool one: a `mcp_tool_call:<tool>` permission
 * granted or denied for one workspace, and what an agent sees through both
 * surfaces afterwards. It runs after S16 (which enrolls the second workspace
 * and asserts it is bound to no MCP server) and after S18.
 */

const SERVER_NAME = 'uat-none';
const GRANTED_TOOL = 'echo';
const DENIED_TOOL = 'whoami';
const WS2 = UAT.workspace2Dir;
/** The tag the documented policy generator is pointed at. */
const S20_TAG = 'uat-s20';

/** The ACTION REFERENCE block at the head of the shipped default policy. */
function actionReference(): string {
  const text = fs.readFileSync(
    path.resolve(__dirname, '..', '..', '..', 'policies', 'default.cedar'),
    'utf8',
  );
  return text.slice(text.indexOf('ACTION REFERENCE'));
}

/** The MCP server's Access tab, loaded. */
async function openAccessTab(page: Page, id: string) {
  await page.goto(`/mcp-servers/${id}`);
  await page.locator('#mcp-tab-access').click();
  await expect(page.locator('.mcp-access-permissions')).toBeVisible();
}

/** Audit rows, newest first, as the admin API serves them. */
async function auditRows(page: Page, limit = 300): Promise<any[]> {
  const audit = await apiFromPage(page, 'GET', `/api/v1/audit?limit=${limit}`);
  expect(audit.status, JSON.stringify(audit.body)).toBe(200);
  return audit.body.data;
}

test.describe('S20 MCP tool gating', () => {
  test('an MCP server\'s tool list cannot be restricted through the UI or the API [G-S20-1]', async ({
    page,
  }, testInfo) => {
    await login(page);
    const id = need('mcpNoneId');

    // The discovered list is what an agent sees, and it is all four tools.
    const detail = await apiFromPage(page, 'GET', `/api/v1/mcp-servers/${id}`);
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.data.tools.map((t: any) => t.name).sort()).toEqual([
      'echo',
      'echo_raw_auth',
      'team_notice',
      'whoami',
    ]);

    // The detail page shows them and offers no way to change the set: the
    // Tools tab is a listing with one action on it, Rediscover.
    await page.goto(`/mcp-servers/${id}`);
    const toolsPanel = page.locator('#mcp-panel-tools');
    await expect(toolsPanel).toBeVisible();
    expect(
      await toolsPanel.locator('input[type="checkbox"], select, textarea').count(),
      'the Tools tab offers no control to edit the tool list',
    ).toBe(0);
    await shot(page, testInfo, 's20-mcp-tools-tab-no-control');

    // And the update endpoint refuses the field outright: it takes `name` and
    // `enabled`, and `deny_unknown_fields` rejects anything else.
    const attempt = await apiFromPage(page, 'PUT', `/api/v1/mcp-servers/${id}`, {
      allowed_tools: [GRANTED_TOOL, DENIED_TOOL],
    });
    expect(attempt.status, JSON.stringify(attempt.body)).toBeGreaterThanOrEqual(400);

    // The docs agree with the code, which is why this is a product gap and not
    // a documentation one.
    const doc = readDoc('docs/granting-mcp-server-access.md');
    expect(doc).toContain('Update MCP server: `name` and/or `enabled`');

    recordFinding({
      scenario: 'S20',
      title:
        "An MCP server's tool list cannot be narrowed; `allowed_tools` is a discovery projection, not a permission list",
      doc: 'docs/granting-mcp-server-access.md § "API Reference"',
      detail:
        '`allowed_tools` is written only by tool discovery (crates/server/src/services/mcp_servers.rs). ' +
        'PUT /api/v1/mcp-servers/{id} accepts only `name` and `enabled` and rejects `allowed_tools` ' +
        '(deny_unknown_fields), and the detail page has no control for it. An operator who wants an agent ' +
        'to see two of four tools has no supported way to do it: the per-tool Cedar deny below refuses the ' +
        'CALL but leaves the tool in every listing, so the agent still discovers it and still tries it.',
      workaround:
        'Per-tool `mcp_tool_call:<tool>` denies from the Access tab, which is what the rest of this scenario exercises.',
    });
  });

  test('an admin shares uat-none with the second workspace from the Access tab (docs/granting-mcp-server-access.md § "Sharing with more workspaces")', async ({
    page,
  }, testInfo) => {
    test.setTimeout(240_000);
    await login(page);
    const id = need('mcpNoneId');
    const workspace2Id = need('workspace2Id');

    await openAccessTab(page, id);
    const alreadyBound = page.locator('.mcp-ws-table tbody tr', { hasText: UAT.workspace2Name });
    if ((await alreadyBound.count()) === 0) {
      await page.locator('[data-testid="share-with-workspace"]').click();
      const modal = page.locator('.mcp-share-modal');
      await expect(modal).toBeVisible();
      await modal
        .locator('label.mcp-share-row', { hasText: UAT.workspace2Name })
        .locator('input[type="checkbox"]')
        .check();
      await shot(page, testInfo, 's20-share-with-workspace2');

      const shared = page.waitForResponse(
        (r) => r.url().includes(`/mcp-servers/${id}/workspaces`) && r.request().method() === 'POST',
        { timeout: 60_000 },
      );
      await modal.locator('[data-testid="share-submit"]').click();
      await expectOk(page, await shared, 'sharing the MCP server with the second workspace');
    } else {
      await shot(page, testInfo, 's20-share-with-workspace2');
    }
    await expect(
      page.locator('.mcp-ws-table tbody tr', { hasText: UAT.workspace2Name }),
    ).toHaveCount(1);

    const bindings = await apiFromPage(page, 'GET', `/api/v1/mcp-servers/${id}/workspaces`);
    expect(bindings.body.data.map((w: any) => w.name)).toContain(UAT.workspace2Name);
    expect(bindings.body.data.map((w: any) => w.id)).toContain(workspace2Id);

    // The broker syncs MCP configs on an interval, so the second workspace can
    // see the server only once that tick has landed. This is the documented
    // AGTCRDN_MCP_SYNC_INTERVAL behaviour, not a flake.
    await waitFor(
      'the broker to sync uat-none to the second workspace',
      () => cliIn(WS2, ['mcp-servers']).out.includes(SERVER_NAME),
      120_000,
      3000,
    );
  });

  test('the Access tab writes a per-tool Grant and a per-tool Deny for the second workspace (docs/admin-ui.md § "MCP Servers")', async ({
    page,
  }, testInfo) => {
    await login(page);
    const id = need('mcpNoneId');
    const workspace2Id = need('workspace2Id');

    // One control with two values: Grant writes a permit policy, Deny a forbid.
    for (const [mode, tool] of [
      ['grant', GRANTED_TOOL],
      ['deny', DENIED_TOOL],
    ] as const) {
      await openAccessTab(page, id);
      const form = page.locator('.perm-form-batch');
      await form.locator('select.perm-agent-select').selectOption(workspace2Id);
      await form
        .locator('.mcp-grant-mode-toggle [role="radio"]', {
          hasText: mode === 'grant' ? 'Grant' : 'Deny',
        })
        .click();
      await expect(
        form.locator(`.mcp-grant-mode-toggle [role="radio"][aria-checked="true"]`),
      ).toHaveText(mode === 'grant' ? 'Grant' : 'Deny');

      // `hasText` is a substring match and `echo` is a prefix of
      // `echo_raw_auth`, so the label is matched on its exact text.
      await form
        .locator('.mcp-tool-checkboxes label.checkbox-label')
        .filter({ has: page.locator(`span.mono-sm:text-is("${tool}")`) })
        .locator('input[type="checkbox"]')
        .check();
      await shot(page, testInfo, `s20-access-${mode}-${tool}`);

      const written = page.waitForResponse(
        (r) =>
          r.url().includes(`/mcp-servers/${id}/permissions`) && r.request().method() === 'POST',
        { timeout: 60_000 },
      );
      await form.locator('button.btn-sm').last().click();
      await expectOk(page, await written, `writing the ${mode} for ${tool}`);
    }

    // Both are listed as granted permissions on the same tab, per workspace.
    await openAccessTab(page, id);
    const listed = await apiFromPage(page, 'GET', `/api/v1/mcp-servers/${id}/permissions`);
    expect(listed.status, JSON.stringify(listed.body)).toBe(200);
    const forWs2 = listed.body.data.permissions.find(
      (p: any) => p.workspace_id === workspace2Id,
    );
    expect(forWs2, JSON.stringify(listed.body.data)).toBeTruthy();
    expect(forWs2.permissions).toContain(`mcp_tool_call:${GRANTED_TOOL}`);
    expect(forWs2.permissions).toContain(`mcp_tool_call:${DENIED_TOOL}`);
    await shot(page, testInfo, 's20-access-permissions-listed');
  });

  test('the second workspace may call the granted tool and not the denied one, and the audit says which (docs/cli-reference.md § "agentcordon mcp-call")', async ({
    page,
  }) => {
    await login(page);
    const before = new Set((await auditRows(page)).map((e: any) => e.id));

    // Granted: the call goes through.
    const granted = cliIn(WS2, ['mcp-call', SERVER_NAME, GRANTED_TOOL, '--arg', 'hello=ws2']);
    expect(granted.code, granted.out).toBe(0);
    expect(granted.out).toContain('ws2');

    // Denied: refused. One line on stderr, the documented exit code 5, and a
    // JSON error envelope on stdout naming the tool.
    const denied = cliIn(WS2, ['mcp-call', SERVER_NAME, DENIED_TOOL]);
    expect(denied.code, denied.out).toBe(5);
    expect(denied.stderr.trim().split('\n').length, denied.stderr).toBe(1);
    expect(denied.stderr, denied.stderr).toMatch(/denied|forbid|not permitted|policy/i);
    const envelope = JSON.parse(denied.stdout);
    expect(envelope.error.tool).toBe(DENIED_TOOL);
    expect(envelope.error.message, denied.stdout).toMatch(/denied by policy/i);

    // EVIDENCE ONLY (a raw API read): the rows the two calls left behind.
    const fresh = (await auditRows(page)).filter((e: any) => !before.has(e.id));

    const permitted = fresh.find(
      (e: any) =>
        e.event_type === 'mcp_tool_called' &&
        e.workspace_name === UAT.workspace2Name &&
        e.metadata?.tool_name === GRANTED_TOOL,
    );
    expect(permitted, JSON.stringify(fresh.map((e: any) => [e.event_type, e.metadata]))).toBeTruthy();
    expect(permitted.decision).toBe('permit');

    // The Cedar decision behind it is its own row. `policy_evaluated` is
    // excluded from the default listing as noise, so it is asked for by name.
    const evaluatedResp = await apiFromPage(
      page,
      'GET',
      '/api/v1/audit?limit=200&event_type=policy_evaluated',
    );
    expect(evaluatedResp.status, JSON.stringify(evaluatedResp.body)).toBe(200);
    const evaluated = evaluatedResp.body.data.find(
      (e: any) =>
        e.action === 'mcp_tool_call' &&
        e.workspace_name === UAT.workspace2Name &&
        e.decision === 'permit',
    );
    expect(evaluated, 'a policy_evaluated permit for the granted call').toBeTruthy();

    // Both decisions were made; the forbid is in the same place.
    const forbidden = evaluatedResp.body.data.find(
      (e: any) =>
        e.action === 'mcp_tool_call' &&
        e.workspace_name === UAT.workspace2Name &&
        e.decision !== 'permit',
    );
    expect(forbidden, 'a policy_evaluated forbid for the denied call').toBeTruthy();

    // The per-tool deny refuses the CALL; it does not hide the tool. The
    // listing still names it — the gap G-S20-1 records.
    const listed = cliIn(WS2, ['mcp-tools']);
    expect(listed.code, listed.out).toBe(0);
    expect(listed.out, 'a denied tool is still discoverable').toContain(DENIED_TOOL);
  });

  test('a tool call refused by policy writes an mcp_tool_call_denied audit row [G-S20-5]', async ({
    page,
  }) => {
    // KNOWN OPEN DEFECT — G-S20-5. `McpServerService::record_tool_denied`
    // exists, `AuditEventType::McpToolCallDenied` exists, the admin UI has a
    // label for it ("MCP Tool Denied") and docs/audit-logging.md lists it —
    // but nothing calls it. `crates/server/src/routes/control_plane/
    // mcp_authorize.rs` emits the domain row only on permit, so a tool call
    // refused by a policy leaves a `policy_evaluated` forbid and no domain
    // event. The only `mcp_tool_call_denied` rows in an install come from the
    // broker's "unknown server" path. An operator who writes a per-tool Deny
    // therefore gets no audit record of the refusals it causes — the one thing
    // the deny exists to produce. Call `record_tool_denied` on the forbid
    // branch and this goes green.
    test.fail();

    await login(page);
    const before = new Set((await auditRows(page)).map((e: any) => e.id));

    const denied = cliIn(WS2, ['mcp-call', SERVER_NAME, DENIED_TOOL]);
    expect(denied.code, denied.out).toBe(5);

    const fresh = (await auditRows(page)).filter((e: any) => !before.has(e.id));
    const refused = fresh.find(
      (e: any) =>
        e.event_type === 'mcp_tool_call_denied' &&
        e.workspace_name === UAT.workspace2Name &&
        e.metadata?.tool_name === DENIED_TOOL,
    );
    expect(
      refused,
      JSON.stringify(fresh.map((e: any) => [e.event_type, e.workspace_name, e.metadata])),
    ).toBeTruthy();
    expect(refused.decision).toBe('forbid');
  });

  test('the first workspace is unaffected by the second workspace\'s per-tool deny', async () => {
    const stillWorks = cli(['mcp-call', SERVER_NAME, DENIED_TOOL]);
    expect(stillWorks.code, stillWorks.out).toBe(0);
    expect(stillWorks.out).toContain('whoami');
  });

  test('the same grant and deny decide agentcordon_mcp_call and an --exposed tool, with the correlation id in _meta (docs/cli-reference.md § "agentcordon mcp-serve")', async ({
    page,
  }) => {
    await login(page);
    const before = new Set((await auditRows(page)).map((e: any) => e.id));

    // The fixed surface, from the second workspace's directory.
    const session = mcpServe(
      [
        callTool('agentcordon_mcp_call', {
          server: SERVER_NAME,
          tool: GRANTED_TOOL,
          arguments: { hello: 'ws2-mcp' },
        }),
        callTool('agentcordon_mcp_call', { server: SERVER_NAME, tool: DENIED_TOOL }),
      ],
      { workdir: WS2 },
    );
    expect(session.error, session.describe()).toBeNull();

    const ok = toolResult(session.responses[0]);
    expect(ok.isError ?? false, session.describe()).toBe(false);
    expect(resultText(session.responses[0]), session.describe()).toContain('ws2-mcp');
    const permittedCorrelation = ok._meta?.correlation_id;
    expect(permittedCorrelation, session.describe()).toBeTruthy();

    const refused = toolResult(session.responses[1]);
    expect(refused.isError, session.describe()).toBe(true);
    expect(resultText(session.responses[1]), session.describe()).toMatch(
      /denied|forbid|not permitted|policy/i,
    );

    // The typed re-export is the same gate: `--expose` publishes both tools,
    // and calling the denied one is refused exactly as the generic call is.
    const exposed = mcpServe(
      [listTools(), callTool(`uat_none__${DENIED_TOOL}`, {})],
      { workdir: WS2, expose: [SERVER_NAME] },
    );
    expect(exposed.error, exposed.describe()).toBeNull();
    const names = toolNames(exposed.responses[0]);
    const deniedTypedName = names.find((n) => /^uat[-_]none__/.test(n) && n.endsWith(DENIED_TOOL));
    expect(deniedTypedName, exposed.describe()).toBeTruthy();
    const typed = toolResult(exposed.responses[1]);
    expect(typed.isError, exposed.describe()).toBe(true);
    expect(resultText(exposed.responses[1]), exposed.describe()).toMatch(
      /denied|forbid|not permitted|policy/i,
    );

    // EVIDENCE ONLY: the MCP surface's calls wrote the same two row types, and
    // the id it handed the model is the one the server audited.
    const fresh = (await auditRows(page)).filter((e: any) => !before.has(e.id));
    const permittedRow = fresh.find(
      (e: any) =>
        e.event_type === 'mcp_tool_called' && e.correlation_id === permittedCorrelation,
    );
    expect(
      permittedRow,
      `no mcp_tool_called row with correlation_id ${permittedCorrelation}`,
    ).toBeTruthy();
    expect(permittedRow.workspace_name).toBe(UAT.workspace2Name);
    expect(permittedRow.metadata.tool_name).toBe(GRANTED_TOOL);

    // Both refusals are Cedar forbids on `mcp_tool_call`; the domain row a
    // denial should also write is the open defect G-S20-5 above.
    const evaluated = await apiFromPage(
      page,
      'GET',
      '/api/v1/audit?limit=200&event_type=policy_evaluated',
    );
    const forbids = evaluated.body.data.filter(
      (e: any) =>
        e.action === 'mcp_tool_call' &&
        e.workspace_name === UAT.workspace2Name &&
        e.decision !== 'permit',
    );
    expect(
      forbids.length,
      'the generic call and the exposed tool were each refused by policy',
    ).toBeGreaterThanOrEqual(2);
  });

  test('the rows the Access tab writes are marked generated, not authored', async ({
    page,
  }, testInfo) => {
    // The seeded `default` policy is the one thing between this install and
    // deny-all, and the list refuses to disable it while it is the only
    // *authored* policy enabled. Per-tool grants and denies must therefore be
    // recognised as generated rather than counted as another policy: the list
    // keys that off the `grant:` / `deny:` name prefix.
    await login(page);
    const policies = (await apiFromPage(page, 'GET', '/api/v1/policies')).body.data;
    const grantRow = policies.find((p: any) =>
      (p.name || '').startsWith('grant:mcp:') && p.name.endsWith(`:${GRANTED_TOOL}`),
    );
    expect(grantRow, JSON.stringify(policies.map((p: any) => p.name))).toBeTruthy();
    const denyRow = policies.find((p: any) =>
      (p.name || '').startsWith('deny:mcp:') && p.name.endsWith(`:${DENIED_TOOL}`),
    );
    expect(denyRow, JSON.stringify(policies.map((p: any) => p.name))).toBeTruthy();

    await page.goto('/security');
    await expect(page.locator('table.tbl tbody')).toBeVisible();

    // Hidden from the default view, which is the authored list.
    await page.locator('select.policy-filter-select').selectOption('all');
    await page.fill('input.policy-search-input', grantRow.name);
    await expect(page.locator('tr.policy-row')).toHaveCount(0);

    // The deny row is not: the list's `isGrant` test is the `grant:` prefix
    // alone, while its `isGenerated` test — the one the enabled count uses —
    // covers `deny:` too. So a per-tool Deny is excluded from the count and
    // shown in the authored list, badged Custom.
    await page.fill('input.policy-search-input', denyRow.name);
    const denyVisible = page.locator('tr.policy-row').first();
    await expect(denyVisible).toBeVisible();
    // The name cell carries one span per badge and shows one of them, so the
    // badge is read from the visible one.
    await expect(denyVisible.locator('.policy-type-badge:visible').first()).toHaveText('Custom');
    recordFinding({
      scenario: 'S20',
      title: 'A per-tool Deny is listed as an authored "Custom" policy while a per-tool Grant is hidden',
      doc: 'docs/admin-ui.md § Policies',
      detail:
        'crates/server/templates/pages/policies/list.html has two predicates: `isGrant` (the `grant:` prefix) ' +
        'decides what the "All except grants" filter hides and what the Grant badge is drawn on, and ' +
        '`isGenerated` (`grant:` or `deny:`) decides the enabled count. A `deny:` row therefore falls between ' +
        'them: it does not count as an authored policy but is displayed as one, so the Policies list grows a ' +
        '"Custom" row per per-tool Deny that nobody wrote and that cannot be meaningfully edited there.',
    });
    await page.fill('input.policy-search-input', '');

    // And present, badged Grant, under "Grants only".
    await page.locator('select.policy-filter-select').selectOption('grants');
    const row = page.locator('tr.policy-row.policy-row-grant').first();
    await expect(row).toBeVisible();
    await expect(row.locator('.policy-badge-grant')).toHaveText('Grant');
    await shot(page, testInfo, 's20-access-tab-rows-are-grants');
  });

  test('generate-policies has no control in the admin UI, and its rows are not marked as generated [G-S20-2]', async ({
    page,
  }, testInfo) => {
    await login(page);
    const id = need('mcpNoneId');

    // (a) The gap: the endpoint is documented as an operator step, and nothing
    // on the page calls it.
    await page.goto(`/mcp-servers/${id}`);
    const pageHtml = await page.content();
    expect(
      pageHtml.includes('generate-policies'),
      'the MCP detail page never references the generate-policies endpoint',
    ).toBe(false);
    expect(readDoc('docs/granting-mcp-server-access.md')).toContain('/generate-policies');
    recordFinding({
      scenario: 'S20',
      title: 'POST /api/v1/mcp-servers/{id}/generate-policies has no control anywhere in the admin UI',
      doc: 'docs/granting-mcp-server-access.md § "The same thing over the API" step 3, § "API Reference"',
      detail:
        'The tag-based per-tool policy generator is documented as an operator step and is reachable only with curl. ' +
        'Nothing on /mcp-servers/{id} — Tools, Access or History — offers it, so an operator following ' +
        'docs/admin-ui.md never finds it. Worse, what it writes is inconsistent with what the Access tab writes: ' +
        'the Access tab names its rows `grant:`/`deny:`, which the Policies list treats as generated and excludes ' +
        'from the enabled-policy count, while the generator names its rows `mcp-<server>-<tool>-<tag>`, which the ' +
        'list shows as ordinary Custom policies and counts as authored ones.',
      workaround: 'Issued from the signed-in page with fetch(), the way the UI would if it had a button.',
    });

    // (b) LABELLED WORKAROUND: the documented call, made from the signed-in page.
    const generated = await apiFromPage(
      page,
      'POST',
      `/api/v1/mcp-servers/${id}/generate-policies`,
      { tools: [GRANTED_TOOL, DENIED_TOOL], agent_tags: [S20_TAG] },
    );
    expect(generated.status, JSON.stringify(generated.body)).toBe(200);
    // A rerun creates nothing: the generator skips a policy whose name it has
    // already used. Either way the rows must be there afterwards.
    const all = (await apiFromPage(page, 'GET', '/api/v1/policies')).body.data;
    const created: any[] = all.filter((p: any) =>
      new RegExp(`^mcp-.*-(${GRANTED_TOOL}|${DENIED_TOOL})-${S20_TAG}$`).test(p.name || ''),
    );
    expect(
      created.length,
      `generate-policies answered ${JSON.stringify(generated.body)}; policies: ` +
        JSON.stringify(all.map((p: any) => p.name)),
    ).toBeGreaterThan(0);
    writeState({ s20GeneratedPolicyNames: created.map((p: any) => p.name) });

    // (c) They land on the Policies list — as **Custom** policies, because the
    // generator names them `mcp-<server>-<tool>-<tag>` while the Access tab's
    // Grant/Deny control names its rows `grant:`/`deny:`. The list, the count
    // and the "Grants only" filter all key off that prefix.
    for (const p of created) {
      expect(p.name, JSON.stringify(created)).toMatch(/^mcp-/);
      expect(p.name.startsWith('grant:'), 'the generator does not use the grant: prefix').toBe(false);
    }
    await page.goto('/security');
    await page.locator('select.policy-filter-select').selectOption('grants');
    const asGrant = page.locator('tr.policy-row', { hasText: created[0].name });
    await expect(asGrant, 'a generated row does not appear under "Grants only"').toHaveCount(0);

    await page.locator('select.policy-filter-select').selectOption('custom');
    await page.fill('input.policy-search-input', created[0].name);
    const asCustom = page.locator('tr.policy-row', { hasText: created[0].name }).first();
    await expect(asCustom).toBeVisible();
    // Badged **Custom**: indistinguishable, in the list an operator reads,
    // from a policy a person wrote.
    await expect(asCustom.locator('.policy-type-badge:visible').first()).toHaveText('Custom');
    await shot(page, testInfo, 's20-generated-policies-are-custom');
  });

  test('a policy generate-policies wrote is excluded from the last-enabled-policy count [G-S20-2]', async ({
    page,
  }) => {
    // KNOWN OPEN DEFECT — G-S20-2. `POST /generate-policies` names its rows
    // `mcp-<server>-<tool>-<tag>`, while the Access tab's Grant/Deny control
    // names its rows `grant:`/`deny:`. Only the second prefix is treated as
    // generated, so a documented operator step silently converts the install
    // from "one authored policy, protected" to "several policies, unprotected":
    // the `default` policy loses its last-enabled badge and the API will let it
    // be disabled, leaving an install whose only enabled policies each permit
    // one workspace one tool — locked out for every operator, viewer and
    // workspace, with only root still able to sign in. Give the generator the
    // `grant:` prefix (or teach `isGenerated` about `mcp-`) and this goes green.
    test.fail();

    await login(page);
    expect(need('s20GeneratedPolicyNames').length).toBeGreaterThan(0);

    await page.goto('/security');
    await page.locator('select.policy-filter-select').selectOption('all');
    const defaultRow = page.locator('tr.policy-row', { hasText: 'default' }).first();
    await expect(
      defaultRow.locator('.policy-last-enabled-pill'),
      'generated per-tool policies must not count as another enabled policy',
    ).toBeVisible();
  });

  test('the policy tester cannot answer a per-tool mcp_tool_call question [G-S20-3]', async ({
    page,
  }, testInfo) => {
    await login(page);
    const id = need('mcpNoneId');
    const workspace2Id = need('workspace2Id');

    await page.goto('/security/tester');
    await expect(page.locator('#tester-action')).toBeVisible();

    const actionValues = await page
      .locator('#tester-action option')
      .evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value));
    expect(actionValues).toContain('mcp_tool_call');
    expect(actionValues).toContain('mcp_list_tools');

    // (a) The gap: `mcp_tool_call` takes a `tool_name` context claim — every
    // policy the Access tab's Grant/Deny control writes conditions on exactly
    // that — and the tester has nowhere to type it.
    const toolNameInputs = await page
      .locator('input, select, textarea')
      .evaluateAll((els) =>
        els.filter((e) => /tool[_ -]?name/i.test((e as HTMLElement).outerHTML)).length,
      );
    expect(toolNameInputs, 'the tester offers no tool_name field').toBe(0);
    await shot(page, testInfo, 's20-tester-no-tool-name');

    // (b) What the page answers for the server as a whole.
    await page.locator('#tester-principal').selectOption(`Workspace:${workspace2Id}`);
    await page.locator('#tester-action').selectOption('mcp_tool_call');
    await page.locator('#tester-resource').selectOption(`McpServer:${id}`);
    const decided = page.waitForResponse(
      (r) => r.url().includes('/api/v1/policies/test') && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.locator('.tester-action-row button.btn-primary').click();
    const pageDecision = (await (await decided).json()).data.decision;
    expect(typeof pageDecision).toBe('string');
    await shot(page, testInfo, 's20-tester-mcp-tool-call');

    // (c) LABELLED WORKAROUND: the same endpoint with the claim the UI omits.
    // It separates the two tools; the page's single answer cannot be right for
    // both, which is the finding.
    const perTool: Record<string, string> = {};
    for (const tool of [GRANTED_TOOL, DENIED_TOOL]) {
      const tested = await apiFromPage(page, 'POST', '/api/v1/policies/test', {
        principal: { type: 'Workspace', id: workspace2Id },
        action: 'mcp_tool_call',
        resource: { type: 'McpServer', id },
        context: { tool_name: tool },
      });
      expect(tested.status, JSON.stringify(tested.body)).toBe(200);
      perTool[tool] = tested.body.data.decision;
    }
    expect(
      perTool[GRANTED_TOOL],
      `granted ${GRANTED_TOOL} vs denied ${DENIED_TOOL}: ${JSON.stringify(perTool)}`,
    ).not.toBe(perTool[DENIED_TOOL]);
    expect(perTool[DENIED_TOOL], JSON.stringify(perTool)).toBe('forbid');

    recordFinding({
      scenario: 'S20',
      title: 'The policy tester cannot evaluate a per-tool mcp_tool_call decision: there is no tool_name field',
      doc: 'docs/authorization-and-cedar-policy.md § "Context Fields by Action" (mcp_tool_call takes tool_name)',
      detail:
        'POST /api/v1/policies/test accepts context.tool_name and answers ' +
        `${JSON.stringify(perTool)} for the two tools this scenario granted and denied. /security/tester ` +
        `sends no tool_name and offers no input for one, so it answers "${pageDecision}" for the server as a ` +
        'whole — one answer for a question whose real answer differs per tool. An operator who writes a ' +
        'per-tool deny from the Access tab has no way to check it from the tester the docs point them at.',
      workaround: 'The same endpoint called with context.tool_name from the signed-in page.',
    });
  });

  test('every action the Cedar schema defines is named in the tester, the grant form and the reference docs [G-S20-4]', async ({
    page,
  }) => {
    await login(page);

    // The served schema is the authority; the file is the same bytes.
    const served = await apiFromPage(page, 'GET', '/api/v1/policies/schema');
    expect(served.status, JSON.stringify(served.body)).toBe(200);
    const schema = JSON.parse(served.body.data);
    const namespace = schema.AgentCordon ?? schema[Object.keys(schema)[0]];
    const schemaActions: string[] = Object.keys(namespace.actions).sort();
    expect(schemaActions).toContain('mcp_tool_call');
    expect(schemaActions).toContain('mcp_list_tools');

    // The tester's dropdown offers every one of them.
    await page.goto('/security/tester');
    await expect(page.locator('#tester-action')).toBeVisible();
    const offered = await page
      .locator('#tester-action option')
      .evaluateAll((os) =>
        os.map((o) => (o as HTMLOptionElement).value).filter((v) => v !== ''),
      );
    expect(
      schemaActions.filter((a) => !offered.includes(a)),
      `actions the schema defines and the tester does not offer: ${JSON.stringify(offered)}`,
    ).toEqual([]);

    // The MCP grant form covers the two MCP actions: "List Tools" is
    // `mcp_list_tools`, "All Tools" is `mcp_tool_call`, and the per-tool boxes
    // are `mcp_tool_call:<tool>`.
    await page.goto(`/mcp-servers/${need('mcpNoneId')}`);
    await page.locator('#mcp-tab-access').click();
    await expect(page.locator('[data-testid="grant-list-tools"]')).toBeVisible();
    await expect(page.locator('[data-testid="grant-all-tools"]')).toBeVisible();
    await expect(page.locator('.mcp-tool-checkboxes label.checkbox-label')).toHaveCount(4);

    // `mcp_tool_call` and `mcp_list_tools` are the two this scenario is about,
    // and they are in both prose references whatever else is missing.
    const authzDoc = readDoc('docs/authorization-and-cedar-policy.md');
    const reference = actionReference();
    for (const action of ['mcp_tool_call', 'mcp_list_tools']) {
      expect(authzDoc, `docs must name ${action}`).toContain(`\`${action}\``);
      expect(reference, `default.cedar's ACTION REFERENCE must name ${action}`).toContain(action);
    }

    writeState({ s20SchemaActions: schemaActions });
  });

  test('the two prose action references name every action the schema defines [G-S20-4]', async ({
    page,
  }) => {
    // KNOWN OPEN DEFECT — G-S20-4. `policies/default.cedar`'s ACTION REFERENCE
    // and docs/authorization-and-cedar-policy.md § Actions are the two lists an
    // operator writes a policy from, and neither is generated from the schema.
    // Both currently omit `manage_consents`. Fix either list and this flips to
    // an unexpected pass; fix both and it goes green.
    test.fail();

    await login(page);
    const served = await apiFromPage(page, 'GET', '/api/v1/policies/schema');
    expect(served.status, JSON.stringify(served.body)).toBe(200);
    const schema = JSON.parse(served.body.data);
    const namespace = schema.AgentCordon ?? schema[Object.keys(schema)[0]];
    const schemaActions: string[] = Object.keys(namespace.actions).sort();

    const authzDoc = readDoc('docs/authorization-and-cedar-policy.md');
    const reference = actionReference();
    const missingFromDoc = schemaActions.filter((a) => !authzDoc.includes(`\`${a}\``));
    const missingFromCedar = schemaActions.filter((a) => !reference.includes(a));

    recordFinding({
      scenario: 'S20',
      title: 'The two action references do not list every action the Cedar schema defines',
      doc: 'docs/authorization-and-cedar-policy.md § "Actions"; policies/default.cedar "ACTION REFERENCE"',
      detail:
        `The served schema defines ${schemaActions.length} actions. ` +
        `Missing from docs/authorization-and-cedar-policy.md § Actions: ${JSON.stringify(missingFromDoc)}. ` +
        `Missing from policies/default.cedar's ACTION REFERENCE: ${JSON.stringify(missingFromCedar)}. ` +
        'Both are the list an operator writes a policy from, so an action nobody documents is one nobody ' +
        'uses and nobody reviews.',
    });

    expect(
      { doc: missingFromDoc, cedar: missingFromCedar },
      'every schema action is named in both references',
    ).toEqual({ doc: [], cedar: [] });
  });
});
