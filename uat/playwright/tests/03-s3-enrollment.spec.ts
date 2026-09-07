import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli, cliDetached, readFileInContainer, waitFor } from './helpers/docker';
import { login, shot } from './helpers/ui';
import { readDoc } from './helpers/docs';
import { need, readState, writeState } from './helpers/state';

/**
 * S3 — Workspace enrollment (RFC 8628 device flow).
 *
 * Documented steps:
 *   README.md § "Quick Start / 3. Set up a workspace":
 *       agentcordon init
 *       agentcordon register --server-url http://localhost:3140
 *     "Open the URL in any browser ... paste the 4-word code, and click Approve."
 *   docs/index.md § "Quick Start / 3. Set up a workspace" (manual variant:
 *     `agentcordon register` with a broker already running).
 *   docs/cli-reference.md § "agentcordon register" and § "agentcordon status".
 *   docs/workspace-enrollment.md § "Flow 1: Interactive Registration".
 *
 * `register` blocks while polling the broker, so it is started detached with
 * its output redirected to a file — the terminal equivalent of leaving it
 * running in another window while you go to the browser.
 */
test.describe('S3 enrollment', () => {
  test('agentcordon init generates the workspace identity (docs/cli-reference.md § "agentcordon init")', async () => {
    const init = cli(['init']);
    expect(init.code, init.out).toBe(0);
    expect(init.out).toMatch(/Workspace identity: sha256:[0-9a-f]{64}/);
    const pkHash = /sha256:([0-9a-f]{64})/.exec(init.out)![1];
    writeState({ pkHash });
  });

  test('agentcordon register prints a one-time code and an activation URL, and the docs warn about the AGTCRDN_BASE_URL fallback (README § "Quick Start / 3") [G1]', async () => {
    cliDetached('agentcordon register --name uat-ws > /home/uat/register.log 2>&1');

    const log = await waitFor(
      'register to print its user code',
      () => {
        const text = readFileInContainer(UAT.cli, '/home/uat/register.log');
        return /one-time code: (\S+)/.test(text) ? text : null;
      },
      120_000,
      1000,
    );
    const userCode = /one-time code: (\S+)/.exec(log)![1];
    expect(userCode).toMatch(/^[a-z]+-[a-z]+-[a-z]+-[a-z]+$/);
    writeState({ userCode });

    // The URL the CLI hands the user must be one they can actually open.
    const printedUrl = /Then open this URL in your browser:\s*\n\s*(\S+)/.exec(log)?.[1] ?? '';
    expect(printedUrl, log).toBeTruthy();
    writeState({ printedActivationUrl: printedUrl });

    // G1 — the device flow's verification_uri is built from AGTCRDN_BASE_URL
    // and falls back to "http://" + the listen address. This harness starts
    // the server the way docker-compose.yml ships it, with AGTCRDN_BASE_URL
    // unset, so the fallback is what a user sees. That used to be an
    // undocumented trap: README and .env.example described the variable as
    // needed "for OAuth2 MCP flows" only. Both now warn about exactly this
    // URL and tell the operator to set the variable before anyone enrolls.
    // These assertions go red if either the fallback shape or that warning
    // changes.
    expect(
      printedUrl,
      'with AGTCRDN_BASE_URL unset the CLI prints the listen-address fallback',
    ).toMatch(/^http:\/\/0\.0\.0\.0:3140\/activate/);

    const readme = readDoc('README.md');
    expect(
      readme,
      'README must warn that the activation URL is built from AGTCRDN_BASE_URL',
    ).toContain('Set `AGTCRDN_BASE_URL` before anyone enrolls.');
    expect(readme).toContain('http://0.0.0.0:3140');

    const envExample = readDoc('.env.example');
    expect(envExample).toContain("activation URL that `agentcordon register` prints");
    expect(envExample).toContain('Set it before anyone');
  });

  test('the /activate page names the workspace and the device key before approval (docs/workspace-enrollment.md § "Flow 1", step 6)', async ({ page }, testInfo) => {
    const { userCode, pkHash } = readState();
    await login(page);

    await page.goto(`/activate?user_code=${userCode}`);
    await expect(page.locator('h1.activate-title')).toHaveText('Activate a new device');

    // CHANGELOG (Unreleased): "The activation page shows the device key and
    // warns when it is already registered."
    await expect(page.locator('p.activate-desc strong')).toHaveText(UAT.workspaceName);
    await expect(page.locator('p.activate-keyhash code')).toHaveText(`sha256:${pkHash}`);
    await expect(page.locator('ul.activate-scopes li')).toHaveCount(4);
    await expect(page.locator('#activate-user-code')).toHaveValue(userCode);
    await shot(page, testInfo, 's3-activate-page');

    await page.click('button.btn-approve');
    await page.waitForURL('**/activate/success', { timeout: 30_000 });
    await shot(page, testInfo, 's3-activate-success');
  });

  test('the CLI completes and agentcordon status reports the workspace registered (docs/cli-reference.md § "agentcordon status")', async () => {
    const log = await waitFor(
      'register to report success',
      () => {
        const text = readFileInContainer(UAT.cli, '/home/uat/register.log');
        return text.includes('Logged in as') ? text : null;
      },
      120_000,
      1000,
    );
    expect(log).toContain(`Logged in as ${UAT.workspaceName}`);
    expect(log).toContain('credentials:vend');

    const status = cli(['status']);
    expect(status.code, status.out).toBe(0);
    expect(status.out).toContain('Registered: yes');
    expect(status.out).toMatch(/Broker: .* \(healthy\)/);
    expect(status.out).toMatch(/Server: .* \(reachable\)/);
  });

  test('the workspaces page lists uat-ws as active', async ({ page }, testInfo) => {
    await login(page);

    const listResponse = page.waitForResponse(
      (r) => r.url().endsWith('/api/v1/workspaces') && r.request().method() === 'GET',
      { timeout: 30_000 },
    );
    await page.goto('/workspaces');
    const list = await listResponse;
    expect(list.status()).toBe(200);
    const workspaces = (await list.json()).data;
    const ws = workspaces.find((w: any) => w.name === UAT.workspaceName);
    expect(ws, JSON.stringify(workspaces)).toBeTruthy();
    expect(ws.status).toBe('active');
    expect(ws.enabled).toBe(true);
    writeState({ workspaceId: ws.id });

    const row = page.locator(`tr.ws-row[aria-label="${UAT.workspaceName}"]`);
    await expect(row).toBeVisible();
    await expect(row.locator('span.pill.pill-sm')).toContainText('Active');
    await shot(page, testInfo, 's3-workspaces-list');
  });

  /*
   * `/workspaces/{id}` is the workspace, on every viewport. It used to render
   * the split-pane list with that row selected, and the CSS hid the pane below
   * 768 px, so the link showed a phone the list and nothing else
   * (uat/artifacts/reviews/UI-REVIEW-live.md M4, uat/artifacts/reviews/UI-REVIEW-static.md J1). One page needs no
   * viewport branch (uat/artifacts/reviews/DESIGN-REVIEW.md §2.3); `/view` redirects to it.
   */
  test('the canonical workspace deep link shows the workspace on a phone', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.setViewportSize({ width: 390, height: 844 });

    const workspaceId = need('workspaceId');
    await page.goto(`/workspaces/${workspaceId}/view`);

    // The old link redirects to the canonical page, which every viewport reads.
    await page.waitForURL(`**/workspaces/${workspaceId}`, { timeout: 30_000 });
    await expect(page.locator('div.detail-header h3')).toHaveText(UAT.workspaceName, {
      timeout: 30_000,
    });
    // The History tab used to exist only in the desktop pane, so the page a
    // phone lands on could not show a workspace's events at all
    // (uat/artifacts/reviews/UI-REVIEW-static.md B1).
    await expect(page.locator('button.tab-btn', { hasText: 'History' })).toBeVisible();
    await shot(page, testInfo, 's3-workspace-deeplink-mobile');
  });
});
