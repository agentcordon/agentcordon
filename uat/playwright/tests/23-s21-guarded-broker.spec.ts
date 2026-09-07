import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli, docker, logs, readFileInContainer, sh, waitFor } from './helpers/docker';
import { apiFromPage, login, shot } from './helpers/ui';
import { readDoc } from './helpers/docs';
import { writeState } from './helpers/state';

/**
 * S21 — The SSRF guard as the broker ships it, and the one thing that
 * overrides it.
 *
 * Every other scenario runs its CLI half against a broker started with
 * `--proxy-allow-loopback`, which switches the guard off (uat/README.md,
 * "Known concessions" 2). That is why the defect this scenario covers reached
 * a release: a credential the admin had fenced to exactly one host on a
 * tailnet was refused by the guard, and the only way through was a flag that
 * disables the protection for everything and needs the broker restarted.
 *
 * This scenario uses the second broker `run.sh` starts *without* the flag and
 * a CLI container in its network namespace, enrolled as a third workspace the
 * documented way.
 *
 * Documented steps:
 *   docs/configuration.md § "The SSRF guard is two variables": "a credential
 *     whose allowed_url_pattern names the target host with no wildcard ... is
 *     forwarded to whatever that host resolves to".
 *   docs/cli-reference.md § "agentcordon proxy" -> "SSRF Protection".
 *   docs/workspace-enrollment.md § "Flow 1" (the enrollment).
 *   ADR-0014.
 */

/** `agentcordon ...` in the guarded CLI container, in its enrolled workspace. */
function cliGuarded(args: string[]): ReturnType<typeof cli> {
  return docker(['exec', '-w', '/home/uat/workspace', UAT.cliGuarded, 'agentcordon', ...args]);
}

test.describe('S21 SSRF guard on, credential pinned to the host', () => {
  test('the guarded broker was started without --proxy-allow-loopback', async () => {
    const inspect = docker(['inspect', '--format', '{{json .Config.Cmd}}', UAT.brokerGuarded]);
    expect(inspect.code, inspect.out).toBe(0);
    expect(inspect.stdout).toContain('agentcordon-broker');
    expect(inspect.stdout, 'the guard must be on for this scenario to mean anything').not.toContain(
      'proxy-allow-loopback',
    );
    const env = docker(['inspect', '--format', '{{json .Config.Env}}', UAT.brokerGuarded]);
    expect(env.stdout).not.toContain('AGTCRDN_PROXY_ALLOW_LOOPBACK');
  });

  test('a third workspace is enrolled through the guarded broker (docs/workspace-enrollment.md § "Flow 1")', async ({
    page,
  }, testInfo) => {
    test.setTimeout(240_000);

    docker([
      'exec',
      '-d',
      '-w',
      '/home/uat/workspace',
      UAT.cliGuarded,
      'sh',
      '-c',
      `agentcordon init --server-url http://server:3140 --name ${UAT.workspace3Name} ` +
        `> /home/uat/register3.log 2>&1`,
    ]);

    const log = await waitFor(
      'the third init to print its user code',
      () => {
        const text = readFileInContainer(UAT.cliGuarded, '/home/uat/register3.log');
        return /one-time code: (\S+)/.test(text) ? text : null;
      },
      120_000,
      1000,
    );
    const pkHash = /sha256:([0-9a-f]{64})/.exec(log)![1];
    const userCode = /one-time code: (\S+)/.exec(log)![1];

    await login(page);
    await page.goto(`/activate?user_code=${userCode}`);
    await expect(page.locator('p.activate-desc strong')).toHaveText(UAT.workspace3Name);
    await expect(page.locator('p.activate-keyhash code')).toHaveText(`sha256:${pkHash}`);
    await shot(page, testInfo, 's21-activate-guarded-workspace');
    await page.click('button.btn-approve');
    await page.waitForURL('**/activate/success', { timeout: 30_000 });

    const done = await waitFor(
      'the third init to report success',
      () => {
        const text = readFileInContainer(UAT.cliGuarded, '/home/uat/register3.log');
        return text.includes('Registered as') ? text : null;
      },
      120_000,
      1000,
    );
    expect(done).toContain(`Registered as ${UAT.workspace3Name} at http://server:3140.`);

    const status = cliGuarded(['status']);
    expect(status.code, status.out).toBe(0);
    expect(status.out).toContain('Registered: yes');
    writeState({ workspace3PkHash: pkHash });
  });

  test('a credential fenced to one literal host is forwarded to its private address with the guard on (docs/configuration.md § "The SSRF guard is two variables")', async () => {
    // `upstream-token` (S2) is fenced to http://upstream:8080/*: scheme, host
    // and port, no wildcard in the host. `upstream` resolves to a Docker
    // bridge address, which the guard refuses for anything else.
    const r = cliGuarded(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo']);
    expect(r.code, r.out).toBe(0);
    expect(r.out, r.out).toContain('HTTP 200');
    const echoed = JSON.parse(r.stdout);
    expect(echoed.path).toBe('/echo');
    // The credential travelled and came back scrubbed, exactly as through the
    // flagged broker.
    expect(echoed.headers.authorization).toBe('[REDACTED]');
    expect(r.out).not.toContain(UAT.credentialSecret);

    // The broker says why it let a private address through, so an auditor
    // reading its log sees the pin, not a silent exception.
    const brokerLog = logs(UAT.brokerGuarded);
    expect(brokerLog).toContain('allowed_url_pattern pins this host');
  });

  test('an admin creates a credential with no URL pattern from /credentials/new', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto('/credentials/new');
    await page.click('button.template-card:has-text("Blank")');
    await page.fill('#cred-name', UAT.unfencedCredentialName);
    await page.fill('#cred-service', 'upstream');
    await page.fill('#cred-field-secret_value', UAT.unfencedCredentialSecret);
    // Left blank on purpose. The form warns, and the warning is the point:
    // this credential vouches for no host.
    await expect(page.locator('#cred-url-pattern')).toHaveValue('');
    await expect(page.locator('.form-hint-warn')).toBeVisible();
    await shot(page, testInfo, 's21-unfenced-credential-form');

    const createResponse = page.waitForResponse(
      (r) => r.url().endsWith('/api/v1/credentials') && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.click('button[type="submit"]:has-text("Store Credential")');
    expect((await createResponse).status()).toBe(200);
    await page.waitForURL(/\/credentials\/[0-9a-f-]{36}$/, { timeout: 30_000 });
    const id = page.url().split('/').pop()!;
    writeState({ unfencedCredentialId: id });

    const detail = await apiFromPage(page, 'GET', `/api/v1/credentials/${id}`);
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.data.allowed_url_pattern).toBeFalsy();
  });

  test('the unfenced credential is refused at the same private address, and the refusal names the pattern an admin would write and the flag', async () => {
    const r = cliGuarded([
      'proxy',
      UAT.unfencedCredentialName,
      'GET',
      'http://upstream:8080/echo',
    ]);
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toContain('Blocked by SSRF protection');
    // Nothing was proxied, so this must not be reported as an upstream
    // failure (exit 6).
    expect(r.code, r.out).not.toBe(6);
    // The two ways out, both spelled out: the exact fence to write, and the
    // development-only flag with where it is read.
    expect(r.out).toContain('has no allowed_url_pattern');
    expect(r.out).toContain('http://upstream:8080/*');
    expect(r.out).toContain('AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon-broker');
    expect(r.out).toContain('startup');
    expect(r.out).not.toContain(UAT.unfencedCredentialSecret);
  });

  test('the same unfenced credential goes through on the broker started with --proxy-allow-loopback (the contrast)', async () => {
    const r = cli(['proxy', UAT.unfencedCredentialName, 'GET', 'http://upstream:8080/echo']);
    expect(r.code, r.out).toBe(0);
    expect(r.out, r.out).toContain('HTTP 200');
    expect(JSON.parse(r.stdout).path).toBe('/echo');
  });

  test('the docs and the agent skill describe the pin rule, not only the flag', async () => {
    const config = readDoc('docs/configuration.md');
    expect(config).toContain('names the target host with no wildcard');
    const cliDoc = readDoc('docs/cli-reference.md');
    expect(cliDoc).toContain('pins that exact host');
    const skill = readDoc('crates/cli/src/agents/SKILL.md');
    expect(skill).toContain('no wildcard in the host');
    // The one the agent actually reads is the copy `init` installed.
    const installed = sh(UAT.cliGuarded, 'cat /home/uat/workspace/.agents/skills/agentcordon/SKILL.md');
    expect(installed.out).toContain('no wildcard in the host');
  });
});
