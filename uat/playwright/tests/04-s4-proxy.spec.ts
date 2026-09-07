import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli } from './helpers/docker';

/**
 * S4 — Proxy and enforcement, all through the documented CLI.
 *
 * Documented steps:
 *   README.md § "Quick Start / 4. Use credentials":
 *       agentcordon credentials
 *       agentcordon proxy github-token GET <url>
 *   docs/index.md § "Quick Start / 4. Use credentials" (full-URL form).
 *   docs/cli-reference.md § "agentcordon credentials", § "agentcordon proxy"
 *     (default output, --headers, --auto) and § "For agents: the fast path".
 *   docs/credential-encryption.md § "allowed_url_pattern" (SSRF mitigation).
 *   CHANGELOG [Unreleased]: injected secrets are redacted from upstream
 *     responses; the outbound client never follows a 3xx.
 */
test.describe('S4 proxy and enforcement', () => {
  test('agentcordon credentials lists the credential the admin created (docs/cli-reference.md § "agentcordon credentials")', async () => {
    const r = cli(['credentials']);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain(UAT.credentialName);
    expect(r.out).toContain('generic');
  });

  test('a proxied call succeeds and the injected Authorization header comes back [REDACTED] (leak scanner)', async () => {
    const r = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo']);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain('HTTP 200');

    // The mock upstream echoes every request header it received. The broker's
    // leak scanner must have replaced the injected value on the way back.
    expect(r.out).toContain('"authorization":"[REDACTED]"');
    expect(r.out, 'the raw secret must never reach the caller').not.toContain(
      UAT.credentialSecret,
    );
  });

  test('the default output is the body on stdout and one summary line on stderr (docs/cli-reference.md § "agentcordon proxy" -> Default output)', async () => {
    const r = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo']);
    expect(r.code, r.out).toBe(0);

    // stdout is the response body, byte for byte: it parses on its own, with
    // no status line to strip first.
    const body = JSON.parse(r.stdout);
    expect(body.path).toBe('/echo');

    // Everything that is not the body is one line, on stderr.
    expect(r.stderr.trim()).toMatch(
      /^HTTP 200 \u00b7 [\d.]+ (B|KB|MB) \u00b7 content-type: application\/json$/,
    );
  });

  test('--raw is the body and nothing else; --json is one object (docs/cli-reference.md § "agentcordon proxy")', async () => {
    const raw = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo', '--raw']);
    expect(raw.code, raw.out).toBe(0);
    expect(raw.stderr).toBe('');
    expect(JSON.parse(raw.stdout).path).toBe('/echo');

    const json = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/echo', '--json']);
    expect(json.code, json.out).toBe(0);
    expect(json.stdout.trim().split('\n')).toHaveLength(1);
    const parsed = JSON.parse(json.stdout);
    expect(parsed.status).toBe(200);
    expect(parsed.headers['content-type']).toContain('application/json');
    expect(parsed.body.path).toBe('/echo');
  });

  test('agentcordon proxy --auto picks the credential whose fence covers the URL (docs/cli-reference.md § "For agents: the fast path")', async () => {
    const r = cli(['proxy', '--auto', 'GET', 'http://upstream:8080/echo']);
    expect(r.code, r.out).toBe(0);
    // The summary names the credential --auto chose -- the only place that
    // choice is visible.
    expect(r.stderr).toContain(`via ${UAT.credentialName}`);
    expect(JSON.parse(r.stdout).path).toBe('/echo');
    expect(r.out).not.toContain(UAT.credentialSecret);
  });

  test('agentcordon proxy --auto refuses rather than guessing when no fence covers the URL (exit 7)', async () => {
    const r = cli(['proxy', '--auto', 'GET', 'http://evil.example/x']);
    expect(r.code, r.out).toBe(7);
    expect(r.out).toContain('no credential is fenced for http://evil.example/x');
    expect(r.out).toContain('agentcordon credentials');
  });

  test('a 3xx is returned to the caller instead of being followed (the credential must not travel to the redirect target)', async () => {
    const r = cli([
      'proxy',
      UAT.credentialName,
      'GET',
      'http://upstream:8080/redirect',
      // The Location header is the point of this test, so ask for headers:
      // the default output is the body and a one-line summary.
      '--headers',
    ]);
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain('HTTP 302');
    expect(r.out.toLowerCase()).toContain('location: http://upstream:8080/secret');
    // The body of /secret must not appear — that would mean the redirect was followed.
    expect(r.out).not.toContain('you followed the redirect');
    expect(r.out).not.toContain('secret_page');
  });

  test('a target outside allowed_url_pattern is refused (docs/credential-encryption.md: "restricts which URLs this credential can be used against")', async () => {
    const r = cli(['proxy', UAT.credentialName, 'GET', 'http://evil.example/x']);
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toMatch(/url_pattern_denied|forbidden|403/);
    expect(r.out).not.toContain(UAT.credentialSecret);
  });
});
