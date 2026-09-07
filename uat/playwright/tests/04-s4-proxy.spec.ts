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
 *   docs/cli-reference.md § "agentcordon credentials" and § "agentcordon proxy".
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

  test('a 3xx is returned to the caller instead of being followed (the credential must not travel to the redirect target)', async () => {
    const r = cli(['proxy', UAT.credentialName, 'GET', 'http://upstream:8080/redirect']);
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
