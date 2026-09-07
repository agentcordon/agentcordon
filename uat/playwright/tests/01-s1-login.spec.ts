import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { login, shot } from './helpers/ui';

/**
 * S1 — Login.
 *
 * Documented step: README.md § "Quick Start / 1. Start the server" —
 * "Open http://localhost:3140. Default admin credentials are printed to the
 * console on first boot." docs/index.md § "Quick Start" says the same.
 * Nothing but the browser is used here.
 */
test.describe('S1 login', () => {
  test('root signs in through the admin UI and the dashboard renders', async ({ page }, testInfo) => {
    await page.goto('/login');
    await shot(page, testInfo, 's1-login-form');

    await page.fill('#login-username', UAT.rootUsername);
    await page.fill('#login-password', UAT.rootPassword);
    await page.click('button.login-submit-btn');

    await page.waitForURL('**/dashboard', { timeout: 30_000 });
    await expect(page.locator('div.content-header h2')).toHaveText('Dashboard');
    await shot(page, testInfo, 's1-dashboard');
  });

  test('the dashboard is a shell: its stats and activity come from the API, not from seeded HTML', async ({ page }, testInfo) => {
    // The page HTML must not carry the numbers; they arrive over /api/v1/stats.
    const rawHtml = await (await fetch(`${UAT.serverUrl}/dashboard`)).text();
    // (unauthenticated fetch returns the login redirect body, which certainly
    // has no stats — the real check is that the authenticated page fetches.)
    expect(rawHtml).not.toContain('dash-card-count');

    const statsRequest = page.waitForResponse(
      (r) => r.url().includes('/api/v1/stats') && r.request().method() === 'GET',
      { timeout: 30_000 },
    );
    const activityRequest = page.waitForResponse(
      (r) => r.url().includes('/api/v1/audit?') && r.url().includes('event_type='),
      { timeout: 30_000 },
    );

    await login(page);

    const stats = await statsRequest;
    expect(stats.status()).toBe(200);
    const statsBody = await stats.json();
    expect(statsBody).toHaveProperty('data.workspaces');
    expect(statsBody).toHaveProperty('data.credentials');

    const activity = await activityRequest;
    expect(activity.status()).toBe(200);

    // The tiles are populated from that response.
    await expect(page.locator('a.dash-card').first()).toBeVisible();
    await expect(page.locator('.dash-card-count').first()).not.toBeEmpty();
    // Two five-row tables merged into one (uat/artifacts/reviews/DESIGN-REVIEW.md 1.3).
    await expect(page.locator('h3.dash-section-title', { hasText: 'Recent activity' })).toBeVisible();
    // The third tile counts MCP servers instead of asserting health.
    await expect(page.locator('a.dash-card[href="/mcp-servers"]')).toBeVisible();
    await expect(page.locator('.dash-health-line')).toContainText('Server responding');
    await shot(page, testInfo, 's1-dashboard-api-backed');
  });
});

/**
 * UI review B2: the SSO button linked to `/api/v1/oidc/auth/<id>`, which is
 * not a route, so every SSO sign-in landed on the generic 404 page. The flow
 * starts at `/api/v1/auth/oidc/authorize?provider=<id>`.
 *
 * The topology does not necessarily configure an identity provider, so the
 * button may not be rendered at all; what must hold either way is that the
 * page names the real route and never the dead one, and that a rendered
 * button points at it.
 */
test.describe('S1 SSO link', () => {
  test('the login page starts SSO at the authorize route, never at the 404', async ({ page }, testInfo) => {
    await page.goto('/login');

    const html = await page.content();
    expect(html).not.toContain('/api/v1/oidc/auth/');
    expect(html).toContain('/api/v1/auth/oidc/authorize?provider=');

    const ssoButtons = page.locator('a.login-sso-btn');
    const count = await ssoButtons.count();
    if (count === 0) {
      // No provider configured: nothing more to assert.
      return;
    }

    const href = await ssoButtons.first().getAttribute('href');
    expect(href).toContain('/api/v1/auth/oidc/authorize?provider=');

    // Following it must reach the provider, not the 404 page.
    const response = await page.request.get(href!, { maxRedirects: 0 });
    expect(response.status()).toBe(302);
    expect(response.headers()['location']).toBeTruthy();
    await shot(page, testInfo, 's1-login-sso-link');
  });
});
