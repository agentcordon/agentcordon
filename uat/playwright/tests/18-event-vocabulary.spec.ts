import { test, expect } from '@playwright/test';
import { login, shot } from './helpers/ui';

/**
 * Audit-event vocabulary and the dashboard's reload behaviour
 * (uat/artifacts/reviews/UI-REVIEW-live.md M11 and m1, uat/artifacts/reviews/UI-REVIEW-static.md B4 and J3).
 *
 * The Rust tests at `crates/server/tests/admin_ui_controls.rs` assert that the
 * shipped HTML names the right event types and routes every surface through
 * `eventTypeLabel` / `eventPrincipal`. Only a browser can say what a reader
 * actually sees in a rendered row, and only a browser can count the requests a
 * burst of SSE events costs — so those are here.
 */
test.describe('audit event vocabulary', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('one label per event type, on the Dashboard and on the Audit page', async ({
    page,
  }, testInfo) => {
    // The helpers are page-shell globals, so they can be exercised directly:
    // both pages call the same two functions.
    const labels = await page.evaluate(() =>
      [
        'mcp_tool_called',
        'mcp_tool_call_denied',
        'credential_vended',
        'credential_secret_rotated',
        'oauth2_token_acquired',
      ].map((t) => (window as any).eventTypeLabel(t)),
    );

    expect(labels).toEqual([
      'MCP Tool Call',
      'MCP Tool Denied',
      'Credential Vended',
      'Secret Rotated',
      'OAuth2 Token Acquired',
    ]);

    // Never the raw wire name, and never "Mcp".
    for (const label of labels) {
      expect(label).not.toContain('_');
      expect(label).not.toContain('Mcp');
    }
  });

  test('one principal per event, whichever page shows it', async ({ page }) => {
    const principals = await page.evaluate(() => {
      const ep = (window as any).eventPrincipal;
      return [
        ep({ workspace_name: 'ws-a', user_name: 'root' }),
        ep({ user_name: 'root' }),
        ep({}),
        ep(null),
      ];
    });
    // The acting workspace wins over the credential's owner, everywhere.
    expect(principals).toEqual(['ws-a', 'root', 'system', 'system']);
  });

  test('the Audit page and the Dashboard agree on the label of the same row', async ({
    page,
  }, testInfo) => {
    await page.goto('/audit');
    await expect(page.locator('div.content-header h2')).toHaveText(/Audit/i);
    // Whatever rows exist, no cell shows a raw snake_case wire name.
    const pills = await page.locator('table.tbl tbody .pill-type').allInnerTexts();
    for (const text of pills) {
      expect(text.trim()).not.toMatch(/^[a-z0-9]+(_[a-z0-9]+)+$/);
    }
    await shot(page, testInfo, 'audit-event-labels');
  });

  test('the audit filters report their state', async ({ page }) => {
    await page.goto('/audit');
    // Seventeen event types wrapped the pill row onto two lines and reflowed it
    // on every load, so the type filter is a dropdown (uat/artifacts/reviews/DESIGN-REVIEW.md
    // §2.6); the three decision values stay pills.
    const types = page.locator('#audit-type-filter');
    await expect(types).toHaveAttribute('aria-label', 'Event type');
    await expect(types).toHaveValue('');

    const permit = page.locator('.audit-filter-pill', { hasText: /^Permit$/ });
    await expect(permit).toHaveAttribute('aria-pressed', 'false');
    await permit.click();
    await expect(permit).toHaveAttribute('aria-pressed', 'true');
    await permit.click();
    await expect(permit).toHaveAttribute('aria-pressed', 'false');
  });

  test('the audit table keeps its header row on a phone and scrolls sideways', async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/audit');
    // The header row survives: it used to be `display: none` under 768px,
    // which left every decision and principal cell unlabelled.
    await expect(page.locator('table.audit-tbl thead')).toBeVisible();
    // ac.js wraps the table in a horizontally scrolling box.
    const scrolls = await page.evaluate(() => {
      const box = document.querySelector('table.audit-tbl')?.parentElement;
      if (!box) return null;
      return {
        wrapped: box.classList.contains('tbl-scroll'),
        overflowX: getComputedStyle(box).overflowX,
      };
    });
    expect(scrolls?.wrapped).toBe(true);
    expect(scrolls?.overflowX).toBe('auto');
    // The page itself never scrolls sideways.
    const bodyOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(bodyOverflow).toBeLessThanOrEqual(1);
    await shot(page, testInfo, 'audit-mobile-table');
  });

  test('a burst of audit events costs one dashboard refresh, not one each', async ({
    page,
  }) => {
    await page.goto('/dashboard');
    await expect(page.locator('div.content-header h2')).toHaveText('Dashboard');
    // Let the initial load settle before counting.
    await page.waitForTimeout(1000);

    let requests = 0;
    page.on('request', (r) => {
      const u = r.url();
      if (u.includes('/api/v1/audit') || u.includes('/api/v1/stats')) requests += 1;
    });

    // Ten audit events arriving back to back, as a busy broker produces them.
    await page.evaluate(() => {
      for (let i = 0; i < 10; i += 1) {
        window.dispatchEvent(new CustomEvent('ac:audit_event', { detail: {} }));
      }
    });

    // 300 ms debounce plus room for the fetches to start.
    await page.waitForTimeout(1500);

    // One refresh is 1 stats + 4 audit fetches. Without the debounce, ten
    // events cost fifty.
    expect(requests).toBeLessThanOrEqual(6);
  });
});

/**
 * A viewer is not offered a control the API will refuse
 * (uat/artifacts/reviews/UI-REVIEW-live.md M3, the MCP half).
 */
test.describe('MCP list for a limited role', () => {
  test('an admin sees the marketplace', async ({ page }) => {
    await login(page);
    await page.goto('/mcp-servers');
    // The list's primary action is the way to it; the catalog is its own page.
    const addServer = page.locator('a.btn-primary', { hasText: 'Add server' });
    await expect(addServer).toBeVisible();
    await addServer.click();
    await page.waitForURL('**/mcp-servers/marketplace', { timeout: 30_000 });
    await expect(page.locator('#marketplace')).toBeVisible();
  });
});
