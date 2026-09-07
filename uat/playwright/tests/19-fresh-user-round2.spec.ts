import { test, expect } from '@playwright/test';
import { login, shot } from './helpers/ui';
import { UAT } from './helpers/env';

/**
 * The second pair of fresh-user walkthroughs
 * (uat/artifacts/fresh-user-native-2.md, uat/artifacts/fresh-user-docker-2.md).
 *
 * The Rust tests at `crates/server/tests/fresh_user_round2.rs` assert that the
 * markup, the stylesheet and the routes ship the fix. Only a browser can say
 * whether a click in the *last* cell of a row actually navigates, whether an
 * arrow key moves between tabs, or what a reader sees in a rendered timestamp
 * — so those are here.
 */
test.describe('fresh-user round 2', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  /**
   * Native F2. "Clicking the last cell of the first row on /security did
   * nothing." Every list is one pattern now: the name cell's anchor is
   * stretched over the row, so the row navigates from anywhere in it.
   */
  test('every list row navigates from its last cell, not only its name', async ({
    page,
  }, testInfo) => {
    const lists: Array<[string, string, RegExp]> = [
      ['/credentials', 'tr.cred-row', /\/credentials\/[0-9a-f-]{36}$/],
      ['/workspaces', 'tr.ws-row', /\/workspaces\/[0-9a-f-]{36}$/],
      ['/security', 'tr.policy-row', /\/security\/.+$/],
    ];

    for (const [path, rowSelector, destination] of lists) {
      await page.goto(path);
      const row = page.locator(rowSelector).first();
      await expect(row).toBeVisible();

      // The click lands in the middle of the row's LAST cell — the place the
      // walkthrough clicked and nothing happened.
      const lastCell = row.locator('td').last();
      await lastCell.click();
      await page.waitForURL(destination, { timeout: 15_000 });
      expect(page.url()).toMatch(destination);
    }
    await shot(page, testInfo, 'row-link-last-cell');
  });

  /**
   * Docker impression 2. Tools/Access/History were three plain buttons; they
   * are a tablist whose arrow keys move between the tabs.
   */
  test('a detail tab bar is a tablist with arrow-key navigation', async ({
    page,
  }, testInfo) => {
    await page.goto('/workspaces');
    await page.locator('tr.ws-row').first().locator('td').last().click();
    await page.waitForURL(/\/workspaces\/[0-9a-f-]{36}$/, { timeout: 15_000 });

    const bar = page.locator('[role="tablist"]').first();
    await expect(bar).toBeVisible();
    const tabs = bar.locator('[role="tab"]');
    await expect(tabs).toHaveCount(3);

    // The selected tab is the one Tab reaches, and it says it is selected.
    const first = tabs.nth(0);
    await expect(first).toHaveAttribute('aria-selected', 'true');
    await expect(first).toHaveAttribute('tabindex', '0');
    const panelId = await first.getAttribute('aria-controls');
    expect(panelId).toBeTruthy();
    await expect(page.locator(`#${panelId}`)).toHaveAttribute('role', 'tabpanel');

    await first.focus();
    await page.keyboard.press('ArrowRight');
    await expect(tabs.nth(1)).toBeFocused();
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
    await expect(tabs.nth(0)).toHaveAttribute('aria-selected', 'false');

    // And it wraps, so End/Home and the ends of the bar behave.
    await page.keyboard.press('End');
    await expect(tabs.nth(2)).toBeFocused();
    await page.keyboard.press('ArrowRight');
    await expect(tabs.nth(0)).toBeFocused();
    await shot(page, testInfo, 'tablist-arrow-keys');
  });

  /**
   * Native F15. At 420 px the Recent activity table clipped Resource and
   * Decision with no scroll affordance, and spent the Timestamp column on a
   * full `9/6/2026 12:38:32 PM`.
   */
  test('the dashboard activity table scrolls on a phone and reads in relative time', async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width: 420, height: 900 });
    await page.goto('/dashboard');

    const table = page.locator('.dash-section table.tbl');
    await expect(table).toBeVisible();

    // `ac.js` wraps every `.tbl`, and below 768px the wrapper is the scrollport.
    const wrap = page.locator('.dash-section .tbl-scroll');
    await expect(wrap).toBeVisible();
    const scrollable = await wrap.evaluate(
      (el) => getComputedStyle(el).overflowX === 'auto' && el.scrollWidth > el.clientWidth,
    );
    expect(scrollable).toBe(true);

    // And the timestamp is relative, with the exact time on the title.
    const cell = page.locator('.dash-section table.tbl td.timestamp').first();
    await expect(cell).toHaveText(/(just now|\d+[mhd] ago|\d{1,2}\/\d{1,2}\/\d{4})/);
    await expect(cell).toHaveAttribute('title', /\d{1,2}\/\d{1,2}\/\d{4}/);
    await shot(page, testInfo, 'dashboard-mobile-activity');
  });

  /**
   * Docker F5. `/users` and `/settings/users` were a third and fourth surface
   * for one function; both land on the Settings section that holds the table.
   */
  test('user management is a Settings section, reached from both old paths', async ({
    page,
  }) => {
    for (const path of ['/users', '/settings/users']) {
      await page.goto(path);
      await expect(page).toHaveURL(/\/settings#users-section$/);
      await expect(page.locator('#users-section')).toBeVisible();
    }

    // One label for one action, and it goes straight to the form.
    const add = page.locator('#users-section a', { hasText: 'Add User' });
    await expect(add).toHaveAttribute('href', '/settings/users/new');
    await add.click();
    await page.waitForURL(/\/settings\/users\/new$/, { timeout: 15_000 });
    await expect(
      page.locator('a[href="/settings#users-section"]').first(),
    ).toBeVisible();
  });

  /**
   * Native impression 2. The list showed `generic` for both a bearer
   * credential and a basic-auth one.
   */
  test('a generic credential names its transform in the list', async ({ page }) => {
    await page.goto('/credentials');
    const cell = page.locator(
      `tr.cred-row[aria-label="${UAT.credentialName}"] .cred-type-cell`,
    );
    await expect(cell).toHaveText(/generic · (bearer|basic-auth|identity)/);
  });

  /**
   * Native F8. A card whose bundled logo is missing draws the first letter,
   * the way `docs/granting-mcp-server-access.md` promises.
   */
  test('no marketplace card renders a broken image', async ({ page }, testInfo) => {
    await page.goto('/mcp-servers/marketplace');
    await expect(page.locator('.marketplace-card-icon').first()).toBeVisible();

    const broken = await page
      .locator('.marketplace-card-icon img')
      .evaluateAll((imgs) =>
        imgs.filter((i) => !(i as HTMLImageElement).complete || (i as HTMLImageElement).naturalWidth === 0).length,
      );
    expect(broken).toBe(0);
    await shot(page, testInfo, 'marketplace-logos');
  });
});
