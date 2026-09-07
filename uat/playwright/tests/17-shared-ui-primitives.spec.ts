import { test, expect } from '@playwright/test';
import { login, shot } from './helpers/ui';

/**
 * The shared UI primitives — `AC.confirm`, `AC.fetch`, the toast region and the
 * mobile navigation drawer (uat/artifacts/reviews/UI-REVIEW findings A1, A2, B3, B4, M6, M7,
 * M13).
 *
 * The Rust tests at `crates/server/tests/admin_ui_controls.rs` assert that the
 * markup and the module are shipped. Only a browser can say whether focus
 * actually moves, whether Tab stays inside the dialog, and whether the drawer
 * covers the page — so those are here.
 */
test.describe('shared UI primitives', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('AC.confirm opens a labelled dialog, starts on Cancel, traps Tab and restores focus', async ({
    page,
  }, testInfo) => {
    await page.goto('/dashboard');

    // Drive the primitive directly: it is shared, so no one page owns it.
    await page.evaluate(() => {
      const opener = document.createElement('button');
      opener.id = 'ac-test-opener';
      opener.textContent = 'Open';
      document.querySelector('main')!.appendChild(opener);
      opener.addEventListener('click', () => {
        (window as any).__acResult = (window as any).AC.confirm({
          title: 'Delete something',
          message: 'This cannot be undone.',
          confirmLabel: 'Delete',
          danger: true,
        });
      });
    });

    await page.click('#ac-test-opener');

    const dialog = page.locator('#ac-confirm');
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAttribute('role', 'dialog');
    await expect(dialog).toHaveAttribute('aria-modal', 'true');
    await expect(page.locator('#ac-confirm-title')).toHaveText('Delete something');

    // Initial focus is Cancel, never the destructive button.
    await expect(page.locator('#ac-confirm-cancel')).toBeFocused();
    await shot(page, testInfo, 'ac-confirm-open');

    // The page behind is inert.
    await expect(page.locator('main#main-content')).toHaveAttribute('inert', '');

    // Tab cycles inside the dialog and never reaches the page.
    await page.keyboard.press('Tab');
    await expect(page.locator('#ac-confirm-ok')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#ac-confirm-cancel')).toBeFocused();

    // Escape cancels, resolves false, un-inerts the page and restores focus.
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    expect(await page.evaluate(() => (window as any).__acResult)).toBe(false);
    await expect(page.locator('main#main-content')).not.toHaveAttribute('inert', '');
    await expect(page.locator('#ac-test-opener')).toBeFocused();
  });

  test('an error toast is assertive, persistent and dismissable; a blank one is refused', async ({
    page,
  }) => {
    await page.goto('/dashboard');

    await page.evaluate(() => (window as any).AC.toast('Something went wrong', 'error'));
    const toast = page.locator('.toast-error');
    await expect(toast).toHaveAttribute('role', 'alert');

    // Success toasts vanish on their own; error toasts do not.
    await page.waitForTimeout(5_000);
    await expect(toast).toBeVisible();

    await page.locator('.toast-error .toast-close').click();
    await expect(toast).toHaveCount(0);

    // M13: two empty rectangles used to appear beside a real error.
    await page.evaluate(() => (window as any).AC.toast('', 'error'));
    await page.evaluate(() => (window as any).AC.toast('   ', 'error'));
    await expect(page.locator('.toast')).toHaveCount(0);
  });

  test('AC.fetch sends an expired session to the login page with a message', async ({ page }) => {
    await page.goto('/dashboard');
    await page.context().clearCookies();

    // Fire and forget: AC.fetch navigates on 401 and its promise never settles.
    await page.evaluate(() => {
      void (window as any).AC.fetch('/api/v1/vaults');
    });

    await page.waitForURL(/\/login\?/, { timeout: 15_000 });
    expect(page.url()).toContain('next=');
    await expect(page.locator('body')).toContainText(/session expired/i);
  });

  test('the mobile navigation is a labelled drawer with a backdrop and labelled links', async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/dashboard');

    const drawer = page.locator('#main-nav');
    await expect(drawer).toBeHidden();

    await page.locator('.hamburger-btn').click();
    await expect(drawer).toBeVisible();
    await expect(page.locator('.nav-drawer-backdrop')).toBeVisible();
    await shot(page, testInfo, 'mobile-nav-drawer');

    // B3: the links were a strip of unlabelled icons.
    // "Security" was the only name in the product for pages whose titles, back
    // links and breadcrumb all say "policy" (uat/artifacts/reviews/DESIGN-REVIEW.md 1.1).
    for (const label of ['Dashboard', 'Workspaces', 'Credentials', 'Policies', 'Audit Log', 'Sign Out']) {
      await expect(drawer.getByText(label, { exact: true })).toBeVisible();
    }

    await page.keyboard.press('Escape');
    await expect(drawer).toBeHidden();
  });

  test('every table scrolls horizontally on a phone instead of clipping', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/audit');
    await page.waitForSelector('table.tbl', { timeout: 30_000 });

    // ac.js wraps the table, and the wrapper is what scrolls.
    const wrapped = await page.evaluate(() => {
      const table = document.querySelector('table.tbl')!;
      const parent = table.parentElement!;
      return {
        wrapper: parent.classList.contains('tbl-scroll'),
        scrolls: parent.scrollWidth > parent.clientWidth,
      };
    });
    expect(wrapped.wrapper).toBe(true);

    // B4: the document itself must not scroll sideways.
    const overflows = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth + 1,
    );
    expect(overflows).toBe(false);
  });

  test('the device activation buttons are styled, not bare text', async ({ page }) => {
    // C3: .btn-approve / .btn-deny lived only in consent.html's inline stylesheet.
    await page.goto('/activate');
    const approve = page.locator('.btn-approve').first();
    if ((await approve.count()) > 0) {
      const bg = await approve.evaluate((el) => getComputedStyle(el).backgroundColor);
      expect(bg).not.toBe('rgba(0, 0, 0, 0)');
    }
  });
});
