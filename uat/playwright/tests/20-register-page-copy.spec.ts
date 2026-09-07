import { test, expect } from '@playwright/test';
import { login, shot } from './helpers/ui';

/**
 * `/register` is the page a new user reads before running anything, and its
 * copy is the product's instructions (native F1, docker F9).
 *
 * `crates/server/tests/register_page_copy.rs` asserts the shipped markup. Only
 * a browser can say what the reader actually sees: the install command is
 * written into the page by script, per operating-system tab, so the rendered
 * text is the only place the flags are visible.
 */
test.describe('the register page says what the CLI and the installer do', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('the install command matches the README, and names ~/.local/bin', async ({
    page,
  }, testInfo) => {
    await page.goto('/register');
    await expect(page.locator('div.content-header h2')).toHaveText(
      /Workspace Registration/i,
    );

    // The command is filled in by script from the origin the reader used.
    const linux = page.locator('#install-cmd-linux');
    await expect(linux).toContainText('curl -fsSL');
    await expect(linux).toContainText('/install.sh | sh');
    await expect(linux).not.toContainText('curl -sSfL');

    // The installer installs the binaries itself; it never asks for a move.
    const body = await page.locator('body').innerText();
    expect(body).toContain('~/.local/bin');
    expect(body).not.toContain('move it somewhere on your PATH');

    await shot(page, testInfo, 'register-install-copy');
  });

  test('the page does not promise the CLI opens a browser', async ({ page }) => {
    await page.goto('/register');

    const body = await page.locator('body').innerText();
    // `agentcordon register` deliberately never launches a browser: the broker
    // usually runs on another host, so it would open on the wrong machine.
    expect(body).toContain('does not open a browser');
    expect(body).not.toMatch(/opens\s+\/activate\s+in your browser/);
    // The activation page is still linked, for the reader to open themselves.
    await expect(page.locator('a[href="/activate"]')).toBeVisible();
  });
});
