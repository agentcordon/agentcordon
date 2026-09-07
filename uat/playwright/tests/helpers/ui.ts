import * as fs from 'fs';
import * as path from 'path';
import { Page, TestInfo, expect } from '@playwright/test';
import { UAT, SCREENSHOTS } from './env';

/**
 * Log in as root through the real login form and land on the dashboard.
 * The session cookie is `Secure`, which Chromium and Firefox both accept for
 * 127.0.0.1 (they treat it as a secure origin). See uat/README.md concession 5.
 */
export async function login(page: Page): Promise<void> {
  await loginAs(page, UAT.rootUsername, UAT.rootPassword);
}

/**
 * Log in as a named account through the same form. Used by the scenarios that
 * need a second person — a vault shared read-only is only interesting from the
 * recipient's browser.
 */
export async function loginAs(
  page: Page,
  username: string,
  password: string,
): Promise<void> {
  await page.goto('/login');
  await page.fill('#login-username', username);
  await page.fill('#login-password', password);
  await page.click('button.login-submit-btn');
  await page.waitForURL('**/dashboard', { timeout: 30_000 });
  await expect(page.locator('div.content-header h2')).toHaveText('Dashboard');
}

/**
 * Sign out through the nav's own control, so the next login starts clean.
 *
 * Sign Out moved into the user menu under the signed-in name
 * (uat/artifacts/reviews/DESIGN-REVIEW.md §1.1), so the control is behind one click on desktop
 * and behind the drawer on a phone. `button.sign-out` still names it in both.
 */
export async function logout(page: Page): Promise<void> {
  const signOut = page.locator('button.sign-out:visible');
  if ((await signOut.count()) === 0) {
    const menu = page.locator('.user-menu-btn');
    // On a phone the bar's right-hand group is hidden and the drawer carries
    // the same three items.
    if (await menu.isVisible().catch(() => false)) {
      await menu.click();
    } else {
      await page.locator('.hamburger-btn').click();
    }
  }
  await page.locator('button.sign-out:visible').first().click();
  await page.waitForURL('**/login', { timeout: 30_000 });
}

/**
 * Capture a full-page screenshot into uat/artifacts/screenshots AND attach it
 * to the HTML report, so both the report and REPORT.md can reference it.
 *
 * The sequence number comes from the directory, not from a module-level
 * counter: Playwright restarts its worker after a failure, which would reset
 * an in-process counter and produce duplicate prefixes.
 */
export async function shot(page: Page, testInfo: TestInfo, name: string): Promise<string> {
  fs.mkdirSync(SCREENSHOTS, { recursive: true });
  const next = fs.readdirSync(SCREENSHOTS).filter((f) => f.endsWith('.png')).length + 1;
  const file = path.join(
    SCREENSHOTS,
    `${String(next).padStart(2, '0')}-${name}.png`,
  );
  await page.screenshot({ path: file, fullPage: true });
  await testInfo.attach(name, { path: file, contentType: 'image/png' });
  return file;
}

/**
 * Assert that a form's own POST/PUT succeeded.
 *
 * Deliberately never calls `response.text()`: every admin-UI form navigates on
 * success, and reading a response body after its page has navigated away
 * either errors ("No resource with given identifier found") or hangs until the
 * test times out. On failure it reports the toast the UI showed instead, which
 * is what the user would see anyway.
 */
export async function expectOk(
  page: Page,
  response: { status(): number; url(): string },
  what: string,
): Promise<void> {
  const status = response.status();
  if (status >= 200 && status < 300) return;
  const toast = await page
    .locator('.toast, [role="alert"], .install-form-error')
    .first()
    .textContent()
    .catch(() => null);
  throw new Error(
    `${what}: ${response.url()} answered HTTP ${status}${toast ? ` — UI said: ${toast.trim()}` : ''}`,
  );
}

/** The double-submit CSRF token the admin API requires for writes. */
export async function csrfToken(page: Page): Promise<string> {
  const fromMeta = await page
    .locator('meta[name="csrf-token"]')
    .getAttribute('content')
    .catch(() => null);
  if (fromMeta) return fromMeta;
  return page.evaluate(() => {
    const m = document.cookie.match(/agtcrdn_csrf=([^;]+)/);
    return m ? m[1] : '';
  });
}

export interface ApiResult {
  status: number;
  body: any;
}

/**
 * Issue an admin-API call from inside the page, i.e. with the browser's real
 * session cookie and CSRF token — the same way the UI's own JS does it.
 */
export async function apiFromPage(
  page: Page,
  method: string,
  urlPath: string,
  body?: unknown,
): Promise<ApiResult> {
  const csrf = await csrfToken(page);
  return page.evaluate(
    async ({ method, urlPath, body, csrf }) => {
      const init: RequestInit = {
        method,
        headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' },
        credentials: 'same-origin',
      };
      if (body !== undefined && body !== null) init.body = JSON.stringify(body);
      const resp = await fetch(urlPath, init);
      const text = await resp.text();
      let parsed: any = text;
      try {
        parsed = JSON.parse(text);
      } catch {
        /* keep raw text */
      }
      return { status: resp.status, body: parsed };
    },
    { method, urlPath, body: body ?? null, csrf },
  );
}
