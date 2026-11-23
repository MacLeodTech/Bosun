import { type Page, expect, test } from '@playwright/test';
import { PROXY_PORT, TARGET_PORT } from '../ports';
import { hits, seen, viaProxy } from '../target';

// One engine and one account for the whole file; the tests build on each other in order.
test.describe.configure({ mode: 'serial' });

const USER = 'admin';
const PASSWORD = 'correct horse battery staple';
const TARGET = `http://127.0.0.1:${TARGET_PORT}`;

let page: Page;

test.beforeAll(async ({ browser }) => {
  page = await (await browser.newContext()).newPage();
});
test.afterAll(async () => {
  await page.context().close();
});

async function signedIn() {
  await expect(page.getByText(`${USER} (admin)`)).toBeVisible();
}

test('first run: the setup code creates the admin account', async () => {
  // The link carries the code in the fragment, so it never reaches the server.
  await page.goto(`/#setup=${process.env.BOSUN_E2E_SETUP_CODE}`);
  await page.getByLabel('Username').fill(USER);
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByLabel('Confirm password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Create admin' }).click();
  await signedIn();
  expect(page.url()).not.toContain('setup=');
});

test('sign out, a wrong password is refused, the right one signs in', async () => {
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.getByLabel('Username').fill(USER);
  await page.getByLabel('Password').fill('not the password at all');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.locator('.error')).toBeVisible();
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await signedIn();
});

test('scope: an include rule is saved and survives a reload', async () => {
  await page.getByRole('navigation').getByRole('button', { name: 'Target' }).click();
  await page.getByRole('button', { name: 'Add include rule' }).click();
  await page.locator('section.scope tbody tr').first().locator('input.mono').first().fill('127.0.0.1');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(page.getByText('Scope saved.')).toBeVisible();
  await page.reload();
  await page.getByRole('navigation').getByRole('button', { name: 'Target' }).click();
  await expect(page.locator('section.scope input.mono').first()).toHaveValue('127.0.0.1');
});

test('history: a request through the proxy appears without a reload', async () => {
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  const reply = await viaProxy(PROXY_PORT, `${TARGET}/hello-history`);
  expect(reply).toEqual({ status: 200, body: 'hello from /hello-history' });
  await expect(page.locator('.row', { hasText: '/hello-history' })).toBeVisible();
});

test('history: a large response is shown a page at a time', async () => {
  await viaProxy(PROXY_PORT, `${TARGET}/big`);
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await page.locator('.row', { hasText: '/big' }).click();
  const resp = page.locator('.msg').nth(1);
  await expect(resp.locator('pre.code')).toContainText('START-MARK');
  await expect(resp.locator('pre.code')).not.toContainText('END-MARK');
  await expect(resp.getByText(/of the body not loaded/)).toBeVisible();
  // Two more pages bring in the rest.
  await resp.getByRole('button', { name: 'Load more' }).click();
  await resp.getByRole('button', { name: 'Load more' }).click();
  await expect(resp.locator('pre.code')).toContainText('END-MARK');
  await expect(resp.getByRole('button', { name: 'Load more' })).toHaveCount(0);
  await expect(resp.getByRole('link', { name: 'download body' })).toHaveAttribute('href', /\/response\/body$/);
});

test('the render view cannot run script from a hostile page', async () => {
  await viaProxy(PROXY_PORT, `${TARGET}/evil`);
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await page.locator('.row', { hasText: '/evil' }).click();
  // Request pane first, response pane second: the response is what hostile servers control.
  await page.getByRole('button', { name: 'render', exact: true }).nth(1).click();

  const frame = page.locator('iframe.render');
  await expect(frame).toBeVisible();
  // The sandbox attribute must be present and empty: no scripts, no same-origin, no forms, no popups. The UI's
  // CSP (inherited by srcdoc) would also stop inline script, so this assertion is what guards the sandbox on its
  // own: weakening it fails here even though the call-back check below would still pass.
  await expect(frame).toHaveAttribute('sandbox', '');
  // The page is shown (so a "pass" is not just an empty frame)...
  await expect(page.frameLocator('iframe.render').locator('#evil-heading')).toHaveText('evil page');
  // ...and none of its script, event handlers or javascript: links called back.
  await page.waitForTimeout(1500);
  expect(hits).toEqual([]);
  expect(seen.some((s) => s.path === '/hit')).toBe(false);
});

/// Switch request interception on or off and wait until the server has saved it. The checkbox flips in the browser at
/// once, but the proxy only holds requests after the `PUT /intercept` has returned.
async function setIntercept(on: boolean) {
  const box = page.getByLabel('Intercept requests');
  const saved = page.waitForResponse((r) => r.request().method() === 'PUT' && /\/intercept$/.test(r.url()));
  await box.setChecked(on);
  expect((await saved).ok()).toBe(true);
  await expect(box).toBeChecked({ checked: on });
}

test('intercept: hold a request, edit it, forward it, and the target sees the edit', async () => {
  await page.getByRole('navigation').getByRole('button', { name: 'Intercept' }).click();
  await setIntercept(true);

  const pending = viaProxy(PROXY_PORT, `${TARGET}/echo`);
  await expect(page.locator('.list li button', { hasText: '/echo' })).toBeVisible();

  const editor = page.locator('textarea.code');
  const raw = await editor.inputValue();
  expect(raw).toContain('GET /echo');
  await editor.fill(raw.replace(/\r?\n\r?\n$/, '\r\nX-Edited-By-Test: yes\r\n\r\n'));
  await page.getByRole('button', { name: 'Forward', exact: true }).click();

  const reply = await pending;
  expect(reply.status).toBe(200);
  expect(JSON.parse(reply.body)['x-edited-by-test']).toBe('yes');

  await setIntercept(false);
});

test('intercept: dropping a request answers the client with an error', async () => {
  await setIntercept(true);
  const pending = viaProxy(PROXY_PORT, `${TARGET}/dropped`).catch((e) => ({ status: 0, body: String(e) }));
  await expect(page.locator('.list li button', { hasText: '/dropped' })).toBeVisible();
  await page.getByRole('button', { name: 'Drop', exact: true }).click();
  const reply = await pending;
  expect(reply.status).not.toBe(200);
  expect(seen.some((s) => s.path === '/dropped')).toBe(false);
  await setIntercept(false);
});

test('projects: a new project starts empty, and the first one comes back with its history', async () => {
  const nav = page.getByRole('navigation');
  await nav.getByRole('button', { name: 'Projects' }).click();
  await expect(page.getByText('Open: default')).toBeVisible();

  await page.getByLabel('Project name').fill('second');
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page.locator('tbody tr', { hasText: 'second' })).toBeVisible();
  // "open it" is on by default.
  await expect(page.getByText('Open: second')).toBeVisible();

  await nav.getByRole('button', { name: 'HTTP history' }).click();
  await expect(page.locator('.row', { hasText: '/hello-history' })).toHaveCount(0);

  await nav.getByRole('button', { name: 'Projects' }).click();
  await page.locator('tbody tr', { hasText: 'default' }).getByRole('button', { name: 'Open' }).click();
  await expect(page.getByText('Open: default')).toBeVisible();
  await nav.getByRole('button', { name: 'HTTP history' }).click();
  await expect(page.locator('.row', { hasText: '/hello-history' }).first()).toBeVisible();
});
