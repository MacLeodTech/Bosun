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
  await expect(resp.locator('.code')).toContainText('START-MARK');
  await expect(resp.locator('.code')).not.toContainText('END-MARK');
  await expect(resp.getByText(/of the body not loaded/)).toBeVisible();
  // Two more pages bring in the rest.
  await resp.getByRole('button', { name: 'Load more' }).click();
  await resp.getByRole('button', { name: 'Load more' }).click();
  await expect(resp.locator('.code')).toContainText('END-MARK');
  await expect(resp.getByRole('button', { name: 'Load more' })).toHaveCount(0);
  await expect(resp.getByRole('link', { name: 'download body' })).toHaveAttribute('href', /\/response\/body$/);
});

test('history: the open flow and the filters survive a visit to another page', async () => {
  const nav = page.getByRole('navigation');
  await nav.getByRole('button', { name: 'HTTP history' }).click();
  const filter = page.getByLabel('Filter', { exact: true });
  await filter.fill('host:127.0.0.1');
  await filter.press('Enter');
  await page.locator('.row', { hasText: '/hello-history' }).click();
  await expect(page.locator('.row.active', { hasText: '/hello-history' })).toBeVisible();
  await nav.getByRole('button', { name: 'Match & replace' }).click();
  await nav.getByRole('button', { name: 'HTTP history' }).click();
  await expect(filter).toHaveValue('host:127.0.0.1');
  await expect(page.locator('.row.active', { hasText: '/hello-history' })).toBeVisible();
  await expect(page.locator('.msg').nth(1).locator('.code')).toContainText('hello from /hello-history');
  await filter.fill('');
  await filter.press('Enter');
});

test('history: the keyboard moves the selection', async () => {
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  // /big came after /hello-history, so it is the row above it (newest first).
  await page.locator('.row', { hasText: '/hello-history' }).click();
  const here = await page.locator('.row.active').getAttribute('id');
  await page.getByRole('listbox', { name: 'HTTP history' }).focus();
  await page.keyboard.press('k');
  await expect(page.locator('.row.active')).toHaveCount(1);
  await expect(page.locator('.row.active')).not.toHaveAttribute('id', here!);
  await expect(page.locator('.row.active', { hasText: '/big' })).toBeVisible();
  await page.keyboard.press('j');
  await expect(page.locator('.row.active')).toHaveAttribute('id', here!);
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

test('repeater: send by hand, again with a change, diff the two, and the sends are recorded', async () => {
  const nav = page.getByRole('navigation');
  await nav.getByRole('button', { name: 'Repeater' }).click();
  // Panels stay mounted in the background, so labels are only unique within one panel.
  const rp = page.getByRole('tabpanel', { name: 'Repeater', exact: true });
  await rp.getByLabel('Scheme').selectOption('http');
  await rp.getByLabel('Host', { exact: true }).fill('127.0.0.1');
  await rp.getByLabel('Port').fill(String(TARGET_PORT));
  await rp.getByLabel('Request').fill('GET /rp-one HTTP/1.1\nHost: 127.0.0.1\n\n');
  await rp.getByRole('button', { name: 'Send', exact: true }).click();
  await expect(rp.locator('.out')).toContainText('hello from /rp-one');
  await expect(rp.getByText('send 1 of 1')).toBeVisible();

  await rp.getByLabel('Request').fill('GET /rp-two HTTP/1.1\nHost: 127.0.0.1\n\n');
  await rp.getByRole('button', { name: 'Send', exact: true }).click();
  await expect(rp.locator('.out')).toContainText('hello from /rp-two');
  await rp.getByLabel('Diff with previous').check();
  await expect(rp.locator('.out .del', { hasText: 'hello from /rp-one' })).toBeVisible();
  await expect(rp.locator('.out .add', { hasText: 'hello from /rp-two' })).toBeVisible();

  // Many at once: a group shows how many different answers it produced.
  await rp.getByLabel('Count').fill('5');
  await rp.getByLabel('Mode').selectOption('parallel');
  await rp.getByRole('button', { name: 'Send', exact: true }).click();
  await expect(rp.getByRole('status')).toContainText('5 results, 1 different');

  // The sends are in the history as the Repeater's.
  await nav.getByRole('button', { name: 'HTTP history' }).click();
  await expect(page.locator('.row', { hasText: '/rp-two' }).first()).toBeVisible();

  // Out-of-scope targets are refused until the setting is turned on.
  await nav.getByRole('button', { name: 'Repeater' }).click();
  await rp.getByLabel('Host', { exact: true }).fill('localhost');
  await rp.getByLabel('Count').fill('1');
  await rp.getByLabel('Mode').selectOption('sequential');
  await rp.getByRole('button', { name: 'Send', exact: true }).click();
  await expect(rp.getByText('refused')).toBeVisible();
});

test('decoder and comparer: a chain decodes, smart decode peels layers, and the diff marks what changed', async () => {
  const nav = page.getByRole('navigation');
  await nav.getByRole('button', { name: 'Decoder' }).click();
  const dp = page.getByRole('tabpanel', { name: 'Decoder', exact: true });
  await dp.getByLabel('Decoder input').fill('aGVsbG8lMjB3b3JsZA==');
  await dp.getByLabel('Step to add').selectOption('base64_decode');
  await dp.getByRole('button', { name: 'Add step' }).click();
  await dp.getByLabel('Step to add').selectOption('url_decode');
  await dp.getByRole('button', { name: 'Add step' }).click();
  await expect(dp.locator('.out').last()).toHaveText('hello world');
  // Smart decode finds the same layers without being told.
  await dp.getByRole('button', { name: 'Clear steps' }).click();
  await dp.getByRole('button', { name: 'Smart decode' }).click();
  await expect(dp.locator('.out').last()).toHaveText('hello world');

  await nav.getByRole('button', { name: 'Comparer' }).click();
  const cp = page.getByRole('tabpanel', { name: 'Comparer', exact: true });
  await cp.getByLabel('Left side').fill('the quick brown fox');
  await cp.getByLabel('Right side').fill('the slow brown fox');
  await expect(cp.locator('del')).toContainText('quick');
  await expect(cp.locator('ins')).toContainText('slow');
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

// ---- the dock -------------------------------------------------------------------------------------------------

async function layoutMenu(item: string) {
  await page.getByRole('button', { name: 'Layout', exact: false }).filter({ hasText: 'Layout' }).first().click();
  await page.getByRole('menuitem', { name: item }).or(page.getByRole('menuitemradio', { name: item })).first().click();
}

test('dock: a layout survives a reload, and a corrupt one falls back with a notice', async () => {
  await layoutMenu('Reset layout');
  const nav = page.getByRole('navigation');
  await nav.getByRole('button', { name: 'Target' }).click();
  await expect(page.getByRole('tab', { name: 'Target' })).toHaveAttribute('aria-selected', 'true');
  await layoutMenu('Intercept');
  // The Intercept preset has the queue on top and History below.
  await expect(page.getByRole('tablist')).toHaveCount(3);
  await page.reload();
  await signedIn();
  await expect(page.getByRole('tablist')).toHaveCount(3);
  await expect(page.getByRole('tab', { name: 'Intercept' })).toBeVisible();

  // Opening #target at startup schedules a debounced save; let it land so it cannot overwrite what is injected next.
  await page.waitForTimeout(400);
  await page.evaluate(() => localStorage.setItem('bosun.workspace.v1', JSON.stringify({ version: 1, root: { kind: 'split', id: 'x', dir: 'row', sizes: [1, 1], children: [{ kind: 'bogus' }] } })));
  await page.reload();
  await signedIn();
  await expect(page.getByRole('tab', { name: 'HTTP history' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Request / response' })).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: 'saved layout was not valid' })).toBeVisible();
});

test('dock: the keyboard moves a tab into a split of its own and resizes the divider', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'Settings' }).click();
  const tab = page.getByRole('tab', { name: 'Settings' });
  await expect(page.getByRole('tablist')).toHaveCount(2);
  await tab.focus();
  await page.keyboard.press('Alt+Shift+ArrowDown');
  await expect(page.getByRole('tablist')).toHaveCount(3);
  await expect(page.getByRole('tab', { name: 'Settings' })).toBeFocused();

  const sep = page.getByRole('separator', { name: 'Resize panels' }).first();
  await sep.focus();
  const before = Number(await sep.getAttribute('aria-valuenow'));
  await page.keyboard.press('Shift+ArrowDown');
  await expect.poll(async () => Number(await sep.getAttribute('aria-valuenow'))).toBeGreaterThan(before);
  await page.keyboard.press('Enter');
  await expect(sep).toHaveAttribute('aria-valuenow', '50');
});

test('dock: dragging a tab onto the lower edge of a pane splits it, and Escape cancels a drag', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'Match & replace' }).click();
  await expect(page.getByRole('tablist')).toHaveCount(2);

  const tab = await page.getByRole('tab', { name: 'Match & replace' }).boundingBox();
  const target = await page.locator('#pane-flow').boundingBox();
  expect(tab && target).toBeTruthy();
  const drag = async (release: () => Promise<void>) => {
    await page.mouse.move(tab!.x + tab!.width / 2, tab!.y + tab!.height / 2);
    await page.mouse.down();
    await page.mouse.move(tab!.x + tab!.width / 2 + 20, tab!.y + 30, { steps: 4 });
    await page.mouse.move(target!.x + target!.width / 2, target!.y + target!.height - 12, { steps: 8 });
    await release();
  };
  // Escape: nothing moves.
  await drag(async () => {
    await page.keyboard.press('Escape');
    await page.mouse.up();
  });
  await expect(page.getByRole('tablist')).toHaveCount(2);
  // Drop: the pane under the pointer splits and the tab lands in the new half.
  await drag(() => page.mouse.up());
  await expect(page.getByRole('tablist')).toHaveCount(3);
  await expect(page.getByRole('tab', { name: 'Match & replace' })).toHaveAttribute('aria-selected', 'true');
});

test('dock: a panel in the background ignores keys meant for the one on screen', async () => {
  await layoutMenu('Reset layout');
  const nav = page.getByRole('navigation');
  await nav.getByRole('button', { name: 'Intercept' }).click();
  await setIntercept(true);
  const pending = viaProxy(PROXY_PORT, `${TARGET}/background-keys`);
  const item = page.locator('.list li button', { hasText: '/background-keys' });
  await expect(item).toBeVisible();

  // History is in front now; Intercept is mounted but hidden. D would drop the request if it listened.
  await nav.getByRole('button', { name: 'HTTP history' }).click();
  await expect(page.getByRole('tab', { name: 'Intercept' })).toHaveAttribute('aria-selected', 'false');
  await page.getByRole('listbox', { name: 'HTTP history' }).focus();
  await page.keyboard.press('d');
  await page.keyboard.press('Shift+F');
  await page.waitForTimeout(400);

  await nav.getByRole('button', { name: 'Intercept' }).click();
  await expect(item).toBeVisible();
  await page.getByRole('button', { name: 'Forward', exact: true }).click();
  expect((await pending).status).toBe(200);
  await setIntercept(false);
});

test('dock: layouts can be saved, exported and imported', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'Target' }).click();
  await layoutMenu('Save or manage layouts…');
  const dlg = page.getByRole('dialog', { name: 'Layouts' });
  await dlg.getByLabel('Name for the current layout').fill('mine');
  await dlg.getByRole('button', { name: 'Save current layout' }).click();
  await expect(dlg.getByText('Saved “mine”.')).toBeVisible();
  await dlg.getByRole('button', { name: 'Delete' }).click();
  await expect(dlg.getByText('Nothing saved yet.')).toBeVisible();

  await dlg.getByLabel('Paste layouts to import').fill('{"nope":1}');
  await dlg.getByRole('button', { name: 'Import pasted text' }).click();
  await expect(dlg.getByRole('status')).toContainText('not a Bosun layout file');
  const good = { version: 1, presets: { imported: { kind: 'group', id: 'g1', active: 'repeater', tabs: [{ id: 'repeater', panel: 'repeater' }] } } };
  await dlg.getByLabel('Paste layouts to import').fill(JSON.stringify(good));
  await dlg.getByRole('button', { name: 'Import pasted text' }).click();
  await expect(dlg.getByRole('status')).toContainText('Imported 1 layout');
  await dlg.getByRole('button', { name: 'Apply' }).last().click();
  await expect(page.getByRole('tablist')).toHaveCount(1);
  await expect(page.getByRole('tab', { name: 'Repeater' })).toBeVisible();
  await page.keyboard.press('Escape');
  await layoutMenu('Reset layout');
});

// ---- the viewer -----------------------------------------------------------------------------------------------

async function openFlow(path: string) {
  // New rows are held back while the pointer is over the list (so the list never moves under it): keep it elsewhere.
  await page.mouse.move(2, 2);
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  // Match the path cell exactly: a MIME of application/json would otherwise match "/json" too.
  await page.locator('.row', { has: page.locator('.c-path', { hasText: new RegExp(`^${path}$`) }) }).first().click();
}

test('viewer: a large JSON body is pretty-printed, windowed, searchable and scrolls quickly', async () => {
  await viaProxy(PROXY_PORT, `${TARGET}/json`);
  await openFlow('/json');
  const resp = page.locator('.msg').nth(1);
  await resp.getByRole('button', { name: 'pretty', exact: true }).click();
  const code = resp.getByRole('textbox', { name: 'Response' });
  await expect(code).toContainText('"item-0"');
  // Tens of thousands of lines, but only the ones on screen are in the page.
  const rows = await resp.locator('.ln-row').count();
  expect(rows).toBeGreaterThan(5);
  expect(rows).toBeLessThan(200);
  // Syntax colour comes from spans, not markup.
  await expect(resp.locator('.sx-key').first()).toBeVisible();

  // Scroll through the whole body in steps; every frame must settle quickly and the window must stay small.
  const ms = await code.evaluate(async (el) => {
    const t0 = performance.now();
    for (let i = 0; i <= 60; i++) {
      el.scrollTop = (el.scrollHeight - el.clientHeight) * (i / 60);
      await new Promise((r) => requestAnimationFrame(() => r(null)));
    }
    return performance.now() - t0;
  });
  expect(ms).toBeLessThan(4000);
  await expect(resp.locator('.ln-row').last()).toContainText('}');
  expect(await resp.locator('.ln-row').count()).toBeLessThan(200);

  // Ctrl+F searches the whole text, including lines that are not in the page.
  await code.focus();
  await page.keyboard.press('Control+f');
  await resp.getByLabel('Find in message').fill('item-2400"');
  await expect(resp.getByRole('status').filter({ hasText: /of 1$/ })).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(code).toContainText('"item-2400"');
  await expect(resp.locator('.hit.cur')).toBeVisible();
  await page.keyboard.press('Escape');
});

test('viewer: the edited request shows what changed, and a header can filter the history', async () => {
  await openFlow('/echo');
  await page.getByRole('button', { name: 'Changes' }).click();
  const added = page.locator('.diff .add', { hasText: 'X-Edited-By-Test' });
  await expect(added).toBeVisible();
  await expect(page.locator('.diff .w', { hasText: 'X-Edited-By-Test' }).or(added).first()).toBeVisible();

  await page.getByRole('button', { name: 'Request / Response', exact: true }).click();
  const req = page.locator('.msg').first();
  await req.getByRole('button', { name: 'headers', exact: true }).click();
  await req.getByRole('button', { name: 'Filter history by X-Edited-By-Test' }).click();
  await expect(page.getByLabel('Filter', { exact: true })).toHaveValue(/"X-Edited-By-Test: yes"/);
  await expect(page.locator('.row', { hasText: '/echo' })).toBeVisible();
  await expect(page.locator('.row', { hasText: '/hello-history' })).toHaveCount(0);
  await page.getByLabel('Filter', { exact: true }).fill('');
  await page.getByLabel('Filter', { exact: true }).press('Enter');
  await req.getByRole('button', { name: 'raw', exact: true }).click();
});

test('viewer: the render view follows the UI theme and stays sandboxed', async () => {
  await openFlow('/evil');
  await page.getByRole('button', { name: 'render', exact: true }).nth(1).click();
  const frame = page.locator('iframe.render');
  await expect(frame).toHaveAttribute('sandbox', '');
  const doc = await frame.getAttribute('srcdoc');
  // The scheme is a <meta> placed after the doctype (before it, the page would fall into quirks mode).
  expect(doc).toMatch(/^<!doctype html><meta name="color-scheme" content="(dark|light)">/i);
  await page.locator('.msg').nth(1).getByRole('button', { name: 'raw', exact: true }).click();
});

// ---- commands, filter, selection, menus, drag and drop -----------------------------------------------------------

const filterBox = () => page.getByLabel('Filter', { exact: true });
async function applyFilter(q: string) {
  await filterBox().fill(q);
  await filterBox().press('Enter');
}

test('palette: Ctrl+K runs a command, opens a request by number, and Escape closes it', async () => {
  await layoutMenu('Reset layout');
  await page.locator('body').click({ position: { x: 5, y: 5 } });
  await page.keyboard.press('Control+k');
  const dlg = page.getByRole('dialog', { name: 'Command palette' });
  await expect(dlg).toBeVisible();
  await dlg.getByRole('combobox').fill('open sett');
  await expect(dlg.getByRole('option').first()).toContainText('Open Settings');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('tab', { name: 'Settings' })).toHaveAttribute('aria-selected', 'true');

  await page.keyboard.press('Control+k');
  await dlg.getByRole('combobox').fill('#1');
  await expect(dlg.getByRole('option').first()).toContainText('Open request #1');
  await page.keyboard.press('Enter');
  await expect(page.locator('footer')).toContainText('Request #1');

  await page.keyboard.press('Control+k');
  await expect(dlg).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dlg).toBeHidden();
});

test('filter bar: terms become chips, a bad term is explained, and filters can be saved', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await applyFilter('');
  await expect(page.locator('.row', { hasText: '/hello-history' })).toBeVisible();

  await applyFilter('method:POST');
  await expect(page.locator('.chip', { hasText: 'method:POST' })).toBeVisible();
  await expect(page.locator('.row', { hasText: '/hello-history' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Remove method:POST' }).click();
  await expect(page.locator('.row', { hasText: '/hello-history' })).toBeVisible();

  await filterBox().fill('status:abc');
  await expect(page.getByText(/status: expects/)).toBeVisible();

  await applyFilter('host:127.0.0.1 status:2xx');
  await expect(page.locator('.row', { hasText: '/hello-history' })).toBeVisible();
  await page.getByRole('button', { name: 'Saved' }).click();
  await page.getByRole('menuitem', { name: 'Save the applied filter as…' }).click();
  await page.getByLabel('Name for this filter').fill('local ok');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await applyFilter('');
  await page.getByRole('button', { name: 'Saved' }).click();
  await page.getByRole('menuitem', { name: 'local ok', exact: true }).click();
  await expect(filterBox()).toHaveValue('host:127.0.0.1 status:2xx');
  await page.getByRole('button', { name: 'Saved' }).click();
  await page.getByRole('menuitem', { name: 'Delete “local ok”' }).click();
  await applyFilter('');
});

test('query bar: or, not and groups run on the server, keys complete, a mistake is refused, saved filters outlive a reload', async () => {
  await viaProxy(PROXY_PORT, `${TARGET}/q-alpha`);
  await viaProxy(PROXY_PORT, `${TARGET}/q-beta`);
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  const alpha = page.locator('.row', { hasText: '/q-alpha' });
  const beta = page.locator('.row', { hasText: '/q-beta' });
  await applyFilter('');
  await expect(alpha).toBeVisible();
  await expect(beta).toBeVisible();

  // Operators, groups and a newer key (path:) are the server's.
  await applyFilter('(path:q-alpha or path:nothing-like-it) -ext:css');
  await expect(alpha).toBeVisible();
  await expect(beta).toHaveCount(0);
  await applyFilter('host:127.0.0.1 not path:q-alpha path:q-');
  await expect(beta).toBeVisible();
  await expect(alpha).toHaveCount(0);
  await expect(page.locator('.chip', { hasText: 'path:q-' }).first()).toBeVisible();

  // Completion: a key from a prefix, then a value; Tab takes the first suggestion.
  await filterBox().fill('meth');
  await expect(page.getByRole('option', { name: /method:/ })).toBeVisible();
  await filterBox().press('Tab');
  await expect(filterBox()).toHaveValue('method:');
  await expect(page.getByRole('option', { name: 'GET' })).toBeVisible();
  await filterBox().press('ArrowDown');
  await filterBox().press('Enter');
  await expect(filterBox()).toHaveValue('method:GET');
  await filterBox().press('Enter');
  await expect(alpha).toBeVisible();
  await expect(beta).toBeVisible();

  // A mistake is explained and nothing is applied: the list and the applied line stay as they were.
  await filterBox().fill('status:banana path:q-alpha');
  await filterBox().press('Enter');
  await expect(page.getByRole('alert')).toContainText('status: expects');
  await expect(beta).toBeVisible();
  await expect(page.locator('.chip', { hasText: 'method:GET' })).toBeVisible();

  // Saved on the server, so a reload (which drops everything the page held) still has it, and it re-runs.
  await applyFilter('path:q-alpha or path:q-beta');
  await page.getByRole('button', { name: 'Saved' }).click();
  await page.getByRole('menuitem', { name: 'Save the applied filter as…' }).click();
  await page.getByLabel('Name for this filter').fill('both q');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await applyFilter('path:q-alpha');
  await expect(beta).toHaveCount(0);
  await page.getByRole('button', { name: 'Saved' }).click();
  await page.getByRole('menuitem', { name: 'both q', exact: true }).click();
  await expect(filterBox()).toHaveValue('path:q-alpha or path:q-beta');
  await expect(alpha).toBeVisible();
  await expect(beta).toBeVisible();
  await page.getByRole('button', { name: 'Saved' }).click();
  await page.getByRole('menuitem', { name: 'Delete “both q”' }).click();
  await applyFilter('');
});

test('history: shift-click and Ctrl+A select several, delete can be undone, and an undone delete changes nothing', async () => {
  await page.mouse.move(2, 2);
  for (const p of ['ms-a', 'ms-b', 'ms-c']) await viaProxy(PROXY_PORT, `${TARGET}/${p}`);
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await applyFilter('');
  const row = (p: string) => page.locator('.row', { hasText: `/${p}` });
  await row('ms-c').click();
  await row('ms-a').click({ modifiers: ['Shift'] });
  await expect(page.getByRole('region', { name: 'Selection' })).toContainText('3 selected');

  await page.getByRole('region', { name: 'Selection' }).getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(row('ms-a')).toHaveCount(0);
  await page.getByRole('button', { name: 'Undo' }).click();
  await expect(row('ms-a')).toBeVisible();
  await expect(row('ms-c')).toBeVisible();

  // Ctrl+A in the list selects every row; Escape drops back to one.
  await page.getByRole('listbox', { name: 'HTTP history' }).focus();
  await page.keyboard.press('Control+a');
  await expect(page.getByRole('region', { name: 'Selection' })).toContainText('selected');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('region', { name: 'Selection' })).toHaveCount(0);

  // Let a delete run its course: after the undo window the flows are gone from the server too.
  await row('ms-b').click();
  await page.getByRole('listbox', { name: 'HTTP history' }).focus();
  await page.keyboard.press('Delete');
  await expect(row('ms-b')).toHaveCount(0);
  await expect(page.getByText('Deleted 1 request.')).toBeHidden({ timeout: 9000 });
  await page.reload();
  await signedIn();
  await expect(row('ms-b')).toHaveCount(0);
  await expect(row('ms-a')).toBeVisible();
});

test('context menu: a row offers its actions, Escape closes it, and Send to Repeater fills the Repeater', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await applyFilter('');
  const r = page.locator('.row', { hasText: '/hello-history' });
  await r.click({ button: 'right' });
  const menu = page.getByRole('menu', { name: 'Request actions' });
  await expect(menu).toBeVisible();
  for (const name of ['Repeater', 'URL', 'as cURL', 'Add host to scope', 'Delete']) await expect(menu.getByRole('menuitem', { name, exact: true })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(menu).toBeHidden();

  await r.click({ button: 'right' });
  await menu.getByRole('menuitem', { name: 'Repeater', exact: true }).click();
  await expect(page.getByRole('tab', { name: 'Repeater' })).toHaveAttribute('aria-selected', 'true');
  const rp = page.getByRole('tabpanel', { name: 'Repeater', exact: true });
  await expect(rp.getByLabel('Host', { exact: true })).toHaveValue('127.0.0.1');
  await expect(rp.getByLabel('Request')).toHaveValue(/GET \/hello-history/);
});

test('shortcuts: Ctrl+R sends to the Repeater without reloading, and ? lists every shortcut and any conflict', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await page.locator('.row', { hasText: '/hello-history' }).click();
  await page.evaluate(() => ((window as unknown as { __mark: number }).__mark = 1));
  await page.getByRole('listbox', { name: 'HTTP history' }).focus();
  await page.keyboard.press('Control+r');
  await expect(page.getByRole('tab', { name: 'Repeater' })).toHaveAttribute('aria-selected', 'true');
  expect(await page.evaluate(() => (window as unknown as { __mark?: number }).__mark)).toBe(1);

  await page.locator('body').click({ position: { x: 5, y: 5 } });
  await page.keyboard.press('?');
  const help = page.getByRole('dialog', { name: 'Keyboard shortcuts' });
  await expect(help).toBeVisible();
  await expect(help).toContainText('Command palette');
  await expect(help).toContainText('Send to Repeater');
  await expect(help.getByRole('heading', { name: 'Conflicts' })).toBeVisible();
  await expect(help).toContainText('None');
  await page.keyboard.press('Escape');
  await expect(help).toBeHidden();
});

test('drag and drop: dropping requests on a pane opens the Repeater there with one tab each', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await applyFilter('');
  const src = page.locator('.row', { hasText: '/hello-history' }).first();
  const target = await page.locator('#pane-flow').boundingBox();
  expect(target).toBeTruthy();
  await src.dragTo(page.locator('#pane-flow'), { targetPosition: { x: target!.width / 2, y: target!.height - 10 } });
  await expect(page.getByRole('tablist')).toHaveCount(3);
  const rp = page.getByRole('tabpanel', { name: 'Repeater', exact: true });
  await expect(rp.getByLabel('Request')).toHaveValue(/GET \/hello-history/);
});

test('deep link: the address names the open request and a reload brings it back', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await applyFilter('');
  await page.locator('.row', { hasText: '/hello-history' }).first().click();
  await expect.poll(() => page.url()).toMatch(/#history\?flow=\d+$/);
  const id = /flow=(\d+)/.exec(page.url())![1];
  await page.reload();
  await signedIn();
  await expect(page.locator('footer')).toContainText(`Request #${id}`);
  await expect(page.locator('.msg').nth(1).locator('.code')).toContainText('hello from /hello-history');
});

// ---- pop-out windows ---------------------------------------------------------------------------------------------

test('pop-out: a tab moves to its own window, follows the selection, and comes back', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
  await applyFilter('');
  // The request panel leaves the main window.
  await page.getByRole('tab', { name: 'Request / response' }).click({ button: 'right' });
  const popupPromise = page.context().waitForEvent('page');
  await page.getByRole('menuitem', { name: 'Move to a new window' }).click();
  const popup = await popupPromise;
  await popup.waitForLoadState('domcontentloaded');
  await expect(page.getByRole('tab', { name: 'Request / response' })).toHaveCount(0);

  // It is the same app, signed in through the shared session, showing only that panel.
  await expect(popup.getByRole('tab', { name: 'Request / response' })).toBeVisible();
  await expect(popup.getByRole('button', { name: 'Return to main window' })).toBeVisible();
  expect(popup.url()).toContain('#/popout/');

  // Selecting a request in the main window shows it in the pop-out (ids travel, the pop-out fetches the bodies).
  await page.locator('.row', { hasText: '/hello-history' }).first().click();
  await expect(popup.locator('.msg').nth(1).locator('.code')).toContainText('hello from /hello-history', { timeout: 10000 });

  // Return: the window closes and the panel is back in the main window.
  const closed = popup.waitForEvent('close');
  await popup.getByRole('button', { name: 'Return to main window' }).click();
  await closed;
  await expect(page.getByRole('tab', { name: 'Request / response' })).toBeVisible({ timeout: 5000 });
});

test('pop-out: closing the window by hand also brings its panel back', async () => {
  await layoutMenu('Reset layout');
  await page.getByRole('tab', { name: 'Request / response' }).click({ button: 'right' });
  const popupPromise = page.context().waitForEvent('page');
  await page.getByRole('menuitem', { name: 'Move to a new window' }).click();
  const popup = await popupPromise;
  await popup.waitForLoadState('domcontentloaded');
  await expect(page.getByRole('tab', { name: 'Request / response' })).toHaveCount(0);
  await popup.close();
  await expect(page.getByRole('tab', { name: 'Request / response' })).toBeVisible({ timeout: 8000 });
});

// ---- accessibility ----------------------------------------------------------------------------------------------

/** Structural checks that need no extra package: every control has a name, every ARIA reference resolves, no id twice. */
async function a11yIssues(): Promise<string[]> {
  return page.evaluate(() => {
    const issues: string[] = [];
    const nameOf = (el: Element): string => {
      const aria = el.getAttribute('aria-label')?.trim();
      if (aria) return aria;
      const by = el.getAttribute('aria-labelledby');
      if (by) {
        const t = by.split(/\s+/).map((id) => document.getElementById(id)?.textContent ?? '').join(' ').trim();
        if (t) return t;
      }
      if (el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement) {
        const l = el.labels ? [...el.labels].map((x) => x.textContent ?? '').join(' ').trim() : '';
        if (l) return l;
      }
      if (el instanceof HTMLImageElement) return el.alt;
      return (el.textContent ?? '').trim() || (el.getAttribute('title') ?? '').trim();
    };
    const shown = (el: Element) => !!(el as HTMLElement).offsetParent || getComputedStyle(el).position === 'fixed' || !!el.closest('dialog[open]');
    const sel = 'button, a[href], input:not([type=hidden]), select, textarea, [role=tab], [role=option], [role=menuitem], [role=menuitemradio], [role=separator][tabindex], [role=textbox], [role=combobox], [role=listbox], [role=tabpanel], [role=tablist], [role=menu], dialog[open]';
    for (const el of document.querySelectorAll(sel)) {
      if (el.closest('[hidden]') || !shown(el)) continue;
      if (!nameOf(el)) issues.push(`no accessible name: <${el.tagName.toLowerCase()} class="${el.getAttribute('class') ?? ''}" role="${el.getAttribute('role') ?? ''}">`);
    }
    const seen = new Map<string, number>();
    document.querySelectorAll('[id]').forEach((e) => seen.set(e.id, (seen.get(e.id) ?? 0) + 1));
    for (const [id, n] of seen) if (n > 1) issues.push(`duplicate id: ${id}`);
    for (const el of document.querySelectorAll('[aria-controls],[aria-labelledby],[aria-activedescendant]')) {
      for (const attr of ['aria-controls', 'aria-labelledby', 'aria-activedescendant']) {
        for (const id of (el.getAttribute(attr) ?? '').split(/\s+/).filter(Boolean)) {
          if (!document.getElementById(id)) issues.push(`${attr} points at a missing #${id} on <${el.tagName.toLowerCase()}>`);
        }
      }
    }
    for (const img of document.querySelectorAll('img')) if (!img.hasAttribute('alt')) issues.push('image without alt');
    // A focusable thing inside something aria-hidden is unreachable to a screen reader but not to the keyboard.
    for (const el of document.querySelectorAll('[aria-hidden="true"] :is(button, a[href], input, select, textarea, [tabindex="0"])')) issues.push(`focusable inside aria-hidden: <${el.tagName.toLowerCase()}>`);
    return issues;
  });
}

for (const theme of ['dark', 'light'] as const) {
  test(`accessibility (${theme}): controls have names, references resolve, dialogs and menus are labelled`, async () => {
    await page.evaluate((t) => localStorage.setItem('bosun.theme', t), theme);
    await page.reload();
    await signedIn();
    await layoutMenu('Reset layout');
    await page.getByRole('navigation').getByRole('button', { name: 'HTTP history' }).click();
    await applyFilter('host:127.0.0.1');
    await page.locator('.row', { hasText: '/hello-history' }).first().click();
    await expect(page.locator('.msg').nth(1).locator('.code')).toContainText('hello from');

    expect(await a11yIssues(), 'main view').toEqual([]);

    await page.locator('.row', { hasText: '/hello-history' }).first().click({ button: 'right' });
    await expect(page.getByRole('menu', { name: 'Request actions' })).toBeVisible();
    expect(await a11yIssues(), 'context menu').toEqual([]);
    await page.keyboard.press('Escape');

    await page.getByRole('button', { name: 'Layout' }).click();
    await expect(page.getByRole('menu', { name: 'Layout' })).toBeVisible();
    expect(await a11yIssues(), 'layout menu').toEqual([]);
    await page.keyboard.press('Escape');

    for (const [open, dialog] of [['Control+k', 'Command palette'], ['?', 'Keyboard shortcuts']] as const) {
      await page.locator('body').click({ position: { x: 3, y: 3 } });
      await page.keyboard.press(open);
      await expect(page.getByRole('dialog', { name: dialog })).toBeVisible();
      expect(await a11yIssues(), dialog).toEqual([]);
      await page.keyboard.press('Escape');
    }

    await layoutMenu('Save or manage layouts…');
    await expect(page.getByRole('dialog', { name: 'Layouts' })).toBeVisible();
    expect(await a11yIssues(), 'layouts dialog').toEqual([]);
    await page.keyboard.press('Escape');

    for (const panel of ['Intercept', 'Repeater', 'Match & replace', 'Target', 'Projects', 'Settings']) {
      await page.getByRole('navigation').getByRole('button', { name: panel }).click();
      expect(await a11yIssues(), panel).toEqual([]);
    }
    await page.evaluate(() => localStorage.removeItem('bosun.theme'));
  });
}

test('keyboard only: panes, tabs, the palette and the history list can be driven without a mouse', async () => {
  await layoutMenu('Reset layout');
  await page.locator('body').click({ position: { x: 3, y: 3 } });
  // Alt+1 puts focus on the first pane's active tab (Settings, just opened); the arrows move between its tabs.
  await page.getByRole('navigation').getByRole('button', { name: 'Settings' }).click();
  await page.keyboard.press('Alt+1');
  await expect(page.getByRole('tab', { name: 'Settings' })).toBeFocused();
  await page.keyboard.press('ArrowLeft');
  await expect(page.getByRole('tab', { name: 'HTTP history' })).toBeFocused();
  await expect(page.getByRole('tab', { name: 'HTTP history' })).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('End');
  await expect(page.getByRole('tab', { name: 'Settings' })).toBeFocused();
  await page.keyboard.press('Home');
  await expect(page.getByRole('tab', { name: 'HTTP history' })).toBeFocused();

  // The list: / focuses the filter, Escape leaves it.
  await page.getByRole('listbox', { name: 'HTTP history' }).focus();
  await page.keyboard.press('/');
  await expect(filterBox()).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(filterBox()).not.toBeFocused();

  // The palette returns focus to where it was.
  await page.getByRole('listbox', { name: 'HTTP history' }).focus();
  await page.keyboard.press('Control+k');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('listbox', { name: 'HTTP history' })).toBeFocused();

  // A menu opens from the keyboard, Escape closes it and focus comes back to its button.
  const layoutBtn = page.getByRole('button', { name: 'Layout' });
  await layoutBtn.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('menu', { name: 'Layout' })).toBeVisible();
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('menu', { name: 'Layout' })).toBeHidden();
  await expect(layoutBtn).toBeFocused();
});
