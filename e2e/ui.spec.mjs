import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';

// A fresh single-use pairing URL from the CLI, exactly as a user gets it.
const pairUrl = () =>
  execFileSync(process.env.CG_BIN, ['--home', process.env.CG_E2E_HOME, 'ui', '--print'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

// Fail on uncaught page errors and console errors. WebKit logs one CSP line
// per <select> for its own user-agent styles; that is the browser, not us.
function watch(page, browserName) {
  const problems = [];
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    if (browserName === 'webkit' && /Content Security Policy/.test(m.text())) return;
    problems.push('console: ' + m.text());
  });
  return problems;
}

async function paired(page) {
  await page.goto(pairUrl());
  await expect(page.locator('#q')).toBeVisible();
}

test('pairing scrubs the code from the URL and serves strict headers', async ({ page, browserName }) => {
  const problems = watch(page, browserName);
  const res = await page.goto(pairUrl());
  const h = res.headers();
  expect(h['content-security-policy']).toContain("default-src 'none'");
  expect(h['x-content-type-options']).toBe('nosniff');
  await expect(page.locator('#q')).toBeVisible();
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(() => history.length >= 1 && !location.href.includes('#p='))).toBe(true);
  expect(problems).toEqual([]);
});

test('chat round trip renders the answer, route meta and copy button', async ({ page, browserName }) => {
  const problems = watch(page, browserName);
  await paired(page);
  await page.fill('#q', 'what protects backups from ransomware?');
  await page.press('#q', 'Enter');
  const bot = page.locator('.msg.bot').last();
  await expect(bot.locator('.body')).toContainText('MOCK ANSWER');
  await expect(bot.locator('.meta')).toBeVisible();
  await expect(bot.locator('.actions button')).toBeVisible();
  expect(problems).toEqual([]);
});

test('a second Enter while busy does not send twice', async ({ page }) => {
  await paired(page);
  const sent = [];
  page.on('request', (r) => { if (new URL(r.url()).pathname.startsWith('/query')) sent.push(r.url()); });
  await page.fill('#q', 'SLOW what protects backups from ransomware?');
  await page.press('#q', 'Enter');
  await expect(page.locator('#chatForm button[type=submit]')).toBeDisabled();
  await page.fill('#q', 'SLOW second');
  await page.press('#q', 'Enter');
  await expect(page.locator('.msg.bot .meta').first()).toBeVisible({ timeout: 15_000 });
  expect(sent.length).toBe(1);
  await expect(page.locator('#q')).toHaveValue('SLOW second'); // kept for the user, not dropped
});

test('markdown attachment reaches the model', async ({ page }) => {
  await paired(page);
  await page.setInputFiles('#files', { name: 'note.md', mimeType: 'text/markdown', buffer: Buffer.from('# hi\nATTACH-OK\n') });
  await page.fill('#q', 'summarise the attachment');
  await page.press('#q', 'Enter');
  await expect(page.locator('.msg.bot .body').last()).toContainText('attachment=True');
});

test('an invalid session locks the UI instead of half-working', async ({ page }) => {
  await paired(page);
  await page.evaluate(() => {
    for (const k of Object.keys(sessionStorage)) sessionStorage.setItem(k, 'bogus');
  });
  await page.click('[data-tab=status]');
  await expect(page.locator('#locked')).toBeVisible();
});

test('mobile layout has no horizontal overflow', async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  await paired(page);
  // On failure, name the boxes that cross the right edge; "5px over" alone is
  // not debuggable from a CI log.
  const { over, culprits } = await page.evaluate(() => {
    const iw = window.innerWidth;
    const culprits = [];
    for (const el of document.querySelectorAll('body *')) {
      if (el.closest('[hidden]')) continue;
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.right > iw) culprits.push(`${el.tagName.toLowerCase()}#${el.id}.${el.className} right=${Math.round(r.right)} w=${Math.round(r.width)}`);
    }
    return { over: document.documentElement.scrollWidth - iw, culprits };
  });
  expect(over, culprits.join('\n')).toBeLessThanOrEqual(0);
  await expect(page.locator('.tabs')).toBeVisible();
  await ctx.close();
});
