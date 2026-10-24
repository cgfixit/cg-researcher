// Streaming answers (/query/stream, SSE). The mock model (examples/mock_llm.rs)
// sends each event as its own network write with a delay, and a
// MutationObserver records every state of the answer bubble, so these tests
// see what a user could have seen at any instant, not only the final text.
import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';

const pairUrl = () =>
  execFileSync(process.env.CG_BIN, ['--home', process.env.CG_E2E_HOME, 'ui', '--print'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

async function paired(page) {
  await page.goto(pairUrl());
  await page.waitForFunction(() => sessionStorage.getItem('cg-researcher-session'));
  await expect(page.locator('#q')).toBeVisible();
}

// Record [classes, text] of the newest bot bubble on every DOM change, and
// whether an <img> ever appeared in the log.
async function record(page) {
  await page.evaluate(() => {
    window.__frames = [];
    window.__imgs = 0;
    const log = document.getElementById('log');
    new MutationObserver(() => {
      const bots = log.querySelectorAll('.msg.bot');
      const b = bots[bots.length - 1];
      if (b) window.__frames.push([b.className, b.querySelector('.body')?.textContent ?? '']);
      window.__imgs += log.querySelectorAll('img').length;
    }).observe(log, { subtree: true, childList: true, characterData: true });
  });
}

async function ask(page, q) {
  await page.fill('#q', q);
  await page.press('#q', 'Enter');
  const bot = page.locator('.msg.bot').last();
  await expect(bot.locator('.meta')).toBeVisible({ timeout: 20_000 });
  return { bot, frames: await page.evaluate(() => window.__frames), imgs: await page.evaluate(() => window.__imgs) };
}

const streamed = (frames) => frames.filter(([c]) => c.includes('streaming')).map(([, t]) => t);

test('answers stream in as growing text, then the final answer replaces them', async ({ page }) => {
  await paired(page);
  const sent = [];
  page.on('request', (r) => sent.push(new URL(r.url()).pathname));
  await record(page);
  const { bot, frames } = await ask(page, 'DRIP what protects backups from ransomware?');
  expect(sent).toContain('/query/stream');
  expect(sent).not.toContain('/query'); // no fallback to the non-streaming call

  const s = streamed(frames);
  expect(new Set(s).size).toBeGreaterThanOrEqual(4); // several visible updates, not one
  for (let i = 1; i < s.length; i++) expect(s[i].startsWith(s[i - 1])).toBe(true); // append-only
  expect(s[0]).toMatch(/^MOCK ANSWER/); // no "Thinking…" timer text mixed in

  await expect(bot).not.toHaveClass(/streaming|pending/);
  const final = await bot.locator('.body').textContent();
  expect(final).toMatch(/^MOCK ANSWER: saw \d+ chars; attachment=False\. lorem0 .* lorem29$/);
  expect(final.startsWith(s[s.length - 1].trimEnd())).toBe(true);
});

test('secrets and exfil images are never on screen, not even mid-stream', async ({ page }) => {
  await paired(page);
  await record(page);
  const { bot, frames, imgs } = await ask(page, 'LEAK tell me the configuration');
  expect(streamed(frames).length).toBeGreaterThan(0); // it did stream
  for (const [, text] of frames) {
    // The removed image keeps its bare host by design ("[image removed: evil.example]");
    // the path and query, which carry the data, must never show.
    for (const bad of ['sk-ant-api03', 'ABCDEFGHIJ', 's3cr3tvalue', 'evil.example/', 'EXFILDATA', '](']) {
      expect(text, `"${bad}" was visible in: ${text}`).not.toContain(bad);
    }
  }
  expect(imgs).toBe(0);
  const final = await bot.locator('.body').textContent();
  expect(final).toContain('[REDACTED]');
  expect(final).toContain('[image removed: evil.example]');
  expect(final).toContain('keeps going');
});

test('a tool-call round discards provisional text and shows the tool phase', async ({ page }) => {
  await paired(page);
  await record(page);
  const { bot, frames } = await ask(page, 'TOOLCALL check the network');
  const texts = frames.map(([, t]) => t);
  const firstTools = texts.findIndex((t) => t.startsWith('Running tools'));
  expect(firstTools).toBeGreaterThan(0); // the reset event reached the UI
  expect(texts.slice(0, firstTools).some((t) => t.startsWith('Let me look'))).toBe(true); // round 1 streamed
  const final = await bot.locator('.body').textContent();
  expect(final).not.toContain('Let me look'); // round-1 text did not survive
  expect(final).toMatch(/^MOCK ANSWER/);
});
