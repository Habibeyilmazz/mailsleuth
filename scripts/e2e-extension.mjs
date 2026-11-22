// End-to-end check of the browser extension: loads dist-extension/ unpacked into Chromium and opens a
// synthetic Gmail-like page (test/fixtures/gmail/thread.html) as https://mail.google.com/mail/u/0/,
// served from localhost through Playwright routing. Real Gmail is never contacted and no account is used.
// Checks: the button appears on each message with a valid id, one click downloads exactly that message,
// the panel shows what the CLI computes (score, reasons, attachment hashes, lookup links), axe finds
// nothing in light or dark, Escape closes the panel, the popup rates a dropped-in .msg file, and the
// browser made no request anywhere but the (fake) mail.google.com.
// Usage: npm run build:cli && npm run build:extension && node scripts/e2e-extension.mjs [--screenshots]
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { resolve } from 'node:path';
import { chromium } from 'playwright';

const PORT = 4194;
const SHOTS = process.argv.includes('--screenshots');
const MESSAGES = {
  'permmsgid=msg-f:1790000000000000042': 'samples/10-voicemail-zip.eml',
  'th=18d6f5c2a4b3e001': 'samples/01-paypal-lookalike.eml',
};
const downloads = [];
const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/mail/u/0/') return res.writeHead(404).end();
  if (!url.search) return res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(readFileSync('test/fixtures/gmail/thread.html'));
  const p = url.searchParams;
  const id = p.has('permmsgid') ? `permmsgid=${p.get('permmsgid')}` : `th=${p.get('th')}`;
  downloads.push(id);
  if (p.get('view') !== 'att' || p.get('attid') !== '0' || p.get('disp') !== 'comp' || !MESSAGES[id]) return res.writeHead(404).end();
  res.writeHead(200, { 'content-type': 'message/rfc822' }).end(readFileSync(MESSAGES[id]));
});
await new Promise((ok) => server.listen(PORT, 'localhost', ok));

const AXE = readFileSync('node_modules/axe-core/axe.min.js', 'utf8');
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'];
const cli = (file) => JSON.parse(execFileSync('node', ['dist-cli/mailsleuth.js', '--compact', file], { maxBuffer: 1 << 26 }).toString());
const expected = (a) => ({ score: a.score, reasons: a.findings.map((f) => f.title), hashes: a.attachments.flatMap((x) => [x.sha256, ...x.zipHashes.map((z) => z.sha256)]) });
const shown = (frame) => frame.evaluate(() => ({
  score: Number(document.querySelector('.score-n').textContent),
  reasons: [...document.querySelectorAll('.finding-head h3')].map((x) => x.textContent),
  hashes: [...document.querySelectorAll('.hash')].map((x) => x.textContent.trim().replace('SHA-256 ', '')),
}));
const problems = [];
const check = (where, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want)) problems.push(`${where}:\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(want)}`);
};

async function audit(frame, page, where) {
  await frame.evaluate(AXE); // evaluate() is not subject to the extension page's CSP
  await frame.$$eval('details', (d) => d.forEach((x) => (x.open = true)));
  for (const colorScheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme, reducedMotion: 'reduce' }); // no colour transition mid-measurement
    const v = await frame.evaluate((tags) => window.axe.run(document, { runOnly: { type: 'tag', values: tags } }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.map((n) => n.target.join(' ')).join(', ')}`)), AXE_TAGS);
    if (v.length) problems.push(`axe on ${where} (${colorScheme}): ${v.join(', ')}`);
  }
  await page.emulateMedia({ colorScheme: 'light', reducedMotion: null });
  await frame.$$eval('details', (d) => d.forEach((x) => (x.open = false)));
}

const ext = resolve('dist-extension');
const context = await chromium.launchPersistentContext('', {
  channel: 'chromium', // extensions need the full browser, not the headless shell
  headless: !process.env.HEADED,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  viewport: { width: 1280, height: 800 },
});
const requests = [];
context.on('request', (r) => requests.push(r.url()));
await context.route('**/*', async (route) => {
  const u = new URL(route.request().url());
  if (u.protocol === 'chrome-extension:') return route.continue(); // the extension's own files
  if (u.origin !== 'https://mail.google.com') return route.abort();
  await route.fulfill({ response: await route.fetch({ url: `http://localhost:${PORT}${u.pathname}${u.search}` }) });
});

try {
  const page = await context.newPage();
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  await page.goto('https://mail.google.com/mail/u/0/#inbox/FMfcgzQXJWDsKvGbVwRrJtPSvZqhLKbN');
  const buttons = page.getByRole('button', { name: 'Check with mailsleuth' });
  await buttons.first().waitFor();
  check('buttons (two valid ids, one malformed)', await buttons.count(), 2);
  check('downloads before any click', downloads.length, 0);

  // 1. The current-style id: the voicemail with a ZIP.
  await buttons.first().click();
  const panel = page.frameLocator('iframe[title="mailsleuth result"]');
  await panel.locator('.score-n').waitFor();
  const frame = page.frames().find((f) => f.url().startsWith('chrome-extension://'));
  check('panel vs CLI, voicemail', await shown(frame), expected(cli(MESSAGES['permmsgid=msg-f:1790000000000000042'])));
  check('downloads after first click', downloads, ['permmsgid=msg-f:1790000000000000042']);
  const sha = cli(MESSAGES['permmsgid=msg-f:1790000000000000042']).attachments[0].sha256;
  check('lookup links for the attachment', await frame.$$eval('.att a.lookup', (a) => a.map((x) => x.href)), [
    `https://www.virustotal.com/gui/file/${sha}`,
    `https://bazaar.abuse.ch/browse.php?search=sha256%3A${sha}`,
  ]);
  check('focus moves to the verdict', await frame.evaluate(() => document.activeElement?.id), 'verdict-h');
  if (SHOTS) {
    await page.screenshot({ path: 'docs/screenshots/extension-gmail.png' });
    await frame.evaluate(() => document.getElementById('reasons').scrollIntoView());
    await page.screenshot({ path: 'docs/screenshots/extension-gmail-reasons.png' });
  }
  await audit(frame, page, 'Gmail panel');

  await page.keyboard.press('Escape');
  await page.locator('iframe[title="mailsleuth result"]').waitFor({ state: 'detached' });
  check('focus back on the button after Escape', await page.evaluate(() => document.activeElement?.textContent), 'Check with mailsleuth');

  // 2. The legacy hex id: the PayPal look-alike.
  await buttons.nth(1).click();
  await panel.locator('.score-n').waitFor();
  const frame2 = page.frames().find((f) => f.url().startsWith('chrome-extension://'));
  check('panel vs CLI, legacy id', await shown(frame2), expected(cli(MESSAGES['th=18d6f5c2a4b3e001'])));
  check('one download per click', downloads.length, 2);
  const extId = new URL(frame2.url()).host;

  // 3. The toolbar popup with an Outlook .msg file.
  const popup = await context.newPage();
  popup.on('pageerror', (e) => problems.push(`popup error: ${e.message}`));
  await popup.setViewportSize({ width: 440, height: 600 });
  await popup.goto(`chrome-extension://${extId}/panel.html?popup`);
  await audit(popup.mainFrame(), popup, 'popup start');
  await popup.setInputFiles('#file', 'samples/07-outlook-sign-request.msg');
  await popup.locator('.score-n').waitFor();
  check('popup vs CLI, .msg', await shown(popup.mainFrame()), expected(cli('samples/07-outlook-sign-request.msg')));
  if (SHOTS) await popup.screenshot({ path: 'docs/screenshots/extension-popup.png' });
  await audit(popup.mainFrame(), popup, 'popup result');

  const elsewhere = requests.filter((u) => !u.startsWith('https://mail.google.com/') && !u.startsWith(`chrome-extension://${extId}/`));
  check('requests to anywhere but mail.google.com', elsewhere, []);
} finally {
  await context.close();
  server.close();
}

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`extension: button on 2 of 3 messages, ${downloads.length} downloads, panel matches the CLI for 2 messages and the popup for a .msg; axe clean; no other requests\nok`);
