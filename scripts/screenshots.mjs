// Drives the built app in Chromium: runs every sample, fails on console errors or on any
// request that leaves localhost, and saves screenshots.
// Usage: npm run build && npm run screenshots -- [outDir]   (needs Playwright's Chromium)
import { mkdirSync, readFileSync } from 'node:fs';
import { chromium } from 'playwright';
import { preview } from 'vite';

const outDir = process.argv[2] ?? 'test-results/screenshots';
mkdirSync(outDir, { recursive: true });

const server = await preview({ preview: { port: 4191, strictPort: true } });
const base = 'http://localhost:4191/';
const browser = await chromium.launch();
const problems = [];

async function newPage(options) {
  const page = await browser.newPage(options);
  page.on('console', (m) => m.type() === 'error' && problems.push(`console: ${m.text()}`));
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  page.on('request', (r) => !r.url().startsWith(base) && !r.url().startsWith('data:') && problems.push(`external request: ${r.url()}`));
  await page.goto(base);
  return page;
}

async function runSample(page, file) {
  await page.selectOption('#sample', { value: `../../samples/${file}` });
  await page.click('#load-sample');
  await page.waitForSelector('#verdict-h');
}

try {
  const page = await newPage({ viewport: { width: 1280, height: 860 }, colorScheme: 'light' });
  await page.screenshot({ path: `${outDir}/home.png` });

  // Empty paste: an error the user can see, focus back in the box.
  await page.click('#analyze-paste');
  if (!(await page.isVisible('#status.is-error'))) problems.push('empty paste: no visible error');
  if ((await page.evaluate(() => document.activeElement?.id)) !== 'paste') problems.push('empty paste: focus not moved to the paste box');

  const samples = await page.$$eval('#sample option', (o) => o.map((x) => x.value.split('/').pop()));
  for (const file of samples) {
    await runSample(page, file);
    const level = await page.textContent('#verdict-h');
    console.log(`${file}: ${level}, score ${await page.textContent('.score-n')}`);
    await page.screenshot({ path: `${outDir}/${file.replace(/\.(eml|msg)$/, '')}.png`, fullPage: true });
    if (file.startsWith('01-')) await page.screenshot({ path: `${outDir}/result.png` });
    // The sticky verdict column can be taller than the window: its last step must be reachable by keyboard.
    await page.evaluate(() => window.scrollTo(0, 1200));
    await page.keyboard.press('Shift+Tab'); // from the focused verdict heading to its scrollable column
    if (!(await page.evaluate(() => document.activeElement?.classList.contains('col-verdict')))) problems.push(`${file}: verdict column not keyboard-focusable`);
    const tall = await page.evaluate(() => { const c = document.querySelector('.col-verdict'); return c.scrollHeight > c.clientHeight; });
    await page.keyboard.press('End');
    await page.waitForTimeout(400); // keyboard scrolling is smooth
    if (tall && (await page.evaluate(() => window.scrollY)) !== 1200) problems.push(`${file}: End scrolled the page, not the verdict column`);
    const hidden = await page.evaluate(() => document.querySelector('.steps li:last-child').getBoundingClientRect().bottom - window.innerHeight);
    if (hidden > 0) problems.push(`${file}: last next step hidden ${Math.round(hidden)}px below the window`);
    await page.click('text=Analyze another email');
  }

  // Forwarded report: open the inner email from the attachment card.
  await runSample(page, '06-user-report-forwarded.eml');
  await page.click('text=Analyze attached email');
  await page.waitForSelector('.crumbs button');
  console.log(`inner email: ${await page.textContent('#verdict-h')}`);
  await page.screenshot({ path: `${outDir}/nested.png`, fullPage: true });

  // Paste path: headers only, submitted from the keyboard.
  await page.click('text=Analyze another email');
  await page.fill('#paste', 'From: "IT Helpdesk" <helpdesk@gmail.com>\nSubject: Password expires today\nTo: you@example.net\n\n');
  await page.press('#paste', 'Control+Enter');
  await page.waitForSelector('#verdict-h');
  console.log(`pasted: ${await page.textContent('#verdict-h')}`);

  // Paste path: body text only, no headers.
  await page.click('text=Analyze another email');
  await page.fill('#paste', 'Dear customer,\nverify your account within 24 hours: https://paypa1-login.example/\n');
  await page.click('#analyze-paste');
  await page.waitForSelector('#verdict-h');
  if (!(await page.isVisible('text=No email headers found'))) problems.push('body-only paste: missing "No email headers found" note');
  console.log(`pasted body only: ${await page.textContent('#verdict-h')}, ${await page.textContent('.score-n')}`);

  // Bidi controls from the email are shown as markers, never obeyed: "photo\u202Egpj.exe" must not display as "photoexe.jpg".
  await page.click('text=Analyze another email');
  await page.fill('#paste', 'From: a@b.example\nSubject: Holiday \u202Egpj.exe\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: application/octet-stream; name="photo\u202Egpj.exe"\n\nMZ\n--x--\n');
  await page.click('#analyze-paste');
  await page.waitForSelector('#verdict-h');
  const shownText = await page.textContent('#results');
  if (shownText.includes('\u202E') || !shownText.includes('photo⟨U+202E⟩gpj.exe')) problems.push('bidi control in an attachment name reached the page unescaped');

  // File picker path (same code path as drag and drop).
  await page.click('text=Analyze another email');
  await page.setInputFiles('#file', 'samples/02-invoice-macro.eml');
  await page.waitForSelector('#verdict-h');
  console.log(`file input: ${await page.textContent('#verdict-h')}, ${await page.textContent('.score-n')}`);

  // Outlook .msg through the file picker; a damaged one gets a readable error, not a blank result.
  await page.click('text=Analyze another email');
  await page.setInputFiles('#file', 'samples/07-outlook-sign-request.msg');
  await page.waitForSelector('#verdict-h');
  if (!(await page.isVisible('text=Read from an Outlook .msg file'))) problems.push('.msg file input: missing "Read from an Outlook .msg file" note');
  console.log(`.msg file input: ${await page.textContent('#verdict-h')}, ${await page.textContent('.score-n')}`);
  await page.click('text=Analyze another email');
  const msgBytes = readFileSync('samples/07-outlook-sign-request.msg');
  await page.setInputFiles('#file', { name: 'broken.msg', mimeType: 'application/vnd.ms-outlook', buffer: msgBytes.subarray(0, 1000) });
  await page.waitForSelector('#status.is-error');
  const brokenMsg = await page.textContent('#status');
  if (!brokenMsg.includes('damaged')) problems.push(`damaged .msg: unexpected message "${brokenMsg}"`);
  console.log(`damaged .msg: ${brokenMsg}`);

  // A slow file read must not replace a newer analysis; a failed read must say so.
  const race = await newPage({ viewport: { width: 1280, height: 860 } });
  await race.evaluate(() => {
    const real = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function () {
      if (this.name.includes('invoice')) return new Promise((ok) => setTimeout(() => ok(real.call(this)), 800));
      return Promise.reject(new Error('NotReadableError'));
    };
  });
  await race.setInputFiles('#file', 'samples/02-invoice-macro.eml');
  await runSample(race, '03-newsletter-legit.eml');
  await race.waitForTimeout(1200);
  if ((await race.textContent('.crumbs')) !== '03-newsletter-legit.eml') problems.push('slow file read replaced a newer analysis');
  await race.click('text=Analyze another email');
  await race.setInputFiles('#file', 'samples/01-paypal-lookalike.eml');
  await race.waitForSelector('#status.is-error');
  console.log(`unreadable file: ${await race.textContent('#status')}`);

  const mobile = await newPage({ viewport: { width: 390, height: 844 }, colorScheme: 'dark', isMobile: true, hasTouch: true });
  await mobile.screenshot({ path: `${outDir}/mobile-home-dark.png` });
  for (const file of samples) {
    await runSample(mobile, file);
    const overflow = await mobile.evaluate(() => document.documentElement.scrollWidth - screen.width);
    if (overflow > 0) problems.push(`mobile ${file}: page scrolls horizontally by ${overflow}px`);
    await mobile.click('text=Analyze another email');
  }
  await runSample(mobile, '01-paypal-lookalike.eml');
  await mobile.screenshot({ path: `${outDir}/mobile-result-dark.png` });
} finally {
  await browser.close();
  await server.close();
}

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`ok, screenshots in ${outDir}`);
