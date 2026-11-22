// End-to-end check of the main user journey in real browser engines, served from a sub-path
// the way GitHub Pages serves the project (/mailsleuth/). For every sample, the page must show
// exactly what the CLI computes in Node (score, reasons, delivery dates, attachment hashes), so
// engine differences (dates, text decoding, regex, crypto) surface as failures.
// Usage: npm run build && node scripts/e2e.mjs [chromium] [firefox] [webkit]
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import * as playwright from 'playwright';

const PORT = 4192;
const base = `http://localhost:${PORT}/mailsleuth/`;
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png' };
const server = createServer((req, res) => {
  const path = new URL(req.url, base).pathname;
  if (!path.startsWith('/mailsleuth/')) return res.writeHead(404).end();
  const file = join('dist', normalize(path.slice('/mailsleuth/'.length) || 'index.html').replace(/^(\.\.[/\\])+/, ''));
  try {
    const body = readFileSync(file);
    res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((ok) => server.listen(PORT, 'localhost', ok));

const cli = (file) => JSON.parse(execFileSync('node', ['dist-cli/mailsleuth.js', '--compact', file], { maxBuffer: 1 << 26 }).toString());
const utc = (iso) => iso.replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

/** What the page shows for the current result, in the same shape as the expectation built from the CLI. */
const shown = (page) =>
  page.evaluate(() => ({
    score: Number(document.querySelector('.score-n').textContent),
    reasons: [...document.querySelectorAll('.finding-head h3')].map((x) => x.textContent),
    hashes: [...document.querySelectorAll('.hash')].map((x) => x.textContent.replace('SHA-256 ', '')),
    dates: [...document.querySelectorAll('.hop-meta')].map((x) => x.textContent.split(',')[0]),
  }));
const expected = (a) => ({
  score: a.score,
  reasons: a.findings.map((f) => f.title),
  hashes: a.attachments.map((x) => x.sha256),
  dates: a.hops.map((h) => (h.date ? utc(h.date) : 'no readable date')),
});

const problems = [];
const check = (where, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want)) problems.push(`${where}:\n  page ${JSON.stringify(got)}\n  cli  ${JSON.stringify(want)}`);
};

const engines = process.argv.slice(2).length ? process.argv.slice(2) : ['chromium'];
try {
  for (const name of engines) {
    const browser = await playwright[name].launch();
    // Not the CLI's zone (UTC on CI): a date read as local time shows up as a mismatch.
    const page = await browser.newPage({ timezoneId: 'Asia/Kolkata' });
    page.on('console', (m) => m.type() === 'error' && problems.push(`${name} console: ${m.text()}`));
    page.on('pageerror', (e) => problems.push(`${name} pageerror: ${e.message}`));
    page.on('request', (r) => !r.url().startsWith(base) && !r.url().startsWith('data:') && problems.push(`${name} external request: ${r.url()}`));
    await page.goto(base);

    // Every bundled sample, picked from the list.
    const samples = await page.$$eval('#sample option', (o) => o.map((x) => x.value.split('/').pop()));
    if (samples.length < 7) problems.push(`${name}: only ${samples.length} samples listed`);
    for (const file of samples) {
      await page.selectOption('#sample', { value: `../../samples/${file}` });
      await page.click('#load-sample');
      await page.waitForSelector('#verdict-h');
      const want = cli(`samples/${file}`);
      check(`${name} sample ${file}`, await shown(page), expected(want));
      // A forwarded report: open the attached email from its card.
      if (want.attachments[0]?.email) {
        await page.click('text=Analyze attached email');
        await page.waitForSelector('.crumbs button');
        check(`${name} sample ${file}, attached email`, await shown(page), expected(want.attachments[0].email));
      }
      await page.click('text=Analyze another email');
    }

    // A file from disk (same code path as drag and drop), .eml and .msg.
    for (const file of ['samples/01-paypal-lookalike.eml', 'samples/07-outlook-sign-request.msg']) {
      await page.setInputFiles('#file', file);
      await page.waitForSelector('#verdict-h');
      check(`${name} file ${file}`, await shown(page), expected(cli(file)));
      await page.click('text=Analyze another email');
    }

    // The attachment itself dropped instead of the email: an error, not a "low risk" result.
    await page.setInputFiles('#file', { name: 'invoice.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.7\n1 0 obj\n<< >>\n') });
    await page.waitForSelector('#status.is-error');
    if (!(await page.textContent('#status')).includes('not an email')) problems.push(`${name}: a dropped PDF did not say "not an email"`);

    // Pasted source: headers with a zone-less Received date must not depend on the browser's time zone.
    const pasted = 'Received: from a.example by mx.b.example; Tue, 10 Nov 2026 09:00:00\nReceived: from c.example by a.example; Tue, 10 Nov 2026 09:00:00 +0530\nFrom: "IT Helpdesk" <helpdesk@gmail.com>\nSubject: Password expires today\n\nVerify your account within 24 hours.\n';
    await page.fill('#paste', pasted);
    await page.click('#analyze-paste');
    await page.waitForSelector('#verdict-h');
    check(`${name} paste`, await shown(page), expected(JSON.parse(execFileSync('node', ['dist-cli/mailsleuth.js', '--compact', '-'], { input: pasted }).toString())));

    await browser.close();
    console.log(`${name}: ${samples.length} samples (and the attached email), 2 files, 1 PDF, 1 paste checked`);
  }
} finally {
  server.close();
}

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log('ok');
