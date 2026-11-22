// Records the README demo: the built app analyzing a synthetic sample, saved as docs/demo.gif.
// Usage: npm run build && node scripts/demo.mjs   (needs Playwright's Chromium and ffmpeg on PATH)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright';
import { preview } from 'vite';

const size = { width: 1100, height: 720 };
const videoDir = mkdtempSync(join(tmpdir(), 'mailsleuth-demo-'));
const server = await preview({ preview: { port: 4192, strictPort: true } });
const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: size, colorScheme: 'light', recordVideo: { dir: videoDir, size } });
  const page = await context.newPage();
  await page.goto('http://localhost:4192/');
  await page.waitForTimeout(1200);
  await page.selectOption('#sample', { value: '../../samples/05-parcel-redelivery.eml' });
  await page.waitForTimeout(600);
  await page.click('#load-sample');
  await page.waitForSelector('#verdict-h');
  await page.waitForTimeout(2200);
  for (let i = 0; i < 14; i++) {
    await page.mouse.move(800, 400);
    await page.mouse.wheel(0, 180);
    await page.waitForTimeout(260);
  }
  await page.waitForTimeout(1500);
  const video = page.video();
  await context.close();
  const webm = await video.path();
  // Two-pass palette keeps the GIF small and the text crisp.
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', webm, '-vf',
    'fps=8,scale=880:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle',
    'docs/demo.gif']);
  console.log('wrote docs/demo.gif');
} finally {
  await browser.close();
  await server.close();
  rmSync(videoDir, { recursive: true, force: true });
}
