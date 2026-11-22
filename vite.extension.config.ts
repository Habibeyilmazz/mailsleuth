import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { defineConfig, type Plugin } from 'vite';
import { makeZip } from './scripts/zip.ts';

// Builds the browser extension into dist-extension/ (load it unpacked) and zips it twice:
// mailsleuth-extension-chrome.zip, and mailsleuth-extension-firefox.zip whose manifest adds Firefox's settings.
const OUT = resolve('dist-extension');

const files = (dir: string): string[] =>
  readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? files(join(dir, n)) : [join(dir, n)]));

const zipIt = (name: string, manifest: object) => {
  const entries = files(OUT).map((f) => {
    const rel = relative(OUT, f).split('\\').join('/');
    const data = rel === 'manifest.json' ? new TextEncoder().encode(JSON.stringify(manifest, null, 2)) : new Uint8Array(readFileSync(f));
    return { name: rel, data, deflated: new Uint8Array(deflateRawSync(data)) };
  });
  writeFileSync(name, makeZip(entries));
};

const pack: Plugin = {
  name: 'mailsleuth-extension-pack',
  apply: 'build',
  closeBundle() {
    // A content script cannot be an ES module: fail the build rather than ship one that silently does nothing.
    if (/^\s*(import|export)\b/m.test(readFileSync(join(OUT, 'content.js'), 'utf8'))) throw new Error('content.js must be a plain script');
    const manifest = JSON.parse(readFileSync(join(OUT, 'manifest.json'), 'utf8'));
    zipIt('mailsleuth-extension-chrome.zip', manifest);
    zipIt('mailsleuth-extension-firefox.zip', {
      ...manifest,
      browser_specific_settings: { gecko: { id: 'mailsleuth@habibeyilmazz.github.io', strict_min_version: '128.0', data_collection_permissions: { required: ['none'] } } },
    });
  },
};

export default defineConfig({
  root: 'extension',
  base: './',
  publicDir: 'public',
  plugins: [pack],
  build: {
    outDir: OUT,
    emptyOutDir: true,
    modulePreload: false, // the polyfill is an inline script, which the extension's CSP forbids
    rollupOptions: {
      input: { panel: resolve('extension/panel.html'), content: resolve('src/extension/content.ts') },
      output: { entryFileNames: (c) => (c.name === 'content' ? 'content.js' : 'assets/[name]-[hash].js') },
    },
  },
});
