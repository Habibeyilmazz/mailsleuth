import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

// The built page declares, and the browser enforces, that it cannot talk to any server.
// Dev mode skips this because Vite's hot reload needs a websocket.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'none'",
  "form-action 'none'",
  "base-uri 'none'",
].join('; ');

const csp: Plugin = {
  name: 'mailsleuth-csp',
  apply: 'build',
  transformIndexHtml: (html) => html.replace('<meta charset="utf-8" />', `<meta charset="utf-8" />\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`),
};

export default defineConfig({
  base: './',
  plugins: [csp],
  assetsInclude: ['**/*.msg'], // lets the .msg sample be imported with ?inline
  server: { port: 4190, strictPort: true },
  preview: { port: 4191, strictPort: true },
  test: { include: ['test/**/*.test.ts'] },
});
