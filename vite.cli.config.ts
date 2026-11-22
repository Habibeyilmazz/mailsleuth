import { defineConfig } from 'vite';

// Bundles the shared core + CLI entry into one Node ESM file.
export default defineConfig({
  publicDir: false, // the web app's favicon does not belong next to the CLI
  build: {
    ssr: 'src/cli.ts',
    outDir: 'dist-cli',
    emptyOutDir: true,
    target: 'node20',
    rollupOptions: {
      output: { entryFileNames: 'mailsleuth.js', banner: '#!/usr/bin/env node' },
    },
  },
});
