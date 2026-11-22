import { defineConfig } from 'vite';

// Bundles the shared core + CLI entry into one Node ESM file.
export default defineConfig({
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
