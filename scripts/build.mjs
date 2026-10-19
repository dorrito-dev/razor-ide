#!/usr/bin/env node
// Bundles the browser UI into src/web/vendor so the IDE runs fully offline
// (no CDN) -- required because Safe Exam Browser blocks network access.
import { build } from 'esbuild';
import { mkdir, cp } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const vendor = resolve(root, 'src/web/vendor');

await mkdir(vendor, { recursive: true });

const result = await build({
  entryPoints: [resolve(root, 'src/web/app.js')],
  bundle: true,
  format: 'iife',
  target: ['chrome110'],
  minify: true,
  // Sourcemaps are large; enable locally with RAZOR_UI_SOURCEMAP=1 when debugging.\n  sourcemap: process.env.RAZOR_UI_SOURCEMAP === '1',
  outfile: resolve(vendor, 'app.js'),
  logLevel: 'info',
  metafile: true,
});

// xterm's stylesheet must ship locally too.
await cp(
  resolve(root, 'node_modules/@xterm/xterm/css/xterm.css'),
  resolve(vendor, 'xterm.css'),
);

// The shell stylesheet lives next to the HTML for editing convenience but is
// served from /vendor/ with everything else, so there is one static path.
await cp(resolve(root, 'src/web/style.css'), resolve(vendor, 'app.css'));

let bytes = 0;
for (const [file, meta] of Object.entries(result.metafile.outputs)) {
  bytes += meta.bytes;
  console.log(`  ${file}  ${(meta.bytes / 1024).toFixed(1)} kB`);
}
console.log(`UI bundle written to ${vendor} (${(bytes / 1024).toFixed(1)} kB total)`);
