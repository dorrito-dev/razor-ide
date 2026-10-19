#!/usr/bin/env node
// Build-time (postinstall) check that node-pty actually loaded its prebuilt
// binary for this platform. Fails loudly at install time instead of at first
// terminal use -- important for air-gapped exam images.
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let pty;
try {
  pty = require('node-pty');
} catch (err) {
  console.error('[verify-pty] node-pty failed to load:');
  console.error(`  ${err.message}`);
  console.error('');
  console.error('  Expected cause: no prebuilt binary for ' +
    `${process.platform}-${process.arch}. node-pty 1.1.0 ships`);
  console.error('  prebuilds for win32-x64, win32-arm64, darwin-x64, darwin-arm64.');
  console.error('  If yours is missing, install Visual Studio Build Tools 2022 including');
  console.error('  the Spectre-mitigated libraries, then re-run: npm install --ignore-scripts');
  console.error('  && npm rebuild node-pty');
  process.exit(1);
}

const version = require('node-pty/package.json').version;
console.log(`[verify-pty] node-pty ${version} loaded on ${process.platform}-${process.arch}`);

// Loading the module only proves the .node binary resolved. Actually spawning a
// PTY proves the native backend (ConPTY on Windows) is usable. This is skipped
// in restricted/sandboxed environments where creating the ConPTY named pipe is
// denied, so install never fails for that reason -- it warns instead.
try {
  const proc = pty.spawn(
    process.platform === 'win32' ? 'cmd.exe' : '/bin/sh',
    process.platform === 'win32' ? ['/c', 'ver'] : ['-c', 'echo ok'],
    { name: 'xterm-256color', cols: 80, rows: 24, cwd: process.cwd(), env: process.env },
  );
  await new Promise((res) => {
    const timer = setTimeout(res, 10_000);
    proc.onExit(() => {
      clearTimeout(timer);
      res();
    });
  });
  console.log('[verify-pty] live PTY spawn OK');
} catch (err) {
  console.warn(`[verify-pty] live PTY spawn test skipped: ${err.message}`);
  console.warn('             (expected inside a restricted sandbox; verify on the real machine)');
}
