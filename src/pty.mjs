// Loads node-pty, and never throws while doing it.
//
// Why this module exists: nothing in the source ever loaded the PTY module, yet
// TerminalSession.start() requires one. The only caller passed `{ policy }` with
// no ptyModule, so `ptyModule.spawn(...)` dereferenced undefined and threw
// *inside a WebSocket upgrade callback* -- an uncaught exception that killed the
// whole IDE the moment the browser opened a terminal. Observed live: opening
// Razor inside Safe Exam Browser crashed the server ~0.3 s after the page
// loaded, which also ended the SEB kiosk early.
//
// Two lessons are encoded here:
//   1. the module has to be loaded somewhere, and loading is fallible on a
//      machine without a matching node-pty prebuild;
//   2. the failure has to be a value the caller can report, not an exception in
//      a callback where nothing can catch it.
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let cached = null;

/**
 * @returns {{ ok: true, pty: object } | { ok: false, reason: string, detail: string }}
 */
export function loadPtyModule() {
  if (cached) return cached;

  try {
    const pty = require('node-pty');
    if (!pty || typeof pty.spawn !== 'function') {
      cached = {
        ok: false,
        reason: 'pty-unavailable',
        detail: 'node-pty loaded but exposes no spawn()',
      };
      return cached;
    }
    cached = { ok: true, pty };
  } catch (err) {
    cached = {
      ok: false,
      reason: 'pty-load-failed',
      detail:
        `${err?.message ?? err}. The integrated terminal needs the node-pty native ` +
        `module for ${process.platform}-${process.arch}; re-run "npm install" (or ` +
        `"npm rebuild node-pty") on the exam image, then verify with ` +
        `"node scripts/verify-pty.mjs".`,
    };
  }

  return cached;
}

/** Test seam: forget the cached load result. */
export function resetPtyModuleCache() {
  cached = null;
}
