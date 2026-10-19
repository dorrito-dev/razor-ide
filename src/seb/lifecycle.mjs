// SEB exit policy, extracted from the entry point so it can be unit-tested.
//
// This lived inline in main.mjs and took its dependencies from positional
// arguments. SebController calls it with a context object, so the positional
// signature silently produced `audit === undefined` and the first SEB exit threw
// `TypeError: Cannot read properties of undefined (reading 'record')` inside an
// uncaught exception handler -- taking the whole IDE down *after* SEB had
// already closed, which is the worst possible moment (no clean shutdown, no
// audit record). Keeping it here with a named context object and a test that
// exercises it is what stops that from coming back.
import { isProduction, logger } from '../config.mjs';

const log = logger('seb');

/**
 * Build the handler invoked when the SEB process exits.
 *
 * @param {{ env: object, gate: object, audit: object }} context
 * @returns {(info: { code?: number|null, signal?: string|null, reason?: string }) => void}
 */
export function createSebExitHandler({ env, gate, audit } = {}) {
  return function handleSebExit(info = {}) {
    audit?.record?.('seb.exited', {
      code: info.code ?? null,
      signal: info.signal ?? null,
      reason: info.reason ?? 'process-exit',
    });

    // Production: the session ends. A candidate who kills SEB does not get to
    // keep working in a plain browser. Dev: log it and let the operator go on.
    // `env ?? {}` matters: isProduction() dereferences env.mode, and this code
    // runs inside an exit callback where a throw is unrecoverable.
    if (isProduction(env ?? {})) {
      log.warn('SEB exited: ending the session');
      gate?.stopSession?.('seb-exited');
    }
  };
}
