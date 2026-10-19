// Tests for the SEB exit policy.
//
// Regression guard: this handler used to be defined inline in main.mjs with a
// positional signature ({env, gate, audit}) while SebController invoked it with
// a context object. That mismatch made `audit` undefined and the first SEB exit
// threw `TypeError: Cannot read properties of undefined (reading 'record')`
// inside an uncaught exception handler, crashing Razor the moment SEB closed
// and skipping the whole clean-shutdown path.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSebExitHandler } from '../src/seb/lifecycle.mjs';

function harness({ mode = 'dev' } = {}) {
  const audit = { entries: [], record(kind, detail) { this.entries.push({ kind, detail }); } };
  const gate = { stops: [], stopSession(reason) { this.stops.push(reason); } };
  return { audit, gate, env: { mode } };
}

test('the exit handler records an audit entry and never throws', () => {
  const { audit, gate, env } = harness({ mode: 'dev' });
  const handle = createSebExitHandler({ env, gate, audit });

  assert.doesNotThrow(() => handle({ code: 0, signal: null }));
  assert.equal(audit.entries.length, 1);
  assert.equal(audit.entries[0].kind, 'seb.exited');
  assert.equal(audit.entries[0].detail.code, 0);
  assert.equal(audit.entries[0].detail.reason, 'process-exit');
});

test('dev mode: a SEB exit does not end the session', () => {
  const { audit, gate, env } = harness({ mode: 'dev' });
  createSebExitHandler({ env, gate, audit })({ code: 1, signal: null });

  assert.deepEqual(gate.stops, [], 'dev lets the operator keep working');
  assert.equal(audit.entries[0].detail.code, 1);
});

test('production mode: a SEB exit ends the session', () => {
  const { audit, gate, env } = harness({ mode: 'production' });
  createSebExitHandler({ env, gate, audit })({ code: 0, signal: null, reason: 'error' });

  assert.deepEqual(gate.stops, ['seb-exited']);
  assert.equal(audit.entries[0].detail.reason, 'error');
});

test('the handler is defensive: no context, no info, no throw', () => {
  assert.doesNotThrow(() => createSebExitHandler()());
  assert.doesNotThrow(() => createSebExitHandler({})({}));
  assert.doesNotThrow(() => createSebExitHandler({ env: { mode: 'production' } })({}));
});

test('the handler tolerates a partial info object', () => {
  const { audit, gate, env } = harness();
  createSebExitHandler({ env, gate, audit })({ signal: 'SIGTERM' });

  assert.equal(audit.entries[0].detail.signal, 'SIGTERM');
  assert.equal(audit.entries[0].detail.code, null);
  assert.equal(audit.entries[0].detail.reason, 'process-exit');
});
