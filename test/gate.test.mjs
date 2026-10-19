// Tests for the signed-grant / lease gate.
//
// These cover the properties the whole design rests on:
//   * production ignores every bypass flag,
//   * a grant is single-use (replay is refused),
//   * an expired grant is refused,
//   * a grant for another machine or exam is refused,
//   * a tampered grant is refused,
//   * the lease locks the session when renewals stop.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SessionGate, GateState } from '../src/security/gate.mjs';
import { issueGrant, verifyGrant, GrantError, Session } from '../src/security/grants.mjs';

const KEY = 'a'.repeat(64);
const MACHINE = 'exam-pc/student';

function makeGate({ mode = 'production', bypassGate = false } = {}) {
  const records = [];
  const gate = new SessionGate({
    env: { mode, bypassGate },
    key: KEY,
    machineId: MACHINE,
    audit: { record: (kind, detail) => records.push({ kind, ...detail }) },
  });
  return { gate, records };
}

function grantFor(overrides = {}) {
  return issueGrant({
    key: KEY,
    examId: 'exam-1',
    machineId: MACHINE,
    issuedBy: 'test',
    sebQuitPassword: 'secret-per-session',
    ...overrides,
  });
}

test('a valid grant starts a session', () => {
  const { gate } = makeGate();
  assert.equal(gate.state, GateState.AWAITING_ADMIN);

  const result = gate.applyGrant(grantFor(), { source: 'test' });
  assert.equal(result.ok, true);
  assert.equal(gate.state, GateState.RUNNING);
  assert.match(gate.session.token, /^[0-9a-f]{64}$/);
  assert.equal(gate.session.grant.sebQuitPassword, 'secret-per-session');
});

test('no grant means no session (the core invariant)', () => {
  const { gate } = makeGate();
  assert.equal(gate.session, null);
  assert.equal(gate.tokenMatches('anything'), false);
});

test('production refuses the bypass flag and logs it', () => {
  const { gate, records } = makeGate({ mode: 'production', bypassGate: true });
  const result = gate.devStart('cli-flag');

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'production-refuses-bypass');
  assert.equal(gate.state, GateState.AWAITING_ADMIN);
  assert.equal(gate.session, null);
  assert.ok(records.some((r) => r.kind === 'bypass.refused' && r.reason === 'production'));
});

test('dev allows the bypass flag', () => {
  const { gate } = makeGate({ mode: 'dev', bypassGate: true });
  const result = gate.devStart('cli-flag');

  assert.equal(result.ok, true);
  assert.equal(gate.state, GateState.RUNNING);
});

test('dev without the flag still refuses', () => {
  const { gate } = makeGate({ mode: 'dev', bypassGate: false });
  const result = gate.devStart('cli-flag');

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'bypass-flag-not-set');
});

test('a replayed grant is refused', () => {
  const { gate } = makeGate();
  const grant = grantFor();

  assert.equal(gate.applyGrant(grant, { source: 'first' }).ok, true);
  // Same process, same nonce -> replay guard fires on the *verify* path.
  const nonces = new Set();
  assert.doesNotThrow(() => verifyGrant({ key: KEY, grant, machineId: MACHINE, usedNonces: nonces }));
  assert.throws(
    () => verifyGrant({ key: KEY, grant, machineId: MACHINE, usedNonces: nonces }),
    (err) => err instanceof GrantError && err.reason === 'replayed',
  );
});

test('an expired grant is refused', () => {
  const { gate } = makeGate();
  const grant = grantFor({ ttlMs: 1_000, now: Date.now() - 120_000 });
  const result = gate.applyGrant(grant, { source: 'test' });

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'expired');
  assert.equal(gate.state, GateState.AWAITING_ADMIN);
});

test('a grant for another machine is refused', () => {
  const { gate } = makeGate();
  const result = gate.applyGrant(grantFor({ machineId: 'other-pc/attacker' }), { source: 'test' });

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'wrong-machine');
});

test('a grant signed with a different key is refused', () => {
  const { gate } = makeGate();
  const forged = issueGrant({
    key: 'b'.repeat(64),
    examId: 'exam-1',
    machineId: MACHINE,
    issuedBy: 'attacker',
  });
  const result = gate.applyGrant(forged, { source: 'test' });

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'bad-signature');
});

test('tampering with a signed field is refused', () => {
  const { gate } = makeGate();
  const grant = grantFor();
  grant.sebQuitPassword = 'attacker-chosen';
  const result = gate.applyGrant(grant, { source: 'test' });

  assert.equal(result.ok, false);
  assert.equal(result.reason, 'bad-signature');
});

test('the lease locks the session after the grace window when renewals stop', () => {
  const session = new Session({
    token: 'x'.repeat(64),
    grant: { examId: 'e', sebQuitPassword: null },
    leaseMs: 1_000,
    graceMs: 2_000,
    now: 0,
  });

  assert.equal(session.state(0), 'live');
  assert.equal(session.state(1_500), 'grace');
  assert.equal(session.state(4_000), 'locked');
  assert.equal(session.isUsable(1_500), true);
  assert.equal(session.isUsable(4_000), false);

  // A successful round trip moves the window forward.
  session.renew(1_500);
  assert.equal(session.state(2_400), 'live');
});

test('stopping a session locks the gate and revokes the token', () => {
  const { gate } = makeGate();
  gate.applyGrant(grantFor(), { source: 'test' });
  const token = gate.session.token;

  const result = gate.stopSession('admin-stop');
  assert.equal(result.ok, true);
  assert.equal(gate.state, GateState.LOCKED);
  assert.equal(gate.lockReason, 'admin-stop');
  // The revoked token must not keep working.
  assert.equal(gate.tokenMatches(token), false);
});

test('bootstrap codes are single use', () => {
  const { gate } = makeGate();
  gate.applyGrant(grantFor(), { source: 'test' });

  const code = gate.session.mintBootstrap();
  assert.equal(gate.session.consumeBootstrap(code).ok, true);
  const second = gate.session.consumeBootstrap(code);
  assert.equal(second.ok, false);
  assert.equal(second.reason, 'already-used');
});

test('an expired bootstrap code is refused', () => {
  const { gate } = makeGate();
  gate.applyGrant(grantFor(), { source: 'test' });

  const code = gate.session.mintBootstrap(1_000, 0);
  const result = gate.session.consumeBootstrap(code, 5_000);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'expired-code');
});

test('an unknown bootstrap code is refused', () => {
  const { gate } = makeGate();
  gate.applyGrant(grantFor(), { source: 'test' });
  assert.equal(gate.session.consumeBootstrap('nope').reason, 'unknown-code');
});

test('renewing while running extends the lease instead of restarting', () => {
  const { gate } = makeGate();
  const grant = grantFor();
  gate.applyGrant(grant, { source: 'first' });
  const firstToken = gate.session.token;
  const startedAt = gate.session.startedAt;

  const result = gate.applyGrant(grant, { source: 'renew' });
  assert.equal(result.ok, true);
  assert.equal(result.renewed, true);
  // Same session object: renewals must never mint a second token.
  assert.equal(gate.session.token, firstToken);
  assert.equal(gate.session.startedAt, startedAt);
});
