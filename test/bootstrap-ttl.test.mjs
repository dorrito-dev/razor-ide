// Tests for the bootstrap-code lifetime.
//
// Regression guard: the bootstrap code in the generated .seb start URL was
// minted with a hardcoded 30 s TTL. The code is only redeemed once Safe Exam
// Browser has started its service, Client process and CEF browser -- measured at
// ~64 s on SEB 3.10.2 -- so the first request for the exam page arrived after
// the code had expired. The audit log recorded
// `bootstrap.refused {"reason":"expired-code"}` and the candidate got a refused
// page. Single use is the real protection here, so the window has to cover SEB's
// boot; these tests pin that down.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  DEFAULT_BOOTSTRAP_TTL_MS,
  bootstrapTtlMs,
  Session,
} from '../src/security/grants.mjs';

const newSession = () =>
  new Session({ token: 'tok', grant: { examId: 'e' }, leaseMs: 60_000, graceMs: 60_000 });

test('the default TTL outlasts a measured SEB cold start (~64 s)', () => {
  // The observed margin was roughly 1.3x; require a clear one, not a hair.
  assert.ok(
    DEFAULT_BOOTSTRAP_TTL_MS >= 120_000,
    `default bootstrap TTL ${DEFAULT_BOOTSTRAP_TTL_MS} ms is too short for SEB startup`,
  );
});

test('a code minted with the default TTL is still redeemable after 64 s', () => {
  const grant = newSession();
  const code = grant.mintBootstrap(DEFAULT_BOOTSTRAP_TTL_MS, 1_000_000);

  // SEB asks for the page 64 s later; this used to be `expired-code`.
  const result = grant.consumeBootstrap(code, 1_000_000 + 64_000);
  assert.equal(result.ok, true, 'SEB must be able to redeem the start URL');
});

test('a code is single use even inside its window', () => {
  const grant = newSession();
  const code = grant.mintBootstrap(180_000, 1_000_000);

  assert.equal(grant.consumeBootstrap(code, 1_000_000 + 1_000).ok, true);
  const replay = grant.consumeBootstrap(code, 1_000_000 + 2_000);
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'already-used');
});

test('the window still closes: an expired code is refused', () => {
  const grant = newSession();
  const code = grant.mintBootstrap(180_000, 1_000_000);

  const late = grant.consumeBootstrap(code, 1_000_000 + 180_001);
  assert.equal(late.ok, false);
  assert.equal(late.reason, 'expired-code');
});

test('bootstrapTtlMs reads the operator override', () => {
  assert.equal(bootstrapTtlMs({ RAZOR_BOOTSTRAP_TTL_MS: '240000' }), 240_000);
  assert.equal(bootstrapTtlMs({}), DEFAULT_BOOTSTRAP_TTL_MS);
  assert.equal(bootstrapTtlMs(undefined), DEFAULT_BOOTSTRAP_TTL_MS);
});

test('bootstrapTtlMs clamps instead of trusting a typo', () => {
  // Garbage falls back to the default rather than producing NaN/Immortal codes.
  assert.equal(bootstrapTtlMs({ RAZOR_BOOTSTRAP_TTL_MS: 'soon' }), DEFAULT_BOOTSTRAP_TTL_MS);
  assert.equal(bootstrapTtlMs({ RAZOR_BOOTSTRAP_TTL_MS: '0' }), DEFAULT_BOOTSTRAP_TTL_MS);
  assert.equal(bootstrapTtlMs({ RAZOR_BOOTSTRAP_TTL_MS: '-5' }), DEFAULT_BOOTSTRAP_TTL_MS);
  // Below the floor nothing could ever redeem it; above the ceiling it would
  // outlive the exam itself.
  assert.equal(bootstrapTtlMs({ RAZOR_BOOTSTRAP_TTL_MS: '1000' }), 30_000);
  assert.equal(bootstrapTtlMs({ RAZOR_BOOTSTRAP_TTL_MS: '999999999' }), 3_600_000);
});
