// Signed session grants and leases -- the "only an admin starts the session"
// boundary.
//
// Threat model this file is built against:
//   * The candidate controls the machine, the filesystem, and every process
//     running as their own account. They must NOT be able to *conjure* a
//     session start, replay a captured one, or extend one past its expiry --
//     even with full read access to disk.
//
// It does NOT defend against: a candidate who edits this file before Razor
// starts. That requires the production build's integrity measures (install
// directory ACL, separate account, code signing). See docs/security.md.
import { canonicalJson, hmacHex, randomHex, randomToken, safeEqual } from './crypto.mjs';

/** Accepted clock skew between issuer and verifier, in milliseconds. */
const CLOCK_SKEW_MS = 30_000;

/**
 * Default lifetime of a bootstrap code.
 *
 * This is not a stylistic number, it is measured. The bootstrap code travels
 * inside the generated .seb start URL, and the clock starts when Razor mints it
 * -- but the browser that redeems it only appears after Safe Exam Browser has
 * started its service handshake, Client process and CEF browser. Observed on SEB
 * 3.10.2: ~64 s from launch to the first request for the start URL. With the
 * original 30 s the code had already expired, `bootstrap.refused/expired-code`
 * was recorded, and the candidate got a refused page instead of the IDE.
 *
 * Single-use is what protects this code, not shortness (see mintBootstrap), so
 * widening the window costs little: 3 minutes covers a cold SEB start on a slow
 * machine and is still gone the moment the exam page loads once.
 */
export const DEFAULT_BOOTSTRAP_TTL_MS = 180_000;

/** Bounds for the operator override; below 30 s nothing could ever redeem it. */
const MIN_BOOTSTRAP_TTL_MS = 30_000;
const MAX_BOOTSTRAP_TTL_MS = 3_600_000;

/**
 * Bootstrap TTL: RAZOR_BOOTSTRAP_TTL_MS when it is a sane number, otherwise the
 * measured default. An out-of-range value is clamped rather than honoured, so a
 * typo can never produce an immortal bootstrap code.
 */
export function bootstrapTtlMs(env = process.env) {
  const raw = Number(env?.RAZOR_BOOTSTRAP_TTL_MS);
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_BOOTSTRAP_TTL_MS;
  return Math.min(Math.max(raw, MIN_BOOTSTRAP_TTL_MS), MAX_BOOTSTRAP_TTL_MS);
}

export class GrantError extends Error {
  constructor(reason, detail) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = 'GrantError';
    this.reason = reason;
  }
}

/**
 * A grant is an HMAC-signed, single-use, expiring authorisation to run exactly
 * one exam session on exactly one host.
 *
 * `key` is the HMAC key. In the local-admin flow it is a per-run random secret
 * written to run/admin-key.pem. In the control-plane flow it is derived from
 * the device key (see heartbeat.mjs). Either way the candidate never needs it
 * to *use* a grant -- only to check one. Forging requires the key, and a
 * forged grant still has to survive verify().
 */
export function issueGrant({
  key,
  examId,
  machineId,
  ttlMs = 120_000,
  now = Date.now(),
  sebQuitPassword = null,
  terminalPolicy = null,
  issuedBy = 'local-admin',
  extendMinutes = 0,
}) {
  const payload = {
    v: 1,
    grantId: randomHex(16),
    nonce: randomToken(18),
    examId: String(examId ?? 'default'),
    machineId: String(machineId ?? 'unknown'),
    issuedBy,
    issuedAt: now,
    expiresAt: now + ttlMs,
    // Per-session secret. Never an env var: a stale quit password shared
    // between sessions is one leaked .seb away from being useless.
    sebQuitPassword: sebQuitPassword ?? null,
    terminalPolicy: terminalPolicy ?? null,
    extendMinutes: Number(extendMinutes) || 0,
  };
  return { ...payload, signature: signGrant(key, payload) };
}

/** HMAC-SHA256 over canonical JSON of the payload, excluding `signature`. */
function signGrant(key, payload) {
  const { signature: _drop, ...rest } = payload;
  return hmacHex(key, canonicalJson(rest));
}

/**
 * Verify a grant. Throws GrantError with a stable `reason` on any failure.
 *
 * `usedNonces` is the replay guard: a Set of nonces already consumed this
 * process lifetime. Single-use is enforced here, not by the signature.
 */
export function verifyGrant({
  key,
  grant,
  machineId,
  usedNonces,
  now = Date.now(),
  requireExamId = null,
}) {
  if (!grant || typeof grant !== 'object') {
    throw new GrantError('malformed', 'grant is not an object');
  }
  for (const field of ['grantId', 'nonce', 'examId', 'machineId', 'issuedAt', 'expiresAt', 'signature']) {
    if (grant[field] === undefined || grant[field] === null) {
      throw new GrantError('malformed', `missing field ${field}`);
    }
  }

  const expected = signGrant(key, grant);
  if (!safeEqual(expected, grant.signature)) {
    throw new GrantError('bad-signature');
  }

  if (String(grant.machineId) !== String(machineId)) {
    throw new GrantError('wrong-machine', `${grant.machineId} != ${machineId}`);
  }

  if (requireExamId !== null && String(grant.examId) !== String(requireExamId)) {
    throw new GrantError('wrong-exam');
  }

  if (Number(grant.issuedAt) > now + CLOCK_SKEW_MS) {
    throw new GrantError('not-yet-valid');
  }
  if (Number(grant.expiresAt) + CLOCK_SKEW_MS < now) {
    throw new GrantError('expired');
  }

  if (usedNonces) {
    if (usedNonces.has(grant.nonce)) {
      throw new GrantError('replayed');
    }
    usedNonces.add(grant.nonce);
  }

  return grant;
}

// ---------------------------------------------------------------------------
// Session token + lease
// ---------------------------------------------------------------------------

/**
 * A running session. The token is the only thing the browser needs; the lease
 * is what keeps it alive.
 *
 * Lease semantics (the anti-"pull the network cable" property):
 *   * `renew()` is called on every successful admin heartbeat.
 *   * When renewals stop, `state()` reports `grace` until `lockAt`, then
 *     `locked`. A locked session rejects every API and WebSocket request.
 *   * Grace default is 60s (stable wired LAN). `--grace-ms` overrides.
 */
export class Session {
  constructor({ token, grant, leaseMs, graceMs, now = Date.now() }) {
    this.token = token;
    this.grant = grant;
    this.examId = grant.examId;
    this.startedAt = now;
    this.leaseMs = leaseMs;
    this.graceMs = graceMs;
    this.lastRenewedAt = now;
    this.expiresAt = now + leaseMs;
    this.lockAt = now + leaseMs + graceMs;
    this.revoked = null;
    // Bootstrap codes are single-use and short-lived; see consumeBootstrap.
    this.bootstrap = new Map();
    this.activeWebSockets = new Set();
  }

  renew(now = Date.now()) {
    this.lastRenewedAt = now;
    this.expiresAt = now + this.leaseMs;
    this.lockAt = now + this.leaseMs + this.graceMs;
  }

  /** 'live' | 'grace' | 'locked' | 'revoked' */
  state(now = Date.now()) {
    if (this.revoked) return 'revoked';
    if (now <= this.expiresAt) return 'live';
    if (now <= this.lockAt) return 'grace';
    return 'locked';
  }

  isUsable(now = Date.now()) {
    const s = this.state(now);
    return s === 'live' || s === 'grace';
  }  revoke(reason) {
    this.revoked = reason ?? 'revoked';
  }

  // -- single-use bootstrap handshake --------------------------------------

  /**
   * Mint a one-time bootstrap code. The generated .seb carries this in its
   * startURL; the browser exchanges it for an HttpOnly+SameSite=Strict cookie
   * on first load.
   *
   * Why: the .seb file is readable by the candidate (an unencrypted config is).
   * A permanent token in the start URL would therefore be a permanent key. A
   * bootstrap code is worthless after the first successful exchange, so
   * copying the URL into Chrome after SEB has loaded gets you a 403.
   *
   * The TTL must outlast SEB's own startup: the redeeming browser does not exist
   * until SEB has booted. See DEFAULT_BOOTSTRAP_TTL_MS for the measurement.
   */
  mintBootstrap(ttlMs = DEFAULT_BOOTSTRAP_TTL_MS, now = Date.now()) {
    const code = randomToken(24);
    this.bootstrap.set(code, { expiresAt: now + ttlMs, used: false });
    return code;
  }

  consumeBootstrap(code, now = Date.now()) {
    const entry = this.bootstrap.get(code);
    if (!entry) return { ok: false, reason: 'unknown-code' };
    if (entry.used) return { ok: false, reason: 'already-used' };
    if (entry.expiresAt < now) {
      this.bootstrap.delete(code);
      return { ok: false, reason: 'expired-code' };
    }
    entry.used = true;
    return { ok: true };
  }

  pruneBootstrap(now = Date.now()) {
    for (const [code, entry] of this.bootstrap) {
      if (entry.used || entry.expiresAt < now) this.bootstrap.delete(code);
    }
  }
}
