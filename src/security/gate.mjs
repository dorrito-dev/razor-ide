// The session gate: the single place that decides whether a session exists.
//
// State machine
//
//   AWAITING_ADMIN ──grant──▶ STARTING ──ready──▶ RUNNING ──expiry──▶ LOCKED
//         ▲                                            │              │
//         └────────────── admin stop / revoke ─────────┴──────────────┘
//
// Invariant: nothing in lock/dev mode can move the machine out of
// AWAITING_ADMIN except a grant that passes verifyGrant(). In `production`,
// every bypass-shaped input is recorded in the audit log and then ignored --
// see `requestBypass`.
import { EventEmitter } from 'node:events';
import { isProduction } from '../config.mjs';
import { GrantError, Session, issueGrant, verifyGrant } from '../security/grants.mjs';
import { randomHex, safeEqual } from '../security/crypto.mjs';
import { AuditLog } from '../security/state.mjs';

export const GateState = Object.freeze({
  AWAITING_ADMIN: 'awaiting_admin',
  STARTING: 'starting',
  RUNNING: 'running',
  LOCKED: 'locked',
  STOPPED: 'stopped',
});

const DEFAULT_LEASE_MS = 60_000;
const DEFAULT_GRACE_MS = 60_000;

export class SessionGate extends EventEmitter {
  #env;
  #audit;
  #key;
  #machineId;
  #usedNonces = new Set();
  #usedGrantIds = new Set();
  #session = null;
  #state = GateState.AWAITING_ADMIN;
  #lockReason = null;
  #timer = null;

  constructor({ env, key, machineId, audit = new AuditLog() }) {
    super();
    this.#env = env;
    this.#key = key;
    this.#machineId = machineId;
    this.#audit = audit;
    this.leaseMs = Number(process.env.RAZOR_LEASE_MS ?? DEFAULT_LEASE_MS) || DEFAULT_LEASE_MS;
    this.graceMs = Number(process.env.RAZOR_GRACE_MS ?? DEFAULT_GRACE_MS) || DEFAULT_GRACE_MS;
  }

  get state() {
    return this.#state;
  }

  get session() {
    return this.#session;
  }

  get lockReason() {
    return this.#lockReason;
  }

  get audit() {
    return this.#audit;
  }

  /** HMAC key used to verify grants issued on this machine. */
  get adminKey() {
    return this.#key;
  }

  get machineId() {
    return this.#machineId;
  }

  /** Clock ticks so the lease can expire without a heartbeat. */
  start() {
    if (this.#timer) return;
    this.#timer = setInterval(() => this.#tick(), 1_000);
    this.#timer.unref?.();
  }

  stop() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  #tick() {
    if (this.#state !== GateState.RUNNING || !this.#session) return;
    const state = this.#session.state();
    if (state === 'locked' || state === 'revoked') {
      this.#enterLocked(state === 'revoked' ? this.#session.revoked : 'lease-expired');
    } else if (state === 'grace') {
      this.emit('lease:grace', { remainingMs: this.#session.lockAt - Date.now() });
    }
  }

  /**
   * Record a bypass attempt. In production it is logged and refused; the
   * return value is what callers must branch on.
   */
  requestBypass(source) {
    if (isProduction(this.#env)) {
      this.#audit.record('bypass.refused', { source, reason: 'production' });
      return { ok: false, reason: 'production-refuses-bypass' };
    }
    if (!this.#env.bypassGate) {
      this.#audit.record('bypass.refused', { source, reason: 'flag-not-set' });
      return { ok: false, reason: 'bypass-flag-not-set' };
    }
    this.#audit.record('bypass.allowed', { source, mode: this.#env.mode });
    return { ok: true };
  }

  /**
   * Dev-only immediate start. Production cannot reach RUNNING through here:
   * requestBypass refuses, so this returns a refusal instead of a session.
   */
  devStart(reason = 'bypass') {
    const decision = this.requestBypass(reason);
    if (!decision.ok) return decision;

    const grant = issueGrant({
      key: this.#key,
      examId: 'dev',
      machineId: this.#machineId,
      issuedBy: 'dev-bypass',
      sebQuitPassword: process.env.RAZOR_QUIT_PASSWORD ?? null,
      ttlMs: 24 * 60 * 60 * 1000,
    });
    return { ok: true, grant, session: this.#openSession(grant, 'dev-bypass') };
  }

  /**
   * The real entry point. `keyOverride` lets the control-plane heartbeat path
   * pass a device-key-derived HMAC key instead of the local admin key.
   *
   * Renewal vs replay: re-presenting the *same* grant while it is the active
   * one extends the lease (that is what a heartbeat does). Presenting that
   * grant again after the session ended is refused, because the grant id is
   * remembered for the lifetime of the process -- a captured start command
   * cannot be used to open a second session.
   */
  applyGrant(grant, { keyOverride = null, source = 'admin' } = {}) {
    if (this.#state === GateState.RUNNING && this.#session) {
      if (grant?.grantId && grant.grantId === this.#session.grant.grantId) {
        // Same grant: a legitimate renewal. The signature was verified when it
        // opened the session, so the nonce replay guard must not veto this.
        this.#session.renew();
        this.#audit.record('grant.renewed', { grantId: grant.grantId, source });
        return { ok: true, renewed: true, session: this.#session };
      }
      const decision = this.#tryVerify(grant, keyOverride, source);
      if (decision.ok) {
        this.#session.renew();
        this.#audit.record('grant.renewed', { grantId: grant.grantId, source });
        return { ok: true, renewed: true, session: this.#session };
      }
      return decision;
    }

    // Not running. A grant that was already consumed can never start again.
    if (grant?.grantId && this.#usedGrantIds.has(grant.grantId)) {
      this.#audit.record('grant.refused', { source, reason: 'consumed', grantId: grant.grantId });
      return { ok: false, reason: 'consumed' };
    }

    const decision = this.#tryVerify(grant, keyOverride, source);
    if (!decision.ok) return decision;

    this.#setState(GateState.STARTING);
    const session = this.#openSession(grant, source);
    this.#usedGrantIds.add(grant.grantId);
    return { ok: true, session };
  }

  #tryVerify(grant, keyOverride, source) {
    try {
      verifyGrant({
        key: keyOverride ?? this.#key,
        grant,
        machineId: this.#machineId,
        usedNonces: this.#usedNonces,
      });
      return { ok: true };
    } catch (err) {
      const reason = err instanceof GrantError ? err.reason : 'verify-failed';
      this.#audit.record('grant.refused', {
        source,
        reason,
        detail: err.message,
        grantId: grant?.grantId ?? null,
      });
      return { ok: false, reason, detail: err.message };
    }
  }

  #openSession(grant, source) {
    const token = randomHex(32);
    const session = new Session({
      token,
      grant,
      leaseMs: this.leaseMs,
      graceMs: this.graceMs,
    });
    this.#session = session;
    this.#setState(GateState.RUNNING);
    this.#audit.record('session.started', {
      source,
      examId: grant.examId,
      grantId: grant.grantId,
      leaseMs: this.leaseMs,
      graceMs: this.graceMs,
    });
    return session;
  }

  /**
   * Constant-time check of the session token used by the browser cookie.
   *
   * Returns false for a revoked session even if the token string matches, so a
   * proctor stop or a lease lock immediately invalidates live cookies.
   */
  tokenMatches(candidate) {
    if (!this.#session) return false;
    if (!this.#session.isUsable()) return false;
    return safeEqual(candidate ?? '', this.#session.token);
  }

  /** Called by the heartbeat loop; returns false once the session is gone. */
  renewLease(source = 'heartbeat') {
    if (this.#state !== GateState.RUNNING || !this.#session) return false;
    this.#session.renew();
    this.#audit.record('lease.renewed', { source });
    return true;
  }

  stopSession(reason = 'admin-stop') {
    if (!this.#session) {
      this.#setState(GateState.STOPPED);
      return { ok: true, stopped: false };
    }
    this.#session.revoke(reason);
    const sockets = this.#session.activeWebSockets.size;
    for (const ws of this.#session.activeWebSockets) {
      try {
        ws.close(4401, reason);
      } catch {
        /* best effort */
      }
    }
    this.#session.activeWebSockets.clear();
    this.#enterLocked(reason);
    return { ok: true, stopped: true, closedSockets: sockets };
  }

  #enterLocked(reason) {
    this.#lockReason = reason;
    this.#setState(GateState.LOCKED);
    this.#audit.record('session.locked', { reason });
  }

  /** Dev restart helper: returns the gate to AWAITING_ADMIN. */
  reset(reason = 'reset') {
    this.#session?.revoke(reason);
    this.#session = null;
    this.#lockReason = null;
    this.#usedNonces.clear();
    // Grant ids are intentionally NOT cleared: a grant consumed before a reset
    // must not become usable again.
    this.#setState(GateState.AWAITING_ADMIN);
    this.#audit.record('gate.reset', { reason });
  }

  #setState(next) {
    if (this.#state === next) return;
    const previous = this.#state;
    this.#state = next;
    this.emit('state', { previous, next, at: Date.now() });
  }

  /** Snapshot for the UI / status endpoint. Never includes the token. */
  describe() {
    const session = this.#session;
    return {
      state: this.#state,
      lockReason: this.#lockReason,
      examId: session?.examId ?? null,
      lease: session
        ? {
            state: session.state(),
            expiresAt: session.expiresAt,
            lockAt: session.lockAt,
            remainingMs: Math.max(0, session.expiresAt - Date.now()),
            graceRemainingMs: Math.max(0, session.lockAt - Date.now()),
          }
        : null,
      startedAt: session?.startedAt ?? null,
    };
  }
}
