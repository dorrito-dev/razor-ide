// Outbound admin channel: signed heartbeat + lease renewal + command intake.
//
// Why outbound: Razor binds to 127.0.0.1, so a remote proctor cannot POST to it
// and we refuse to expose an admin port with shared Basic-auth credentials over
// plain HTTP. Instead Razor *dials the control plane*, which means:
//
//   * no inbound port is opened on the exam machine,
//   * no shared password is stored on the exam machine,
//   * the control-plane reply carries the lease renewal and any pending
//     commands, which also fills the gap we found in lab-agent -- its
//     `commands` table can be written but was never read back.
//
// Route contract (documented in docs/research.md):
//
//   POST {base}/heartbeat                       -- status report, lease renew
//   GET  {base}/commands?deviceId=...&since=... -- pending commands (optional)
//
// A missing `{base}/commands` route is not fatal: we log it once and fall back
// to reporting-only, so the reference lab-agent works unmodified.
import { hostname } from 'node:os';
import { logger } from './config.mjs';

const log = logger('heartbeat');

const DEFAULT_INTERVAL_MS = 7_000;
const DEFAULT_TIMEOUT_MS = 5_000;

/** The commands a proctor may send. Anything else is logged and ignored. */
export const CommandKind = Object.freeze({
  START_SESSION: 'start_session',
  STOP_SESSION: 'stop_session',
  EXTEND: 'extend_session',
  LOCK: 'lock_session',
  COLLECT: 'collect_artifacts',
});

const ACCEPTED_KINDS = new Set(Object.values(CommandKind));

export class ControlPlaneClient {
  #env;
  #url;
  #deviceId;
  #token;
  #intervalMs;
  #timer = null;
  #misses = 0;
  #since = null;
  #commandsUnsupported = false;
  #consecutiveFailures = 0;
  #onCommand;
  #onMiss;
  #onRecover;
  #statusProvider;
  #inFlight = false;
  #seq = 0;

  constructor({
    baseUrl,
    deviceId,
    token = null,
    intervalMs = Number(process.env.RAZOR_HEARTBEAT_MS ?? DEFAULT_INTERVAL_MS),
    // Thresholds: warn after 3 misses, and the *gate* locks separately on lease
    // expiry, so these are reporting-only numbers.
    missThreshold = 3,
    onCommand,
    onMiss,
    onRecover,
    statusProvider,
  }) {
    this.baseUrl = baseUrl;
    this.deviceId = deviceId;
    this.#token = token;
    this.#intervalMs = intervalMs;
    this.missThreshold = missThreshold;
    this.#onCommand = onCommand;
    this.#onMiss = onMiss;
    this.#onRecover = onRecover;
    this.#statusProvider = statusProvider;
  }

  get failures() {
    return this.#consecutiveFailures;
  }

  start() {
    if (this.#timer) return;
    this.#timer = setInterval(() => {
      void this.tick();
    }, this.#intervalMs);
    this.#timer.unref?.();
    void this.tick();
  }

  stop() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  /** One heartbeat round. Never throws. */
  async tick() {
    if (this.#inFlight) return { ok: false, reason: 'in-flight' };
    this.#inFlight = true;
    try {
      const report = this.#buildReport();
      const response = await this.#post('/heartbeat', report);
      if (!response.ok) {
        this.#registerFailure(response.reason ?? `http-${response.status}`);
        return response;
      }

      if (this.#consecutiveFailures >= this.missThreshold) this.#onRecover?.();
      this.#consecutiveFailures = 0;
      this.#misses = 0;

      const handled = this.#handleResponse(response.body);
      // Lease renewal is driven by a *successful authenticated round trip*,
      // which is the property that makes pulling the network cable lock the
      // session rather than extend it.
      return { ok: true, renewed: true, handled };
    } catch (err) {
      this.#registerFailure(err.message);
      return { ok: false, reason: 'exception', detail: err.message };
    } finally {
      this.#inFlight = false;
    }
  }

  #registerFailure(reason) {
    this.#consecutiveFailures += 1;
    this.#misses += 1;
    if (this.#misses === this.missThreshold) {
      log.warn(`control plane unreachable ${this.#misses}x (${reason}); lease will expire`);
      this.#onMiss?.({ misses: this.#misses, reason });
    } else if (this.#misses % this.missThreshold === 0) {
      log.warn(`control plane still unreachable (${this.#misses} misses, last: ${reason})`);
      this.#onMiss?.({ misses: this.#misses, reason });
    } else {
      log.debug(`heartbeat failed: ${reason}`);
    }
  }

  #buildReport() {
    const status = this.#statusProvider?.() ?? {};
    return {
      deviceId: this.deviceId,
      hostname: hostname(),
      observedAt: new Date().toISOString(),
      // Self-reported fields. Recorded, never trusted as proof -- see
      // docs/security.md. A candidate who controls the process can lie here.
      mode: status.mode ?? null,
      gateState: status.gateState ?? null,
      lease: status.lease ?? null,
      seb: status.seb ?? null,
      terminal: status.terminal ?? null,
      policy: status.policy ?? null,
      seq: ++this.#seq,
    };
  }

  #handleResponse(body) {
    const commands = Array.isArray(body?.commands) ? body.commands : [];
    const renewed = body?.lease?.renew !== false;
    let handled = 0;

    for (const command of commands) {
      const kind = String(command?.kind ?? '');
      if (!ACCEPTED_KINDS.has(kind)) {
        log.warn(`ignoring unknown command kind "${kind}"`);
        continue;
      }
      // Expiry is enforced locally: a replayed command from an old capture does
      // not get to act just because it arrived.
      if (command.expiresAt && Date.parse(command.expiresAt) < Date.now()) {
        log.warn(`ignoring expired command ${command.id ?? kind}`);
        continue;
      }
      handled += 1;
      this.#onCommand?.(command);
    }

    if (!renewed) log.warn('control plane declined to renew the lease');
    void this.#pollCommands();
    return handled;
  }

  /**
   * Optional command read-back. Historically absent from lab-agent, so a 404
   * downgrades us to report-only instead of erroring every 7 seconds.
   */
  async #pollCommands() {
    if (this.#commandsUnsupported) return;
    const query = new URLSearchParams({ deviceId: this.deviceId });
    if (this.#since) query.set('since', this.#since);
    const response = await this.#get(`/commands?${query}`);
    if (!response.ok) {
      if (response.status === 404) {
        this.#commandsUnsupported = true;
        log.info('control plane has no /commands route; continuing in report-only mode');
      }
      return;
    }
    const commands = Array.isArray(response.body?.commands) ? response.body.commands : [];
    this.#since = response.body?.cursor ?? this.#since;
    for (const command of commands) {
      const kind = String(command?.kind ?? '');
      if (!ACCEPTED_KINDS.has(kind)) continue;
      if (command.expiresAt && Date.parse(command.expiresAt) < Date.now()) continue;
      this.#onCommand?.(command);
    }
  }

  // -- HTTP ---------------------------------------------------------------

  #headers() {
    const headers = { 'content-type': 'application/json', accept: 'application/json' };
    if (this.#token) headers.authorization = `Bearer ${this.#token}`;
    return headers;
  }

  async #post(path, payload) {
    return this.#request('POST', path, payload);
  }

  async #get(path) {
    return this.#request('GET', path, null);
  }

  async #request(method, path, payload) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Number(process.env.RAZOR_HEARTBEAT_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS));
    try {
      const response = await fetch(new URL(path, this.baseUrl), {
        method,
        headers: this.#headers(),
        body: payload ? JSON.stringify(payload) : undefined,
        signal: controller.signal,
      });
      const text = await response.text();
      let body = null;
      if (text) {
        try {
          body = JSON.parse(text);
        } catch {
          body = { raw: text };
        }
      }
      return { ok: response.ok, status: response.status, body };
    } finally {
      clearTimeout(timer);
    }
  }
}
