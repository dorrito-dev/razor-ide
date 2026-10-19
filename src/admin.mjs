// Local admin surface -- the proctor's CLI talks to this.
//
// Deliberately *not* how a remote proctor starts an exam: this is bound to
// loopback and exists for the same-machine operator workflow and for testing.
// Remote authorisation goes through the signed-grant path (heartbeat.mjs), and
// both funnel into the same SessionGate.applyGrant().
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { logger } from './config.mjs';
import { safeEqual, sebRequestHash } from './security/crypto.mjs';
import { PATHS, hardenDirectoryAcl } from './security/state.mjs';

const log = logger('admin');

/**
 * Resolve admin credentials.
 *
 * Production refuses to fall back to a generated password: a printed-default
 * credential on an exam machine is exactly the shared-secret weakness we are
 * avoiding. Dev generates a random one per run and reports the file path.
 */
export function resolveAdminCredentials(env) {
  const user = process.env.RAZOR_ADMIN_USER ?? 'admin';
  const pass = process.env.RAZOR_ADMIN_PASS ?? null;
  const token = process.env.RAZOR_ADMIN_TOKEN ?? null;

  if (token) return { user, kind: 'token', secret: token, source: 'RAZOR_ADMIN_TOKEN' };

  if (pass) return { user, kind: 'basic', secret: pass, source: 'RAZOR_ADMIN_PASS' };

  if (env.mode === 'production') {
    return {
      ok: false,
      reason: 'production-requires-credentials',
      detail:
        'RAZOR_ADMIN_PASS (or RAZOR_ADMIN_TOKEN) must be set in production. ' +
        'Razor will not generate a default admin credential on an exam machine.',
    };
  }

  // Dev: generate once per run, persist for the CLI to read, harden the ACL.
  const path = PATHS.adminKey;
  if (existsSync(path)) {
    const existing = readFileSync(path, 'utf8').trim();
    if (existing) {
      return { user, kind: 'basic', secret: existing, source: `generated (${path})`, generated: true };
    }
  }
  const generated = Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
  writeFileSync(path, generated + '\n', 'utf8');
  hardenDirectoryAcl(PATHS.run);
  return { user, kind: 'basic', secret: generated, source: `generated (${path})`, generated: true };
}

/** Constant-time Basic-auth check. Returns the username, or null. */
export function authenticateAdmin(headerValue, credentials) {
  if (!credentials || credentials.ok === false) return null;
  const header = String(headerValue ?? '');
  if (!header.startsWith('Basic ')) {
    // Also accept a bearer token, which is what tools/admin-cli.mjs uses.
    if (/^Bearer\s+/i.test(header)) {
      const supplied = header.replace(/^Bearer\s+/i, '').trim();
      return safeEqual(supplied, credentials.secret) ? credentials.user : null;
    }
    return null;
  }
  let decoded;
  try {
    decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  } catch {
    return null;
  }
  const index = decoded.indexOf(':');
  if (index < 0) return null;
  const user = decoded.slice(0, index);
  const pass = decoded.slice(index + 1);
  const userOk = safeEqual(user, credentials.user);
  const passOk = safeEqual(pass, credentials.secret);
  return userOk && passOk ? user : null;
}

/**
 * Verify SEB's attestation headers for an incoming request.
 *
 * Supported evidence:
 *   * X-SafeExamBrowser-ConfigKeyHash -- the Config Key request hash. This is
 *     platform-independent and therefore the only one Razor can compute.
 *     Documented construction: SHA-256( absoluteUrlWithoutFragment + baseKey ).
 *   * SafeExamBrowser.version via the SEB JS API, reported by the page over the
 *     authenticated WebSocket. Weaker (self-reported) but it is what SEB
 *     exposes on Windows.
 *
 * NOT supported, deliberately: the Browser Exam Key
 * (X-SafeExamBrowser-RequestHash). Its base key folds in SEB's code signature,
 * so it is platform- AND bitness-specific and cannot be computed server-side --
 * every build has a different value. Supporting it means pinning it per build;
 * see docs/security.md.
 */
export function verifySebRequest({ headers, absoluteUrl, expectedConfigKeyHash, requireAttestation }) {
  const supplied = headers['x-safeexambrowsers-configkeyhash']
    ?? headers['x-safeexambrowser-configkeyhash']
    ?? null;

  if (!supplied) {
    return requireAttestation
      ? { ok: false, reason: 'missing-config-key-header' }
      : { ok: true, attestation: 'absent', enforced: false };
  }
  if (!expectedConfigKeyHash) {
    return requireAttestation
      ? { ok: false, reason: 'no-expected-config-key-configured' }
      : { ok: true, attestation: 'unverified', enforced: false };
  }

  const expected = sebRequestHash(absoluteUrl, expectedConfigKeyHash);
  const match = safeEqual(supplied.toLowerCase(), expected);
  return match
    ? { ok: true, attestation: 'verified', enforced: true }
    : { ok: false, reason: 'config-key-mismatch', supplied, expected };
}

/**
 * Host and Origin validation.
 *
 * A loopback server with a shell behind it is the textbook DNS-rebinding and
 * cross-site-WebSocket-hijacking target: any page the candidate's browser loads
 * can attempt `fetch('http://127.0.0.1:PORT/api/...')` or open a WebSocket.
 * SameSite=Strict cookies defeat most of it; these checks are the second lock.
 */
export function verifyHostAndOrigin({ hostHeader, originHeader, port, allowExtraHosts = [] }) {
  const allowedHosts = new Set([
    `127.0.0.1:${port}`,
    `localhost:${port}`,
    `[::1]:${port}`,
    ...allowExtraHosts,
  ]);

  if (!hostHeader) return { ok: false, reason: 'missing-host' };
  const host = String(hostHeader).toLowerCase();
  if (!allowedHosts.has(host)) {
    return { ok: false, reason: 'bad-host', detail: `${host} is not a loopback host` };
  }

  if (originHeader) {
    const origin = String(originHeader).toLowerCase().replace(/\/$/, '');
    const allowedOrigins = new Set([
      `http://127.0.0.1:${port}`,
      `http://localhost:${port}`,
      `http://[::1]:${port}`,
      ...allowExtraHosts.map((h) => `http://${h}`),
    ]);
    if (!allowedOrigins.has(origin)) {
      return { ok: false, reason: 'bad-origin', detail: origin };
    }
  }

  return { ok: true };
}
