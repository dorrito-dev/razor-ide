// Cryptography primitives. Node's built-in crypto only -- no third-party deps.
//
// Everything secret here (session tokens, bootstrap codes, quit passwords,
// nonces) is generated from `randomBytes`, never from Math.random or timestamps.
import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

/** Hex, `bytes` bytes of CSPRNG output (2 hex chars per byte). */
export const randomHex = (bytes = 32) => randomBytes(bytes).toString('hex');

/** URL-safe base32-ish token: unambiguous, no padding, 26 chars per 16 bytes. */
export function randomToken(bytes = 24) {
  return randomBytes(bytes).toString('base64url');
}

export const sha256Hex = (data) => createHash('sha256').update(data).digest('hex');

/**
 * SEB's `hashedQuitPassword` / `hashedAdminPassword`.
 *
 * Evidence: the published SEB configuration example carries
 * `"hashedQuitPassword":"8577da2ea54085708b3b851bc50315a36bb740ba5135e747cfb12457b5d3060f"`
 * -- exactly 64 lowercase hex characters, i.e. a bare SHA-256 digest with no
 * salt component and no `salt:hash` separator.
 *
 * This is NOT independently confirmed for 3.10.2: the hashing scheme is not
 * documented on any page we could reach. `tools/verify-seb-config.mjs` exists
 * to settle it against the real client in one step. If it disagrees, do not
 * guess -- vendor the hash produced by SEB Config Tool.
 */
export const sebPasswordHash = (plaintext) => sha256Hex(String(plaintext), 'utf8');

/** Constant-time compare of two strings, safe against length oracle. */
export function safeEqual(a, b) {
  const bufA = Buffer.from(String(a ?? ''), 'utf8');
  const bufB = Buffer.from(String(b ?? ''), 'utf8');
  if (bufA.length !== bufB.length) {
    // Still burn a comparison so the timing does not trivially reveal length.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

export const hmacHex = (key, data) =>
  createHmac('sha256', key).update(data).digest('hex');

/** Canonical JSON: recursively sorted keys, no whitespace. Used for signing. */
export function canonicalJson(value) {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortDeep(value[key]);
    return out;
  }
  return value;
}

/**
 * SEB Config Key, per the SEB developer documentation.
 *
 * Canonicalise the decrypted plist to "SEB-JSON": drop `originatorVersion`,
 * sort every dict recursively, no whitespace, no character escaping, drop
 * empty dicts, `<data>` -> base64 string, `<date>` -> ISO 8601, round
 * `<real>` floats -- then SHA-256 and render as lowercase base16.
 *
 * Input here is the parsed plist (see src/seb/plist.mjs), not the XML text, so
 * the escaping/rounding rules are handled at parse time.
 */
export function sebConfigKey(parsedPlist) {
  const clone = structuredClone(parsedPlist);
  delete clone.originatorVersion;
  return sha256Hex(canonicalJson(clone), 'utf8');
}

/**
 * SEB per-request verification value.
 *
 * Documented construction: absolute URL with the fragment removed, then the
 * base key, SHA-256, base16. SEB sends the same construction in the
 * `X-SafeExamBrowser-ConfigKeyHash` (config key) and
 * `X-SafeExamBrowser-RequestHash` (browser exam key) request headers.
 */
export function sebRequestHash(absoluteUrlNoFragment, baseKey) {
  const url = String(absoluteUrlNoFragment).split('#')[0];
  return sha256Hex(`${url}${baseKey}`, 'utf8');
}

const SEB_NONCE_BYTES = 16;

/** A fresh nonce for the SEB JS-API path (`SafeExamBrowser.security.*`). */
export const sebNonce = () => randomBytes(SEB_NONCE_BYTES).toString('base64');
