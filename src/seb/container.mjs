// SEB `.seb` container writer.
//
// Format (SEB developer documentation, "Encrypted SEB Config File Format"):
//
//   file       = gzip( "plnd" + gzip( plistXml ) )     -- unencrypted
//   file       = gzip( "pswd" + RNCryptor( gzip(plistXml) ) )   -- password
//
// IMPORTANT LIMITATION, stated plainly:
//
//   We emit the `plnd` (plain) container only. The password form uses
//   RNCryptor (PBKDF2/AES-256-CBC/HMAC-SHA-256) and SEB 3.x's exact parameter
//   set -- iteration count, RNCryptor schema version, and whether the salt is
//   derived per the v15 spec or the RNCryptor v3 scheme -- is not documented
//   anywhere we could verify. Producing a wrong `pswd` file yields a config
//   that fails to open at exam time, so we refuse to guess:
//
//     * Production requires an encrypted .seb (or an explicit, logged opt-in
//       to the plain one). Supply it with RAZOR_SEB_CONFIG=/path/to/exam.seb,
//       generated with SEB Config Tool.
//     * `inspectContainer()` reads the prefix so the operator can confirm what
//       they supplied.
//
// A `plnd` file is fully readable and forgeable by the candidate. It is fine
// for development and CI, and is NOT acceptable for a graded exam.
import { gzipSync, gunzipSync } from 'node:zlib';
import { readFileSync, writeFileSync } from 'node:fs';
import { buildDocument, parsePlistXml } from './plist.mjs';

export const Prefix = Object.freeze({
  PublicKeyAndSymmetric: 'phsk',
  PublicKeyOnly: 'pkhs',
  Password: 'pswd',
  PasswordClientConfig: 'pwcc',
  Plain: 'plnd',
});

/** Serialise a plist-shaped object into a `plnd` .seb buffer. */
export function encodePlain(policyObject) {
  const xml = buildDocument(policyObject);
  const inner = gzipSync(Buffer.from(xml, 'utf8'), { level: 9 });
  const prefixed = Buffer.concat([Buffer.from(Prefix.Plain, 'ascii'), inner]);
  return gzipSync(prefixed, { level: 9 });
}

/** Read the 4-byte prefix of a .seb buffer without decrypting it. */
export function inspectContainer(buffer) {
  let decompressed;
  try {
    decompressed = gunzipSync(buffer);
  } catch (err) {
    return { ok: false, reason: 'not-gzip', detail: err.message };
  }
  const prefix = decompressed.subarray(0, 4).toString('ascii');
  const known = Object.values(Prefix).includes(prefix);
  return {
    ok: known,
    prefix,
    encrypted: prefix !== Prefix.Plain,
    bytes: buffer.length,
    ...(known ? {} : { reason: 'unknown-prefix' }),
  };
}

/** Decode a `plnd` .seb buffer back to its parsed plist object. */
export function decodePlain(buffer) {
  const outer = gunzipSync(buffer);
  const prefix = outer.subarray(0, 4).toString('ascii');
  if (prefix !== Prefix.Plain) {
    throw new Error(
      `container prefix is "${prefix}", not "plnd"; encrypted configs must be decrypted by SEB`,
    );
  }
  const xml = gunzipSync(outer.subarray(4)).toString('utf8');
  return { xml, plist: parsePlistXml(xml) };
}

export function writeSebFile(path, policyObject) {
  const buffer = encodePlain(policyObject);
  writeFileSync(path, buffer);
  return buffer;
}

export function readSebFile(path) {
  return readFileSync(path);
}
