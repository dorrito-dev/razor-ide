// Where secrets and per-session state live on disk.
//
// Windows note: POSIX modes are a no-op here, so every directory Razor creates
// for secrets is also handed a restrictive NTFS ACL (see hardenDirectoryAcl).
// That is defence in depth only -- a candidate running as the same user can
// read anything that user can read. See docs/security.md.
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { BUILD_DIR, RUN_DIR, ensureDirs as ensureBaseDirs, logger } from '../config.mjs';

const log = logger('state');

export const PATHS = {
  run: RUN_DIR,
  build: BUILD_DIR,
  adminKey: join(RUN_DIR, 'admin-key.pem'),
  trust: join(RUN_DIR, 'trust.json'),
  audit: join(RUN_DIR, 'audit.jsonl'),
  session: join(RUN_DIR, 'session.json'),
  sebConfig: join(RUN_DIR, 'razor.seb'),
  sebPlist: join(RUN_DIR, 'razor.plist.xml'),
};

export function ensureDirs() {
  ensureBaseDirs();
  mkdirSync(RUN_DIR, { recursive: true });
}

/**
 * Restrict a directory to the current user, SYSTEM and Administrators.
 *
 * `icacls` is the supported way to do this without native bindings. Failure is
 * logged, never fatal: on a correctly provisioned exam image the ACL is set by
 * the installer instead.
 */
export function hardenDirectoryAcl(dir) {
  if (process.platform !== 'win32') return false;
  try {
    // /inheritance:r  -> drop inherited ACEs
    // /grant:r        -> replace grants for the listed principals
    execFileSync(
      'icacls',
      [
        dir,
        '/inheritance:r',
        '/grant:r',
        `${process.env.USERNAME}:F`,
        'SYSTEM:F',
        'Administrators:F',
      ],
      { stdio: 'ignore', windowsHide: true },
    );
    return true;
  } catch (err) {
    log.warn(`could not harden ACL on ${dir}: ${err.message}`);
    return false;
  }
}

export function writeJson(path, value) {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

export function readJson(path) {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    log.warn(`could not parse ${path}: ${err.message}`);
    return null;
  }
}

export const removeQuietly = (path) => {
  try {
    rmSync(path, { force: true, recursive: true });
  } catch {
    /* best effort */
  }
};

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/**
 * Append-only JSONL audit trail. Every terminal command, every state
 * transition, every SEB attestation failure lands here.
 *
 * This is a *local* record. Tamper-evidence requires shipping it off-box,
 * which is out of scope for this build (see docs/security.md).
 */
export class AuditLog {
  #path;

  constructor(path = PATHS.audit) {
    this.#path = path;
  }

  record(kind, detail = {}) {
    const line = JSON.stringify({ ts: new Date().toISOString(), kind, ...detail });
    try {
      appendFileSync(this.#path, line + '\n', 'utf8');
    } catch (err) {
      log.warn(`audit write failed: ${err.message}`);
    }
    if (process.env.RAZOR_AUDIT_STDERR === '1') process.stderr.write(line + '\n');
  }

  close() {
    /* appendFileSync opens and closes per record -- nothing to flush */
  }
}
