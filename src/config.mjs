import { existsSync, mkdirSync, appendFileSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Automatically load .env file if present
const envFile = join(ROOT, '.env');
if (existsSync(envFile) && typeof process.loadEnvFile === 'function') {
  try {
    process.loadEnvFile(envFile);
  } catch {
    /* ignore malformed .env or permission errors */
  }
}

export const RUN_DIR = join(ROOT, 'run');
export const BUILD_DIR = join(ROOT, 'build');
export const SEB_GENERATED_DIR = join(ROOT, 'seb', 'generated');

export function ensureDirs() {
  for (const dir of [RUN_DIR, BUILD_DIR, SEB_GENERATED_DIR]) {
    mkdirSync(dir, { recursive: true });
  }
}

/** Absolute path; relative inputs resolve against the Razor root. */
export function abs(p) {
  return isAbsolute(p) ? p : resolve(ROOT, p);
}

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

/**
 * Two orthogonal axes:
 *
 *   --ui dev            UI convenience mode (browser auto-open, watch-friendly)
 *   --ui prod | (none)  normal UI boot
 *   --seb               additionally launch Razor inside Safe Exam Browser
 *
 *   RAZOR_ENV=dev|production   the SECURITY mode. This is what decides whether
 *                              lockdown restrictions can be bypassed.
 *
 * The security mode is deliberately NOT the same switch as the UI mode, and in
 * `production` it ignores every request-level bypass (see gate.mjs).
 */
export function readEnv(argv = process.argv.slice(2)) {
  const flag = (name) => argv.includes(name);
  const value = (name, fallback) => {
    const i = argv.indexOf(name);
    return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
  };

  const rawEnvMode = (process.env.RAZOR_ENV ?? '').trim().toLowerCase();
  let mode;
  if (rawEnvMode === 'production' || rawEnvMode === 'prod') mode = 'production';
  else if (rawEnvMode === 'dev' || rawEnvMode === 'development') mode = 'dev';
  else mode = 'dev'; // unset defaults to dev, loudly (see logBanner)

  const ui = (value('--ui', 'prod') || 'prod').toLowerCase();

  return {
    /** 'dev' | 'production' -- the security mode. */
    mode,
    /** true when RAZOR_ENV was not set at all (we defaulted). */
    modeWasImplicit: rawEnvMode === '',
    /** 'dev' | 'prod' -- how the browser UI is booted. Purely cosmetic. */
    ui,
    /** Launch Safe Exam Browser after the server is up. */
    seb: flag('--seb'),
    /** Print the exact SEB argv and exit -- safe SEB integration smoke test. */
    sebArgvOnly: flag('--seb-argv-only'),
    /** Skip the admin-request gate. Silently ignored in production. */
    bypassGate: flag('--bypass-gate') || process.env.RAZOR_DEV_BYPASS_GATE === '1',
    /** Trust X-Forwarded-For for loopback checks (proxy setups). */
    openBrowser: flag('--open') || process.env.RAZOR_OPEN_BROWSER === '1',
    port: Number(value('--port', process.env.RAZOR_PORT ?? '0')) || 0,
    host: value('--host', process.env.RAZOR_HOST ?? '127.0.0.1'),
  };
}

export const isProduction = (env) => env.mode === 'production';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/**
 * The directory the editor/terminal operate in. Kept separate from Razor's own
 * source tree so an exam candidate can never see or edit the launcher.
 */
export function workspaceDir(env = readEnv()) {
  const raw = process.env.RAZOR_WORKSPACE
    ?? (env.mode === 'production' ? 'C:\\RazorExam' : join(ROOT, 'workspace'));
  return abs(raw);
}

export function adminTokenFile() {
  return join(RUN_DIR, 'admin-token');
}

/** The admin bearer token, from RAZOR_ADMIN_TOKEN or run/admin-token. */
export function adminToken() {
  const fromEnv = (process.env.RAZOR_ADMIN_TOKEN ?? '').trim();
  if (fromEnv) return fromEnv;
  try {
    return readFileSync(adminTokenFile(), 'utf8').trim();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN = LEVELS[(process.env.RAZOR_LOG_LEVEL ?? 'info').toLowerCase()] ?? LEVELS.info;

export function makeLogger(scope) {
  const stamp = () => new Date().toISOString().replace('T', ' ').slice(0, 23);
  const write = (level, args) => {
    if (LEVELS[level] < MIN) return;
    const line = `${stamp()} ${level.toUpperCase().padEnd(5)} [${scope}] ${args
      .map((a) => (typeof a === 'string' ? a : inspect(a)))
      .join(' ')}`;
    (level === 'error' || level === 'warn' ? console.error : console.log)(line);
    if (process.env.RAZOR_LOG_FILE) {
      try {
        appendFileSync(process.env.RAZOR_LOG_FILE, line + '\n');
      } catch {
        /* logging must never break the exam */
      }
    }
  };
  return {
    debug: (...a) => write('debug', a),
    info: (...a) => write('info', a),
    warn: (...a) => write('warn', a),
    error: (...a) => write('error', a),
  };
}

function inspect(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export { makeLogger as logger };
