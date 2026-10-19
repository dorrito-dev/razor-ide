// Locating, verifying and launching Safe Exam Browser.
//
// Sourced facts (see docs/research.md for citations):
//   * SEB is launched as `"<install>\Application\SafeExamBrowser.exe" "<abs>.seb"`.
//     The config path is plain argv[1]; there are NO command-line flags.
//   * SEB cannot be run portable -- it must be installed, because the Windows
//     service (`SafeExamBrowser`, LocalSystem) does the Ctrl+Alt+Del lockdown
//     and privilege work.
//   * There is no `startURLs` array: the target URL must be inside the config.
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { logger } from '../config.mjs';
import { sha256Hex } from '../security/crypto.mjs';

const log = logger('seb');

const CANDIDATE_PATHS = [
  'C:\\Program Files\\SafeExamBrowser\\Application\\SafeExamBrowser.exe',
  'C:\\Program Files (x86)\\SafeExamBrowser\\Application\\SafeExamBrowser.exe',
  join(process.env.ProgramFiles ?? 'C:\\Program Files', 'SafeExamBrowser', 'Application', 'SafeExamBrowser.exe'),
  join(process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)', 'SafeExamBrowser', 'Application', 'SafeExamBrowser.exe'),
];

/** Minimum SEB build we are willing to run. 3.10.2 is what we verified against. */
export const MIN_SEB_VERSION = [3, 10, 0];

export function findSebExecutable(explicitPath = process.env.RAZOR_SEB_EXE) {
  if (explicitPath) {
    if (!existsSync(explicitPath)) {
      return { ok: false, reason: 'not-found', detail: `RAZOR_SEB_EXE does not exist: ${explicitPath}` };
    }
    return { ok: true, path: explicitPath };
  }
  for (const candidate of CANDIDATE_PATHS) {
    if (existsSync(candidate)) return { ok: true, path: candidate };
  }
  return {
    ok: false,
    reason: 'not-installed',
    detail: 'Safe Exam Browser not found. Install SEB (it has no portable mode).',
  };
}

/**
 * Read the SEB file version and signature state.
 *
 * Deliberately implemented by parsing the PE image rather than shelling out to
 * PowerShell: `powershell.exe` is not guaranteed to be on PATH (it is not, in
 * the environment this was developed in), and an exam launcher should not
 * depend on it being reachable.
 *
 * What "signed" means here: the PE optional header carries a non-zero
 * certificate-table directory, i.e. the image contains an Authenticode
 * signature. That is a *structural* check. Full cryptographic validation needs
 * WinVerifyTrust via native bindings, which this build does not include -- see
 * docs/security.md.
 */
export function inspectSebBinary(path) {
  const info = { path, exists: existsSync(path) };

  if (!info.exists) return { ...info, ok: false, reason: 'not-found' };

  let buffer;
  try {
    buffer = readFileSync(path);
    info.bytes = statSync(path).size;
  } catch (err) {
    return { ...info, ok: false, reason: 'unreadable', detail: err.message };
  }

  try {
    const pe = parsePe(buffer);
    info.machine = pe.machine;
    info.signaturePresent = pe.signatureSize > 0;
    info.signatureSize = pe.signatureSize;
    info.subsystem = pe.subsystem;
  } catch (err) {
    info.peError = err.message;
    return { ...info, ok: false, reason: 'not-a-pe', detail: err.message };
  }

  // Prefer the version resource's own FileVersion entry. Falling back to
  // scanning the image for the highest `n.n.n.n` is unreliable: SEB ships
  // bundled Chromium/CEF components whose versions outrank its own.
  info.fileVersion = findStringTableValue(buffer, 'FileVersion');
  info.version = parseVersion(info.fileVersion) ? info.fileVersion : findVersionString(buffer);
  const company = findStringTableValue(buffer, 'CompanyName');
  info.company = company;
  info.product = findStringTableValue(buffer, 'ProductName');
  info.signedByEth = /ETH|Z[üu]rich|Safe Exam Browser/i.test(String(company ?? ''));

  const version = parseVersion(info.version);
  info.versionTuple = version;
  if (version && compareVersions(version, MIN_SEB_VERSION) < 0) {
    return {
      ...info,
      ok: false,
      reason: 'too-old',
      detail: `SEB ${info.version} is older than the required ${MIN_SEB_VERSION.join('.')}`,
    };
  }
  if (!info.signaturePresent) {
    return {
      ...info,
      ok: false,
      reason: 'unsigned',
      detail: 'the image carries no Authenticode signature',
    };
  }

  return { ...info, ok: true };
}

/**
 * Minimal PE parser: enough to reach the optional header's certificate table
 * entry (data directory index 4) and the machine/subsystem fields.
 */
function parsePe(buffer) {
  if (buffer.length < 0x40) throw new Error('file too small to be a PE image');
  if (buffer.readUInt16LE(0) !== 0x5a4d) throw new Error('missing MZ signature'); // "MZ"

  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 24 > buffer.length) throw new Error('PE header offset out of range');
  if (buffer.readUInt32LE(peOffset) !== 0x00004550) throw new Error('missing PE signature'); // "PE\0\0"

  const machine = buffer.readUInt16LE(peOffset + 4);
  const optionalHeaderOffset = peOffset + 24;
  const magic = buffer.readUInt16LE(optionalHeaderOffset);
  if (magic !== 0x10b && magic !== 0x20b) throw new Error(`unexpected optional header magic 0x${magic.toString(16)}`);

  const subsystem = buffer.readUInt16LE(optionalHeaderOffset + 68);
  // Data directories start at +96 for PE32 and +112 for PE32+.
  const dataDirOffset = optionalHeaderOffset + (magic === 0x20b ? 112 : 96);
  // Index 4 is IMAGE_DIRECTORY_ENTRY_SECURITY.
  const securityEntry = dataDirOffset + 4 * 8;
  let signatureSize = 0;
  if (securityEntry + 8 <= buffer.length) {
    const virtualAddress = buffer.readUInt32LE(securityEntry);
    signatureSize = virtualAddress ? buffer.readUInt32LE(securityEntry + 4) : 0;
  }

  return { machine, subsystem, signatureSize };
}

/** Find the first `n.n.n.n` version-like string in the image. */
function findVersionString(buffer) {
  const candidates = [];
  const re = /(\d+\.\d+\.\d+\.\d+)/g;
  const ascii = buffer.toString('latin1');
  let match;
  while ((match = re.exec(ascii)) !== null) {
    candidates.push(match[1]);
    if (candidates.length > 400) break;
  }
  if (!candidates.length) return null;
  // SEB's real file version is the highest one found, not the first (the
  // resource section also carries compiler and manifest versions).
  return candidates.sort((a, b) => compareVersions(parseVersion(b), parseVersion(a)))[0];
}

/** Read a value out of the version resource's StringFileInfo block. */
function findStringTableValue(buffer, key) {
  // The version resource stores keys and values as UTF-16LE, padded to 4 bytes.
  const needle = Buffer.from(key, 'utf16le');
  const index = buffer.indexOf(needle);
  if (index < 0) return null;
  // Layout: key (UTF-16LE, NUL-terminated, 4-byte aligned) then the value.
  let cursor = index + needle.length;
  cursor += (4 - (cursor % 4)) % 4;
  // Skip the UTF-16 NUL terminator of the key, then realign.
  if (buffer.readUInt16LE(cursor) === 0) cursor += 2;
  cursor += (4 - (cursor % 4)) % 4;

  let end = cursor;
  while (end + 1 < buffer.length && buffer.readUInt16LE(end) !== 0) end += 2;
  const value = buffer.subarray(cursor, end).toString('utf16le').trim();
  return value || null;
}

export function parseVersion(text) {
  if (!text) return null;
  const match = /(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?/.exec(String(text));
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4] ?? 0)];
}

function compareVersions(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

export function fileSha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/**
 * Build the exact argv SEB expects. Kept separate from spawning so
 * `--seb-argv-only` can print it without locking the desktop.
 */
export function buildSebArgv({ executable, configPath }) {
  return {
    command: executable,
    args: [configPath],
    // Windows quoting rules for a path with spaces, which Program Files has.
    printable: `"${executable}" "${configPath}"`,
  };
}

/**
 * Launch SEB. Returns a handle; the caller decides what to do on exit.
 *
 * `detached: false` on purpose: we want the child's exit to be observable so a
 * quit, crash or kill can end the lease instead of silently leaving a session
 * open.
 */
export function launchSeb({ executable, configPath, onExit, cwd = undefined }) {
  const argv = buildSebArgv({ executable, configPath });
  log.info(`launching: ${argv.printable}`);

  const child = spawn(argv.command, argv.args, {
    cwd: cwd ?? undefined,
    detached: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: false,
  });

  const result = { pid: child.pid, argv, startedAt: Date.now(), exited: null };

  child.stdout?.on('data', (chunk) => log.debug(`seb stdout: ${String(chunk).trim()}`));
  child.stderr?.on('data', (chunk) => log.debug(`seb stderr: ${String(chunk).trim()}`));

  child.on('error', (err) => {
    result.error = err.message;
    log.error(`SEB failed to start: ${err.message}`);
    onExit?.({ ...result, code: null, signal: null, error: err.message });
  });

  child.on('exit', (code, signal) => {
    result.exited = { at: Date.now(), code, signal };
    log.info(`SEB exited (code=${code}, signal=${signal}) after ${result.exited.at - result.startedAt} ms`);
    onExit?.({ ...result, code, signal });
  });

  return { ...result, child, kill: () => child.kill() };
}

/** Stop SEB without a password prompt. Used by admin stop and by shutdown. */
export function killSebProcesses() {
  if (process.platform !== 'win32') return false;
  try {
    execFileSync('taskkill', ['/IM', 'SafeExamBrowser.exe', '/T', '/F'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    return true;
  } catch (err) {
    log.warn(`taskkill SafeExamBrowser returned: ${err.message}`);
    return false;
  }
}

export { sha256Hex };
