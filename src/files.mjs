// Workspace file API.
//
// Windows path confinement is harder than it looks. Every one of these cases is
// rejected or canonicalised, because each has historically been used to escape a
// "rooted" file API:
//
//   * NT namespace  \\?\C:\...        -> bypasses normalisation entirely
//   * UNC           \\server\share    -> goes to the network
//   * device paths  \\.\C:            -> raw volume access
//   * drive-relative C:foo            -> resolves against that drive's CWD
//   * alternate data streams  file.txt:secret  -> hidden content, hidden size
//   * reserved device names   CON, NUL, COM1   -> not files at all
//   * 8.3 short aliases       PROGRA~1          -> defeats string comparisons
//   * junctions / symlinks    out\ -> C:\      -> the classic escape
//
// The rule is: reject on shape, then canonicalise with realpath, then verify
// containment of the canonical path against the canonical root.
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';

export class PathRejected extends Error {
  constructor(reason, detail) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = 'PathRejected';
    this.reason = reason;
  }
}

const WINDOWS_RESERVED = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
]);

export const MAX_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_TREE_ENTRIES = 5_000;

export class Workspace {
  #root;

  constructor(root) {
    if (!existsSync(root)) mkdirSync(root, { recursive: true });
    this.#root = realpathSync(root);
  }

  get root() {
    return this.#root;
  }

  /**
   * Resolve a client-supplied relative path to an absolute path inside the
   * workspace, or throw PathRejected.
   */
  resolveSafe(input, { mustExist = false } = {}) {
    if (typeof input !== 'string') throw new PathRejected('not-a-string');
    if (input.length === 0) throw new PathRejected('empty');
    if (input.length > 4096) throw new PathRejected('too-long');
    if (input.includes('\0')) throw new PathRejected('null-byte');

    const normalised = input.replace(/\//g, '\\');

    if (normalised.startsWith('\\\\')) {
      throw new PathRejected('unc-or-extended', 'UNC and \\\\?\\ paths are not permitted');
    }
    if (/^[A-Za-z]:/.test(normalised)) {
      // C:\... is absolute; C:foo is drive-relative. Neither belongs here.
      throw new PathRejected('absolute-path', 'absolute paths are not permitted');
    }
    if (normalised.startsWith('\\')) {
      throw new PathRejected('rooted-path', 'root-relative paths are not permitted');
    }

    for (const segment of normalised.split(/[\\/]+/)) {
      if (!segment || segment === '.') continue;
      if (segment === '..') throw new PathRejected('traversal');
      if (segment.includes(':')) {
        throw new PathRejected('alternate-data-stream', `":" is not permitted in "${segment}"`);
      }
      const bare = segment.replace(/[ .]+$/, '');
      const stem = bare.split('.')[0].toUpperCase();
      if (WINDOWS_RESERVED.has(stem)) {
        throw new PathRejected('reserved-name', `"${segment}" is a reserved device name`);
      }
      if (/[<>"|?*]/.test(segment)) {
        throw new PathRejected('invalid-character', `"${segment}" contains characters Windows forbids`);
      }
    }

    const absolute = resolve(this.#root, normalised);
    if (!this.#isInside(absolute)) throw new PathRejected('escaped-root', absolute);

    if (mustExist && !existsSync(absolute)) {
      throw new PathRejected('not-found', normalised);
    }

    // Canonicalise. For a path that does not exist yet, canonicalise the
    // deepest existing ancestor and re-append the *whole* remaining tail --
    // keeping only the basename here would silently collapse
    // "deep/nested/new.txt" to "new.txt" inside the workspace root.
    const canonical = existsSync(absolute)
      ? realpathSync(absolute)
      : this.#realpathOfAncestor(absolute, normalised);
    if (!this.#isInside(canonical)) {
      throw new PathRejected('escaped-via-link', `${normalised} resolves outside the workspace`);
    }
    // Check every component from the root down, whether or not it exists yet.
    this.#assertNoReparsePoints(relative(this.#root, canonical));

    return canonical;
  }

  /** Relative POSIX-style path for display and for the client. */
  toRelative(absolute) {
    return relative(this.#root, absolute).split(sep).join('/');
  }

  #isInside(absolute) {
    if (absolute === this.#root) return true;
    return absolute.startsWith(this.#root.endsWith(sep) ? this.#root : this.#root + sep);
  }

  /**
   * Canonicalise a not-yet-existing path: resolve the deepest existing
   * ancestor, then re-append the full tail of components that do not exist.
   */
  #realpathOfAncestor(absolute, display) {
    let current = absolute;
    for (let i = 0; i < 64; i++) {
      const parent = dirname(current);
      if (parent === current) break;
      if (existsSync(parent)) {
        const tail = relative(parent, absolute);
        return tail ? join(realpathSync(parent), tail) : realpathSync(parent);
      }
      current = parent;
    }
    throw new PathRejected('no-existing-ancestor', display);
  }

  /**
   * Walk every component and refuse symlinks.
   *
   * realpath already resolved them, so a symlink surviving here points *inside*
   * the workspace -- still refused, because a candidate can retarget it later
   * and a stale check is worse than none.
   *
   * Limit: Windows directory *junctions* created without the symlink flag are
   * not distinguishable from ordinary directories by lstat alone. `realpath`
   * containment above is the real guard; see test/paths.test.mjs for the
   * junction-escape case, and docs/security.md for the residual risk.
   */
  #assertNoReparsePoints(relativePath) {
    if (!relativePath) return;
    const parts = relativePath.split(sep);
    let current = this.#root;
    for (const part of parts) {
      current = join(current, part);
      let stat;
      try {
        stat = lstatSync(current);
      } catch {
        continue; // component may not exist yet on a create path
      }
      if (stat.isSymbolicLink()) {
        throw new PathRejected('symlink', `${relativePath} traverses a symlink`);
      }
    }
  }

  // -- operations ----------------------------------------------------------

  list(inputDir = '.', { depth = 3 } = {}) {
    const dir = this.resolveSafe(inputDir, { mustExist: true });
    if (!statSync(dir).isDirectory()) throw new PathRejected('not-a-directory', inputDir);

    const entries = [];
    const walk = (current, level) => {
      if (entries.length >= MAX_TREE_ENTRIES) return;
      let dirents;
      try {
        dirents = readdirSync(current, { withFileTypes: true });
      } catch {
        return;
      }
      dirents.sort((a, b) => Number(b.isDirectory()) - Number(a.isDirectory()) || a.name.localeCompare(b.name));
      for (const dirent of dirents) {
        if (dirent.name.startsWith('.razor')) continue;
        const absolute = join(current, dirent.name);
        const rel = this.toRelative(absolute);
        if (dirent.isDirectory()) {
          entries.push({ path: rel, type: 'dir' });
          if (level + 1 < depth) walk(absolute, level + 1);
        } else if (dirent.isFile()) {
          let size = 0;
          try {
            size = statSync(absolute).size;
          } catch {
            /* ignore */
          }
          entries.push({ path: rel, type: 'file', size });
        }
      }
    };
    walk(dir, 0);
    return { root: this.#root, dir: this.toRelative(dir), entries, truncated: entries.length >= MAX_TREE_ENTRIES };
  }

  read(inputPath) {
    const absolute = this.resolveSafe(inputPath, { mustExist: true });
    const stat = statSync(absolute);
    if (!stat.isFile()) throw new PathRejected('not-a-file', inputPath);
    if (stat.size > MAX_FILE_BYTES) {
      throw new PathRejected('too-large', `${stat.size} bytes exceeds the ${MAX_FILE_BYTES} byte limit`);
    }
    const buffer = readFileSync(absolute);
    if (buffer.includes(0)) throw new PathRejected('binary-file', 'binary files cannot be opened in the editor');
    return { path: this.toRelative(absolute), content: buffer.toString('utf8'), size: stat.size, mtime: stat.mtimeMs };
  }

  /** Atomic write: temp file in the same directory, then rename. */
  write(inputPath, content) {
    if (typeof content !== 'string') throw new PathRejected('bad-content');
    const buffer = Buffer.from(content, 'utf8');
    if (buffer.byteLength > MAX_FILE_BYTES) {
      throw new PathRejected('too-large', `${buffer.byteLength} bytes exceeds the limit`);
    }
    const absolute = this.resolveSafe(inputPath);
    mkdirSync(dirname(absolute), { recursive: true });
    const temp = `${absolute}.razor-tmp-${process.pid}`;
    writeFileSync(temp, buffer);
    renameSync(temp, absolute);
    return { path: this.toRelative(absolute), size: buffer.byteLength };
  }

  mkdir(inputPath) {
    const absolute = this.resolveSafe(inputPath);
    mkdirSync(absolute, { recursive: true });
    return { path: this.toRelative(absolute), type: 'dir' };
  }

  remove(inputPath) {
    const absolute = this.resolveSafe(inputPath, { mustExist: true });
    if (absolute === this.#root) throw new PathRejected('refuse-root');
    const stat = lstatSync(absolute);
    if (stat.isDirectory()) rmSync(absolute, { recursive: true, force: true });
    else unlinkSync(absolute);
    return { path: this.toRelative(absolute), removed: true };
  }
}

/**
 * Seed the workspace with something runnable so a candidate (and our own
 * verification) is never staring at an empty tree.
 */
export function seedWorkspace(workspace, { force = false } = {}) {
  const starter = join(workspace.root, 'hello.py');
  if (force || !existsSync(starter)) {
    writeFileSync(
      starter,
      ['# Razor IDE -- scratch file', 'def greet(name: str) -> str:', '    return f"hello {name}"', '', 'print(greet("world"))', ''].join('\n'),
      'utf8',
    );
  }
  const notes = join(workspace.root, 'README.md');
  if (force || !existsSync(notes)) {
    writeFileSync(
      notes,
      [
        '# Exam workspace',
        '',
        'Files you create here are collected at the end of the session.',
        'The terminal is audited: every command is written to the session log.',
        '',
      ].join('\n'),
      'utf8',
    );
  }
  return workspace.root;
}
