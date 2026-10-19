// Windows path-confinement tests.
//
// Every rejection case here is a real historical escape technique, not a
// theoretical one. The junction case is the important one: an admin-created
// junction inside the workspace is the canonical way to walk a "rooted" file
// API out of its root.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PathRejected, Workspace, seedWorkspace } from '../src/files.mjs';

let base;
let workspace;
let outside;

before(() => {
  base = mkdtempSync(join(tmpdir(), 'razor-files-'));
  outside = join(base, 'outside');
  mkdirSync(outside, { recursive: true });
  writeFileSync(join(outside, 'secret.txt'), 'this must never be readable\n', 'utf8');

  workspace = new Workspace(join(base, 'workspace'));
  mkdirSync(join(workspace.root, 'src'), { recursive: true });
  writeFileSync(join(workspace.root, 'src', 'main.py'), 'print("hi")\n', 'utf8');
});

after(() => {
  try {
    rmSync(base, { recursive: true, force: true });
  } catch {
    /* Windows sometimes holds a handle briefly */
  }
});

const rejects = (input, reason) => {
  assert.throws(
    () => workspace.resolveSafe(input),
    (err) => {
      assert.ok(err instanceof PathRejected, `expected PathRejected, got ${err.name}: ${err.message}`);
      if (reason) assert.equal(err.reason, reason);
      return true;
    },
    `expected "${input}" to be rejected`,
  );
};

test('ordinary relative paths resolve inside the workspace', () => {
  const resolved = workspace.resolveSafe('src/main.py', { mustExist: true });
  assert.equal(resolved, join(workspace.root, 'src', 'main.py'));
  assert.equal(workspace.toRelative(resolved), 'src/main.py');
});

test('traversal is rejected', () => {
  rejects('..\\outside\\secret.txt', 'traversal');
  rejects('src/../../outside/secret.txt', 'traversal');
  rejects('..', 'traversal');
});

test('absolute paths are rejected', () => {
  rejects('C:\\Windows\\System32\\drivers\\etc\\hosts', 'absolute-path');
  rejects('C:\\', 'absolute-path');
});

test('drive-relative paths are rejected', () => {
  // "C:foo" resolves against that drive's current directory, not ours.
  rejects('C:foo.txt', 'absolute-path');
});

test('UNC and extended-length paths are rejected', () => {
  rejects('\\\\server\\share\\payload.exe', 'unc-or-extended');
  rejects('\\\\?\\C:\\Windows\\System32', 'unc-or-extended');
  rejects('//server/share', 'unc-or-extended');
});

test('alternate data streams are rejected', () => {
  rejects('src/main.py:hidden', 'alternate-data-stream');
  rejects('notes.txt:$DATA', 'alternate-data-stream');
});

test('reserved device names are rejected', () => {
  for (const name of ['CON', 'NUL', 'AUX', 'COM1', 'LPT1', 'con.txt', 'NUL.txt']) {
    rejects(name, 'reserved-name');
  }
});

test('characters Windows forbids are rejected', () => {
  rejects('bad<name>.txt', 'invalid-character');
  rejects('bad|name.txt', 'invalid-character');
});

test('null bytes and non-strings are rejected', () => {
  rejects('src/main.py\u0000.txt', 'null-byte');
  rejects('', 'empty');
  assert.throws(() => workspace.resolveSafe({ path: 'x' }), PathRejected);
});

test('a symlink pointing outside the workspace is rejected', () => {
  const link = join(workspace.root, 'escape-link');
  try {
    symlinkSync(outside, link, 'junction');
  } catch (err) {
    // Creating links needs elevation or Developer Mode; skip rather than lie.
    console.log(`# skipped symlink case: ${err.message}`);
    return;
  }

  assert.throws(
    () => workspace.resolveSafe('escape-link/secret.txt', { mustExist: true }),
    (err) => err instanceof PathRejected && /escaped|symlink/.test(err.reason),
  );
  rmSync(link, { recursive: true, force: true });
});

test('an admin-created junction cannot be used for write-outside', (t) => {
  const link = join(workspace.root, 'junction-escape');
  let created = false;
  try {
    execFileSync('cmd', ['/c', 'mklink', '/J', link, outside], { stdio: 'ignore', windowsHide: true });
    created = true;
  } catch (err) {
    t.diagnostic(`mklink /J unavailable (${err.message}); junction case not exercised on this host`);
  }
  if (!created) return;

  try {
    assert.throws(
      () => workspace.resolveSafe('junction-escape/secret.txt', { mustExist: true }),
      (err) => err instanceof PathRejected && /escaped|symlink/.test(err.reason),
    );
    assert.throws(() => workspace.write('junction-escape/pwned.txt', 'nope'), PathRejected);
    assert.equal(readFileSync(join(outside, 'secret.txt'), 'utf8').includes('never be readable'), true);
  } finally {
    rmSync(link, { recursive: true, force: true });
  }
});

test('reading a file outside the workspace is impossible via the API', () => {
  assert.throws(() => workspace.read('..\\outside\\secret.txt'), PathRejected);
});

test('binary files are refused by the editor API', () => {
  const binary = join(workspace.root, 'blob.bin');
  writeFileSync(binary, Buffer.from([0x00, 0x01, 0x02, 0x03]));
  assert.throws(() => workspace.read('blob.bin'), (err) => err.reason === 'binary-file');
});

test('oversized files are refused by the editor API', () => {
  const big = join(workspace.root, 'big.txt');
  writeFileSync(big, 'x'.repeat(3 * 1024 * 1024));
  assert.throws(() => workspace.read('big.txt'), (err) => err.reason === 'too-large');
});

test('writes are atomic and readable back', () => {
  const result = workspace.write('deep/nested/new.txt', 'content\n');
  assert.equal(result.path, 'deep/nested/new.txt');
  assert.equal(workspace.read('deep/nested/new.txt').content, 'content\n');
  // No temp files left behind.
  const listing = workspace.list('.', { depth: 6 });
  assert.equal(listing.entries.some((e) => e.path.includes('.razor-tmp-')), false);
});

test('removing the workspace root is refused', () => {
  assert.throws(() => workspace.remove('.'), (err) => err.reason === 'refuse-root');
});

test('listing is depth-limited and hides nothing unexpected', () => {
  const listing = workspace.list('.', { depth: 2 });
  const paths = listing.entries.map((e) => e.path);
  assert.ok(paths.includes('src'));
  assert.ok(paths.includes('src/main.py'));
  assert.ok(!paths.includes('src/main.py:hidden'));
});

test('seeding is idempotent and does not clobber edits', () => {
  const root = join(base, 'seed-workspace');
  const seeded = new Workspace(root);
  seedWorkspace(seeded);
  assert.ok(readFileSync(join(root, 'hello.py'), 'utf8').includes('greet'));

  seeded.write('hello.py', '# my work\n');
  seedWorkspace(seeded);
  assert.equal(readFileSync(join(root, 'hello.py'), 'utf8'), '# my work\n');
});
