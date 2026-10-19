// Tests for the SEB binary inspection and the process-level launch refusal.
//
// The point of these is that Razor checks the SEB image it is about to lock a
// candidate's desktop with, using only built-in parsing -- no PowerShell, no
// native bindings.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { existsSync } from 'node:fs';
import {
  MIN_SEB_VERSION,
  buildSebArgv,
  findSebExecutable,
  inspectSebBinary,
  parseVersion,
} from '../src/seb/launch.mjs';

const SEB_EXE = 'C:\\Program Files\\SafeExamBrowser\\Application\\SafeExamBrowser.exe';
const HAS_SEB = process.platform === 'win32' && existsSync(SEB_EXE);

test('parseVersion extracts a four-part version', () => {
  assert.deepEqual(parseVersion('3.10.2.920'), [3, 10, 2, 920]);
  assert.deepEqual(parseVersion('3.10.2'), [3, 10, 2, 0]);
  assert.deepEqual(parseVersion('Safe Exam Browser 3.10.2.920 (x64)'), [3, 10, 2, 920]);
  assert.equal(parseVersion('no version here'), null);
  assert.equal(parseVersion(null), null);
});

test('the minimum version is pinned to the build this was verified against', () => {
  assert.deepEqual(MIN_SEB_VERSION, [3, 10, 0]);
});

test('buildSebArgv passes the config path as a bare argument', () => {
  const argv = buildSebArgv({ executable: SEB_EXE, configPath: 'C:\\Exam\\config.seb' });
  assert.equal(argv.args.length, 1, 'SEB takes exactly one argument: the config path');
  assert.equal(argv.args[0], 'C:\\Exam\\config.seb');
  // No flags of any kind -- documented and registry-corroborated.
  assert.equal(argv.args.some((a) => a.startsWith('-') || a.startsWith('/')), false);
  assert.match(argv.printable, /^".*SafeExamBrowser\.exe" ".*config\.seb"$/);
});

test('a missing SEB install is reported, not guessed at', () => {
  const result = findSebExecutable('C:\\definitely\\not\\here\\SafeExamBrowser.exe');
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'not-found');
});

test('a non-existent path fails inspection cleanly', () => {
  const result = inspectSebBinary('C:\\definitely\\not\\here\\SafeExamBrowser.exe');
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'not-found');
});

test('a non-PE file is rejected as not a PE image', () => {
  const result = inspectSebBinary(process.execPath.replace('node.exe', 'README.md'));
  // Whatever the path resolves to, the answer must be a clean refusal, never a
  // crash and never a false "ok".
  assert.equal(result.ok, false);
  assert.ok(result.reason);
});

test('the installed SEB image parses to a real version with a signature', { skip: !HAS_SEB }, () => {
  const info = inspectSebBinary(SEB_EXE);

  assert.equal(info.ok, true, `${info.reason ?? ''} ${info.detail ?? ''}`);
  assert.match(info.version, /^\d+\.\d+\.\d+\.\d+$/, `version was ${info.version}`);
  // The bundled Chromium version must not be mistaken for SEB's own.
  const major = Number(info.version.split('.')[0]);
  assert.ok(major < 10, `parsed ${info.version}; that looks like a bundled Chromium version`);
  assert.equal(info.signaturePresent, true, 'the official build is Authenticode-signed');
  assert.equal(info.signedByEth, true, `signer company was ${info.company}`);
  assert.match(info.product, /Safe Exam Browser/i);
});
