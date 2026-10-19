// Tests for desktop-level kiosk enforcement.
//
// Why this matters: the dev policy set createNewDesktop=false and only killed
// the Explorer shell in production, so "SEB mode" was a fullscreen browser
// sitting on the candidate's own desktop. Observed live: Alt+Tab away, switch
// windows, close SEB -- the lockdown was cosmetic. `hardened` (and production)
// now put the browser on a dedicated SEB desktop with Explorer out of the way,
// which is the setting that actually enforces it.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ViewMode, buildSebPolicy, validateSebPolicy } from '../src/seb/config.mjs';

const START_URL = 'http://127.0.0.1:41234/?b=abc123';
const QUIT = 'per-session-quit-secret';

const policy = (overrides = {}) => buildSebPolicy({ startUrl: START_URL, quitPassword: QUIT, ...overrides });

test('a plain dev policy stays on the user desktop (no desktop takeover)', () => {
  const p = policy({ mode: 'dev' });
  assert.equal(p.createNewDesktop, false, 'dev must not seize the desktop by default');
  assert.equal(p.killExplorerShell, false);
});

test('hardened forces the enforcement keys in dev mode', () => {
  const p = policy({ mode: 'dev', hardened: true });
  assert.equal(p.createNewDesktop, true, 'a dedicated desktop is what blocks window switching');
  assert.equal(p.killExplorerShell, true);
  assert.equal(p.enableSessionVerification, true);
});

test('production is enforced without the explicit flag', () => {
  const p = policy({ mode: 'production' });
  assert.equal(p.createNewDesktop, true);
  assert.equal(p.killExplorerShell, true);
});

test('hardened keeps the kiosk quittable and usable for a rehearsal', () => {
  const p = policy({ mode: 'dev', hardened: true });
  // A rehearsal run in dev mode still has to be recoverable and must not
  // silently become production-grade in the other direction.
  assert.equal(p.allowQuit, true, 'dev stays quittable');
  assert.equal(p.allowVirtualMachine, true, 'VM policy is independent of hardened');
  assert.equal(p.allowDeveloperConsole, false, 'hardened must not ship a dev console');
  assert.equal(typeof p.hashedQuitPassword, 'string', 'the per-session quit password must be honoured');
});

test('hardened still validates cleanly', () => {
  assert.deepEqual(validateSebPolicy(policy({ mode: 'dev', hardened: true })), []);
  assert.deepEqual(validateSebPolicy(policy({ mode: 'production' })), []);
});

test('hardened overrides windowed view rather than producing a contradiction', () => {
  const p = policy({ mode: 'dev', hardened: true, windowed: true });
  assert.equal(p.browserViewMode, ViewMode.Fullscreen);
  assert.deepEqual(validateSebPolicy(p), []);
});

test('the validator catches a desktop/window contradiction if it ever appears', () => {
  const broken = { ...policy({ mode: 'dev' }), createNewDesktop: true, browserViewMode: ViewMode.Windowed };
  const problems = validateSebPolicy(broken);
  assert.ok(
    problems.some((p) => p.includes('createNewDesktop')),
    'a window on an isolated desktop is a misconfiguration and must be reported',
  );
});

test('the lockdown key set is present in every mode', () => {
  for (const opts of [{ mode: 'dev' }, { mode: 'dev', hardened: true }, { mode: 'production' }]) {
    const p = policy(opts);
    for (const key of ['enableAltTab', 'enableAltEsc', 'enableAltF4', 'enableCtrlEsc', 'enableStartMenu']) {
      assert.equal(p[key], false, `${key} must stay disabled in ${JSON.stringify(opts)}`);
    }
    assert.equal(p.monitorProcesses, true);
  }
});
