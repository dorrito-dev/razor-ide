// SEB container round-trip + Config Key tests.
//
// What these prove: our writer and reader agree, and the Config Key we compute
// is stable and sensitive to the things SEB says it is sensitive to.
//
// What these do NOT prove: that the real SEB client loads our file. No
// in-process test can prove that. `tools/verify-seb-config.mjs` exists for that
// and requires a human watching a real SEB launch -- see docs/security.md.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gunzipSync, gzipSync } from 'node:zlib';
import { Prefix, decodePlain, encodePlain, inspectContainer } from '../src/seb/container.mjs';
import { buildDocument, parsePlistXml, roundReal, toPlistXml } from '../src/seb/plist.mjs';
import { buildSebPolicy, validateSebPolicy } from '../src/seb/config.mjs';
import { sebConfigKey, sebPasswordHash, sebRequestHash } from '../src/security/crypto.mjs';

const START_URL = 'http://127.0.0.1:41234/?b=abc123';

function samplePolicy(overrides = {}) {
  return buildSebPolicy({
    startUrl: START_URL,
    quitPassword: 'per-session-quit-secret',
    mode: 'production',
    ...overrides,
  });
}

test('the container is gzip("plnd" + gzip(xml))', () => {
  const buffer = encodePlain(samplePolicy());
  const outer = gunzipSync(buffer);
  assert.equal(outer.subarray(0, 4).toString('ascii'), Prefix.Plain);

  const xml = gunzipSync(outer.subarray(4)).toString('utf8');
  assert.match(xml, /^<\?xml version="1.0" encoding="UTF-8"\?>/);
  assert.match(xml, /<key>startURL<\/key>/);
});

test('a written container reads back to the same policy', () => {
  const policy = samplePolicy();
  const { plist } = decodePlain(encodePlain(policy));

  assert.equal(plist.startURL, START_URL);
  assert.equal(plist.browserViewMode, policy.browserViewMode);
  assert.equal(plist.hashedQuitPassword, policy.hashedQuitPassword);
  assert.deepEqual(plist.URLFilterRules, policy.URLFilterRules);
});

test('inspectContainer reports plain vs encrypted without decrypting', () => {
  const plain = inspectContainer(encodePlain(samplePolicy()));
  assert.equal(plain.ok, true);
  assert.equal(plain.prefix, 'plnd');
  assert.equal(plain.encrypted, false);

  const fakeEncrypted = gzipSync(Buffer.concat([Buffer.from('pswd', 'ascii'), Buffer.from([1, 2, 3])]));
  const encrypted = inspectContainer(fakeEncrypted);
  assert.equal(encrypted.ok, true);
  assert.equal(encrypted.prefix, 'pswd');
  assert.equal(encrypted.encrypted, true);

  assert.equal(inspectContainer(Buffer.from('not gzip at all')).ok, false);
});

test('plist writer escapes XML and sorts keys deterministically', () => {
  const xml = buildDocument({ zeta: 'a & b < c', alpha: true });
  assert.match(xml, /a &amp; b &lt; c/);
  assert.ok(xml.indexOf('<key>alpha</key>') < xml.indexOf('<key>zeta</key>'));
});

test('plist parser round-trips every type SEB uses', () => {
  const original = {
    aString: 'hello <world>',
    aBool: true,
    aFalse: false,
    anInt: 42,
    aReal: { __type: 'real', value: 0.1 },
    anArray: [1, 'two', false],
    aNested: { inner: { deep: 'value' } },
  };
  const parsed = parsePlistXml(buildDocument(original));

  assert.equal(parsed.aString, 'hello <world>');
  assert.equal(parsed.aBool, true);
  assert.equal(parsed.aFalse, false);
  assert.equal(parsed.anInt, 42);
  assert.deepEqual(parsed.aReal, { __type: 'real', value: 0.1 });
  assert.deepEqual(parsed.anArray, [1, 'two', false]);
  assert.equal(parsed.aNested.inner.deep, 'value');
});

test('floats are rounded so IEEE noise cannot change the Config Key', () => {
  assert.equal(roundReal(0.10000000000000001), '0.1');
  assert.equal(roundReal(1), '1');
  assert.equal(roundReal(0.3333333333333333), '0.333333333333');
});

// ---------------------------------------------------------------------------
// Config Key
// ---------------------------------------------------------------------------

test('the Config Key is 64 lowercase hex characters', () => {
  assert.match(sebConfigKey(samplePolicy()), /^[0-9a-f]{64}$/);
});

test('originatorVersion is exempt from the Config Key', () => {
  const policy = samplePolicy();
  const withVersion = { ...policy, originatorVersion: '3.10.0' };
  const withOtherVersion = { ...policy, originatorVersion: '3.9.0' };
  assert.equal(sebConfigKey(withVersion), sebConfigKey(withOtherVersion));
});

test('the Config Key changes when a security-relevant setting changes', () => {
  const base = sebConfigKey(samplePolicy());
  assert.notEqual(sebConfigKey(samplePolicy({ quitPassword: 'different' })), base);
  assert.notEqual(sebConfigKey(samplePolicy({ startUrl: 'http://127.0.0.1:1/?b=x' })), base);
  // Production enforcement forces fullscreen (createNewDesktop wins over a
  // windowed request), so the desktop setting -- not `windowed` -- is the one
  // that moves the key here.
  assert.notEqual(sebConfigKey(samplePolicy({ hardened: false, mode: 'dev' })), base);
  // In dev the view mode is still a real difference and must be hashed.
  const devBase = sebConfigKey(samplePolicy({ mode: 'dev' }));
  assert.notEqual(sebConfigKey(samplePolicy({ mode: 'dev', windowed: true })), devBase);
});

test('the Config Key is independent of key insertion order', () => {
  const policy = samplePolicy();
  const reversed = Object.fromEntries(Object.entries(policy).reverse());
  assert.equal(sebConfigKey(policy), sebConfigKey(reversed));
});

test('the request hash is URL-first per the documented construction', () => {
  const configKey = sebConfigKey(samplePolicy());
  const url = 'http://127.0.0.1:41234/api/state';
  const hash = sebRequestHash(url, configKey);
  assert.match(hash, /^[0-9a-f]{64}$/);
  // Fragments are stripped before hashing.
  assert.equal(hash, sebRequestHash(`${url}#section`, configKey));
  assert.notEqual(hash, sebRequestHash(`${url}?x=1`, configKey));
});

test('the password hash is a bare SHA-256 hex digest', () => {
  // Documented shape: 64 lowercase hex, matching SEB's published example value.
  assert.match(sebPasswordHash('hunter2'), /^[0-9a-f]{64}$/);
  assert.equal(sebPasswordHash('hunter2'), sebPasswordHash('hunter2'));
  assert.notEqual(sebPasswordHash('hunter2'), sebPasswordHash('hunter3'));
});

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

test('production disables the escape hatches', () => {
  const policy = samplePolicy();
  assert.equal(policy.allowQuit, false);
  assert.equal(policy.enableAltTab, false);
  assert.equal(policy.enableCtrlEsc, false);
  assert.equal(policy.enableStartMenu, false);
  assert.equal(policy.allowDownloads, false);
  assert.equal(policy.allowScreenSharing, false);
  assert.equal(policy.allowVirtualMachine, false);
  assert.equal(policy.allowDeveloperConsole, false);
  assert.equal(policy.downloadAndOpenSebConfig, false);
  assert.equal(policy.examSessionReconfigureAllow, false);
  assert.equal(policy.killExplorerShell, true);
});

test('dev is deliberately more permissive', () => {
  const policy = samplePolicy({ mode: 'dev', enableDevConsole: true });
  assert.equal(policy.allowQuit, true);
  assert.equal(policy.allowVirtualMachine, true);
  assert.equal(policy.allowDeveloperConsole, true);
  assert.equal(policy.killExplorerShell, false);
});

test('the loopback origin is explicitly allowed over http and ws', () => {
  const rules = samplePolicy().URLFilterRules;
  const expressions = rules.map((r) => r.expression);
  assert.ok(expressions.includes('127.0.0.1:41234'));
  assert.ok(expressions.includes('http://127.0.0.1:41234'));
  assert.ok(expressions.includes('ws://127.0.0.1:41234'));
  assert.ok(rules.every((r) => r.action === 1 && r.active === true));
});

test('legacy and Apple-only keys are not emitted', () => {
  const policy = samplePolicy();
  for (const forbidden of [
    'startURLs',
    'openLinksInNewWindow',
    'activeExamMode',
    'allowSwitchToApplications',
    'blockPopUpWindows',
    'enableJavaScript',
    'allowScreenCapture',
    'allowWindowCapture',
    'quitPassword',
  ]) {
    assert.equal(policy[forbidden], undefined, `${forbidden} must not appear in a Windows config`);
  }
});

test('validateSebPolicy catches the configs that would deadlock an exam', () => {
  assert.deepEqual(validateSebPolicy(samplePolicy()), []);

  // allowQuit=false with no password is the classic lockout.
  const lockout = { ...samplePolicy(), hashedQuitPassword: undefined };
  assert.ok(validateSebPolicy(lockout).some((p) => /unquittable/.test(p)));

  // A hostname instead of 127.0.0.1 makes URL-filter matching ambiguous.
  const hostname = { ...samplePolicy(), startURL: 'http://localhost:41234/?b=x' };
  assert.ok(validateSebPolicy(hostname).some((p) => /127\.0\.0\.1/.test(p)));

  // Filtering on with no allow rule blocks the IDE itself.
  const noRules = { ...samplePolicy(), URLFilterRules: [] };
  assert.ok(validateSebPolicy(noRules).some((p) => /allow rule/.test(p)));
});

test('a malformed password hash is rejected before it reaches SEB', () => {
  const bad = { ...samplePolicy(), hashedQuitPassword: 'not-a-hash' };
  assert.ok(validateSebPolicy(bad).some((p) => /64 lowercase hex/.test(p)));
});

test('toPlistXml refuses values the plist format cannot express', () => {
  assert.throws(() => toPlistXml({ bad: Number.NaN }), /non-finite/);
  assert.throws(() => toPlistXml({ bad: () => {} }), /unsupported plist value/);
});
