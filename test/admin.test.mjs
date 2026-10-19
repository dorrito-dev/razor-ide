// Admin-surface unit tests: Host/Origin validation, Basic auth, SEB request
// verification, and admin credential resolution in each mode.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { authenticateAdmin, resolveAdminCredentials, verifyHostAndOrigin, verifySebRequest } from '../src/admin.mjs';
import { sebConfigKey, sebRequestHash } from '../src/security/crypto.mjs';

// ---------------------------------------------------------------------------
// Host / Origin
// ---------------------------------------------------------------------------

test('loopback Host headers are accepted', () => {
  for (const host of ['127.0.0.1:8080', 'localhost:8080', '[::1]:8080']) {
    const result = verifyHostAndOrigin({ hostHeader: host, originHeader: null, port: 8080 });
    assert.equal(result.ok, true, `${host} should be accepted`);
  }
});

test('a missing Host header is refused', () => {
  const result = verifyHostAndOrigin({ hostHeader: undefined, originHeader: null, port: 8080 });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'missing-host');
});

test('foreign Host headers are refused (DNS rebinding)', () => {
  for (const host of ['evil.example.com', '127.0.0.1:9999', 'attacker.local:8080']) {
    const result = verifyHostAndOrigin({ hostHeader: host, originHeader: null, port: 8080 });
    assert.equal(result.ok, false, `${host} should be refused`);
    assert.equal(result.reason, 'bad-host');
  }
});

test('a foreign Origin is refused (cross-site WebSocket hijacking)', () => {
  const result = verifyHostAndOrigin({
    hostHeader: '127.0.0.1:8080',
    originHeader: 'http://evil.example.com',
    port: 8080,
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'bad-origin');
});

test('a loopback Origin is accepted, with or without a trailing slash', () => {
  for (const origin of ['http://127.0.0.1:8080', 'http://127.0.0.1:8080/', 'http://localhost:8080']) {
    const result = verifyHostAndOrigin({ hostHeader: '127.0.0.1:8080', originHeader: origin, port: 8080 });
    assert.equal(result.ok, true, `${origin} should be accepted`);
  }
});

test('a null Origin (non-browser client) is allowed through to auth', () => {
  const result = verifyHostAndOrigin({ hostHeader: '127.0.0.1:8080', originHeader: null, port: 8080 });
  assert.equal(result.ok, true);
});

test('extra allowed hosts can be configured explicitly', () => {
  const result = verifyHostAndOrigin({
    hostHeader: 'exam-pc.lan:8080',
    originHeader: 'http://exam-pc.lan:8080',
    port: 8080,
    allowExtraHosts: ['exam-pc.lan:8080'],
  });
  assert.equal(result.ok, true);
});

// ---------------------------------------------------------------------------
// Admin auth
// ---------------------------------------------------------------------------

const credentials = { ok: true, user: 'admin', secret: 'correct horse battery staple' };

test('correct Basic credentials authenticate', () => {
  const header = `Basic ${Buffer.from('admin:correct horse battery staple').toString('base64')}`;
  assert.equal(authenticateAdmin(header, credentials), 'admin');
});

test('wrong password, wrong user and malformed headers do not authenticate', () => {
  const wrongPass = `Basic ${Buffer.from('admin:nope').toString('base64')}`;
  const wrongUser = `Basic ${Buffer.from('root:correct horse battery staple').toString('base64')}`;
  assert.equal(authenticateAdmin(wrongPass, credentials), null);
  assert.equal(authenticateAdmin(wrongUser, credentials), null);
  assert.equal(authenticateAdmin('Basic !!!not-base64!!!', credentials), null);
  assert.equal(authenticateAdmin('Basic ' + Buffer.from('nocolon').toString('base64'), credentials), null);
  assert.equal(authenticateAdmin(undefined, credentials), null);
  assert.equal(authenticateAdmin('Bearer something', credentials), null);
});

test('a bearer token also authenticates', () => {
  assert.equal(authenticateAdmin('Bearer correct horse battery staple', credentials), 'admin');
});

test('a failed credential resolution authenticates nobody', () => {
  assert.equal(authenticateAdmin('Basic YWRtaW46eA==', { ok: false }), null);
});

// ---------------------------------------------------------------------------
// Admin credential resolution
// ---------------------------------------------------------------------------

test('production requires explicit credentials and never generates a default', () => {
  const savedEnv = { ...process.env };
  try {
    delete process.env.RAZOR_ADMIN_PASS;
    delete process.env.RAZOR_ADMIN_TOKEN;
    const result = resolveAdminCredentials({ mode: 'production' });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'production-requires-credentials');
    assert.match(result.detail, /RAZOR_ADMIN_PASS/);
  } finally {
    Object.assign(process.env, savedEnv);
  }
});

test('RAZOR_ADMIN_PASS is accepted in production', () => {
  const saved = process.env.RAZOR_ADMIN_PASS;
  const savedToken = process.env.RAZOR_ADMIN_TOKEN;
  try {
    delete process.env.RAZOR_ADMIN_TOKEN;
    process.env.RAZOR_ADMIN_PASS = 'explicit';
    const result = resolveAdminCredentials({ mode: 'production' });
    assert.equal(result.ok !== false, true);
    assert.equal(result.secret, 'explicit');
    assert.equal(result.kind, 'basic');
  } finally {
    if (saved === undefined) delete process.env.RAZOR_ADMIN_PASS;
    else process.env.RAZOR_ADMIN_PASS = saved;
    if (savedToken !== undefined) process.env.RAZOR_ADMIN_TOKEN = savedToken;
  }
});

// ---------------------------------------------------------------------------
// SEB request verification
// ---------------------------------------------------------------------------

const CONFIG_KEY = sebConfigKey({ startURL: 'http://127.0.0.1:8080/?b=x' });

test('a correct Config Key header verifies', () => {
  const absoluteUrl = 'http://127.0.0.1:8080/api/state';
  const result = verifySebRequest({
    headers: { 'x-safeexambrowser-configkeyhash': sebRequestHash(absoluteUrl, CONFIG_KEY) },
    absoluteUrl,
    expectedConfigKeyHash: CONFIG_KEY,
    requireAttestation: true,
  });
  assert.equal(result.ok, true);
  assert.equal(result.attestation, 'verified');
  assert.equal(result.enforced, true);
});

test('a wrong Config Key header is refused', () => {
  const absoluteUrl = 'http://127.0.0.1:8080/api/state';
  const result = verifySebRequest({
    headers: { 'x-safeexambrowser-configkeyhash': 'f'.repeat(64) },
    absoluteUrl,
    expectedConfigKeyHash: CONFIG_KEY,
    requireAttestation: true,
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'config-key-mismatch');
});

test('a header computed for a different URL is refused', () => {
  const result = verifySebRequest({
    headers: { 'x-safeexambrowser-configkeyhash': sebRequestHash('http://127.0.0.1:8080/other', CONFIG_KEY) },
    absoluteUrl: 'http://127.0.0.1:8080/api/state',
    expectedConfigKeyHash: CONFIG_KEY,
    requireAttestation: true,
  });
  assert.equal(result.ok, false);
});

test('production refuses a request with no attestation header at all', () => {
  const result = verifySebRequest({
    headers: {},
    absoluteUrl: 'http://127.0.0.1:8080/api/state',
    expectedConfigKeyHash: CONFIG_KEY,
    requireAttestation: true,
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'missing-config-key-header');
});

test('dev records absent attestation instead of refusing', () => {
  const result = verifySebRequest({
    headers: {},
    absoluteUrl: 'http://127.0.0.1:8080/api/state',
    expectedConfigKeyHash: CONFIG_KEY,
    requireAttestation: false,
  });
  assert.equal(result.ok, true);
  assert.equal(result.attestation, 'absent');
  assert.equal(result.enforced, false);
});

test('production refuses if no expected Config Key was configured', () => {
  const absoluteUrl = 'http://127.0.0.1:8080/api/state';
  const result = verifySebRequest({
    headers: { 'x-safeexambrowser-configkeyhash': 'a'.repeat(64) },
    absoluteUrl,
    expectedConfigKeyHash: null,
    requireAttestation: true,
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'no-expected-config-key-configured');
});

test('the BEK (request hash) header is deliberately not trusted as a config key', () => {
  // X-SafeExamBrowser-RequestHash cannot be computed server-side, so presenting
  // it must not satisfy Config Key attestation.
  const absoluteUrl = 'http://127.0.0.1:8080/api/state';
  const result = verifySebRequest({
    headers: { 'x-safeexambrowser-requesthash': sebRequestHash(absoluteUrl, CONFIG_KEY) },
    absoluteUrl,
    expectedConfigKeyHash: CONFIG_KEY,
    requireAttestation: true,
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'missing-config-key-header');
});
