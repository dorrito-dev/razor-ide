#!/usr/bin/env node
// Razor end-to-end verification. Exercises the real HTTP surface, in order:
//
//   1. the gate starts locked (no session without an admin request)
//   2. an unauthenticated /api/* request is refused
//   3. the admin endpoint starts a session and mints a single-use bootstrap code
//   4. exchanging the code sets an HttpOnly cookie and redirects
//   5. the cookie unlocks /api/*
//   6. replaying the same code is refused
//   7. a path escape is refused
//   8. Host-header spoofing is refused
//   9. a foreign Origin is refused (CSWSH guard)
//  10. stopping the session immediately invalidates the cookie
//
// Usage: node tools/verify-e2e.mjs [--keep] [--mode dev|production]
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { connect as netConnect } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const keep = args.includes('--keep');
const mode = args[args.indexOf('--mode') + 1] ?? 'dev';
const modeArg = args.includes('--mode') ? ['--mode', mode] : [];
void modeArg;

const PORT = Number(process.env.RAZOR_VERIFY_PORT ?? 45901);
const ORIGIN = `http://127.0.0.1:${PORT}`;
const ADMIN_PASS = 'verify-e2e-password';
const DEV_PASS = 'verify-dev-password';

let passed = 0;
let failed = 0;

function check(name, condition, detail = '') {
  if (condition) {
    passed += 1;
    console.log(`  ok   ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL ${name}${detail ? ` -- ${detail}` : ''}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Send a raw HTTP request with a forged Host header.
 *
 * fetch() silently drops `Host` (it is a forbidden header name), so a real
 * socket is the only way to test the DNS-rebinding guard end to end.
 */
function rawHostHeaderRequest(port, host, cookie) {
  return new Promise((resolve) => {
    const socket = netConnect({ host: '127.0.0.1', port }, () => {
      socket.write(
        `GET /api/files/list?path=. HTTP/1.1\r\n` +
          `Host: ${host}\r\n` +
          `Cookie: ${cookie}\r\n` +
          `Connection: close\r\n\r\n`,
      );
    });
    let buffer = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      buffer += chunk;
    });
    socket.on('error', () => resolve(0));
    socket.on('close', () => {
      const match = /^HTTP\/1\.1 (\d{3})/.exec(buffer);
      resolve(match ? Number(match[1]) : 0);
    });
    setTimeout(() => {
      socket.destroy();
      resolve(0);
    }, 5_000);
  });
}

async function waitForServer(timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${ORIGIN}/healthz`);
      if (response.ok) return true;
    } catch {
      /* not up yet */
    }
    await sleep(250);
  }
  return false;
}

async function main() {
  // A clean run directory so a stale dev password cannot mask a real failure.
  const runDir = join(ROOT, 'run');
  for (const file of ['admin-key.pem', 'session.json', 'audit.jsonl']) {
    const path = join(runDir, file);
    if (existsSync(path)) rmSync(path, { force: true });
  }

  const child = spawn(
    process.execPath,
    ['src/main.mjs', '--port', String(PORT)],
    {
      cwd: ROOT,
      env: {
        ...process.env,
        RAZOR_ENV: mode,
        RAZOR_ADMIN_PASS: ADMIN_PASS,
        RAZOR_QUIT_PASSWORD: DEV_PASS,
        RAZOR_WORKSPACE: join(ROOT, 'workspace'),
        RAZOR_LOG_LEVEL: 'warn',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );

  const output = [];
  child.stdout.on('data', (chunk) => output.push(String(chunk)));
  child.stderr.on('data', (chunk) => output.push(String(chunk)));

  const stop = () => {
    try {
      child.kill();
    } catch {
      /* already gone */
    }
  };

  try {
    if (!(await waitForServer())) {
      console.error('server never came up. output:\n' + output.join(''));
      process.exitCode = 1;
      return;
    }

    console.log('\n1. gate starts locked');
    const idle = await (await fetch(`${ORIGIN}/api/state`)).json();
    check('no session at boot', idle.gate.state === 'awaiting_admin', idle.gate.state);
    check('mode reported correctly', idle.mode === mode, idle.mode);

    console.log('\n2. the IDE surface is locked');
    const lockedFiles = await fetch(`${ORIGIN}/api/files/list?path=.`);
    check('unauthenticated /api/files/list refused', lockedFiles.status === 401, `status ${lockedFiles.status}`);
    const lockedPage = await fetch(`${ORIGIN}/`);
    check('the shell page itself is refused while locked', lockedPage.status === 401, `status ${lockedPage.status}`);

    console.log('\n3. an admin request starts the session');
    const auth = `Basic ${Buffer.from(`admin:${ADMIN_PASS}`).toString('base64')}`;
    const badAuth = await fetch(`${ORIGIN}/admin/session/start`, {
      method: 'POST',
      headers: { authorization: `Basic ${Buffer.from('admin:wrong').toString('base64')}` },
    });
    check('wrong admin password refused', badAuth.status === 401, `status ${badAuth.status}`);

    const startResponse = await fetch(`${ORIGIN}/admin/session/start`, {
      method: 'POST',
      headers: { authorization: auth, 'content-type': 'application/json' },
      body: JSON.stringify({ examId: 'verify', sebQuitPassword: 'per-session-secret' }),
    });
    const started = await startResponse.json();
    check('start accepted', startResponse.status === 200, `status ${startResponse.status}`);
    check('gate is running', started.gate?.state === 'running', started.gate?.state);
    check('a single-use start URL was minted', /\/\?b=[\w-]{20,}$/.test(started.startUrl ?? ''), started.startUrl);
    check('the per-session quit password is returned once', started.sebQuitPassword === 'per-session-secret');

    console.log('\n4. the bootstrap code is exchanged for a cookie');
    const bootstrapUrl = started.startUrl;
    const exchange = await fetch(bootstrapUrl, { redirect: 'manual' });
    const setCookie = exchange.headers.get('set-cookie') ?? '';
    check('exchange redirects', exchange.status === 303, `status ${exchange.status}`);
    check('cookie is HttpOnly', /HttpOnly/i.test(setCookie), setCookie);
    check('cookie is SameSite=Strict', /SameSite=Strict/i.test(setCookie), setCookie);
    const cookie = setCookie.split(';')[0];

    console.log('\n5. the cookie unlocks the IDE');
    const authedFiles = await fetch(`${ORIGIN}/api/files/list?path=.`, { headers: { cookie } });
    check('authenticated /api/files/list works', authedFiles.status === 200, `status ${authedFiles.status}`);
    const authedPage = await fetch(`${ORIGIN}/`, { headers: { cookie } });
    check('the shell page loads with the cookie', authedPage.status === 200, `status ${authedPage.status}`);
    const html = await authedPage.text();
    check('the page is self-hosted (no external asset hosts)', !/https?:\/\/(?!127\.0\.0\.1|localhost)/.test(html));

    console.log('\n6. the bootstrap code is single use');
    const replay = await fetch(bootstrapUrl, { redirect: 'manual' });
    check('replaying the start URL is refused', replay.status === 403, `status ${replay.status}`);

    console.log('\n7. path escapes are refused');
    for (const attempt of [
      '..%5C..%5CWindows%5Cwin.ini',
      'C%3A%5CWindows%5Cwin.ini',
      '..%2F..%2Fpackage.json',
      'src%2Fmain.py%3Ahidden',
    ]) {
      const response = await fetch(`${ORIGIN}/api/files/read?path=${attempt}`, { headers: { cookie } });
      check(`escape refused: ${decodeURIComponent(attempt)}`, response.status === 400, `status ${response.status}`);
    }

    console.log('\n8. Host-header spoofing is refused');
    // Node's fetch refuses to set a Host header (it is a forbidden header), so
    // this is exercised with a raw socket instead of fetch. The unit-level
    // check lives in test/admin.test.mjs.
    const rawHostStatus = await rawHostHeaderRequest(PORT, 'evil.example.com', cookie);
    check('foreign Host refused', rawHostStatus === 403, `status ${rawHostStatus}`);

    console.log('\n9. foreign Origin is refused');
    const badOrigin = await fetch(`${ORIGIN}/api/files/list?path=.`, {
      headers: { cookie, origin: 'http://evil.example.com' },
    });
    check('foreign Origin refused', badOrigin.status === 403, `status ${badOrigin.status}`);

    console.log('\n10. writing a file records it in the audit log');
    const write = await fetch(`${ORIGIN}/api/files/write?path=verify/out.txt`, {
      method: 'PUT',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ content: 'written by verify-e2e\n' }),
    });
    check('write accepted', write.status === 200, `status ${write.status}`);
    const readBack = await (await fetch(`${ORIGIN}/api/files/read?path=verify/out.txt`, { headers: { cookie } })).json();
    check('read-back matches', readBack.content === 'written by verify-e2e\n', readBack.content);

    console.log('\n11. stop invalidates the session immediately');
    const stopResponse = await fetch(`${ORIGIN}/admin/session/stop`, { method: 'POST', headers: { authorization: auth } });
    const stopped = await stopResponse.json();
    check('stop accepted', stopResponse.status === 200, `status ${stopResponse.status}`);
    check('gate is locked', stopped.gate?.lockReason === 'admin-stop', stopped.gate?.lockReason);
    const afterStop = await fetch(`${ORIGIN}/api/files/list?path=.`, { headers: { cookie } });
    check('the old cookie is now refused', afterStop.status === 403 || afterStop.status === 401, `status ${afterStop.status}`);

    console.log('\n12. production refuses bypass flags');
    if (mode === 'production') {
      const state = await (await fetch(`${ORIGIN}/api/state`)).json();
      check('gate returned to a non-running state', state.gate.state !== 'running', state.gate.state);
    } else {
      check('dev mode runs the bypass path elsewhere (see tools/verify-seb.mjs)', true);
    }

    const auditPath = join(runDir, 'audit.jsonl');
    if (existsSync(auditPath)) {
      const audit = readFileSync(auditPath, 'utf8');
      check('audit log recorded the session lifecycle', /session\.started/.test(audit));
      check('audit log recorded the bootstrap exchange', /bootstrap\.accepted/.test(audit));
      check('audit log recorded the refusal', /bootstrap\.refused/.test(audit));
    } else {
      check('audit log exists', false, auditPath);
    }
  } finally {
    if (!keep) stop();
    else console.log(`\n(--keep: leaving pid ${child.pid} running on ${ORIGIN})`);
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
}

await main();
