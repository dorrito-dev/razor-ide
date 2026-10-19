#!/usr/bin/env node
// The single most important production property, checked against a real boot:
//
//   RAZOR_ENV=production node src/main.mjs --bypass-gate
//
// must NOT produce a running session. The flag is refused and logged. This runs
// a real child process rather than unit-testing the gate, because the thing
// being tested is what the actual entry point does with the actual flag.
//
// Usage: node tools/verify-bypass-refused.mjs
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.RAZOR_BYPASS_PORT ?? 45903);
const ORIGIN = `http://127.0.0.1:${PORT}`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForServer(timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`${ORIGIN}/healthz`)).ok) return true;
    } catch {
      /* not up yet */
    }
    await sleep(200);
  }
  return false;
}

let failures = 0;
function check(name, condition, detail = '') {
  if (condition) console.log(`  ok   ${name}`);
  else {
    failures += 1;
    console.log(`  FAIL ${name}${detail ? ` -- ${detail}` : ''}`);
  }
}

const runDir = join(ROOT, 'run');
const auditPath = join(runDir, 'audit.jsonl');
if (existsSync(auditPath)) rmSync(auditPath, { force: true });

const child = spawn(process.execPath, ['src/main.mjs', '--port', String(PORT), '--bypass-gate'], {
  cwd: ROOT,
  env: {
    ...process.env,
    RAZOR_ENV: 'production',
    RAZOR_ADMIN_PASS: 'production-bypass-check',
    RAZOR_LOG_LEVEL: 'warn',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

const output = [];
child.stdout.on('data', (c) => output.push(String(c)));
child.stderr.on('data', (c) => output.push(String(c)));

try {
  console.log('\nRAZOR_ENV=production with --bypass-gate');

  if (!(await waitForServer())) {
    console.error('server never came up:\n' + output.join(''));
    process.exitCode = 1;
    process.exit();
  }
  await sleep(1_000);

  const state = await (await fetch(`${ORIGIN}/api/state`)).json();
  check('mode is production', state.mode === 'production', state.mode);
  check('the gate is NOT running', state.gate.state !== 'running', state.gate.state);
  check('no session was created', state.gate.examId === null, String(state.gate.examId));

  const locked = await fetch(`${ORIGIN}/api/files/list?path=.`);
  check('the IDE surface stays locked', locked.status === 401, `status ${locked.status}`);

  const combined = output.join('');
  check('the refusal was reported', /refused in production/i.test(combined), combined.slice(-400));

  if (existsSync(auditPath)) {
    const audit = readFileSync(auditPath, 'utf8');
    check('the bypass attempt is in the audit log', /bypass\.refused/.test(audit));
    check('the audit log names production as the reason', /"reason":"production"/.test(audit));
  } else {
    check('audit log exists', false, auditPath);
  }
} finally {
  try {
    child.kill();
  } catch {
    /* already gone */
  }
}

assert.ok(true);
console.log(failures === 0 ? '\nproduction refuses the bypass flag.' : `\n${failures} failed`);
if (failures > 0) process.exitCode = 1;
