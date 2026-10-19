#!/usr/bin/env node
// Proctor CLI. Talks to a running Razor instance's local admin surface.
//
//   node tools/admin-cli.mjs status
//   node tools/admin-cli.mjs start  [--exam-id N] [--quit-password P]
//   node tools/admin-cli.mjs stop
//   node tools/admin-cli.mjs extend --minutes 15
//
// Credentials come from RAZOR_ADMIN_USER / RAZOR_ADMIN_PASS (or
// RAZOR_ADMIN_TOKEN). In dev, if RAZOR_ADMIN_PASS is unset, the password
// generated at boot is read from run/admin-key.pem.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { flags, positional };
}

function loadCredentials() {
  const user = process.env.RAZOR_ADMIN_USER ?? 'admin';
  const pass = process.env.RAZOR_ADMIN_PASS;
  const token = process.env.RAZOR_ADMIN_TOKEN;
  if (pass) return { user, header: `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}` };
  if (token) return { user, header: `Bearer ${token}` };

  const keyFile = join(ROOT, 'run', 'admin-key.pem');
  if (existsSync(keyFile)) {
    const generated = readFileSync(keyFile, 'utf8').trim();
    return {
      user,
      header: `Basic ${Buffer.from(`${user}:${generated}`).toString('base64')}`,
      source: `generated dev password from ${keyFile}`,
    };
  }
  return null;
}

function loadOrigin() {
  if (process.env.RAZOR_URL) return process.env.RAZOR_URL;
  const sessionFile = join(ROOT, 'run', 'session.json');
  if (existsSync(sessionFile)) {
    try {
      return JSON.parse(readFileSync(sessionFile, 'utf8')).origin;
    } catch {
      /* fall through */
    }
  }
  return null;
}

const { flags, positional } = parseArgs(process.argv.slice(2));
const command = positional[0] ?? 'status';

const credentials = loadCredentials();
if (!credentials) {
  console.error('No admin credentials. Set RAZOR_ADMIN_PASS or RAZOR_ADMIN_TOKEN.');
  process.exit(2);
}
if (credentials.source) console.error(`(using ${credentials.source})`);

const origin = loadOrigin();
if (!origin) {
  console.error('Cannot determine the Razor origin. Set RAZOR_URL=http://127.0.0.1:<port>.');
  process.exit(2);
}

async function call(path, { method = 'GET', body } = {}) {
  const response = await fetch(`${origin}${path}`, {
    method,
    headers: {
      authorization: credentials.header,
      // Mirrors lab-agent's mutating-route convention.
      'x-labagent-admin': '1',
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = { raw: text };
  }
  return { status: response.status, body: parsed };
}

const print = (result) => {
  console.log(JSON.stringify(result.body, null, 2));
  if (result.status >= 400) process.exitCode = 1;
};

switch (command) {
  case 'status': {
    print(await call('/admin/status'));
    break;
  }

  case 'start': {
    const body = {
      examId: flags['exam-id'] ?? 'local',
      ...(flags['quit-password'] ? { sebQuitPassword: String(flags['quit-password']) } : {}),
      ...(flags['terminal-policy'] ? { terminalPolicy: JSON.parse(String(flags['terminal-policy'])) } : {}),
    };
    const result = await call('/admin/session/start', { method: 'POST', body });
    print(result);
    if (result.status < 400 && result.body?.sebQuitPassword) {
      console.log('');
      console.log('  ================================================================');
      console.log(`   SEB QUIT PASSWORD (shown once): ${result.body.sebQuitPassword}`);
      console.log('   Required to leave kiosk mode. Record it before the exam.');
      console.log('  ================================================================');
      console.log('');
    }
    if (result.status < 400 && result.body?.startUrl) {
      console.log(`  start URL (single use): ${result.body.startUrl}`);
    }
    break;
  }

  case 'stop': {
    print(await call('/admin/session/stop', { method: 'POST' }));
    break;
  }

  case 'extend': {
    const minutes = Number(flags.minutes ?? 15);
    print(await call('/admin/session/extend', { method: 'POST', body: { minutes } }));
    break;
  }

  default:
    console.error(`Unknown command "${command}". Use: status | start | stop | extend`);
    process.exit(2);
}
