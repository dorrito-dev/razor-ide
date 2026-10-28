#!/usr/bin/env node
// Build, inspect and (optionally) really launch the SEB configuration.
//
// Modes:
//   node tools/verify-seb.mjs              build the .seb and report on it
//   node tools/verify-seb.mjs --inspect    also print the decoded plist
//   node tools/verify-seb.mjs --argv       print the exact SEB command line
//   node tools/verify-seb.mjs --launch     actually start SEB (LOCKS THE DESKTOP)
//
// Why a tool instead of an automated test: nothing running inside this process
// can prove that the real SEB client accepts our file. Only SEB can. This
// script produces the artefact and, on request, launches it and then reads
// SEB's own log directory to see whether the configuration was accepted.
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hostname } from 'node:os';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { buildSebPolicy, validateSebPolicy } = await import('../src/seb/config.mjs');
const { encodePlain, inspectContainer, decodePlain } = await import('../src/seb/container.mjs');
const { findSebExecutable, inspectSebBinary, buildSebArgv, launchSeb, fileSha256 } =
  await import('../src/seb/launch.mjs');
const { sebConfigKey, sebPasswordHash } = await import('../src/security/crypto.mjs');

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);

mkdirSync(join(ROOT, 'run'), { recursive: true });
const OUT = join(ROOT, 'run', 'verify.seb');
const PLIST = join(ROOT, 'run', 'verify.plist.xml');
const PORT = 45909;
const QUIT_PASSWORD = 'VERIFY-Quit-Password-1234';

function hr(title) {
  console.log(`\n=== ${title} ===`);
}

hr('1. locate Safe Exam Browser');
const located = findSebExecutable();
if (!located.ok) {
  console.error(`  ${located.reason}: ${located.detail}`);
  process.exitCode = 1;
  process.exit();
}
console.log(`  executable : ${located.path}`);

const binary = inspectSebBinary(located.path);
console.log(`  version    : ${binary.version ?? 'unknown'}`);
console.log(
  `  signature  : ${binary.signaturePresent ? `present (${binary.signatureSize} bytes)` : 'ABSENT'}` +
    `${binary.signedByEth ? ' -- ETH Zurich' : ''}`,
);
console.log(`  company    : ${binary.company ?? 'unknown'}`);
console.log(`  sha256     : ${fileSha256(located.path)}`);
if (!binary.ok) console.log(`  WARNING    : ${binary.reason} -- ${binary.detail ?? ''}`);

hr('2. build the configuration');
const policy = buildSebPolicy({
  startUrl: `http://127.0.0.1:${PORT}/?b=VERIFY-BOOTSTRAP-CODE`,
  quitPassword: QUIT_PASSWORD,
  // Windowed + allowQuit so a failed run cannot trap the operator.
  mode: 'dev',
  windowed: true,
});
const problems = validateSebPolicy(policy);
if (problems.length) {
  console.log('  policy problems:');
  for (const problem of problems) console.log(`    - ${problem}`);
} else {
  console.log('  policy validates');
}

const buffer = encodePlain(policy);
writeFileSync(OUT, buffer);
writeFileSync(PLIST, `${JSON.stringify(policy, null, 2)}\n`, 'utf8');
console.log(`  wrote      : ${OUT} (${buffer.length} bytes)`);
console.log(`  plain plist: ${PLIST}`);

hr('3. inspect the container');
const info = inspectContainer(buffer);
console.log(`  prefix     : ${info.prefix}  (${info.encrypted ? 'encrypted' : 'plain'})`);
console.log(`  readable   : ${info.ok ? 'yes' : `no -- ${info.reason}`}`);
const decoded = decodePlain(buffer);
console.log(`  keys       : ${Object.keys(decoded.plist).length}`);
console.log(`  startURL   : ${decoded.plist.startURL}`);
console.log(`  filter     : ${decoded.plist.URLFilterRules.map((r) => r.expression).join(', ')}`);

hr('4. Config Key');
const configKey = sebConfigKey(policy);
console.log(`  config key : ${configKey}`);
console.log(`  password   : ${sebPasswordHash(QUIT_PASSWORD)}  (SHA-256 of the quit password)`);
console.log('');
console.log('  THIS IS THE UNVERIFIED PART. The hashedQuitPassword scheme is not');
console.log('  documented. To confirm it:');
console.log('    1. open SEB Config Tool and load run/verify.plist.xml');
console.log(`    2. set the quit password to "${QUIT_PASSWORD}"`);
console.log('    3. save as a .seb and gunzip it twice (see docs/seb.md)');
console.log('    4. compare hashedQuitPassword with the value above');
console.log('  If they differ, vendor Config Tool\'s value -- do not guess.');

hr('5. the exact command line');
const argv = buildSebArgv({ executable: located.path, configPath: OUT });
console.log(`  ${argv.printable}`);

if (flag('--inspect')) {
  hr('decoded plist');
  console.log(JSON.stringify(decoded.plist, null, 2));
}

if (flag('--argv')) {
  console.log('');
  process.exit(0);
}

if (!flag('--launch')) {
  hr('not launching');
  console.log('  Add --launch to really start SEB.');
  console.log('  WARNING: that locks this desktop in fullscreen kiosk mode unless');
  console.log('           RAZOR_SEB_WINDOWED is set. The quit password is printed above.');
  console.log('           Run it in a VM or on a disposable profile the first time.');
  process.exit(0);
}

hr('6. launching SEB');
console.log(`  quit password: ${QUIT_PASSWORD}`);
console.log('  Waiting for SEB to exit. Close it with the quit password.');
console.log('  (If SEB rejects the config it usually exits within ~10 seconds.)');

const logDir = join(process.env.LOCALAPPDATA ?? '', 'SafeExamBrowser');
const before = existsSync(logDir) ? new Set(readdirSync(logDir)) : new Set();

launchSeb({
  executable: located.path,
  configPath: OUT,
  onExit: (exit) => {
    console.log(`\n  SEB exited after ${exit.at - exit.startedAt} ms (code=${exit.code})`);

    hr('7. SEB logs (whether the config was accepted)');
    if (!existsSync(logDir)) {
      console.log(`  no log directory at ${logDir}`);
      return;
    }
    const after = readdirSync(logDir).filter((name) => !before.has(name));
    const candidates = after.length ? after : readdirSync(logDir).slice(-4);
    let sawAccepted = false;
    for (const name of candidates) {
      const path = join(logDir, name);
      try {
        if (!statSync(path).isFile()) continue;
        const text = readFileSync(path, 'utf8');
        const loading = /FileResourceLoader.*Loading data from/i.test(text);
        const errors = text.split(/\r?\n/).filter((line) => /ERROR|FATAL/i.test(line)).slice(0, 5);
        if (loading) sawAccepted = true;
        console.log(`  ${name}: ${loading ? 'loaded our config' : 'no load line'}`);
        for (const line of errors) console.log(`      ${line.trim()}`);
      } catch {
        /* log may be locked while SEB is running */
      }
    }
    console.log(
      sawAccepted
        ? '  RESULT: SEB read the configuration file. The plnd container is accepted.'
        : '  RESULT: inconclusive -- look at the log files above by hand.',
    );
  },
});
