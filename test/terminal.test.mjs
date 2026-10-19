// Terminal policy and AppLocker generation tests.
//
// Reminder: the command policy is a deterrent with an audit trail, not a
// security boundary. These tests document what it does and does not catch, so
// nobody mistakes it for confinement.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  DEFAULT_POLICY,
  generateAppLockerPolicy,
  resolvePolicy,
  screenCommand,
  pickShell,
} from '../src/terminal.mjs';

test('network tooling is refused', () => {
  for (const line of [
    'curl http://example.com/exfil',
    'Invoke-WebRequest -Uri https://pastebin.com',
    'iwr https://x',
    'bitsadmin /transfer job http://x/y',
    'certutil -urlcache -f http://x/y z',
    'netsh advfirewall set allprofiles state off',
    'ssh user@host',
    'Test-NetConnection 8.8.8.8',
  ]) {
    assert.equal(screenCommand(line, DEFAULT_POLICY).decision, 'deny', `should deny: ${line}`);
  }
});

test('escape and host-manipulation tooling is refused', () => {
  for (const line of [
    'taskkill /IM SafeExamBrowser.exe /F',
    'Stop-Process -Name SafeExamBrowser',
    'schtasks /create /tn x /tr y',
    'wmic process call create calc',
    'reg add HKLM\\Software\\X /v Y /d Z',
    'shutdown /r /t 0',
    'start chrome',
    'Start-Process notepad',
    'mstsc /v:10.0.0.1',
  ]) {
    assert.equal(screenCommand(line, DEFAULT_POLICY).decision, 'deny', `should deny: ${line}`);
  }
});

test('tampering with the exam artefacts is refused', () => {
  for (const line of ['type admin-key.pem', 'cat audit.jsonl', 'del razor.seb']) {
    assert.equal(screenCommand(line, DEFAULT_POLICY).decision, 'deny', `should deny: ${line}`);
  }
});

test('normal exam work is allowed', () => {
  for (const line of [
    'python hello.py',
    'python -m pytest',
    'dir',
    'cd src',
    'git status',
    'python -c "print(1+1)"',
  ]) {
    assert.equal(screenCommand(line, DEFAULT_POLICY).decision, 'allow', `should allow: ${line}`);
  }
});

test('the policy reports which pattern matched, for the audit log', () => {
  const verdict = screenCommand('curl http://x', DEFAULT_POLICY);
  assert.equal(verdict.decision, 'deny');
  assert.equal(verdict.match, 'curl');
});

test('obfuscation defeats the policy -- documented, not hidden', () => {
  // This is the honest limitation. The policy is substring matching; anyone who
  // wants around it can. That is precisely why Job Object + AppLocker +
  // a separate account are the real controls.
  assert.equal(screenCommand('c""url http://x', DEFAULT_POLICY).decision, 'allow');
  assert.equal(screenCommand('$c = "cu" + "rl"; & $c http://x', DEFAULT_POLICY).decision, 'allow');
});

test('an operator can extend the policy but not weaken the defaults', () => {
  const extended = resolvePolicy({ deniedPatterns: ['my-custom-tool'], allowedPrograms: ['python.exe'] });
  assert.ok(extended.deniedPatterns.includes('curl'));
  assert.ok(extended.deniedPatterns.includes('my-custom-tool'));
  // allowedPrograms replaces rather than merges, so an operator can narrow it.
  assert.deepEqual(extended.allowedPrograms, ['python.exe']);
});

test('pickShell only ever returns an allowed interpreter', () => {
  const shell = pickShell(DEFAULT_POLICY);
  if (shell === null) {
    assert.ok(process.platform !== 'win32', 'a Windows host should have a usable shell');
    return;
  }
  assert.ok(
    DEFAULT_POLICY.allowedPrograms.some((p) => shell.toLowerCase().endsWith(p.toLowerCase())),
    `${shell} is not in the allowlist`,
  );

  assert.equal(pickShell(resolvePolicy({ allowedPrograms: ['definitely-not-a-shell.exe'] })), null);
});

test('the AppLocker policy is well-formed XML with the expected allow rules', () => {
  const xml = generateAppLockerPolicy({ examUserSid: 'S-1-5-21-1-2-3-1001' });

  // Strip comments and the declaration before checking tag balance: both may
  // legitimately contain angle brackets.
  const body = xml.replace(/<!--[\s\S]*?-->/g, '').replace(/<\?[\s\S]*?\?>/g, '');
  const opens = [...body.matchAll(/<([A-Za-z][A-Za-z0-9]*)[^/>]*>/g)].map((m) => m[1]);
  const closes = [...body.matchAll(/<\/([A-Za-z][A-Za-z0-9]*)>/g)].map((m) => m[1]);
  assert.ok(opens.length > 0, 'expected some elements');
  assert.deepEqual(opens.sort(), closes.sort());

  assert.match(xml, /<RuleCollection Type="Exe" EnforcementMode="Enabled">/);
  assert.match(xml, /%PROGRAMFILES%\\SafeExamBrowser\\\*/);
  assert.match(xml, /S-1-5-21-1-2-3-1001/);
  assert.match(xml, /Scope note: apply this to the exam account \(S-1-5-21-1-2-3-1001\)/);
});

test('extra allow paths are escaped, not injected', () => {
  const xml = generateAppLockerPolicy({
    examUserSid: '*',
    extraPaths: ['C:\\Tools & <Scripts>\\*'],
  });
  assert.match(xml, /C:\\Tools &amp; &lt;Scripts&gt;\\\*/);
  assert.doesNotMatch(xml, /<Scripts>/);
});
