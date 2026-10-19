// Regression test for the terminal attach path.
//
// The incident: nothing loaded node-pty, and TerminalSession.start() was called
// without one. `ptyModule.spawn(...)` therefore threw a TypeError from *inside a
// WebSocket upgrade callback*, where no caller could catch it. Node terminated
// the process -- observed live, ~0.3 s after Razor loaded inside Safe Exam
// Browser, which also tore down the SEB kiosk and handed the desktop back.
//
// The contract these tests pin: a broken/missing PTY is reported to the client
// as an error frame and closes that socket, while the server keeps serving.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventEmitter } from 'node:events';
import { WebSocket } from 'ws';
import { RazorServer } from '../src/server.mjs';
import { TerminalSession, resolvePolicy, createConfinement } from '../src/terminal.mjs';
import { loadPtyModule } from '../src/pty.mjs';

function makeAudit() {
  const entries = [];
  return { entries, record(kind, detail) { entries.push({ kind, detail }); } };
}

function makeSession() {
  return {
    activeWebSockets: new Set(),
    grant: { terminalPolicy: null },
    isUsable: () => true,
  };
}

/** Minimal node-pty stand-in: enough for TerminalSession to attach and talk. */
function fakePtyModule() {
  const spawned = [];
  return {
    spawned,
    spawn(shell, args, options) {
      const proc = new EventEmitter();
      proc.pid = 4242;
      proc.shell = shell;
      proc.options = options;
      proc.written = [];
      proc.write = (data) => proc.written.push(data);
      proc.resize = () => {};
      proc.kill = () => proc.emit('exit', { exitCode: 0, signal: 0 });
      // node-pty's surface: onData/onExit registration, not EventEmitter names.
      proc.onData = (listener) => proc.on('data', listener);
      proc.onExit = (listener) => proc.on('exit', listener);
      spawned.push(proc);
      return proc;
    },
  };
}

/** A pty module whose spawn() throws, like ConPTY being denied by a sandbox. */
const throwingPty = {
  spawn() {
    throw new Error('EPERM: operation not permitted, open \\\\.\\pipe\\conpty-test-in');
  },
};

async function withTerminalServer(fn, { ptyModule } = {}) {
  const audit = makeAudit();
  const gate = {
    audit,
    session: makeSession(),
    state: 'running',
    describe: () => ({ state: 'running' }),
    tokenMatches: (token) => token === 'test-token',
  };
  const terminal = new TerminalSession({
    policy: resolvePolicy(null),
    cwd: process.cwd(),
    audit,
    confinement: createConfinement({ mode: 'none', policy: resolvePolicy(null) }),
  });
  // The server loads the real native module; substitute the test double so these
  // tests never depend on ConPTY being permitted (it is not, in a sandbox).
  const originalStart = terminal.start.bind(terminal);
  terminal.start = (args) => originalStart({ ...args, ptyModule });

  const server = new RazorServer({
    env: { mode: 'dev', ui: 'dev', host: '127.0.0.1', port: 0 },
    gate,
    workspace: {},
    terminal,
    credentials: { ok: true },
    sebState: {},
  });
  await server.listen({ host: '127.0.0.1', port: 0 });
  try {
    return await fn({ server, audit, terminal });
  } finally {
    await server.close();
  }
}

/** Connect, collect the first message, and resolve with it plus the close code. */
function connectTerminal(server) {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${server.port}/ws/terminal`, {
      headers: {
        origin: `http://127.0.0.1:${server.port}`,
        authorization: 'Bearer test-token',
      },
    });
    const result = { message: null, closeCode: null };

    ws.on('message', (raw) => {
      if (result.message) return;
      try {
        result.message = JSON.parse(raw.toString('utf8'));
      } catch {
        result.message = { raw: raw.toString('utf8') };
      }
    });
    ws.on('close', (code) => {
      result.closeCode = code;
      resolve(result);
    });
    ws.on('error', (err) => resolve({ ...result, error: err.message }));
    setTimeout(() => resolve(result), 4000);
  });
}

test('a failing PTY spawn is reported to the client and does not kill the server', async () => {
  await withTerminalServer(async ({ server, audit }) => {
    const { message, closeCode } = await connectTerminal(server);

    assert.ok(message, 'the client must get an error frame, not a dead socket');
    assert.equal(message.type, 'error');
    assert.equal(message.error, 'pty-spawn-failed');
    assert.match(message.detail, /EPERM/);
    assert.equal(closeCode, 1011, 'the terminal socket closes; the server does not');

    // The whole point: the process is still alive and still serving.
    const health = await fetch(`${server.origin}/healthz`, {
      headers: { host: `127.0.0.1:${server.port}` },
    });
    assert.equal(health.status, 200, 'Razor must keep serving after a terminal failure');
    assert.ok(
      audit.entries.some((e) => e.kind === 'terminal.unavailable'),
      'the failure must be recorded in the audit log',
    );
  }, { ptyModule: throwingPty });
});

test('a working PTY module reaches a ready terminal, so the fix is not just a guard', async () => {
  const pty = fakePtyModule();
  await withTerminalServer(async ({ server }) => {
    const { message } = await connectTerminal(server);

    assert.ok(message, 'expected a ready frame');
    assert.equal(message.type, 'ready');
    assert.equal(message.pid, 4242);
    assert.equal(pty.spawned.length, 1, 'exactly one PTY is spawned');
    assert.equal(pty.spawned[0].options.useConpty, true);
  }, { ptyModule: pty });
});

test("the PTY's own output is never screened as a denied command", () => {
  const audit = makeAudit();
  const session = new TerminalSession({
    policy: resolvePolicy(null),
    cwd: process.cwd(),
    audit,
    confinement: createConfinement({ mode: 'none', policy: resolvePolicy(null) }),
  });
  const pty = fakePtyModule();
  session.start({ ptyModule: pty });

  // This is what a real shell emits on startup: the banner and a prompt naming
  // the install directory. It contains the denied word "razor", but it is
  // OUTPUT. Screening it produced "terminal.command.denied match:razor" for a
  // candidate who had typed nothing.
  pty.spawned[0].emit(
    'data',
    'Windows PowerShell\r\nPS C:\\Users\\chris\\Desktop\\Lab_devil\\Razor-ide\\workspace> \r\n',
  );

  const denied = audit.entries.filter((e) => e.kind === 'terminal.command.denied');
  assert.deepEqual(denied, [], 'shell output must never be recorded as a denied command');
  assert.ok(
    audit.entries.some((e) => e.kind === 'terminal.output' && e.detail.line.includes('Razor-ide')),
    'the output is still captured for the audit trail, just classified as output',
  );
});

test('denied input is refused and recorded once, at the write path', () => {
  const audit = makeAudit();
  const session = new TerminalSession({
    policy: resolvePolicy(null),
    cwd: process.cwd(),
    audit,
    confinement: createConfinement({ mode: 'none', policy: resolvePolicy(null) }),
  });
  const pty = fakePtyModule();
  session.start({ ptyModule: pty });

  const verdict = session.write('curl something\r\n');
  assert.equal(verdict.decision, 'deny');
  assert.equal(verdict.match, 'curl');
  assert.equal(
    pty.spawned[0].written.join('').includes('\r'),
    false,
    'the terminator is withheld, so a denied command never executes',
  );
  assert.equal(
    pty.spawned[0].written.join(''),
    'curl something',
    'the characters themselves reach the shell so the candidate sees what they typed',
  );

  const denied = audit.entries.filter((e) => e.kind === 'terminal.command.denied');
  assert.equal(denied.length, 1, 'exactly one audit entry per denied line');
  assert.equal(denied[0].detail.line, 'curl something');
});

test('allowed input reaches the PTY and is recorded as a command', () => {
  const audit = makeAudit();
  const session = new TerminalSession({
    policy: resolvePolicy(null),
    cwd: process.cwd(),
    audit,
    confinement: createConfinement({ mode: 'none', policy: resolvePolicy(null) }),
  });
  const pty = fakePtyModule();
  session.start({ ptyModule: pty });

  // Keystrokes arrive one frame at a time from the browser.
  for (const chunk of ['e', 'c', 'h', 'o', ' ', 'h', 'i', '\r']) {
    session.write(chunk);
  }

  assert.equal(pty.spawned[0].written.join(''), 'echo hi\r', 'the shell receives the line');
  const commands = audit.entries.filter((e) => e.kind === 'terminal.command');
  assert.equal(commands.length, 1);
  assert.equal(commands[0].detail.line, 'echo hi');
});

test('a CRLF-terminated denied line does not sneak through on the second terminator', () => {
  const audit = makeAudit();
  const session = new TerminalSession({
    policy: resolvePolicy(null),
    cwd: process.cwd(),
    audit,
    confinement: createConfinement({ mode: 'none', policy: resolvePolicy(null) }),
  });
  const pty = fakePtyModule();
  session.start({ ptyModule: pty });

  const verdict = session.write('curl something\r\n');
  assert.equal(verdict.decision, 'deny');
  // CR and LF are one Enter: neither may reach the PTY, or the refused command
  // would execute on the second one.
  assert.equal(pty.spawned[0].written.join(''), 'curl something');
  assert.equal(audit.entries.filter((e) => e.kind === 'terminal.command').length, 0);
  assert.equal(audit.entries.filter((e) => e.kind === 'terminal.command.denied').length, 1);
});

test('an allowed CRLF line still executes exactly once', () => {
  const audit = makeAudit();
  const session = new TerminalSession({
    policy: resolvePolicy(null),
    cwd: process.cwd(),
    audit,
    confinement: createConfinement({ mode: 'none', policy: resolvePolicy(null) }),
  });
  const pty = fakePtyModule();
  session.start({ ptyModule: pty });

  session.write('echo hi\r\n');
  const written = pty.spawned[0].written.join('');
  assert.equal(written, 'echo hi\r', 'one terminator, not two');
  assert.equal(audit.entries.filter((e) => e.kind === 'terminal.command').length, 1);
});

test('TerminalSession.start refuses a missing pty module instead of throwing', () => {
  const session = new TerminalSession({
    policy: resolvePolicy(null),
    cwd: process.cwd(),
    audit: makeAudit(),
    confinement: createConfinement({ mode: 'none', policy: resolvePolicy(null) }),
  });

  const result = session.start({});
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'pty-unavailable');
  assert.equal(session.alive, false);
});

test('loadPtyModule reports a usable module or an actionable failure', () => {
  const loaded = loadPtyModule();
  if (loaded.ok) {
    assert.equal(typeof loaded.pty.spawn, 'function');
  } else {
    // Never a bare throw, and the detail must tell an operator what to do.
    assert.match(loaded.reason, /^pty-/);
    assert.match(loaded.detail, /node-pty/);
    assert.match(loaded.detail, /npm/);
  }
});
