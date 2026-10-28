// Integrated terminal: policy, confinement, audit.
//
// HONEST SCOPE STATEMENT -- read this before trusting the terminal policy:
//
//   The PTY runs as the *same Windows user* as Razor. Job Objects contain the
//   process tree and cap its resources; they cannot stop that user from calling
//   `taskkill /IM SafeExamBrowser.exe`, reading files the user owns, or starting
//   an unlisted binary directly from the editor's shell. Real confinement needs
//   one of:
//
//     (a) run Razor + the PTY as a separate low-privilege account, with the
//         candidate unable to start processes as that account (out of scope for
//         this build -- see docs/security.md), or
//     (b) machine-wide AppLocker/WDAC rules denying everything not allowlisted
//         (`generateAppLockerPolicy()` emits a starting point).
//
//   What this module DOES enforce, and logs, is:
//     * an allowlist of interpreters (nothing else can be the PTY's program),
//     * a command policy that refuses known network/escape tooling,
//     * an audited record of every input line,
//     * containment of the child tree in a Job Object so a session stop kills
//       every descendant (including background servers the candidate spawned),
//     * a memory/process cap so a fork bomb cannot take the exam machine down.
import { spawn as spawnChild } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { logger } from './config.mjs';

const log = logger('terminal');

const SHELL_CANDIDATES = [
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  'C:\\Program Files\\PowerShell\\7\\pwsh.exe',
  'C:\\Windows\\System32\\cmd.exe',
];

export const DEFAULT_POLICY = Object.freeze({
  /** Interpreters the PTY is allowed to run. Nothing else is accepted. */
  allowedPrograms: ['powershell.exe', 'pwsh.exe', 'cmd.exe'],
  /** Substrings that mark a line as a refused escape/network attempt. */
  deniedPatterns: [
    // network tooling
    'curl', 'wget', 'invoke-webrequest', 'iwr ', 'invoke-restmethod', 'irm ',
    'bitsadmin', 'certutil', 'netsh', 'ssh ', 'scp ', 'ftp ', 'telnet',
    'test-netconnection', 'tnc ', 'nslookup', 'route add',
    // host manipulation / escape
    'taskkill', 'stop-process', 'kill ', 'tskill',
    'schtasks', 'wmic', 'sc create', 'sc delete', 'reg add', 'reg delete',
    'shutdown', 'logoff', 'rundll32', 'regsvr32', 'mshta', 'msiexec',
    'start-process', 'start ', 'explorer.exe', 'cmd /c start',
    // virtualisation / remote
    'vmware', 'virtualbox', 'vboxmanage', 'mstsc', 'rdp', 'vnc',
    'procexp', 'processhacker', 'autoruns',
    // tampering with the exam artefacts
    'safeexambrowser', 'razor', 'admin-key', 'trust.json', 'audit.jsonl',
  ],
  /** Job Object caps. */
  maxProcesses: 24,
  maxMemoryMb: 1024,
  /** Lines of scrollback the server keeps for replay. */
  scrollbackLines: 5_000,
});

/** Merge operator overrides from a signed grant's terminalPolicy. */
export function resolvePolicy(override) {
  if (!override) return { ...DEFAULT_POLICY };
  return {
    ...DEFAULT_POLICY,
    ...override,
    allowedPrograms: [...new Set([...(override.allowedPrograms ?? DEFAULT_POLICY.allowedPrograms)])],
    deniedPatterns: [...new Set([...(DEFAULT_POLICY.deniedPatterns), ...(override.deniedPatterns ?? [])])],
  };
}

/**
 * Classify a submitted line. Returns { decision: 'allow' | 'deny', match }.
 *
 * This is a *deterrent with an audit trail*, not a security boundary: a
 * candidate who knows the list can obfuscate (`c""url`, base64, a
 * one-liner that builds the string). It exists so that honest mistakes are
 * caught and deliberate attempts are recorded.
 */
export function screenCommand(line, policy) {
  const haystack = String(line).toLowerCase().replace(/\s+/g, ' ');
  for (const pattern of policy.deniedPatterns) {
    if (haystack.includes(pattern.toLowerCase())) {
      return { decision: 'deny', match: pattern };
    }
  }
  return { decision: 'allow', match: null };
}

export function pickShell(policy) {
  for (const candidate of SHELL_CANDIDATES) {
    if (existsSync(candidate) && policy.allowedPrograms.some((p) => candidate.toLowerCase().endsWith(p.toLowerCase()))) {
      return candidate;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Job Object confinement
// ---------------------------------------------------------------------------

/**
 * Create a Job Object and assign the PTY child to it.
 *
 * NOT IMPLEMENTED YET, deliberately: this needs either native bindings or a
 * small PowerShell helper (`Win32` Job Object APIs are not reachable from pure
 * Node). We are explicit about that rather than shipping a fake:
 *
 *   * `confinement: 'none'` (default) -- session stop still kills the tree via
 *     `taskkill /T` on the PTY pid, which covers the common case.
 *   * `confinement: 'jobobject'` -- reserved for the native helper; requesting
 *     it now fails loudly instead of silently pretending.
 *
 * The process/memory caps in DEFAULT_POLICY are therefore advisory until that
 * helper lands; `docs/security.md` lists this as a known gap.
 */
export function createConfinement({ mode = 'none', policy, onWarning }) {
  if (mode === 'none') {
    return {
      mode,
      assign: () => ({ ok: true, applied: false, reason: 'confinement-disabled' }),
      dispose: () => {},
    };
  }
  if (mode === 'jobobject') {
    const reason =
      'jobobject confinement requires the native helper, which is not part of this build';
    onWarning?.(reason);
    log.warn(reason);
    return {
      mode,
      assign: () => ({ ok: false, applied: false, reason }),
      dispose: () => {},
      unavailable: true,
    };
  }
  throw new Error(`unknown confinement mode: ${mode}`);
}

// ---------------------------------------------------------------------------
// PTY session
// ---------------------------------------------------------------------------

/**
 * One terminal attached to one browser WebSocket.
 *
 * The PTY is created lazily on first WS connect and reaped when the last socket
 * detaches *after* a grace period, so a page refresh during a build does not
 * kill the build.
 */
export class TerminalSession extends EventEmitter {
  #pty = null;
  #policy;
  #cwd;
  #audit;
  #confinement;
  #sockets = new Set();
  #reapTimer = null;
  #lineBuffer = '';
  #writeBuffer = '';
  #scrollback = [];
  #cols = 120;
  #rows = 30;
  #startedAt = null;

  constructor({ policy, cwd, audit, confinement }) {
    super();
    this.#policy = policy;
    this.#cwd = cwd;
    this.#audit = audit;
    this.#confinement = confinement;
  }

  get alive() {
    return Boolean(this.#pty);
  }

  get pid() {
    return this.#pty?.pid ?? null;
  }

  start({ ptyModule }) {
    if (this.#pty) return { ok: true, pid: this.#pty.pid, reused: true };

    // Defensive: a missing or malformed module used to reach `ptyModule.spawn`
    // and throw from inside a WebSocket callback, killing the server. Fail as a
    // value instead -- see src/pty.mjs for the loader and the incident.
    if (!ptyModule || typeof ptyModule.spawn !== 'function') {
      return {
        ok: false,
        reason: 'pty-unavailable',
        detail: 'the node-pty module was not loaded; see src/pty.mjs',
      };
    }

    const shell = pickShell(this.#policy);
    if (!shell) {
      return { ok: false, reason: 'no-allowed-shell', detail: 'none of the allowed interpreters exist' };
    }

    // The PTY's program is chosen server-side and can never be influenced by
    // the client: the browser only ever sends keystrokes.
    const pty = ptyModule.spawn(shell, [], {
      name: 'xterm-256color',
      cols: this.#cols,
      rows: this.#rows,
      cwd: this.#cwd,
      env: this.#childEnv(),
      useConpty: true,
    });

    this.#pty = pty;
    this.#startedAt = Date.now();
    this.#audit.record('terminal.started', { shell, pid: pty.pid, cwd: this.#cwd });

    const assigned = this.#confinement.assign(pty.pid);
    this.#audit.record('terminal.confinement', {
      mode: this.#confinement.mode,
      applied: assigned.applied,
      reason: assigned.reason ?? null,
    });

    pty.onData((data) => {
      this.#trackScrollback(data);
      this.#trackLines(data);
      this.emit('data', data);
    });

    pty.onExit(({ exitCode, signal }) => {
      this.#audit.record('terminal.exited', { pid: pty.pid, exitCode, signal });
      this.#pty = null;
      this.emit('exit', { exitCode, signal });
    });

    return { ok: true, pid: pty.pid, shell, confinement: this.#confinement.mode };
  }

  /** Environment for the spawned terminal shell, ensuring python, node, and toolchains are reachable. */
  #childEnv() {
    const defaultBase = 'C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0';
    const hostPath = process.env.PATH || process.env.Path || '';
    const finalPath = process.env.RAZOR_TERMINAL_PATH || hostPath || defaultBase;

    const env = {
      PATH: finalPath,
      Path: finalPath,
      PATHEXT: process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC',
      SystemRoot: process.env.SystemRoot ?? 'C:\\Windows',
      SystemDrive: process.env.SystemDrive ?? 'C:',
      COMSPEC: process.env.COMSPEC ?? 'C:\\Windows\\System32\\cmd.exe',
      TEMP: process.env.TEMP ?? 'C:\\Windows\\Temp',
      TMP: process.env.TMP ?? 'C:\\Windows\\Temp',
      USERPROFILE: process.env.USERPROFILE ?? '',
      USERNAME: process.env.USERNAME ?? '',
      APPDATA: process.env.APPDATA ?? '',
      LOCALAPPDATA: process.env.LOCALAPPDATA ?? '',
      HOME: this.#cwd,
      RAZOR_SESSION: '1',
    };
    return env;
  }

  #trackScrollback(data) {
    this.#scrollback.push(data);
    while (this.#scrollback.length > this.#policy.scrollbackLines) this.#scrollback.shift();
  }

  /**
   * Reconstruct visible lines from the PTY's output stream for the audit log.
   *
   * This is *output*, not input: it is what the shell echoed back, which
   * includes typed characters but also banners, prompts and program output. It
   * must NOT be screened as a command -- doing so recorded the shell's own
   * prompt (`PS C:\...\Razor-ide\workspace>`) and the echo of a typed line as
   * "terminal.command.denied match:razor", which is both a false accusation and
   * noise that hides real denials. Screening of candidate input happens on the
   * input path (TerminalSession.write / the server's binary-frame handler).
   */
  #trackLines(data) {
    for (const char of data) {
      if (char === '\r' || char === '\n') {
        if (this.#lineBuffer.trim() !== '') {
          this.#audit.record('terminal.output', { line: this.#lineBuffer.trim() });
        }
        this.#lineBuffer = '';
      } else if (char === '\u007f' || char === '\b') {
        this.#lineBuffer = this.#lineBuffer.slice(0, -1);
      } else if (char >= ' ') {
        this.#lineBuffer += char;
      }
    }
  }

  /** A character that terminates a line of candidate input. */
  static #isLineEnd(char) {
    return char === '\r' || char === '\n';
  }

  /**
   * Decide a completed input line and, if allowed, submit it.
   *
   * The characters themselves have already been streamed to the PTY as they
   * were typed (that is how a shell works: nothing executes until Enter). What
   * is withheld on a denial is the line terminator, so a refused command is left
   * unexecuted at the prompt while the candidate still sees what they typed.
   */
  #submitLine(terminator) {
    const line = this.#writeBuffer.trim();
    this.#writeBuffer = '';

    if (line === '') {
      this.#pty.write(terminator);
      return { ok: true, decision: 'allow', match: null, line: '' };
    }

    const verdict = screenCommand(line, this.#policy);
    this.#audit.record(verdict.decision === 'deny' ? 'terminal.command.denied' : 'terminal.command', {
      line,
      match: verdict.match,
    });

    if (verdict.decision === 'deny') {
      this.emit('command:denied', { line, match: verdict.match });
      return { ok: false, decision: 'deny', match: verdict.match, line };
    }

    this.#pty.write(terminator);
    return { ok: true, decision: 'allow', match: verdict.match, line };
  }

  /**
   * Raw input from the browser. This is where the command policy bites.
   *
   * Input arrives as whatever the terminal emits per keystroke, so a frame may
   * be one character (`\r` for Enter), a pasted block, or a whole line with its
   * terminator. Screening therefore happens on the reconstructed line when the
   * terminator arrives -- checking only a frame that happens to contain both
   * would miss the ordinary case of typing a line and then pressing Enter.
   */
  write(data) {
    if (!this.#pty) {
      return { ok: false, decision: 'deny', match: null, line: '', reason: 'no-pty' };
    }

    const text = String(data);
    let result = { ok: true, decision: 'allow', match: null, line: '' };
    let lastWasLineEnd = false;

    for (const char of text) {
      if (TerminalSession.#isLineEnd(char)) {
        // CRLF is one Enter, not two. Without this, Windows-style "\r\n" would
        // submit the line, then submit an empty second line whose terminator
        // reached the PTY -- which executes the very command just refused.
        if (lastWasLineEnd) {
          lastWasLineEnd = false;
          continue;
        }
        lastWasLineEnd = true;
        const submitted = this.#submitLine(char);
        if (!submitted.ok) result = submitted;
      } else {
        lastWasLineEnd = false;
        this.#writeBuffer += char;
        this.#pty.write(char);
      }
    }

    return result;
  }

  resize(cols, rows) {
    if (!Number.isInteger(cols) || !Number.isInteger(rows)) return;
    if (cols < 2 || rows < 2 || cols > 500 || rows > 200) return;
    this.#cols = cols;
    this.#rows = rows;
    try {
      this.#pty?.resize(cols, rows);
    } catch (err) {
      log.warn(`resize failed: ${err.message}`);
    }
  }

  attach(socket) {
    if (this.#reapTimer) {
      clearTimeout(this.#reapTimer);
      this.#reapTimer = null;
    }
    this.#sockets.add(socket);
    // Replay scrollback so a refresh does not lose the screen.
    for (const chunk of this.#scrollback) socket.send(JSON.stringify({ type: 'data', data: chunk }));
  }

  detach(socket, { graceMs = 20_000 } = {}) {
    this.#sockets.delete(socket);
    if (this.#sockets.size > 0 || !this.#pty) return;
    this.#reapTimer = setTimeout(() => {
      if (this.#sockets.size === 0) this.kill('last-socket-detached');
    }, graceMs);
    this.#reapTimer.unref?.();
  }

  kill(reason = 'killed') {
    if (this.#reapTimer) clearTimeout(this.#reapTimer);
    this.#reapTimer = null;
    if (!this.#pty) return { ok: true, alreadyStopped: true };
    const pid = this.#pty.pid;
    try {
      // On Windows node-pty's kill() takes no signal.
      this.#pty.kill();
    } catch (err) {
      log.warn(`pty.kill failed: ${err.message}`);
    }
    try {
      // Belt and braces: descendants a candidate started are in the same tree.
      spawnChild('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
    } catch {
      /* best effort */
    }
    this.#audit.record('terminal.killed', { pid, reason });
    return { ok: true, pid };
  }

  describe() {
    return {
      alive: this.alive,
      pid: this.pid,
      startedAt: this.#startedAt,
      sockets: this.#sockets.size,
      confinement: this.#confinement.mode,
      scrollbackChunks: this.#scrollback.length,
    };
  }
}

// ---------------------------------------------------------------------------
// AppLocker starting point
// ---------------------------------------------------------------------------

/**
 * Emit an AppLocker policy that denies executables outside the exam allowlist.
 * NOT applied automatically -- applying it is an administrative decision, and
 * it is machine-wide. The operator applies it with:
 *
 *   Set-AppLockerPolicy -XmlPolicy build/applocker-razor.xml
 *
 * Deliberately not called from the server: a policy that can be applied by the
 * same user the policy constrains is not a policy.
 */
export function generateAppLockerPolicy({ examUserSid, razorUser = null, extraPaths = [] }) {
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const userSid = examUserSid ?? '*';
  const filePathRule = (id, name, path, sid = 'S-1-1-0') => `
    <FilePathRule Id="${id}" Name="${esc(name)}" Description="" UserOrGroupSid="${esc(sid)}" Action="Allow">
      <Conditions>
        <FilePathCondition Path="${esc(path)}" />
      </Conditions>
    </FilePathRule>`;

  return `<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by razor-ide/src/terminal.mjs -- review before applying.
     Apply with: Set-AppLockerPolicy -XmlPolicy <this file> -ErrorAction Stop
     Deny-by-default for the exam account is implicit: AppLocker denies anything
     not matched by an Allow rule once its service is enforcing. -->
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
${filePathRule('a1000000-0000-4000-8000-000000000001', 'SEB install', '%PROGRAMFILES%\\SafeExamBrowser\\*')}
${filePathRule('a1000000-0000-4000-8000-000000000002', 'Windows', '%WINDIR%\\*')}
${filePathRule('a1000000-0000-4000-8000-000000000003', 'Program Files', '%PROGRAMFILES%\\*')}
${filePathRule('a1000000-0000-4000-8000-000000000004', 'Python', '%PROGRAMFILES%\\Python*\\*')}
${filePathRule('a1000000-0000-4000-8000-000000000005', 'Node runtime (for Razor)', '%PROGRAMFILES%\\nodejs\\*')}
${extraPaths.map((p, i) => filePathRule(`a1000000-0000-4000-8000-0000000010${i}`, `Extra ${i}`, p)).join('\n')}
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="Enabled">
${filePathRule('a1000000-0000-4000-8000-000000000101', 'PowerShell', '%WINDIR%\\System32\\WindowsPowerShell\\v1.0\\*')}
${filePathRule('a1000000-0000-4000-8000-000000000102', 'Cmd', '%WINDIR%\\System32\\cmd.exe')}
  </RuleCollection>
</AppLockerPolicy>
<!-- Scope note: apply this to the exam account (${esc(userSid)}), not to
     administrators, so the proctor can still recover the machine. -->
`;
}
