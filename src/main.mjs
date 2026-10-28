// Razor entry point.
//
//   node src/main.mjs [--ui dev|prod] [--seb] [--seb-argv-only]
//                     [--bypass-gate] [--port N] [--host H]
//
// Order of operations (matches the brief):
//   1. resolve mode + credentials, fail closed in production
//   2. create the run directory and the workspace
//   3. start the IDE server and print its origin
//   4. arm the gate -- the session does not exist yet
//   5. only when an admin grant arrives: mint a session, generate the .seb,
//      launch Safe Exam Browser
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { isProduction, logger, readEnv, workspaceDir } from './config.mjs';
import { SessionGate, GateState } from './security/gate.mjs';
import { AuditLog, PATHS, ensureDirs, hardenDirectoryAcl, removeQuietly } from './security/state.mjs';
import { randomHex } from './security/crypto.mjs';
import { issueGrant, bootstrapTtlMs } from './security/grants.mjs';
import { resolveAdminCredentials, authenticateAdmin } from './admin.mjs';
import { Workspace, seedWorkspace } from './files.mjs';
import { TerminalSession, createConfinement, resolvePolicy, generateAppLockerPolicy } from './terminal.mjs';
import { RazorServer } from './server.mjs';
import { ControlPlaneClient, CommandKind } from './heartbeat.mjs';
import {
  buildSebArgv,
  findSebExecutable,
  inspectSebBinary,
  launchSeb,
  killSebProcesses,
} from './seb/launch.mjs';
import { buildSebPolicy, machineId, validateSebPolicy } from './seb/config.mjs';
import { createSebExitHandler } from './seb/lifecycle.mjs';
import { Prefix, inspectContainer, writeSebFile } from './seb/container.mjs';
import { sebConfigKey } from './security/crypto.mjs';

const log = logger('main');

async function main() {
  const env = readEnv();
  const production = isProduction(env);

  ensureDirs();
  hardenDirectoryAcl(PATHS.run);

  printBanner(env);

  // -- 1. credentials --------------------------------------------------------
  const credentials = resolveAdminCredentials(env);
  if (credentials.ok === false) {
    log.error(credentials.detail);
    process.exitCode = 2;
    return;
  }
  if (credentials.generated) {
    log.warn(`generated a dev admin password in ${PATHS.adminKey} -- never do this in production`);
  }

  // -- 2. audit + gate key ---------------------------------------------------
  const audit = new AuditLog();
  audit.record('razor.boot', {
    mode: env.mode,
    ui: env.ui,
    sebRequested: env.seb,
    hostname: hostname(),
    node: process.version,
    adminSource: credentials.source,
  });

  const adminKey = loadOrCreateAdminKey(production);
  const machine = machineId({ hostname: hostname() });

  const gate = new SessionGate({ env, key: adminKey, machineId: machine, audit });
  gate.start();

  // -- 3. workspace ----------------------------------------------------------
  const root = workspaceDir(env);
  const workspace = new Workspace(root, { isolate: process.env.RAZOR_ISOLATE_WORKSPACE !== '0' });
  seedWorkspace(workspace);
  log.info(`workspace: ${workspace.root}`);

  // -- 4. terminal -----------------------------------------------------------
  const confinementMode = process.env.RAZOR_CONFINEMENT ?? (production ? 'jobobject' : 'none');
  const confinement = createConfinement({
    mode: confinementMode,
    policy: resolvePolicy(null),
    onWarning: (reason) =>
      audit.record('terminal.confinement.unavailable', { mode: confinementMode, reason }),
  });
  const terminal = new TerminalSession({
    policy: resolvePolicy(null),
    cwd: workspace.root,
    audit,
    confinement,
  });

  // -- 5. SEB controller -----------------------------------------------------
  const seb = new SebController({ env, audit, gate, onExit: handleSebExit });
  const server = new RazorServer({
    env,
    gate,
    workspace,
    terminal,
    credentials,
    sebState: seb.publicState,
  });
  seb.attach({ server, workspace });
  const { origin } = await server.listen({ host: env.host, port: env.port });
  writeJson(PATHS.session, { origin, mode: env.mode, startedAt: new Date().toISOString() });

  log.info(`razor IDE listening on ${origin}`);
  log.info(`gate: ${gate.state} (no session until an admin grant arrives)`);

  // -- 6. admin request sources ---------------------------------------------
  if (env.bypassGate && !production) {
    const result = gate.devStart('cli-flag');
    if (result.ok) {
      log.warn('--bypass-gate: session started without an admin request (DEV ONLY)');
      await onSessionStarted({ env, gate, seb, audit, server });
    } else {
      log.warn(`--bypass-gate refused: ${result.reason}`);
    }
  } else if (env.bypassGate && production) {
    audit.record('bypass.refused', { source: 'cli-flag', reason: 'production' });
    log.error('--bypass-gate is refused in production and has been logged.');
  }

  startControlPlane(env, { gate, seb, terminal, audit, server });

  // -- 7. control surface ----------------------------------------------------
  installSignalHandlers({ server, gate, terminal, seb, audit });

  if (env.seb && env.sebArgvOnly) {
    // Safe SEB integration smoke test: print the exact command line and stop.
    // Does not lock the desktop, so it is safe to run in a terminal.
    const readiness = seb.dryRun();
    log.info(`--seb-argv-only: not launching`);
    console.log(readiness.argv.printable);
    if (readiness.problems.length) {
      for (const problem of readiness.problems) log.warn(`seb config problem: ${problem}`);
    }
    return;
  }

  gate.on('state', (event) => {
    log.info(`gate ${event.previous} -> ${event.next}`);
    if (event.next === GateState.RUNNING && env.seb) {
      void onSessionStarted({ env, gate, seb, audit, server });
    }
  });
}

// ---------------------------------------------------------------------------
// Session start: generate the .seb and launch SEB
// ---------------------------------------------------------------------------

async function onSessionStarted({ env, gate, seb, audit, server }) {
  const session = gate.session;
  if (!session) return;

  // The TTL has to outlast SEB's startup in the --seb path; see
  // DEFAULT_BOOTSTRAP_TTL_MS for the measurement that set it.
  const bootstrap = session.mintBootstrap(bootstrapTtlMs());
  const startUrl = `${server.origin}/?b=${bootstrap}`;
  audit.record('session.start_url', { startUrl: `${server.origin}/?b=<redacted>` });

  if (!env.seb) {
    log.info(`session live. open ${startUrl} in the exam browser`);
    console.log(`\n  Razor start URL (single use): ${startUrl}\n`);
    return;
  }

  const result = await seb.start({ startUrl, quitPassword: session.grant.sebQuitPassword, mode: env.mode });
  if (!result.ok) {
    log.error(`SEB launch refused: ${result.reason} ${result.detail ?? ''}`);
    audit.record('seb.launch.refused', result);
    if (isProduction(env)) {
      // Fail closed: no SEB, no exam.
      gate.stopSession(`seb-not-launched:${result.reason}`);
    }
  }
}

/**
 * SEB exit handling lives in ./seb/lifecycle.mjs so it is unit-testable; see
 * the note there about the positional-argument bug this replaced.
 */
const handleSebExit = createSebExitHandler;

// ---------------------------------------------------------------------------
// SEB controller
// ---------------------------------------------------------------------------

class SebController {
  #env;
  #audit;
  #gate;
  #onExit;
  #server = null;
  #workspace = null;
  #handle = null;
  publicState = {
    running: false,
    pid: null,
    version: null,
    binary: null,
    binarySha256: null,
    configPath: null,
    configPrefix: null,
    configKeyHash: null,
    attestation: 'not-configured',
    lastExit: null,
  };

  constructor({ env, audit, gate, onExit }) {
    this.#env = env;
    this.#audit = audit;
    this.#gate = gate;
    this.#onExit = onExit;
  }

  attach({ server, workspace }) {
    this.#server = server;
    this.#workspace = workspace;
  }

  /** Build the config and argv without launching. Used by --seb-argv-only. */
  dryRun({ startUrl = 'http://127.0.0.1:0/?b=PREVIEW' } = {}) {
    const problems = [];
    const located = findSebExecutable();
    if (!located.ok) problems.push(`${located.reason}: ${located.detail}`);

    const configPath = this.#configPath();
    let policy = null;
    try {
      policy = buildSebPolicy({
        startUrl,
        quitPassword: 'PREVIEW-ONLY',
        mode: this.#env.mode,
        windowed: process.env.RAZOR_SEB_WINDOWED === '1',
        allowedOrigins: parseList(process.env.RAZOR_SEB_ALLOW_ORIGINS),
        sendBrowserExamKey: process.env.RAZOR_SEB_KEY_HEADERS !== '0',
        enableDevConsole: !isProduction(this.#env) && !hardenedSeb(),
        hardened: hardenedSeb(),
      });
      problems.push(...validateSebPolicy(policy));
    } catch (err) {
      problems.push(`policy build failed: ${err.message}`);
    }

    return {
      argv: buildSebArgv({ executable: located.path ?? '<SEB not found>', configPath }),
      problems,
      policy,
    };
  }

  async start({ startUrl, quitPassword, mode }) {
    const located = findSebExecutable();
    if (!located.ok) return { ok: false, reason: located.reason, detail: located.detail };

    // Verify the binary before locking a candidate's desktop with it.
    const binary = inspectSebBinary(located.path);
    if (!binary.ok) {
      log.error(`SEB binary check failed: ${binary.reason} ${binary.detail ?? ''}`);
      if (isProduction(this.#env)) {
        return { ok: false, reason: `seb-binary-${binary.reason}`, detail: binary.detail };
      }
      log.warn('continuing anyway because RAZOR_ENV is not production');
    }
    this.publicState.version = binary.version ?? null;
    this.publicState.binary = binary.path;
    this.publicState.signedByEth = binary.signedByEth ?? null;

    // An operator-supplied encrypted config always wins over our generated one.
    const supplied = process.env.RAZOR_SEB_CONFIG;
    let configPath = this.#configPath();
    let prefix = Prefix.Plain;
    let configKeyHash = null;
    let plist = null;

    if (supplied) {
      if (!existsSync(supplied)) return { ok: false, reason: 'seb-config-missing', detail: supplied };
      const buffer = readFileSync(supplied);
      const info = inspectContainer(buffer);
      if (!info.ok) return { ok: false, reason: 'seb-config-unreadable', detail: info.detail ?? info.reason };
      configPath = supplied;
      prefix = info.prefix;
      if (prefix !== Prefix.Plain) {
        // We cannot derive the Config Key from an encrypted config, so
        // attestation stays off unless the operator pinned the expected hash.
        configKeyHash = process.env.RAZOR_SEB_CONFIG_KEY_HASH ?? null;
        this.publicState.attestation = configKeyHash ? 'pinned-config-key' : 'encrypted-not-verifiable';
      }
    } else {
      if (isProduction(this.#env) && process.env.RAZOR_ALLOW_UNENCRYPTED_SEB !== '1') {
        return {
          ok: false,
          reason: 'unencrypted-config-in-production',
          detail:
            'Production requires an encrypted .seb (RAZOR_SEB_CONFIG=...) because a plain ' +
            'config is readable and forgeable by the candidate. Set ' +
            'RAZOR_ALLOW_UNENCRYPTED_SEB=1 to override explicitly (this is logged).',
        };
      }
      try {
        plist = buildSebPolicy({
          startUrl,
          quitPassword,
          mode: mode ?? this.#env.mode,
          windowed: process.env.RAZOR_SEB_WINDOWED === '1',
          allowedOrigins: parseList(process.env.RAZOR_SEB_ALLOW_ORIGINS),
          sendBrowserExamKey: process.env.RAZOR_SEB_KEY_HEADERS !== '0',
          enableDevConsole: !isProduction(this.#env) && !hardenedSeb(),
          hardened: hardenedSeb(),
        });
      } catch (err) {
        return { ok: false, reason: 'policy-build-failed', detail: err.message };
      }

      const problems = validateSebPolicy(plist);
      if (problems.length) {
        for (const problem of problems) log.warn(`seb config: ${problem}`);
        if (isProduction(this.#env)) return { ok: false, reason: 'policy-invalid', detail: problems.join('; ') };
      }

      // Compute the Config Key *before* writing, from the same object that
      // produces the XML, so what we verify against is what we shipped.
      configKeyHash = sebConfigKey(plist);
      writeSebFile(configPath, plist);
      writeFileSync(PATHS.sebPlist, `${JSON.stringify(plist, null, 2)}\n`, 'utf8');
      this.publicState.attestation = 'config-key-computed';
    }

    this.publicState.configPath = configPath;
    this.publicState.configPrefix = prefix;
    this.publicState.configKeyHash = configKeyHash;
    this.#server.setSebState(this.publicState, configKeyHash);

    this.#audit.record('seb.config', { configPath, prefix, configKeyHash, attestation: this.publicState.attestation });

    const handle = launchSeb({
      executable: binary.path,
      configPath,
      onExit: (info) => {
        this.publicState.running = false;
        this.publicState.pid = null;
        this.publicState.lastExit = { at: Date.now(), code: info.code, signal: info.signal, reason: info.error ? 'error' : 'exit' };
        this.#onExit?.({
          env: this.#env,
          gate: this.#gate,
          audit: this.#audit,
        })(this.publicState.lastExit);
      },
    });
    this.#handle = handle;
    this.publicState.running = true;
    this.publicState.pid = handle.pid;
    this.#audit.record('seb.launched', { pid: handle.pid, argv: handle.argv.printable });
    log.info(`SEB started (pid ${handle.pid}); kiosk active. Quit password is per-session.`);
    return { ok: true, pid: handle.pid, configPath, prefix };
  }

  async stop(reason) {
    if (!this.publicState.running) return { ok: true, alreadyStopped: true };
    killSebProcesses();
    this.publicState.running = false;
    this.#audit.record('seb.stopped', { reason });
    return { ok: true, reason };
  }

  #configPath() {
    return process.env.RAZOR_SEB_CONFIG_OUT ?? PATHS.sebConfig;
  }
}

// ---------------------------------------------------------------------------
// Control plane (outbound heartbeat + lease renewal)
// ---------------------------------------------------------------------------

function startControlPlane(env, { gate, seb, terminal, audit, server }) {
  const baseUrl = process.env.RAZOR_CONTROL_PLANE_URL;
  if (!baseUrl) {
    log.info('RAZOR_CONTROL_PLANE_URL not set: running in local-admin mode');
    return null;
  }

  const client = new ControlPlaneClient({
    baseUrl,
    deviceId: process.env.RAZOR_DEVICE_ID ?? machineId({ hostname: hostname() }),
    token: process.env.RAZOR_DEVICE_TOKEN ?? null,
    statusProvider: () => ({
      mode: env.mode,
      gateState: gate.state,
      lease: gate.describe().lease,
      seb: { running: seb.publicState.running, version: seb.publicState.version, prefix: seb.publicState.configPrefix },
      terminal: terminal.describe(),
      policy: resolvePolicy(null).allowedPrograms,
    }),
    onMiss: ({ misses, reason }) => audit.record('controlplane.miss', { misses, reason }),
    onRecover: () => audit.record('controlplane.recovered', {}),
    onCommand: (command) => handleControlPlaneCommand(command, { env, gate, seb, terminal, audit, server }),
  });

  client.start();
  log.info(`control-plane heartbeat active: ${baseUrl} (every ${process.env.RAZOR_HEARTBEAT_MS ?? 7000} ms)`);
  return client;
}

function handleControlPlaneCommand(command, { env, gate, seb, terminal, audit, server }) {
  const kind = String(command.kind);
  audit.record('controlplane.command', { kind, id: command.id ?? null });

  switch (kind) {
    case CommandKind.START_SESSION: {
      if (command.grant) {
        const result = server.startSessionFromExternal({ grant: command.grant, source: 'control-plane' });
        if (!result.ok) {
          audit.record('controlplane.start.refused', result);
          log.error(`control-plane start refused: ${result.reason}`);
        }
        return result;
      }
      // No signed grant: fall back to the local issue path, which is exactly
      // what a local admin would do. Recorded so the weaker provenance shows.
      const result = server.startSessionFromExternal({ source: 'control-plane-unsigned' });
      audit.record('controlplane.start.unsigned', { ok: result.ok });
      return result;
    }
    case CommandKind.STOP_SESSION:
      terminal.kill('control-plane-stop');
      void seb.stop('control-plane-stop');
      return gate.stopSession('control-plane-stop');

    case CommandKind.EXTEND: {
      gate.session?.renew();
      audit.record('session.extended', { by: 'control-plane', minutes: command.minutes ?? null });
      return { ok: true };
    }

    case CommandKind.LOCK:
      return gate.stopSession('control-plane-lock');

    case CommandKind.COLLECT: {
      const listing = server.workspace?.list?.('.') ?? null;
      audit.record('artifacts.collect', { entries: listing?.entries?.length ?? null });
      return { ok: true, note: 'artifacts remain local; upload is out of scope for this build' };
    }

    default:
      log.warn(`unhandled command ${kind}`);
      return { ok: false, reason: 'unhandled' };
  }
}

/**
 * Desktop-level kiosk enforcement, requested by the operator.
 *
 * `RAZOR_SEB_HARDENED=1` forces the SEB settings that make the lockdown real --
 * a dedicated SEB desktop with the Explorer shell out of the way -- instead of a
 * fullscreen browser on the candidate's own desktop. It exists so an operator
 * can rehearse a production-grade lockdown while still running in dev mode
 * (bypassable gate, plain .seb, quittable kiosk). Production implies it.
 */
const hardenedSeb = () => process.env.RAZOR_SEB_HARDENED === '1';

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

function installSignalHandlers({ server, gate, terminal, seb, audit }) {
  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.warn(`received ${signal}; shutting down`);
    audit.record('razor.shutdown', { signal });
    gate.stop();
    if (isProduction(readEnv())) {
      // Never leave a candidate inside a kiosk with no Razor behind it.
      await seb.stop('shutdown');
    }
    terminal.kill('shutdown');
    gate.stopSession('shutdown');
    await server.close();
    audit.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

function loadOrCreateAdminKey(production) {
  const fromEnv = process.env.RAZOR_GRANT_KEY;
  if (fromEnv) return fromEnv;

  if (existsSync(PATHS.adminKey) && !production) {
    const existing = readFileSync(PATHS.adminKey, 'utf8').trim();
    if (/^[0-9a-f]{64}$/.test(existing)) return existing;
  }
  if (production && !fromEnv) {
    // A generated key means grants cannot be forged by editing the file we
    // just wrote, but it also means an out-of-process issuer cannot sign.
    log.warn('RAZOR_GRANT_KEY is not set: grants are signed with a per-run key, so only this process can issue them.');
  }
  const key = randomHex(32);
  removeQuietly(PATHS.adminKey);
  writeFileSync(PATHS.adminKey, key + '\n', 'utf8');
  return key;
}

function writeJson(path, value) {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

function parseList(value) {
  return String(value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function printBanner(env) {
  const production = isProduction(env);
  console.log('');
  console.log('  Razor IDE');
  console.log(`  security mode : ${production ? 'PRODUCTION (lockdown enforced)' : 'DEV (restrictions bypassable)'}`);
  console.log(`  ui mode       : ${env.ui}`);
  console.log(`  safe exam br. : ${env.seb ? 'will launch' : 'not launched'}`);
  console.log(`  workspace     : ${workspaceDir(env)}`);
  console.log('');
  if (production) {
    log.info('production mode: --bypass-gate is ignored, an admin grant is required, SEB is required.');
  } else if (env.modeWasImplicit) {
    log.warn('RAZOR_ENV was not set, so Razor defaulted to dev mode. Set RAZOR_ENV=production for exams.');
  }

  // Emit the AppLocker starting point once per boot so the operator has it.
  const aclPath = join(PATHS.build, 'applocker-razor.xml');
  if (!existsSync(aclPath)) {
    writeFileSync(aclPath, generateAppLockerPolicy({ examUserSid: process.env.RAZOR_EXAM_SID ?? '*' }), 'utf8');
    log.info(`wrote an AppLocker starting point to ${aclPath} (review before applying)`);
  }
}

export { authenticateAdmin };

// Entry point runs last so every class declaration above is initialised.
main().catch((err) => {
  log.error(`fatal: ${err.stack ?? err.message}`);
  process.exitCode = 1;
});
