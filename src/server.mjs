// Zero-dependency HTTP server + WebSocket upgrade handling.
//
// Hardening applied on *every* request, before routing:
//   1. Host header must be loopback (DNS-rebinding guard).
//   2. Origin header, when present, must be loopback (CSWSH guard).
//   3. `?b=<bootstrap>` is single-use and is exchanged for an
//      HttpOnly + SameSite=Strict cookie, so the token never lives in a URL,
//      in browser history, or in the WebSocket query string.
//   4. Strict CSP with no external origins: the IDE must work with SEB's URL
//      filter blocking everything except the loopback origin.
import { createServer } from 'node:http';
import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { basename, extname, join, normalize } from 'node:path';
import { WebSocketServer } from 'ws';
import { logger, ROOT } from './config.mjs';
import { authenticateAdmin, verifyHostAndOrigin, verifySebRequest } from './admin.mjs';
import { resolvePolicy } from './terminal.mjs';
import { issueGrant, bootstrapTtlMs } from './security/grants.mjs';
import { loadPtyModule } from './pty.mjs';
import { createZip } from './zip.mjs';

const log = logger('server');

export const SESSION_COOKIE = 'razor_session';
export const BOOTSTRAP_PARAM = 'b';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
};

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' ws://127.0.0.1:* ws://localhost:*",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
].join('; ');

export class RazorServer {
  #env;
  #gate;
  #workspace;
  #terminal;
  #credentials;
  #sebState;
  #sebPublic = null;
  #sebConfigKeyHash = null;
  #http = null;
  #wss = null;
  #port = null;

  constructor({ env, gate, workspace, terminal, credentials, sebState = {} }) {
    this.#env = env;
    this.#gate = gate;
    this.#workspace = workspace;
    this.#terminal = terminal;
    this.#credentials = credentials;
    this.#sebState = sebState;
    // The caller normally hands us the SEB controller's *live* state object, so
    // both would be the same reference. Keep the display copy in its own field:
    // writing `#sebState.public = #sebState` makes that object self-referential,
    // and every /api/state or /admin/status response then dies with
    // "Converting circular structure to JSON" (which is exactly what happened
    // the moment SEB reported itself launched).
    this.#sebPublic = sebState.public ?? null;
    this.#sebConfigKeyHash = sebState.expectedConfigKeyHash ?? null;
  }

  get workspace() {
    return this.#workspace;
  }

  /**
   * Late-bound SEB state: the expected Config Key only exists once a config has
   * been generated, which happens after the server is listening.
   */
  setSebState(publicState, expectedConfigKeyHash) {
    this.#sebPublic = publicState ?? null;
    this.#sebConfigKeyHash = expectedConfigKeyHash ?? null;
  }

  get port() {
    return this.#port;
  }

  get origin() {
    return `http://127.0.0.1:${this.#port}`;
  }

  async listen({ host = '127.0.0.1', port = 0 } = {}) {
    this.#http = createServer((req, res) => {
      this.#handle(req, res).catch((err) => {
        log.error(`unhandled request error: ${err.stack ?? err.message}`);
        this.#json(res, 500, { error: 'internal', detail: err.message });
      });
    });

    this.#wss = new WebSocketServer({ noServer: true });
    this.#http.on('upgrade', (req, socket, head) => this.#handleUpgrade(req, socket, head));

    await new Promise((resolve, reject) => {
      this.#http.once('error', reject);
      this.#http.listen(port, host, () => {
        this.#port = this.#http.address().port;
        resolve();
      });
    });

    this.#gate.audit.record('server.listening', { origin: this.origin, mode: this.#env.mode });
    return { origin: this.origin, port: this.#port };
  }

  async close() {
    for (const client of this.#wss?.clients ?? []) {
      try {
        client.close(1001, 'server shutting down');
      } catch {
        /* best effort */
      }
    }
    await new Promise((resolve) => this.#http?.close(resolve));
  }

  // -------------------------------------------------------------------------
  // Request pipeline
  // -------------------------------------------------------------------------

  async #handle(req, res) {
    const url = new URL(req.url, `http://127.0.0.1:${this.#port}`);
    const headers = req.headers;

    res.setHeader('content-security-policy', CSP);
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('cache-control', 'no-store');

    const hostCheck = verifyHostAndOrigin({
      hostHeader: headers.host,
      originHeader: headers.origin,
      port: this.#port,
    });
    if (!hostCheck.ok) {
      this.#gate.audit.record('http.rejected', { reason: hostCheck.reason, path: url.pathname, host: headers.host });
      return this.#json(res, 403, { error: hostCheck.reason });
    }

    // -- bootstrap handshake ------------------------------------------------
    const bootstrap = url.searchParams.get(BOOTSTRAP_PARAM);
    if (bootstrap) {
      const result = this.#gate.session?.consumeBootstrap(bootstrap);
      if (!result?.ok) {
        this.#gate.audit.record('bootstrap.refused', { reason: result?.reason ?? 'no-session' });
        return this.#html(res, 403, rejectionPage(result?.reason ?? 'no-session'));
      }
      // Exchange the single-use code for the session cookie and scrub the URL,
      // so a copied start URL is worthless after the first load.
      this.#gate.audit.record('bootstrap.accepted', { ip: req.socket.remoteAddress });
      res.setHeader(
        'set-cookie',
        `${SESSION_COOKIE}=${this.#gate.session.token}; HttpOnly; SameSite=Strict; Path=/`,
      );
      res.statusCode = 303;
      res.setHeader('location', '/');
      return res.end();
    }

    // -- public endpoints ---------------------------------------------------
    if (url.pathname === '/healthz') {
      return this.#json(res, 200, { ok: true, mode: this.#env.mode });
    }

    if (url.pathname === '/api/state') {
      // Reachable without a session so a locked gate can render an explanation.
      return this.#json(res, 200, {
        gate: this.#gate.describe(),
        mode: this.#env.mode,
        seb: this.#sebPublic,
        terminalPolicy: this.#publicPolicy(),
      });
    }

    if (url.pathname === '/admin/status' || url.pathname.startsWith('/admin/')) {
      return this.#handleAdmin(req, res, url);
    }

    // -- authenticated surface ---------------------------------------------
    const auth = this.#authorize(req, url);
    if (!auth.ok) {
      const gateState = this.#gate.state;
      if (url.pathname.startsWith('/api/')) {
        return this.#json(res, auth.status ?? 401, {
          error: auth.reason,
          gate: gateState,
          hint:
            gateState === 'awaiting_admin'
              ? 'no session: an admin grant is required before the IDE unlocks'
              : gateState === 'locked'
                ? `session locked: ${this.#gate.lockReason}`
                : undefined,
        });
      }
      return this.#html(res, auth.status ?? 401, rejectionPage(auth.reason, gateState));
    }

    if (url.pathname.startsWith('/api/files')) return this.#handleFiles(req, res, url);
    if (url.pathname === '/api/seb/verify') return this.#handleSebVerify(req, res, url);

    if (url.pathname === '/' || url.pathname === '/index.html') {
      return this.#serveStatic(res, 'index.html');
    }
    if (url.pathname.startsWith('/vendor/')) {
      return this.#serveStatic(res, url.pathname.slice(1));
    }

    return this.#json(res, 404, { error: 'not-found', path: url.pathname });
  }

  #publicPolicy() {
    const policy = this.#gate.session?.grant?.terminalPolicy ?? null;
    const resolved = resolvePolicy(policy);
    return {
      allowedPrograms: resolved.allowedPrograms,
      maxProcesses: resolved.maxProcesses,
      maxMemoryMb: resolved.maxMemoryMb,
    };
  }

  /** Session cookie first, then a bearer token for CLI/tests. */
  #authorize(req, url) {
    if (!this.#gate.session) return { ok: false, reason: 'no-session', status: 401 };
    if (this.#gate.state === 'locked' || this.#gate.state === 'stopped') {
      return { ok: false, reason: `session-${this.#gate.state}`, status: 403 };
    }
    if (!this.#gate.session.isUsable()) {
      return { ok: false, reason: 'lease-expired', status: 403 };
    }

    const cookies = parseCookies(req.headers.cookie);
    const fromCookie = cookies[SESSION_COOKIE];
    if (fromCookie && this.#gate.tokenMatches(fromCookie)) return { ok: true, via: 'cookie' };

    const authHeader = req.headers.authorization;
    if (/^Bearer\s+/i.test(String(authHeader ?? ''))) {
      const supplied = String(authHeader).replace(/^Bearer\s+/i, '').trim();
      if (this.#gate.tokenMatches(supplied)) return { ok: true, via: 'bearer' };
    }

    return { ok: false, reason: 'unauthorized', status: 401 };
  }

  // -------------------------------------------------------------------------
  // Admin endpoints
  // -------------------------------------------------------------------------

  /**
   * Tell the candidate when a line was refused. The audit entry is written by
   * TerminalSession.write, which is the single screening point for input.
   */
  #rejectIfDenied(ws, verdict) {
    if (!verdict || verdict.decision !== 'deny') return;
    safeSend(
      ws,
      JSON.stringify({
        type: 'notice',
        level: 'error',
        message: `Refused: "${verdict.match}" is not permitted in the exam terminal. This attempt has been logged.`,
      }),
    );
  }

  async #handleAdmin(req, res, url) {
    const user = authenticateAdmin(req.headers.authorization, this.#credentials);
    const audit = (kind, detail) =>
      this.#gate.audit.record(kind, { actor: user ?? 'anonymous', ...detail });

    if (url.pathname === '/admin/status') {
      if (!user) {
        audit('admin.unauthorized', { path: url.pathname });
        return this.#json(res, 401, { error: 'unauthorized' });
      }
      return this.#json(res, 200, {
        gate: this.#gate.describe(),
        mode: this.#env.mode,
        monitor: this.#sebPublic,
        terminal: this.#terminal.describe(),
      });
    }

    if (url.pathname === '/admin/session/start') {
      if (!user && this.#env.mode === 'production') {
        audit('admin.unauthorized', { path: url.pathname });
        return this.#json(res, 401, { error: 'unauthorized' });
      }

      const body = await readJsonBody(req);
      if (body === BAD_JSON) return this.#json(res, 400, { error: 'bad-json' });

      if (!user) {
        // Dev-only convenience: the printed start URL carries the local admin
        // key, so the CLI/curl path works without credentials in dev.
        const decision = this.#gate.requestBypass('admin-endpoint-unauthenticated');
        if (!decision.ok) {
          audit('admin.unauthorized', { path: url.pathname, detail: decision.reason });
          return this.#json(res, 401, { error: 'unauthorized', detail: decision.reason });
        }
      }

      const result = this.#startSession({ body, source: body?.source ?? (user ? 'admin-endpoint' : 'dev-bypass') });
      return this.#json(res, result.ok ? 200 : 400, result);
    }

    if (url.pathname === '/admin/session/stop') {
      if (!user) {
        audit('admin.unauthorized', { path: url.pathname });
        return this.#json(res, 401, { error: 'unauthorized' });
      }
      const result = this.#gate.stopSession('admin-stop');
      this.#terminal.kill('admin-stop');
      await this.#sebState.stop?.('admin-stop');
      return this.#json(res, 200, { ...result, gate: this.#gate.describe() });
    }

    if (url.pathname === '/admin/session/extend') {
      if (!user) return this.#json(res, 401, { error: 'unauthorized' });
      const body = await readJsonBody(req);
      const minutes = Number(body?.minutes ?? 0);
      if (!Number.isFinite(minutes) || minutes <= 0 || minutes > 240) {
        return this.#json(res, 400, { error: 'minutes must be between 1 and 240' });
      }
      this.#gate.session?.renew();
      audit('session.extended', { minutes });
      return this.#json(res, 200, { ok: true, gate: this.#gate.describe() });
    }

    return this.#json(res, 404, { error: 'not-found', path: url.pathname });
  }

  /** Shared by the admin endpoint and the control-plane command handler. */
  startSessionFromExternal({ grant, source }) {
    if (grant) return { ...this.#gate.applyGrant(grant, { source }), startedBy: source };
    return this.#startSession({ body: {}, source });
  }

  /** The Config Key the launched SEB instance must present, if known. */
  get expectedConfigKeyHash() {
    return this.#sebConfigKeyHash;
  }

  #startSession({ body, source }) {
    // Per-session quit password: from the request if supplied, otherwise
    // generated and reported once so the proctor can hold it.
    const sessionSecret = body?.sebQuitPassword ?? generateSecret();
    const grant = issueGrant({
      key: this.#gate.adminKey,
      examId: body?.examId ?? 'local',
      machineId: this.#gate.machineId,
      issuedBy: source,
      ttlMs: Number(body?.ttlMs ?? 120_000),
      sebQuitPassword: sessionSecret,
      terminalPolicy: body?.terminalPolicy ?? null,
      extendMinutes: Number(body?.extendMinutes ?? 0),
    });

    const applied = this.#gate.applyGrant(grant, { source });
    if (!applied.ok) return applied;

    // Mint the bootstrap code that goes into the generated .seb start URL.
    // The TTL has to outlast SEB's startup; see DEFAULT_BOOTSTRAP_TTL_MS.
    const bootstrap = this.#gate.session.mintBootstrap(bootstrapTtlMs());
    const startUrl = `${this.origin}/?${BOOTSTRAP_PARAM}=${bootstrap}`;

    this.#gate.audit.record('session.start_url', { startUrl: `${this.origin}/?${BOOTSTRAP_PARAM}=<redacted>` });

    return {
      ok: true,
      startedBy: source,
      gate: this.#gate.describe(),
      startUrl,
      sebQuitPassword: sessionSecret,
      warning:
        'sebQuitPassword is shown once. It is required to leave SEB kiosk mode; store it before the exam starts.',
    };
  }

  // -------------------------------------------------------------------------
  // Files + SEB verification
  // -------------------------------------------------------------------------

  async #handleFiles(req, res, url) {
    const rel = url.searchParams.get('path') ?? '.';
    try {
      if (req.method === 'GET' && url.pathname === '/api/files/list') {
        return this.#json(res, 200, this.#workspace.list(rel));
      }
      if (req.method === 'GET' && url.pathname === '/api/files/read') {
        return this.#json(res, 200, this.#workspace.read(rel));
      }
      if (req.method === 'PUT' && url.pathname === '/api/files/write') {
        const body = await readJsonBody(req);
        if (body === BAD_JSON) return this.#json(res, 400, { error: 'bad-json' });
        const result = this.#workspace.write(rel, body?.content ?? '');
        this.#gate.audit.record('file.written', { path: result.path, bytes: result.size });
        return this.#json(res, 200, result);
      }
      if (req.method === 'POST' && url.pathname === '/api/files/mkdir') {
        return this.#json(res, 200, this.#workspace.mkdir(rel));
      }
      if (req.method === 'DELETE' && url.pathname === '/api/files') {
        const result = this.#workspace.remove(rel);
        this.#gate.audit.record('file.removed', { path: result.path });
        return this.#json(res, 200, result);
      }
      if (req.method === 'GET' && url.pathname === '/api/files/download') {
        const absolute = this.#workspace.resolveSafe(rel, { mustExist: true });
        const stat = statSync(absolute);
        if (!stat.isFile()) return this.#json(res, 400, { error: 'not-a-file' });
        const buffer = readFileSync(absolute);
        const name = basename(absolute);
        this.#gate.audit.record('file.downloaded', { path: rel, bytes: buffer.length });
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-disposition': `attachment; filename="${encodeURIComponent(name)}"`,
          'content-length': buffer.length,
        });
        return res.end(buffer);
      }
      if (req.method === 'GET' && url.pathname === '/api/files/export-zip') {
        const allFiles = this.#workspace.getAllFiles();
        const zipBuffer = createZip(allFiles);
        const name = `workspace-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.zip`;
        this.#gate.audit.record('workspace.exported_zip', { count: allFiles.length, bytes: zipBuffer.length });
        res.writeHead(200, {
          'content-type': 'application/zip',
          'content-disposition': `attachment; filename="${name}"`,
          'content-length': zipBuffer.length,
        });
        return res.end(zipBuffer);
      }
      return this.#json(res, 405, { error: 'method-not-allowed' });
    } catch (err) {
      if (err.name === 'PathRejected') {
        this.#gate.audit.record('file.rejected', { path: rel, reason: err.reason, detail: err.message });
        return this.#json(res, 400, { error: 'path-rejected', reason: err.reason, detail: err.message });
      }
      throw err;
    }
  }

  async #handleSebVerify(req, res, url) {
    const result = verifySebRequest({
      headers: req.headers,
      absoluteUrl: `${this.origin}${url.pathname}${url.search}`,
      expectedConfigKeyHash: this.#sebConfigKeyHash,
      requireAttestation: this.#env.mode === 'production',
    });
    if (!result.ok) this.#gate.audit.record('seb.attestation.failed', result);
    return this.#json(res, result.ok ? 200 : 403, result);
  }

  // -------------------------------------------------------------------------
  // WebSocket (terminal)
  // -------------------------------------------------------------------------

  #handleUpgrade(req, socket, head) {
    const url = new URL(req.url, `http://127.0.0.1:${this.#port}`);

    const hostCheck = verifyHostAndOrigin({
      hostHeader: req.headers.host,
      originHeader: req.headers.origin,
      port: this.#port,
    });
    if (!hostCheck.ok) {
      this.#gate.audit.record('ws.rejected', { reason: hostCheck.reason, origin: req.headers.origin });
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    if (url.pathname !== '/ws/terminal') {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }

    const auth = this.#authorize(req, url);
    if (!auth.ok) {
      this.#gate.audit.record('ws.unauthorized', { reason: auth.reason });
      socket.write(`HTTP/1.1 ${auth.status ?? 401} Unauthorized\r\n\r\n`);
      socket.destroy();
      return;
    }

    this.#wss.handleUpgrade(req, socket, head, (ws) => {
      this.#attachTerminal(ws, req);
    });
  }

  #attachTerminal(ws, req) {
    const session = this.#gate.session;
    session.activeWebSockets.add(ws);
    this.#gate.audit.record('ws.connected', { ip: req.socket.remoteAddress });

    const policy = resolvePolicy(session.grant?.terminalPolicy ?? null);

    // The PTY module is a native dependency and loading it can fail on an image
    // without a matching prebuild. That must surface as an error frame the UI can
    // render -- not as an exception thrown up through the WebSocket upgrade,
    // which would take the whole IDE (and the SEB kiosk with it) down.
    const loaded = loadPtyModule();
    if (!loaded.ok) {
      this.#gate.audit.record('terminal.unavailable', { reason: loaded.reason, detail: loaded.detail });
      log.error(`terminal unavailable: ${loaded.reason}: ${loaded.detail}`);
      ws.send(JSON.stringify({ type: 'error', error: loaded.reason, detail: loaded.detail }));
      ws.close(1011, loaded.reason);
      return;
    }

    let started;
    try {
      started = this.#terminal.start({ ptyModule: loaded.pty, policy });
    } catch (err) {
      // A native spawn can still fail (no ConPTY, resource limits, a restricted
      // sandbox). Same rule: report it, keep serving.
      this.#gate.audit.record('terminal.unavailable', { reason: 'pty-spawn-failed', detail: err?.message ?? String(err) });
      log.error(`terminal spawn failed: ${err?.stack ?? err}`);
      ws.send(
        JSON.stringify({
          type: 'error',
          error: 'pty-spawn-failed',
          detail: `${err?.message ?? err}`,
        }),
      );
      ws.close(1011, 'pty-spawn-failed');
      return;
    }

    if (!started.ok) {
      ws.send(JSON.stringify({ type: 'error', error: started.reason, detail: started.detail }));
      ws.close(1011, started.reason);
      return;
    }

    this.#terminal.attach(ws);
    ws.send(JSON.stringify({ type: 'ready', pid: started.pid, shell: started.shell, confinement: started.confinement }));

    ws.on('message', (raw, isBinary) => {
      if (!this.#gate.session?.isUsable()) {
        ws.close(4401, 'lease-expired');
        return;
      }
      if (isBinary) {
        // Bulk/raw stream: policy screening lives in TerminalSession.write.
        const verdict = this.#terminal.write(raw.toString('utf8'));
        this.#rejectIfDenied(ws, verdict);
        return;
      }
      // Text frames are the control channel; bulk data goes over binary frames.
      let message;
      try {
        message = JSON.parse(raw.toString('utf8'));
      } catch {
        return;
      }
      if (message.type === 'input') {
        // The single place candidate input is screened. TerminalSession.write
        // records the audit entry and reports the verdict; the UI must not be
        // the only thing enforcing this.
        const verdict = this.#terminal.write(message.data ?? '');
        this.#rejectIfDenied(ws, verdict);
        return;
      }
      if (message.type === 'resize') {
        this.#terminal.resize(Number(message.cols), Number(message.rows));
        return;
      }
      if (message.type === 'seb') {
        // SEB JS API self-report. Recorded as a claim, never as proof.
        this.#gate.audit.record('seb.selfreport', message.value ?? {});
        return;
      }
    });

    const onData = (data) => safeSend(ws, JSON.stringify({ type: 'data', data }));
    const onExit = (info) => {
      safeSend(ws, JSON.stringify({ type: 'exit', ...info }));
    };
    this.#terminal.on('data', onData);
    this.#terminal.on('exit', onExit);

    ws.on('close', () => {
      session.activeWebSockets.delete(ws);
      this.#terminal.off('data', onData);
      this.#terminal.off('exit', onExit);
      this.#terminal.detach(ws);
      this.#gate.audit.record('ws.disconnected', {});
    });
    ws.on('error', (err) => log.warn(`ws error: ${err.message}`));
  }

  // -------------------------------------------------------------------------
  // Static assets
  // -------------------------------------------------------------------------

  #serveStatic(res, rel) {
    const webRoot = join(ROOT, 'src', 'web');
    const target = normalize(join(webRoot, rel));
    if (!target.startsWith(webRoot)) return this.#json(res, 403, { error: 'forbidden' });
    if (!existsSync(target) || !statSync(target).isFile()) {
      return this.#json(res, 404, { error: 'not-found', path: rel });
    }
    const body = readFileSync(target);
    res.statusCode = 200;
    res.setHeader('content-type', MIME[extname(target).toLowerCase()] ?? 'application/octet-stream');
    return res.end(body);
  }

  #json(res, status, payload) {
    const body = JSON.stringify(payload ?? null);
    res.statusCode = status;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    return res.end(body);
  }

  #html(res, status, body) {
    res.statusCode = status;
    res.setHeader('content-type', 'text/html; charset=utf-8');
    return res.end(body);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BAD_JSON = Symbol('bad-json');

async function readJsonBody(req, limitBytes = 4 * 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > limitBytes) return BAD_JSON;
    chunks.push(chunk);
  }
  if (total === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return BAD_JSON;
  }
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    out[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return out;
}

function safeSend(ws, payload) {
  try {
    if (ws.readyState === ws.OPEN) ws.send(payload);
  } catch {
    /* the socket died between the check and the send */
  }
}

function generateSecret() {
  // 24 chars from a 96-bit draw: long enough to be unguessable, short enough to
  // read off a proctor's screen and type into SEB's quit dialog.
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
}

function rejectionPage(reason, gateState) {
  const messages = {
    'no-session': 'No exam session is active. An administrator must start the session first.',
    'already-used': 'This start link has already been used. Ask your proctor for a new one.',
    'expired-code': 'This start link expired before it was used. Ask your proctor for a new one.',
    'unknown-code': 'This start link is not valid.',
    'lease-expired': 'The exam session lost contact with the exam server and has been locked.',
    'session-locked': 'The session is locked. Contact your proctor.',
    'session-stopped': 'The session has ended.',
    unauthorized: 'Not authorised.',
  };
  const title = gateState === 'locked' ? 'Session locked' : 'Session unavailable';
  const message = messages[reason] ?? 'This session cannot be started.';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Razor -- ${title}</title>
<style>body{font:15px/1.5 system-ui,sans-serif;background:#14171c;color:#e6e6e6;display:grid;place-items:center;height:100vh;margin:0}
main{max-width:34rem;padding:2rem;border:1px solid #2c313a;border-radius:.75rem;background:#1a1e25}
h1{font-size:1.1rem;margin:0 0 .5rem;color:#ff6b6b}p{margin:.5rem 0;color:#a9b1bd}code{background:#11141a;padding:.1rem .3rem;border-radius:.2rem}</style>
</head><body><main><h1>${title}</h1><p>${message}</p>
<p><code>${String(reason)}</code></p></main></body></html>`;
}
