# Razor IDE — Environment Setup Guide

> A full walkthrough for reproducing the development environment from scratch on a fresh Windows machine.

---

## 1. System Requirements

| Requirement | Version / Notes |
|---|---|
| **OS** | Windows 11 (required — `node-pty` and Safe Exam Browser are Windows-native) |
| **Node.js** | `>= 20.0.0` (verified on 22.18.0). Install from [nodejs.org](https://nodejs.org) or via `winget install OpenJS.NodeJS.LTS` |
| **npm** | Bundled with Node (no separate install) |
| **Safe Exam Browser** | v3.10.2.920 verified. Install to default path: `C:\Program Files\SafeExamBrowser\`. Download from [safeexambrowser.org](https://safeexambrowser.org/download_en.html) — **no portable mode** |
| **Git** | Any recent version (`winget install Git.Git`) |
| **Build tools** | **None required** — `node-pty` 1.1.0 ships prebuilt Windows binaries |

> [!IMPORTANT]
> This project is **Windows-only**. The PTY layer (`node-pty`), Safe Exam Browser integration, Job Object confinement, and AppLocker policy generation are all Windows-specific. Running on WSL or Linux will break the terminal and SEB features.

---

## 2. Clone & Install

```powershell
# Clone the repo
git clone https://github.com/dorrito-dev/razor-ide.git
cd razor-ide

# Install npm dependencies (postinstall automatically verifies the PTY native module)
npm install

# Bundle the browser UI (CodeMirror 6 + xterm.js) into src/web/vendor/
# Required because Safe Exam Browser blocks all CDN access — the IDE must be fully offline.
npm run build

# Run the full unit test suite (105 tests)
npm test
```

> [!NOTE]
> If `npm install` reports an `EPERM` error during `node-pty`'s install script (a restricted-sandbox artifact), run:
> ```powershell
> npm install --ignore-scripts
> node scripts/verify-pty.mjs
> ```

---

## 3. Project Structure

```
razor-ide/
├── src/
│   ├── main.mjs              Entry point: mode check, server, gate, SEB launch
│   ├── config.mjs            Flags, env vars, paths, logger
│   ├── server.mjs            HTTP + WebSocket server with host/origin/CSP hardening
│   ├── admin.mjs             Basic auth, Host/Origin checks, SEB attestation
│   ├── heartbeat.mjs         Outbound control-plane client (lease + commands)
│   ├── files.mjs             Workspace file API with Windows path confinement
│   ├── terminal.mjs          PTY, command policy, audit, AppLocker policy generator
│   ├── pty.mjs               node-pty loader
│   ├── security/
│   │   ├── crypto.mjs        SHA-256/HMAC, SEB Config Key + request hash
│   │   ├── grants.mjs        Signed single-use grants, sessions, leases
│   │   ├── gate.mjs          State machine: "is there a session?"
│   │   └── state.mjs         Run directory, ACL hardening, audit log
│   ├── seb/
│   │   ├── plist.mjs         Plist writer/parser (SEB's config format)
│   │   ├── config.mjs        SEB policy: lockdown keys, URL filter
│   │   ├── container.mjs     .seb container (gzip + "plnd" prefix)
│   │   └── launch.mjs        Find/verify/spawn SafeExamBrowser.exe
│   └── web/                  CodeMirror 6 + xterm.js UI source (offline bundle)
│       ├── app.js            UI entry point (bundled by esbuild → src/web/vendor/)
│       ├── style.css         Shell styles
│       └── vendor/           ← gitignored, built by `npm run build`
├── scripts/
│   ├── build.mjs             esbuild bundler script
│   ├── verify-pty.mjs        Post-install native module check
│   ├── run-timed.ps1         Run Razor for N minutes then cleanly quit
│   └── run-seb-timed.ps1     Run Razor+SEB for N minutes (windowed or hardened)
├── tools/
│   ├── admin-cli.mjs         Proctor CLI: status | start | stop | extend
│   ├── fake-admin.mjs        Mock control plane for heartbeat flow testing
│   ├── verify-e2e.mjs        End-to-end check of the locked/unlocked HTTP surface
│   ├── verify-seb.mjs        Build + inspect the real .seb, optionally launch SEB
│   └── verify-terminal.mjs   Test PTY spawn via WebSocket (no browser needed)
├── test/                     node:test unit suites
├── docs/
│   ├── research.md           Library choices, SEB findings with citations
│   ├── security.md           Threat model, what is and isn't enforced
│   └── seb.md                .seb format, lockdown keys, attestation
├── run/                      ← gitignored, generated at runtime (secrets!)
├── build/                    ← gitignored, generated build artifacts
├── seb/generated/            ← gitignored, generated .seb files
├── package.json
├── .gitignore
└── ENVIRONMENT.md            ← this file
```

---

## 4. Available npm Scripts

| Script | Command | Description |
|---|---|---|
| `build` | `npm run build` | Bundle the browser UI with esbuild into `src/web/vendor/` |
| `dev` | `npm run dev` | Start server in dev mode (no SEB, gate not armed) |
| `dev:seb` | `npm run dev:seb` | Dev mode + SEB launch |
| `start` | `npm start` | Start server (production-style, no auto flags) |
| `start:seb` | `npm run start:seb` | Start + launch SEB |
| `admin` | `npm run admin` | Proctor CLI (`status`, `start`, `stop`, `extend`) |
| `fake-admin` | `npm run fake-admin` | Mock control plane for testing heartbeat flow |
| `test` | `npm test` | Run all 105 unit tests via `node:test` |
| `postinstall` | _(auto)_ | Verifies `node-pty` native module loaded correctly |

---

## 5. Environment Variables

All variables are optional in dev mode. Production variables marked **required** have no defaults.

### Core

| Variable | Default | Description |
|---|---|---|
| `RAZOR_ENV` | `dev` (warns if unset) | **Security mode.** Set to `production` for exam use. This is the single security switch — asymmetric by design |
| `RAZOR_PORT` | `0` (ephemeral) | HTTP listen port. `0` picks a random port |
| `RAZOR_HOST` | `127.0.0.1` | Listen address. Do NOT expose to a network interface |
| `RAZOR_WORKSPACE` | `./workspace` (dev) / `C:\RazorExam` (prod) | The only directory the editor and terminal can access |

### Admin / Auth

| Variable | Default | Description |
|---|---|---|
| `RAZOR_ADMIN_USER` | `admin` | Admin username for Basic auth |
| `RAZOR_ADMIN_PASS` | _(generated in dev, **required** in prod)_ | Admin password. In dev, printed to `run/admin-key.pem` |
| `RAZOR_ADMIN_TOKEN` | none | Bearer token alternative to Basic auth |

### Safe Exam Browser

| Variable | Default | Description |
|---|---|---|
| `RAZOR_SEB_EXE` | auto-detected | Path to `SafeExamBrowser.exe` |
| `RAZOR_SEB_CONFIG` | none | Operator-supplied **encrypted** `.seb` config file path |
| `RAZOR_SEB_CONFIG_KEY_HASH` | none | Pinned expected Config Key hash for SEB attestation |
| `RAZOR_SEB_WINDOWED` | `0` | `1` = windowed mode (not fullscreen). For smoke testing |
| `RAZOR_SEB_HARDENED` | `0` | `1` = force `createNewDesktop` + `killExplorerShell`. Production always implies this |
| `RAZOR_SEB_ALLOW_ORIGINS` | none | Extra URL-filter allow entries (comma-separated) |
| `RAZOR_ALLOW_UNENCRYPTED_SEB` | `0` | `1` = allow generated plain (non-encrypted) `.seb` in production (logged as warning) |

### Session & Timing

| Variable | Default | Description |
|---|---|---|
| `RAZOR_QUIT_PASSWORD` | generated per session | Dev bypass only; production takes it from the signed grant |
| `RAZOR_LEASE_MS` | `60000` | Lease duration in ms (how long a session stays active without heartbeat) |
| `RAZOR_GRACE_MS` | `60000` | Grace window after lease expires before session is locked |
| `RAZOR_BOOTSTRAP_TTL_MS` | `180000` (3 min) | Life of the single-use `?b=` code. Must outlast SEB startup (~64 s). Clamped to 30 s–1 h |

### Control Plane (optional remote proctor)

| Variable | Default | Description |
|---|---|---|
| `RAZOR_CONTROL_PLANE_URL` | none | Enables outbound heartbeat + command channel to a remote control plane |
| `RAZOR_DEVICE_ID` | hostname | Device identity sent in heartbeat |
| `RAZOR_DEVICE_TOKEN` | hostname | Auth token for control-plane identity |
| `RAZOR_HEARTBEAT_MS` | `7000` | Heartbeat polling interval in ms |

### Terminal & Logging

| Variable | Default | Description |
|---|---|---|
| `RAZOR_CONFINEMENT` | `none` (dev) / `jobobject` (prod) | Terminal process confinement mode |
| `RAZOR_EXAM_SID` | `*` | Windows SID for the exam account (used in AppLocker policy generation) |
| `RAZOR_LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `RAZOR_LOG_FILE` | _(stderr only)_ | Path to append logs to (in addition to stderr) |
| `RAZOR_UI_SOURCEMAP` | `0` | `1` = emit esbuild sourcemaps during `npm run build` (large, dev only) |

---

## 6. Quick Start — Development

```powershell
# Simplest: start with gate bypassed (no admin step needed)
$env:RAZOR_ENV = 'dev'
$env:RAZOR_ADMIN_PASS = 'devpass'
npm run dev -- --bypass-gate
# → Prints a single-use start URL. Open it in any browser.
```

To use the real admin flow (no bypass):

```powershell
# Terminal 1
$env:RAZOR_ENV = 'dev'
$env:RAZOR_ADMIN_PASS = 'devpass'
npm run dev

# Terminal 2 (proctor)
npm run admin -- start         # prints start URL + quit password
npm run admin -- status
npm run admin -- stop
```

To test with SEB in windowed mode (won't lock your desktop):

```powershell
$env:RAZOR_ENV = 'dev'
$env:RAZOR_ADMIN_PASS = 'devpass'
$env:RAZOR_SEB_WINDOWED = '1'
npm run dev:seb -- --bypass-gate
```

---

## 7. Production Setup

```powershell
$env:RAZOR_ENV          = 'production'
$env:RAZOR_ADMIN_PASS   = '<strong-secret>'        # no default — must be set
$env:RAZOR_SEB_CONFIG   = 'C:\Exam\exam.seb'       # encrypted .seb from SEB Config Tool
$env:RAZOR_WORKSPACE    = 'C:\RazorExam'
node src/main.mjs --seb

# Proctor starts the session:
node tools/admin-cli.mjs start --exam-id midterm-2026
```

### Production Checklist

- [ ] `RAZOR_ENV=production` and `RAZOR_ADMIN_PASS` set from a secret store
- [ ] An **encrypted** `.seb` supplied via `RAZOR_SEB_CONFIG`
- [ ] `razor-ide` installed into an admin-writable-only directory
- [ ] `build/applocker-razor.xml` reviewed and applied with `Set-AppLockerPolicy`
- [ ] A separate low-privilege Windows account for the terminal (see `docs/security.md`)
- [ ] SEB quit password recorded before the exam starts

---

## 8. Verification

```powershell
npm test                              # 105 unit tests (gate, paths, SEB, admin, terminal)
node tools/verify-e2e.mjs            # 31 end-to-end checks over the real HTTP surface (dev)
node tools/verify-e2e.mjs --mode production
node tools/verify-seb.mjs            # Build .seb, inspect container, print Config Key hash
node tools/verify-seb.mjs --launch  # Actually launch SEB (locks your desktop)
```

---

## 9. Technology Stack

| Layer | Technology |
|---|---|
| **Runtime** | Node.js ≥ 20, ESM (`"type": "module"`) |
| **HTTP/WebSocket server** | Node built-ins (`node:http`) + `ws` ^8.22 |
| **PTY** | `node-pty` 1.1.0 (Windows prebuilt) |
| **Editor** | CodeMirror 6 (`codemirror` ^6, `@codemirror/*` extensions) |
| **Terminal UI** | xterm.js (`@xterm/xterm` ^5.5, fit + web-links addons) |
| **Bundler** | esbuild ^0.24 (build-time only, not in production) |
| **Languages supported in editor** | JavaScript, TypeScript, Python, Rust, HTML, CSS, JSON, Markdown |
| **Security** | Node `node:crypto` (SHA-256/HMAC), Job Objects, AppLocker XML generation |
| **Exam lockdown** | Safe Exam Browser 3.10.x (Windows) |
| **Testing** | `node:test` (built-in, no test framework dependency) |

---

## 10. What Is Gitignored

See [`.gitignore`](.gitignore) for full detail. Key exclusions:

| Path | Reason |
|---|---|
| `node_modules/` | npm dependency tree — restore with `npm install` |
| `src/web/vendor/` | esbuild bundle output — rebuild with `npm run build` |
| `run/` | **Runtime secrets** (admin key PEM, session grants, audit logs, `.seb` files). Never commit. |
| `build/` | Generated AppLocker XML and other runtime artifacts |
| `seb/generated/` | Generated `.seb` container files |
| `*.seb` | Encrypted/plain SEB configs (may contain exam passwords) |
| `.env`, `.env.local` | Local secret overrides |
| `*.log`, `*.pem` | Log files and PEM keys written at runtime |

---

## 11. Further Reading

- [`docs/research.md`](docs/research.md) — library choices, SEB findings with citations
- [`docs/security.md`](docs/security.md) — threat model, what is and isn't enforced
- [`docs/seb.md`](docs/seb.md) — `.seb` format, lockdown keys, attestation
