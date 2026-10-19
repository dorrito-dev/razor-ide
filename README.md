# Razor IDE + Safe Exam Browser

A locally running, browser-based IDE (**Razor**) plus a launcher that runs it
inside **Safe Exam Browser** under exam restrictions, and a gate that means a
session exists only after an administrator asks for one.

```
razor-ide/
├── src/
│   ├── main.mjs              entry point: mode check, server, gate, SEB launch
│   ├── config.mjs            flags, env, paths, logger
│   ├── server.mjs            HTTP + WebSocket, host/origin/CSP hardening
│   ├── admin.mjs             Basic auth, Host/Origin checks, SEB attestation
│   ├── heartbeat.mjs         outbound control-plane client (lease + commands)
│   ├── files.mjs             workspace file API with Windows path confinement
│   ├── terminal.mjs          PTY, command policy, audit, AppLocker generator
│   ├── security/
│   │   ├── crypto.mjs        SHA-256/HMAC, SEB Config Key + request hash
│   │   ├── grants.mjs        signed single-use grants, sessions, leases
│   │   ├── gate.mjs          the state machine that decides "is there a session"
│   │   └── state.mjs         run directory, ACL hardening, audit log
│   ├── seb/
│   │   ├── plist.mjs         plist writer/parser (SEB's config format)
│   │   ├── config.mjs        SEB policy: lockdown keys, URL filter
│   │   ├── container.mjs     .seb container (gzip + "plnd" prefix)
│   │   └── launch.mjs        find/verify/spawn SafeExamBrowser.exe
│   └── web/                  CodeMirror 6 + xterm.js UI (offline bundle)
├── tools/
│   ├── admin-cli.mjs         proctor CLI: status | start | stop | extend
│   ├── fake-admin.mjs        mock control plane for the heartbeat flow
│   ├── verify-e2e.mjs        end-to-end check of the locked/unlocked surface
│   └── verify-seb.mjs        build + inspect the real .seb, optionally launch SEB
├── test/                     node:test unit suites
├── docs/                     research, security model, SEB findings
└── run/                      generated .seb, admin key, audit log (gitignored)
```

## Requirements

| | |
|---|---|
| OS | Windows 11 (SEB is Windows-only here) |
| Node.js | >= 20 (verified on 22.18.0) |
| Safe Exam Browser | installed at `C:\Program Files\SafeExamBrowser\` — **SEB has no portable mode**. Verified against 3.10.2.920 |
| Build tools | none for the default install: `node-pty` 1.1.0 ships Windows prebuilds |

## Install

```powershell
cd razor-ide
npm install          # downloads deps; postinstall verifies the PTY native module
npm run build        # bundles the UI into src/web/vendor (offline, no CDN)
npm test             # 105 unit tests
```

If `npm install` reports an EPERM while running node-pty's install script, that
is a restricted-sandbox artefact, not a package problem. Re-run
`npm install --ignore-scripts` and then `node scripts/verify-pty.mjs` in a
normal shell.

## Run — development

Development mode makes the restrictions bypassable so you can iterate.

```powershell
# terminal 1: start Razor, unlocked immediately, no SEB
$env:RAZOR_ENV = 'dev'
$env:RAZOR_ADMIN_PASS = 'devpass'
npm run dev -- --bypass-gate
# -> prints a single-use start URL; open it in a browser
```

To drive the real admin flow instead of bypassing it:

```powershell
$env:RAZOR_ENV = 'dev'; $env:RAZOR_ADMIN_PASS = 'devpass'
npm run dev
# in another terminal:
npm run admin -- start          # prints the start URL and quit password
npm run admin -- status
npm run admin -- stop
```

To run it inside SEB in dev:

```powershell
$env:RAZOR_ENV = 'dev'
$env:RAZOR_ADMIN_PASS = 'devpass'
$env:RAZOR_SEB_WINDOWED = '1'      # windowed, allowQuit=true: easy to escape
npm run dev:seb -- --bypass-gate
```

To check the SEB integration **without locking your desktop**:

```powershell
npm run dev -- --seb --seb-argv-only   # prints the exact command line, launches nothing
node tools/verify-seb.mjs --inspect    # writes the .seb and reports its container prefix
```

### Timed runs that quit themselves

Razor has no self-timer and no shutdown endpoint: `main.mjs` only exits on
SIGINT/SIGTERM. These wrappers run it for a fixed time and then guarantee the
machine comes back, which matters because `killSebProcesses()` alone only stops
`SafeExamBrowser.exe` and leaves `SafeExamBrowser.Client.exe` and the CefSharp
browser subprocesses holding the desktop.

```powershell
# Razor alone, unlocked, 1 minute, then quit
powershell -ExecutionPolicy Bypass -File scripts/run-timed.ps1 -Minutes 1

# Razor inside SEB, windowed (allowQuit=true) for 2 minutes, then quit
powershell -ExecutionPolicy Bypass -File scripts/run-seb-timed.ps1 -Minutes 2

# fully-enforced kiosk: dedicated SEB desktop, Explorer shell killed.
# Your desktop is taken over for the whole run; it ends by itself.
powershell -ExecutionPolicy Bypass -File scripts/run-seb-timed.ps1 -Minutes 3 -Hardened
```

Both scripts kill the whole Razor process tree, tear down every SEB image
child-first, restore the `SafeExamBrowser` service to the state it was found in,
and then *verify* — reporting any surviving process or listening port — before
printing a pass/fail line.

#### Windowed vs fullscreen vs hardened

`-Hardened` (or `RAZOR_SEB_HARDENED=1`, or production) sets `createNewDesktop`
and `killExplorerShell`. That pairing is what actually enforces the lockdown: the
browser runs on a dedicated desktop with Explorer out of the way. Without it,
SEB's keyboard hooks are only filtering keys inside a fullscreen window that sits
on the candidate's own desktop, and Alt+Tab / closing the window still work —
observed live on 3.10.2. `createNewDesktop` is opt-in because SEB documents it as
breaking NVDA/JAWS screen readers.

### Checking the terminal without a browser

```powershell
node tools/verify-terminal.mjs      # needs RAZOR_ORIGIN and RAZOR_START_URL
```

It exchanges the single-use start URL for a session cookie, opens
`/ws/terminal` exactly as the UI does, types a command, and reports whether the
PTY really spawned. Either outcome exits non-zero only if the shell did not
answer — a *reported* PTY failure is a pass, because the failure mode this guards
against was the IDE dying with the desktop locked.

## Run — production

Production requires explicit credentials, ignores every bypass flag, refuses to
start without SEB, and refuses an unencrypted `.seb`.

```powershell
$env:RAZOR_ENV          = 'production'
$env:RAZOR_ADMIN_PASS   = '<strong-secret>'      # no default is generated
$env:RAZOR_SEB_CONFIG   = 'C:\Exam\exam.seb'     # encrypted config from SEB Config Tool
$env:RAZOR_WORKSPACE    = 'C:\RazorExam'
node src/main.mjs --seb
# in another terminal (as the proctor):
node tools/admin-cli.mjs start --exam-id midterm-2026
```

If you have no encrypted `.seb` yet, generate one with **SEB Config Tool**
(`C:\Program Files\SafeExamBrowser\Configuration\SEBConfigTool.exe`): load
`run/razor.plist.xml`, set the exam URL to `http://127.0.0.1:<port>/?b=...`,
choose a password or a certificate identity, and save. Razor will not silently
substitute an unencrypted config for you.

To opt into the unencrypted generated config anyway (development-grade; logged):

```powershell
$env:RAZOR_ALLOW_UNENCRYPTED_SEB = '1'
```

### Production checklist

- [ ] `RAZOR_ENV=production` and `RAZOR_ADMIN_PASS` set from a secret store.
- [ ] An **encrypted** `.seb` supplied via `RAZOR_SEB_CONFIG`.
- [ ] Install `razor-ide` into an admin-writable-only directory.
- [ ] `build/applocker-razor.xml` reviewed and applied with `Set-AppLockerPolicy`.
- [ ] A separate low-privilege account for the terminal (see `docs/security.md`).
- [ ] The SEB quit password for this session recorded before the exam starts.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `RAZOR_ENV` | `dev` (warns) | **Security mode.** `production` cannot be downgraded by the end user |
| `RAZOR_ADMIN_USER` / `RAZOR_ADMIN_PASS` | none (required in production) | Local admin credentials |
| `RAZOR_ADMIN_TOKEN` | none | Bearer token alternative to Basic auth |
| `RAZOR_PORT` / `--port` | `0` (ephemeral) | Listen port |
| `RAZOR_HOST` | `127.0.0.1` | Listen address |
| `RAZOR_WORKSPACE` | `./workspace` (dev), `C:\RazorExam` (production) | The only directory the editor and terminal touch |
| `RAZOR_SEB_EXE` | auto-detected | Path to `SafeExamBrowser.exe` |
| `RAZOR_SEB_CONFIG` | none | Operator-supplied **encrypted** `.seb` |
| `RAZOR_SEB_CONFIG_KEY_HASH` | none | Pinned expected Config Key for attestation |
| `RAZOR_SEB_WINDOWED` | `0` | `1` = windowed instead of fullscreen (first-run smoke test) |
| `RAZOR_SEB_HARDENED` | `0` | `1` = force `createNewDesktop` + `killExplorerShell` (real desktop lockdown) in dev. Production always implies it |
| `RAZOR_SEB_ALLOW_ORIGINS` | none | Extra URL-filter allow entries (comma-separated) |
| `RAZOR_ALLOW_UNENCRYPTED_SEB` | `0` | `1` = allow the generated plain config in production (logged) |
| `RAZOR_QUIT_PASSWORD` | generated per session | Dev bypass only; production takes it from the grant |
| `RAZOR_LEASE_MS` / `RAZOR_GRACE_MS` | `60000` / `60000` | Lease length and lock-after-contact-lost window |
| `RAZOR_BOOTSTRAP_TTL_MS` | `180000` | Life of the single-use `?b=` code in the `.seb` start URL. Must outlast SEB's own startup — measured ~64 s from launch to first request — so the default is 3 min. Clamped to 30 s–1 h |
| `RAZOR_CONTROL_PLANE_URL` | none | Enables the outbound heartbeat + command channel |
| `RAZOR_DEVICE_ID` / `RAZOR_DEVICE_TOKEN` | hostname | Control-plane identity |
| `RAZOR_HEARTBEAT_MS` | `7000` | Heartbeat interval |
| `RAZOR_CONFINEMENT` | `none` (dev), `jobobject` (production) | Terminal confinement mode |
| `RAZOR_LOG_LEVEL` / `RAZOR_LOG_FILE` | `info` / stderr | Logging |

## The dev/production switch

`RAZOR_ENV` is the single security switch, and it is asymmetric on purpose:

| | dev | production |
|---|---|---|
| `--bypass-gate` | starts a session immediately | **refused and logged** |
| Admin credentials | generated per run into `run/admin-key.pem` | must be supplied; no default exists |
| SEB | optional | required; a failed launch terminates the session |
| `.seb` config | generated plain (`plnd`) is fine | must be **encrypted** (or explicit logged opt-in) |
| Quit password | `RAZOR_QUIT_PASSWORD` or generated | taken per session from the signed grant |
| Autocomplete / paste | enabled | disabled |
| Developer console, VM allowed | on | off |

Read `docs/security.md` before trusting any of this in a graded exam. The short
version: with a single interactive user, production is **deterrent-grade**, not
tamper-resistant.

## Verification

```powershell
npm test                      # unit suites: gate, paths, SEB, admin, terminal
node tools/verify-e2e.mjs     # dev: 31 checks over the real HTTP surface
node tools/verify-e2e.mjs --mode production
node tools/verify-seb.mjs     # build the .seb, inspect the container, hash it
node tools/verify-seb.mjs --launch   # really start SEB (locks the desktop)
```

## Documentation

- [`docs/research.md`](docs/research.md) — library choice, SEB findings with citations
- [`docs/security.md`](docs/security.md) — threat model, what is and is not enforced
- [`docs/seb.md`](docs/seb.md) — the `.seb` format, lockdown keys, attestation
