# Security model — what Razor enforces, and what it does not

This document is the honest version. The controls below are real, they are
tested, and several of them fail closed. But the design also has a hard ceiling
that no amount of code in this repository can lift, and pretending otherwise
would be the most dangerous thing in the project.

---

## 1. The ceiling: same-user trust

Razor's server, its PTY, and Safe Exam Browser all run **as the same interactive
Windows user as the candidate**.

That single fact has consequences that must be stated plainly:

- The candidate can read every file Razor writes, including `run/admin-key.pem`,
  the audit log, and the generated `.seb`.
- The candidate can `taskkill /IM SafeExamBrowser.exe`, kill Razor, or start
  `chrome.exe` directly.
- The candidate can edit Razor's source and restart it with `RAZOR_ENV=dev`.
- A per-user ACL (`icacls /inheritance:r`) does not change any of the above. On
  Windows, "0600-ish" between processes of the same user means nothing.

So: **with a single interactive user, production mode is deterrent-grade, not
tamper-resistant.** It stops shortcuts, accidents and casual cheating. It does
not stop a determined candidate with local access.

### What actually fixes it

Either of these, both of which are deployment decisions rather than code:

1. **Run Razor and its PTY as a separate low-privilege account** whose process
   the candidate cannot start or impersonate, with the candidate unable to
   administer it. This was explicitly descoped (see §7) but it is the real fix.
2. **Machine-wide execution control** — AppLocker or WDAC denying everything not
   allowlisted, applied to an account the candidate does not administer.
   `generateAppLockerPolicy()` writes a reviewed starting point to
   `build/applocker-razor.xml`; Razor deliberately never applies it, because a
   policy the constrained user can apply is not a policy.

---

## 2. The gate: what "an admin starts the session" actually guarantees

`src/security/gate.mjs` is the only place that can move the machine into a
running session. The invariant is: **nothing reaches `RUNNING` except a grant
that passes HMAC verification.**

| Property | Enforced? | Evidence |
|---|---|---|
| No session exists at boot | yes | `test/gate.test.mjs` "no grant means no session" |
| Production refuses `--bypass-gate` and logs it | yes | `test/gate.test.mjs` "production refuses the bypass flag"; `tools/verify-e2e.mjs` |
| Grant is single-use (replay refused) | yes | `test/gate.test.mjs` "a replayed grant is refused", "consumed" |
| Grant expires | yes | `test/gate.test.mjs` "an expired grant is refused" |
| Grant is bound to one machine | yes | `test/gate.test.mjs` "a grant for another machine is refused" |
| Tampering with a signed field is refused | yes | `test/gate.test.mjs` "tampering with a signed field is refused" |
| Session ends when SEB exits | yes, production | `src/main.mjs` `handleSebExit` → `gate.stopSession('seb-exited')` |
| Session locks when heartbeats stop | yes | `Session.state()` → `grace` → `locked`; `test/gate.test.mjs` lease test |
| A revoked cookie stops working immediately | yes | `test/gate.test.mjs` "stopping a session locks the gate and revokes the token" |

**The residual hole:** the grant HMAC key lives on the same machine, in
`run/admin-key.pem`. A candidate who can read that file *and* run code as that
user can mint their own grant. In dev that is by design. In production,
`RAZOR_GRANT_KEY` should come from a secret the candidate cannot read — and even
then, a candidate who can run code can patch `gate.mjs` itself. Which is §1
again.

### Lease and the fail-closed decision

The lease is what makes "pull the network cable and keep working" impossible:

```
live   ──┬── renewed on every successful heartbeat
         ├── grace  (default 60s)   editing continues, UI warns
         └── locked (default +60s)  every API and WebSocket call refused
```

**Chosen policy: fail closed with a grace window.** A stable wired LAN is the
assumed deployment. `RAZOR_LEASE_MS` and `RAZOR_GRACE_MS` are configurable, and
a proctor can extend remotely with a signed `extend_session` command. The
alternative — fail open with logging — is kinder to candidates on flaky Wi-Fi
and weaker against cheating; it is deliberately not the default.

The lock is honest about its limits: it stops the candidate *continuing to work
in Razor*. It cannot stop them reading files already on disk.

---

## 3. Browser-side hardening

| Control | Implementation | Notes |
|---|---|---|
| Only SEB can use the IDE | Single-use bootstrap code exchanged for an `HttpOnly; SameSite=Strict` cookie | A permanent token in the start URL would be a permanent key; the `.seb` is readable, so the URL must be worthless after first use |
| Replay of the start URL | Refused (`bootstrap.refused`, HTTP 403) | Verified in `tools/verify-e2e.mjs` step 6 |
| DNS rebinding | `Host` must be a loopback host | Verified end to end over a raw socket (Node's `fetch` refuses to set `Host`) |
| Cross-site WebSocket hijacking | `Origin`, when present, must be loopback | `test/admin.test.mjs` |
| Cross-site script injection | Strict CSP, `default-src 'none'`, no external origins | The page is asserted to reference no non-loopback host |
| Token leakage via URLs | Token is never a query parameter after the exchange; cookie only | `tools/verify-e2e.mjs` step 4 |
| SEB attestation | Config Key request hash verified per request | §5 |

### SEB attestation — and its precise meaning

SEB sends two hash headers when `sendBrowserExamKey=true`:

- `X-SafeExamBrowser-ConfigKeyHash` — **implemented.**
- `X-SafeExamBrowser-RequestHash` (Browser Exam Key) — **deliberately not
  implemented.**

The Config Key is derived only from the config, so it is platform-independent
and Razor can compute it. The BEK additionally folds in SEB's *code signature*,
making it platform- and bitness-specific: it cannot be computed server-side
without pinning one value per SEB build. `test/admin.test.mjs` asserts that
presenting a BEK does **not** satisfy Config Key attestation, so nobody
mistakes one for the other.

**What the Config Key proves:** the request came from a browser holding this
exact configuration. **What it does not prove:** that the browser is SEB, or
that the candidate has not tampered with anything. With an unencrypted `plnd`
config the Config Key is public anyway, which is precisely why production
requires an encrypted `.seb`.

Version/identity information from the SEB JavaScript API is recorded in the
audit log as a **claim**, never as proof — `src/server.mjs` logs it as
`seb.selfreport`.

---

## 4. Terminal: the largest escape vector

The PTY runs **outside** SEB, as the candidate's own user. From it, a candidate
can start another browser, kill SEB, or read files the user owns.

| Control | Status |
|---|---|
| Server-side interpreter allowlist — the client can never name the program | **enforced** |
| Command policy: refuses `curl`, `Invoke-WebRequest`, `bitsadmin`, `certutil`, `netsh`, `ssh`, `taskkill`, `Stop-Process`, `schtasks`, `wmic`, `reg add`, `shutdown`, `Start-Process`, `mstsc`, VM tooling, and the whole **`SafeExamBrowser` / `razor` / audit-log** family | **enforced** |
| Every submitted line written to `run/audit.jsonl` | **enforced** |
| Blocked attempts surfaced in the UI and the audit log | **enforced** |
| Child tree killed on session stop (`taskkill /T`) | **enforced** |
| Job Object with kill-on-close, process cap, memory cap | **NOT implemented.** `RAZOR_CONFINEMENT=jobobject` is the production default and **fails loudly** rather than pretending. Needs native bindings or a helper; see `createConfinement()` |
| Outbound firewall rule for the PTY user | **not implemented** |
| AppLocker/WDAC applied | **not applied** — a reviewed policy is generated to `build/applocker-razor.xml` |

**The command policy is a deterrent with an audit trail, not a boundary.**
`test/terminal.test.mjs` contains a test named *"obfuscation defeats the policy —
documented, not hidden"* which asserts that `c""url ...` and a string-built
command both pass. That test exists on purpose: anyone reading this file should
know exactly where the line is.

### Escape-attempt test list

Run these by hand in a provisioned session and confirm the expected outcome:

| Attempt | Expected |
|---|---|
| `curl http://example.com` | refused, logged `terminal.command.denied` |
| `taskkill /IM SafeExamBrowser.exe /F` | refused, logged |
| `Start-Process chrome` | refused, logged |
| `c""url http://example.com` | **allowed** — obfuscation; check the audit log and the firewall |
| navigate SEB to `http://evil.example.com` | blocked by SEB's URL filter |
| open Chrome and paste the start URL | 403 (bootstrap already consumed) |
| stop the heartbeat, work for 3 minutes | UI locks after the grace window |
| create a junction in the workspace, write through it | refused (`PathRejected: escaped-via-link`) |
| `cd ..` then read `package.json` | refused |

---

## 5. Filesystem confinement

`src/files.mjs` rejects, with tests for each: NT namespace (`\\?\`), UNC,
device paths, absolute paths, drive-relative paths (`C:foo`), alternate data
streams (`file.txt:stream`), reserved device names (`CON`, `NUL`, `COM1`…),
Windows-forbidden characters, traversal, and **symlinks or junctions** — via
`realpath` containment plus a per-component `lstat` walk.

**Residual risk:** Windows directory *junctions* created without the symlink
flag are not distinguishable from ordinary directories by `lstat` alone, so the
real guard is `realpath` containment. `test/paths.test.mjs` attempts a real
`mklink /J` escape and skips with a diagnostic if the host cannot create one.
**Verify that test is not skipped on your exam image.**

Also note the workspace is only the *editor and terminal's* root. It is not a
security boundary against a shell that can `cd` anywhere — see §4.

---

## 6. SEB configuration

| Control | Where |
|---|---|
| URL filter allows only the loopback origin (http, ws, bare `host:port`) | `buildFilterRules()` |
| Alt+Tab, Alt+Esc, Alt+F4, Ctrl+Esc, Start menu, PrintScreen, F1–F12 blocked | `buildSebPolicy()` |
| Injected (synthetic) keystrokes blocked | `enableInjected` |
| Downloads, uploads, printing, spell-check, page zoom, developer console off | `buildSebPolicy()` |
| `.seb`-driven reconfiguration disabled | `downloadAndOpenSebConfig`, `examSessionReconfigureAllow` |
| New browser windows cannot become an escape hatch | `newBrowserWindow*` |
| Screen sharing/capture and VMs blocked | `allowScreenSharing`, `allowVirtualMachine` |
| Explorer shell killed, process monitoring on | `killExplorerShell`, `monitorProcesses` |
| Config that would deadlock an exam is refused before launch | `validateSebPolicy()` — e.g. `allowQuit=false` with no password |

---

## 7. Known gaps, and who they block

| Gap | Impact | Fix |
|---|---|---|
| `hashedQuitPassword` scheme undocumented | A wrong hash means the kiosk cannot be quit. Razor uses bare `SHA-256(password)` (the published example is 64 hex chars with no salt), and **this is unconfirmed for 3.10.2** | Settle it once with `tools/verify-seb.mjs`; if it disagrees, vendor Config Tool's hash. Never guess |
| Job Object confinement absent | A fork bomb or a runaway background process is only stopped by `taskkill /T` | Native bindings or a small helper process |
| No firewall rule for the PTY user | The command policy can be bypassed by obfuscation | AppLocker/WDAC plus an outbound block scoped to the exam account |
| AppLocker policy not applied | Nothing stops a candidate launching an unlisted binary | Apply `build/applocker-razor.xml` as an administrator, on the exam account |
| BEK not implemented | SEB cannot be distinguished from a *very* faithful imitation purely by the RequestHash header | Pin the BEK per SEB build if you need it; CK already covers config provenance |
| Attestation is only as good as the config's secrecy | With `plnd`, the CK is public | Use an encrypted `.seb` (production requires it, or an explicit logged opt-in) |
| Audit log is local and writable | A candidate can delete it | Ship it off-box (the heartbeat is the seam for this) |
| Self-reported status | `mode`, `seb.running` etc. in the heartbeat are claims | Device-key-signed heartbeats with a nonce and monotonic counter |
| Single interactive user | See §1 | Separate low-privilege account |

## 8. Things this build deliberately refuses to do

1. **Fabricate a `pswd` (encrypted) `.seb`.** SEB 3.x's exact RNCryptor
   parameters are not documented anywhere reachable. A wrong `pswd` file fails
   at exam time, so production requires a Config Tool artifact instead.
2. **Guess the quit-password hash.** It computes SHA-256 and tells you to
   verify it, rather than silently shipping something that might lock a room
   out of kiosk mode.
3. **Ship a hand-rolled WebSocket server.** `ws` is a deliberate dependency in
   an otherwise dependency-light design: framing, masking, fragmentation,
   `maxPayload` and backpressure are easy to get subtly wrong in front of a
   shell.
4. **Pretend Job Object confinement works.** `RAZOR_CONFINEMENT=jobobject`
   fails loudly instead of reporting a control it does not have.
5. **Apply AppLocker automatically.** It generates a policy and prints where it
   is; applying machine-wide execution control is an administrator's decision.
