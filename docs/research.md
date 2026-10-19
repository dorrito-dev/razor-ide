# Research summary

Two questions had to be answered before writing code: which libraries to embed,
and how Safe Exam Browser can be driven from a local launcher. Both were
answered from primary sources, and the parts that could not be verified are
flagged as such rather than guessed.

---

## 1. Editor

**Chosen: CodeMirror 6.**

| | CodeMirror 6 | Monaco | Ace | CodeJar |
|---|---|---|---|---|
| Bundle (gz) | **~119 kB** for `basicSetup`; ~45–60 kB for a minimal editor | ~1.5–3.5 MB for a multi-language setup | ~300 kB | ~10 kB |
| Bundler config | **none** — plain esbuild | worker wiring (`MonacoEnvironment.getWorker`), AMD build deprecated | none | none |
| Module format | dual ESM + CJS | ESM + workers | script/ESM | ESM |
| Language support | Lezer, first-party `@codemirror/lang-*` | TextMate-ish + real TS/JS services in workers | modes | Prism |
| Multi-tab | free — one `EditorState` per file, `view.setState()` | manual models | possible | no |
| Offline / self-hosted | yes, trivially | yes, but you must bundle the workers and `codicon.ttf` | yes | yes |

Rationale, in five lines: the brief prioritises "lightweight and easy to embed",
and CodeMirror 6 is 5–10× smaller than Monaco with **zero** build-tooling
requirements, where Monaco needs custom worker plumbing in every bundler.
Razor must run entirely offline because SEB's URL filter blocks external
origins, so the library must be bundled locally — trivial for CodeMirror,
extra work for Monaco. Monaco's one genuine advantage is VS Code's exact
TypeScript IntelliSense, which an exam IDE does not need. If you later want
language-server features, `@codemirror/lsp-client` exists.

Versions verified on this machine: `codemirror` 6.0.2, `@codemirror/view`
6.43.13, `@codemirror/state` 6.7.6, `@codemirror/language` 6.12.4.

*Caveats:* the size figures are published bundle measurements and exclude
language packages (each `@codemirror/lang-*` adds roughly 10–40 kB gz). The
built Razor UI is **988 kB minified** including CodeMirror, seven language
packages and xterm — that is the number that actually matters.

## 2. Terminal

**Chosen: `@xterm/xterm` (front end) + `node-pty` (backend).**

- **xterm.js** has no credible competitor: it is the renderer behind VS Code's
  integrated terminal, ~82 kB gz with zero dependencies, and the
  `@xterm/*` scope migration is complete. The alternatives are dead ends —
  `hterm` is not published as a maintained standalone package, and `wterm` on
  npm is a 526-byte placeholder, not the real project.
- **Transport:** one WebSocket per terminal. **Binary frames for terminal
  data**, text frames carrying JSON for control messages (`resize`, `input`,
  `seb`). JSON frames for bulk terminal data would waste bandwidth and can
  corrupt UTF-8 sequences split across frames.
- **`node-pty` 1.1.0 supports Windows ConPTY** (winpty support was removed;
  Windows 10 1809+ required) and **ships prebuilt binaries**, so no Visual
  Studio Build Tools are needed on win32-x64.

**Verified empirically on this machine**, not just from documentation:

```
node-pty loaded OK, version: 1.1.0
EXIT {"exitCode":0}
OUTPUT>>>HELLO_FROM_PTY
Microsoft Windows [Version 10.0.26100.9457]<<<
```

*Caveats:* `node-pty` is not thread-safe, and a PTY child inherits the parent's
privilege level — which is why the terminal confinement story in
`docs/security.md` matters. Prebuilds are ABI-tied, so pin the Node version and
vendor `node_modules` for an air-gapped install.

## 3. WebSocket library

**Chosen: `ws`** — a deliberate exception to the otherwise zero-dependency
design. Framing, masking, fragmentation handling, `maxPayload` enforcement and
backpressure are easy to get subtly wrong, and `ws` is small and
battle-tested. Writing a custom WebSocket server in front of a shell is not a
place to be clever.

---

## 4. Safe Exam Browser

Everything below was checked against the SEB 3.10.2.920 installation on this
machine, SEB's own published developer documentation, and SEB's source of truth
for setting names — `SafeExamBrowser.Configuration/ConfigurationData/Keys.cs`
(ETH Zurich, MPL-2.0).

### 4.1 Launching it

```powershell
"C:\Program Files\SafeExamBrowser\Application\SafeExamBrowser.exe" "C:\path\to\exam.seb"
```

- **The config path is plain `argv[1]`. There are no command-line flags** — no
  `/seb`, `--seb`, `-c` or `--help`. Confirmed by the SEB project lead on the
  official tracker ([support request #72](https://sourceforge.net/p/seb/support-requests/72/)):
  *"You can simply pass the full path to a file (or a seb(s) link) on the
  command line."*
- **Independently corroborated on this machine** — the registry handler for
  both the `.seb` file association and the `seb:` / `sebs:` URI schemes is
  literally:
  ```
  HKLM\SOFTWARE\Classes\seb\shell\open\command
    (Default) = "C:\Program Files\SafeExamBrowser\Application\SafeExamBrowser.exe" "%1"
  ```
- **SEB has no portable mode.** It must be installed, because the Windows
  service `SafeExamBrowser` (LocalSystem, automatic) performs the
  Ctrl+Alt+Del registry lockdown and the privileged work.
- Use an **absolute, quoted** path: `Program Files` has a space in it, and the
  vendor left relative-path resolution explicitly unresolved.

### 4.2 The `.seb` file format

From SEB's published developer documentation, *File Format*:

```
file = gzip( "plnd" + gzip( plistXml ) )            -- unencrypted
file = gzip( "pswd" + RNCryptor( gzip(plistXml) ) ) -- password
file = gzip( "pkhs" | 20-byte key hash | ... )      -- certificate
```

`plnd` = "plain data"; `pswd` = password; `pwcc` = client settings; `phsk` =
certificate + symmetric key; `pkhs` = certificate only. On load, SEB gunzips,
reads the 4-byte prefix, and for `plnd` strips it and treats the remainder as
the XML settings data — **the unencrypted form is a first-class, documented
format.** Only the Config Tool *UI* refuses to save one.

The payload is an Apple plist. Razor writes `plnd` and reads it back; it
**refuses to fabricate `pswd`**, because SEB 3.x's exact RNCryptor parameters
(iteration count, schema version, salt derivation) are not documented anywhere
reachable, and a wrong `pswd` file fails at exam time. Production therefore
requires a config produced by SEB Config Tool.

### 4.3 Settings that matter

| Purpose | Key | Notes |
|---|---|---|
| Start URL | `startURL` | **Singular. There is no `startURLs` array.** This is the single most important finding: the loopback URL must live inside the config, because the command line takes a *file*, not a URL |
| Quit / unlock | `hashedQuitPassword`, `allowQuit`, `quitURL`, `quitURLConfirm`, `quitURLRestart` | No plaintext `quitPassword` key exists in 3.x |
| Kiosk | `browserViewMode`, `createNewDesktop`, `killExplorerShell`, `monitorProcesses` | `createNewDesktop` is documented to break NVDA/JAWS screen readers; `killExplorerShell` is the compatible alternative |
| Key blocking | `enableAltTab`, `enableAltEsc`, `enableAltF4`, `enableCtrlEsc`, `enableStartMenu`, `enablePrintScreen`, `enableInjected`, `enableF1`…`enableF12` | Pairwise booleans, not a single "lockdown" switch |
| URL filter | `URLFilterEnable`, `URLFilterRules`, `URLFilterEnableContentFilter` | Rules are `{active, regex, expression, action}` with **action 1 = allow, 0 = block**; the filter **blocks by default** |
| Downloads / reconfig | `allowDownloads`, `allowUploads`, `downloadAndOpenSebConfig`, `examSessionReconfigureAllow` | The last two gate `.seb`-driven reconfiguration |
| Capture / VM | `allowScreenSharing`, `allowVirtualMachine`, `enableSessionVerification` | Windows uses `allowScreenSharing`; `allowScreenCapture`/`allowWindowCapture` are Apple-only |
| New windows | `newBrowserWindowByLinkPolicy`, `newBrowserWindowAllowAddressBar`, `newBrowserWindowNavigation`, `newBrowserWindowByLinkBlockForeign` | Must be locked down or they are an escape hatch |
| Dev console | `allowDeveloperConsole` | Off in production, on in dev |

**Do not use** (2.x-legacy, or macOS/iOS-only, absent from the Windows key
map): `blockPopUpWindows`, `enableJavaScript`, `hookKeys`, `ignoreExitKeys`,
`exitKey1..3`, `blacklistURLFilter`/`whitelistURLFilter`, `additionalResources`,
`allowSwitchToApplications` (Mac), `allowScreenCapture` (Apple).
**Non-existent** as SEB keys, despite appearing in common folklore:
`startURLs`, `openLinksInNewWindow`, `activeExamMode`.

### 4.4 The localhost problem

Because the command line takes a config file and `startURL` is singular, the
flow must be: **generate a `.seb` whose `startURL` points at the Razor origin,
then hand SEB that file.** Consequently:

- The URL-filter allow rule for `127.0.0.1:<port>` is **mandatory**, not
  optional. Razor writes explicit allow rules for the bare `host:port`, the
  `http://` form and the `ws://` form, rather than relying on SEB's historical
  auto-allow of the start URL.
- Use **`127.0.0.1`, not `localhost`**: deterministic filter matching, no DNS
  or IPv6 ambiguity.
- The WebSocket must also be allow-listed. `ws://127.0.0.1:<port>` is written
  explicitly; an unverified assumption here would present as "the terminal
  never connects", so it is called out in `docs/security.md` as an item to
  confirm during the first live SEB run.

### 4.5 Server-side verification (attestation)

SEB can send two hash headers on every request when `sendBrowserExamKey=true`:

- `X-SafeExamBrowser-ConfigKeyHash` — the **Config Key** request hash.
- `X-SafeExamBrowser-RequestHash` — the **Browser Exam Key** request hash.

Documented construction for both: `SHA-256( absoluteUrlWithoutFragment + baseKey )`,
rendered as lowercase base16.

**Razor validates the Config Key and deliberately does not implement the BEK.**
The CK is derived only from the config (canonical SEB-JSON: strip
`originatorVersion`, sort every dict recursively, no whitespace, no escaping,
drop empty dicts, `<data>`→base64, `<date>`→ISO 8601, round `<real>`), so it is
**platform-independent and server-computable**. The BEK folds in SEB's *code
signature*, which makes it platform- **and bitness-specific** and impossible to
compute without pinning one value per SEB build. Using the CK is the correct
choice for a Windows-only integration.

Because a `plnd` config is readable, the Config Key derived from it is public —
so CK validation proves *which config a request came from*, not that the
candidate is honest. In production, attestation is meaningful only with an
**encrypted** config.

### 4.6 Remaining unknowns, stated plainly

1. **The `hashedQuitPassword` hashing scheme is not documented.** The published
   example is 64 lowercase hex characters, i.e. a bare SHA-256 digest with no
   salt component, so Razor uses plain `SHA-256(password)`. This is
   **unconfirmed for 3.10.2** and a wrong value in kiosk mode means nobody can
   quit. `tools/verify-seb.mjs` exists to settle it: save a config with a known
   password in SEB Config Tool, and compare. If it disagrees, vendor Config
   Tool's hash rather than guessing.
2. **The BEK byte-level formula** lives only in a PDF we could not retrieve, so
   it is not implemented (see above) — which is a deliberate design choice, not
   a gap.
3. **`browserViewMode`'s integer encoding** (0/1/2) is not first-party
   documented; windowed = 0 and fullscreen = 1 is what Razor emits and what the
   first live run should confirm.
4. **`sebConfigPurpose` 0 = start exam, 1 = configure client** comes from the
   config-key documentation family and should be confirmed in the same run.
5. **Whether SEB issues a GET to `quitURL`** is not stated in the docs; it is
   documented as a *navigation detection*, so no reliance is placed on it.
