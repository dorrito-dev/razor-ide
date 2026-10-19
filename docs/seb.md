# The `.seb` file, concretely

Everything here is either (a) quoted from SEB's published developer
documentation, (b) read from SEB's own source of setting names, or (c) marked as
unverified. The unverified items are the ones to confirm on the first live run.

---

## 1. Container format

A `.seb` file is a **gzip archive with a `.seb` extension**. That is deliberate:
it makes browsers download rather than display it.

After the outer gunzip, the first four bytes are a prefix:

| Prefix | Meaning |
|---|---|
| `plnd` | Plain data — unencrypted, gzip-compressed plist |
| `pswd` | Password-encrypted (RNCryptor) |
| `pwcc` | Password-encrypted **client settings** |
| `phsk` | Certificate + symmetric key |
| `pkhs` | Certificate only (20-byte public key hash follows) |

For the unencrypted case the file is **gzipped twice**:

```
.seb file  = gzip( "plnd" + gzip( plistXml ) )
```

SEB's documented load procedure: gunzip, read the prefix, and *"if it is `plnd`,
then strip the 4 bytes prefix, the remaining data is the XML settings data."*
The Config Tool **UI** refuses to save an unencrypted config, but the client
accepts one — that is a documented, first-class format.

Razor writes exactly this. Inspect any generated file with:

```powershell
node tools/verify-seb.mjs --inspect
```

### Why Razor will not write `pswd`

The password path is RNCryptor: PBKDF2 → AES-256-CBC → HMAC-SHA-256, laid out as
`version|options|encSalt8|hmacSalt8|IV16|ciphertext|HMAC32`. The *documented*
parameters (PBKDF2, 10 000 iterations) come from an older specification, and
SEB 3.x's actual schema version and iteration count could not be verified. A
guessed `pswd` file fails at exam time, in a room, with no recourse — so
production requires a config saved by **SEB Config Tool** and refuses to
substitute one silently.

### A `plnd` config is not secret

It is plain XML. A candidate can read the exam URL and filter rules, and craft
their own config with `allowQuit=true`. It is fine for development and CI and
**is not acceptable for a graded exam.** Production enforces an encrypted config
(`RAZOR_SEB_CONFIG=...`) unless `RAZOR_ALLOW_UNENCRYPTED_SEB=1` is set, which is
logged.

---

## 2. Launching it

```powershell
"C:\Program Files\SafeExamBrowser\Application\SafeExamBrowser.exe" "C:\path\to\exam.seb"
```

- **No flags exist.** The config path is `argv[1]`. Confirmed by the SEB lead on
  the official tracker and corroborated by this machine's registry handler
  (`...\SafeExamBrowser.exe "%1"` for `.seb`, `seb:` and `sebs:`).
- **Absolute, quoted path.** `Program Files` contains a space.
- **Installation is mandatory.** SEB has no portable mode; the
  `SafeExamBrowser` Windows service (LocalSystem) does the privileged work.
- Print the exact command without launching anything:
  ```powershell
  node src/main.mjs --seb --seb-argv-only
  ```

---

## 3. The settings Razor emits

Grep `src/seb/config.mjs`. The table is in
[`research.md` §4.3](research.md#43-settings-that-matter). Two keys deserve
emphasis:

- **`startURL` is singular.** There is no `startURLs` array in SEB 3.x, which is
  why the loopback URL has to be written into a generated config rather than
  passed on the command line.
- **`URLFilterEnable` blocks by default.** An explicit allow rule for the
  loopback origin is mandatory. Razor writes three forms —
  `127.0.0.1:<port>`, `http://127.0.0.1:<port>`, `ws://127.0.0.1:<port>` —
  because the terminal's WebSocket has to pass the same filter, and an
  unverified assumption there would present as "the terminal never connects".

---

## 4. Verifying the config against the real client

Nothing in this repository can prove SEB accepts our file. Only SEB can.

```powershell
# build it, inspect the container, print the command line and the quit hash
node tools/verify-seb.mjs

# really launch it. Windowed + allowQuit so a failure cannot trap you.
node tools/verify-seb.mjs --launch
```

After launching, read SEB's own logs under
`%LOCALAPPDATA%\SafeExamBrowser\` and look for
`[FileResourceLoader] Loading data from ...`. That line means the configuration
was read.

**Run this in a VM or on a disposable profile the first time.** A
password-protected config puts the machine into kiosk mode, and the quit
password printed by the tool is the only way out.

### The one thing to confirm by hand

`hashedQuitPassword` — SEB's password hashing scheme is not documented. The
published example value is 64 lowercase hex characters, i.e. a bare SHA-256
digest with no salt, so Razor computes `SHA-256(password)`.

To settle it:

1. Open `SEBConfigTool.exe` and load `run/verify.plist.xml`.
2. Set the quit password to the value the tool printed.
3. Save as a `.seb`, then gunzip it twice and read `hashedQuitPassword`:
   ```powershell
   node -e "const z=require('zlib'),f=require('fs');const o=z.gunzipSync(f.readFileSync('out.seb'));console.log(z.gunzipSync(o.subarray(4)).toString('utf8'))"
   ```
4. Compare with the hash the tool printed.

If they differ, **vendor Config Tool's value** — do not guess, and do not ship a
kiosk config whose quit password has never been tested.

---

## 5. Attestation

| Header | Base key | Server-computable? |
|---|---|---|
| `X-SafeExamBrowser-ConfigKeyHash` | Config Key — canonical config only | **yes** — Razor implements this |
| `X-SafeExamBrowser-RequestHash` | Browser Exam Key — config **+ SEB code signature** | **no** — platform- and bitness-specific |

Both are `SHA-256( absoluteUrlWithoutFragment + baseKey )`, lowercase base16,
sent on every request when `sendBrowserExamKey=true`.

The Config Key canonicalisation (from SEB's documentation): strip
`originatorVersion`, sort every dict recursively and case-insensitively, no
whitespace, no character escaping, drop empty dicts, `<data>`→base64,
`<date>`→ISO 8601, round `<real>` floats (so `0.10000000000000001` and `0.1`
hash identically). Razor computes it from the same object that produces the XML,
so what is verified is what was shipped.

**The BEK is intentionally not implemented.** Pinning it means copying a value
out of each SEB build. `test/admin.test.mjs` asserts that a RequestHash header
does not satisfy Config Key attestation.

---

## 6. Operational notes

- **A config with a quit password is a "secure session"**, which blocks
  reconfiguration. To re-point a running SEB you need both
  `downloadAndOpenSebConfig` and `examSessionReconfigureAllow`. Relaunching per
  exam is tighter and is what Razor assumes.
- **A forced reboot can leave the Ctrl+Alt+Del registry lockdown in place**
  until SEB exits cleanly, the machine reboots, or the reset utility runs
  (`C:\Program Files\SafeExamBrowser\Reset\SafeExamBrowser.ResetUtility.exe`).
  Put that in the exam-day runbook.
- **Antivirus HTTPS inspection** can trip SEB's own integrity check
  ("irregular files were found in SEB's program directory"). Disable HTTPS
  inspection before exams, or use `embeddedCertificates`.
