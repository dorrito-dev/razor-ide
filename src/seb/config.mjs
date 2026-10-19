// Builds the SEB configuration as a plain JS object (which is also the parsed
// plist that the SEB Config Key is computed from).
//
// Every key name here was taken from SEB's own Windows source of truth,
// `SafeExamBrowser.Configuration/ConfigurationData/Keys.cs` (ETH Zurich,
// MPL-2.0). Keys that exist only on macOS/iOS (`allowSwitchToApplications`,
// `allowScreenCapture`, `allowWindowCapture`) and 2.x-legacy keys
// (`blockPopUpWindows`, `enableJavaScript`, `hookKeys`) are deliberately
// absent -- see docs/research.md for the do-not-use list.
import { sebPasswordHash } from '../security/crypto.mjs';

/** SEB `browserViewMode`: windowed for the first-run smoke test, fullscreen otherwise. */
export const ViewMode = Object.freeze({ Windowed: 0, Fullscreen: 1, TouchOptimized: 2 });

export const ORIGINATOR_VERSION = '3.10.0';

/**
 * Stable per-install machine identity. Used inside signed grants so a grant
 * captured on one workstation cannot be replayed on another.
 */
export function machineId({ hostname, username = process.env.USERNAME ?? 'unknown' }) {
  return `${hostname}/${username}`.toLowerCase();
}

/**
 * @param {object} opts
 * @param {string} opts.startUrl            http://127.0.0.1:<port>/?b=<bootstrap>
 * @param {string|null} opts.quitPassword   per-session secret from the signed grant
 * @param {string} opts.mode                'dev' | 'production'
 * @param {boolean} opts.windowed           first-run smoke test only
 * @param {string[]} opts.allowedOrigins    extra URL-filter allow rules
 * @param {boolean} opts.sendBrowserExamKey enable CK/BEK request headers
 * @param {string|null} opts.configKeyHash  pinned expected Config Key (production)
 * @param {boolean} opts.enableDevConsole   allow Developer Console (dev only)
 * @param {boolean} opts.hardened           force desktop-level kiosk enforcement
 */
export function buildSebPolicy(opts) {
  const {
    startUrl,
    quitPassword = null,
    mode = 'dev',
    windowed = false,
    allowedOrigins = [],
    sendBrowserExamKey = true,
    configKeyHash = null,
    enableDevConsole = false,
    hardened = false,
  } = opts;

  const production = mode === 'production';
  // Desktop-level enforcement: the candidate works on a dedicated SEB desktop
  // rather than on their own with a fullscreen window in front of it.
  //
  // This is the difference between "looks locked" and "is locked". With
  // createNewDesktop=false the keyboard hooks below (Alt+Tab, Alt+F4, ...) are
  // merely filtered inside the SEB window, and the Windows desktop is still
  // reachable underneath, so the session can be switched away from or closed.
  // createNewDesktop=true moves the browser to a separate desktop with the
  // Explorer shell out of the way, which is what actually prevents that.
  //
  // Verified live on SEB 3.10.2: with the previous setting a user could Alt+Tab
  // away and close the kiosk; see docs/security.md for the accessibility
  // caveat (SEB documents createNewDesktop as breaking NVDA/JAWS screen
  // readers, which is why it is opt-in rather than the default).
  const enforceDesktop = hardened || production;

  /** @type {Record<string, unknown>} */
  const policy = {
    // -- session ---------------------------------------------------------
    sebConfigPurpose: 0, // 0 = start exam, 1 = configure client
    startURL: startUrl,
    startURLAppendQueryParameter: false,
    originatorVersion: ORIGINATOR_VERSION,

    // -- window / kiosk --------------------------------------------------
    // A window on an isolated desktop is a contradiction, so enforcement wins
    // over a windowed request rather than emitting a config validateSebPolicy
    // would reject.
    browserViewMode: windowed && !enforceDesktop ? ViewMode.Windowed : ViewMode.Fullscreen,
    // See enforceDesktop above: this is the setting that makes the lockdown
    // real rather than cosmetic.
    createNewDesktop: enforceDesktop,
    killExplorerShell: enforceDesktop,
    monitorProcesses: true,

    browserWindowAllowAddressBar: false,
    browserWindowAllowReload: false,
    browserWindowShowURL: 0, // never show the URL
    allowBrowsingBackForward: false,

    // -- quitting --------------------------------------------------------
    // Dev: always quittable. Production: quittable only through the
    // per-session password, so an unattended kiosk is always recoverable.
    allowQuit: !production,
    ...(quitPassword ? { hashedQuitPassword: sebPasswordHash(quitPassword) } : {}),

    // -- keyboard / input lockdown --------------------------------------
    enableAltTab: false,
    enableAltEsc: false,
    enableAltF4: false,
    enableCtrlEsc: false,
    enableEsc: true, // Esc itself is harmless once Ctrl+Esc and Alt+* are gone
    enableStartMenu: false,
    enablePrintScreen: false,
    enableF1: false,
    enableF2: false,
    enableF3: false,
    enableF6: false,
    enableF7: false,
    enableF8: false,
    enableF9: false,
    enableF10: false,
    enableF11: false,
    enableF12: false,
    enableInjected: true, // block synthetically injected keystrokes
    enableRightMouse: !production,
    enableMiddleMouse: false,

    // -- browser policy --------------------------------------------------
    allowDownloads: false,
    allowUploads: false,
    allowSpellCheck: false,
    allowDeveloperConsole: enableDevConsole,
    allowFind: true,
    allowPrint: false,
    enableZoomPage: false,
    sendBrowserExamKey,
    downloadAndOpenSebConfig: false, // blocks .seb-driven reconfiguration
    examSessionReconfigureAllow: false,
    examSessionClearCookiesOnStart: true,
    examSessionClearCookiesOnEnd: true,
    removeBrowserProfile: true,
    enableBrowserWindowToolbar: false,
    showReloadButton: false,
    browserShowFileSystemElementPath: false,

    // New windows must not become an escape hatch.
    newBrowserWindowByLinkPolicy: 2, // open in same window
    newBrowserWindowByLinkBlockForeign: true,
    newBrowserWindowByLinkWidth: '1024',
    newBrowserWindowByLinkHeight: '768',
    newBrowserWindowAllowAddressBar: false,
    newBrowserWindowAllowReload: false,
    newBrowserWindowNavigation: false,
    newBrowserWindowShowURL: 0,
    newBrowserWindowByLinkPositioning: 2,
    newBrowserWindowShowReloadWarning: true,

    // -- virtualisation / capture / integrity ---------------------------
    // Left keyed to `production` only: refusing to start inside a VM is a
    // separate, higher-risk policy (it makes SEB fail closed on virtualised exam
    // hardware), so `hardened` deliberately does not change it.
    allowVirtualMachine: !production, // false makes SEB refuse to start in a VM
    allowScreenSharing: false,
    allowStickyKeys: false,
    enableSessionVerification: enforceDesktop,
    ...(process.env.RAZOR_SEB_ALLOWED_VERSIONS
      ? { sebAllowedVersions: JSON.parse(process.env.RAZOR_SEB_ALLOWED_VERSIONS) }
      : {}),

    // -- URL filtering ---------------------------------------------------
    // The filter blocks by default; an explicit allow rule is mandatory for
    // the loopback origin, including the WebSocket scheme.
    URLFilterEnable: true,
    URLFilterEnableContentFilter: false,
    URLFilterRules: buildFilterRules(startUrl, allowedOrigins),

    // -- clipboard -------------------------------------------------------
    clipboardPolicy: 0, // 0 = disabled
  };

  if (configKeyHash) policy.configKeyHashExpected = configKeyHash;

  return policy;
}

function buildFilterRules(startUrl, allowedOrigins) {
  const rules = [];
  const seen = new Set();
  const add = (expression) => {
    const e = String(expression);
    if (seen.has(e)) return;
    seen.add(e);
    // action 1 = allow (0 = block)
    rules.push({ active: true, regex: false, expression: e, action: 1 });
  };

  // Loopback over both schemes, with the exact port, in every form SEB's
  // matcher may see. Written explicitly rather than relying on SEB's
  // historical auto-allow of the start URL.
  const url = new URL(startUrl);
  const port = url.port;
  add(`127.0.0.1:${port}`);
  add(`ws://127.0.0.1:${port}`);
  add(`http://127.0.0.1:${port}`);
  for (const origin of allowedOrigins) add(origin);

  return rules;
}

/**
 * Very small, deliberately conservative sanity check. This is a guard against
 * generating a config that cannot work, not a validation of SEB semantics.
 */
export function validateSebPolicy(policy) {
  const problems = [];
  if (!policy.startURL) problems.push('startURL is required (SEB has no startURLs array)');
  if (typeof policy.startURL === 'string' && !policy.startURL.startsWith('http://127.0.0.1')) {
    problems.push(`startURL should use 127.0.0.1 rather than a hostname: ${policy.startURL}`);
  }
  if (!Array.isArray(policy.URLFilterRules) || policy.URLFilterRules.length === 0) {
    problems.push('URLFilterRules needs at least one allow rule for the loopback origin');
  }
  if (policy.URLFilterEnable && !policy.URLFilterRules.some((r) => r.action === 1)) {
    problems.push('URLFilterEnable is on but no allow rule exists: everything would be blocked');
  }
  if (policy.hashedQuitPassword && !/^[0-9a-f]{64}$/.test(policy.hashedQuitPassword)) {
    problems.push('hashedQuitPassword must be 64 lowercase hex characters');
  }
  if (policy.allowQuit === false && !policy.hashedQuitPassword) {
    problems.push('allowQuit=false without a hashedQuitPassword would make the session unquittable');
  }
  if (policy.createNewDesktop && policy.browserViewMode === ViewMode.Windowed) {
    problems.push('createNewDesktop with browserViewMode=windowed is contradictory: one isolates the desktop, the other asks for a window');
  }
  return problems;
}
