// Razor browser UI: CodeMirror 6 editor + xterm.js terminal.
//
// Offline by construction: every dependency is bundled by scripts/build.mjs
// into /vendor, and the page makes no request to any origin other than
// http://127.0.0.1:<port>. That is required -- SEB's URL filter blocks
// everything else by default.
import { EditorState, Compartment } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine, drawSelection } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';
import { searchKeymap, highlightSelectionMatches } from '@codemirror/search';
import { autocompletion, completionKeymap, closeBrackets } from '@codemirror/autocomplete';
import { bracketMatching, indentOnInput, syntaxHighlighting, defaultHighlightStyle } from '@codemirror/language';
import { oneDark } from '@codemirror/theme-one-dark';
import { javascript } from '@codemirror/lang-javascript';
import { python } from '@codemirror/lang-python';
import { json } from '@codemirror/lang-json';
import { markdown } from '@codemirror/lang-markdown';
import { html } from '@codemirror/lang-html';
import { css } from '@codemirror/lang-css';
import { rust } from '@codemirror/lang-rust';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';

const $ = (id) => document.getElementById(id);

// Runtime config: production disables autocomplete and paste, because both are
// leakage channels in an exam (completion models and clipboard smuggling).
const CONFIG = window.__RAZOR__ ?? { mode: 'dev', autocomplete: true, paste: true };

const state = {
  files: [],
  tabs: new Map(), // path -> { path, state, dirty }
  active: null,
  gate: null,
  socket: null,
  term: null,
  fit: null,
};

// ---------------------------------------------------------------------------
// Gate / lock overlay
// ---------------------------------------------------------------------------

function renderGate(gate, mode) {
  const locked = gate.state !== 'running';
  $('lock').hidden = !locked;
  $('app').inert = locked;

  $('lock-mode').textContent = mode;
  $('lock-state').textContent = gate.state;
  $('lock-lease').textContent = gate.lease
    ? `${gate.lease.state} (expires in ${Math.round(gate.lease.remainingMs / 1000)}s)`
    : 'none';

  if (gate.state === 'locked') {
    $('lock-title').textContent = 'Session locked';
    $('lock-message').textContent =
      `The session lost contact with the exam server (${gate.lockReason ?? 'lease expired'}). ` +
      'Contact your proctor.';
  } else if (gate.state === 'stopped') {
    $('lock-title').textContent = 'Session ended';
    $('lock-message').textContent = 'The exam session has been stopped by an administrator.';
  } else if (gate.state === 'running') {
    $('lock-title').textContent = 'Session active';
  } else {
    $('lock-title').textContent = 'Waiting for administrator';
    $('lock-message').textContent =
      'This session has not been authorised yet. It starts only when an administrator ' +
      'sends a start request.';
  }

  const lease = $('lease-status');
  if (gate.lease) {
    const seconds = Math.round(gate.lease.remainingMs / 1000);
    lease.textContent = `lease: ${gate.lease.state} ${seconds}s`;
    lease.className = `status-pill ${gate.lease.state === 'live' ? 'ok' : 'warn'}`;
  } else {
    lease.textContent = 'lease: --';
    lease.className = 'status-pill';
  }
}

async function pollState() {
  try {
    const response = await fetch('/api/state', { credentials: 'same-origin' });
    const body = await response.json();
    state.gate = body.gate;
    renderGate(body.gate, body.mode);

    const seb = body.seb;
    const pill = $('seb-status');
    if (!seb || !seb.running) {
      pill.textContent = 'SEB: not running';
      pill.className = 'status-pill warn';
    } else {
      pill.textContent = `SEB ${seb.version ?? '?'} (${seb.attestation ?? 'unknown'})`;
      pill.className = `status-pill ${seb.attestation === 'verified' ? 'ok' : 'warn'}`;
    }

    if (body.gate.state === 'running' && !state.socket) connectTerminal();
  } catch {
    /* the server may be mid-restart; the next tick retries */
  }
}

// ---------------------------------------------------------------------------
// Editor
// ---------------------------------------------------------------------------

const languageCompartment = new Compartment();

function languageFor(path) {
  const ext = (path.split('.').pop() ?? '').toLowerCase();
  switch (ext) {
    case 'js':
    case 'mjs':
    case 'cjs':
    case 'jsx':
    case 'ts':
      return javascript();
    case 'py':
      return python();
    case 'json':
      return json();
    case 'md':
      return markdown();
    case 'html':
    case 'htm':
      return html();
    case 'css':
      return css();
    case 'rs':
      return rust();
    default:
      return [];
  }
}

function baseExtensions() {
  const extensions = [
    lineNumbers(),
    history(),
    drawSelection(),
    highlightActiveLine(),
    highlightSelectionMatches(),
    bracketMatching(),
    closeBrackets(),
    indentOnInput(),
    syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
    oneDark,
    keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap, indentWithTab]),
    // No completion keymap in production: autocomplete is disabled outright.
    ...(CONFIG.autocomplete ? [autocompletion(), keymap.of(completionKeymap)] : []),
    EditorView.updateListener.of((update) => {
      if (!update.docChanged || !state.active) return;
      const tab = state.tabs.get(state.active);
      if (!tab || tab.dirty) return;
      tab.dirty = true;
      renderTabs();
    }),
    EditorView.domEventHandlers({
      paste: (event) => {
        if (CONFIG.paste) return false;
        event.preventDefault();
        toast('Pasting is disabled during the exam.', 'error');
        return true;
      },
    }),
  ];
  return extensions;
}

const view = new EditorView({
  state: EditorState.create({ doc: '', extensions: baseExtensions() }),
  parent: $('editor'),
});

async function openFile(path) {
  if (state.tabs.has(path)) return selectTab(path);
  const response = await fetch(`/api/files/read?path=${encodeURIComponent(path)}`, {
    credentials: 'same-origin',
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    toast(`Cannot open ${path}: ${body.reason ?? body.error ?? response.status}`, 'error');
    return;
  }
  const body = await response.json();
  state.tabs.set(path, { path, content: body.content, dirty: false });
  selectTab(path);
  renderTabs();
}

function selectTab(path) {
  state.active = path;
  const tab = state.tabs.get(path);
  if (tab) {
    view.setState(
      EditorState.create({
        doc: tab.content,
        extensions: [...baseExtensions(), languageCompartment.of(languageFor(path))],
      }),
    );
  }
  $('active-file').textContent = path;
  renderTabs();
  markTreeSelection();
}

function closeTab(path) {
  state.tabs.delete(path);
  if (state.active === path) {
    const next = [...state.tabs.keys()].pop();
    if (next) selectTab(next);
    else {
      state.active = null;
      $('active-file').textContent = 'no file open';
      view.setState(EditorState.create({ doc: '', extensions: baseExtensions() }));
    }
  }
  renderTabs();
}

function renderTabs() {
  const container = $('tabs');
  container.textContent = '';
  for (const [path, tab] of state.tabs) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `tab${path === state.active ? ' active' : ''}`;
    button.append(document.createTextNode(path.split('/').pop()));
    if (tab.dirty) {
      const dot = document.createElement('span');
      dot.className = 'dirty';
      dot.textContent = '\u25cf';
      button.append(dot);
    }
    button.addEventListener('click', () => selectTab(path));
    button.addEventListener('auxclick', (event) => {
      if (event.button === 1) closeTab(path);
    });
    container.append(button);
  }
}

async function saveActive() {
  if (!state.active) return;
  const tab = state.tabs.get(state.active);
  if (!tab) return;
  const content = view.state.doc.toString();
  const response = await fetch(`/api/files/write?path=${encodeURIComponent(tab.path)}`, {
    method: 'PUT',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ content }),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    toast(`Save failed: ${body.reason ?? body.error ?? response.status}`, 'error');
    return;
  }
  tab.content = content;
  tab.dirty = false;
  renderTabs();
  toast(`Saved ${tab.path}`, 'ok');
}

// ---------------------------------------------------------------------------
// Explorer
// ---------------------------------------------------------------------------

async function refreshTree() {
  const response = await fetch('/api/files/list?path=.', { credentials: 'same-origin' });
  if (!response.ok) return;
  const body = await response.json();
  state.files = body.entries;
  const list = $('tree');
  list.textContent = '';
  for (const entry of body.entries) {
    const item = document.createElement('li');
    const depth = entry.path.split('/').length - 1;
    item.style.paddingLeft = `${10 + depth * 12}px`;
    item.dataset.path = entry.path;
    item.className = entry.type === 'dir' ? 'dir' : 'file';
    item.textContent = (entry.type === 'dir' ? '\u25b8 ' : '') + entry.path.split('/').pop();
    if (entry.type === 'file') item.addEventListener('click', () => openFile(entry.path));
    list.append(item);
  }
  markTreeSelection();
}

function markTreeSelection() {
  for (const item of document.querySelectorAll('#tree li')) {
    item.classList.toggle('active', item.dataset.path === state.active);
  }
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

function connectTerminal() {
  if (state.socket) return;
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${proto}//${location.host}/ws/terminal`);
  socket.binaryType = 'arraybuffer';
  state.socket = socket;

  const term = new Terminal({
    fontFamily: 'ui-monospace, "Cascadia Mono", Consolas, monospace',
    fontSize: 13,
    cursorBlink: true,
    scrollback: 5000,
    theme: {
      background: '#11141a',
      foreground: '#e6e8eb',
      cursor: '#4aa3ff',
      selectionBackground: '#2b3a52',
    },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  // Links are shown but never opened: navigation is blocked by SEB.
  term.loadAddon(new WebLinksAddon((_event, uri) => toast(`Link blocked: ${uri}`, 'error')));
  term.open($('terminal'));
  state.term = term;
  state.fit = fit;

  const sendResize = debounce(() => {
    fit.fit();
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
    }
  }, 80);

  socket.addEventListener('open', () => {
    sendResize();
    term.focus();
  });

  socket.addEventListener('message', (event) => {
    if (typeof event.data !== 'string') {
      term.write(new Uint8Array(event.data));
      return;
    }
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message.type === 'data') term.write(message.data);
    else if (message.type === 'notice') toast(message.message, message.level === 'error' ? 'error' : 'ok');
    else if (message.type === 'exit') term.write('\r\n[process exited]\r\n');
    else if (message.type === 'error') toast(`Terminal error: ${message.error}`, 'error');
    else if (message.type === 'ready') {
      $('term-hint').textContent = `audited · pid ${message.pid} · confinement ${message.confinement}`;
    }
  });

  socket.addEventListener('close', () => {
    state.socket = null;
    term.write('\r\n[disconnected]\r\n');
  });

  socket.addEventListener('error', () => toast('Terminal connection failed.', 'error'));

  // Keystrokes go over the text control channel so the server can screen every
  // line before it reaches the PTY.
  let lineBuffer = '';
  term.onData((data) => {
    if (socket.readyState !== WebSocket.OPEN) return;
    lineBuffer = data.includes('\r') || data.includes('\n') ? '' : lineBuffer + data;
    socket.send(JSON.stringify({ type: 'input', data }));
  });

  window.addEventListener('resize', sendResize);
}

function restartTerminal() {
  if (state.socket) {
    state.socket.close();
    state.socket = null;
  }
  state.term?.dispose();
  state.term = null;
  $('terminal').textContent = '';
  connectTerminal();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let toastTimer = null;
function toast(message, kind = '') {
  const element = $('toast');
  element.textContent = message;
  element.className = `toast ${kind}`;
  element.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    element.hidden = true;
  }, 4000);
}

function debounce(fn, ms) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

// ---------------------------------------------------------------------------
// File actions: New File, Download, Export ZIP
// ---------------------------------------------------------------------------

async function promptNewFile() {
  const name = window.prompt('Enter new file name (e.g. solution.py, test.js):', '');
  if (!name || !name.trim()) return;
  const cleanName = name.trim();
  try {
    const response = await fetch(`/api/files/write?path=${encodeURIComponent(cleanName)}`, {
      method: 'PUT',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ content: '' }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      toast(`Create failed: ${body.reason ?? body.error ?? response.status}`, 'error');
      return;
    }
    toast(`Created ${cleanName}`, 'ok');
    await refreshTree();
    await openFile(cleanName);
  } catch (err) {
    toast(`Create failed: ${err.message}`, 'error');
  }
}

function downloadActiveFile() {
  if (!state.active) {
    toast('No file is currently open to download', 'warn');
    return;
  }
  const a = document.createElement('a');
  a.href = `/api/files/download?path=${encodeURIComponent(state.active)}`;
  a.download = state.active.split('/').pop();
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  toast(`Downloading ${state.active}...`, 'ok');
}

function exportWorkspaceZip() {
  const a = document.createElement('a');
  a.href = '/api/files/export-zip';
  a.download = 'workspace.zip';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  toast('Exporting workspace zip archive...', 'ok');
}

function runActiveFile() {
  if (!state.active) {
    toast('No file is currently open to run', 'warn');
    return;
  }
  void saveActive().then(() => {
    if (!state.socket || state.socket.readyState !== WebSocket.OPEN) {
      toast('Terminal is not connected', 'error');
      return;
    }
    const ext = state.active.split('.').pop().toLowerCase();
    const filename = state.active.replace(/\//g, '\\');
    let cmd = '';
    if (ext === 'py') cmd = `python "${filename}"`;
    else if (ext === 'js' || ext === 'mjs' || ext === 'cjs') cmd = `node "${filename}"`;
    else if (ext === 'c') cmd = `gcc "${filename}" -o "${filename}.exe"; .\\"${filename}.exe"`;
    else if (ext === 'cpp') cmd = `g++ "${filename}" -o "${filename}.exe"; .\\"${filename}.exe"`;
    else if (ext === 'ps1') cmd = `powershell -File "${filename}"`;
    else if (ext === 'bat' || ext === 'cmd') cmd = `cmd /c "${filename}"`;
    else cmd = `.\\"${filename}"`;

    state.socket.send(JSON.stringify({ type: 'input', data: `${cmd}\r` }));
    state.term?.focus();
    toast(`Running ${cmd}...`, 'ok');
  });
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

$('save').addEventListener('click', () => void saveActive());
$('run-code')?.addEventListener('click', runActiveFile);
$('term-run')?.addEventListener('click', runActiveFile);
$('download-file')?.addEventListener('click', downloadActiveFile);
$('export-zip')?.addEventListener('click', exportWorkspaceZip);
$('new-file')?.addEventListener('click', () => void promptNewFile());
$('refresh').addEventListener('click', () => void refreshTree());
$('term-restart').addEventListener('click', restartTerminal);

window.addEventListener('keydown', (event) => {
  if (event.key === 'F5') {
    event.preventDefault();
    runActiveFile();
  } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
    event.preventDefault();
    void saveActive();
  }
});

// Report the SEB JS API state. On Windows SEB >= 3.3.2 the values are already
// present without updateKeys(); they are URL-hashed and self-reported, so the
// server records them as a claim rather than as proof.
function reportSebIdentity() {
  if (typeof window.SafeExamBrowser === 'undefined') return;
  const api = window.SafeExamBrowser;
  try {
    const value = {
      version: api.version ?? null,
      configKey: api.security?.configKey ?? null,
      browserExamKey: api.security?.browserExamKey ?? null,
    };
    if (state.socket?.readyState === WebSocket.OPEN) {
      state.socket.send(JSON.stringify({ type: 'seb', value }));
    }
  } catch {
    /* API shape varies by SEB build */
  }
}

void refreshTree();
void pollState();
setInterval(pollState, 3000);
setInterval(reportSebIdentity, 15_000);
