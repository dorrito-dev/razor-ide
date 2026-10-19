// Live check of the terminal path against the real node-pty module.
//
// Starts against an already-running Razor and connects to /ws/terminal exactly
// as the browser does, reporting the first frame it gets. Either outcome is a
// pass as long as the server survives:
//   * type=ready  -> the PTY really spawned (named pipes are available)
//   * type=error  -> the PTY could not spawn and was reported, not thrown
// Before the fix this path threw inside the WebSocket upgrade and killed Razor.
//
// Start Razor with --bypass-gate, then pass the single-use start URL here
// (RAZOR_START_URL); this script exchanges it for the session cookie and opens
// the terminal WebSocket the same way the browser does.
import { WebSocket } from 'ws';
import { setTimeout as delay } from 'node:timers/promises';

const origin = process.env.RAZOR_ORIGIN;
const startUrl = process.env.RAZOR_START_URL;
if (!origin || !startUrl) {
  console.error('set RAZOR_ORIGIN=http://127.0.0.1:<port> and RAZOR_START_URL=<single-use url>');
  process.exit(2);
}
const port = new URL(origin).port;

// Exchange the bootstrap code for the session cookie.
const handshake = await fetch(startUrl, { redirect: 'manual' });
const setCookie = handshake.headers.get('set-cookie') ?? '';
const cookie = setCookie.split(';')[0];
console.log('bootstrap exchange:', handshake.status, cookie ? `cookie ${cookie.split('=')[0]} set` : 'NO COOKIE');
if (!cookie) {
  console.error('cannot continue without a session cookie');
  process.exit(2);
}

const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/terminal`, {
  headers: { origin, cookie },
});

let sawOutput = false;
let dataFrames = 0;
ws.on('message', (raw) => {
  const text = raw.toString('utf8');
  if (text.startsWith('{') && text.includes('"type":"data"')) dataFrames += 1;
});

let first = null;
ws.on('message', (raw) => {
  const text = raw.toString('utf8');
  if (!first) {
    first = JSON.parse(text);
    console.log('first frame:', JSON.stringify(first));
    if (first.type === 'ready') {
      // Give the shell a moment to finish starting before typing at it.
      setTimeout(() => {
        ws.send(Buffer.from(process.platform === 'win32' ? 'echo pty-is-alive\r\n' : 'echo pty-is-alive\n'));
      }, 1200);
    }
    return;
  }
  if (text.includes('pty-is-alive')) {
    sawOutput = true;
    console.log('PTY echoed our command back: interactive shell confirmed');
    ws.close();
  }
});
ws.on('close', (code) => console.log('terminal socket closed:', code));
ws.on('error', (err) => console.log('terminal socket error:', err.message));

await delay(10000);

// The server must still be answering after that.
try {
  const res = await fetch(`${origin}/healthz`);
  console.log('healthz after terminal attempt:', res.status, await res.text());
} catch (err) {
  console.log('healthz FAILED (server died):', err.message);
  process.exitCode = 1;
}
console.log('data frames received from the PTY:', dataFrames);
console.log(sawOutput ? 'RESULT: interactive PTY working' : `RESULT: no shell echo; first frame was ${first?.type ?? 'none'}, data frames ${dataFrames}`);

// A live PTY keeps the event loop (and the shell it spawned) alive, so exit
// explicitly rather than waiting for Node to drain.
ws.terminate();
process.exit(sawOutput ? 0 : 1);
