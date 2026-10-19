#!/usr/bin/env node
// Mock control plane: the smallest server satisfying the heartbeat contract
// Razor expects, so the outbound admin channel can be exercised end to end
// without lab-agent.
//
//   node tools/fake-admin.mjs [--port 8443] [--start-after 3]
//
//   POST /heartbeat   -> { lease: { renew: true } }
//   GET  /commands    -> { commands: [...], cursor }
//   GET  /state       -> what Razor has reported
//
// `--start-after N` queues a start_session command on the Nth heartbeat, which
// is how you watch the whole flow: heartbeat -> lease -> .seb -> SEB launch.
import { createServer } from 'node:http';

const args = process.argv.slice(2);
const port = Number(args[args.indexOf('--port') + 1] ?? process.env.PORT ?? 8443);
const startAfter = Number(args[args.indexOf('--start-after') + 1] ?? 0) || 0;

let heartbeats = 0;
let cursor = 0;
const pending = [];
const seen = [];

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const send = (status, payload) => {
    res.statusCode = status;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(payload));
  };

  if (req.method === 'GET' && url.pathname === '/commands') {
    return send(200, { commands: pending.splice(0, pending.length), cursor });
  }

  if (req.method === 'POST' && url.pathname === '/heartbeat') {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      heartbeats += 1;
      let report = null;
      try {
        report = JSON.parse(raw);
      } catch {
        /* tolerate a malformed body; the point is to count round trips */
      }
      seen.push({ at: new Date().toISOString(), gateState: report?.gateState, seb: report?.seb });
      console.log(
        `#${String(heartbeats).padStart(3)} ${report?.hostname ?? '?'} gate=${
          report?.gateState ?? '?'
        } seb=${report?.seb?.running ? `running(${report.seb.version})` : 'no'}`,
      );

      if (startAfter && heartbeats === startAfter) {
        cursor += 1;
        pending.push({
          id: `cmd-${cursor}`,
          kind: 'start_session',
          issuedBy: 'fake-admin',
          issuedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
          // Deliberately unsigned: Razor records this as weaker provenance.
          // A real deployment sends a signed grant here instead.
        });
        console.log('    -> queued start_session (unsigned)');
      }

      return send(200, {
        lease: { renew: true, leaseMs: 60_000, graceMs: 60_000 },
        serverTime: new Date().toISOString(),
      });
    });
    return undefined;
  }

  if (req.method === 'GET' && req.url === '/state') {
    return send(200, { heartbeats, commands: cursor, seen });
  }

  return send(404, { error: 'not-found', path: url.pathname });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`fake control plane on http://127.0.0.1:${port}`);
  console.log('  POST /heartbeat   heartbeat + lease renewal');
  console.log('  GET  /commands    pending commands');
  console.log('  GET  /state       what Razor has reported');
  if (startAfter) console.log(`  will queue start_session on heartbeat #${startAfter}`);
});
