// Regression test for the SEB state handed to the HTTP API.
//
// The bug: main.mjs gives RazorServer the SEB controller's *live* state object
// (`sebState: seb.publicState`), and setSebState() then did
//
//     this.#sebState.public = publicState     // == this.#sebState itself
//
// making that object self-referential. /api/state and /admin/status serialise it,
// so the instant SEB reported itself launched every response died with
// "TypeError: Converting circular structure to JSON" -- observed live, once every
// 3 seconds for the whole session, on the endpoint the IDE polls for its status.
//
// These tests drive the real server over real HTTP, because the failure mode was
// serialisation, not logic.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RazorServer } from '../src/server.mjs';

/** The shape SebController.publicState has when SEB is running. */
function liveSebPublicState() {
  return {
    running: true,
    pid: 4242,
    version: '3.10.2.920',
    binary: 'C:\\Program Files\\SafeExamBrowser\\Application\\SafeExamBrowser.exe',
    binarySha256: null,
    configPath: 'C:\\Exam\\razor.seb',
    configPrefix: 'plnd',
    configKeyHash: 'a'.repeat(64),
    attestation: 'config-key-computed',
    lastExit: null,
  };
}

function stubGate(session = null) {
  return {
    audit: { record() {} },
    session,
    state: 'running',
    describe: () => ({ state: 'running', session: null }),
  };
}

async function withServer(fn) {
  const server = new RazorServer({
    env: { mode: 'dev', ui: 'dev', host: '127.0.0.1', port: 0 },
    gate: stubGate(),
    workspace: {},
    terminal: {},
    credentials: { ok: true },
    sebState: {},
  });
  await server.listen({ host: '127.0.0.1', port: 0 });
  try {
    return await fn(server);
  } finally {
    await server.close();
  }
}

async function getJson(server, path) {
  const response = await fetch(`${server.origin}${path}`, {
    headers: { host: `127.0.0.1:${server.port}` },
  });
  const text = await response.text();
  return { status: response.status, text, json: JSON.parse(text) };
}

test('a live SEB state object does not make /api/state unserialisable', async () => {
  await withServer(async (server) => {
    const publicState = liveSebPublicState();
    server.setSebState(publicState, publicState.configKeyHash);

    const { status, json } = await getJson(server, '/api/state');

    assert.equal(status, 200);
    assert.equal(json.seb.running, true, 'the SEB state must survive into the response');
    assert.equal(json.seb.pid, 4242);
    assert.equal(json.seb.configKeyHash, publicState.configKeyHash);
  });
});

test('setSebState never turns the caller\'s object into a cycle', async () => {
  await withServer(async (server) => {
    const publicState = liveSebPublicState();
    server.setSebState(publicState, 'abc');

    // The exact corruption that broke the endpoint.
    assert.notEqual(publicState.public, publicState, 'publicState must not reference itself');
    assert.equal(
      Object.prototype.hasOwnProperty.call(publicState, 'public'),
      false,
      'setSebState must not write a .public property onto the controller state',
    );
    assert.equal(server.expectedConfigKeyHash, 'abc');
  });
});

test('/admin/status also survives a live SEB state object', async () => {
  await withServer(async (server) => {
    const publicState = liveSebPublicState();
    server.setSebState(publicState, publicState.configKeyHash);

    // No credentials -> 401, but it must not be a 500 from a circular throw.
    const response = await fetch(`${server.origin}/admin/status`, {
      headers: { host: `127.0.0.1:${server.port}` },
    });
    assert.notEqual(response.status, 500, 'circular serialisation must not 500 the admin surface');
  });
});

test('SEB state is null before any config is generated', async () => {
  await withServer(async (server) => {
    const { status, json } = await getJson(server, '/api/state');
    assert.equal(status, 200);
    assert.equal(json.seb, null);
    assert.equal(server.expectedConfigKeyHash, null);
  });
});
