import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createZip, crc32 } from '../src/zip.mjs';

test('crc32 produces correct checksum for known strings', () => {
  const buf = Buffer.from('123456789', 'utf8');
  assert.equal(crc32(buf), 0xcbf43926);
});

test('createZip produces a valid zip extractable by powershell Expand-Archive', () => {
  const zip = createZip([
    { name: 'hello.py', data: 'print("hello")\n' },
    { name: 'nested/app.js', data: 'console.log("world");\n' },
  ]);

  assert.ok(zip.length > 0);
  assert.equal(zip.subarray(0, 4).toString('hex'), '504b0304'); // PK\x03\x04

  const tmpZip = join(process.cwd(), 'run', 'test_sample.zip');
  const tmpOut = join(process.cwd(), 'run', 'test_unzip');
  mkdirSync(join(process.cwd(), 'run'), { recursive: true });
  writeFileSync(tmpZip, zip);

  if (process.platform === 'win32') {
    if (existsSync(tmpOut)) rmSync(tmpOut, { recursive: true, force: true });
    execFileSync('powershell', ['-Command', `Expand-Archive -Path '${tmpZip}' -DestinationPath '${tmpOut}' -Force`]);

    assert.equal(readFileSync(join(tmpOut, 'hello.py'), 'utf8'), 'print("hello")\n');
    assert.equal(readFileSync(join(tmpOut, 'nested', 'app.js'), 'utf8'), 'console.log("world");\n');

    rmSync(tmpOut, { recursive: true, force: true });
    rmSync(tmpZip, { force: true });
  }
});
