#!/usr/bin/env node
// Export the isolated Razor workspace to a target folder or zip file.
// Can be run after an exam/isolation period to recover or archive candidate work.
import { existsSync, mkdirSync, writeFileSync, copyFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROOT, readEnv, workspaceDir } from '../src/config.mjs';
import { Workspace, unprotectIsolatedFolder } from '../src/files.mjs';
import { createZip } from '../src/zip.mjs';

const args = process.argv.slice(2);
const env = readEnv();
const root = workspaceDir(env);
const workspace = new Workspace(root);

const target = args[0] ? resolve(args[0]) : join(ROOT, `workspace-export-${Date.now()}`);

console.log(`\n=== Razor Workspace Exporter ===`);
console.log(`Source (isolated): ${workspace.root}`);

const files = workspace.getAllFiles();
console.log(`Found ${files.length} file(s) in workspace.`);

if (args.includes('--unhide')) {
  unprotectIsolatedFolder(workspace.root);
  console.log(`Removed System and Hidden attributes from: ${workspace.root}`);
}

if (target.endsWith('.zip')) {
  const zipBuffer = createZip(files);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, zipBuffer);
  console.log(`Exported archive: ${target} (${(zipBuffer.length / 1024).toFixed(1)} kB)`);
} else {
  mkdirSync(target, { recursive: true });
  for (const file of files) {
    const dest = join(target, file.name);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, file.data);
  }
  console.log(`Exported all files to: ${target}`);
}

console.log(`Export completed successfully.\n`);
