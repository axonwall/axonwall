// Test helper (not a test file): holds the MCP DesiredState lock
// until killed, touching the lockfile so it stays fresh. Spawned by
// mcp-lock-batch2-followup.test.js to stand in for a concurrent MCP
// propose (or CLI apply) holding the lock while the TUI tries to
// save. The lock path comes from AXONWALL_DESIRED_STATE_LOCK_PATH,
// exactly as the MCP propose path resolves it.
import fs from 'node:fs';
import { acquireMcpLockFile, desiredStateLockPath } from '../dist/index.js';

const lockPath = desiredStateLockPath();
const release = acquireMcpLockFile(lockPath);
setInterval(() => {
  try { fs.utimesSync(lockPath, new Date(), new Date()); } catch {}
}, 500);
console.log(`holding ${lockPath}`);
process.on('SIGTERM', () => {
  release();
  process.exit(0);
});
