// Test helper (not a test file): holds the MCP DesiredState lock
// until killed, WITHOUT touching the lockfile. The built-in
// heartbeat in acquireMcpLockFile is what keeps the lock fresh now
// (R4-B-L6); this helper stands in for a live-but-slow holder (e.g.
// a slow DesiredState persist) while a waiter tries to acquire the
// same lock. The lock path comes from
// AXONWALL_DESIRED_STATE_LOCK_PATH, exactly as the MCP propose path
// resolves it. HOLD_MS controls how long the lock is held
// (default 13000); the process exits 0 after releasing, or on
// SIGTERM after releasing.
import { acquireMcpLockFile, desiredStateLockPath } from '../dist/index.js';

const lockPath = desiredStateLockPath();
const holdMs = Number(process.env.HOLD_MS || '13000');
const release = acquireMcpLockFile(lockPath);
console.log(`holding ${lockPath} pid=${process.pid} for ${holdMs}ms`);
setTimeout(() => {
  console.log('releasing');
  release();
  process.exit(0);
}, holdMs);
process.on('SIGTERM', () => {
  release();
  process.exit(0);
});
