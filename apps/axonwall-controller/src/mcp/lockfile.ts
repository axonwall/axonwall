import * as fs from 'node:fs';
import * as path from 'node:path';

// B2-M4: the lockfile path for DesiredState mutation. The lock
// must be one path for every process sharing the state files (the
// HTTP controller, the stdio MCP server, axonwallctl, and the TUI).
// Prefer the primary state dir when it exists; the lock helper
// creates the lock dir itself, so only the choice needs to be
// deterministic across processes. AXONWALL_DESIRED_STATE_LOCK_PATH
// overrides the path (tests); it lives here, next to the lock
// itself, so the CLI and TUI can import the lock and its path from
// this one tiny module instead of the whole MCP server.
export function desiredStateLockPath(): string {
  const override = process.env.AXONWALL_DESIRED_STATE_LOCK_PATH;
  if (override) return override;
  return fs.existsSync('/etc/axonwall') ? '/etc/axonwall/state.json.lock' : '/var/lib/axonwall/state.json.lock';
}

export function acquireMcpLockFile(lockPath: string, timeoutMs = 10000): () => void {
  const deadline = Date.now() + timeoutMs;
  const staleThresholdMs = Math.min(Math.max(1000, timeoutMs - 500), 10000);
  const waiter = new Int32Array(new SharedArrayBuffer(4));
  const lockDir = path.dirname(lockPath);
  if (!fs.existsSync(lockDir)) {
    fs.mkdirSync(lockDir, { recursive: true, mode: 0o775 });
  }
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o660);
      try {
        fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }));
      } catch {
        // Lock content is diagnostic only.
      }
      let released = false;
      return () => {
        if (released) return;
        released = true;
        try {
          fs.closeSync(fd);
        } catch {}
        try {
          fs.unlinkSync(lockPath);
        } catch {}
      };
    } catch (err: any) {
      if (err?.code !== 'EEXIST') throw err;
      // Lock is held. Break it if the holder died holding it or exceeded staleThresholdMs.
      let stale = false;
      try {
        const stat = fs.statSync(lockPath);
        stale = Date.now() - stat.mtimeMs > staleThresholdMs;
        if (!stale && stat.size > 0) {
          const raw = fs.readFileSync(lockPath, 'utf8');
          const parsed = JSON.parse(raw);
          if (typeof parsed?.pid === 'number' && parsed.pid > 0 && parsed.pid !== process.pid) {
            try {
              process.kill(parsed.pid, 0);
            } catch (killErr: any) {
              if (killErr?.code === 'ESRCH') {
                stale = true;
              }
            }
          }
        }
      } catch {
        // Lock vanished or unreadable between attempts; retry below.
      }
      if (stale) {
        try {
          fs.unlinkSync(lockPath);
        } catch {}
        continue;
      }
      if (Date.now() >= deadline) {
        throw new Error(`timed out waiting for lock ${lockPath} after ${timeoutMs}ms`);
      }
      Atomics.wait(waiter, 0, 0, 5);
    }
  }
}
