import * as fs from 'node:fs';

/**
 * Acquire an exclusive lockfile with O_CREAT|O_EXCL, returning a
 * release function. Used to serialise the MCP key-file and audit-log
 * read-modify-write sequences across processes (B-S1, B-S2): the HTTP
 * controller and the stdio MCP server both mutate these files, and
 * without a lock a concurrent writer could resurrect a revoked key
 * or fork the audit hash chain.
 *
 * The wait is synchronous (Atomics.wait — available on the Node main
 * thread) because all callers are synchronous file operations. A lock
 * older than 30s is treated as stale (crashed holder) and broken.
 * Throws on timeout so the caller can decide: key mutations fail
 * loudly rather than silently losing an update, while the audit
 * writer skips the append to preserve chain integrity.
 */
export function acquireMcpLockFile(lockPath: string, timeoutMs = 10000): () => void {
  const deadline = Date.now() + timeoutMs;
  const waiter = new Int32Array(new SharedArrayBuffer(4));
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
      // Lock is held. Break it if the holder died holding it.
      let stale = false;
      try {
        const stat = fs.statSync(lockPath);
        stale = Date.now() - stat.mtimeMs > 30000;
      } catch {
        // Lock vanished between attempts; retry below.
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
