import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { isControllerDevRuntime, resolveControllerDirs } from '../dev-paths.js';

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
  if (process.env.AXONWALL_STATE_FILE) {
    return `${process.env.AXONWALL_STATE_FILE}.lock`;
  }
  if (process.env.AXONWALL_STATE_JSON_PATH) {
    return `${process.env.AXONWALL_STATE_JSON_PATH}.lock`;
  }
  const configDir = process.env.AXONWALL_CONFIG_DIR || process.env.AXONWALL_ETC_DIR;
  if (configDir) {
    return path.join(configDir, 'state.json.lock');
  }
  const stateDir = process.env.AXONWALL_STATE_DIR?.trim();
  if (stateDir) {
    return path.join(stateDir, 'state.json.lock');
  }
  if (isControllerDevRuntime()) {
    return path.join(resolveControllerDirs().etcDir, 'state.json.lock');
  }
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
  let warnedLiveHolder = false;
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o660);
      // B2-L8: the release used to unlink lockPath unconditionally,
      // so a slow holder past the stale threshold could unlink the
      // lock a second holder had just acquired, admitting two
      // holders at once. The lock file now carries a unique token
      // for this acquisition, and release unlinks only if the file
      // on disk still carries our token (compare-and-delete).
      const token = `${process.pid}:${Date.now()}:${crypto.randomBytes(8).toString('hex')}`;
      try {
        fs.writeFileSync(
          fd,
          JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString(), token })
        );
      } catch {
        // Lock content is diagnostic only.
      }
      let released = false;
      // R4-B-L6: the lock used to infer staleness from file mtime
      // alone, and mtime only advanced at acquisition — so a
      // live-but-slow holder (large state.json, slow disk) past the
      // threshold looked exactly like a dead holder, and a waiter
      // unlinked the lock and admitted a second holder. The holder
      // now heartbeats: it refreshes the lockfile mtime while it
      // holds the lock, so a live holder never looks stale. The
      // beat stops (and never throws) if the file no longer carries
      // our token, i.e. we no longer own the lock.
      const heartbeatMs = Math.max(250, Math.min(2000, Math.floor(staleThresholdMs / 3)));
      const heartbeat = setInterval(() => {
        try {
          const raw = fs.readFileSync(lockPath, 'utf8');
          if (JSON.parse(raw)?.token !== token) {
            clearInterval(heartbeat);
            return;
          }
          fs.utimesSync(lockPath, new Date(), new Date());
        } catch {
          // A failed beat must never throw out of the holder; the
          // next beat retries, and the waiter still needs the pid
          // to be dead before breaking (see below).
        }
      }, heartbeatMs);
      if (typeof heartbeat === 'object' && heartbeat !== null && typeof (heartbeat as any).unref === 'function') {
        (heartbeat as any).unref();
      }
      return () => {
        if (released) return;
        released = true;
        try {
          clearInterval(heartbeat);
        } catch {}
        try {
          fs.closeSync(fd);
        } catch {}
        try {
          const raw = fs.readFileSync(lockPath, 'utf8');
          const parsed = JSON.parse(raw);
          if (parsed?.token !== token) {
            // Another holder owns the lock at this path now; our
            // unlink would remove theirs. Leave it in place.
            console.warn(
              `[MCP Lock] Not unlinking ${lockPath}: lock is now held by another owner (expected our token, found a different one).`
            );
            return;
          }
          fs.unlinkSync(lockPath);
        } catch {
          // Lock already gone, or unreadable: nothing to unlink.
        }
      };
    } catch (err: any) {
      if (err?.code !== 'EEXIST') throw err;
      // Lock is held. Break it only when the holder is actually
      // gone: R4-B-L6 — mtime staleness alone is NOT enough, because
      // a live-but-slow holder (or one whose heartbeat is briefly
      // delayed) has a stale mtime while still holding the lock.
      // A live holder pid vetoes the break; the waiter keeps waiting
      // until its own deadline and then fails closed (timeout)
      // instead of admitting a second holder. A pid that cannot be
      // determined (empty/unparseable lock file) still breaks on
      // mtime alone, as before.
      let stale = false;
      let holderPid: number | null = null;
      let holderPidAlive: boolean | null = null;
      let observedMtimeMs = 0;
      try {
        const stat = fs.statSync(lockPath);
        observedMtimeMs = stat.mtimeMs;
        const mtimeStale = Date.now() - stat.mtimeMs > staleThresholdMs;
        if (stat.size > 0) {
          const raw = fs.readFileSync(lockPath, 'utf8');
          const parsed = JSON.parse(raw);
          if (typeof parsed?.pid === 'number' && parsed.pid > 0 && parsed.pid !== process.pid) {
            holderPid = parsed.pid;
            try {
              process.kill(parsed.pid, 0);
              holderPidAlive = true;
            } catch (killErr: any) {
              if (killErr?.code === 'ESRCH') {
                holderPidAlive = false;
              } else {
                // EPERM (or any other error): the process exists
                // but cannot be signalled — treat it as alive.
                holderPidAlive = true;
              }
            }
          }
        }
        // Break immediately when a non-self holder PID is confirmed dead (ESRCH);
        // keep mtimeStale for unparseable/empty lockfiles without a holder PID.
        stale =
          (holderPid !== null && holderPidAlive === false) ||
          (mtimeStale && holderPid === null);
        if (mtimeStale && holderPid !== null && holderPidAlive === true && !warnedLiveHolder) {
          warnedLiveHolder = true;
          console.warn(
            `[MCP Lock] Lock ${lockPath} looks mtime-stale (${Math.round((Date.now() - observedMtimeMs) / 1000)}s old) but holder pid ${holderPid} is still alive; not breaking it.`
          );
        }
      } catch {
        // Lock vanished or unreadable between attempts; retry below.
      }
      if (stale) {
        // B2-L8: re-verify the lock is still the same stale one
        // before breaking it — a fresh holder may have acquired it
        // since we read it. Re-check the pid liveness too: a holder
        // that came alive (or a new holder with a live pid) since
        // the first read vetoes the break.
        let stillStale = true;
        try {
          const restat = fs.statSync(lockPath);
          if (restat.mtimeMs !== observedMtimeMs) stillStale = false;
          if (stillStale && holderPid !== null && restat.size > 0) {
            const raw = fs.readFileSync(lockPath, 'utf8');
            const parsed = JSON.parse(raw);
            if (parsed?.pid !== holderPid) stillStale = false;
            if (stillStale && typeof parsed?.pid === 'number' && parsed.pid > 0 && parsed.pid !== process.pid) {
              try {
                process.kill(parsed.pid, 0);
                stillStale = false;
              } catch (killErr: any) {
                if (killErr?.code !== 'ESRCH') stillStale = false;
              }
            }
          }
        } catch {
          // Lock vanished; retry below.
          stillStale = false;
        }
        if (stillStale) {
          try {
            fs.unlinkSync(lockPath);
          } catch {}
        }
        continue;
      }
      if (Date.now() >= deadline) {
        throw new Error(`timed out waiting for lock ${lockPath} after ${timeoutMs}ms`);
      }
      Atomics.wait(waiter, 0, 0, 5);
    }
  }
}
