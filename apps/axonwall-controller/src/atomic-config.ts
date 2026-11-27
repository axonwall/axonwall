import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

// R4-B-M1: one canonical path per config. Several controller configs
// (mcp-keys.json, mcp-settings.json, state.json, synced-routes.json)
// used to exist as mirrors in two or three directories, with reads
// taking the first file that parsed and writes fanning out with a
// silent catch per path. A failed primary write (or a missing/corrupt
// primary) let a stale mirror defeat a revocation, a disable, or a
// state load while the operator's command reported success.
//
// The rules, implemented here and used by every reader/writer:
//   - ONE canonical path per config (env override wins when set).
//     All reads and writes go through it.
//   - Writes are atomic (write-temp + rename) and THROW when the
//     canonical write fails. Mirrors are written best-effort AFTER
//     the canonical write succeeds, and a failed mirror write is
//     logged loudly, never swallowed.
//   - Reads never prefer a mirror over the canonical file. The one
//     exception is migration: when the canonical file does not exist
//     at all, the newest parseable mirror is adopted INTO the
//     canonical path (atomic write, loud warning) so pre-existing
//     installs whose only copy lives on a mirror do not lose their
//     keys/state on upgrade. A canonical file that exists but is
//     unreadable or corrupt is NEVER fallen back past: the load fails
//     closed (null) with a loud error, because a corrupt canonical
//     plus a valid-but-older mirror is exactly the revocation
//     defeat this fix closes.

/** Atomic write: temp file in the same directory + rename. Throws on failure. */
export function writeFileAtomicSync(filePath: string, data: string, mode = 0o660): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o775 });
  const tmpPath = `${filePath}.tmp.${process.pid}.${crypto.randomUUID()}`;
  try {
    fs.writeFileSync(tmpPath, data, { mode });
    try {
      fs.chmodSync(tmpPath, mode);
    } catch {
      // chmod is best-effort; the rename still lands the content.
    }
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      // Temp file may never have been created.
    }
    throw err;
  }
}

export interface CanonicalConfigRead<T> {
  canonicalPath: string;
  mirrorPaths: string[];
  /** Parse raw file text; return null when the content is not usable. */
  parse: (raw: string) => T | null;
  /** Human label for log lines, e.g. 'mcp-keys.json'. */
  label: string;
  /** File permissions used when adopting a mirror into canonicalPath (defaults to 0o600). */
  mode?: number;
}

/**
 * Read a config from its canonical path only. When the canonical
 * file is missing, adopt the newest parseable mirror into it (see
 * the module comment). When the canonical file exists but cannot be
 * read or parsed, log loudly and return null — never a mirror.
 */
export function readCanonicalConfig<T>(opts: CanonicalConfigRead<T>): T | null {
  const { canonicalPath, mirrorPaths, parse, label } = opts;
  if (fs.existsSync(canonicalPath)) {
    try {
      const parsed = parse(fs.readFileSync(canonicalPath, 'utf8'));
      if (parsed !== null) return parsed;
      console.error(
        `[Config] ${label}: canonical file ${canonicalPath} is present but unusable; refusing to fall back to a mirror (a stale mirror must never defeat a revocation or disable).`
      );
      return null;
    } catch (err: any) {
      console.error(
        `[Config] ${label}: cannot read canonical file ${canonicalPath} (${err?.message || err}); refusing to fall back to a mirror.`
      );
      return null;
    }
  }
  // Canonical is missing: adopt the newest parseable mirror, if any.
  // The raw mirror bytes are copied verbatim (not re-serialized from
  // the parsed value) so adoption never normalizes away content.
  let newest: { value: T; raw: string; mtimeMs: number; source: string } | null = null;
  for (const mirror of mirrorPaths) {
    if (mirror === canonicalPath) continue;
    try {
      if (!fs.existsSync(mirror)) continue;
      const raw = fs.readFileSync(mirror, 'utf8');
      const value = parse(raw);
      if (value === null) continue;
      const mtimeMs = fs.statSync(mirror).mtimeMs;
      if (!newest || mtimeMs > newest.mtimeMs) newest = { value, raw, mtimeMs, source: mirror };
    } catch {
      // Unreadable mirror: skip it.
    }
  }
  if (!newest) return null;
  console.warn(
    `[Config] ${label}: canonical file ${canonicalPath} is missing; adopting the newest mirror copy (${newest.source}) as the canonical file. ` +
      `Mirror copies are migration-only from here on: all reads and writes go through the canonical path.`
  );
  const adoptMode = opts.mode ?? 0o600;
  try {
    writeFileAtomicSync(canonicalPath, newest.raw, adoptMode);
  } catch (err: any) {
    console.error(
      `[Config] ${label}: could not adopt mirror ${newest.source} into canonical path ${canonicalPath} (${err?.message || err}); ` +
        `using the mirror content for this load only — the next load will re-adopt.`
    );
  }
  return newest.value;
}

export interface CanonicalConfigWrite {
  canonicalPath: string;
  mirrorPaths: string[];
  serialized: string;
  mode?: number;
  label: string;
}

/**
 * Write a config to its canonical path atomically, then best-effort
 * to the mirrors. Throws when the canonical write fails. Returns the
 * mirrors that failed (each already logged loudly).
 */
export function writeCanonicalConfig(opts: CanonicalConfigWrite): { failedMirrors: string[] } {
  const { canonicalPath, mirrorPaths, serialized, mode = 0o660, label } = opts;
  try {
    writeFileAtomicSync(canonicalPath, serialized, mode);
  } catch (err: any) {
    throw new Error(
      `Failed to persist ${label} to canonical path ${canonicalPath}: ${err?.message || err}. ` +
        `Nothing was written; the change did NOT land.`
    );
  }
  const failedMirrors: string[] = [];
  for (const mirror of mirrorPaths) {
    if (mirror === canonicalPath) continue;
    try {
      writeFileAtomicSync(mirror, serialized, mode);
    } catch (err: any) {
      failedMirrors.push(mirror);
      console.warn(
        `[Config] ${label}: mirror write to ${mirror} failed (${err?.message || err}) after the canonical write succeeded. ` +
          `The canonical file is authoritative; repair or remove the stale mirror.`
      );
    }
  }
  return { failedMirrors };
}
