import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  type OsFamily,
  type ParsedOsRelease,
  type OsReleaseInfo,
  type OvmfCandidate,
  SERVICE_UNIT_CANDIDATES,
  OVMF_FIRMWARE_CANDIDATES,
  KEA_HA_HOOK_CANDIDATES,
  parseOsRelease,
  classifyOsFamily,
  resolveFirstExistingPathPure,
  resolveOvmfFirmwarePure,
  resolveKeaHaHookPathPure,
} from './pure.js';

export {
  type OsFamily,
  type ParsedOsRelease,
  type OsReleaseInfo,
  type OvmfCandidate,
  SERVICE_UNIT_CANDIDATES,
  OVMF_FIRMWARE_CANDIDATES,
  KEA_HA_HOOK_CANDIDATES,
  parseOsRelease,
  classifyOsFamily,
};

/**
 * Detects host OS release details from `rootDir` (defaults to `'/'`).
 */
export function detectHostOs(rootDir = '/'): OsReleaseInfo {
  const etcOsRelease = path.join(rootDir, 'etc', 'os-release');
  const usrOsRelease = path.join(rootDir, 'usr', 'lib', 'os-release');
  const archRelease = path.join(rootDir, 'etc', 'arch-release');
  const alpineRelease = path.join(rootDir, 'etc', 'alpine-release');

  let content = '';
  for (const candidate of [etcOsRelease, usrOsRelease]) {
    try {
      content = fs.readFileSync(candidate, 'utf8');
      break;
    } catch {
      // Try next release file
    }
  }

  const parsed = content ? parseOsRelease(content) : { id: 'debian', idLike: [] };
  const hasArchRelease = fs.existsSync(archRelease);
  const hasAlpineRelease = fs.existsSync(alpineRelease);
  const family = classifyOsFamily(parsed, { hasArchRelease, hasAlpineRelease });

  return {
    ...parsed,
    family,
    isDerivative: parsed.id !== family && parsed.id !== 'linux',
  };
}

/**
 * Convenience helper returning just `'arch' | 'debian' | 'alpine'`.
 */
export function detectHostOsFamily(rootDir = '/'): OsFamily {
  return detectHostOs(rootDir).family;
}

/**
 * Returns the first candidate path present on disk, or null if none exist.
 */
export function resolveFirstExistingPath(
  candidates: readonly string[],
  existsFn: (p: string) => boolean = fs.existsSync,
): string | null {
  return resolveFirstExistingPathPure(candidates, existsFn);
}

/**
 * Resolves the best OVMF firmware pair for the current host or fallback family.
 */
export function resolveOvmfFirmware(
  options: {
    secureBoot?: boolean;
    osFamily?: OsFamily;
    probeHost?: boolean;
    existsFn?: (p: string) => boolean;
  } = {},
): OvmfCandidate {
  return resolveOvmfFirmwarePure({
    ...options,
    existsFn: options.existsFn ?? (options.probeHost ? fs.existsSync : undefined),
  });
}

/**
 * Resolves the Kea HA hook library path across Arch, Alpine, and Debian/Ubuntu.
 */
export function resolveKeaHaHookPath(
  options: {
    osFamily?: OsFamily;
    arch?: string;
    probeHost?: boolean;
    existsFn?: (p: string) => boolean;
  } = {},
): string {
  return resolveKeaHaHookPathPure({
    ...options,
    existsFn: options.existsFn ?? (options.probeHost ? fs.existsSync : undefined),
  });
}
