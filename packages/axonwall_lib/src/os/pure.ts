export type OsFamily = 'arch' | 'debian' | 'alpine';

export interface ParsedOsRelease {
  id: string;
  idLike: string[];
  name?: string;
  prettyName?: string;
  versionId?: string;
}

export interface OsReleaseInfo extends ParsedOsRelease {
  family: OsFamily;
  isDerivative: boolean;
}

export interface OvmfCandidate {
  code: string;
  vars: string;
  secboot: boolean;
}

/**
 * Canonical distro unit aliases shared by the UI, compiler, and Go daemon.
 */
export const SERVICE_UNIT_CANDIDATES: Readonly<Record<string, readonly string[]>> = {
  smbd: ['smbd', 'smb'],
  smb: ['smb', 'smbd'],
  nmbd: ['nmbd', 'nmb'],
  nmb: ['nmb', 'nmbd'],
  'kea-dhcp4-server': ['kea-dhcp4-server', 'kea-dhcp4'],
  'kea-dhcp4': ['kea-dhcp4', 'kea-dhcp4-server'],
  'kea-dhcp6-server': ['kea-dhcp6-server', 'kea-dhcp6'],
  'kea-dhcp6': ['kea-dhcp6', 'kea-dhcp6-server'],
  'kea-dhcp-ddns-server': ['kea-dhcp-ddns-server', 'kea-dhcp-ddns'],
  'kea-dhcp-ddns': ['kea-dhcp-ddns', 'kea-dhcp-ddns-server'],
  chrony: ['chrony', 'chronyd'],
  chronyd: ['chronyd', 'chrony'],
  freeradius: ['freeradius', 'radiusd'],
  radiusd: ['radiusd', 'freeradius'],
  'rtslib-fb-targetctl': ['rtslib-fb-targetctl', 'target'],
  target: ['target', 'rtslib-fb-targetctl'],
  'nut-client': ['nut-client', 'nut-monitor'],
  'nut-monitor': ['nut-monitor', 'nut-client'],
  ssh: ['ssh', 'sshd'],
  sshd: ['sshd', 'ssh'],
  'nfs-kernel-server': ['nfs-kernel-server', 'nfs-server'],
  'nfs-server': ['nfs-server', 'nfs-kernel-server'],
};

/**
 * Ordered OVMF firmware pairs across Arch Linux (`edk2-ovmf`), Alpine, and Debian/Ubuntu.
 */
export const OVMF_FIRMWARE_CANDIDATES: readonly OvmfCandidate[] = [
  // Arch Linux standard edk2-ovmf paths
  {
    code: '/usr/share/edk2/x64/OVMF_CODE.4m.fd',
    vars: '/usr/share/edk2/x64/OVMF_VARS.4m.fd',
    secboot: false,
  },
  {
    code: '/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd',
    vars: '/usr/share/edk2/x64/OVMF_VARS.4m.fd',
    secboot: true,
  },
  {
    code: '/usr/share/OVMF/x64/OVMF_CODE.4m.fd',
    vars: '/usr/share/OVMF/x64/OVMF_VARS.4m.fd',
    secboot: false,
  },
  {
    code: '/usr/share/OVMF/x64/OVMF_CODE.secboot.4m.fd',
    vars: '/usr/share/OVMF/x64/OVMF_VARS.4m.fd',
    secboot: true,
  },
  // Debian / Ubuntu OVMF paths
  {
    code: '/usr/share/OVMF/OVMF_CODE_4M.fd',
    vars: '/usr/share/OVMF/OVMF_VARS_4M.fd',
    secboot: false,
  },
  {
    code: '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
    vars: '/usr/share/OVMF/OVMF_VARS_4M.fd',
    secboot: true,
  },
  {
    code: '/usr/share/OVMF/OVMF_CODE.fd',
    vars: '/usr/share/OVMF/OVMF_VARS.fd',
    secboot: false,
  },
  // Alpine / generic fallback
  {
    code: '/usr/share/edk2/ovmf/OVMF_CODE.fd',
    vars: '/usr/share/edk2/ovmf/OVMF_VARS.fd',
    secboot: false,
  },
];

/**
 * Known Kea High Availability hook shared-object locations by Linux distro & architecture.
 */
export const KEA_HA_HOOK_CANDIDATES: readonly string[] = [
  '/usr/lib/kea/hooks/libdhcp_ha.so',
  '/usr/lib64/kea/hooks/libdhcp_ha.so',
  '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so',
  '/usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp_ha.so',
];

function stripQuotes(raw: string): string {
  const trimmed = raw.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/**
 * Parses `/etc/os-release` key=value text into structured fields.
 */
export function parseOsRelease(content: string): ParsedOsRelease {
  const result: ParsedOsRelease = {
    id: 'linux',
    idLike: [],
  };

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eqIdx = line.indexOf('=');
    if (eqIdx <= 0) continue;
    const key = line.slice(0, eqIdx).trim();
    const val = stripQuotes(line.slice(eqIdx + 1));

    switch (key) {
      case 'ID':
        if (val) result.id = val.toLowerCase();
        break;
      case 'ID_LIKE':
        result.idLike = val
          .toLowerCase()
          .split(/\s+/)
          .filter(Boolean);
        break;
      case 'NAME':
        if (val) result.name = val;
        break;
      case 'PRETTY_NAME':
        if (val) result.prettyName = val;
        break;
      case 'VERSION_ID':
        if (val) result.versionId = val;
        break;
    }
  }

  return result;
}

/**
 * Classifies a parsed os-release payload into an OS family, treating
 * Arch derivatives such as Omarchy (`ID=omarchy`, `ID_LIKE=arch`) as `'arch'`.
 */
export function classifyOsFamily(
  parsed: ParsedOsRelease,
  flags: { hasArchRelease?: boolean; hasAlpineRelease?: boolean } = {},
): OsFamily {
  const id = parsed.id.toLowerCase();
  if (id === 'arch' || parsed.idLike.includes('arch') || flags.hasArchRelease) {
    return 'arch';
  }
  if (id === 'alpine' || parsed.idLike.includes('alpine') || flags.hasAlpineRelease) {
    return 'alpine';
  }
  return 'debian';
}

/**
 * Returns the first candidate path accepted by `existsFn`, or `null` if no probe function is given or none match.
 */
export function resolveFirstExistingPathPure(
  candidates: readonly string[],
  existsFn?: (p: string) => boolean,
): string | null {
  if (!existsFn) return null;
  for (const candidate of candidates) {
    try {
      if (existsFn(candidate)) return candidate;
    } catch {
      // Ignore permission errors probing candidate paths
    }
  }
  return null;
}

/**
 * Pure isomorphic resolver for the best OVMF firmware pair (probes only when `existsFn` is supplied).
 */
export function resolveOvmfFirmwarePure(
  options: {
    secureBoot?: boolean;
    osFamily?: OsFamily;
    probeHost?: boolean;
    existsFn?: (p: string) => boolean;
  } = {},
): OvmfCandidate {
  const preferSecboot = Boolean(options.secureBoot);

  if (options.existsFn) {
    const ordered = [...OVMF_FIRMWARE_CANDIDATES].sort((a, b) => {
      if (a.secboot === b.secboot) return 0;
      return a.secboot === preferSecboot ? -1 : 1;
    });

    for (const pair of ordered) {
      try {
        if (options.existsFn(pair.code)) {
          return pair;
        }
      } catch {
        // Ignore probe error
      }
    }
  }

  if (options.osFamily === 'arch') {
    return preferSecboot
      ? OVMF_FIRMWARE_CANDIDATES[1]
      : OVMF_FIRMWARE_CANDIDATES[0];
  }

  // Deterministic Debian defaults (OVMF_CODE.fd for standard, OVMF_CODE_4M.secboot.fd for Secure Boot)
  return preferSecboot
    ? OVMF_FIRMWARE_CANDIDATES[5]
    : OVMF_FIRMWARE_CANDIDATES[6];
}

/**
 * Pure isomorphic resolver for Kea HA hook library path across Arch, Alpine, and Debian/Ubuntu.
 */
export function resolveKeaHaHookPathPure(
  options: {
    osFamily?: OsFamily;
    arch?: string;
    probeHost?: boolean;
    existsFn?: (p: string) => boolean;
  } = {},
): string {
  if (options.existsFn) {
    const found = resolveFirstExistingPathPure(KEA_HA_HOOK_CANDIDATES, options.existsFn);
    if (found) return found;
  }

  if (options.osFamily === 'arch' || options.osFamily === 'alpine') {
    return '/usr/lib/kea/hooks/libdhcp_ha.so';
  }
  if (options.arch === 'arm64' || options.arch === 'aarch64') {
    return '/usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp_ha.so';
  }
  return '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so';
}
