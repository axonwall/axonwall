import { z } from 'zod';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { DesiredStateSchema, inferInterfaceRole, type DesiredState } from '../schemas/index.js';

// ==============================================================================
// 1. Storage & Custom Partitioning Schemas (used during ISO install & cloud init)
// ==============================================================================

export const FilesystemTypeSchema = z.enum(['ext4', 'xfs', 'btrfs']).default('ext4');
export type FilesystemType = z.infer<typeof FilesystemTypeSchema>;

export const PartitionSlotSchema = z.object({
  size_gb: z.number().min(4).default(16),
  filesystem: FilesystemTypeSchema.default('ext4'),
});

export const SwapPartitionSchema = z.object({
  size_gb: z.number().min(0).default(2),
  zram_enabled: z.boolean().default(false),
});

export const DataPartitionSchema = z.object({
  size_gb: z.number().min(2).optional(),
  allocate_remaining: z.boolean().default(false),
  filesystem: FilesystemTypeSchema.default('ext4'),
});

export const LogsPartitionSchema = z.object({
  enabled: z.boolean().default(false),
  size_gb: z.number().min(2).default(10),
  filesystem: FilesystemTypeSchema.default('xfs'),
  mountpoint: z.string().default('/var/log'),
});

export const CustomMountSchema = z.object({
  name: z.string().min(1),
  disk: z.string().optional(),
  size_gb: z.number().min(1),
  filesystem: FilesystemTypeSchema.default('ext4'),
  mountpoint: z.string().min(1),
});

export const SystemRaidSchema = z.object({
  enabled: z.boolean().default(false),
  level: z.enum(['raid1']).default('raid1'),
});

const RFC1123_HOSTNAME = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
const LINUX_USERNAME = /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,31}$/;
const OPENSSH_PUBKEY = /^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+[A-Za-z0-9+/=]+(\s+[^\r\n]*)?$/;

export const EncryptionSchema = z.object({
  enabled: z.boolean().default(false),
  tpm2_auto_unlock: z.boolean().default(false),
  passphrase: z
    .string()
    .refine((s) => !/[\r\n\0]/.test(s), 'Passphrase cannot contain newlines or null bytes')
    .optional(),
  cipher: z.string().default('aes-xts-plain64'),
  key_size: z.number().default(512),
});

export const CloudInitZfsDatasetSchema = z.object({
  name: z.string().min(1),
  mountpoint: z.string().optional(),
  compression: z.string().default('lz4'),
  properties: z.record(z.string(), z.string()).optional(),
});

export const CloudInitZfsStorageSchema = z.object({
  enabled: z.boolean().default(false),
  pool_name: z.string().default('tank'),
  allocate_system_disk_remainder: z.boolean().default(true),
  system_disk_size_gb: z.number().min(0).default(0),
  extra_disks: z.array(z.string()).default([]),
  topology: z
    .enum(['auto', 'stripe', 'mirror', 'raidz1', 'raidz2', 'raidz3', 'draid1', 'draid2'])
    .default('auto'),
  datasets: z.array(CloudInitZfsDatasetSchema).default([]),
});

export const CloudInitStorageSchema = z.object({
  layout_mode: z
    .enum(['standard_ab', 'compact_ab', 'single_root', 'custom'])
    .default('standard_ab'),
  target_disks: z.array(z.string()).min(1).default(['/dev/sda']),
  system_raid: SystemRaidSchema.default(() => ({ enabled: false, level: 'raid1' as const })),
  encryption: EncryptionSchema.default(() => ({
    enabled: false,
    tpm2_auto_unlock: false,
    cipher: 'aes-xts-plain64',
    key_size: 512,
  })),
  partitions: z
    .object({
      efi_size_mb: z.number().min(128).max(4096).default(512),
      slot_a: PartitionSlotSchema.default(() => ({ size_gb: 16, filesystem: 'ext4' as const })),
      slot_b: PartitionSlotSchema.default(() => ({ size_gb: 16, filesystem: 'ext4' as const })),
      swap: SwapPartitionSchema.default(() => ({ size_gb: 2, zram_enabled: false })),
      data: DataPartitionSchema.default(() => ({ allocate_remaining: true, filesystem: 'ext4' as const })),
      logs: LogsPartitionSchema.default(() => ({
        enabled: false,
        size_gb: 10,
        filesystem: 'xfs' as const,
        mountpoint: '/var/log',
      })),
      custom_mounts: z.array(CustomMountSchema).default([]),
    })
    .default(() => ({
      efi_size_mb: 512,
      slot_a: { size_gb: 16, filesystem: 'ext4' as const },
      slot_b: { size_gb: 16, filesystem: 'ext4' as const },
      swap: { size_gb: 2, zram_enabled: false },
      data: { allocate_remaining: true, filesystem: 'ext4' as const },
      logs: { enabled: false, size_gb: 10, filesystem: 'xfs' as const, mountpoint: '/var/log' },
      custom_mounts: [],
    })),
  zfs: CloudInitZfsStorageSchema.default(() => ({
    enabled: false,
    pool_name: 'tank',
    allocate_system_disk_remainder: true,
    system_disk_size_gb: 0,
    extra_disks: [],
    topology: 'auto' as const,
    datasets: [],
  })),
});

export type CloudInitStorage = z.infer<typeof CloudInitStorageSchema>;

// ==============================================================================
// 2. Authentication & ZTP Enrollment Schemas
// ==============================================================================

export const CloudInitZtpSchema = z.object({
  enabled: z.boolean().default(false),
  controller_url: z.string().url().optional(),
  enrollment_token: z
    .string()
    .refine((s) => !/[\r\n\0]/.test(s), 'Enrollment token cannot contain newlines or null bytes')
    .optional(),
});

export const CloudInitAuthSchema = z.object({
  admin_username: z.string().regex(LINUX_USERNAME, 'Invalid Linux username format').default('admin'),
  admin_password: z
    .string()
    .refine((s) => !/[\r\n\0]/.test(s), 'Password cannot contain newlines or null bytes')
    .optional(),
  admin_password_hash: z.string().optional(),
  ztp: CloudInitZtpSchema.default({ enabled: false }),
});

export type CloudInitAuth = z.infer<typeof CloudInitAuthSchema>;

// ==============================================================================
// 3. Top-Level Axonwall Cloud-Config Namespace
// ==============================================================================

export const AxonwallCloudConfigSchema = z.object({
  storage: CloudInitStorageSchema.optional(),
  auth: CloudInitAuthSchema.optional(),
  desired_state: DesiredStateSchema.partial().optional(),
});

export type AxonwallCloudConfig = z.infer<typeof AxonwallCloudConfigSchema>;

export const CloudInitUserSchema = z.object({
  name: z.string().regex(LINUX_USERNAME, 'Invalid Linux username format'),
  gecos: z.string().optional(),
  sudo: z.string().optional(),
  shell: z.string().default('/usr/bin/zsh'),
  lock_passwd: z.boolean().default(false),
  ssh_authorized_keys: z.array(z.string().regex(OPENSSH_PUBKEY, 'Invalid OpenSSH public key format')).default([]),
});

export const FullCloudInitSchema = z.object({
  hostname: z
    .string()
    .regex(RFC1123_HOSTNAME, 'Hostname must adhere to RFC 1123 format (e.g. host-01)')
    .optional(),
  fqdn: z.string().optional(),
  manage_etc_hosts: z.boolean().optional(),
  timezone: z.string().optional(),
  users: z.array(CloudInitUserSchema).optional(),
  packages: z.array(z.string()).optional(),
  runcmd: z.array(z.string()).optional(),
  growpart: z
    .object({
      mode: z.string().optional(),
      devices: z.array(z.string()).optional(),
      ignore_growroot_disabled: z.boolean().optional(),
    })
    .optional(),
  axonwall: AxonwallCloudConfigSchema.optional(),
});

export type FullCloudInit = z.infer<typeof FullCloudInitSchema>;

// ==============================================================================
// 4. Installer Integration Helpers
// ==============================================================================

export interface InstallerChoices {
  TARGET_DISK: string;
  SYSTEM_RAID_MODE: 'single' | 'mirror';
  SYSTEM_RAID_DISKS: string;
  EFI_MB: number;
  ROOT_GB: number;
  ROOT_MB: number;
  ROOT_FSTYPE: 'ext4' | 'xfs' | 'btrfs';
  STANDBY_ENABLED: boolean;
  SWAP_GB: number;
  SWAP_MB: number;
  ZRAM_ENABLED: boolean;
  DATA_GB: number;
  DATA_MB: number;
  DATA_FSTYPE: 'ext4' | 'xfs' | 'btrfs';
  DATA_ALLOC_MODE: 'remainder' | 'explicit' | 'split';
  LOGS_ENABLED: boolean;
  LOGS_GB: number;
  LOGS_MB: number;
  LOGS_FSTYPE: 'ext4' | 'xfs' | 'btrfs';
  LUKS_ENABLED: boolean;
  LUKS_TPM2: boolean;
  LUKS_PASSPHRASE: string;
  ZFS_ALLOC_MODE: 'remainder' | 'split' | 'custom' | 'none';
  ZFS_GB: number;
  ZFS_MB: number;
  ZFS_EXTRA_DISKS: string;
  ZFS_RAID_TOPOLOGY: string;
  CUSTOM_MOUNTS_JSON: string;
}

/**
 * Converts a validated CloudInitStorage configuration into the key-value pairs
 * expected by the Axonwall ISO installer (/var/lib/partman/axonwall-choices).
 */
export function cloudInitStorageToInstallerChoices(storage: CloudInitStorage): InstallerChoices {
  const targetDisk = storage.target_disks[0] || '/dev/sda';
  const systemRaidMode = storage.system_raid.enabled && storage.target_disks.length >= 2 ? 'mirror' : 'single';
  const systemRaidDisks = storage.target_disks.join(' ');

  const efiMb = storage.partitions.efi_size_mb || 512;
  const rootGb = storage.partitions.slot_a?.size_gb ?? 16;
  const rootMb = rootGb * 1024;
  const rootFstype = storage.partitions.slot_a?.filesystem ?? 'ext4';
  const standbyEnabled = storage.layout_mode !== 'single_root';

  const swapGb = storage.partitions.swap?.size_gb ?? 2;
  const swapMb = swapGb * 1024;
  const zramEnabled = Boolean(storage.partitions.swap?.zram_enabled);

  const dataGb = storage.partitions.data?.size_gb ?? 16;
  const dataMb = dataGb * 1024;
  const dataFstype = storage.partitions.data?.filesystem ?? 'ext4';
  const dataAllocMode = storage.partitions.data?.allocate_remaining ? 'remainder' : 'explicit';

  const logsEnabled = Boolean(storage.partitions.logs?.enabled);
  const logsGb = storage.partitions.logs?.size_gb ?? 0;
  const logsMb = logsGb * 1024;
  const logsFstype = storage.partitions.logs?.filesystem ?? 'xfs';

  const luksEnabled = Boolean(storage.encryption?.enabled);
  const luksTpm2 = Boolean(storage.encryption?.tpm2_auto_unlock);
  const luksPassphrase = storage.encryption?.passphrase || '';

  const zfsEnabled = Boolean(storage.zfs?.enabled);
  const zfsAllocMode = zfsEnabled
    ? storage.zfs.system_disk_size_gb > 0
      ? 'custom'
      : storage.zfs.allocate_system_disk_remainder
        ? 'remainder'
        : 'none'
    : 'none';
  const zfsGb = storage.zfs?.system_disk_size_gb || 0;
  const zfsMb = zfsGb * 1024;
  const zfsExtraDisks = (storage.zfs?.extra_disks || []).join(' ');
  const zfsTopology = storage.zfs?.topology || 'auto';

  const customMountsJson = JSON.stringify(storage.partitions.custom_mounts || []);

  return {
    TARGET_DISK: targetDisk,
    SYSTEM_RAID_MODE: systemRaidMode,
    SYSTEM_RAID_DISKS: systemRaidDisks,
    EFI_MB: efiMb,
    ROOT_GB: rootGb,
    ROOT_MB: rootMb,
    ROOT_FSTYPE: rootFstype,
    STANDBY_ENABLED: standbyEnabled,
    SWAP_GB: swapGb,
    SWAP_MB: swapMb,
    ZRAM_ENABLED: zramEnabled,
    DATA_GB: dataGb,
    DATA_MB: dataMb,
    DATA_FSTYPE: dataFstype,
    DATA_ALLOC_MODE: dataAllocMode,
    LOGS_ENABLED: logsEnabled,
    LOGS_GB: logsGb,
    LOGS_MB: logsMb,
    LOGS_FSTYPE: logsFstype,
    LUKS_ENABLED: luksEnabled,
    LUKS_TPM2: luksTpm2,
    LUKS_PASSPHRASE: luksPassphrase,
    ZFS_ALLOC_MODE: zfsAllocMode,
    ZFS_GB: zfsGb,
    ZFS_MB: zfsMb,
    ZFS_EXTRA_DISKS: zfsExtraDisks,
    ZFS_RAID_TOPOLOGY: zfsTopology,
    CUSTOM_MOUNTS_JSON: customMountsJson,
  };
}

function escapeShellSingleQuotes(val: string | number | boolean): string {
  if (typeof val === 'number' || typeof val === 'boolean') {
    return String(val);
  }
  return `'${String(val).replace(/'/g, "'\\''")}'`;
}

/**
 * Formats InstallerChoices as shell variables suitable for sourcing in sh scripts.
 */
export function formatInstallerChoicesEnv(choices: InstallerChoices): string {
  return [
    `# ==============================================================================`,
    `# Axonwall Installer Automated Choices (generated from cloud-config)`,
    `# ==============================================================================`,
    `TARGET_DISK=${escapeShellSingleQuotes(choices.TARGET_DISK)}`,
    `SYSTEM_RAID_MODE=${escapeShellSingleQuotes(choices.SYSTEM_RAID_MODE)}`,
    `SYSTEM_RAID_DISKS=${escapeShellSingleQuotes(choices.SYSTEM_RAID_DISKS)}`,
    `EFI_MB=${choices.EFI_MB}`,
    `ROOT_GB=${choices.ROOT_GB}`,
    `ROOT_MB=${choices.ROOT_MB}`,
    `ROOT_FSTYPE=${escapeShellSingleQuotes(choices.ROOT_FSTYPE)}`,
    `STANDBY_ENABLED=${choices.STANDBY_ENABLED}`,
    `SWAP_GB=${choices.SWAP_GB}`,
    `SWAP_MB=${choices.SWAP_MB}`,
    `ZRAM_ENABLED=${choices.ZRAM_ENABLED}`,
    `DATA_GB=${choices.DATA_GB}`,
    `DATA_MB=${choices.DATA_MB}`,
    `DATA_FSTYPE=${escapeShellSingleQuotes(choices.DATA_FSTYPE)}`,
    `DATA_ALLOC_MODE=${escapeShellSingleQuotes(choices.DATA_ALLOC_MODE)}`,
    `LOGS_ENABLED=${choices.LOGS_ENABLED}`,
    `LOGS_GB=${choices.LOGS_GB}`,
    `LOGS_MB=${choices.LOGS_MB}`,
    `LOGS_FSTYPE=${escapeShellSingleQuotes(choices.LOGS_FSTYPE)}`,
    `LUKS_ENABLED=${choices.LUKS_ENABLED}`,
    `LUKS_TPM2=${choices.LUKS_TPM2}`,
    `LUKS_PASSPHRASE=${escapeShellSingleQuotes(choices.LUKS_PASSPHRASE)}`,
    `ZFS_ALLOC_MODE=${escapeShellSingleQuotes(choices.ZFS_ALLOC_MODE)}`,
    `ZFS_GB=${choices.ZFS_GB}`,
    `ZFS_MB=${choices.ZFS_MB}`,
    `ZFS_EXTRA_DISKS=${escapeShellSingleQuotes(choices.ZFS_EXTRA_DISKS)}`,
    `ZFS_RAID_TOPOLOGY=${escapeShellSingleQuotes(choices.ZFS_RAID_TOPOLOGY)}`,
    `CUSTOM_MOUNTS_JSON=${escapeShellSingleQuotes(choices.CUSTOM_MOUNTS_JSON)}`,
    ``,
  ].join('\n');
}

/**
 * Parses raw YAML text into a validated FullCloudInit configuration.
 */
export function parseCloudInitYaml(yamlText: string): FullCloudInit {
  const raw = parseYaml(yamlText);
  return FullCloudInitSchema.parse(raw);
}

/**
 * Serializes arbitrary data to YAML.
 */
export function serializeYaml(value: unknown): string {
  return stringifyYaml(value, { indent: 2, lineWidth: 120 });
}

/**
 * Serializes a FullCloudInit configuration into standard #cloud-config YAML.
 */
export function serializeCloudInitYaml(config: FullCloudInit): string {
  const validated = FullCloudInitSchema.parse(config);
  const body = stringifyYaml(validated, { indent: 2, lineWidth: 120 });
  return `#cloud-config\n${body}`;
}

// ==============================================================================
// 5. Live System Introspection & Cloud-Init Exporter
// ==============================================================================

export interface LsblkBlockDevice {
  name: string;
  size?: number | string;
  type?: string;
  fstype?: string | null;
  label?: string | null;
  mountpoint?: string | null;
  mountpoints?: Array<string | null>;
  pkname?: string | null;
  children?: LsblkBlockDevice[];
}

export interface CloudInitExportOptions {
  /** Redact passwords, private keys, PSKs, and tokens (default: true) */
  redactSecrets?: boolean;
  /** Strip node-unique WAN IPs/keys and append -clone to hostname for golden templates (default: false) */
  templateMode?: boolean;
  /** Include storage partitioning topology under axonwall.storage (default: true) */
  includeStorage?: boolean;
  /** Include OS / admin users and SSH authorized keys (default: true) */
  includeUsers?: boolean;
  /** Include OS packages for enabled plugins and guest agents (default: true) */
  includePackages?: boolean;
  /** Override exported hostname */
  hostnameOverride?: string;
}

export interface HostIntrospectionData {
  desiredState: DesiredState;
  hostname?: string;
  fqdn?: string;
  timezone?: string;
  storage?: CloudInitStorage;
  adminUsername?: string;
  adminPassword?: string;
  adminPasswordHash?: string;
  ztp?: {
    enabled: boolean;
    controllerUrl?: string;
    enrollmentToken?: string;
  };
  osUsers?: Array<{
    name: string;
    gecos?: string;
    sudo?: string;
    shell?: string;
    lockPasswd?: boolean;
    sshAuthorizedKeys?: string[];
  }>;
  extraPackages?: string[];
}

export const REDACTED_SECRET_PLACEHOLDER = 'CHANGE_ME_ON_DEPLOY';
export const REDACTED_KEY32_PLACEHOLDER = 'CHANGE_ME_ON_DEPLOY_SECRET_KEY_000000000';

export function isValidOpenSshPubKey(key: string): boolean {
  return OPENSSH_PUBKEY.test(key.trim());
}

export function sanitizeRfc1123Hostname(raw: string | undefined, fallback = 'axonwall-fw'): string {
  if (!raw) return fallback;
  const short = raw.trim().split('.')[0] || '';
  const cleaned = short
    .replace(/[^a-zA-Z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
    .replace(/-+$/g, '');
  if (!cleaned || !RFC1123_HOSTNAME.test(cleaned)) {
    return fallback;
  }
  return cleaned;
}

function normalizeFilesystem(fsType: string | null | undefined): FilesystemType {
  if (fsType === 'xfs' || fsType === 'btrfs' || fsType === 'ext4') {
    return fsType;
  }
  return 'ext4';
}

function bytesToGb(bytes: number | string | undefined, minGb: number, defaultGb: number): number {
  const num = typeof bytes === 'string' ? Number(bytes) : bytes;
  if (!num || !Number.isFinite(num) || num <= 0) return defaultGb;
  const gb = Math.round(num / (1024 * 1024 * 1024));
  return Math.max(minGb, gb);
}

function bytesToMb(bytes: number | string | undefined, minMb: number, maxMb: number, defaultMb: number): number {
  const num = typeof bytes === 'string' ? Number(bytes) : bytes;
  if (!num || !Number.isFinite(num) || num <= 0) return defaultMb;
  const mb = Math.round(num / (1024 * 1024));
  return Math.min(maxMb, Math.max(minMb, mb));
}

/**
 * Parses `lsblk -J -b -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT,PKNAME` output
 * from a running Axonwall host into a validated CloudInitStorage configuration.
 */
export function parseStorageFromLsblk(
  lsblkInput: string | { blockdevices?: LsblkBlockDevice[] },
  extra?: {
    zramEnabled?: boolean;
    zfsPools?: Array<{
      name: string;
      datasets?: Array<{ name: string; mountpoint?: string; compression?: string }>;
    }>;
  }
): CloudInitStorage {
  let parsed: { blockdevices?: LsblkBlockDevice[] } = {};
  try {
    parsed = typeof lsblkInput === 'string' ? JSON.parse(lsblkInput) : lsblkInput;
  } catch {
    parsed = {};
  }

  const topDevices = Array.isArray(parsed.blockdevices) ? parsed.blockdevices : [];
  const allNodes: Array<{ node: LsblkBlockDevice; rootDisk?: string }> = [];

  function walk(nodes: LsblkBlockDevice[], currentRootDisk?: string) {
    for (const n of nodes) {
      const diskName = n.type === 'disk' ? `/dev/${n.name}` : currentRootDisk;
      allNodes.push({ node: n, rootDisk: diskName });
      if (Array.isArray(n.children)) {
        walk(n.children, diskName);
      }
    }
  }
  walk(topDevices);

  const systemDisks = new Set<string>();
  let raidEnabled = false;
  let luksEnabled = false;
  let efiSizeMb = 512;
  let slotA: { size_gb: number; filesystem: FilesystemType } | undefined;
  let slotB: { size_gb: number; filesystem: FilesystemType } | undefined;
  let rootFallback: { size_gb: number; filesystem: FilesystemType } | undefined;
  let swapSizeGb = 0;
  let zramDetected = Boolean(extra?.zramEnabled);
  let dataPart: { size_gb: number; allocate_remaining: boolean; filesystem: FilesystemType } | undefined;
  let logsPart: { enabled: boolean; size_gb: number; filesystem: FilesystemType; mountpoint: string } | undefined;
  const customMounts: Array<{
    name: string;
    disk?: string;
    size_gb: number;
    filesystem: FilesystemType;
    mountpoint: string;
  }> = [];

  for (const { node, rootDisk } of allNodes) {
    const label = (node.label || '').trim();
    const fstype = (node.fstype || '').trim();
    const mps: string[] = [];
    if (node.mountpoint) mps.push(node.mountpoint);
    if (Array.isArray(node.mountpoints)) {
      for (const m of node.mountpoints) {
        if (m && !mps.includes(m)) mps.push(m);
      }
    }
    const primaryMp = mps[0] || '';

    if (node.type === 'raid1') {
      raidEnabled = true;
    }
    if (node.type === 'crypt' || fstype === 'crypto_LUKS') {
      luksEnabled = true;
    }
    if (node.name?.startsWith('zram')) {
      zramDetected = true;
      continue;
    }

    const isSystemPart =
      label === 'axon_root_a' ||
      label === 'axon_root_b' ||
      label === 'axon_data' ||
      label === 'axon_logs' ||
      primaryMp === '/' ||
      primaryMp === '/boot/efi' ||
      primaryMp === '/var/lib/axonwall';

    if (isSystemPart && rootDisk) {
      systemDisks.add(rootDisk);
    }

    if (primaryMp === '/boot/efi' || (fstype === 'vfat' && label.toLowerCase().includes('efi'))) {
      efiSizeMb = bytesToMb(node.size, 128, 4096, 512);
    } else if (label === 'axon_root_a') {
      slotA = {
        size_gb: bytesToGb(node.size, 4, 16),
        filesystem: normalizeFilesystem(fstype),
      };
    } else if (label === 'axon_root_b') {
      slotB = {
        size_gb: bytesToGb(node.size, 4, 16),
        filesystem: normalizeFilesystem(fstype),
      };
    } else if (primaryMp === '/' && !slotA) {
      rootFallback = {
        size_gb: bytesToGb(node.size, 4, 16),
        filesystem: normalizeFilesystem(fstype),
      };
    } else if (fstype === 'swap' || primaryMp === '[SWAP]') {
      swapSizeGb = Math.max(swapSizeGb, bytesToGb(node.size, 1, 2));
    } else if (label === 'axon_data' || primaryMp === '/var/lib/axonwall') {
      dataPart = {
        size_gb: bytesToGb(node.size, 2, 16),
        allocate_remaining: true,
        filesystem: normalizeFilesystem(fstype),
      };
    } else if (label === 'axon_logs' || primaryMp === '/var/log') {
      logsPart = {
        enabled: true,
        size_gb: bytesToGb(node.size, 2, 10),
        filesystem: normalizeFilesystem(fstype || 'xfs'),
        mountpoint: primaryMp || '/var/log',
      };
    } else if (
      node.type === 'part' &&
      primaryMp &&
      primaryMp.startsWith('/') &&
      !['/boot', '/boot/efi', '/', '/var/lib/axonwall', '/var/log', '/mnt/standby-slot'].includes(primaryMp) &&
      !primaryMp.startsWith('/run/') &&
      !primaryMp.startsWith('/sys/') &&
      !primaryMp.startsWith('/proc/') &&
      !primaryMp.startsWith('/dev/')
    ) {
      customMounts.push({
        name: label || node.name || `mount_${customMounts.length + 1}`,
        disk: rootDisk,
        size_gb: bytesToGb(node.size, 1, 10),
        filesystem: normalizeFilesystem(fstype),
        mountpoint: primaryMp,
      });
    }
  }

  if (systemDisks.size === 0) {
    const firstDisk = topDevices.find(
      (d) => d.type === 'disk' && !d.name.startsWith('zram') && !d.name.startsWith('loop')
    );
    systemDisks.add(firstDisk ? `/dev/${firstDisk.name}` : '/dev/sda');
  }

  const finalSlotA = slotA || rootFallback || { size_gb: 16, filesystem: 'ext4' as const };
  const hasDualSlots = Boolean(slotA && slotB);
  const finalSlotB = slotB || { size_gb: finalSlotA.size_gb, filesystem: finalSlotA.filesystem };

  let layoutMode: 'standard_ab' | 'compact_ab' | 'single_root' | 'custom' = 'standard_ab';
  if (customMounts.length > 0 || logsPart?.enabled) {
    layoutMode = 'custom';
  } else if (!hasDualSlots && rootFallback && !slotB) {
    layoutMode = 'single_root';
  } else if (finalSlotA.size_gb <= 8) {
    layoutMode = 'compact_ab';
  } else {
    layoutMode = 'standard_ab';
  }

  const zfsPool = extra?.zfsPools?.[0];

  return CloudInitStorageSchema.parse({
    layout_mode: layoutMode,
    target_disks: Array.from(systemDisks),
    system_raid: {
      enabled: raidEnabled || systemDisks.size >= 2,
      level: 'raid1',
    },
    encryption: {
      enabled: luksEnabled,
      tpm2_auto_unlock: false,
      cipher: 'aes-xts-plain64',
      key_size: 512,
    },
    partitions: {
      efi_size_mb: efiSizeMb,
      slot_a: finalSlotA,
      slot_b: finalSlotB,
      swap: {
        size_gb: swapSizeGb,
        zram_enabled: zramDetected,
      },
      data: dataPart || {
        allocate_remaining: true,
        filesystem: 'ext4',
      },
      logs: logsPart || {
        enabled: false,
        size_gb: 10,
        filesystem: 'xfs',
        mountpoint: '/var/log',
      },
      custom_mounts: customMounts,
    },
    zfs: zfsPool
      ? {
          enabled: true,
          pool_name: zfsPool.name || 'tank',
          allocate_system_disk_remainder: true,
          system_disk_size_gb: 0,
          extra_disks: [],
          topology: 'auto',
          datasets: (zfsPool.datasets || []).map((ds) => ({
            name: ds.name,
            mountpoint: ds.mountpoint,
            compression: ds.compression || 'lz4',
          })),
        }
      : undefined,
  });
}

/**
 * Deep-clones DesiredState and optionally redacts secrets and/or applies template transformations.
 */
export function prepareDesiredStateForCloudInit(
  state: DesiredState,
  options: CloudInitExportOptions = {}
): Partial<DesiredState> {
  const redact = options.redactSecrets !== false;
  const templateMode = Boolean(options.templateMode);
  const cloned: DesiredState = structuredClone(state);

  if (redact) {
    if (cloned.wireguard) {
      if (cloned.wireguard.privateKey) {
        cloned.wireguard.privateKey = REDACTED_KEY32_PLACEHOLDER;
      }
      if (Array.isArray(cloned.wireguard.peers)) {
        for (const peer of cloned.wireguard.peers) {
          if (peer.presharedKey) {
            peer.presharedKey = REDACTED_SECRET_PLACEHOLDER;
          }
        }
      }
    }
    if (cloned.ipsec && Array.isArray(cloned.ipsec.tunnels)) {
      for (const tunnel of cloned.ipsec.tunnels) {
        if (tunnel.presharedKey) {
          tunnel.presharedKey = REDACTED_SECRET_PLACEHOLDER;
        }
      }
    }
    if (cloned.openvpn && Array.isArray(cloned.openvpn.servers)) {
      for (const srv of cloned.openvpn.servers) {
        if (srv.serverKey) {
          srv.serverKey = REDACTED_SECRET_PLACEHOLDER;
        }
      }
    }
    if (cloned.frr?.bgp && Array.isArray(cloned.frr.bgp.neighbors)) {
      for (const neighbor of cloned.frr.bgp.neighbors) {
        if (neighbor.password) {
          neighbor.password = REDACTED_SECRET_PLACEHOLDER;
        }
      }
    }
    if (Array.isArray(cloned.virtualIps)) {
      for (const vip of cloned.virtualIps) {
        if (vip.password) {
          vip.password = REDACTED_SECRET_PLACEHOLDER;
        }
      }
    }
    if (cloned.acme) {
      if (Array.isArray(cloned.acme.accounts)) {
        for (const acct of cloned.acme.accounts) {
          if (acct.eabHmacKey) {
            acct.eabHmacKey = REDACTED_SECRET_PLACEHOLDER;
          }
        }
      }
      if (Array.isArray(cloned.acme.internalCAs)) {
        for (const ca of cloned.acme.internalCAs) {
          if (ca.privateKeyBase64) {
            ca.privateKeyBase64 = REDACTED_SECRET_PLACEHOLDER;
          }
        }
      }
    }
    if (cloned.crowdsec?.apiKey) {
      cloned.crowdsec.apiKey = REDACTED_SECRET_PLACEHOLDER;
    }
    if (cloned.sso?.clientSecret) {
      cloned.sso.clientSecret = REDACTED_SECRET_PLACEHOLDER;
    }
    if (cloned.ha) {
      if (cloned.ha.mtlsKey) {
        cloned.ha.mtlsKey = REDACTED_SECRET_PLACEHOLDER;
      }
      if (Array.isArray(cloned.ha.vrrpInstances)) {
        for (const vi of cloned.ha.vrrpInstances) {
          if (vi.authPassword) {
            vi.authPassword = REDACTED_SECRET_PLACEHOLDER;
          }
        }
      }
      if (cloned.ha.sqliteSync) {
        if (cloned.ha.sqliteSync.authToken) {
          cloned.ha.sqliteSync.authToken = REDACTED_SECRET_PLACEHOLDER;
        }
        if (cloned.ha.sqliteSync.litestreamSecretAccessKey) {
          cloned.ha.sqliteSync.litestreamSecretAccessKey = REDACTED_SECRET_PLACEHOLDER;
        }
      }
    }
    if (cloned.observability?.clickhouse?.password) {
      cloned.observability.clickhouse.password = REDACTED_SECRET_PLACEHOLDER;
    }
    if (cloned.freeradius && Array.isArray(cloned.freeradius.clients)) {
      for (const client of cloned.freeradius.clients) {
        if (client.secret) {
          client.secret = REDACTED_SECRET_PLACEHOLDER;
        }
      }
    }
    if (cloned.ai?.providers) {
      for (const p of Object.values(cloned.ai.providers) as Array<{ apiKey?: string }>) {
        if (p && p.apiKey) {
          p.apiKey = REDACTED_SECRET_PLACEHOLDER;
        }
      }
    }
    if (cloned.fleet && Array.isArray(cloned.fleet.nodes)) {
      for (const node of cloned.fleet.nodes) {
        if (node.ztpToken) {
          node.ztpToken = REDACTED_SECRET_PLACEHOLDER;
        }
      }
    }
    if (cloned.nas) {
      if (Array.isArray(cloned.nas.iscsiTargets)) {
        for (const tgt of cloned.nas.iscsiTargets) {
          if (tgt.chapSecret) {
            tgt.chapSecret = REDACTED_SECRET_PLACEHOLDER;
          }
        }
      }
      if (cloned.nas.s3?.secretKey) {
        cloned.nas.s3.secretKey = REDACTED_SECRET_PLACEHOLDER;
      }
    }
  }

  if (templateMode) {
    const baseHost = sanitizeRfc1123Hostname(
      options.hostnameOverride || cloned.system?.hostname || 'axonwall-fw'
    );
    const templateHostname = options.hostnameOverride
      ? baseHost
      : sanitizeRfc1123Hostname(`${baseHost.slice(0, 56)}-clone`);
    if (cloned.system) {
      cloned.system.hostname = templateHostname;
    }
    // Convert WAN static interfaces to DHCP in template mode to avoid immediate duplicate IP collision on boot
    if (Array.isArray(cloned.interfaces)) {
      for (const iface of cloned.interfaces) {
        if (inferInterfaceRole(iface) === 'wan' && iface.type === 'static') {
          iface.type = 'dhcp';
          delete iface.ipv4Address;
          delete iface.ipv4Gateway;
        }
        // Clear hardware MAC pinning when cloning to new virtual/physical NICs
        if (iface.macAddress) {
          delete iface.macAddress;
        }
      }
    }
  } else if (options.hostnameOverride && cloned.system) {
    cloned.system.hostname = sanitizeRfc1123Hostname(options.hostnameOverride);
  }

  return cloned;
}

/**
 * Infers required OS packages from enabled plugins and services in DesiredState.
 */
export function inferCloudInitPackages(state: DesiredState, extraPackages: string[] = []): string[] {
  const pkgs = new Set<string>(['qemu-guest-agent', 'cloud-guest-utils', ...extraPackages]);

  const enabledPluginIds = new Set(
    (state.plugins || []).filter((p) => p.enabled !== false).map((p) => p.id)
  );

  if (state.frr?.enabled || state.frr?.bgp?.enabled || state.frr?.ospf?.enabled || enabledPluginIds.has('frr')) {
    pkgs.add('frr');
  }
  if (state.suricata?.enabled || enabledPluginIds.has('suricata')) {
    pkgs.add('suricata');
  }
  if (state.wireguard?.enabled || enabledPluginIds.has('wireguard')) {
    pkgs.add('wireguard-tools');
  }
  if (state.ipsec?.enabled || (Array.isArray(state.ipsec?.tunnels) && state.ipsec.tunnels.some((t) => t.enabled))) {
    pkgs.add('strongswan');
    pkgs.add('strongswan-swanctl');
  }
  if (state.ups?.enabled || enabledPluginIds.has('nut')) {
    pkgs.add('nut');
    pkgs.add('nut-client');
    pkgs.add('nut-server');
  }
  if (state.headscale?.enabled || enabledPluginIds.has('headscale')) {
    pkgs.add('headscale');
  }
  if (state.haproxy?.enabled || enabledPluginIds.has('haproxy')) {
    pkgs.add('haproxy');
  }
  if (state.freeradius?.enabled || enabledPluginIds.has('freeradius')) {
    pkgs.add('freeradius');
  }
  if (state.snmp?.enabled || enabledPluginIds.has('snmpd')) {
    pkgs.add('snmpd');
  }
  if (state.sso?.enabled) {
    pkgs.add('sssd');
    pkgs.add('sssd-ldap');
  }

  return Array.from(pkgs);
}

/**
 * Builds a complete, schema-validated FullCloudInit object from a live Axonwall system's
 * introspected state, storage layout, users, and authentication settings.
 */
export function buildCloudInitFromSystem(
  data: HostIntrospectionData,
  options: CloudInitExportOptions = {}
): FullCloudInit {
  const redact = options.redactSecrets !== false;
  const templateMode = Boolean(options.templateMode);
  const includeStorage = options.includeStorage !== false;
  const includeUsers = options.includeUsers !== false;
  const includePackages = options.includePackages !== false;

  const preparedState = prepareDesiredStateForCloudInit(data.desiredState, options);
  const baseHost = sanitizeRfc1123Hostname(
    options.hostnameOverride ||
      data.hostname ||
      data.desiredState.system?.hostname ||
      'axonwall-fw'
  );
  const finalHostname =
    templateMode && !options.hostnameOverride
      ? sanitizeRfc1123Hostname(`${baseHost.slice(0, 56)}-clone`)
      : baseHost;

  const domain = data.desiredState.system?.domain || 'axonwall.local';
  const fqdn = data.fqdn && !templateMode && !options.hostnameOverride ? data.fqdn : `${finalHostname}.${domain}`;
  const timezone = data.timezone || data.desiredState.system?.timezone || 'UTC';

  // Assemble users list
  const usersMap = new Map<
    string,
    {
      name: string;
      gecos?: string;
      sudo?: string;
      shell: string;
      lock_passwd: boolean;
      ssh_authorized_keys: string[];
    }
  >();

  if (includeUsers) {
    for (const osUser of data.osUsers || []) {
      const name = osUser.name.trim();
      if (!LINUX_USERNAME.test(name)) continue;
      const validKeys = (osUser.sshAuthorizedKeys || [])
        .map((k) => k.trim())
        .filter((k) => isValidOpenSshPubKey(k));
      usersMap.set(name, {
        name,
        gecos: osUser.gecos || `${name} User`,
        sudo: osUser.sudo,
        shell: osUser.shell || '/usr/bin/zsh',
        lock_passwd: osUser.lockPasswd ?? false,
        ssh_authorized_keys: Array.from(new Set(validKeys)),
      });
    }
  }

  // Storage section
  let exportedStorage: CloudInitStorage | undefined;
  if (includeStorage && data.storage) {
    exportedStorage = structuredClone(data.storage);
    if (exportedStorage.encryption?.enabled) {
      exportedStorage.encryption.passphrase = redact
        ? REDACTED_SECRET_PLACEHOLDER
        : exportedStorage.encryption.passphrase || REDACTED_SECRET_PLACEHOLDER;
    }
  }

  // Auth section
  const adminUser =
    data.adminUsername && LINUX_USERNAME.test(data.adminUsername) ? data.adminUsername : 'admin';
  const authSection: CloudInitAuth = {
    admin_username: adminUser,
    admin_password: redact
      ? REDACTED_SECRET_PLACEHOLDER
      : data.adminPassword || REDACTED_SECRET_PLACEHOLDER,
    ...(redact || !data.adminPasswordHash ? {} : { admin_password_hash: data.adminPasswordHash }),
    ztp: data.ztp?.enabled
      ? {
          enabled: true,
          ...(data.ztp.controllerUrl ? { controller_url: data.ztp.controllerUrl } : {}),
          enrollment_token: redact
            ? REDACTED_SECRET_PLACEHOLDER
            : data.ztp.enrollmentToken || REDACTED_SECRET_PLACEHOLDER,
        }
      : { enabled: false },
  };

  const fullConfig: FullCloudInit = {
    hostname: finalHostname,
    fqdn,
    manage_etc_hosts: true,
    timezone,
    ...(includeUsers && usersMap.size > 0 ? { users: Array.from(usersMap.values()) } : {}),
    ...(includePackages ? { packages: inferCloudInitPackages(data.desiredState, data.extraPackages) } : {}),
    runcmd: ['/usr/local/bin/axonwall-firstboot'],
    axonwall: {
      ...(exportedStorage ? { storage: exportedStorage } : {}),
      auth: authSection,
      desired_state: preparedState,
    },
  };

  return FullCloudInitSchema.parse(fullConfig);
}

/**
 * Generates an annotated #cloud-config YAML document from a running Axonwall system.
 */
export function exportCloudInitYaml(
  data: HostIntrospectionData,
  options: CloudInitExportOptions = {}
): string {
  const config = buildCloudInitFromSystem(data, options);
  const body = stringifyYaml(config, { indent: 2, lineWidth: 120 });
  const modeLabel = options.templateMode ? 'Golden Fleet Template' : '1:1 Appliance Clone';
  const redactLabel = options.redactSecrets !== false ? 'REDACTED (Search for CHANGE_ME_ON_DEPLOY)' : 'UNREDACTED (Contains live secrets)';

  return [
    `#cloud-config`,
    `# ==============================================================================`,
    `# Axonwall Cloud-Init Appliance Replicator Specification`,
    `# Mode:    ${modeLabel}`,
    `# Secrets: ${redactLabel}`,
    `# Usage:`,
    `#   - ISO Installer: Provide on a FAT/ISO volume labeled 'cidata' or 'AXONCFG' as /user-data`,
    `#   - Proxmox / KVM: Attach NoCloud cidata.iso or pass via --cicustom`,
    `#   - CLI Reconcile: axonwallctl cloudinit <path-to-this-file.yaml>`,
    `# ==============================================================================`,
    body,
  ].join('\n');
}

/**
 * Generates NoCloud `meta-data` YAML content.
 */
export function generateCloudInitMetaData(instanceId?: string, localHostname?: string): string {
  const host = sanitizeRfc1123Hostname(localHostname, 'axonwall-fw');
  const id = instanceId || `axonwall-${host}-${Date.now().toString(36)}`;
  return stringifyYaml({
    'instance-id': id,
    'local-hostname': host,
  });
}

// ==============================================================================
// 6. Pure-TypeScript ISO9660 + Rock Ridge (`cidata`) Seed Image Builder
// ==============================================================================

function writeBothEndian16(buf: Uint8Array, offset: number, val: number) {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
  buf[offset + 2] = (val >>> 8) & 0xff;
  buf[offset + 3] = val & 0xff;
}

function writeBothEndian32(buf: Uint8Array, offset: number, val: number) {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
  buf[offset + 2] = (val >>> 16) & 0xff;
  buf[offset + 3] = (val >>> 24) & 0xff;
  buf[offset + 4] = (val >>> 24) & 0xff;
  buf[offset + 5] = (val >>> 16) & 0xff;
  buf[offset + 6] = (val >>> 8) & 0xff;
  buf[offset + 7] = val & 0xff;
}

function writeAsciiPadded(buf: Uint8Array, offset: number, str: string, len: number, padChar = 0x20) {
  for (let i = 0; i < len; i++) {
    buf[offset + i] = i < str.length ? str.charCodeAt(i) & 0x7f : padChar;
  }
}

function writeIsoDate7(buf: Uint8Array, offset: number, d = new Date()) {
  buf[offset] = d.getUTCFullYear() - 1900;
  buf[offset + 1] = d.getUTCMonth() + 1;
  buf[offset + 2] = d.getUTCDate();
  buf[offset + 3] = d.getUTCHours();
  buf[offset + 4] = d.getUTCMinutes();
  buf[offset + 5] = d.getUTCSeconds();
  buf[offset + 6] = 0; // GMT offset
}

function writeIsoDate17(buf: Uint8Array, offset: number, d = new Date()) {
  const s =
    String(d.getUTCFullYear()).padStart(4, '0') +
    String(d.getUTCMonth() + 1).padStart(2, '0') +
    String(d.getUTCDate()).padStart(2, '0') +
    String(d.getUTCHours()).padStart(2, '0') +
    String(d.getUTCMinutes()).padStart(2, '0') +
    String(d.getUTCSeconds()).padStart(2, '0') +
    '00';
  writeAsciiPadded(buf, offset, s, 16, 0x30);
  buf[offset + 16] = 0;
}

function buildRockRidgePxEntry(mode: number, nlink: number): Uint8Array {
  // RRIP 'PX' POSIX file attributes (36 bytes)
  const px = new Uint8Array(36);
  px[0] = 0x50; // 'P'
  px[1] = 0x58; // 'X'
  px[2] = 36; // length
  px[3] = 1; // version
  writeBothEndian32(px, 4, mode);
  writeBothEndian32(px, 12, nlink);
  writeBothEndian32(px, 20, 0); // uid = 0
  writeBothEndian32(px, 28, 0); // gid = 0
  return px;
}

function buildRockRidgeNmEntry(posixName: string): Uint8Array {
  const nameBytes = new TextEncoder().encode(posixName);
  const len = 5 + nameBytes.length;
  const nm = new Uint8Array(len);
  nm[0] = 0x4e; // 'N'
  nm[1] = 0x4d; // 'M'
  nm[2] = len;
  nm[3] = 1; // version
  nm[4] = 0; // flags
  nm.set(nameBytes, 5);
  return nm;
}

function buildDirRecord(opts: {
  extentSector: number;
  dataLength: number;
  isDirectory: boolean;
  isoIdentifier: Uint8Array;
  systemUse?: Uint8Array;
  date?: Date;
}): Uint8Array {
  const idLen = opts.isoIdentifier.length;
  const padLen = idLen % 2 === 0 ? 1 : 0;
  const suLen = opts.systemUse ? opts.systemUse.length : 0;
  const suPad = suLen % 2 === 1 ? 1 : 0;
  const totalLen = 33 + idLen + padLen + suLen + suPad;

  const rec = new Uint8Array(totalLen);
  rec[0] = totalLen;
  rec[1] = 0; // ext attr length
  writeBothEndian32(rec, 2, opts.extentSector);
  writeBothEndian32(rec, 10, opts.dataLength);
  writeIsoDate7(rec, 18, opts.date);
  rec[25] = opts.isDirectory ? 0x02 : 0x00;
  rec[26] = 0; // file unit size
  rec[27] = 0; // interleave gap
  writeBothEndian16(rec, 28, 1); // volume sequence number
  rec[32] = idLen;
  rec.set(opts.isoIdentifier, 33);
  if (opts.systemUse) {
    rec.set(opts.systemUse, 33 + idLen + padLen);
  }
  return rec;
}

/**
 * Builds a bootable/mountable ISO9660 + Rock Ridge NoCloud seed image (`cidata.iso`)
 * in pure TypeScript with volume label `cidata`, containing `/user-data`, `/meta-data`,
 * and optionally `/network-config`. Requires zero external CLI dependencies.
 */
export function buildNoCloudIso(
  userData: string,
  metaData: string,
  networkConfig?: string,
  volumeLabel = 'cidata'
): Uint8Array {
  const encoder = new TextEncoder();
  const files: Array<{ posixName: string; isoName: string; content: Uint8Array; sector: number }> = [
    {
      posixName: 'meta-data',
      isoName: 'META_DAT.;1',
      content: encoder.encode(metaData),
      sector: 0,
    },
    {
      posixName: 'user-data',
      isoName: 'USER_DAT.;1',
      content: encoder.encode(userData),
      sector: 0,
    },
  ];

  if (networkConfig) {
    files.push({
      posixName: 'network-config',
      isoName: 'NET_CFG.;1',
      content: encoder.encode(networkConfig),
      sector: 0,
    });
  }

  const SECTOR_SIZE = 2048;
  const PVD_SECTOR = 16;
  const TERM_SECTOR = 17;
  const LPATH_SECTOR = 18;
  const MPATH_SECTOR = 19;
  const ROOT_DIR_SECTOR = 20;

  let nextSector = 21;
  for (const f of files) {
    f.sector = nextSector;
    const sectorsNeeded = Math.max(1, Math.ceil(f.content.length / SECTOR_SIZE));
    nextSector += sectorsNeeded;
  }

  // Pad image to at least 180 sectors (368 KB) per ISO9660 minimum track size conventions
  const totalSectors = Math.max(180, nextSector + 4);
  const iso = new Uint8Array(totalSectors * SECTOR_SIZE);
  const now = new Date();

  // 1. Build Root Directory Sector (Sector 20)
  const spEntry = new Uint8Array([0x53, 0x50, 7, 1, 0xbe, 0xef, 0]); // SUSP 'SP' signature
  const dirPx = buildRockRidgePxEntry(0o040755, 2);
  const dotSu = new Uint8Array(spEntry.length + dirPx.length);
  dotSu.set(spEntry, 0);
  dotSu.set(dirPx, spEntry.length);

  const dotRecord = buildDirRecord({
    extentSector: ROOT_DIR_SECTOR,
    dataLength: SECTOR_SIZE,
    isDirectory: true,
    isoIdentifier: new Uint8Array([0x00]),
    systemUse: dotSu,
    date: now,
  });

  const dotDotRecord = buildDirRecord({
    extentSector: ROOT_DIR_SECTOR,
    dataLength: SECTOR_SIZE,
    isDirectory: true,
    isoIdentifier: new Uint8Array([0x01]),
    systemUse: dirPx,
    date: now,
  });

  let dirOffset = ROOT_DIR_SECTOR * SECTOR_SIZE;
  iso.set(dotRecord, dirOffset);
  dirOffset += dotRecord.length;
  iso.set(dotDotRecord, dirOffset);
  dirOffset += dotDotRecord.length;

  for (const f of files) {
    const filePx = buildRockRidgePxEntry(0o100644, 1);
    const fileNm = buildRockRidgeNmEntry(f.posixName);
    const su = new Uint8Array(filePx.length + fileNm.length);
    su.set(filePx, 0);
    su.set(fileNm, filePx.length);

    const rec = buildDirRecord({
      extentSector: f.sector,
      dataLength: f.content.length,
      isDirectory: false,
      isoIdentifier: encoder.encode(f.isoName),
      systemUse: su,
      date: now,
    });
    iso.set(rec, dirOffset);
    dirOffset += rec.length;

    // Write file data payload
    iso.set(f.content, f.sector * SECTOR_SIZE);
  }

  // 2. Path Tables (Sectors 18 and 19)
  const pathTableSize = 10;
  const lPathOffset = LPATH_SECTOR * SECTOR_SIZE;
  iso[lPathOffset + 0] = 1; // name length
  iso[lPathOffset + 1] = 0; // ext attr length
  iso[lPathOffset + 2] = ROOT_DIR_SECTOR & 0xff;
  iso[lPathOffset + 3] = (ROOT_DIR_SECTOR >>> 8) & 0xff;
  iso[lPathOffset + 4] = (ROOT_DIR_SECTOR >>> 16) & 0xff;
  iso[lPathOffset + 5] = (ROOT_DIR_SECTOR >>> 24) & 0xff;
  iso[lPathOffset + 6] = 1; // parent dir number (LE)
  iso[lPathOffset + 7] = 0;
  iso[lPathOffset + 8] = 0; // root identifier

  const mPathOffset = MPATH_SECTOR * SECTOR_SIZE;
  iso[mPathOffset + 0] = 1;
  iso[mPathOffset + 1] = 0;
  iso[mPathOffset + 2] = (ROOT_DIR_SECTOR >>> 24) & 0xff;
  iso[mPathOffset + 3] = (ROOT_DIR_SECTOR >>> 16) & 0xff;
  iso[mPathOffset + 4] = (ROOT_DIR_SECTOR >>> 8) & 0xff;
  iso[mPathOffset + 5] = ROOT_DIR_SECTOR & 0xff;
  iso[mPathOffset + 6] = 0; // parent dir number (BE)
  iso[mPathOffset + 7] = 1;
  iso[mPathOffset + 8] = 0;

  // 3. Primary Volume Descriptor (Sector 16)
  const pvd = iso.subarray(PVD_SECTOR * SECTOR_SIZE, (PVD_SECTOR + 1) * SECTOR_SIZE);
  pvd[0] = 0x01; // Primary Volume Descriptor
  writeAsciiPadded(pvd, 1, 'CD001', 5);
  pvd[6] = 0x01; // Version 1
  writeAsciiPadded(pvd, 8, 'LINUX', 32);
  writeAsciiPadded(pvd, 40, volumeLabel.slice(0, 32), 32);
  writeBothEndian32(pvd, 80, totalSectors);
  writeBothEndian16(pvd, 120, 1); // Volume Set Size
  writeBothEndian16(pvd, 124, 1); // Volume Sequence Number
  writeBothEndian16(pvd, 128, SECTOR_SIZE); // Logical Block Size
  writeBothEndian32(pvd, 132, pathTableSize);
  // L-Path Table sector (LE)
  pvd[140] = LPATH_SECTOR & 0xff;
  // M-Path Table sector (BE)
  pvd[151] = MPATH_SECTOR & 0xff;

  // Root Directory Record in PVD (34 bytes at offset 156)
  const pvdRootRec = buildDirRecord({
    extentSector: ROOT_DIR_SECTOR,
    dataLength: SECTOR_SIZE,
    isDirectory: true,
    isoIdentifier: new Uint8Array([0x00]),
    date: now,
  });
  pvd.set(pvdRootRec, 156);

  writeAsciiPadded(pvd, 190, 'AXONWALL_NOCLOUD', 128);
  writeAsciiPadded(pvd, 318, 'AXONWALL', 128);
  writeAsciiPadded(pvd, 446, 'AXONWALL CLOUDINIT EXPORTER', 128);
  writeAsciiPadded(pvd, 574, 'AXONWALL CLOUD-INIT SEED GENERATOR', 128);
  writeAsciiPadded(pvd, 702, '', 37 + 37 + 37);
  writeIsoDate17(pvd, 813, now); // Creation
  writeIsoDate17(pvd, 830, now); // Modification
  writeAsciiPadded(pvd, 847, '0000000000000000', 16, 0x30); // Expiration
  writeIsoDate17(pvd, 864, now); // Effective
  pvd[881] = 0x01; // File structure version

  // 4. Volume Descriptor Set Terminator (Sector 17)
  const term = iso.subarray(TERM_SECTOR * SECTOR_SIZE, (TERM_SECTOR + 1) * SECTOR_SIZE);
  term[0] = 0xff;
  writeAsciiPadded(term, 1, 'CD001', 5);
  term[6] = 0x01;

  return iso;
}

