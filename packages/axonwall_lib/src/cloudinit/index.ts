import { z } from 'zod';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { DesiredStateSchema, type DesiredState } from '../schemas/index.js';

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

export const EncryptionSchema = z.object({
  enabled: z.boolean().default(false),
  tpm2_auto_unlock: z.boolean().default(false),
  passphrase: z.string().optional(),
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
  enrollment_token: z.string().optional(),
});

export const CloudInitAuthSchema = z.object({
  admin_username: z.string().default('admin'),
  admin_password: z.string().optional(),
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
  name: z.string(),
  gecos: z.string().optional(),
  sudo: z.string().optional(),
  shell: z.string().default('/bin/bash'),
  lock_passwd: z.boolean().default(false),
  ssh_authorized_keys: z.array(z.string()).default([]),
});

export const FullCloudInitSchema = z.object({
  hostname: z.string().optional(),
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

/**
 * Formats InstallerChoices as shell variables suitable for sourcing in sh scripts.
 */
export function formatInstallerChoicesEnv(choices: InstallerChoices): string {
  return [
    `# ==============================================================================`,
    `# Axonwall Installer Automated Choices (generated from cloud-config)`,
    `# ==============================================================================`,
    `TARGET_DISK="${choices.TARGET_DISK}"`,
    `SYSTEM_RAID_MODE="${choices.SYSTEM_RAID_MODE}"`,
    `SYSTEM_RAID_DISKS="${choices.SYSTEM_RAID_DISKS}"`,
    `EFI_MB=${choices.EFI_MB}`,
    `ROOT_GB=${choices.ROOT_GB}`,
    `ROOT_MB=${choices.ROOT_MB}`,
    `ROOT_FSTYPE="${choices.ROOT_FSTYPE}"`,
    `STANDBY_ENABLED=${choices.STANDBY_ENABLED}`,
    `SWAP_GB=${choices.SWAP_GB}`,
    `SWAP_MB=${choices.SWAP_MB}`,
    `ZRAM_ENABLED=${choices.ZRAM_ENABLED}`,
    `DATA_GB=${choices.DATA_GB}`,
    `DATA_MB=${choices.DATA_MB}`,
    `DATA_FSTYPE="${choices.DATA_FSTYPE}"`,
    `DATA_ALLOC_MODE="${choices.DATA_ALLOC_MODE}"`,
    `LOGS_ENABLED=${choices.LOGS_ENABLED}`,
    `LOGS_GB=${choices.LOGS_GB}`,
    `LOGS_MB=${choices.LOGS_MB}`,
    `LOGS_FSTYPE="${choices.LOGS_FSTYPE}"`,
    `LUKS_ENABLED=${choices.LUKS_ENABLED}`,
    `LUKS_TPM2=${choices.LUKS_TPM2}`,
    `LUKS_PASSPHRASE="${choices.LUKS_PASSPHRASE}"`,
    `ZFS_ALLOC_MODE="${choices.ZFS_ALLOC_MODE}"`,
    `ZFS_GB=${choices.ZFS_GB}`,
    `ZFS_MB=${choices.ZFS_MB}`,
    `ZFS_EXTRA_DISKS="${choices.ZFS_EXTRA_DISKS}"`,
    `ZFS_RAID_TOPOLOGY="${choices.ZFS_RAID_TOPOLOGY}"`,
    `CUSTOM_MOUNTS_JSON='${choices.CUSTOM_MOUNTS_JSON.replace(/'/g, "'\\''")}'`,
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
