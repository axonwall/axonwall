import { z } from 'zod';

export const KernelBuildModeSchema = z.enum(['universal', 'stripped']);
export type KernelBuildMode = z.infer<typeof KernelBuildModeSchema>;

export const KernelCapabilityPackSchema = z.enum([
  'k3s',
  'zfs',
  'nftables',
  'ebpf',
  'kvm',
  'ipsec',
  'usb',
  'iscsi_nfs',
]);
export type KernelCapabilityPack = z.infer<typeof KernelCapabilityPackSchema>;

export const KernelLockdownTierSchema = z.enum(['integrity', 'confidentiality']);
export type KernelLockdownTier = z.infer<typeof KernelLockdownTierSchema>;

export const CpuMicroarchTargetSchema = z.enum([
  'x86-64',
  'x86-64-v2',
  'x86-64-v3',
  'x86-64-v4',
  'native',
  'armv8-a',
]);
export type CpuMicroarchTarget = z.infer<typeof CpuMicroarchTargetSchema>;

export const DetectedPciDeviceSchema = z.object({
  bdf: z.string(),
  vendorId: z.string(),
  deviceId: z.string(),
  deviceClass: z.string(),
  deviceName: z.string(),
  driver: z.string(),
  module: z.string().optional(),
  iommuGroup: z.number().int().optional(),
  subsystemVendorId: z.string().optional(),
  subsystemDeviceId: z.string().optional(),
});
export type DetectedPciDevice = z.infer<typeof DetectedPciDeviceSchema>;

export const DetectedStorageControllerSchema = z.object({
  name: z.string(),
  kind: z.string(),
  driver: z.string(),
  model: z.string().optional(),
  transport: z.string().optional(),
  sizeBytes: z.number().nonnegative().optional(),
});
export type DetectedStorageController = z.infer<typeof DetectedStorageControllerSchema>;

export const DetectedNetworkInterfaceSchema = z.object({
  name: z.string(),
  driver: z.string(),
  mac: z.string().optional(),
  operstate: z.string().optional(),
  speedMbps: z.number().int().optional(),
  busPath: z.string().optional(),
});
export type DetectedNetworkInterface = z.infer<typeof DetectedNetworkInterfaceSchema>;

export const LoadedKernelModuleSchema = z.object({
  name: z.string(),
  sizeBytes: z.number().nonnegative(),
  refCount: z.number().int().nonnegative(),
  usedBy: z.array(z.string()).default([]),
});
export type LoadedKernelModule = z.infer<typeof LoadedKernelModuleSchema>;

export const HostBuildToolchainSchema = z.object({
  ready: z.boolean(),
  missingTools: z.array(z.string()),
  availableTools: z.array(z.string()),
  builderScriptPath: z.string().optional(),
  freeBytes: z.number().nonnegative(),
});
export type HostBuildToolchain = z.infer<typeof HostBuildToolchainSchema>;

export const BuiltKernelArtifactSchema = z.object({
  name: z.string(),
  kind: z.enum(['image-deb', 'headers-deb', 'config', 'manifest']),
  sizeBytes: z.number().nonnegative(),
  sha256: z.string().optional(),
  createdAt: z.string(),
});
export type BuiltKernelArtifact = z.infer<typeof BuiltKernelArtifactSchema>;

export const DetectedHardwareProfileSchema = z.object({
  hostname: z.string(),
  kernelRelease: z.string(),
  arch: z.string(),
  cpuVendor: z.string(),
  cpuModel: z.string(),
  cpuCores: z.number().int().nonnegative(),
  cpuFlags: z.array(z.string()).default([]),
  suggestedMarch: CpuMicroarchTargetSchema,
  virtVendor: z.string().optional(),
  efiBooted: z.boolean(),
  secureBootEnabled: z.boolean(),
  iommuActive: z.boolean(),
  iommuGroupsCount: z.number().int().nonnegative().default(0),
  tpmDevices: z.array(z.string()).default([]),
  watchdogDrivers: z.array(z.string()).default([]),
  pciDevices: z.array(DetectedPciDeviceSchema).default([]),
  storageControllers: z.array(DetectedStorageControllerSchema).default([]),
  networkInterfaces: z.array(DetectedNetworkInterfaceSchema).default([]),
  loadedModules: z.array(LoadedKernelModuleSchema).default([]),
  hostAvailableModules: z.number().int().nonnegative().default(0),
});
export type DetectedHardwareProfile = z.infer<typeof DetectedHardwareProfileSchema>;

export const CustomKernelBuildSpecSchema = z.object({
  mode: KernelBuildModeSchema.default('universal'),
  kernelVersion: z
    .string()
    .regex(/^6\.\d+\.\d+$/, 'Kernel version must match 6.x.y')
    .default('6.12.15'),
  arch: z.enum(['amd64', 'arm64']).default('amd64'),
  marchTarget: CpuMicroarchTargetSchema.default('x86-64'),
  capabilities: z
    .array(KernelCapabilityPackSchema)
    .min(1)
    .default(['k3s', 'zfs', 'nftables', 'ebpf', 'kvm', 'ipsec', 'usb', 'iscsi_nfs']),
  lockdownTier: KernelLockdownTierSchema.default('integrity'),
  enableRootlessUserNs: z.boolean().default(true),
  disableIa32Emulation: z.boolean().default(true),
  enforceModuleSig: z.boolean().default(false),
  enableProcKcore: z.boolean().default(true),
  extraDriverSymbols: z
    .array(z.string().regex(/^CONFIG_[A-Z0-9_]{2,64}$/, 'Invalid Kconfig symbol'))
    .default([]),
});
export type CustomKernelBuildSpec = z.infer<typeof CustomKernelBuildSpecSchema>;

export const KernelAuditPillarSchema = z.enum([
  'kspp_memory',
  'attack_surface',
  'k3s_containers',
  'storage_zfs',
  'nftables_ebpf',
]);
export type KernelAuditPillar = z.infer<typeof KernelAuditPillarSchema>;

export const KernelAuditCheckResultSchema = z.object({
  id: z.string(),
  pillar: KernelAuditPillarSchema,
  label: z.string(),
  symbol: z.string(),
  expected: z.string(),
  actual: z.string(),
  status: z.enum(['PASS', 'WARN', 'FAIL']),
  rationale: z.string(),
});
export type KernelAuditCheckResult = z.infer<typeof KernelAuditCheckResultSchema>;

export const KernelHardeningAuditReportSchema = z.object({
  score: z.number().int().min(0).max(100),
  passedCount: z.number().int().nonnegative(),
  warnCount: z.number().int().nonnegative(),
  failCount: z.number().int().nonnegative(),
  totalCount: z.number().int().nonnegative(),
  configSource: z.string(),
  checks: z.array(KernelAuditCheckResultSchema),
});
export type KernelHardeningAuditReport = z.infer<typeof KernelHardeningAuditReportSchema>;

export interface DriverSymbolEntry {
  symbols: string[];
  category: string;
  description: string;
  builtInRecommended?: boolean;
}

export interface CompiledKernelBundle {
  kconfigFragment: string;
  sysctlConfig: string;
  lsmodSeed: string;
  cliCommand: string;
  retainedDrivers: Array<{
    driver: string;
    category: string;
    description: string;
    symbols: string[];
    source: string;
  }>;
  estimatedModuleStats: {
    hostAvailableModules: number;
    loadedModulesCount: number;
    retainedDriverCount: number;
    retainedSymbolCount: number;
    estimatedReductionPercent: number;
  };
  warnings: string[];
  simulatedAudit: KernelHardeningAuditReport;
}
