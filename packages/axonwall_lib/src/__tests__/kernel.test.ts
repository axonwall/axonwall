import { describe, it, expect } from 'vitest';
import {
  CustomKernelBuildSpecSchema,
  auditKernelPostureAndConfig,
  compileCustomKernelArtifacts,
  resolveHardwareKconfigSymbols,
  type DetectedHardwareProfile,
} from '../kernel/index.js';

const SAMPLE_HW: DetectedHardwareProfile = {
  hostname: 'axonwall-edge-01',
  kernelRelease: '6.12.15-amd64',
  arch: 'x86_64',
  cpuVendor: 'GenuineIntel',
  cpuModel: 'Intel(R) Core(TM) i5-1240P',
  cpuCores: 16,
  cpuFlags: ['avx2', 'aes', 'vmx', 'sse4_2'],
  suggestedMarch: 'x86-64-v3',
  efiBooted: true,
  secureBootEnabled: true,
  iommuActive: true,
  iommuGroupsCount: 18,
  tpmDevices: ['tpm0', 'tpmrm0'],
  watchdogDrivers: ['iTCO_wdt'],
  pciDevices: [
    {
      bdf: '0000:01:00.0',
      vendorId: '8086',
      deviceId: '125c',
      deviceClass: '020000',
      deviceName: 'Intel Ethernet Controller I226-V',
      driver: 'igc',
      module: 'igc',
    },
    {
      bdf: '0000:02:00.0',
      vendorId: '144d',
      deviceId: 'a80a',
      deviceClass: '010802',
      deviceName: 'Samsung NVMe SSD Controller',
      driver: 'nvme',
      module: 'nvme',
    },
  ],
  storageControllers: [
    {
      name: 'nvme0n1',
      kind: 'nvme',
      driver: 'nvme',
      model: 'Samsung SSD 980 PRO',
      sizeBytes: 1000204886016,
    },
  ],
  networkInterfaces: [
    {
      name: 'enp1s0',
      driver: 'igc',
      operstate: 'up',
      speedMbps: 2500,
    },
  ],
  loadedModules: [
    { name: 'igc', sizeBytes: 184320, refCount: 0, usedBy: [] },
    { name: 'nvme', sizeBytes: 61440, refCount: 2, usedBy: ['nvme_core'] },
    { name: 'zfs', sizeBytes: 4128768, refCount: 5, usedBy: ['spl'] },
    { name: 'wireguard', sizeBytes: 110592, refCount: 0, usedBy: [] },
    { name: 'nf_tables', sizeBytes: 348160, refCount: 4, usedBy: ['nft_ct'] },
    { name: 'overlay', sizeBytes: 172032, refCount: 12, usedBy: [] },
  ],
  hostAvailableModules: 4200,
};

describe('Axonwall Custom Kernel Schema, Hardware Resolver & Auditor', () => {
  it('resolves CPU, EFI, TPM2, PCIe NIC, NVMe, and OpenZFS modules to exact Kconfig symbols', () => {
    const resolved = resolveHardwareKconfigSymbols(SAMPLE_HW);

    expect(resolved.symbols.CONFIG_MICROCODE_INTEL).toBe('y');
    expect(resolved.symbols.CONFIG_INTEL_IOMMU).toBe('y');
    expect(resolved.symbols.CONFIG_EFI_STUB).toBe('y');
    expect(resolved.symbols.CONFIG_TCG_TPM).toBe('y');
    expect(resolved.symbols.CONFIG_IGC).toBe('y');
    expect(resolved.symbols.CONFIG_BLK_DEV_NVME).toBe('y');
    expect(resolved.symbols.CONFIG_ITCO_WDT).toBe('m');
    expect(resolved.symbols.CONFIG_WIREGUARD).toBe('y');
    expect(resolved.retainedDrivers.some((d) => d.driver === 'igc' && d.category === 'network')).toBe(true);
    expect(resolved.retainedDrivers.some((d) => d.driver === 'nvme' && d.category === 'storage')).toBe(true);
  });

  it('compiles universal hardened kernel bundle achieving 100/100 KSPP+K3s+ZFS+eBPF audit', () => {
    const spec = CustomKernelBuildSpecSchema.parse({
      mode: 'universal',
      kernelVersion: '6.12.15',
      arch: 'amd64',
      marchTarget: 'x86-64',
      capabilities: ['k3s', 'zfs', 'nftables', 'ebpf', 'kvm', 'ipsec', 'usb', 'iscsi_nfs'],
      lockdownTier: 'integrity',
    });

    const bundle = compileCustomKernelArtifacts(spec, SAMPLE_HW);
    expect(bundle.warnings).toHaveLength(0);
    expect(bundle.kconfigFragment).toContain('CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y');
    expect(bundle.kconfigFragment).toContain('# CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY is not set');
    expect(bundle.kconfigFragment).toContain('CONFIG_USER_NS=y');
    expect(bundle.kconfigFragment).toContain('CONFIG_DEBUG_INFO_BTF=y');
    expect(bundle.kconfigFragment).toContain('CONFIG_NF_TABLES=y');
    expect(bundle.kconfigFragment).toContain('# CONFIG_TRIM_UNUSED_KSYMS is not set');
    expect(bundle.sysctlConfig).toContain('-kernel.unprivileged_userns_clone = 1');
    expect(bundle.simulatedAudit.totalCount).toBe(24);
    expect(bundle.simulatedAudit.score).toBe(100);
    expect(bundle.simulatedAudit.failCount).toBe(0);
  });

  it('compiles hardware-stripped kernel with >90% module attack surface reduction', () => {
    const spec = CustomKernelBuildSpecSchema.parse({
      mode: 'stripped',
      kernelVersion: '6.12.15',
      arch: 'amd64',
      marchTarget: 'x86-64-v3',
      capabilities: ['k3s', 'zfs', 'nftables', 'ebpf'],
      lockdownTier: 'integrity',
      extraDriverSymbols: ['CONFIG_MLX5_CORE'],
    });

    const bundle = compileCustomKernelArtifacts(spec, SAMPLE_HW);
    expect(bundle.warnings).toHaveLength(0);
    expect(bundle.kconfigFragment).toContain('# CONFIG_SOUND is not set');
    expect(bundle.kconfigFragment).toContain('# CONFIG_WIRELESS is not set');
    expect(bundle.kconfigFragment).toContain('CONFIG_IGC=y');
    expect(bundle.kconfigFragment).toContain('CONFIG_BLK_DEV_NVME=y');
    expect(bundle.kconfigFragment).toContain('CONFIG_MLX5_CORE=y');
    expect(bundle.lsmodSeed).toContain('igc 184320 0 -');
    expect(bundle.cliCommand).toContain('--mode stripped');
    expect(bundle.cliCommand).toContain('--lsmod-file host.lsmod');
    expect(bundle.estimatedModuleStats.estimatedReductionPercent).toBeGreaterThanOrEqual(90);
  });

  it('emits guardrail warnings when confidentiality lockdown conflicts with eBPF or userns is disabled with K3s', () => {
    const spec = CustomKernelBuildSpecSchema.parse({
      mode: 'stripped',
      capabilities: ['k3s', 'zfs', 'ebpf'],
      lockdownTier: 'confidentiality',
      enableRootlessUserNs: false,
      enforceModuleSig: true,
    });

    const bundle = compileCustomKernelArtifacts(spec);
    expect(bundle.warnings.length).toBeGreaterThanOrEqual(4);
    expect(bundle.warnings.some((w) => w.includes('confidentiality'))).toBe(true);
    expect(bundle.warnings.some((w) => w.includes('CONFIG_USER_NS'))).toBe(true);
    expect(bundle.warnings.some((w) => w.includes('CONFIG_MODULE_SIG_FORCE'))).toBe(true);
    expect(bundle.warnings.some((w) => w.includes('no block storage'))).toBe(true);
  });

  it('audits degraded/unhardened kernel config and flags OpenZFS symbol trimming & missing BTF', () => {
    const report = auditKernelPostureAndConfig({
      CONFIG_TRIM_UNUSED_KSYMS: 'y',
      CONFIG_USER_NS: 'n',
      CONFIG_BPF_UNPRIV_DEFAULT_OFF: 'n',
      CONFIG_DEBUG_INFO_BTF: 'n',
    });

    expect(report.totalCount).toBe(24);
    expect(report.failCount).toBeGreaterThan(0);
    expect(report.score).toBeLessThan(50);
    expect(report.checks.find((c) => c.id === 'storage-no-trim-ksyms')?.status).toBe('FAIL');
    expect(report.checks.find((c) => c.id === 'ebpf-core-btf')?.status).toBe('FAIL');
  });

  it('rejects malformed kernel versions and shell injection in extraDriverSymbols', () => {
    expect(() =>
      CustomKernelBuildSpecSchema.parse({
        kernelVersion: '6.12.15; rm -rf /',
      })
    ).toThrow();

    expect(() =>
      CustomKernelBuildSpecSchema.parse({
        extraDriverSymbols: ['CONFIG_NVME=y;id'],
      })
    ).toThrow();
  });
});
