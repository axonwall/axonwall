import {
  CustomKernelBuildSpecSchema,
  type CompiledKernelBundle,
  type CustomKernelBuildSpec,
  type DetectedHardwareProfile,
  type DriverSymbolEntry,
  type KernelAuditCheckResult,
  type KernelAuditPillar,
  type KernelHardeningAuditReport,
} from './schemas.js';

export const DRIVER_TO_KCONFIG_MAP: Record<string, DriverSymbolEntry> = {
  // NVMe / SATA / SCSI / Enterprise Storage HBAs
  nvme: { symbols: ['CONFIG_NVME_CORE', 'CONFIG_BLK_DEV_NVME', 'CONFIG_NVME_MULTIPATH'], category: 'storage', description: 'NVMe PCIe SSD controller', builtInRecommended: true },
  nvme_core: { symbols: ['CONFIG_NVME_CORE', 'CONFIG_BLK_DEV_NVME'], category: 'storage', description: 'NVMe core subsystem', builtInRecommended: true },
  ahci: { symbols: ['CONFIG_ATA', 'CONFIG_SATA_AHCI'], category: 'storage', description: 'AHCI SATA disk controller', builtInRecommended: true },
  libahci: { symbols: ['CONFIG_ATA', 'CONFIG_SATA_AHCI'], category: 'storage', description: 'AHCI SATA core library', builtInRecommended: true },
  sd_mod: { symbols: ['CONFIG_SCSI', 'CONFIG_BLK_DEV_SD'], category: 'storage', description: 'SCSI/SAS/SATA block disk driver', builtInRecommended: true },
  sr_mod: { symbols: ['CONFIG_SCSI', 'CONFIG_BLK_DEV_SR'], category: 'storage', description: 'SCSI CD/DVD optical media driver' },
  mpt3sas: { symbols: ['CONFIG_SCSI', 'CONFIG_BLK_DEV_SD', 'CONFIG_SCSI_MPT3SAS'], category: 'storage', description: 'Broadcom/LSI SAS 3 HBA (IT/JBOD mode)', builtInRecommended: true },
  megaraid_sas: { symbols: ['CONFIG_SCSI', 'CONFIG_BLK_DEV_SD', 'CONFIG_MEGARAID_SAS'], category: 'storage', description: 'Broadcom/LSI MegaRAID SAS controller', builtInRecommended: true },
  smartpqi: { symbols: ['CONFIG_SCSI', 'CONFIG_BLK_DEV_SD', 'CONFIG_SCSI_SMARTPQI'], category: 'storage', description: 'Microchip/HPE SmartRAID PQI HBA', builtInRecommended: true },

  // Hypervisor / Cloud Paravirtualization Drivers
  virtio_pci: { symbols: ['CONFIG_VIRTIO', 'CONFIG_VIRTIO_PCI'], category: 'virt', description: 'VirtIO PCI bus transport', builtInRecommended: true },
  virtio_blk: { symbols: ['CONFIG_VIRTIO_BLK'], category: 'storage', description: 'VirtIO paravirtual block disk', builtInRecommended: true },
  virtio_scsi: { symbols: ['CONFIG_SCSI', 'CONFIG_BLK_DEV_SD', 'CONFIG_SCSI_VIRTIO'], category: 'storage', description: 'VirtIO SCSI disk controller', builtInRecommended: true },
  virtio_net: { symbols: ['CONFIG_VIRTIO_NET'], category: 'network', description: 'VirtIO paravirtual NIC', builtInRecommended: true },
  virtio_console: { symbols: ['CONFIG_VIRTIO_CONSOLE'], category: 'virt', description: 'VirtIO serial console & qemu-ga', builtInRecommended: true },
  virtio_balloon: { symbols: ['CONFIG_VIRTIO_BALLOON'], category: 'virt', description: 'VirtIO memory balloon' },
  vmw_pvscsi: { symbols: ['CONFIG_SCSI', 'CONFIG_VMWARE_PVSCSI'], category: 'storage', description: 'VMware PVSCSI storage adapter', builtInRecommended: true },
  vmxnet3: { symbols: ['CONFIG_VMXNET3'], category: 'network', description: 'VMware VMXNET3 10GbE NIC', builtInRecommended: true },
  hv_vmbus: { symbols: ['CONFIG_HYPERV'], category: 'virt', description: 'Microsoft Hyper-V VMBus', builtInRecommended: true },
  hv_storvsc: { symbols: ['CONFIG_HYPERV_STORAGE'], category: 'storage', description: 'Microsoft Hyper-V synthetic SCSI', builtInRecommended: true },
  hv_netvsc: { symbols: ['CONFIG_HYPERV_NET'], category: 'network', description: 'Microsoft Hyper-V synthetic NIC', builtInRecommended: true },
  ena: { symbols: ['CONFIG_ENA_ETHERNET'], category: 'network', description: 'AWS Elastic Network Adapter (ENA)', builtInRecommended: true },
  gve: { symbols: ['CONFIG_GVE'], category: 'network', description: 'Google Compute Engine gVNIC', builtInRecommended: true },

  // Physical NICs (1GbE -> 100GbE)
  e1000: { symbols: ['CONFIG_NET_VENDOR_INTEL', 'CONFIG_E1000'], category: 'network', description: 'Intel PRO/1000 Gigabit NIC' },
  e1000e: { symbols: ['CONFIG_NET_VENDOR_INTEL', 'CONFIG_E1000E'], category: 'network', description: 'Intel I217/I219 PCIe Gigabit NIC', builtInRecommended: true },
  igb: { symbols: ['CONFIG_NET_VENDOR_INTEL', 'CONFIG_IGB'], category: 'network', description: 'Intel I210/I211/I350 Gigabit NIC', builtInRecommended: true },
  igc: { symbols: ['CONFIG_NET_VENDOR_INTEL', 'CONFIG_IGC'], category: 'network', description: 'Intel I225/I226 2.5GbE NIC', builtInRecommended: true },
  ixgbe: { symbols: ['CONFIG_NET_VENDOR_INTEL', 'CONFIG_IXGBE'], category: 'network', description: 'Intel X520/X540/X550 10GbE NIC', builtInRecommended: true },
  i40e: { symbols: ['CONFIG_NET_VENDOR_INTEL', 'CONFIG_I40E'], category: 'network', description: 'Intel X710/XL710 10/40GbE NIC', builtInRecommended: true },
  ice: { symbols: ['CONFIG_NET_VENDOR_INTEL', 'CONFIG_ICE'], category: 'network', description: 'Intel E810 25/100GbE NIC', builtInRecommended: true },
  idpf: { symbols: ['CONFIG_NET_VENDOR_INTEL', 'CONFIG_IDPF'], category: 'network', description: 'Intel Infrastructure Data Path NIC' },
  mlx4_core: { symbols: ['CONFIG_NET_VENDOR_MELLANOX', 'CONFIG_MLX4_CORE', 'CONFIG_MLX4_EN'], category: 'network', description: 'NVIDIA/Mellanox ConnectX-3 core' },
  mlx4_en: { symbols: ['CONFIG_NET_VENDOR_MELLANOX', 'CONFIG_MLX4_CORE', 'CONFIG_MLX4_EN'], category: 'network', description: 'NVIDIA/Mellanox ConnectX-3 Ethernet' },
  mlx5_core: { symbols: ['CONFIG_NET_VENDOR_MELLANOX', 'CONFIG_MLX5_CORE', 'CONFIG_MLX5_CORE_EN', 'CONFIG_PAGE_POOL'], category: 'network', description: 'NVIDIA/Mellanox ConnectX-5/6/7 25/100GbE NIC', builtInRecommended: true },
  r8169: { symbols: ['CONFIG_NET_VENDOR_REALTEK', 'CONFIG_R8169'], category: 'network', description: 'Realtek RTL8111/RTL8125 1/2.5GbE NIC', builtInRecommended: true },
  r8152: { symbols: ['CONFIG_USB_NET_DRIVERS', 'CONFIG_USB_RTL8152'], category: 'network', description: 'Realtek RTL8152/8156 USB Ethernet' },
  bnxt_en: { symbols: ['CONFIG_NET_VENDOR_BROADCOM', 'CONFIG_BNXT'], category: 'network', description: 'Broadcom NetXtreme-C/E 25/100GbE NIC', builtInRecommended: true },
  bnx2x: { symbols: ['CONFIG_NET_VENDOR_BROADCOM', 'CONFIG_BNX2X'], category: 'network', description: 'Broadcom NetXtreme II 10GbE NIC' },
  tg3: { symbols: ['CONFIG_NET_VENDOR_BROADCOM', 'CONFIG_TIGON3'], category: 'network', description: 'Broadcom Tigon3 Gigabit NIC' },
  atlantic: { symbols: ['CONFIG_NET_VENDOR_AQUANTIA', 'CONFIG_AQTION'], category: 'network', description: 'Marvell/Aquantia AQtion 10GbE NIC' },

  // USB, TPM, Watchdog & Thermal Sensors
  xhci_pci: { symbols: ['CONFIG_USB', 'CONFIG_USB_XHCI_HCD', 'CONFIG_USB_XHCI_PCI'], category: 'platform', description: 'USB 3.x xHCI PCI host controller', builtInRecommended: true },
  xhci_hcd: { symbols: ['CONFIG_USB', 'CONFIG_USB_XHCI_HCD'], category: 'platform', description: 'USB 3.x xHCI core driver', builtInRecommended: true },
  ehci_pci: { symbols: ['CONFIG_USB', 'CONFIG_USB_EHCI_HCD', 'CONFIG_USB_EHCI_PCI'], category: 'platform', description: 'USB 2.0 EHCI PCI host controller' },
  usbhid: { symbols: ['CONFIG_HID', 'CONFIG_USB_HID'], category: 'platform', description: 'USB HID console keyboard/mouse' },
  usb_storage: { symbols: ['CONFIG_USB_STORAGE'], category: 'storage', description: 'USB mass storage installer media' },
  uas: { symbols: ['CONFIG_USB_UAS'], category: 'storage', description: 'USB Attached SCSI' },
  tpm_tis: { symbols: ['CONFIG_TCG_TPM', 'CONFIG_TCG_TIS'], category: 'security', description: 'TPM 2.0 TIS hardware module', builtInRecommended: true },
  tpm_crb: { symbols: ['CONFIG_TCG_TPM', 'CONFIG_TCG_CRB'], category: 'security', description: 'TPM 2.0 Command Response Buffer', builtInRecommended: true },
  iTCO_wdt: { symbols: ['CONFIG_WATCHDOG', 'CONFIG_WATCHDOG_CORE', 'CONFIG_ITCO_WDT'], category: 'platform', description: 'Intel iTCO hardware watchdog timer' },
  sp5100_tco: { symbols: ['CONFIG_WATCHDOG', 'CONFIG_WATCHDOG_CORE', 'CONFIG_SP5100_TCO'], category: 'platform', description: 'AMD SP5100 hardware watchdog timer' },
  softdog: { symbols: ['CONFIG_WATCHDOG', 'CONFIG_WATCHDOG_CORE', 'CONFIG_SOFT_WATCHDOG'], category: 'platform', description: 'Kernel software fallback watchdog' },
  coretemp: { symbols: ['CONFIG_HWMON', 'CONFIG_SENSORS_CORETEMP'], category: 'telemetry', description: 'Intel CPU package/core temperature sensor' },
  k10temp: { symbols: ['CONFIG_HWMON', 'CONFIG_SENSORS_K10TEMP'], category: 'telemetry', description: 'AMD Ryzen/EPYC thermal sensor' },
  nct6775: { symbols: ['CONFIG_HWMON', 'CONFIG_SENSORS_NCT6775'], category: 'telemetry', description: 'Nuvoton Super-I/O fan & voltage sensor' },

  // Virtualization & Passthrough
  kvm: { symbols: ['CONFIG_KVM'], category: 'virt', description: 'KVM hardware hypervisor core' },
  kvm_intel: { symbols: ['CONFIG_KVM', 'CONFIG_KVM_INTEL'], category: 'virt', description: 'Intel VT-x KVM hypervisor' },
  kvm_amd: { symbols: ['CONFIG_KVM', 'CONFIG_KVM_AMD'], category: 'virt', description: 'AMD-V / SEV KVM hypervisor' },
  vfio: { symbols: ['CONFIG_VFIO'], category: 'virt', description: 'VFIO direct PCIe passthrough core' },
  vfio_pci: { symbols: ['CONFIG_VFIO', 'CONFIG_VFIO_PCI'], category: 'virt', description: 'VFIO PCIe device passthrough' },
  vhost_net: { symbols: ['CONFIG_VHOST_NET'], category: 'virt', description: 'Kernel vhost-net acceleration' },
  vhost_vsock: { symbols: ['CONFIG_VSOCKETS', 'CONFIG_VHOST_VSOCK'], category: 'virt', description: 'VirtIO vhost vsock host transport' },

  // RAID / DM / Filesystems / Storage Targets
  dm_mod: { symbols: ['CONFIG_MD', 'CONFIG_BLK_DEV_DM'], category: 'storage', description: 'Device Mapper core', builtInRecommended: true },
  dm_crypt: { symbols: ['CONFIG_BLK_DEV_DM', 'CONFIG_DM_CRYPT'], category: 'storage', description: 'LUKS2 dm-crypt disk encryption', builtInRecommended: true },
  dm_thin_pool: { symbols: ['CONFIG_BLK_DEV_DM', 'CONFIG_DM_THIN_PROVISIONING'], category: 'storage', description: 'Device Mapper thin provisioning' },
  md_mod: { symbols: ['CONFIG_MD', 'CONFIG_BLK_DEV_MD'], category: 'storage', description: 'Linux mdadm software RAID', builtInRecommended: true },
  raid0: { symbols: ['CONFIG_BLK_DEV_MD', 'CONFIG_MD_RAID0'], category: 'storage', description: 'mdadm RAID-0 striping' },
  raid1: { symbols: ['CONFIG_BLK_DEV_MD', 'CONFIG_MD_RAID1'], category: 'storage', description: 'mdadm RAID-1 mirroring', builtInRecommended: true },
  raid10: { symbols: ['CONFIG_BLK_DEV_MD', 'CONFIG_MD_RAID10'], category: 'storage', description: 'mdadm RAID-10 array' },
  raid456: { symbols: ['CONFIG_BLK_DEV_MD', 'CONFIG_MD_RAID456'], category: 'storage', description: 'mdadm RAID-5/6 parity' },
  zfs: { symbols: ['CONFIG_ZLIB_INFLATE', 'CONFIG_ZLIB_DEFLATE', 'CONFIG_KALLSYMS'], category: 'storage', description: 'OpenZFS out-of-tree DKMS kernel module', builtInRecommended: true },
  spl: { symbols: ['CONFIG_KALLSYMS', 'CONFIG_ZLIB_DEFLATE'], category: 'storage', description: 'OpenZFS Solaris Porting Layer', builtInRecommended: true },
  ext4: { symbols: ['CONFIG_EXT4_FS', 'CONFIG_EXT4_FS_POSIX_ACL', 'CONFIG_EXT4_FS_SECURITY'], category: 'filesystem', description: 'ext4 root/data filesystem', builtInRecommended: true },
  xfs: { symbols: ['CONFIG_XFS_FS', 'CONFIG_XFS_POSIX_ACL'], category: 'filesystem', description: 'XFS OpenEBS/high-IOPS filesystem', builtInRecommended: true },
  btrfs: { symbols: ['CONFIG_BTRFS_FS'], category: 'filesystem', description: 'Btrfs filesystem' },
  overlay: { symbols: ['CONFIG_OVERLAY_FS'], category: 'containers', description: 'OverlayFS container image layering', builtInRecommended: true },
  fuse: { symbols: ['CONFIG_FUSE_FS'], category: 'filesystem', description: 'Userspace FUSE filesystem' },
  vfat: { symbols: ['CONFIG_FAT_FS', 'CONFIG_VFAT_FS'], category: 'filesystem', description: 'EFI System Partition FAT32 filesystem', builtInRecommended: true },
  iso9660: { symbols: ['CONFIG_ISO9660_FS', 'CONFIG_JOLIET', 'CONFIG_ZISOFS'], category: 'filesystem', description: 'ISO9660 cloud-init seed & optical filesystem' },
  iscsi_tcp: { symbols: ['CONFIG_ISCSI_TCP', 'CONFIG_SCSI_ISCSI_ATTRS'], category: 'storage', description: 'iSCSI initiator over TCP' },
  nfsd: { symbols: ['CONFIG_NFSD', 'CONFIG_NFSD_V4'], category: 'storage', description: 'Kernel NFSv4 server' },
  nfs: { symbols: ['CONFIG_NFS_FS', 'CONFIG_NFS_V4'], category: 'storage', description: 'Kernel NFSv4 client' },

  // Networking, nftables & Containers
  wireguard: { symbols: ['CONFIG_WIREGUARD'], category: 'network', description: 'WireGuard kernel VPN', builtInRecommended: true },
  nf_tables: { symbols: ['CONFIG_NETFILTER', 'CONFIG_NF_TABLES', 'CONFIG_NF_TABLES_INET'], category: 'firewall', description: 'nftables packet classification core', builtInRecommended: true },
  nft_chain_nat: { symbols: ['CONFIG_NF_NAT', 'CONFIG_NFT_NAT'], category: 'firewall', description: 'nftables NAT chains', builtInRecommended: true },
  nft_ct: { symbols: ['CONFIG_NF_CONNTRACK', 'CONFIG_NFT_CT'], category: 'firewall', description: 'nftables stateful connection tracking', builtInRecommended: true },
  nft_fib_inet: { symbols: ['CONFIG_NFT_FIB', 'CONFIG_NFT_FIB_INET', 'CONFIG_NFT_FIB_IPV4', 'CONFIG_NFT_FIB_IPV6'], category: 'firewall', description: 'nftables RPF/FIB reverse-path lookup', builtInRecommended: true },
  nft_flow_offload: { symbols: ['CONFIG_NF_FLOW_TABLE', 'CONFIG_NF_FLOW_TABLE_INET', 'CONFIG_NFT_FLOW_OFFLOAD'], category: 'firewall', description: 'nftables fastpath flowtable offload', builtInRecommended: true },
  nf_flow_table: { symbols: ['CONFIG_NF_FLOW_TABLE', 'CONFIG_NF_FLOW_TABLE_INET'], category: 'firewall', description: 'Netfilter fastpath flowtable core', builtInRecommended: true },
  br_netfilter: { symbols: ['CONFIG_BRIDGE', 'CONFIG_BRIDGE_NETFILTER'], category: 'containers', description: 'Bridge netfilter hooks for K8s CNI' },
  vxlan: { symbols: ['CONFIG_VXLAN'], category: 'containers', description: 'VXLAN overlay networking (Flannel/Cilium)' },
  geneve: { symbols: ['CONFIG_GENEVE'], category: 'containers', description: 'Geneve overlay encapsulation' },
  ip_vs: { symbols: ['CONFIG_IP_VS', 'CONFIG_IP_VS_NFCT', 'CONFIG_IP_VS_RR'], category: 'containers', description: 'IPVS K8s Service load balancing' },
  '8021q': { symbols: ['CONFIG_VLAN_8021Q'], category: 'network', description: 'IEEE 802.1Q VLAN tagging', builtInRecommended: true },
  bonding: { symbols: ['CONFIG_BONDING'], category: 'network', description: 'IEEE 802.3ad LACP link aggregation' },
  tun: { symbols: ['CONFIG_TUN'], category: 'network', description: 'TUN/TAP virtual tunnel interfaces', builtInRecommended: true },
  vrf: { symbols: ['CONFIG_NET_VRF'], category: 'network', description: 'Linux Virtual Routing and Forwarding' },
};

function normalizeDriverKey(raw: string): string {
  return raw.trim().replace(/-/g, '_');
}

export interface ResolvedHardwareSymbols {
  symbols: Record<string, 'y' | 'm'>;
  retainedDrivers: Array<{
    driver: string;
    category: string;
    description: string;
    symbols: string[];
    source: string;
  }>;
}

export function resolveHardwareKconfigSymbols(hw: DetectedHardwareProfile): ResolvedHardwareSymbols {
  const symbols: Record<string, 'y' | 'm'> = {
    CONFIG_64BIT: 'y',
    CONFIG_SMP: 'y',
    CONFIG_PCI: 'y',
    CONFIG_ACPI: 'y',
    CONFIG_MICROCODE: 'y',
  };
  const retainedMap = new Map<
    string,
    { driver: string; category: string; description: string; symbols: string[]; sources: Set<string> }
  >();

  const addDriver = (rawDriver: string, source: string, preferBuiltIn = false) => {
    const driver = rawDriver.trim();
    if (!driver || driver === 'none') return;
    const key = normalizeDriverKey(driver);
    const entry = DRIVER_TO_KCONFIG_MAP[key] || DRIVER_TO_KCONFIG_MAP[driver];
    if (!entry) return;
    const mode: 'y' | 'm' = preferBuiltIn || entry.builtInRecommended ? 'y' : 'm';
    for (const sym of entry.symbols) {
      if (symbols[sym] !== 'y') {
        symbols[sym] = mode;
      }
    }
    const existing = retainedMap.get(key);
    if (existing) {
      existing.sources.add(source);
    } else {
      retainedMap.set(key, {
        driver,
        category: entry.category,
        description: entry.description,
        symbols: [...entry.symbols],
        sources: new Set([source]),
      });
    }
  };

  // CPU / Firmware / IOMMU / Crypto
  const cpuLower = `${hw.cpuVendor} ${hw.cpuModel}`.toLowerCase();
  if (cpuLower.includes('intel')) {
    symbols.CONFIG_MICROCODE_INTEL = 'y';
    symbols.CONFIG_CPU_SUP_INTEL = 'y';
    symbols.CONFIG_CRYPTO_AES_NI_INTEL = 'm';
    if (hw.iommuActive) {
      symbols.CONFIG_INTEL_IOMMU = 'y';
      symbols.CONFIG_IRQ_REMAP = 'y';
    }
  }
  if (cpuLower.includes('amd')) {
    symbols.CONFIG_MICROCODE_AMD = 'y';
    symbols.CONFIG_CPU_SUP_AMD = 'y';
    symbols.CONFIG_CRYPTO_AES_NI_INTEL = 'm';
    if (hw.iommuActive) {
      symbols.CONFIG_AMD_IOMMU = 'y';
      symbols.CONFIG_IRQ_REMAP = 'y';
    }
  }
  if (hw.efiBooted) {
    symbols.CONFIG_EFI = 'y';
    symbols.CONFIG_EFI_STUB = 'y';
    symbols.CONFIG_EFIVAR_FS = 'y';
    symbols.CONFIG_VFAT_FS = 'y';
  }
  if (hw.tpmDevices.length > 0) {
    symbols.CONFIG_TCG_TPM = 'y';
    symbols.CONFIG_TCG_TIS = 'y';
    symbols.CONFIG_TCG_CRB = 'y';
  }
  for (const wdt of hw.watchdogDrivers) {
    addDriver(wdt, `watchdog:${wdt}`, false);
  }
  for (const pci of hw.pciDevices) {
    if (pci.driver && pci.driver !== 'none') {
      addDriver(pci.driver, `pci:${pci.bdf}`, pci.deviceClass.startsWith('01') || pci.deviceClass.startsWith('02'));
    }
    if (pci.module) {
      addDriver(pci.module, `pci-mod:${pci.bdf}`);
    }
  }
  for (const blk of hw.storageControllers) {
    addDriver(blk.driver, `block:${blk.name}`, true);
  }
  for (const nic of hw.networkInterfaces) {
    addDriver(nic.driver, `net:${nic.name}`, true);
  }
  for (const mod of hw.loadedModules) {
    addDriver(mod.name, 'lsmod');
  }

  return {
    symbols,
    retainedDrivers: Array.from(retainedMap.values())
      .map((item) => ({
        driver: item.driver,
        category: item.category,
        description: item.description,
        symbols: item.symbols,
        source: Array.from(item.sources).slice(0, 3).join(', '),
      }))
      .sort((a, b) => a.category.localeCompare(b.category) || a.driver.localeCompare(b.driver)),
  };
}

interface AuditRuleSpec {
  id: string;
  pillar: KernelAuditPillar;
  label: string;
  symbol: string;
  expected: string;
  severityOnFail: 'FAIL' | 'WARN';
  check: (cfg: Record<string, string>, live?: LiveAuditPosture) => { ok: boolean; warn?: boolean; actual: string };
  rationale: string;
}

export interface LiveAuditPosture {
  lockdownMode?: string;
  activeLsms?: string[];
  unprivilegedBpfDisabled?: string;
  bpfJitHarden?: string;
  userNsCloneAllowed?: boolean;
}

const AUDIT_RULES: AuditRuleSpec[] = [
  // Pillar 1: KSPP Memory & Control-Flow Hardening
  {
    id: 'kspp-lockdown-integrity',
    pillar: 'kspp_memory',
    label: 'Kernel Lockdown LSM (Integrity)',
    symbol: 'CONFIG_SECURITY_LOCKDOWN_LSM',
    expected: 'y (integrity mode)',
    severityOnFail: 'FAIL',
    check: (cfg, live) => {
      const val = cfg.CONFIG_SECURITY_LOCKDOWN_LSM;
      const mode = live?.lockdownMode;
      if (val === 'y' && mode === 'confidentiality') {
        return { ok: false, warn: true, actual: 'y (confidentiality — breaks CO-RE eBPF)' };
      }
      if (val === 'y' || mode === 'integrity') {
        return { ok: true, actual: mode ? `y (${mode})` : 'y' };
      }
      return { ok: false, actual: val || mode || 'unset' };
    },
    rationale: 'Integrity lockdown blocks unsigned kernel code injection while preserving CO-RE eBPF kernel memory reads.',
  },
  {
    id: 'kspp-slab-random',
    pillar: 'kspp_memory',
    label: 'SLAB Freelist Randomization',
    symbol: 'CONFIG_SLAB_FREELIST_RANDOM',
    expected: 'y',
    severityOnFail: 'FAIL',
    check: (cfg) => ({ ok: cfg.CONFIG_SLAB_FREELIST_RANDOM === 'y', actual: cfg.CONFIG_SLAB_FREELIST_RANDOM || 'unset' }),
    rationale: 'Randomizes slab freelist order to defeat deterministic heap-spraying kernel exploits (KSPP).',
  },
  {
    id: 'kspp-slab-hardened',
    pillar: 'kspp_memory',
    label: 'SLAB Freelist Metadata Hardening',
    symbol: 'CONFIG_SLAB_FREELIST_HARDENED',
    expected: 'y',
    severityOnFail: 'FAIL',
    check: (cfg) => ({ ok: cfg.CONFIG_SLAB_FREELIST_HARDENED === 'y', actual: cfg.CONFIG_SLAB_FREELIST_HARDENED || 'unset' }),
    rationale: 'Obfuscates slab freelist pointers and checks double-frees inside SLUB.',
  },
  {
    id: 'kspp-shuffle-page',
    pillar: 'kspp_memory',
    label: 'Page Allocator Freelist Shuffling',
    symbol: 'CONFIG_SHUFFLE_PAGE_ALLOCATOR',
    expected: 'y',
    severityOnFail: 'WARN',
    check: (cfg) => ({ ok: cfg.CONFIG_SHUFFLE_PAGE_ALLOCATOR === 'y', actual: cfg.CONFIG_SHUFFLE_PAGE_ALLOCATOR || 'unset' }),
    rationale: 'Randomizes buddy page allocation order to prevent predictable page-feng-shui attacks.',
  },
  {
    id: 'kspp-init-on-alloc',
    pillar: 'kspp_memory',
    label: 'Zero Memory on Allocation',
    symbol: 'CONFIG_INIT_ON_ALLOC_DEFAULT_ON',
    expected: 'y',
    severityOnFail: 'WARN',
    check: (cfg) => ({ ok: cfg.CONFIG_INIT_ON_ALLOC_DEFAULT_ON === 'y', actual: cfg.CONFIG_INIT_ON_ALLOC_DEFAULT_ON || 'unset' }),
    rationale: 'Zeros heap/page allocations by default, eliminating uninitialized-stack/heap info leaks.',
  },
  {
    id: 'kspp-stackprotector',
    pillar: 'kspp_memory',
    label: 'Strong Kernel Stack Protector',
    symbol: 'CONFIG_STACKPROTECTOR_STRONG',
    expected: 'y',
    severityOnFail: 'FAIL',
    check: (cfg) => ({ ok: cfg.CONFIG_STACKPROTECTOR_STRONG === 'y', actual: cfg.CONFIG_STACKPROTECTOR_STRONG || 'unset' }),
    rationale: 'Inserts stack canaries on vulnerable kernel functions against stack buffer overflows.',
  },
  {
    id: 'kspp-fortify',
    pillar: 'kspp_memory',
    label: 'FORTIFY_SOURCE Bounds Checking',
    symbol: 'CONFIG_FORTIFY_SOURCE',
    expected: 'y',
    severityOnFail: 'FAIL',
    check: (cfg) => ({ ok: cfg.CONFIG_FORTIFY_SOURCE === 'y', actual: cfg.CONFIG_FORTIFY_SOURCE || 'unset' }),
    rationale: 'Detects compile-time and runtime memcpy/strcpy overflows across kernel buffers.',
  },
  {
    id: 'kspp-module-sig',
    pillar: 'kspp_memory',
    label: 'Cryptographic Kernel Module Signing',
    symbol: 'CONFIG_MODULE_SIG',
    expected: 'y',
    severityOnFail: 'WARN',
    check: (cfg) => ({ ok: cfg.CONFIG_MODULE_SIG === 'y', actual: cfg.CONFIG_MODULE_SIG || 'unset' }),
    rationale: 'Signs compiled kernel modules and OpenZFS kmods with SHA-512 (Talos/CoreOS best practice).',
  },

  // Pillar 2: Attack Surface Stripping
  {
    id: 'surface-vsyscall-none',
    pillar: 'attack_surface',
    label: 'Legacy vsyscall Page Disabled',
    symbol: 'CONFIG_LEGACY_VSYSCALL_NONE',
    expected: 'y',
    severityOnFail: 'WARN',
    check: (cfg) => ({ ok: cfg.CONFIG_LEGACY_VSYSCALL_NONE === 'y', actual: cfg.CONFIG_LEGACY_VSYSCALL_NONE || 'unset' }),
    rationale: 'Removes fixed-address legacy vsyscall ROP gadgets in userspace.',
  },
  {
    id: 'surface-kexec-off',
    pillar: 'attack_surface',
    label: 'kexec Kernel Replacement Disabled',
    symbol: 'CONFIG_KEXEC',
    expected: 'n',
    severityOnFail: 'WARN',
    check: (cfg) => {
      const val = cfg.CONFIG_KEXEC;
      return { ok: val === 'n' || val === undefined || val === 'not set', actual: val || 'unset (disabled)' };
    },
    rationale: 'Prevents runtime replacement of the running signed kernel from root userspace.',
  },
  {
    id: 'surface-dccp-rds-off',
    pillar: 'attack_surface',
    label: 'Legacy DCCP & RDS Sockets Disabled',
    symbol: 'CONFIG_IP_DCCP',
    expected: 'n',
    severityOnFail: 'WARN',
    check: (cfg) => {
      const dccp = cfg.CONFIG_IP_DCCP;
      const rds = cfg.CONFIG_RDS;
      const ok = (!dccp || dccp === 'n') && (!rds || rds === 'n');
      return { ok, actual: `DCCP=${dccp || 'n'}, RDS=${rds || 'n'}` };
    },
    rationale: 'Eliminates historic privilege-escalation CVE surfaces in unused network protocols.',
  },

  // Pillar 3: Kubernetes (K3s) & Rootless Containers
  {
    id: 'k3s-userns',
    pillar: 'k3s_containers',
    label: 'User Namespaces (Rootless Containers)',
    symbol: 'CONFIG_USER_NS',
    expected: 'y (clone=1)',
    severityOnFail: 'FAIL',
    check: (cfg, live) => {
      const enabled = cfg.CONFIG_USER_NS === 'y';
      if (enabled && live?.userNsCloneAllowed === false) {
        return { ok: false, warn: true, actual: 'y (unprivileged_userns_clone=0 — breaks rootless)' };
      }
      return { ok: enabled, actual: enabled ? 'y' : cfg.CONFIG_USER_NS || 'unset' };
    },
    rationale: 'Required for rootless Podman/containerd, K3s user-namespace isolation, and BPF_TOKEN delegation.',
  },
  {
    id: 'k3s-cgroups',
    pillar: 'k3s_containers',
    label: 'Cgroup v2 & MEMCG / CGROUP_BPF',
    symbol: 'CONFIG_CGROUP_BPF',
    expected: 'y',
    severityOnFail: 'FAIL',
    check: (cfg) => {
      const ok = cfg.CONFIG_CGROUPS === 'y' && cfg.CONFIG_MEMCG === 'y' && cfg.CONFIG_CGROUP_BPF === 'y';
      return { ok, actual: `CGROUPS=${cfg.CONFIG_CGROUPS || '?'} MEMCG=${cfg.CONFIG_MEMCG || '?'} CGROUP_BPF=${cfg.CONFIG_CGROUP_BPF || '?'}` };
    },
    rationale: 'Essential for K3s/kubelet resource accounting and eBPF cgroup socket policies.',
  },
  {
    id: 'k3s-overlayfs',
    pillar: 'k3s_containers',
    label: 'OverlayFS Container Rootfs',
    symbol: 'CONFIG_OVERLAY_FS',
    expected: 'y or m',
    severityOnFail: 'FAIL',
    check: (cfg) => ({
      ok: cfg.CONFIG_OVERLAY_FS === 'y' || cfg.CONFIG_OVERLAY_FS === 'm',
      actual: cfg.CONFIG_OVERLAY_FS || 'unset',
    }),
    rationale: 'Primary containerd snapshotter filesystem used by K3s and rootless OCI runtimes.',
  },
  {
    id: 'k3s-seccomp',
    pillar: 'k3s_containers',
    label: 'Seccomp BPF Syscall Filtering',
    symbol: 'CONFIG_SECCOMP_FILTER',
    expected: 'y',
    severityOnFail: 'FAIL',
    check: (cfg) => ({ ok: cfg.CONFIG_SECCOMP_FILTER === 'y', actual: cfg.CONFIG_SECCOMP_FILTER || 'unset' }),
    rationale: 'Enforces per-pod seccomp RuntimeDefault profiles in K3s and containerd.',
  },
  {
    id: 'k3s-cni-veth-bridge',
    pillar: 'k3s_containers',
    label: 'Pod CNI Networking (veth / bridge / VXLAN)',
    symbol: 'CONFIG_VETH',
    expected: 'y or m',
    severityOnFail: 'FAIL',
    check: (cfg) => {
      const veth = cfg.CONFIG_VETH === 'y' || cfg.CONFIG_VETH === 'm';
      const br = cfg.CONFIG_BRIDGE === 'y' || cfg.CONFIG_BRIDGE === 'm';
      return { ok: veth && br, actual: `VETH=${cfg.CONFIG_VETH || '?'} BRIDGE=${cfg.CONFIG_BRIDGE || '?'}` };
    },
    rationale: 'Required by Flannel, Cilium, and Kube-router pod network namespaces.',
  },

  // Pillar 4: OpenZFS & Storage Stack
  {
    id: 'storage-no-trim-ksyms',
    pillar: 'storage_zfs',
    label: 'OpenZFS Symbol Preservation (No KSYM Trim)',
    symbol: 'CONFIG_TRIM_UNUSED_KSYMS',
    expected: 'n',
    severityOnFail: 'FAIL',
    check: (cfg) => {
      const val = cfg.CONFIG_TRIM_UNUSED_KSYMS;
      return { ok: val !== 'y', actual: val === 'y' ? 'y (BREAKS OpenZFS DKMS!)' : val || 'n' };
    },
    rationale: 'CONFIG_TRIM_UNUSED_KSYMS=y strips exported kernel symbols required by out-of-tree OpenZFS kmods.',
  },
  {
    id: 'storage-dm-crypt',
    pillar: 'storage_zfs',
    label: 'LUKS2 Device-Mapper Encryption & RAID',
    symbol: 'CONFIG_DM_CRYPT',
    expected: 'y or m',
    severityOnFail: 'WARN',
    check: (cfg) => ({
      ok: cfg.CONFIG_DM_CRYPT === 'y' || cfg.CONFIG_DM_CRYPT === 'm',
      actual: cfg.CONFIG_DM_CRYPT || 'unset',
    }),
    rationale: 'Supports encrypted swap/volumes alongside OpenZFS native encryption and mdadm RAID.',
  },
  {
    id: 'storage-xfs-ext4',
    pillar: 'storage_zfs',
    label: 'XFS & ext4 Filesystems (OpenEBS Hostpath)',
    symbol: 'CONFIG_XFS_FS',
    expected: 'y or m',
    severityOnFail: 'WARN',
    check: (cfg) => ({
      ok: (cfg.CONFIG_XFS_FS === 'y' || cfg.CONFIG_XFS_FS === 'm') && (cfg.CONFIG_EXT4_FS === 'y' || cfg.CONFIG_EXT4_FS === 'm'),
      actual: `XFS=${cfg.CONFIG_XFS_FS || '?'} EXT4=${cfg.CONFIG_EXT4_FS || '?'}`,
    }),
    rationale: 'Supports root OS, EFI boot, ZFS zvol formatting, and OpenEBS local PersistentVolumes.',
  },

  // Pillar 5: nftables NGFW & eBPF CO-RE Observability
  {
    id: 'net-nftables-flow',
    pillar: 'nftables_ebpf',
    label: 'nftables + Fastpath Flowtable Offload',
    symbol: 'CONFIG_NFT_FLOW_OFFLOAD',
    expected: 'y or m',
    severityOnFail: 'FAIL',
    check: (cfg) => ({
      ok: (cfg.CONFIG_NF_TABLES === 'y' || cfg.CONFIG_NF_TABLES === 'm') && (cfg.CONFIG_NFT_FLOW_OFFLOAD === 'y' || cfg.CONFIG_NFT_FLOW_OFFLOAD === 'm'),
      actual: `NF_TABLES=${cfg.CONFIG_NF_TABLES || '?'} FLOW_OFFLOAD=${cfg.CONFIG_NFT_FLOW_OFFLOAD || '?'}`,
    }),
    rationale: 'Powers Axonwall firewall rulesets, NAT, and line-rate hardware/software flowtable offload.',
  },
  {
    id: 'net-wireguard',
    pillar: 'nftables_ebpf',
    label: 'Kernel WireGuard Mesh VPN',
    symbol: 'CONFIG_WIREGUARD',
    expected: 'y or m',
    severityOnFail: 'WARN',
    check: (cfg) => ({
      ok: cfg.CONFIG_WIREGUARD === 'y' || cfg.CONFIG_WIREGUARD === 'm',
      actual: cfg.CONFIG_WIREGUARD || 'unset',
    }),
    rationale: 'Enables K3s Flannel WireGuard encryption and Headscale/Rosenpass mesh tunnels.',
  },
  {
    id: 'ebpf-unpriv-off',
    pillar: 'nftables_ebpf',
    label: 'Unprivileged eBPF Syscall Blocked',
    symbol: 'CONFIG_BPF_UNPRIV_DEFAULT_OFF',
    expected: 'y',
    severityOnFail: 'FAIL',
    check: (cfg, live) => {
      const ok = cfg.CONFIG_BPF_UNPRIV_DEFAULT_OFF === 'y' || live?.unprivilegedBpfDisabled === '1' || live?.unprivilegedBpfDisabled === '2';
      return { ok, actual: cfg.CONFIG_BPF_UNPRIV_DEFAULT_OFF || (live?.unprivilegedBpfDisabled ? `sysctl=${live.unprivilegedBpfDisabled}` : 'unset') };
    },
    rationale: 'Mitigates unprivileged BPF verifier/JIT exploits while permitting CAP_BPF & BPF_TOKEN workloads.',
  },
  {
    id: 'ebpf-core-btf',
    pillar: 'nftables_ebpf',
    label: 'eBPF CO-RE BTF Type Information',
    symbol: 'CONFIG_DEBUG_INFO_BTF',
    expected: 'y',
    severityOnFail: 'FAIL',
    check: (cfg) => ({ ok: cfg.CONFIG_DEBUG_INFO_BTF === 'y', actual: cfg.CONFIG_DEBUG_INFO_BTF || 'unset' }),
    rationale: 'Exposes /sys/kernel/btf/vmlinux required by Axonwall XDP, BPF-LSM, Cilium, and Tetragon.',
  },
  {
    id: 'ebpf-bpf-lsm',
    pillar: 'nftables_ebpf',
    label: 'CO-RE BPF-LSM Security Hooks',
    symbol: 'CONFIG_BPF_LSM',
    expected: 'y',
    severityOnFail: 'FAIL',
    check: (cfg, live) => {
      const hasLsm = Boolean(live?.activeLsms?.includes('bpf'));
      const ok = cfg.CONFIG_BPF_LSM === 'y' && (!live?.activeLsms || hasLsm);
      return {
        ok,
        warn: cfg.CONFIG_BPF_LSM === 'y' && Boolean(live?.activeLsms) && !hasLsm,
        actual: cfg.CONFIG_BPF_LSM === 'y' ? (hasLsm ? 'y (active in /sys/kernel/security/lsm)' : 'y (not active in boot cmdline)') : cfg.CONFIG_BPF_LSM || 'unset',
      };
    },
    rationale: 'Enables Ghost-in-the-Ring Ring-0 BPF-LSM guards (io_uring SQPOLL, BPF token policy, AF_ALG).',
  },
];

export function auditKernelPostureAndConfig(
  configMap: Record<string, string>,
  livePosture?: LiveAuditPosture,
  configSource = ''
): KernelHardeningAuditReport {
  const checks: KernelAuditCheckResult[] = [];
  let passedCount = 0;
  let warnCount = 0;
  let failCount = 0;

  for (const rule of AUDIT_RULES) {
    const res = rule.check(configMap, livePosture);
    let status: 'PASS' | 'WARN' | 'FAIL' = 'PASS';
    if (!res.ok) {
      status = res.warn || rule.severityOnFail === 'WARN' ? 'WARN' : 'FAIL';
    }
    if (status === 'PASS') passedCount += 1;
    else if (status === 'WARN') warnCount += 1;
    else failCount += 1;

    checks.push({
      id: rule.id,
      pillar: rule.pillar,
      label: rule.label,
      symbol: rule.symbol,
      expected: rule.expected,
      actual: res.actual,
      status,
      rationale: rule.rationale,
    });
  }

  const totalCount = checks.length;
  const weightedPoints = passedCount + warnCount * 0.5;
  const score = totalCount > 0 ? Math.round((weightedPoints / totalCount) * 100) : 0;

  return {
    score,
    passedCount,
    warnCount,
    failCount,
    totalCount,
    configSource,
    checks,
  };
}

export function compileCustomKernelArtifacts(
  rawSpec: CustomKernelBuildSpec,
  hw?: DetectedHardwareProfile
): CompiledKernelBundle {
  const spec = CustomKernelBuildSpecSchema.parse(rawSpec);
  const warnings: string[] = [];
  const symbols: Record<string, string> = {};

  // 1. Base / Hardware Symbols
  let retainedDrivers: CompiledKernelBundle['retainedDrivers'] = [];
  if (hw) {
    const resolved = resolveHardwareKconfigSymbols(hw);
    Object.assign(symbols, resolved.symbols);
    retainedDrivers = resolved.retainedDrivers;
  }

  for (const extraSym of spec.extraDriverSymbols) {
    symbols[extraSym] = 'y';
    retainedDrivers.push({
      driver: extraSym.replace(/^CONFIG_/, '').toLowerCase(),
      category: 'pinned',
      description: 'Manually pinned Kconfig hardware driver symbol',
      symbols: [extraSym],
      source: 'user-pin',
    });
  }

  if (spec.mode === 'universal') {
    Object.assign(symbols, {
      CONFIG_64BIT: 'y',
      CONFIG_MODULES: 'y',
      CONFIG_MODULE_UNLOAD: 'y',
      CONFIG_SMP: 'y',
      CONFIG_NUMA: 'y',
      CONFIG_ACPI: 'y',
      CONFIG_EFI: 'y',
      CONFIG_EFI_STUB: 'y',
      CONFIG_EFIVAR_FS: 'y',
      CONFIG_PCI: 'y',
      CONFIG_PCIEPORTBUS: 'y',
      CONFIG_INTEL_IOMMU: 'y',
      CONFIG_AMD_IOMMU: 'y',
      CONFIG_IRQ_REMAP: 'y',
      CONFIG_VIRTIO: 'y',
      CONFIG_VIRTIO_PCI: 'y',
      CONFIG_VIRTIO_BLK: 'y',
      CONFIG_SCSI_VIRTIO: 'y',
      CONFIG_VIRTIO_NET: 'y',
      CONFIG_NVME_CORE: 'y',
      CONFIG_BLK_DEV_NVME: 'y',
      CONFIG_SATA_AHCI: 'y',
      CONFIG_BLK_DEV_SD: 'y',
      CONFIG_E1000E: 'm',
      CONFIG_IGB: 'm',
      CONFIG_IGC: 'm',
      CONFIG_IXGBE: 'm',
      CONFIG_I40E: 'm',
      CONFIG_ICE: 'm',
      CONFIG_MLX5_CORE: 'm',
      CONFIG_MLX5_CORE_EN: 'y',
      CONFIG_R8169: 'm',
      CONFIG_BNXT: 'm',
    });
  } else {
    // Stripped desktop bloat removal
    Object.assign(symbols, {
      CONFIG_MODULES: 'y',
      CONFIG_MODULE_UNLOAD: 'y',
      CONFIG_SOUND: 'n',
      CONFIG_DRM: 'n',
      CONFIG_SYSFB_SIMPLEFB: 'y',
      CONFIG_WIRELESS: 'n',
      CONFIG_WLAN: 'n',
      CONFIG_BT: 'n',
      CONFIG_NFC: 'n',
      CONFIG_MEDIA_SUPPORT: 'n',
      CONFIG_INFINIBAND: 'n',
      CONFIG_STAGING: 'n',
    });
  }

  // 2. KSPP & LSM Security
  Object.assign(symbols, {
    CONFIG_SECURITY: 'y',
    CONFIG_SECURITY_NETWORK: 'y',
    CONFIG_SECURITY_LOCKDOWN_LSM: 'y',
    CONFIG_SECURITY_LOCKDOWN_LSM_EARLY: 'y',
    CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY: spec.lockdownTier === 'integrity' ? 'y' : 'n',
    CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY: spec.lockdownTier === 'confidentiality' ? 'y' : 'n',
    CONFIG_SECURITY_YAMA: 'y',
    CONFIG_SECURITY_LANDLOCK: 'y',
    CONFIG_SECURITY_APPARMOR: 'y',
    CONFIG_SECURITY_SAFESETID: 'y',
    CONFIG_INTEGRITY: 'y',
    CONFIG_BPF_LSM: 'y',
    CONFIG_LSM: '"landlock,lockdown,yama,integrity,apparmor,bpf"',
    CONFIG_SLAB_FREELIST_RANDOM: 'y',
    CONFIG_SLAB_FREELIST_HARDENED: 'y',
    CONFIG_SHUFFLE_PAGE_ALLOCATOR: 'y',
    CONFIG_RANDOM_KMALLOC_CACHES: 'y',
    CONFIG_INIT_ON_ALLOC_DEFAULT_ON: 'y',
    CONFIG_HARDENED_USERCOPY: 'y',
    CONFIG_FORTIFY_SOURCE: 'y',
    CONFIG_STACKPROTECTOR: 'y',
    CONFIG_STACKPROTECTOR_STRONG: 'y',
    CONFIG_SCHED_STACK_END_CHECK: 'y',
    CONFIG_STRICT_KERNEL_RWX: 'y',
    CONFIG_STRICT_MODULE_RWX: 'y',
    CONFIG_RANDOMIZE_BASE: 'y',
    CONFIG_RANDOMIZE_MEMORY: 'y',
    CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT: 'y',
    CONFIG_ZERO_CALL_USED_REGS: 'y',
    CONFIG_LEGACY_VSYSCALL_NONE: 'y',
    CONFIG_X86_KERNEL_IBT: 'y',
    CONFIG_CPU_MITIGATIONS: 'y',
    CONFIG_MITIGATION_PAGE_TABLE_ISOLATION: 'y',
    CONFIG_MITIGATION_RETPOLINE: 'y',
    CONFIG_STRICT_DEVMEM: 'y',
    CONFIG_IO_STRICT_DEVMEM: 'y',
    CONFIG_SYN_COOKIES: 'y',
    CONFIG_MODULE_SIG: 'y',
    CONFIG_MODULE_SIG_ALL: 'y',
    CONFIG_MODULE_SIG_SHA512: 'y',
    CONFIG_MODULE_SIG_HASH: '"sha512"',
    CONFIG_MODULE_SIG_FORCE: spec.enforceModuleSig ? 'y' : 'n',
    CONFIG_IA32_EMULATION: spec.disableIa32Emulation ? 'n' : 'y',
    CONFIG_KEXEC: 'n',
    CONFIG_KEXEC_FILE: 'n',
    CONFIG_HIBERNATION: 'n',
    CONFIG_DEVKMEM: 'n',
    CONFIG_IP_DCCP: 'n',
    CONFIG_RDS: 'n',
    CONFIG_TIPC: 'n',
    CONFIG_ATM: 'n',
    CONFIG_DECNET: 'n',
    CONFIG_FIREWIRE: 'n',
    CONFIG_PROC_KCORE: spec.enableProcKcore ? 'y' : 'n',
  });

  // 3. Workload Capability Packs
  const caps = new Set(spec.capabilities);
  if (caps.has('k3s')) {
    Object.assign(symbols, {
      CONFIG_NAMESPACES: 'y',
      CONFIG_UTS_NS: 'y',
      CONFIG_IPC_NS: 'y',
      CONFIG_USER_NS: spec.enableRootlessUserNs ? 'y' : 'n',
      CONFIG_PID_NS: 'y',
      CONFIG_NET_NS: 'y',
      CONFIG_TIME_NS: 'y',
      CONFIG_CGROUPS: 'y',
      CONFIG_MEMCG: 'y',
      CONFIG_BLK_CGROUP: 'y',
      CONFIG_CGROUP_SCHED: 'y',
      CONFIG_FAIR_GROUP_SCHED: 'y',
      CONFIG_CFS_BANDWIDTH: 'y',
      CONFIG_CGROUP_PIDS: 'y',
      CONFIG_CGROUP_FREEZER: 'y',
      CONFIG_CPUSETS: 'y',
      CONFIG_CGROUP_DEVICE: 'y',
      CONFIG_CGROUP_CPUACCT: 'y',
      CONFIG_CGROUP_PERF: 'y',
      CONFIG_CGROUP_BPF: 'y',
      CONFIG_CGROUP_HUGETLB: 'y',
      CONFIG_PSI: 'y',
      CONFIG_SECCOMP: 'y',
      CONFIG_SECCOMP_FILTER: 'y',
      CONFIG_OVERLAY_FS: 'y',
      CONFIG_VETH: 'y',
      CONFIG_BRIDGE: 'y',
      CONFIG_BRIDGE_NETFILTER: 'm',
      CONFIG_VLAN_8021Q: 'y',
      CONFIG_VXLAN: 'm',
      CONFIG_GENEVE: 'm',
      CONFIG_IP_VS: 'm',
      CONFIG_IP_VS_NFCT: 'y',
      CONFIG_IP_VS_RR: 'm',
    });
  }

  if (caps.has('zfs')) {
    Object.assign(symbols, {
      CONFIG_TRIM_UNUSED_KSYMS: 'n',
      CONFIG_KALLSYMS: 'y',
      CONFIG_EFI_PARTITION: 'y',
      CONFIG_ZLIB_INFLATE: 'y',
      CONFIG_ZLIB_DEFLATE: 'y',
      CONFIG_ZSTD_COMPRESS: 'y',
      CONFIG_ZSTD_DECOMPRESS: 'y',
      CONFIG_BLK_DEV_DM: 'y',
      CONFIG_DM_CRYPT: 'y',
      CONFIG_MD: 'y',
      CONFIG_BLK_DEV_MD: 'y',
      CONFIG_MD_RAID1: 'y',
      CONFIG_EXT4_FS: 'y',
      CONFIG_EXT4_FS_POSIX_ACL: 'y',
      CONFIG_EXT4_FS_SECURITY: 'y',
      CONFIG_XFS_FS: 'y',
      CONFIG_XFS_POSIX_ACL: 'y',
    });
  }

  if (caps.has('nftables')) {
    Object.assign(symbols, {
      CONFIG_NET: 'y',
      CONFIG_INET: 'y',
      CONFIG_IPV6: 'y',
      CONFIG_TUN: 'y',
      CONFIG_WIREGUARD: 'y',
      CONFIG_NETFILTER: 'y',
      CONFIG_NETFILTER_ADVANCED: 'y',
      CONFIG_NF_CONNTRACK: 'y',
      CONFIG_NF_NAT: 'y',
      CONFIG_NF_TABLES: 'y',
      CONFIG_NF_TABLES_INET: 'y',
      CONFIG_NF_TABLES_IPV4: 'y',
      CONFIG_NF_TABLES_IPV6: 'y',
      CONFIG_NF_TABLES_ARP: 'y',
      CONFIG_NF_TABLES_NETDEV: 'y',
      CONFIG_NFT_CT: 'y',
      CONFIG_NFT_FLOW_OFFLOAD: 'y',
      CONFIG_NF_FLOW_TABLE: 'y',
      CONFIG_NF_FLOW_TABLE_INET: 'y',
      CONFIG_NFT_NAT: 'y',
      CONFIG_NFT_MASQ: 'y',
      CONFIG_NFT_REDIR: 'y',
      CONFIG_NFT_REJECT: 'y',
      CONFIG_NFT_FIB: 'y',
      CONFIG_NFT_FIB_INET: 'y',
      CONFIG_TCP_CONG_BBR: 'y',
    });
  }

  if (caps.has('ebpf')) {
    Object.assign(symbols, {
      CONFIG_BPF: 'y',
      CONFIG_BPF_SYSCALL: 'y',
      CONFIG_BPF_JIT: 'y',
      CONFIG_BPF_JIT_ALWAYS_ON: 'y',
      CONFIG_BPF_UNPRIV_DEFAULT_OFF: 'y',
      CONFIG_BPF_EVENTS: 'y',
      CONFIG_DEBUG_INFO: 'y',
      CONFIG_DEBUG_INFO_BTF: 'y',
      CONFIG_DEBUG_INFO_BTF_MODULES: 'y',
      CONFIG_XDP_SOCKETS: 'y',
      CONFIG_FTRACE: 'y',
      CONFIG_DYNAMIC_FTRACE: 'y',
      CONFIG_FPROBE: 'y',
      CONFIG_KPROBES: 'y',
    });
  }

  if (caps.has('kvm')) {
    symbols.CONFIG_KVM = 'm';
    symbols.CONFIG_VFIO = 'm';
    symbols.CONFIG_VFIO_PCI = 'm';
    symbols.CONFIG_VHOST_NET = 'm';
  }
  if (caps.has('ipsec')) {
    symbols.CONFIG_XFRM_USER = 'y';
    symbols.CONFIG_INET_ESP = 'y';
    symbols.CONFIG_INET6_ESP = 'y';
  }
  if (caps.has('usb')) {
    symbols.CONFIG_USB = 'y';
    symbols.CONFIG_USB_XHCI_HCD = 'y';
    symbols.CONFIG_USB_XHCI_PCI = 'y';
    symbols.CONFIG_USB_STORAGE = 'm';
    symbols.CONFIG_USB_UAS = 'm';
  }
  if (caps.has('iscsi_nfs')) {
    symbols.CONFIG_ISCSI_TCP = 'm';
    symbols.CONFIG_NFSD = 'm';
    symbols.CONFIG_NFSD_V4 = 'y';
    symbols.CONFIG_NFS_FS = 'm';
  }

  // 4. Safety & Compatibility Guardrails
  if (spec.lockdownTier === 'confidentiality' && caps.has('ebpf')) {
    warnings.push(
      'Lockdown mode "confidentiality" blocks bpf_probe_read_kernel() & CO-RE BTF trampolines required by Cilium, Falco, and Axonwall eBPF observability. Recommended: "integrity".'
    );
  }
  if (caps.has('k3s') && !spec.enableRootlessUserNs) {
    warnings.push(
      'Disabling CONFIG_USER_NS while Kubernetes (K3s) is enabled breaks rootless Podman/containerd, userns pod isolation, and Linux 6.9+ BPF_TOKEN delegation.'
    );
  }
  if (spec.enforceModuleSig && caps.has('zfs')) {
    warnings.push(
      'CONFIG_MODULE_SIG_FORCE=y requires signing out-of-tree OpenZFS (zfs.ko/spl.ko) DKMS modules with your kernel signing key before boot.'
    );
  }
  if (spec.mode === 'stripped') {
    const hasStorageDriver = retainedDrivers.some((d) => d.category === 'storage') || Boolean(symbols.CONFIG_BLK_DEV_NVME || symbols.CONFIG_VIRTIO_BLK || symbols.CONFIG_SATA_AHCI || symbols.CONFIG_BLK_DEV_SD);
    const hasNicDriver = retainedDrivers.some((d) => d.category === 'network');
    if (!hasStorageDriver) {
      warnings.push(
        'Stripped mode: no block storage controller driver was detected or pinned. Verify CONFIG_BLK_DEV_NVME / CONFIG_SATA_AHCI / CONFIG_VIRTIO_BLK before compiling to prevent unbootable initramfs.'
      );
    }
    if (!hasNicDriver) {
      warnings.push(
        'Stripped mode: no physical/virtual NIC driver was detected or pinned. Pin your NIC driver symbol (e.g. CONFIG_IGC, CONFIG_IXGBE, CONFIG_VIRTIO_NET) before compiling.'
      );
    }
  }

  // 5. Render Kconfig Fragment
  const headerLines = [
    `# ==============================================================================`,
    `# Axonwall Custom Kernel Configuration Fragment`,
    `# Mode: ${spec.mode} | Linux: ${spec.kernelVersion} | Arch: ${spec.arch} | march: ${spec.marchTarget}`,
    `# Capabilities: ${spec.capabilities.join(',')}`,
    `# Lockdown: ${spec.lockdownTier} | UserNS: ${spec.enableRootlessUserNs ? 'enabled' : 'disabled'}`,
    `# ==============================================================================`,
    '',
  ];
  const sortedKeys = Object.keys(symbols).sort();
  const bodyLines = sortedKeys.map((k) => {
    const val = symbols[k];
    if (val === 'n') return `# ${k} is not set`;
    return `${k}=${val}`;
  });
  const kconfigFragment = [...headerLines, ...bodyLines, ''].join('\n');

  // 6. Render Sysctl Profile
  const sysctlConfig = [
    '# Axonwall Hardened Kernel Runtime Sysctl Profile',
    `-kernel.unprivileged_userns_clone = ${spec.enableRootlessUserNs ? 1 : 0}`,
    'kernel.kptr_restrict = 2',
    'kernel.dmesg_restrict = 1',
    'kernel.unprivileged_bpf_disabled = 1',
    'net.core.bpf_jit_harden = 2',
    '-kernel.perf_event_paranoid = 2',
    '-vm.unprivileged_userfaultfd = 0',
    '-dev.tty.ldisc_autoload = 0',
    'kernel.yama.ptrace_scope = 1',
    '-kernel.io_uring_disabled = 1',
    'fs.protected_fifos = 2',
    'fs.protected_regular = 2',
    'fs.protected_hardlinks = 1',
    'fs.protected_symlinks = 1',
    'fs.suid_dumpable = 0',
    'net.ipv4.tcp_syncookies = 1',
    'net.ipv4.tcp_rfc1337 = 1',
    '',
  ].join('\n');

  // 7. Render lsmod seed & reproducible CLI command
  const lsmodRows = hw?.loadedModules?.length
    ? hw.loadedModules.map((m) => `${m.name} ${m.sizeBytes} ${m.refCount} ${m.usedBy.length ? m.usedBy.join(',') : '-'}`)
    : [];
  const lsmodSeed = lsmodRows.length > 0
    ? ['Module Size Used by', ...lsmodRows, ''].join('\n')
    : '# Run on target host: lsmod > host.lsmod\n';

  const cliFlags = [
    `/usr/share/axonwall/kernel-builder/build-kernel.sh`,
    `--mode ${spec.mode}`,
    `--kernel-version ${spec.kernelVersion}`,
    `--arch ${spec.arch}`,
    `--march ${spec.marchTarget}`,
    `--capabilities ${spec.capabilities.join(',')}`,
    `--lockdown ${spec.lockdownTier}`,
  ];
  if (spec.mode === 'stripped') {
    cliFlags.push(`--lsmod-file host.lsmod`, `--hardware-fragment axonwall-custom.config`);
  }
  if (spec.disableIa32Emulation) cliFlags.push('--disable-ia32');
  if (!spec.enableRootlessUserNs) cliFlags.push('--no-userns');
  if (spec.enforceModuleSig) cliFlags.push('--force-module-sig');
  if (!spec.enableProcKcore) cliFlags.push('--disable-kcore');
  const cliCommand = cliFlags.join(' \\\n  ');

  // 8. Compute Module Reduction Metrics & Simulated Audit
  const hostAvailableModules = hw?.hostAvailableModules || 0;
  const loadedModulesCount = hw?.loadedModules?.length || 0;
  const retainedDriverCount = retainedDrivers.length;
  const retainedSymbolCount = sortedKeys.length;
  let estimatedReductionPercent = 0;
  if (spec.mode === 'stripped' && hostAvailableModules > 0) {
    const baseline = Math.max(loadedModulesCount, retainedDriverCount, 1);
    estimatedReductionPercent = Math.max(
      0,
      Math.min(99, Math.round(((hostAvailableModules - baseline) / hostAvailableModules) * 100))
    );
  }

  const simulatedAudit = auditKernelPostureAndConfig(symbols, {
    lockdownMode: spec.lockdownTier,
    activeLsms: ['landlock', 'lockdown', 'yama', 'integrity', 'apparmor', 'bpf'],
    unprivilegedBpfDisabled: '1',
    bpfJitHarden: '2',
    userNsCloneAllowed: spec.enableRootlessUserNs,
  }, `projected:${spec.mode}`);

  return {
    kconfigFragment,
    sysctlConfig,
    lsmodSeed,
    cliCommand,
    retainedDrivers,
    estimatedModuleStats: {
      hostAvailableModules,
      loadedModulesCount,
      retainedDriverCount,
      retainedSymbolCount,
      estimatedReductionPercent,
    },
    warnings,
    simulatedAudit,
  };
}
