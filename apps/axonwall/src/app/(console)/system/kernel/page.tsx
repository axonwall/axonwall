'use client';

import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Cpu,
  Database,
  Download,
  FileCode2,
  HardDrive,
  Layers,
  Lock,
  Network,
  Play,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Wrench,
  XCircle,
} from 'lucide-react';
import type {
  BuiltKernelArtifact,
  CompiledKernelBundle,
  CpuMicroarchTarget,
  CustomKernelBuildSpec,
  DetectedHardwareProfile,
  HostBuildToolchain,
  KernelAuditPillar,
  KernelCapabilityPack,
  KernelHardeningAuditReport,
} from '@axonwall/lib/kernel';

interface StudioPayload {
  daemonConnected: boolean;
  hardware: DetectedHardwareProfile;
  posture: {
    lockdownMode?: string;
    activeLsms?: string[];
    bpfLsmActive?: boolean;
    unprivilegedBpfDisabled?: string;
    bpfJitHarden?: string;
    userNsCloneAllowed?: boolean;
  };
  audit: KernelHardeningAuditReport;
  toolchain: HostBuildToolchain;
  artifacts: BuiltKernelArtifact[];
  installMode: string;
  defaultSpec: CustomKernelBuildSpec;
  compiled: CompiledKernelBundle;
}

interface TaskProgress {
  task: {
    upid: string;
    status: string;
    exitStatus: string;
    startTime: number;
    endTime?: number;
    targetId: string;
    type: string;
  };
  logTail: string[];
}

const CAPABILITY_CARDS: Array<{
  id: KernelCapabilityPack;
  title: string;
  desc: string;
}> = [
  { id: 'k3s', title: 'Kubernetes (K3s + CNI)', desc: 'Namespaces, cgroups v2, OverlayFS, Seccomp, veth, VXLAN, IPVS' },
  { id: 'zfs', title: 'OpenZFS + OpenEBS Storage', desc: 'Keeps ksyms untrimmed for ZFS DKMS + NVMe, mdadm, dm-crypt, XFS/ext4' },
  { id: 'nftables', title: 'NGFW nftables + WireGuard', desc: 'Fastpath flowtable offload, conntrack, NAT, BBR, WireGuard mesh' },
  { id: 'ebpf', title: 'eBPF CO-RE + BPF LSM', desc: 'BTF type info, JIT harden, XDP sockets, BPF_UNPRIV_DEFAULT_OFF' },
  { id: 'kvm', title: 'KVM / VFIO Passthrough', desc: 'Hardware virtualization & PCIe VFIO/SR-IOV passthrough modules' },
  { id: 'ipsec', title: 'IPsec (XFRM / ESP)', desc: 'Hardware-accelerated AES-GCM/ESP kernel IPsec data plane' },
  { id: 'usb', title: 'USB Console & Installer Media', desc: 'xHCI USB3 + USB mass storage for rescue/CIDATA media' },
  { id: 'iscsi_nfs', title: 'iSCSI & NFSv4 Targets', desc: 'Kernel iSCSI initiator and NFSv4 client/server exports' },
];

const QUICK_PIN_DRIVERS: Array<{ symbol: string; label: string }> = [
  { symbol: 'CONFIG_IGC', label: 'Intel I225/I226 2.5G' },
  { symbol: 'CONFIG_IXGBE', label: 'Intel X550 10GbE' },
  { symbol: 'CONFIG_I40E', label: 'Intel X710 10/40G' },
  { symbol: 'CONFIG_ICE', label: 'Intel E810 25/100G' },
  { symbol: 'CONFIG_MLX5_CORE', label: 'Mellanox ConnectX-5/6' },
  { symbol: 'CONFIG_VIRTIO_NET', label: 'VirtIO NIC' },
  { symbol: 'CONFIG_BLK_DEV_NVME', label: 'NVMe SSD' },
  { symbol: 'CONFIG_SCSI_MPT3SAS', label: 'LSI SAS3 HBA' },
];

const PILLAR_LABELS: Record<KernelAuditPillar, string> = {
  kspp_memory: 'KSPP Memory & Control-Flow',
  attack_surface: 'Attack Surface Stripping',
  k3s_containers: 'K3s & Rootless Containers',
  storage_zfs: 'OpenZFS & Storage Stack',
  nftables_ebpf: 'nftables & CO-RE eBPF',
};

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let val = bytes;
  let i = 0;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i += 1;
  }
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export default function CustomKernelStudioPage() {
  const [studio, setStudio] = useState<StudioPayload | null>(null);
  const [spec, setSpec] = useState<CustomKernelBuildSpec | null>(null);
  const [compiled, setCompiled] = useState<CompiledKernelBundle | null>(null);
  const [loading, setLoading] = useState(true);
  const [previewing, setPreviewing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<'posture' | 'hardware' | 'composer' | 'build'>('posture');
  const [exportSubTab, setExportSubTab] = useState<'kconfig' | 'sysctl' | 'lsmod' | 'cli'>('kconfig');
  const [driverFilter, setDriverFilter] = useState('');
  const [pinInput, setPinInput] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const [activeUpid, setActiveUpid] = useState<string | null>(null);
  const [taskProgress, setTaskProgress] = useState<TaskProgress | null>(null);
  const [submittingBuild, setSubmittingBuild] = useState(false);
  const [installingArtifact, setInstallingArtifact] = useState<string | null>(null);

  const loadStudio = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/system/kernel', { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok || !data.success || !data.studio) {
        throw new Error(data.message || 'Failed to load Kernel Studio telemetry.');
      }
      setStudio(data.studio);
      setSpec((prev) => prev || data.studio.defaultSpec);
      setCompiled(data.studio.compiled);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStudio();
  }, []);

  const refreshPreview = async (nextSpec: CustomKernelBuildSpec) => {
    setSpec(nextSpec);
    setPreviewing(true);
    try {
      const res = await fetch('/api/system/kernel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'preview', spec: nextSpec }),
      });
      const data = await res.json();
      if (res.ok && data.success && data.compiled) {
        setCompiled(data.compiled);
      } else if (data.message) {
        setError(data.message);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPreviewing(false);
    }
  };

  useEffect(() => {
    if (!activeUpid) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await fetch(`/api/system/kernel?upid=${encodeURIComponent(activeUpid)}`, { cache: 'no-store' });
        const data = await res.json();
        if (cancelled || !res.ok) return;
        if (data.taskProgress) {
          setTaskProgress(data.taskProgress);
          if (data.artifacts && studio) {
            setStudio({ ...studio, artifacts: data.artifacts });
          }
          if (data.taskProgress.task.status !== 'running') {
            setActiveUpid(null);
            loadStudio();
          }
        }
      } catch {}
    };
    poll();
    const timer = setInterval(poll, 2000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [activeUpid]);

  const handleTriggerBuild = async (configOnly: boolean) => {
    if (!spec) return;
    setSubmittingBuild(true);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch('/api/system/kernel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'build', spec, configOnly }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.message || 'Kernel build could not be started.');
      }
      setNotice(data.message || 'Kernel build task started.');
      if (data.upid) {
        setActiveUpid(data.upid);
        setActiveTab('build');
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmittingBuild(false);
    }
  };

  const handleInstallArtifact = async (artifactName: string) => {
    setInstallingArtifact(artifactName);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch('/api/system/kernel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'install', artifactName }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.message || 'Failed to stage kernel package.');
      }
      setNotice(`${data.message}${data.safetyNote ? ` — ${data.safetyNote}` : ''}`);
      if (data.upid) {
        setActiveUpid(data.upid);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setInstallingArtifact(null);
    }
  };

  const handleCopy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {}
  };

  const handleDownload = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleCapability = (cap: KernelCapabilityPack) => {
    if (!spec) return;
    const exists = spec.capabilities.includes(cap);
    if (exists && spec.capabilities.length === 1) return;
    const nextCaps = exists
      ? spec.capabilities.filter((c) => c !== cap)
      : [...spec.capabilities, cap];
    refreshPreview({ ...spec, capabilities: nextCaps });
  };

  const addExtraSymbol = (raw: string) => {
    if (!spec) return;
    const sym = raw.trim().toUpperCase();
    if (!/^CONFIG_[A-Z0-9_]{2,64}$/.test(sym)) {
      setError(`Invalid Kconfig symbol '${sym}'. Must match CONFIG_[A-Z0-9_]+.`);
      return;
    }
    if (!spec.extraDriverSymbols.includes(sym)) {
      setError(null);
      refreshPreview({ ...spec, extraDriverSymbols: [...spec.extraDriverSymbols, sym] });
    }
    setPinInput('');
  };

  const removeExtraSymbol = (sym: string) => {
    if (!spec) return;
    refreshPreview({
      ...spec,
      extraDriverSymbols: spec.extraDriverSymbols.filter((s) => s !== sym),
    });
  };

  const filteredModules = useMemo(() => {
    if (!studio) return [];
    const q = driverFilter.trim().toLowerCase();
    if (!q) return studio.hardware.loadedModules;
    return studio.hardware.loadedModules.filter(
      (m) => m.name.toLowerCase().includes(q) || m.usedBy.some((u) => u.toLowerCase().includes(q))
    );
  }, [studio, driverFilter]);

  if (loading && !studio) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[50vh]">
        <div className="flex items-center gap-3 text-slate-300 text-sm">
          <RefreshCw className="w-5 h-5 animate-spin text-emerald-400" />
          Probing host hardware, PCIe drivers, and kernel hardening posture...
        </div>
      </div>
    );
  }

  const audit = studio?.audit;
  const hw = studio?.hardware;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="space-y-1.5">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
            <Cpu className="w-3.5 h-3.5" /> KSPP + Talos / CoreOS + OpenZFS + CO-RE eBPF
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Custom Kernel & Hardware Hardening Studio
          </h1>
          <p className="text-sm text-slate-400 max-w-3xl">
            Audit your running kernel against Axonwall&apos;s Kubernetes + OpenZFS + nftables + eBPF hardening baseline,
            detect live host hardware, and compile a universal or hardware-locked stripped Linux 6.12 LTS kernel.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={loadStudio}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Re-Probe Hardware
          </button>
          <a
            href="/docs/custom-kernel"
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-sky-400 text-xs font-medium border border-slate-700 transition"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            Hardening Guide
          </a>
        </div>
      </div>

      {/* Banners */}
      {error && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-xs sm:text-sm text-rose-200 flex items-start gap-2.5">
          <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}
      {notice && (
        <div className="rounded-xl border border-emerald-500/40 bg-emerald-950/30 px-4 py-3 text-xs sm:text-sm text-emerald-200 flex items-start gap-2.5">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <span>{notice}</span>
        </div>
      )}

      {/* Top KPI Strip */}
      {hw && audit && compiled && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Running Kernel</span>
              <Shield className="w-4 h-4 text-sky-400" />
            </div>
            <div className="text-base font-bold text-white font-mono truncate">{hw.kernelRelease}</div>
            <div className="text-[11px] text-slate-400 flex flex-wrap gap-1.5">
              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">{hw.arch}</span>
              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-emerald-300">{hw.suggestedMarch}</span>
              {hw.efiBooted && <span className="px-1.5 py-0.5 rounded bg-slate-800 text-sky-300">UEFI</span>}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Live Hardening Posture</span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-extrabold text-white">{audit.score}</span>
              <span className="text-xs text-slate-400">/ 100</span>
            </div>
            <div className="text-[11px] text-slate-400">
              {audit.passedCount} pass • {audit.warnCount} warn • {audit.failCount} fail
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Detected Hardware & Drivers</span>
              <HardDrive className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-extrabold text-white">{compiled.retainedDrivers.length}</div>
            <div className="text-[11px] text-slate-400">
              {hw.pciDevices.length} PCIe • {hw.storageControllers.length} disks • {hw.networkInterfaces.length} NICs
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Module Surface Reduction</span>
              <Sparkles className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-extrabold text-emerald-400">
              {spec?.mode === 'stripped' && compiled.estimatedModuleStats.estimatedReductionPercent > 0
                ? `${compiled.estimatedModuleStats.estimatedReductionPercent}%`
                : spec?.mode === 'universal'
                  ? 'Universal'
                  : 'Minimal'}
            </div>
            <div className="text-[11px] text-slate-400">
              {hw.loadedModules.length} active / {hw.hostAvailableModules || '?'} host .ko files
            </div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        {[
          { id: 'posture', label: '1. Running Kernel & KSPP Audit', icon: ShieldCheck },
          { id: 'hardware', label: '2. Hardware & Active Drivers', icon: HardDrive },
          { id: 'composer', label: '3. Kernel Profile Composer', icon: Wrench },
          { id: 'build', label: '4. Export, Compile & Stage', icon: Terminal },
        ].map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs sm:text-sm font-medium transition cursor-pointer ${
                active
                  ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: Running Kernel Posture & KSPP Audit */}
      {activeTab === 'posture' && studio && audit && (
        <div className="space-y-6">
          <div className="rounded-xl border border-sky-500/30 bg-sky-950/20 p-4 text-xs sm:text-sm text-slate-300 space-y-2">
            <div className="flex items-center gap-2 font-semibold text-sky-300">
              <Shield className="w-4 h-4" />
              Why Axonwall Synthesizes Talos KSPP + CoreOS/Flatcar Instead of Desktop linux-hardened
            </div>
            <p>
              Desktop <code className="text-sky-200 font-mono">linux-hardened</code> kernels disable unprivileged user namespaces, restrict overlayfs, and force
              <code className="text-sky-200 font-mono"> Lockdown=confidentiality</code>, breaking rootless containers, K3s pods, Cilium/Falco eBPF <code className="text-sky-200 font-mono">bpf_probe_read_kernel()</code>,
              and external OpenZFS DKMS kmods. Axonwall keeps <code className="text-emerald-300 font-mono">CONFIG_USER_NS=y</code>, <code className="text-emerald-300 font-mono">Lockdown=integrity</code>,{' '}
              <code className="text-emerald-300 font-mono">BPF_UNPRIV_DEFAULT_OFF=y</code>, and <code className="text-emerald-300 font-mono">CONFIG_TRIM_UNUSED_KSYMS=n</code> while enforcing full KSPP heap, stack, and LSM mitigations.
            </p>
            <div className="text-[11px] text-slate-400 font-mono">
              Config Source: {audit.configSource || 'Unavailable (/proc/config.gz & /boot/config-* unreadable)'} • Active LSMs:{' '}
              {studio.posture.activeLsms?.join(', ') || 'unknown'} • Lockdown: {studio.posture.lockdownMode || 'unknown'}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {(Object.keys(PILLAR_LABELS) as KernelAuditPillar[]).map((pillar) => {
              const items = audit.checks.filter((c) => c.pillar === pillar);
              return (
                <div key={pillar} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <h3 className="text-sm font-semibold text-white">{PILLAR_LABELS[pillar]}</h3>
                    <span className="text-xs text-slate-400">
                      {items.filter((i) => i.status === 'PASS').length}/{items.length} PASS
                    </span>
                  </div>
                  <div className="space-y-2.5">
                    {items.map((chk) => (
                      <div key={chk.id} className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-medium text-slate-200">{chk.label}</span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              chk.status === 'PASS'
                                ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                                : chk.status === 'WARN'
                                  ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                                  : 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                            }`}
                          >
                            {chk.status}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 flex flex-wrap justify-between gap-2">
                          <span>{chk.symbol}</span>
                          <span>
                            actual: <strong className="text-slate-200">{chk.actual}</strong> | target: {chk.expected}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400">{chk.rationale}</p>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 2: Live Hardware & Driver Matrix */}
      {activeTab === 'hardware' && hw && compiled && (
        <div className="space-y-6">
          {/* CPU / Firmware / TPM Summary */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                <Cpu className="w-4 h-4" /> Processor & Microarch
              </div>
              <div className="text-sm font-semibold text-white">{hw.cpuModel}</div>
              <div className="text-xs text-slate-400 space-y-1">
                <div>Vendor: {hw.cpuVendor} • Cores: {hw.cpuCores}</div>
                <div>Suggested <code className="text-emerald-300">-march</code>: <span className="font-mono text-white">{hw.suggestedMarch}</span></div>
                <div>Hypervisor/DMI: {hw.virtVendor || 'Bare Metal / Unspecified'}</div>
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-sky-400 uppercase tracking-wider">
                <Lock className="w-4 h-4" /> Boot, IOMMU & TPM2
              </div>
              <div className="text-xs text-slate-300 space-y-1.5">
                <div>UEFI Boot: <span className="font-mono text-white">{hw.efiBooted ? 'Yes (CONFIG_EFI_STUB)' : 'Legacy BIOS'}</span></div>
                <div>Secure Boot: <span className="font-mono text-white">{hw.secureBootEnabled ? 'Enabled' : 'Disabled'}</span></div>
                <div>IOMMU Groups: <span className="font-mono text-white">{hw.iommuActive ? `${hw.iommuGroupsCount} active` : 'Inactive'}</span></div>
                <div>TPM Devices: <span className="font-mono text-white">{hw.tpmDevices.join(', ') || 'None detected'}</span></div>
                <div>Watchdogs: <span className="font-mono text-white">{hw.watchdogDrivers.join(', ') || 'None'}</span></div>
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-amber-400 uppercase tracking-wider">
                <Database className="w-4 h-4" /> Storage & NIC Controllers
              </div>
              <div className="text-xs text-slate-300 space-y-1 max-h-36 overflow-y-auto">
                {hw.storageControllers.map((d) => (
                  <div key={d.name} className="flex items-center justify-between font-mono text-[11px]">
                    <span>{d.name} ({d.driver})</span>
                    <span className="text-slate-400">{formatBytes(d.sizeBytes || 0)}</span>
                  </div>
                ))}
                {hw.networkInterfaces.map((n) => (
                  <div key={n.name} className="flex items-center justify-between font-mono text-[11px] text-sky-300">
                    <span>{n.name} ({n.driver})</span>
                    <span>{n.speedMbps ? `${n.speedMbps} Mbps` : n.operstate || 'link'}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Pin Extra Hardware Drivers */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-white">Pin Additional Driver Symbols (Optional)</h3>
                <p className="text-xs text-slate-400">
                  Keep extra <code className="font-mono text-slate-200">CONFIG_*</code> drivers built in even if hardware isn&apos;t plugged in yet (e.g., before installing an SFP28 NIC or HBA).
                </p>
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={pinInput}
                  onChange={(e) => setPinInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && pinInput && addExtraSymbol(pinInput)}
                  placeholder="CONFIG_IXGBE"
                  className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-emerald-500"
                />
                <button
                  type="button"
                  onClick={() => pinInput && addExtraSymbol(pinInput)}
                  className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium cursor-pointer"
                >
                  Pin Symbol
                </button>
              </div>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {QUICK_PIN_DRIVERS.map((item) => {
                const pinned = spec?.extraDriverSymbols.includes(item.symbol);
                return (
                  <button
                    key={item.symbol}
                    type="button"
                    onClick={() => (pinned ? removeExtraSymbol(item.symbol) : addExtraSymbol(item.symbol))}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-mono border transition cursor-pointer ${
                      pinned
                        ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {pinned ? '✓ ' : '+ '}
                    {item.label} ({item.symbol})
                  </button>
                );
              })}
            </div>
          </div>

          {/* Mapped Retained Drivers + Loaded Modules Table */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
              <h3 className="text-sm font-semibold text-white">
                Mapped Hardware & Workload Drivers Retained ({compiled.retainedDrivers.length})
              </h3>
              <div className="max-h-96 overflow-y-auto space-y-2 pr-1">
                {compiled.retainedDrivers.map((d) => (
                  <div key={`${d.category}-${d.driver}`} className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-semibold text-emerald-300">{d.driver}</span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] uppercase">{d.category}</span>
                    </div>
                    <div className="text-slate-400">{d.description}</div>
                    <div className="font-mono text-[11px] text-sky-300">{d.symbols.join(', ')}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-sm font-semibold text-white">
                  Live <code className="font-mono">/proc/modules</code> ({hw.loadedModules.length})
                </h3>
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                  <input
                    type="text"
                    value={driverFilter}
                    onChange={(e) => setDriverFilter(e.target.value)}
                    placeholder="Filter modules..."
                    className="pl-8 pr-3 py-1 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>
              <div className="max-h-96 overflow-y-auto border border-slate-800 rounded-lg">
                <table className="w-full text-left text-[11px]">
                  <thead className="bg-slate-950 text-slate-400 sticky top-0">
                    <tr>
                      <th className="px-3 py-2">Module</th>
                      <th className="px-3 py-2">Size</th>
                      <th className="px-3 py-2">Ref</th>
                      <th className="px-3 py-2">Dependencies</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {filteredModules.map((mod) => (
                      <tr key={mod.name} className="hover:bg-slate-800/30">
                        <td className="px-3 py-1.5 font-mono text-slate-200">{mod.name}</td>
                        <td className="px-3 py-1.5 text-slate-400">{formatBytes(mod.sizeBytes)}</td>
                        <td className="px-3 py-1.5 text-slate-400">{mod.refCount}</td>
                        <td className="px-3 py-1.5 text-slate-500 font-mono truncate max-w-[180px]">
                          {mod.usedBy.join(', ') || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Custom Kernel Profile Composer */}
      {activeTab === 'composer' && spec && compiled && (
        <div className="space-y-6">
          {/* Guardrail Warnings */}
          {compiled.warnings.length > 0 && (
            <div className="rounded-xl border border-amber-500/40 bg-amber-950/25 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs sm:text-sm font-semibold text-amber-300">
                <AlertTriangle className="w-4 h-4" /> Guardrail Warnings
              </div>
              <ul className="list-disc pl-5 space-y-1 text-xs text-amber-200">
                {compiled.warnings.map((w, idx) => (
                  <li key={idx}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Mode Selector */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <button
              type="button"
              onClick={() => refreshPreview({ ...spec, mode: 'universal', marchTarget: spec.arch === 'arm64' ? 'armv8-a' : 'x86-64' })}
              className={`text-left p-5 rounded-xl border transition cursor-pointer space-y-2 ${
                spec.mode === 'universal'
                  ? 'border-emerald-500/60 bg-emerald-950/25'
                  : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-white flex items-center gap-2">
                  <Server className="w-4 h-4 text-sky-400" /> Universal Hardened (Debian-Equivalent)
                </span>
                {spec.mode === 'universal' && <span className="text-[11px] font-bold text-emerald-400">ACTIVE</span>}
              </div>
              <p className="text-xs text-slate-400">
                Broad x86_64/arm64 bare-metal, cloud, and appliance driver coverage matching Debian 13 portability, layered with full Axonwall KSPP, K3s, OpenZFS, nftables, and CO-RE eBPF hardening.
              </p>
            </button>

            <button
              type="button"
              onClick={() => refreshPreview({ ...spec, mode: 'stripped', marchTarget: hw?.suggestedMarch || 'x86-64-v3' })}
              className={`text-left p-5 rounded-xl border transition cursor-pointer space-y-2 ${
                spec.mode === 'stripped'
                  ? 'border-emerald-500/60 bg-emerald-950/25'
                  : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-white flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-emerald-400" /> Hardware-Locked Stripped (`localmodconfig`)
                </span>
                {spec.mode === 'stripped' && <span className="text-[11px] font-bold text-emerald-400">ACTIVE</span>}
              </div>
              <p className="text-xs text-slate-400">
                Locks the kernel strictly to this machine&apos;s detected PCIe/NVMe/NIC/TPM hardware and active <code className="font-mono">lsmod</code> graph, stripping audio, Wi-Fi, Bluetooth, DRM GPUs, and legacy bloat.
              </p>
            </button>
          </div>

          {/* Workload Capability Packs */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white">Workload & Subsystem Capability Packs</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {CAPABILITY_CARDS.map((card) => {
                const enabled = spec.capabilities.includes(card.id);
                return (
                  <button
                    key={card.id}
                    type="button"
                    onClick={() => toggleCapability(card.id)}
                    className={`text-left p-3.5 rounded-lg border transition cursor-pointer space-y-1 ${
                      enabled
                        ? 'border-emerald-500/50 bg-emerald-950/20'
                        : 'border-slate-800 bg-slate-950/60 opacity-75 hover:opacity-100'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-white">{card.title}</span>
                      <span className={`text-[10px] font-bold ${enabled ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {enabled ? 'ON' : 'OFF'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-snug">{card.desc}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Security & Compiler Fine-Tuning */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="space-y-2">
              <label className="block text-xs font-semibold text-slate-300">CPU Microarchitecture (`-march`)</label>
              <select
                value={spec.marchTarget}
                onChange={(e) => refreshPreview({ ...spec, marchTarget: e.target.value as CpuMicroarchTarget })}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono"
              >
                {(['x86-64', 'x86-64-v2', 'x86-64-v3', 'x86-64-v4', 'native', 'armv8-a'] as CpuMicroarchTarget[]).map((m) => (
                  <option key={m} value={m}>
                    {m}
                    {hw?.suggestedMarch === m ? ' (Host Recommended)' : ''}
                  </option>
                ))}
              </select>

              <label className="block text-xs font-semibold text-slate-300 pt-2">Lockdown LSM Tier</label>
              <select
                value={spec.lockdownTier}
                onChange={(e) =>
                  refreshPreview({ ...spec, lockdownTier: e.target.value as 'integrity' | 'confidentiality' })
                }
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white font-mono"
              >
                <option value="integrity">integrity (Recommended — Preserves CO-RE eBPF)</option>
                <option value="confidentiality">confidentiality (Strict — Blocks kernel eBPF reads)</option>
              </select>
            </div>

            <div className="space-y-3 text-xs">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={spec.enableRootlessUserNs}
                  onChange={(e) => refreshPreview({ ...spec, enableRootlessUserNs: e.target.checked })}
                  className="mt-0.5 accent-emerald-500"
                />
                <span>
                  <strong className="text-white block">Enable User Namespaces (CONFIG_USER_NS=y)</strong>
                  <span className="text-slate-400">Required for rootless Podman/containerd, K3s pods, and BPF_TOKEN delegation.</span>
                </span>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={spec.disableIa32Emulation}
                  onChange={(e) => refreshPreview({ ...spec, disableIa32Emulation: e.target.checked })}
                  className="mt-0.5 accent-emerald-500"
                />
                <span>
                  <strong className="text-white block">Disable Legacy IA-32 32-bit Syscalls</strong>
                  <span className="text-slate-400">Eliminates compat syscall CVEs (CONFIG_IA32_EMULATION=n).</span>
                </span>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={spec.enforceModuleSig}
                  onChange={(e) => refreshPreview({ ...spec, enforceModuleSig: e.target.checked })}
                  className="mt-0.5 accent-emerald-500"
                />
                <span>
                  <strong className="text-white block">Force Module Signature Verification</strong>
                  <span className="text-slate-400">Enforces CONFIG_MODULE_SIG_FORCE=y (requires signed OpenZFS kmods).</span>
                </span>
              </label>
            </div>

            <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4 flex flex-col justify-between">
              <div>
                <div className="text-xs font-semibold text-emerald-300">Projected Hardening Score</div>
                <div className="text-4xl font-extrabold text-white mt-1">
                  {compiled.simulatedAudit.score}
                  <span className="text-sm font-normal text-slate-400"> / 100</span>
                </div>
                <div className="text-xs text-slate-300 mt-1">
                  {compiled.simulatedAudit.passedCount}/{compiled.simulatedAudit.totalCount} checks passing •{' '}
                  {compiled.estimatedModuleStats.retainedSymbolCount} curated Kconfig symbols
                </div>
              </div>
              <button
                type="button"
                onClick={() => setActiveTab('build')}
                className="mt-4 w-full py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold cursor-pointer"
              >
                Continue to Export & Build →
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: Export, Compile & Safe Rollback Staging */}
      {activeTab === 'build' && studio && spec && compiled && (
        <div className="space-y-6">
          {/* Host Toolchain & Build Actions */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-white">On-Box Compiler Toolchain</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    studio.toolchain.ready
                      ? 'bg-emerald-500/20 text-emerald-300'
                      : 'bg-amber-500/20 text-amber-300'
                  }`}
                >
                  {studio.toolchain.ready ? 'READY' : 'TOOLS MISSING'}
                </span>
              </div>
              <div className="text-[11px] text-slate-400 space-y-1">
                <div>Builder: <code className="text-slate-200 font-mono">{studio.toolchain.builderScriptPath || 'Not staged'}</code></div>
                <div>Free Disk: <span className="text-white font-mono">{studio.toolchain.freeBytes ? formatBytes(studio.toolchain.freeBytes) : 'Unknown'}</span></div>
                {studio.toolchain.missingTools.length > 0 && (
                  <div className="text-amber-300">
                    Missing: <code className="font-mono">{studio.toolchain.missingTools.join(', ')}</code>
                    <div className="mt-1 p-2 rounded bg-slate-950 font-mono text-[10px] text-slate-300">
                      apt-get update && apt-get install -y build-essential bc flex bison dwarves libssl-dev libelf-dev debhelper dpkg-dev rsync cpio zstd xz-utils
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col justify-between gap-4">
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-white">
                  Build Target: Linux {spec.kernelVersion} LTS ({spec.mode}, {spec.marchTarget})
                </h3>
                <p className="text-xs text-slate-400">
                  Validate & export deterministic <code className="font-mono">config-only</code> bundles immediately, or compile signed Debian <code className="font-mono">.deb</code> packages on the host with A/B & ZBM rollback protection.
                </p>
              </div>
              <div className="flex flex-wrap gap-3">
                <button
                  type="button"
                  disabled={submittingBuild || previewing}
                  onClick={() => handleTriggerBuild(true)}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white text-xs font-semibold border border-slate-700 cursor-pointer"
                >
                  <FileCode2 className="w-4 h-4 text-sky-400" />
                  Generate Host Bundle (`config-only`)
                </button>
                <button
                  type="button"
                  disabled={submittingBuild || !studio.toolchain.ready}
                  onClick={() => handleTriggerBuild(false)}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold cursor-pointer"
                >
                  <Play className="w-4 h-4" />
                  Compile Custom Kernel `.deb` on Host
                </button>
              </div>
            </div>
          </div>

          {/* Live Task Progress Log */}
          {taskProgress && (
            <div className="rounded-xl border border-slate-800 bg-[#0b101d] p-4 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono text-emerald-300">{taskProgress.task.upid}</span>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 uppercase font-bold">
                  {taskProgress.task.status} ({taskProgress.task.exitStatus})
                </span>
              </div>
              <pre className="text-[11px] font-mono text-slate-300 max-h-64 overflow-y-auto p-3 rounded bg-black/50 border border-slate-800">
                {taskProgress.logTail.join('\n') || 'Waiting for build output...'}
              </pre>
            </div>
          )}

          {/* Export Preview Tabs */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 border-b border-slate-800 bg-slate-950/60">
              <div className="flex flex-wrap gap-1.5">
                {[
                  { id: 'kconfig', label: 'axonwall-custom.config' },
                  { id: 'sysctl', label: '95-axonwall-kernel-hardening.conf' },
                  { id: 'lsmod', label: 'host.lsmod' },
                  { id: 'cli', label: 'build-kernel.sh CLI' },
                ].map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setExportSubTab(t.id as typeof exportSubTab)}
                    className={`px-3 py-1 rounded text-xs font-mono cursor-pointer ${
                      exportSubTab === t.id
                        ? 'bg-emerald-600/25 text-emerald-300 border border-emerald-500/40'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
              <div className="flex gap-2">
                {(() => {
                  const contentMap = {
                    kconfig: compiled.kconfigFragment,
                    sysctl: compiled.sysctlConfig,
                    lsmod: compiled.lsmodSeed,
                    cli: compiled.cliCommand,
                  };
                  const fileMap = {
                    kconfig: `axonwall-${spec.mode}-${spec.kernelVersion}.config`,
                    sysctl: '95-axonwall-kernel-hardening.conf',
                    lsmod: 'host.lsmod',
                    cli: 'build-custom-kernel.sh',
                  };
                  const txt = contentMap[exportSubTab];
                  return (
                    <>
                      <button
                        type="button"
                        onClick={() => handleCopy(exportSubTab, txt)}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 cursor-pointer"
                      >
                        {copiedKey === exportSubTab ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        {copiedKey === exportSubTab ? 'Copied' : 'Copy'}
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDownload(fileMap[exportSubTab], txt)}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Download
                      </button>
                    </>
                  );
                })()}
              </div>
            </div>
            <pre className="p-4 text-xs font-mono text-slate-200 max-h-96 overflow-auto bg-[#0b101d]">
              {exportSubTab === 'kconfig'
                ? compiled.kconfigFragment
                : exportSubTab === 'sysctl'
                  ? compiled.sysctlConfig
                  : exportSubTab === 'lsmod'
                    ? compiled.lsmodSeed
                    : compiled.cliCommand}
            </pre>
          </div>

          {/* Built Artifacts Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">
                Built Kernel Artifacts (Install Mode: <span className="font-mono text-emerald-400 uppercase">{studio.installMode}</span>)
              </h3>
              <span className="text-xs text-slate-400">{studio.artifacts.length} file(s)</span>
            </div>
            {studio.artifacts.length === 0 ? (
              <p className="text-xs text-slate-400">
                No compiled kernel artifacts in <code className="font-mono">/var/lib/axonwall/kernel-builds/output</code> yet.
              </p>
            ) : (
              <div className="overflow-x-auto border border-slate-800 rounded-lg">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400">
                    <tr>
                      <th className="px-3 py-2">Artifact</th>
                      <th className="px-3 py-2">Kind</th>
                      <th className="px-3 py-2">Size</th>
                      <th className="px-3 py-2">SHA-256</th>
                      <th className="px-3 py-2 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {studio.artifacts.map((art) => (
                      <tr key={art.name} className="hover:bg-slate-800/30">
                        <td className="px-3 py-2 font-mono text-white">{art.name}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{art.kind}</td>
                        <td className="px-3 py-2 text-slate-400">{formatBytes(art.sizeBytes)}</td>
                        <td className="px-3 py-2 font-mono text-slate-500">
                          {art.sha256 ? `${art.sha256.slice(0, 16)}…` : '—'}
                        </td>
                        <td className="px-3 py-2 text-right">
                          {art.kind === 'image-deb' ? (
                            <button
                              type="button"
                              disabled={installingArtifact === art.name}
                              onClick={() => handleInstallArtifact(art.name)}
                              className="px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-[11px] font-semibold cursor-pointer"
                            >
                              {installingArtifact === art.name ? 'Staging…' : 'Stage Safely'}
                            </button>
                          ) : (
                            <span className="text-slate-500 text-[11px]">Manifest / Config</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
