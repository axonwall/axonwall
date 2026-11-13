import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import {
  CustomKernelBuildSpecSchema,
  auditKernelPostureAndConfig,
  compileCustomKernelArtifacts,
  type BuiltKernelArtifact,
  type CompiledKernelBundle,
  type CustomKernelBuildSpec,
  type DetectedHardwareProfile,
  type HostBuildToolchain,
  type KernelHardeningAuditReport,
  type LiveAuditPosture,
} from '@axonwall/lib/kernel';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { callAgentApi } from './agent-client';

export interface DaemonKernelStudioState {
  hardware: DetectedHardwareProfile;
  runningConfig: Record<string, string>;
  configSource: string;
  posture: LiveAuditPosture & {
    taintValue?: number;
    ioUringDisabled?: string;
    bpfLsmActive?: boolean;
  };
  toolchain: HostBuildToolchain;
  artifacts: BuiltKernelArtifact[];
  installMode?: string;
  taskProgress?: {
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
  };
}

export interface KernelStudioPayload {
  daemonConnected: boolean;
  hardware: DetectedHardwareProfile;
  posture: DaemonKernelStudioState['posture'];
  audit: KernelHardeningAuditReport;
  toolchain: HostBuildToolchain;
  artifacts: BuiltKernelArtifact[];
  installMode: string;
  defaultSpec: CustomKernelBuildSpec;
  compiled: CompiledKernelBundle;
}

function readTrimmed(filePath: string): string {
  try {
    return fs.readFileSync(filePath, 'utf8').trim();
  } catch {
    return '';
  }
}

function parseKernelConfigText(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of raw.split('\n')) {
    const line = rawLine.trim();
    if (line.startsWith('# CONFIG_') && line.endsWith(' is not set')) {
      const sym = line.slice(2, line.length - ' is not set'.length).trim();
      out[sym] = 'n';
    } else if (line.startsWith('CONFIG_')) {
      const idx = line.indexOf('=');
      if (idx > 0) {
        out[line.slice(0, idx)] = line.slice(idx + 1).replace(/^"|"$/g, '');
      }
    }
  }
  return out;
}

function findInPath(cmd: string): boolean {
  const dirs = (process.env.PATH || '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin').split(':');
  for (const dir of dirs) {
    if (!dir) continue;
    const candidate = path.join(dir, cmd);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return true;
    } catch {}
  }
  return false;
}

function countKoFiles(dir: string, depth = 0): number {
  if (depth > 8 || !fs.existsSync(dir)) return 0;
  let total = 0;
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        total += countKoFiles(path.join(dir, entry.name), depth + 1);
      } else if (
        entry.name.endsWith('.ko') ||
        entry.name.endsWith('.ko.zst') ||
        entry.name.endsWith('.ko.xz') ||
        entry.name.endsWith('.ko.gz')
      ) {
        total += 1;
      }
    }
  } catch {}
  return total;
}

function resolveBuilderScriptLocal(): string | undefined {
  const candidates = [
    '/usr/share/axonwall/kernel-builder/build-kernel.sh',
    path.resolve(process.cwd(), 'packaging/kernel/build-kernel.sh'),
    path.resolve(process.cwd(), '../../packaging/kernel/build-kernel.sh'),
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p) && fs.statSync(p).isFile()) {
        return p;
      }
    } catch {}
  }
  return undefined;
}

function collectFallbackKernelStudioState(): DaemonKernelStudioState {
  const release = os.release();
  const rawArch = os.arch();
  const cpuInfo = readTrimmed('/proc/cpuinfo');
  let cpuVendor = 'Unknown';
  let cpuModel = os.cpus()[0]?.model || 'Unknown CPU';
  let cpuFlags: string[] = [];
  for (const line of cpuInfo.split('\n')) {
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim();
    const val = line.slice(idx + 1).trim();
    if (key === 'vendor_id' && cpuVendor === 'Unknown') cpuVendor = val;
    if ((key === 'model name' || key === 'Model') && val) cpuModel = val;
    if ((key === 'flags' || key === 'Features') && cpuFlags.length === 0) {
      cpuFlags = val.split(/\s+/).filter(Boolean);
    }
  }
  const flagSet = new Set(cpuFlags);
  const suggestedMarch: DetectedHardwareProfile['suggestedMarch'] =
    rawArch === 'arm64'
      ? 'armv8-a'
      : flagSet.has('avx512f') && flagSet.has('avx512bw') && flagSet.has('avx512cd')
        ? 'x86-64-v4'
        : flagSet.has('avx2') && flagSet.has('bmi1') && flagSet.has('bmi2')
          ? 'x86-64-v3'
          : flagSet.has('sse4_2') && flagSet.has('popcnt')
            ? 'x86-64-v2'
            : 'x86-64';

  const loadedModules: DetectedHardwareProfile['loadedModules'] = [];
  const procModules = readTrimmed('/proc/modules');
  if (procModules) {
    for (const line of procModules.split('\n')) {
      const fields = line.trim().split(/\s+/);
      if (fields.length < 3 || !fields[0]) continue;
      loadedModules.push({
        name: fields[0],
        sizeBytes: Number(fields[1]) || 0,
        refCount: Number(fields[2]) || 0,
        usedBy: fields[3] && fields[3] !== '-' ? fields[3].replace(/,$/, '').split(',').filter(Boolean) : [],
      });
    }
  }

  const pciDevices: DetectedHardwareProfile['pciDevices'] = [];
  if (fs.existsSync('/sys/bus/pci/devices')) {
    for (const bdf of fs.readdirSync('/sys/bus/pci/devices').sort()) {
      const devDir = path.join('/sys/bus/pci/devices', bdf);
      const vendorId = readTrimmed(path.join(devDir, 'vendor')).replace(/^0x/, '');
      const deviceId = readTrimmed(path.join(devDir, 'device')).replace(/^0x/, '');
      const deviceClass = readTrimmed(path.join(devDir, 'class')).replace(/^0x/, '');
      let driver = 'none';
      let mod: string | undefined;
      try {
        driver = path.basename(fs.readlinkSync(path.join(devDir, 'driver')));
        try {
          mod = path.basename(fs.readlinkSync(path.join(devDir, 'driver', 'module')));
        } catch {}
      } catch {}
      pciDevices.push({
        bdf,
        vendorId,
        deviceId,
        deviceClass,
        deviceName: `PCI [${vendorId}:${deviceId}] Class ${deviceClass}`,
        driver,
        module: mod,
      });
    }
  }

  const storageControllers: DetectedHardwareProfile['storageControllers'] = [];
  if (fs.existsSync('/sys/class/block')) {
    for (const devName of fs.readdirSync('/sys/class/block').sort()) {
      if (/^(loop|ram|dm-|zd)/.test(devName)) continue;
      const devDir = path.join('/sys/class/block', devName);
      if (fs.existsSync(path.join(devDir, 'partition'))) continue;
      let driver = devName.startsWith('nvme') ? 'nvme' : devName.startsWith('vd') ? 'virtio_blk' : 'unknown';
      try {
        driver = path.basename(fs.readlinkSync(path.join(devDir, 'device', 'driver')));
      } catch {}
      const sectors = Number(readTrimmed(path.join(devDir, 'size'))) || 0;
      storageControllers.push({
        name: devName,
        kind: devName.startsWith('nvme') ? 'nvme' : devName.startsWith('vd') ? 'virtio' : devName.startsWith('md') ? 'mdraid' : 'disk',
        driver,
        model: readTrimmed(path.join(devDir, 'device', 'model')) || undefined,
        sizeBytes: sectors * 512,
      });
    }
  }

  const networkInterfaces: DetectedHardwareProfile['networkInterfaces'] = [];
  if (fs.existsSync('/sys/class/net')) {
    for (const ifName of fs.readdirSync('/sys/class/net').sort()) {
      if (ifName === 'lo' || /^(veth|docker|flannel|cni)/.test(ifName)) continue;
      const ifDir = path.join('/sys/class/net', ifName);
      let driver = 'virtual';
      try {
        driver = path.basename(fs.readlinkSync(path.join(ifDir, 'device', 'driver')));
      } catch {}
      const speedVal = Number(readTrimmed(path.join(ifDir, 'speed')));
      networkInterfaces.push({
        name: ifName,
        driver,
        mac: readTrimmed(path.join(ifDir, 'address')) || undefined,
        operstate: readTrimmed(path.join(ifDir, 'operstate')) || undefined,
        speedMbps: Number.isFinite(speedVal) && speedVal > 0 ? speedVal : undefined,
      });
    }
  }

  let runningConfig: Record<string, string> = {};
  let configSource = '';
  if (fs.existsSync('/proc/config.gz')) {
    try {
      const gunzipped = zlib.gunzipSync(fs.readFileSync('/proc/config.gz')).toString('utf8');
      runningConfig = parseKernelConfigText(gunzipped);
      configSource = '/proc/config.gz';
    } catch {}
  }
  if (!configSource) {
    const bootCfg = `/boot/config-${release}`;
    if (fs.existsSync(bootCfg)) {
      try {
        runningConfig = parseKernelConfigText(fs.readFileSync(bootCfg, 'utf8'));
        configSource = bootCfg;
      } catch {}
    }
  }

  const lockdownRaw = readTrimmed('/sys/kernel/security/lockdown');
  const lockdownMode = lockdownRaw.includes('[confidentiality]')
    ? 'confidentiality'
    : lockdownRaw.includes('[integrity]')
      ? 'integrity'
      : 'none';
  const activeLsms = readTrimmed('/sys/kernel/security/lsm')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const unprivCloneRaw = readTrimmed('/proc/sys/kernel/unprivileged_userns_clone');
  const userNsCloneAllowed = unprivCloneRaw === '' || unprivCloneRaw === '1';

  const iommuGroupsCount = fs.existsSync('/sys/kernel/iommu_groups') ? fs.readdirSync('/sys/kernel/iommu_groups').length : 0;
  const tpmDevices = fs.existsSync('/sys/class/tpm') ? fs.readdirSync('/sys/class/tpm') : [];
  const watchdogDrivers: string[] = [];
  if (fs.existsSync('/sys/class/watchdog')) {
    for (const w of fs.readdirSync('/sys/class/watchdog')) {
      watchdogDrivers.push(readTrimmed(path.join('/sys/class/watchdog', w, 'identity')) || w);
    }
  }

  const requiredTools = ['gcc', 'make', 'flex', 'bison', 'bc', 'pahole', 'dpkg-deb'];
  const availableTools = requiredTools.filter(findInPath);
  const missingTools = requiredTools.filter((t) => !availableTools.includes(t));
  const builderScriptPath = resolveBuilderScriptLocal();

  return {
    hardware: {
      hostname: os.hostname(),
      kernelRelease: release,
      arch: rawArch === 'arm64' ? 'aarch64' : 'x86_64',
      cpuVendor,
      cpuModel,
      cpuCores: os.cpus().length,
      cpuFlags,
      suggestedMarch,
      virtVendor: readTrimmed('/sys/class/dmi/id/sys_vendor') || undefined,
      efiBooted: fs.existsSync('/sys/firmware/efi'),
      secureBootEnabled: false,
      iommuActive: iommuGroupsCount > 0,
      iommuGroupsCount,
      tpmDevices,
      watchdogDrivers,
      pciDevices,
      storageControllers,
      networkInterfaces,
      loadedModules,
      hostAvailableModules: countKoFiles(`/lib/modules/${release}`),
    },
    runningConfig,
    configSource,
    posture: {
      lockdownMode,
      activeLsms,
      bpfLsmActive: activeLsms.includes('bpf'),
      unprivilegedBpfDisabled: readTrimmed('/proc/sys/kernel/unprivileged_bpf_disabled'),
      bpfJitHarden: readTrimmed('/proc/sys/net/core/bpf_jit_harden'),
      userNsCloneAllowed,
    },
    toolchain: {
      ready: missingTools.length === 0 && Boolean(builderScriptPath),
      missingTools,
      availableTools,
      builderScriptPath,
      freeBytes: 0,
    },
    artifacts: [],
    installMode: 'rolling',
  };
}

export async function getKernelStudioTelemetry(): Promise<KernelStudioPayload> {
  const session = await getSession();
  assertActionPermitted(session, 'readonly');

  const daemonRes = await callAgentApi<DaemonKernelStudioState>('/v1/system/kernel/studio', 'GET', undefined, 6000);
  const daemonConnected = Boolean(daemonRes && daemonRes.hardware);
  const state = daemonConnected && daemonRes ? daemonRes : collectFallbackKernelStudioState();

  const audit = auditKernelPostureAndConfig(state.runningConfig || {}, state.posture, state.configSource || '');
  const defaultSpec = CustomKernelBuildSpecSchema.parse({
    mode: 'stripped',
    kernelVersion: '6.12.15',
    arch: state.hardware.arch === 'aarch64' || state.hardware.arch === 'arm64' ? 'arm64' : 'amd64',
    marchTarget: state.hardware.suggestedMarch || 'x86-64-v3',
    capabilities: ['k3s', 'zfs', 'nftables', 'ebpf', 'kvm', 'ipsec', 'usb', 'iscsi_nfs'],
    lockdownTier: 'integrity',
    enableRootlessUserNs: true,
    disableIa32Emulation: true,
    enforceModuleSig: false,
    enableProcKcore: true,
  });

  const compiled = compileCustomKernelArtifacts(defaultSpec, state.hardware);

  return {
    daemonConnected,
    hardware: state.hardware,
    posture: state.posture,
    audit,
    toolchain: state.toolchain,
    artifacts: state.artifacts || [],
    installMode: state.installMode || 'rolling',
    defaultSpec,
    compiled,
  };
}

export async function previewCustomKernelSpec(rawSpec: unknown): Promise<CompiledKernelBundle> {
  const session = await getSession();
  assertActionPermitted(session, 'readonly');
  const spec = CustomKernelBuildSpecSchema.parse(rawSpec);
  const daemonRes = await callAgentApi<DaemonKernelStudioState>('/v1/system/kernel/studio', 'GET', undefined, 4000);
  const hw = daemonRes && daemonRes.hardware ? daemonRes.hardware : collectFallbackKernelStudioState().hardware;
  return compileCustomKernelArtifacts(spec, hw);
}

export async function triggerCustomKernelBuild(rawSpec: unknown, configOnly = false) {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  const spec = CustomKernelBuildSpecSchema.parse(rawSpec);

  const daemonRes = await callAgentApi<DaemonKernelStudioState>('/v1/system/kernel/studio', 'GET', undefined, 4000);
  const hw = daemonRes && daemonRes.hardware ? daemonRes.hardware : collectFallbackKernelStudioState().hardware;
  const compiled = compileCustomKernelArtifacts(spec, hw);

  const res = await callAgentApi<{
    success?: boolean;
    upid?: string;
    buildId?: string;
    message?: string;
    error?: string;
  }>(
    '/v1/system/kernel/build',
    'POST',
    {
      mode: spec.mode,
      configOnly,
      kernelVersion: spec.kernelVersion,
      arch: spec.arch,
      marchTarget: spec.marchTarget,
      capabilities: spec.capabilities,
      lockdownTier: spec.lockdownTier,
      enableRootlessUserNs: spec.enableRootlessUserNs,
      disableIa32Emulation: spec.disableIa32Emulation,
      enforceModuleSig: spec.enforceModuleSig,
      enableProcKcore: spec.enableProcKcore,
      hardwareFragment: compiled.kconfigFragment,
    },
    10000
  );

  if (!res) {
    return { success: false, message: 'axonwalld daemon unreachable over Unix socket.' };
  }
  return {
    success: Boolean(res.success),
    upid: res.upid,
    buildId: res.buildId,
    message: res.message || res.error || 'Kernel build request failed.',
  };
}

export async function installBuiltKernelArtifact(artifactName: string) {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  if (!artifactName || !/^linux-image-[a-zA-Z0-9._+-]+\.deb$/.test(artifactName.trim())) {
    return { success: false, message: 'Invalid kernel package filename.' };
  }

  const res = await callAgentApi<{
    success?: boolean;
    upid?: string;
    installMode?: string;
    safetyNote?: string;
    message?: string;
    error?: string;
  }>('/v1/system/kernel/install', 'POST', { artifactName: artifactName.trim() }, 10000);

  if (!res) {
    return { success: false, message: 'axonwalld daemon unreachable over Unix socket.' };
  }
  return {
    success: Boolean(res.success),
    upid: res.upid,
    installMode: res.installMode,
    safetyNote: res.safetyNote,
    message: res.message || res.error || 'Kernel install request failed.',
  };
}

export async function getKernelTaskProgress(upid: string) {
  const session = await getSession();
  assertActionPermitted(session, 'readonly');
  if (!upid || !upid.startsWith('UPID:')) {
    return null;
  }
  const res = await callAgentApi<DaemonKernelStudioState>(
    `/v1/system/kernel/studio?upid=${encodeURIComponent(upid)}`,
    'GET',
    undefined,
    4000
  );
  if (!res) return null;
  return {
    taskProgress: res.taskProgress || null,
    artifacts: res.artifacts || [],
  };
}
