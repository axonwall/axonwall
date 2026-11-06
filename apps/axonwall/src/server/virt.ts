'use server';

import {
  type VirtualMachine,
  type LxcContainer,
  type IsoImage,
  type PciPassthroughDevice,
  type WorkloadBackupJob,
  type VxlanZone,
  type VirtConfig,
} from '@axonwall/lib/schemas';
import { compileVmProcess, compileLxcContainer } from '@axonwall/lib';
import { getCurrentDesiredState, applyDesiredState } from './agent';
import { callAgentApi } from './agent-client';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';

export interface VMStatusItem {
  vmid: number;
  name: string;
  status: 'running' | 'stopped' | 'paused';
  pid: number;
  cores: number;
  memoryMb: number;
  uptimeSeconds: number;
  qmpSocket: string;
  vncSocket: string;
  serialSocket: string;
  agentRunning: boolean;
}

export interface ContainerStatusItem {
  ctid: number;
  name: string;
  status: 'running' | 'stopped';
  pid: number;
  cores: number;
  memoryMb: number;
  ipAddress: string;
  uptimeSeconds: number;
}

export interface PciDeviceItem {
  bdf: string;
  vendorId: string;
  deviceId: string;
  deviceClass: string;
  deviceName: string;
  iommuGroup: number;
  currentDriver: string;
  isVfioBound: boolean;
  sriovSupported: boolean;
  sriovTotalVfs: number;
  sriovNumVfs: number;
}

export interface IsoItem {
  name: string;
  path: string;
  sizeBytes: number;
  pool: string;
}

export interface BackupItem {
  id: string;
  vmid: number;
  type: string;
  name: string;
  timestamp: number;
  sizeBytes: number;
  format: string;
  destination: string;
}

export interface TaskItem {
  upid: string;
  node: string;
  pid: number;
  startTime: number;
  endTime?: number;
  type: string;
  targetId: string;
  user: string;
  status: 'running' | 'stopped' | 'failed';
  exitStatus: string;
}

export async function getVirtConfigAction(): Promise<VirtConfig> {
  const session = await getSession();
  assertActionPermitted(session);

  const state = await getCurrentDesiredState();
  return (
    state.virt ?? {
      enabled: false,
      defaultPool: 'tank',
      isoPool: 'tank',
      vms: [],
      containers: [],
      isos: [],
      pciDevices: [],
      backupJobs: [],
      vxlanZones: [],
    }
  );
}

export async function getVmListAction(): Promise<VMStatusItem[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const state = await getCurrentDesiredState();
  const configuredVms = state.virt?.vms ?? [];

  const daemonResp = await callAgentApi<{ vms: VMStatusItem[] }>('/v1/virt/vms');
  // C25: a daemon outage used to collapse to "every VM stopped". Throw a
  // distinct daemon-unavailable error so pages render an unknown state
  // instead of a fabricated fleet-wide outage.
  if (!daemonResp) {
    throw new Error('Daemon unavailable: could not load live VM status from axonwalld');
  }
  const liveMap = new Map<number, VMStatusItem>();
  if (daemonResp?.vms) {
    for (const live of daemonResp.vms) {
      liveMap.set(live.vmid, live);
    }
  }

  return configuredVms.map((vm) => {
    const live = liveMap.get(vm.vmid);
    if (live) {
      return {
        ...live,
        name: vm.name,
        cores: vm.cores,
        memoryMb: vm.memoryMb,
      };
    }
    return {
      vmid: vm.vmid,
      name: vm.name,
      status: 'stopped',
      pid: 0,
      cores: vm.cores,
      memoryMb: vm.memoryMb,
      uptimeSeconds: 0,
      qmpSocket: `/run/axonwall/qmp/vm-${vm.vmid}.sock`,
      vncSocket: `/run/axonwall/vnc/vm-${vm.vmid}.sock`,
      serialSocket: `/run/axonwall/serial/vm-${vm.vmid}.sock`,
      agentRunning: false,
    };
  });
}

export async function vmPowerAction(
  vmid: number,
  action: 'start' | 'stop' | 'reset' | 'pause' | 'resume',
  force = false
): Promise<{ success: boolean; upid?: string; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');

  // Register spec with daemon on start if configured
  if (action === 'start') {
    const state = await getCurrentDesiredState();
    const vm = state.virt?.vms?.find((v) => v.vmid === vmid);
    // D1: never start a VM with no configured spec — the daemon would boot
    // a generic diskless VM (2 vCPU / 2048 MB, no disks, no NICs) that is
    // invisible in the VMs table.
    if (!vm) {
      return {
        success: false,
        message: `VM ${vmid} is not configured — refusing to start. Starting without a registered spec would boot a generic diskless VM.`,
      };
    }
    const compiled = compileVmProcess(vm);
    // D1: the register result used to be discarded, so a failed register
    // was invisible and the power POST booted the daemon's fallback spec.
    // Abort the start when registration fails or the daemon is unreachable.
    const registerResp = await callAgentApi<{ success: boolean; message?: string }>(
      '/v1/virt/vms',
      'POST',
      {
        action: 'register',
        vmid: vm.vmid,
        spec: {
          vmid: vm.vmid,
          name: vm.name,
          binary: compiled.qemuBinary,
          args: compiled.args,
          cores: vm.cores,
          memoryMb: vm.memoryMb,
          disks: vm.disks,
          cloudInit: vm.cloudInit
            ? {
                user: vm.cloudInit.user,
                password: vm.cloudInit.password || '',
                sshKeys: vm.cloudInit.sshAuthorizedKeys || [],
                ipConfig: vm.cloudInit.ipConfig,
                gateway: vm.cloudInit.gateway || '',
                nameservers: vm.cloudInit.nameservers || [],
                customPayload: vm.cloudInit.customUserData || '',
              }
            : null,
        },
      }
    );
    if (!registerResp || registerResp.success === false) {
      return {
        success: false,
        message:
          registerResp?.message ||
          `VM ${vmid} spec registration failed${registerResp ? '' : ' (daemon unreachable)'} — start aborted so no generic fallback VM boots.`,
      };
    }
  }

  const daemonResp = await callAgentApi<{ success: boolean; upid?: string; message?: string }>(
    '/v1/virt/vms',
    'POST',
    { action, vmid, force }
  );

  if (daemonResp) {
    return {
      success: daemonResp.success,
      upid: daemonResp.upid,
      message: daemonResp.message || `VM ${vmid} ${action} command sent.`,
    };
  }

  return {
    success: false,
    message: `Daemon unavailable: failed to execute ${action} on VM ${vmid}.`,
  };
}

export async function saveVmAction(
  vm: VirtualMachine
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const state = await getCurrentDesiredState();
  const currentVirt = state.virt ?? {
    enabled: true,
    defaultPool: 'tank',
    isoPool: 'tank',
    vms: [],
    containers: [],
    isos: [],
    pciDevices: [],
    backupJobs: [],
    vxlanZones: [],
  };

  const existingIdx = currentVirt.vms.findIndex((v) => v.vmid === vm.vmid);
  if (existingIdx >= 0 && vm.cloudInit?.password === '********') {
    const prevPw = currentVirt.vms[existingIdx]?.cloudInit?.password;
    if (prevPw && prevPw !== '********') {
      vm = {
        ...vm,
        cloudInit: {
          ...vm.cloudInit,
          password: prevPw,
        },
      };
    }
  }
  let updatedVms: VirtualMachine[];
  if (existingIdx >= 0) {
    updatedVms = [...currentVirt.vms];
    updatedVms[existingIdx] = vm;
  } else {
    updatedVms = [...currentVirt.vms, vm];
  }

  const updatedState = {
    ...state,
    capabilities: {
      firewallEnabled: state.capabilities?.firewallEnabled !== false,
      nasEnabled: Boolean(state.capabilities?.nasEnabled ?? state.nas?.enabled),
      k3sEnabled: Boolean(state.capabilities?.k3sEnabled ?? state.k3s?.enabled),
      virtEnabled: true,
      vigilanteEnabled: Boolean(state.capabilities?.vigilanteEnabled ?? state.vigilante?.enabled),
    },
    virt: {
      ...currentVirt,
      enabled: true,
      vms: updatedVms,
    },
  };

  await applyDesiredState(updatedState);

  // Register with daemon engine
  const compiled = compileVmProcess(vm);
  // D1: the register result used to be discarded. The config is saved, so
  // the save still succeeds — but a failed registration must be visible,
  // or the next start silently boots the daemon's generic fallback spec.
  const registerResp = await callAgentApi<{ success: boolean; message?: string }>('/v1/virt/vms', 'POST', {
    action: 'register',
    vmid: vm.vmid,
    spec: {
      vmid: vm.vmid,
      name: vm.name,
      binary: compiled.qemuBinary,
      args: compiled.args,
      cores: vm.cores,
      memoryMb: vm.memoryMb,
      disks: vm.disks,
      cloudInit: vm.cloudInit
        ? {
            user: vm.cloudInit.user,
            password: vm.cloudInit.password || '',
            sshKeys: vm.cloudInit.sshAuthorizedKeys || [],
            ipConfig: vm.cloudInit.ipConfig,
            gateway: vm.cloudInit.gateway || '',
            nameservers: vm.cloudInit.nameservers || [],
            customPayload: vm.cloudInit.customUserData || '',
          }
        : null,
    },
  });

  return {
    success: true,
    message:
      `VM ${vm.vmid} (${vm.name}) saved to /etc/axonwall/virt.yaml.` +
      (!registerResp || registerResp.success === false
        ? ' Warning: daemon spec registration failed (daemon unreachable or refused) — re-save once the daemon is back, or the next start may boot a generic fallback VM.'
        : ''),
  };
}

export async function deleteVmAction(
  vmid: number
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const state = await getCurrentDesiredState();
  if (!state.virt?.vms) {
    return { success: false, message: 'No VMs configured — nothing deleted.' };
  }
  if (!state.virt.vms.some((v) => v.vmid === vmid)) {
    return { success: false, message: `VM ${vmid} is not configured — nothing deleted.` };
  }

  // D2: deregister with the daemon BEFORE removing the config, and refuse
  // to pretend the delete happened when the daemon cannot be reached —
  // otherwise the registration (and disk) survive and re-creating the ID
  // resurrects the old VM. Best-effort stop first so a running VM is not
  // left orphaned after its spec is gone.
  await callAgentApi('/v1/virt/vms', 'POST', { action: 'stop', vmid, force: true });
  const unregisterResp = await callAgentApi<{ success: boolean; message?: string }>(
    '/v1/virt/vms',
    'POST',
    { action: 'unregister', vmid }
  );
  if (!unregisterResp || unregisterResp.success === false) {
    return {
      success: false,
      message: `Daemon unavailable or unregister refused — VM ${vmid} was NOT deleted; configuration and daemon registration preserved. Retry once axonwalld is reachable.`,
    };
  }

  const updatedState = {
    ...state,
    virt: {
      ...state.virt,
      vms: state.virt.vms.filter((v) => v.vmid !== vmid),
    },
  };

  await applyDesiredState(updatedState);
  return {
    success: true,
    message: `VM ${vmid} removed from configuration and unregistered from the daemon. NOTE: the ZVOL disk was NOT deleted and storage was not freed — re-creating VM ${vmid} will reuse the old disk.`,
  };
}

export async function getContainerListAction(): Promise<ContainerStatusItem[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const state = await getCurrentDesiredState();
  const configuredCts = state.virt?.containers ?? [];

  const daemonResp = await callAgentApi<{ containers: ContainerStatusItem[] }>(
    '/v1/virt/containers'
  );
  // C25: same as VMs — never render configured containers as "stopped"
  // when the daemon simply did not answer.
  if (!daemonResp) {
    throw new Error('Daemon unavailable: could not load live container status from axonwalld');
  }
  const liveMap = new Map<number, ContainerStatusItem>();
  if (daemonResp?.containers) {
    for (const live of daemonResp.containers) {
      liveMap.set(live.ctid, live);
    }
  }

  return configuredCts.map((ct) => {
    const live = liveMap.get(ct.ctid);
    if (live) {
      return {
        ...live,
        name: ct.hostname,
        cores: ct.cores,
        memoryMb: ct.memoryMb,
      };
    }
    return {
      ctid: ct.ctid,
      name: ct.hostname,
      status: 'stopped',
      pid: 0,
      cores: ct.cores,
      memoryMb: ct.memoryMb,
      ipAddress: '',
      uptimeSeconds: 0,
    };
  });
}

export async function containerPowerAction(
  ctid: number,
  action: 'start' | 'stop' | 'reboot' | 'reset',
  force = false
): Promise<{ success: boolean; upid?: string; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');

  if (action === 'start' || action === 'reboot' || action === 'reset') {
    const state = await getCurrentDesiredState();
    const ct = state.virt?.containers?.find((c) => c.ctid === ctid);
    // D1 (container shape): same discarded-register hole as VMs — a failed
    // register must abort before any stop/start, never silently proceed.
    if (!ct) {
      return {
        success: false,
        message: `Container ${ctid} is not configured — refusing to ${action}.`,
      };
    }
    const compiled = compileLxcContainer(ct);
    const registerResp = await callAgentApi<{ success: boolean; message?: string }>(
      '/v1/virt/containers',
      'POST',
      {
        action: 'register',
        ctid: ct.ctid,
        spec: {
          ctid: ct.ctid,
          hostname: ct.hostname,
          cores: ct.cores,
          memoryMb: ct.memoryMb,
          configPath: `/var/lib/lxc/${ct.ctid}/config`,
          rootfsPath: compiled.rootfsPath,
          features: ct.features,
        },
      }
    );
    if (!registerResp || registerResp.success === false) {
      return {
        success: false,
        message:
          registerResp?.message ||
          `Container ${ctid} spec registration failed${registerResp ? '' : ' (daemon unreachable)'} — ${action} aborted.`,
      };
    }
  }

  if (action === 'reboot' || action === 'reset') {
    await callAgentApi('/v1/virt/containers', 'POST', { action: 'stop', ctid, force: true });
    const startResp = await callAgentApi<{ success: boolean; upid?: string; message?: string }>(
      '/v1/virt/containers',
      'POST',
      { action: 'start', ctid, force }
    );
    if (startResp) {
      return {
        success: startResp.success,
        upid: startResp.upid,
        message: startResp.message || `Container ${ctid} restarted.`,
      };
    }
    return {
      success: false,
      message: `Daemon unavailable: failed to restart container ${ctid}.`,
    };
  }

  const daemonResp = await callAgentApi<{ success: boolean; upid?: string; message?: string }>(
    '/v1/virt/containers',
    'POST',
    { action, ctid, force }
  );

  if (daemonResp) {
    return {
      success: daemonResp.success,
      upid: daemonResp.upid,
      message: daemonResp.message || `Container ${ctid} ${action} command sent.`,
    };
  }

  return {
    success: false,
    message: `Daemon unavailable: failed to execute ${action} on container ${ctid}.`,
  };
}

export async function saveContainerAction(
  container: LxcContainer
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const state = await getCurrentDesiredState();
  const currentVirt = state.virt ?? {
    enabled: true,
    defaultPool: 'tank',
    isoPool: 'tank',
    vms: [],
    containers: [],
    isos: [],
    pciDevices: [],
    backupJobs: [],
    vxlanZones: [],
  };

  const existingIdx = currentVirt.containers.findIndex((c) => c.ctid === container.ctid);
  let updatedCts: LxcContainer[];
  if (existingIdx >= 0) {
    updatedCts = [...currentVirt.containers];
    updatedCts[existingIdx] = container;
  } else {
    updatedCts = [...currentVirt.containers, container];
  }

  const updatedState = {
    ...state,
    capabilities: {
      firewallEnabled: state.capabilities?.firewallEnabled !== false,
      nasEnabled: Boolean(state.capabilities?.nasEnabled ?? state.nas?.enabled),
      k3sEnabled: Boolean(state.capabilities?.k3sEnabled ?? state.k3s?.enabled),
      virtEnabled: true,
      vigilanteEnabled: Boolean(state.capabilities?.vigilanteEnabled ?? state.vigilante?.enabled),
    },
    virt: {
      ...currentVirt,
      enabled: true,
      containers: updatedCts,
    },
  };

  await applyDesiredState(updatedState);

  // Register with daemon engine
  const compiled = compileLxcContainer(container);
  // D1 (container shape): surface a failed registration instead of
  // discarding it — the config is saved, but the daemon may not know it.
  const registerResp = await callAgentApi<{ success: boolean; message?: string }>('/v1/virt/containers', 'POST', {
    action: 'register',
    ctid: container.ctid,
    spec: {
      ctid: container.ctid,
      hostname: container.hostname,
      cores: container.cores,
      memoryMb: container.memoryMb,
      configPath: `/var/lib/lxc/${container.ctid}/config`,
      rootfsPath: compiled.rootfsPath,
      features: container.features,
    },
  });

  return {
    success: true,
    message:
      `LXC Container ${container.ctid} (${container.hostname}) saved to /etc/axonwall/virt.yaml.` +
      (!registerResp || registerResp.success === false
        ? ' Warning: daemon spec registration failed (daemon unreachable or refused) — re-save once the daemon is back.'
        : ''),
  };
}

export async function deleteContainerAction(
  ctid: number
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const state = await getCurrentDesiredState();
  if (!state.virt?.containers) {
    return { success: false, message: 'No containers configured — nothing deleted.' };
  }
  if (!state.virt.containers.some((c) => c.ctid === ctid)) {
    return { success: false, message: `Container ${ctid} is not configured — nothing deleted.` };
  }

  // D2: best-effort stop so a running container is not left orphaned.
  // There is no daemon container-unregister action (the daemon handler only
  // knows register/start/stop), so the registration and rootfs CANNOT be
  // removed from here — say so explicitly instead of implying a clean
  // delete. Re-creating this CTID will reuse the old rootfs.
  await callAgentApi('/v1/virt/containers', 'POST', { action: 'stop', ctid, force: true });

  const updatedState = {
    ...state,
    virt: {
      ...state.virt,
      containers: state.virt.containers.filter((c) => c.ctid !== ctid),
    },
  };

  await applyDesiredState(updatedState);
  return {
    success: true,
    message: `Container ${ctid} removed from configuration. NOTE: the daemon registration and rootfs were NOT removed (no container unregister action exists) and storage was not freed — re-creating CTID ${ctid} will reuse the old rootfs.`,
  };
}

export async function getPciInventoryAction(): Promise<PciDeviceItem[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const daemonResp = await callAgentApi<{ devices: PciDeviceItem[] }>('/v1/virt/pci');
  // C25: a daemon outage used to render as "No PCI devices detected",
  // implying VT-d / IOMMU trouble that did not exist.
  if (!daemonResp?.devices) {
    throw new Error('Daemon unavailable: could not load PCI inventory from axonwalld');
  }

  return daemonResp.devices;
}

function validatePoolName(pool: string): void {
  if (!/^[a-zA-Z0-9_.-]+$/.test(pool) || pool.includes('..')) {
    throw new Error('Invalid storage pool name');
  }
}

function validateIsoFilename(filename: string): void {
  if (
    !filename ||
    filename.includes('/') ||
    filename.includes('\\') ||
    filename.includes('..') ||
    !/^[a-zA-Z0-9_.-]+$/.test(filename)
  ) {
    throw new Error('Invalid ISO filename');
  }
}

function validateIsoDownloadUrl(rawUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL((rawUrl || '').trim());
  } catch {
    throw new Error('Invalid ISO download URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('ISO download URL must use http: or https:');
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (
    host === 'localhost' ||
    host === '::1' ||
    host === '0.0.0.0' ||
    host.startsWith('127.') ||
    host.startsWith('169.254.') ||
    host === 'metadata.google.internal'
  ) {
    throw new Error('ISO download from loopback or link-local/metadata addresses is prohibited');
  }
}

function validatePciBdf(bdf: string): void {
  if (!/^(?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$/.test((bdf || '').trim())) {
    throw new Error('Invalid PCI BDF address');
  }
}

export async function bindPciVfioAction(
  bdf: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  validatePciBdf(bdf);

  const daemonResp = await callAgentApi<{ success: boolean; message?: string }>('/v1/virt/pci', 'POST', {
    action: 'bind',
    bdf,
  });

  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: failed to bind ${bdf} to vfio-pci.`,
    };
  }

  return {
    success: daemonResp.success,
    message: daemonResp.message || `Device ${bdf} bound to vfio-pci.`,
  };
}

export async function unbindPciVfioAction(
  bdf: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  validatePciBdf(bdf);

  const daemonResp = await callAgentApi<{ success: boolean; message?: string }>('/v1/virt/pci', 'POST', {
    action: 'unbind',
    bdf,
  });

  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: failed to release ${bdf} from vfio-pci.`,
    };
  }

  return {
    success: daemonResp.success,
    message: daemonResp.message || `Device ${bdf} released from vfio-pci.`,
  };
}

export async function configureSriovAction(
  bdf: string,
  numVfs: number
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  validatePciBdf(bdf);

  const daemonResp = await callAgentApi<{ success: boolean; message?: string }>('/v1/virt/pci', 'POST', {
    action: 'sriov',
    bdf,
    numVfs,
  });

  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: failed to configure SR-IOV on ${bdf}.`,
    };
  }

  return {
    success: daemonResp.success,
    message: daemonResp.message || `SR-IOV configured with ${numVfs} VFs on ${bdf}.`,
  };
}

export async function getIsoListAction(pool?: string): Promise<IsoItem[]> {
  const session = await getSession();
  assertActionPermitted(session);
  if (pool) {
    validatePoolName(pool);
  }

  const path = pool ? `/v1/virt/isos?pool=${encodeURIComponent(pool)}` : '/v1/virt/isos';
  const daemonResp = await callAgentApi<{ isos: IsoItem[] }>(path);
  // C25: never render "No ISO images found" for a daemon outage.
  if (!daemonResp?.isos) {
    throw new Error('Daemon unavailable: could not load ISO images from axonwalld');
  }
  return daemonResp.isos;
}

export async function downloadIsoAction(
  url: string,
  filename: string,
  pool: string,
  sha256?: string
): Promise<{ success: boolean; upid?: string; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  validatePoolName(pool);
  validateIsoFilename(filename);
  validateIsoDownloadUrl(url);

  const daemonResp = await callAgentApi<{ success: boolean; upid?: string; message?: string }>(
    '/v1/virt/isos',
    'POST',
    { url, filename, pool, sha256 }
  );

  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: failed to start ISO download for ${filename}.`,
    };
  }

  return {
    success: daemonResp.success,
    upid: daemonResp.upid,
    message: daemonResp.message || `ISO download started for ${filename}.`,
  };
}

export async function getBackupListAction(pool?: string): Promise<BackupItem[]> {
  const session = await getSession();
  assertActionPermitted(session);
  if (pool) {
    validatePoolName(pool);
  }

  const path = pool ? `/v1/virt/backups?pool=${encodeURIComponent(pool)}` : '/v1/virt/backups';
  const daemonResp = await callAgentApi<{ backups: BackupItem[] }>(path);
  // C25: never render "No backup archives found" for a daemon outage.
  if (!daemonResp?.backups) {
    throw new Error('Daemon unavailable: could not load backups from axonwalld');
  }
  return daemonResp.backups;
}

export async function triggerBackupAction(
  targetType: 'vm' | 'lxc',
  targetId: number,
  pool?: string,
  destType?: string
): Promise<{ success: boolean; upid?: string; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');
  if (pool) {
    validatePoolName(pool);
  }

  const daemonResp = await callAgentApi<{ success: boolean; upid?: string; message?: string }>(
    '/v1/virt/backups',
    'POST',
    { targetType, targetId, pool: pool || 'tank', destType: destType || 'local-zfs' }
  );

  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: failed to trigger backup job for ${targetType} ${targetId}.`,
    };
  }

  return {
    success: daemonResp.success,
    upid: daemonResp.upid,
    message: daemonResp.message || `Backup job triggered for ${targetType} ${targetId}.`,
  };
}

export async function getTaskListAction(): Promise<TaskItem[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const daemonResp = await callAgentApi<{ tasks: TaskItem[] }>('/v1/tasks');
  // C25: never render an empty task list for a daemon outage.
  if (!daemonResp?.tasks) {
    throw new Error('Daemon unavailable: could not load tasks from axonwalld');
  }
  return daemonResp.tasks;
}
