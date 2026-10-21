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
    if (vm) {
      const compiled = compileVmProcess(vm);
      await callAgentApi('/v1/virt/vms', 'POST', {
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
    success: true,
    message: `VM ${vmid} ${action} command queued (mock mode).`,
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
  await callAgentApi('/v1/virt/vms', 'POST', {
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
    },
  });

  return {
    success: true,
    message: `VM ${vm.vmid} (${vm.name}) saved to /etc/axonwall/virt.yaml.`,
  };
}

export async function deleteVmAction(
  vmid: number
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const state = await getCurrentDesiredState();
  if (!state.virt?.vms) {
    return { success: true, message: 'No VMs configured.' };
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
    message: `VM ${vmid} removed from configuration.`,
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
  action: 'start' | 'stop',
  force = false
): Promise<{ success: boolean; upid?: string; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');

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
    success: true,
    message: `Container ${ctid} ${action} command queued (mock mode).`,
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
  await callAgentApi('/v1/virt/containers', 'POST', {
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
    message: `LXC Container ${container.ctid} (${container.hostname}) saved to /etc/axonwall/virt.yaml.`,
  };
}

export async function deleteContainerAction(
  ctid: number
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const state = await getCurrentDesiredState();
  if (!state.virt?.containers) {
    return { success: true, message: 'No containers configured.' };
  }

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
    message: `Container ${ctid} removed from configuration.`,
  };
}

export async function getPciInventoryAction(): Promise<PciDeviceItem[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const daemonResp = await callAgentApi<{ devices: PciDeviceItem[] }>('/v1/virt/pci');
  if (daemonResp?.devices) {
    return daemonResp.devices;
  }

  return [];
}

export async function bindPciVfioAction(
  bdf: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const daemonResp = await callAgentApi<{ success: boolean; message?: string }>('/v1/virt/pci', 'POST', {
    action: 'bind',
    bdf,
  });

  return {
    success: daemonResp?.success ?? true,
    message: daemonResp?.message || `Device ${bdf} bound to vfio-pci.`,
  };
}

export async function unbindPciVfioAction(
  bdf: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const daemonResp = await callAgentApi<{ success: boolean; message?: string }>('/v1/virt/pci', 'POST', {
    action: 'unbind',
    bdf,
  });

  return {
    success: daemonResp?.success ?? true,
    message: daemonResp?.message || `Device ${bdf} released from vfio-pci.`,
  };
}

export async function configureSriovAction(
  bdf: string,
  numVfs: number
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const daemonResp = await callAgentApi<{ success: boolean; message?: string }>('/v1/virt/pci', 'POST', {
    action: 'sriov',
    bdf,
    numVfs,
  });

  return {
    success: daemonResp?.success ?? true,
    message: daemonResp?.message || `SR-IOV configured with ${numVfs} VFs on ${bdf}.`,
  };
}

export async function getIsoListAction(pool?: string): Promise<IsoItem[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const path = pool ? `/v1/virt/isos?pool=${encodeURIComponent(pool)}` : '/v1/virt/isos';
  const daemonResp = await callAgentApi<{ isos: IsoItem[] }>(path);
  if (daemonResp?.isos) {
    return daemonResp.isos;
  }
  return [];
}

export async function downloadIsoAction(
  url: string,
  filename: string,
  pool: string,
  sha256?: string
): Promise<{ success: boolean; upid?: string; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const daemonResp = await callAgentApi<{ success: boolean; upid?: string; message?: string }>(
    '/v1/virt/isos',
    'POST',
    { url, filename, pool, sha256 }
  );

  return {
    success: daemonResp?.success ?? true,
    upid: daemonResp?.upid,
    message: daemonResp?.message || `ISO download started for ${filename}.`,
  };
}

export async function getBackupListAction(pool?: string): Promise<BackupItem[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const path = pool ? `/v1/virt/backups?pool=${encodeURIComponent(pool)}` : '/v1/virt/backups';
  const daemonResp = await callAgentApi<{ backups: BackupItem[] }>(path);
  if (daemonResp?.backups) {
    return daemonResp.backups;
  }
  return [];
}

export async function triggerBackupAction(
  targetType: 'vm' | 'lxc',
  targetId: number,
  pool?: string,
  destType?: string
): Promise<{ success: boolean; upid?: string; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');

  const daemonResp = await callAgentApi<{ success: boolean; upid?: string; message?: string }>(
    '/v1/virt/backups',
    'POST',
    { targetType, targetId, pool: pool || 'tank', destType: destType || 'local-zfs' }
  );

  return {
    success: daemonResp?.success ?? true,
    upid: daemonResp?.upid,
    message: daemonResp?.message || `Backup job triggered for ${targetType} ${targetId}.`,
  };
}

export async function getTaskListAction(): Promise<TaskItem[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const daemonResp = await callAgentApi<{ tasks: TaskItem[] }>('/v1/tasks');
  if (daemonResp?.tasks) {
    return daemonResp.tasks;
  }
  return [];
}
