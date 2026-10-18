import type {
  DesiredState,
  VirtualMachine,
  LxcContainer,
  PciPassthroughDevice,
  VxlanZone,
  VirtConfig,
} from '../../schemas/index.js';

export interface CompiledVmProcess {
  vmid: number;
  name: string;
  qemuBinary: string;
  args: string[];
  qmpSocket: string;
  vncSocket: string;
  serialSocket: string;
  pidFile: string;
}

export interface CompiledCloudInit {
  vmid: number;
  metaDataYaml: string;
  userDataYaml: string;
  networkConfigYaml: string;
  isoPath: string;
}

export interface CompiledLxcContainer {
  ctid: number;
  name: string;
  lxcConfig: string;
  rootfsPath: string;
}

export interface CompiledVfio {
  modprobeConf: string;
  udevRules: string;
  sriovInitScript: string;
}

export interface CompiledVxlan {
  ipCommands: string[];
}

export interface CompiledVirtBundle {
  vms: CompiledVmProcess[];
  cloudInits: CompiledCloudInit[];
  containers: CompiledLxcContainer[];
  vfio: CompiledVfio;
  vxlanCommands: string[];
}

function sanitizeIdentifier(v: string): string {
  return v.replace(/[^a-zA-Z0-9_.-]/g, '_');
}

export function generateDeterministicMac(vmid: number, nicIdx: number): string {
  const hexVmid = vmid.toString(16).padStart(4, '0');
  const b1 = hexVmid.slice(0, 2);
  const b2 = hexVmid.slice(2, 4);
  const b3 = (nicIdx & 0xff).toString(16).padStart(2, '0');
  return `bc:24:11:${b1}:${b2}:${b3}`;
}

export function compileVmProcess(vm: VirtualMachine): CompiledVmProcess {
  const qemuBinary = 'qemu-system-x86_64';
  const qmpSocket = `/run/axonwall/qmp/vm-${vm.vmid}.sock`;
  const vncSocket = `/run/axonwall/vnc/vm-${vm.vmid}.sock`;
  const serialSocket = `/run/axonwall/serial/vm-${vm.vmid}.sock`;
  const pidFile = `/run/axonwall/pids/vm-${vm.vmid}.pid`;

  const totalCpus = (vm.cores || 1) * (vm.sockets || 1);
  const cpuModel = vm.cpuType === 'host' ? 'host' : vm.cpuType || 'host';

  const args: string[] = [
    '-name',
    `${sanitizeIdentifier(vm.name)},process=axonwall-vm-${vm.vmid}`,
    '-enable-kvm',
    '-machine',
    'q35,accel=kvm',
    '-cpu',
    cpuModel,
    '-smp',
    `cpus=${totalCpus},cores=${vm.cores || 1},threads=1,sockets=${vm.sockets || 1}`,
    '-m',
    `${vm.memoryMb || 2048}`,
    '-pidfile',
    pidFile,
    '-chardev',
    `socket,id=qmp,path=${qmpSocket},server=on,wait=off`,
    '-mon',
    'chardev=qmp,mode=control',
    '-chardev',
    `socket,id=serial0,path=${serialSocket},server=on,wait=off`,
    '-serial',
    'chardev:serial0',
    '-vnc',
    `unix:${vncSocket}`,
  ];

  if (vm.bios === 'ovmf') {
    args.push(
      '-drive',
      'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd',
      '-drive',
      `if=pflash,format=raw,file=/var/lib/axonwall/nvram/vm-${vm.vmid}.fd`
    );
  }

  if (vm.tpm2) {
    args.push(
      '-chardev',
      `socket,id=chrtpm,path=/run/axonwall/swtpm/vm-${vm.vmid}.sock`,
      '-tpmdev',
      'emulator,id=tpm0,chardev=chrtpm',
      '-device',
      'tpm-tis,tpmdev=tpm0'
    );
  }

  if (vm.balloonMinMb && vm.balloonMinMb > 0) {
    args.push('-device', 'virtio-balloon-pci,id=balloon0');
  }

  if (vm.agent) {
    args.push(
      '-chardev',
      `socket,path=/run/axonwall/qga/vm-${vm.vmid}.sock,server=on,wait=off,id=qga0`,
      '-device',
      'virtio-serial',
      '-device',
      'virtserialport,chardev=qga0,name=org.qemu.guest_agent.0'
    );
  }

  // SCSI Controller if needed
  const hasScsi = vm.disks.some((d) => d.bus === 'scsi');
  if (hasScsi) {
    args.push('-device', 'virtio-scsi-pci,id=scsihw0');
  }

  // Storage Disks
  vm.disks.forEach((disk, idx) => {
    const driveId = `drive-disk${idx}`;
    const zvolPath =
      disk.zvol || `/dev/zvol/${disk.pool || 'tank'}/vms/vm-${vm.vmid}-disk-${idx}`;
    const cache = disk.cache || 'none';
    const discardOpt = disk.discard ? ',discard=unmap' : '';
    const aioOpt = cache === 'none' ? ',aio=native' : '';
    const roOpt = disk.readOnly ? ',readonly=on' : '';

    args.push(
      '-drive',
      `file=${zvolPath},if=none,id=${driveId},format=raw,cache=${cache}${discardOpt}${aioOpt}${roOpt}`
    );

    const bootIndex = idx + 1;
    switch (disk.bus) {
      case 'scsi':
        args.push(
          '-device',
          `scsi-hd,bus=scsihw0.0,drive=${driveId},id=scsi${idx},bootindex=${bootIndex}`
        );
        break;
      case 'sata':
        args.push(
          '-device',
          `ide-hd,drive=${driveId},id=sata${idx},bootindex=${bootIndex}`
        );
        break;
      case 'nvme':
        args.push(
          '-device',
          `nvme,drive=${driveId},id=nvme${idx},serial=AXON${vm.vmid}D${idx},bootindex=${bootIndex}`
        );
        break;
      case 'ide':
        args.push(
          '-device',
          `ide-hd,drive=${driveId},id=ide${idx},bootindex=${bootIndex}`
        );
        break;
      case 'virtio':
      default:
        args.push(
          '-device',
          `virtio-blk-pci,drive=${driveId},id=virtio${idx},bootindex=${bootIndex}`
        );
        break;
    }
  });

  // ISO / Optical Drive
  if (vm.iso) {
    args.push(
      '-drive',
      `file=${vm.iso},media=cdrom,id=cdrom0,readonly=on`
    );
  }

  // Cloud-Init Seed ISO
  if (vm.cloudInit) {
    args.push(
      '-drive',
      `file=/var/lib/axonwall/cloudinit/vm-${vm.vmid}-cidata.iso,media=cdrom,id=cloudinit0,readonly=on`
    );
  }

  // NICs
  vm.nics.forEach((nic, idx) => {
    const netId = `net${idx}`;
    const tapName = `tap${vm.vmid}i${idx}`;
    const mac = nic.mac || generateDeterministicMac(vm.vmid, idx);

    args.push(
      '-netdev',
      `tap,id=${netId},ifname=${tapName},script=no,downscript=no`
    );

    let devModel = 'virtio-net-pci';
    if (nic.model === 'e1000') devModel = 'e1000';
    if (nic.model === 'e1000e') devModel = 'e1000e';
    if (nic.model === 'vmxnet3') devModel = 'vmxnet3';

    args.push(
      '-device',
      `${devModel},netdev=${netId},mac=${mac},id=nic${idx}`
    );
  });

  // PCIe Passthrough
  vm.pciPassthrough.forEach((pciAddr) => {
    args.push('-device', `vfio-pci,host=${pciAddr}`);
  });

  // Standard VGA output
  args.push('-vga', 'std');

  return {
    vmid: vm.vmid,
    name: vm.name,
    qemuBinary,
    args,
    qmpSocket,
    vncSocket,
    serialSocket,
    pidFile,
  };
}

export function compileCloudInit(vm: VirtualMachine): CompiledCloudInit | null {
  if (!vm.cloudInit) return null;

  const hostname = sanitizeIdentifier(vm.name);
  const user = vm.cloudInit.user || 'axonadmin';

  const metaDataYaml = [
    '# Axonwall Cloud-Init Meta-Data',
    `instance-id: vm-${vm.vmid}`,
    `local-hostname: ${hostname}`,
    '',
  ].join('\n');

  const userDataLines = [
    '#cloud-config',
    `hostname: ${hostname}`,
    'manage_etc_hosts: true',
    'users:',
    `  - name: ${user}`,
    '    sudo: ALL=(ALL) NOPASSWD:ALL',
    '    shell: /bin/bash',
  ];

  if (vm.cloudInit.sshAuthorizedKeys && vm.cloudInit.sshAuthorizedKeys.length > 0) {
    userDataLines.push('    ssh_authorized_keys:');
    for (const key of vm.cloudInit.sshAuthorizedKeys) {
      userDataLines.push(`      - ${key.trim()}`);
    }
  }

  if (vm.cloudInit.password) {
    userDataLines.push(`    plain_text_passwd: ${vm.cloudInit.password}`);
    userDataLines.push('    lock_passwd: false');
  }

  if (vm.cloudInit.customUserData) {
    userDataLines.push('');
    userDataLines.push('# Custom User Data Hook:');
    userDataLines.push(vm.cloudInit.customUserData);
  }
  userDataLines.push('');

  const networkLines = ['version: 2', 'ethernets:', '  eth0:'];
  if (vm.cloudInit.ipConfig === 'dhcp') {
    networkLines.push('    dhcp4: true');
  } else {
    networkLines.push('    dhcp4: false');
    networkLines.push(`    addresses: [${vm.cloudInit.ipConfig}]`);
    if (vm.cloudInit.gateway) {
      networkLines.push(`    gateway4: ${vm.cloudInit.gateway}`);
    }
  }

  if (vm.cloudInit.nameservers && vm.cloudInit.nameservers.length > 0) {
    networkLines.push('    nameservers:');
    networkLines.push(`      addresses: [${vm.cloudInit.nameservers.join(', ')}]`);
    if (vm.cloudInit.searchDomain) {
      networkLines.push(`      search: [${vm.cloudInit.searchDomain}]`);
    }
  }
  networkLines.push('');

  return {
    vmid: vm.vmid,
    metaDataYaml,
    userDataYaml: userDataLines.join('\n'),
    networkConfigYaml: networkLines.join('\n'),
    isoPath: `/var/lib/axonwall/cloudinit/vm-${vm.vmid}-cidata.iso`,
  };
}

export function compileLxcContainer(ct: LxcContainer): CompiledLxcContainer {
  const rootfsPath = `/mnt/${ct.rootfsPool || 'tank'}/lxc/subvol-${ct.ctid}-disk-0`;
  const cores = Math.max(1, ct.cores || 1);
  const memoryMb = Math.max(256, ct.memoryMb || 1024);
  const swapMb = ct.swapMb ?? 512;

  const lines: string[] = [
    `# =============================================================================`,
    `# Axonwall Auto-Generated LXC Container Configuration`,
    `# Container ID: ${ct.ctid} (${ct.hostname})`,
    `# =============================================================================`,
    `lxc.uts.name = ${sanitizeIdentifier(ct.hostname)}`,
    `lxc.arch = x86_64`,
    `lxc.rootfs.path = dir:${rootfsPath}`,
    `lxc.cgroup2.memory.max = ${memoryMb}M`,
    `lxc.cgroup2.memory.swap.max = ${swapMb}M`,
    `lxc.cgroup2.cpuset.cpus = 0-${cores - 1}`,
  ];

  if (ct.unprivileged) {
    lines.push(
      '# Unprivileged container user/group namespaces',
      'lxc.idmap = u 0 100000 65536',
      'lxc.idmap = g 0 100000 65536'
    );
  }

  if (ct.features && ct.features.includes('nesting')) {
    lines.push('lxc.include = /usr/share/lxc/config/nesting.common.conf');
  }

  // Network Interfaces
  ct.nics.forEach((nic, idx) => {
    const mac = nic.mac || generateDeterministicMac(ct.ctid, idx);
    lines.push(
      `# Network Interface net${idx}`,
      `lxc.net.${idx}.type = veth`,
      `lxc.net.${idx}.flags = up`,
      `lxc.net.${idx}.link = ${nic.bridge || 'br0'}`,
      `lxc.net.${idx}.hwaddr = ${mac}`
    );
    if (nic.vlanTag) {
      lines.push(`lxc.net.${idx}.vlan.id = ${nic.vlanTag}`);
    }
  });

  // Mount Points
  ct.mountPoints.forEach((mp) => {
    const flags = mp.readOnly ? 'ro,bind,create=dir' : 'rw,bind,create=dir';
    lines.push(`lxc.mount.entry = ${mp.hostPath} ${mp.mountPath.replace(/^\//, '')} none ${flags} 0 0`);
  });

  lines.push('');

  return {
    ctid: ct.ctid,
    name: ct.hostname,
    lxcConfig: lines.join('\n'),
    rootfsPath,
  };
}

export function compileVfio(devices: PciPassthroughDevice[]): CompiledVfio {
  const vfioDevices = devices.filter(
    (d) => d.driver === 'vfio-pci' && d.vendorId && d.deviceId
  );

  const ids = Array.from(
    new Set(vfioDevices.map((d) => `${d.vendorId}:${d.deviceId}`))
  ).join(',');

  const modprobeConf = [
    '# Axonwall Auto-Generated VFIO Configuration',
    ids ? `options vfio-pci ids=${ids}` : '# No static PCI vendor:device IDs specified',
    '',
  ].join('\n');

  const udevRules = [
    '# Axonwall Auto-Generated VFIO Udev Rules',
    'SUBSYSTEM=="vfio", OWNER="root", GROUP="kvm", MODE="0660"',
    '',
  ].join('\n');

  const sriovLines: string[] = ['#!/bin/bash', 'set -e', '# Axonwall SR-IOV Initialization'];
  devices.forEach((d) => {
    if (d.sriovNumVfs && d.sriovNumVfs > 0) {
      sriovLines.push(
        `if [ -f /sys/bus/pci/devices/${d.bdf}/sriov_numvfs ]; then`,
        `  echo ${d.sriovNumVfs} > /sys/bus/pci/devices/${d.bdf}/sriov_numvfs`,
        `fi`
      );
    }
  });
  sriovLines.push('');

  return {
    modprobeConf,
    udevRules,
    sriovInitScript: sriovLines.join('\n'),
  };
}

export function compileVxlan(zones: VxlanZone[]): CompiledVxlan {
  const ipCommands: string[] = [];

  for (const zone of zones) {
    if (!zone.enabled) continue;
    const name = sanitizeIdentifier(zone.name);
    const port = zone.port || 4789;
    const dev = zone.underlayInterface || 'lan';
    const mtu = zone.mtu || 1450;

    ipCommands.push(
      `ip link add ${name} type vxlan id ${zone.vni} dstport ${port} dev ${dev}`
    );
    ipCommands.push(`ip link set ${name} mtu ${mtu}`);
    ipCommands.push(`ip link set ${name} up`);

    if (zone.bridge) {
      ipCommands.push(`ip link set ${name} master ${zone.bridge}`);
    }
  }

  return { ipCommands };
}

export function compileVirtBundle(state: DesiredState): CompiledVirtBundle {
  const virt: VirtConfig = state.virt ?? {
    enabled: false,
    defaultPool: 'tank',
    isoPool: 'tank',
    vms: [],
    containers: [],
    isos: [],
    pciDevices: [],
    backupJobs: [],
    vxlanZones: [],
  };

  const vms: CompiledVmProcess[] = [];
  const cloudInits: CompiledCloudInit[] = [];
  const containers: CompiledLxcContainer[] = [];

  for (const vm of virt.vms) {
    if (!vm.enabled) continue;
    vms.push(compileVmProcess(vm));
    const ci = compileCloudInit(vm);
    if (ci) {
      cloudInits.push(ci);
    }
  }

  for (const ct of virt.containers) {
    if (!ct.enabled) continue;
    containers.push(compileLxcContainer(ct));
  }

  const vfio = compileVfio(virt.pciDevices);
  const vxlan = compileVxlan(virt.vxlanZones);

  return {
    vms,
    cloudInits,
    containers,
    vfio,
    vxlanCommands: vxlan.ipCommands,
  };
}
