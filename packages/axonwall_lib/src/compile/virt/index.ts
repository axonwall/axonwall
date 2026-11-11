import type {
  DesiredState,
  VirtualMachine,
  LxcContainer,
  PciPassthroughDevice,
  VxlanZone,
  VirtConfig,
  Bridge,
  VirtioFsShare,
  VmDisk,
  VmNic,
} from '../../schemas/index.js';
import { HostedEdgeConfigSchema, FORBIDDEN_RING0_BPF_PROGS } from '../../schemas/index.js';
import { compileSatelliteNftables } from '../nft/index.js';

export interface CompiledVmProcess {
  id?: string;
  vmid: number;
  name: string;
  qemuBinary: string;
  args: string[];
  qmpSocket: string;
  vncSocket: string;
  serialSocket: string;
  qgaSocket?: string;
  pidFile: string;
  cores?: number;
  sockets?: number;
  memoryMb?: number;
  bios?: 'ovmf' | 'seabios';
  secureBoot?: boolean;
  tpm2?: boolean;
  cpuPinning?: string;
  numaEnabled?: boolean;
  hugepages?: 'off' | '2M' | '1G';
  isTemplate?: boolean;
  autostart?: boolean;
  haManaged?: boolean;
  virtioFsShares?: VirtioFsShare[];
  disks?: Array<VmDisk & { resolvedZvol: string }>;
  nics?: Array<VmNic & { tapName: string; resolvedMac: string }>;
  fwCfgFiles?: Array<{ path: string; content: string }>;
  libvirtXml?: string;
}

export type VmProcessSpec = CompiledVmProcess;

export interface CompiledHostedEdge {
  vmSpec: VmProcessSpec;
  userData: string;
  metaData: string;
  baselineNftScript: string;
  wanBridge: Bridge;
  lanBridge: Bridge;
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
  hostname?: string;
  template?: string;
  unprivileged?: boolean;
  cores?: number;
  memoryMb?: number;
  swapMb?: number;
  rootfsPool?: string;
  rootfsSizeGb?: number;
  lxcConfig: string;
  rootfsPath: string;
  autostart?: boolean;
  haManaged?: boolean;
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
  libvirtDomainsXml: Record<number, string>;
}

function sanitizeIdentifier(v: string): string {
  return v.replace(/[^a-zA-Z0-9_.-]/g, '_');
}

function sanitizeCloudInitScalar(val: string): string {
  const singleLine = String(val).replace(/[\r\n\0]+/g, ' ').trim();
  if (/[:#{}[\]&*?|>'"%@`]/.test(singleLine) || /\s/.test(singleLine)) {
    return JSON.stringify(singleLine);
  }
  return singleLine;
}

const SAFE_POOL_REGEX = /^[a-zA-Z0-9_.-]+$/;
const SAFE_ZVOL_PATH_REGEX = /^\/dev\/[a-zA-Z0-9_./-]+$/;
const SAFE_ISO_PATH_REGEX = /^\/[a-zA-Z0-9_./-]+$/;
const SAFE_MAC_REGEX = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
const SAFE_PCI_BDF_REGEX = /^([0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$/;
const SAFE_PCI_SLOT_REGEX = /^0x[0-9a-fA-F]+$/;
const SAFE_IFACE_REGEX = /^[a-zA-Z0-9_.:-]+$/;
const SAFE_FWCFG_NAME_REGEX = /^[a-zA-Z0-9_./-]+$/;

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
  const useSecBoot = vm.bios === 'ovmf' && Boolean(vm.secureBoot) && !vm.kernelPath;
  const machineSpec = useSecBoot ? 'q35,accel=kvm,smm=on' : 'q35,accel=kvm';

  const args: string[] = [
    '-name',
    `${sanitizeIdentifier(vm.name)},process=axonwall-vm-${vm.vmid}`,
    '-enable-kvm',
    '-machine',
    machineSpec,
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

  if (vm.bios === 'ovmf' && !vm.kernelPath) {
    if (useSecBoot) {
      args.push(
        '-global',
        'driver=cfi.pflash01,property=secure,value=on',
        '-drive',
        'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
        '-drive',
        `if=pflash,format=raw,unit=1,file=/var/lib/axonwall/nvram/vm-${vm.vmid}.fd`,
      );
    } else {
      args.push(
        '-drive',
        'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd',
        '-drive',
        `if=pflash,format=raw,file=/var/lib/axonwall/nvram/vm-${vm.vmid}.fd`,
      );
    }
  }

  if (vm.kernelPath) {
    if (
      vm.kernelPath.includes(',') ||
      vm.kernelPath.includes('..') ||
      /[\r\n\0]/.test(vm.kernelPath) ||
      !SAFE_ISO_PATH_REGEX.test(vm.kernelPath)
    ) {
      throw new Error(`Invalid VM kernel path: ${vm.kernelPath}`);
    }
    args.push('-kernel', vm.kernelPath);
    if (vm.initrdPath) {
      if (
        vm.initrdPath.includes(',') ||
        vm.initrdPath.includes('..') ||
        /[\r\n\0]/.test(vm.initrdPath) ||
        !SAFE_ISO_PATH_REGEX.test(vm.initrdPath)
      ) {
        throw new Error(`Invalid VM initrd path: ${vm.initrdPath}`);
      }
      args.push('-initrd', vm.initrdPath);
    }
    if (vm.kernelArgs) {
      args.push('-append', String(vm.kernelArgs).replace(/[\r\n\0]+/g, ' ').trim());
    }
  }

  if (vm.fwCfg && vm.fwCfg.length > 0) {
    for (const entry of vm.fwCfg) {
      if (
        !entry.name ||
        !entry.file ||
        entry.name.includes(',') ||
        entry.file.includes(',') ||
        entry.name.includes('..') ||
        entry.file.includes('..') ||
        !SAFE_FWCFG_NAME_REGEX.test(entry.name) ||
        !SAFE_ISO_PATH_REGEX.test(entry.file)
      ) {
        throw new Error(`Invalid VM fw_cfg entry: ${entry.name}=${entry.file}`);
      }
      args.push('-fw_cfg', `name=${entry.name},file=${entry.file}`);
    }
  }

  if (vm.watchdog === 'i6300esb') {
    args.push('-device', 'i6300esb', '-watchdog-action', 'reset');
  } else if (vm.watchdog === 'ib700') {
    args.push('-device', 'ib700', '-watchdog-action', 'reset');
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

  // Storage Disks (skipped when vm.diskless is true)
  if (!vm.diskless) {
    const hasScsi = vm.disks.some((d) => d.bus === 'scsi');
    if (hasScsi) {
      args.push('-device', 'virtio-scsi-pci,id=scsihw0');
    }

    vm.disks.forEach((disk, idx) => {
      const pool = disk.pool || 'tank';
      if (!SAFE_POOL_REGEX.test(pool) || pool.includes('..')) {
        throw new Error(`Invalid VM disk storage pool: ${pool}`);
      }
      const driveId = `drive-disk${idx}`;
      const zvolPath =
        disk.zvol || `/dev/zvol/${pool}/vms/vm-${vm.vmid}-disk-${idx}`;
      if (
        zvolPath.includes(',') ||
        zvolPath.includes('..') ||
        /[\r\n\0]/.test(zvolPath) ||
        !SAFE_ZVOL_PATH_REGEX.test(zvolPath)
      ) {
        throw new Error(`Invalid VM disk zvol path: ${zvolPath}`);
      }
      const cache = disk.cache || 'none';
      const discardOpt = disk.discard ? ',discard=unmap' : '';
      const aioOpt = cache === 'none' ? ',aio=native' : '';
      const roOpt = disk.readOnly ? ',readonly=on' : '';
      const iopsRdOpt = disk.iopsReadLimit && disk.iopsReadLimit > 0 ? `,iops_rd=${disk.iopsReadLimit}` : '';
      const iopsWrOpt = disk.iopsWriteLimit && disk.iopsWriteLimit > 0 ? `,iops_wr=${disk.iopsWriteLimit}` : '';

      args.push(
        '-drive',
        `file=${zvolPath},if=none,id=${driveId},format=raw,cache=${cache}${discardOpt}${aioOpt}${roOpt}${iopsRdOpt}${iopsWrOpt}`
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
  }

  // ISO / Optical Drive
  if (vm.iso) {
    if (
      vm.iso.includes(',') ||
      vm.iso.includes('..') ||
      /[\r\n\0]/.test(vm.iso) ||
      !SAFE_ISO_PATH_REGEX.test(vm.iso)
    ) {
      throw new Error(`Invalid VM ISO image path: ${vm.iso}`);
    }
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
    const tapName = nic.vnet && SAFE_IFACE_REGEX.test(nic.vnet) ? nic.vnet : `tap${vm.vmid}i${idx}`;
    const mac = nic.mac || generateDeterministicMac(vm.vmid, idx);
    if (!SAFE_MAC_REGEX.test(mac)) {
      throw new Error(`Invalid VM NIC MAC address: ${mac}`);
    }

    let netdevSpec = `tap,id=${netId},ifname=${tapName},script=no,downscript=no,vhost=on`;
    if (nic.queues && nic.queues > 1) {
      netdevSpec += `,queues=${nic.queues}`;
    }

    args.push('-netdev', netdevSpec);

    let devModel = 'virtio-net-pci';
    if (nic.model === 'e1000') devModel = 'e1000';
    if (nic.model === 'e1000e') devModel = 'e1000e';
    if (nic.model === 'vmxnet3') devModel = 'vmxnet3';

    let devSpec = `${devModel},netdev=${netId},mac=${mac},id=nic${idx}`;
    if (nic.queues && nic.queues > 1 && devModel === 'virtio-net-pci') {
      devSpec += `,mq=on,vectors=${2 * nic.queues + 2}`;
    }
    if (nic.pciAddr) {
      if (!SAFE_PCI_SLOT_REGEX.test(nic.pciAddr)) {
        throw new Error(`Invalid VM NIC PCI slot address: ${nic.pciAddr}`);
      }
      devSpec += `,addr=${nic.pciAddr}`;
    }

    args.push('-device', devSpec);
  });

  // PCIe Passthrough
  vm.pciPassthrough.forEach((pciAddr) => {
    if (!SAFE_PCI_BDF_REGEX.test(pciAddr)) {
      throw new Error(`Invalid PCIe passthrough BDF address: ${pciAddr}`);
    }
    args.push('-device', `vfio-pci,host=${pciAddr}`);
  });

  // VirtioFS Zero-Copy Host ZFS Dataset Mounts (vhost-user-fs-pci)
  if (vm.virtioFsShares && vm.virtioFsShares.length > 0) {
    args.push(
      '-object',
      `memory-backend-memfd,id=mem,size=${vm.memoryMb || 2048}M,share=on`,
      '-numa',
      'node,memdev=mem',
    );
    vm.virtioFsShares.forEach((share, idx) => {
      const safeTag = share.tag.replace(/[^a-zA-Z0-9_-]/g, '');
      args.push(
        '-chardev',
        `socket,id=vfs${idx},path=/run/axonwall/virtiofs/vm-${vm.vmid}-${safeTag}.sock`,
        '-device',
        `vhost-user-fs-pci,chardev=vfs${idx},tag=${safeTag}`,
      );
    });
  }

  // USB Host Passthrough (vendor:product e.g. 1050:0407 or bus.addr e.g. 1.4)
  if (vm.usbPassthrough && vm.usbPassthrough.length > 0) {
    args.push('-device', 'qemu-xhci,id=xhci0');
    vm.usbPassthrough.forEach((usbSpec, idx) => {
      const clean = usbSpec.trim();
      const vpMatch = clean.match(/^([0-9a-fA-F]{4}):([0-9a-fA-F]{4})$/);
      const busMatch = clean.match(/^(\d+)\.(\d+)$/);
      if (vpMatch) {
        args.push(
          '-device',
          `usb-host,bus=xhci0.0,vendorid=0x${vpMatch[1]},productid=0x${vpMatch[2]},id=usbhost${idx}`,
        );
      } else if (busMatch) {
        args.push(
          '-device',
          `usb-host,bus=xhci0.0,hostbus=${busMatch[1]},hostaddr=${busMatch[2]},id=usbhost${idx}`,
        );
      } else {
        throw new Error(`Invalid USB passthrough identifier (expected VVVV:PPPP or bus.addr): ${usbSpec}`);
      }
    });
  }

  // Standard VGA output
  args.push('-vga', 'std');

  const resolvedDisks = (vm.disks ?? []).map((disk, idx) => ({
    ...disk,
    resolvedZvol: disk.zvol || `/dev/zvol/${disk.pool || 'tank'}/vms/vm-${vm.vmid}-disk-${idx}`,
  }));
  const resolvedNics = (vm.nics ?? []).map((nic, idx) => ({
    ...nic,
    tapName: nic.vnet && SAFE_IFACE_REGEX.test(nic.vnet) ? nic.vnet : `tap${vm.vmid}i${idx}`,
    resolvedMac: nic.mac || generateDeterministicMac(vm.vmid, idx),
  }));

  return {
    ...(vm.id ? { id: vm.id } : {}),
    vmid: vm.vmid,
    name: vm.name,
    qemuBinary,
    args,
    qmpSocket,
    vncSocket,
    serialSocket,
    qgaSocket: vm.agent ? `/run/axonwall/qga/vm-${vm.vmid}.sock` : undefined,
    pidFile,
    cores: vm.cores || 2,
    sockets: vm.sockets || 1,
    memoryMb: vm.memoryMb || 2048,
    bios: vm.bios || 'ovmf',
    secureBoot: Boolean(vm.secureBoot),
    tpm2: Boolean(vm.tpm2),
    cpuPinning: vm.cpuPinning,
    numaEnabled: Boolean(vm.numaEnabled),
    hugepages: vm.hugepages || 'off',
    isTemplate: Boolean(vm.isTemplate),
    autostart: Boolean(vm.autostart),
    haManaged: Boolean(vm.haManaged),
    virtioFsShares: vm.virtioFsShares ?? [],
    disks: resolvedDisks,
    nics: resolvedNics,
    libvirtXml: compileLibvirtDomainXml(vm),
  };
}

export function compileLibvirtDomainXml(vm: VirtualMachine): string {
  const safeName = sanitizeIdentifier(vm.name);
  const vcpus = (vm.cores || 1) * (vm.sockets || 1);
  const memKib = (vm.memoryMb || 2048) * 1024;
  const secBoot = vm.bios === 'ovmf' && Boolean(vm.secureBoot);
  const xml: string[] = [
    `<domain type='kvm'>`,
    `  <name>${safeName}</name>`,
    `  <metadata>`,
    `    <axonwall:vm xmlns:axonwall='https://axonwall.com/xmlns/libvirt/1.0' vmid='${vm.vmid}' ha='${Boolean(vm.haManaged)}'/>`,
    `  </metadata>`,
    `  <memory unit='KiB'>${memKib}</memory>`,
    `  <vcpu placement='static'>${vcpus}</vcpu>`,
  ];

  if (vm.cpuPinning) {
    xml.push(`  <cputune>`);
    xml.push(`    <vcpupin vcpu='0' cpuset='${vm.cpuPinning.replace(/[^0-9,-]/g, '')}'/>`);
    xml.push(`  </cputune>`);
  }

  if (vm.hugepages && vm.hugepages !== 'off') {
    const pageSize = vm.hugepages === '1G' ? '1048576' : '2048';
    xml.push(`  <memoryBacking>`);
    xml.push(`    <hugepages><page size='${pageSize}' unit='KiB'/></hugepages>`);
    xml.push(`    <source type='memfd'/><access mode='shared'/>`);
    xml.push(`  </memoryBacking>`);
  } else if (vm.virtioFsShares && vm.virtioFsShares.length > 0) {
    xml.push(`  <memoryBacking><source type='memfd'/><access mode='shared'/></memoryBacking>`);
  }

  xml.push(`  <os>`);
  xml.push(`    <type arch='x86_64' machine='pc-q35-8.2'>hvm</type>`);
  if (vm.bios === 'ovmf' && !vm.kernelPath) {
    const loaderPath = secBoot ? '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd' : '/usr/share/OVMF/OVMF_CODE.fd';
    xml.push(`    <loader readonly='yes' secure='${secBoot ? 'yes' : 'no'}' type='pflash'>${loaderPath}</loader>`);
    xml.push(`    <nvram>/var/lib/axonwall/nvram/vm-${vm.vmid}.fd</nvram>`);
  }
  xml.push(`  </os>`);
  xml.push(`  <features><acpi/><apic/>${secBoot ? "<smm state='on'/>" : ''}</features>`);
  xml.push(`  <cpu mode='${vm.cpuType === 'host' ? 'host-passthrough' : 'custom'}'>`);
  xml.push(`    <topology sockets='${vm.sockets || 1}' dies='1' cores='${vm.cores || 1}' threads='1'/>`);
  xml.push(`  </cpu>`);
  xml.push(`  <devices>`);
  xml.push(`    <emulator>/usr/bin/qemu-system-x86_64</emulator>`);

  if (!vm.diskless) {
    vm.disks.forEach((disk, idx) => {
      const zvolPath = disk.zvol || `/dev/zvol/${disk.pool || 'tank'}/vms/vm-${vm.vmid}-disk-${idx}`;
      const devPrefix = disk.bus === 'scsi' ? 'sd' : disk.bus === 'nvme' ? 'nvme0n' : 'vd';
      const targetDev = disk.bus === 'nvme' ? `${devPrefix}${idx + 1}` : `${devPrefix}${String.fromCharCode(97 + idx)}`;
      const targetBus = disk.bus === 'nvme' ? 'virtio' : disk.bus || 'virtio';
      xml.push(`    <disk type='block' device='disk'>`);
      xml.push(`      <driver name='qemu' type='raw' cache='${disk.cache || 'none'}' discard='${disk.discard ? 'unmap' : 'ignore'}'/>`);
      xml.push(`      <source dev='${zvolPath}'/>`);
      xml.push(`      <target dev='${targetDev}' bus='${targetBus}'/>`);
      if (disk.readOnly) xml.push(`      <readonly/>`);
      xml.push(`    </disk>`);
    });
  }

  for (const share of vm.virtioFsShares ?? []) {
    xml.push(`    <filesystem type='mount' accessmode='passthrough'>`);
    xml.push(`      <driver type='virtiofs' queue='1024'/>`);
    xml.push(`      <source dir='${share.hostPath}'/>`);
    xml.push(`      <target dir='${share.tag}'/>`);
    if (share.readOnly) xml.push(`      <readonly/>`);
    xml.push(`    </filesystem>`);
  }

  vm.nics.forEach((nic, idx) => {
    const mac = nic.mac || generateDeterministicMac(vm.vmid, idx);
    const tapName = nic.vnet && SAFE_IFACE_REGEX.test(nic.vnet) ? nic.vnet : `tap${vm.vmid}i${idx}`;
    xml.push(`    <interface type='bridge'>`);
    xml.push(`      <mac address='${mac}'/>`);
    xml.push(`      <source bridge='${nic.bridge || 'br0'}'/>`);
    xml.push(`      <target dev='${tapName}'/>`);
    xml.push(`      <model type='${nic.model || 'virtio'}'/>`);
    if (nic.vlanTag && nic.vlanTag > 0) {
      xml.push(`      <vlan><tag id='${nic.vlanTag}'/></vlan>`);
    }
    xml.push(`    </interface>`);
  });

  if (vm.tpm2) {
    xml.push(`    <tpm model='tpm-tis'><backend type='emulator' version='2.0'/></tpm>`);
  }
  if (vm.agent) {
    xml.push(`    <channel type='unix'>`);
    xml.push(`      <source mode='bind' path='/run/axonwall/qga/vm-${vm.vmid}.sock'/>`);
    xml.push(`      <target type='virtio' name='org.qemu.guest_agent.0'/>`);
    xml.push(`    </channel>`);
  }
  xml.push(`    <graphics type='vnc' socket='/run/axonwall/vnc/vm-${vm.vmid}.sock'/>`);
  xml.push(`  </devices>`);
  xml.push(`</domain>`);
  return xml.join('\n') + '\n';
}

export function compileCloudInit(vm: VirtualMachine): CompiledCloudInit | null {
  if (!vm.cloudInit) return null;

  const hostname = sanitizeIdentifier(vm.name);
  const user = sanitizeCloudInitScalar(vm.cloudInit.user || 'axonadmin');

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
      const safeKey = String(key).replace(/[\r\n\0]+/g, ' ').trim();
      userDataLines.push(`      - ${safeKey}`);
    }
  }

  if (vm.cloudInit.password) {
    const safePassword = sanitizeCloudInitScalar(vm.cloudInit.password);
    userDataLines.push(`    plain_text_passwd: ${safePassword}`);
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
    const safeIpCfg = sanitizeCloudInitScalar(vm.cloudInit.ipConfig);
    networkLines.push('    dhcp4: false');
    networkLines.push(`    addresses: [${safeIpCfg}]`);
    if (vm.cloudInit.gateway) {
      networkLines.push(`    gateway4: ${sanitizeCloudInitScalar(vm.cloudInit.gateway)}`);
    }
  }

  if (vm.cloudInit.nameservers && vm.cloudInit.nameservers.length > 0) {
    const safeNs = vm.cloudInit.nameservers.map((ns) => sanitizeCloudInitScalar(ns));
    networkLines.push('    nameservers:');
    networkLines.push(`      addresses: [${safeNs.join(', ')}]`);
    if (vm.cloudInit.searchDomain) {
      networkLines.push(`      search: [${sanitizeCloudInitScalar(vm.cloudInit.searchDomain)}]`);
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
  const pool = ct.rootfsPool || 'tank';
  if (!SAFE_POOL_REGEX.test(pool) || pool.includes('..')) {
    throw new Error(`Invalid LXC rootfs pool: ${pool}`);
  }
  const rootfsPath = `/mnt/${pool}/lxc/subvol-${ct.ctid}-disk-0`;
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
    if (!SAFE_MAC_REGEX.test(mac)) {
      throw new Error(`Invalid LXC NIC MAC address: ${mac}`);
    }
    const bridge = nic.bridge || 'br0';
    if (!SAFE_IFACE_REGEX.test(bridge)) {
      throw new Error(`Invalid LXC bridge interface: ${bridge}`);
    }
    lines.push(
      `# Network Interface net${idx}`,
      `lxc.net.${idx}.type = veth`,
      `lxc.net.${idx}.flags = up`,
      `lxc.net.${idx}.link = ${bridge}`,
      `lxc.net.${idx}.hwaddr = ${mac}`
    );
    if (nic.vlanTag) {
      lines.push(`lxc.net.${idx}.vlan.id = ${nic.vlanTag}`);
    }
  });

  // Mount Points
  ct.mountPoints.forEach((mp) => {
    if (
      !mp.hostPath ||
      !mp.mountPath ||
      /[\r\n\0\s]/.test(mp.hostPath) ||
      /[\r\n\0\s]/.test(mp.mountPath) ||
      mp.hostPath.includes('..') ||
      mp.mountPath.includes('..') ||
      !mp.hostPath.startsWith('/mnt/') ||
      !/^\/mnt\/[a-zA-Z0-9_./-]+$/.test(mp.hostPath) ||
      !/^\/?[a-zA-Z0-9_./-]+$/.test(mp.mountPath)
    ) {
      throw new Error(`Invalid or unsafe LXC mount point: ${mp.hostPath} -> ${mp.mountPath}`);
    }
    const flags = mp.readOnly ? 'ro,bind,create=dir' : 'rw,bind,create=dir';
    lines.push(`lxc.mount.entry = ${mp.hostPath} ${mp.mountPath.replace(/^\//, '')} none ${flags} 0 0`);
  });

  // Linux 6.9+ Delegated bpffs & BPF_TOKEN_CREATE (UserNS Container eBPF)
  if (ct.bpfToken?.enabled && ct.bpfToken.preset !== 'disabled') {
    if (!ct.unprivileged) {
      throw new Error(
        `LXC container ${ct.ctid} (${ct.hostname}) cannot enable BPF_TOKEN delegation while unprivileged=false; CLONE_NEWUSER isolation is mandatory`,
      );
    }
    const presetDefaults: Record<
      string,
      { cmds: string; progs: string; maps: string; attachs: string }
    > = {
      'socket-observability': {
        cmds: 'prog_load:map_create:btf_load:map_lookup_elem:map_update_elem:map_delete_elem:map_get_next_key',
        progs: 'socket_filter:cgroup_skb',
        maps: 'array:hash:lru_hash:percpu_array:ringbuf',
        attachs: 'cgroup_inet_ingress:cgroup_inet_egress',
      },
      'network-dataplane': {
        cmds: 'prog_load:map_create:btf_load:link_create:link_update:link_detach:obj_pin:obj_get:map_lookup_elem:map_update_elem:map_delete_elem:map_get_next_key',
        progs: 'xdp:sched_cls:sched_act:socket_filter:cgroup_skb:cgroup_sock_addr:sk_skb:sk_msg',
        maps: 'array:percpu_array:hash:percpu_hash:lru_hash:lru_percpu_hash:lpm_trie:ringbuf:devmap:sockmap:sockhash',
        attachs: 'xdp:tcx_ingress:tcx_egress:cgroup_inet_ingress:cgroup_inet_egress:cgroup_inet4_connect:cgroup_inet6_connect',
      },
      'cgroup-microsegmentation': {
        cmds: 'prog_load:map_create:btf_load:link_create:map_lookup_elem:map_update_elem:map_delete_elem',
        progs: 'cgroup_skb:cgroup_sock:cgroup_sock_addr',
        maps: 'array:hash:lru_hash:lpm_trie:ringbuf',
        attachs: 'cgroup_inet_ingress:cgroup_inet_egress:cgroup_inet4_bind:cgroup_inet6_bind:cgroup_inet4_connect:cgroup_inet6_connect',
      },
    };

    const base = presetDefaults[ct.bpfToken.preset];
    const cmds = (ct.bpfToken.preset === 'custom' ? ct.bpfToken.delegateCmds : base?.cmds) || '';
    const progs = (ct.bpfToken.preset === 'custom' ? ct.bpfToken.delegateProgs : base?.progs) || '';
    const maps = (ct.bpfToken.preset === 'custom' ? ct.bpfToken.delegateMaps : base?.maps) || '';
    const attachs = (ct.bpfToken.preset === 'custom' ? ct.bpfToken.delegateAttachs : base?.attachs) || '';

    const safeOptRegex = /^[a-z0-9_:]+$/;
    for (const [label, val] of [
      ['delegate_cmds', cmds],
      ['delegate_progs', progs],
      ['delegate_maps', maps],
      ['delegate_attachs', attachs],
    ] as const) {
      if (!val || !safeOptRegex.test(val) || val.split(':').includes('any')) {
        throw new Error(`Invalid LXC BPF_TOKEN ${label}: '${val}'`);
      }
    }
    for (const p of progs.split(':')) {
      if ((FORBIDDEN_RING0_BPF_PROGS as readonly string[]).includes(p)) {
        throw new Error(
          `LXC BPF_TOKEN rejects Ring-0 program type '${p}' (prevents bpf_probe_read_kernel() host RAM inspection)`,
        );
      }
    }

    lines.push(
      '# Linux 6.9+ BPF_TOKEN_CREATE Delegation (UserNS Scoped, Zero Host CAP_BPF)',
      'lxc.environment = LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf',
      `lxc.mount.entry = bpffs sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,create=dir,delegate_cmds=${cmds},delegate_progs=${progs},delegate_maps=${maps},delegate_attachs=${attachs} 0 0`,
    );
  }

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
    if (!SAFE_IFACE_REGEX.test(dev)) {
      throw new Error(`Invalid VXLAN underlay interface: ${dev}`);
    }
    const mtu = zone.mtu || 1450;

    ipCommands.push(
      `ip link add ${name} type vxlan id ${zone.vni} dstport ${port} dev ${dev}`
    );
    ipCommands.push(`ip link set ${name} mtu ${mtu}`);
    ipCommands.push(`ip link set ${name} up`);

    if (zone.bridge) {
      if (!SAFE_IFACE_REGEX.test(zone.bridge)) {
        throw new Error(`Invalid VXLAN bridge interface: ${zone.bridge}`);
      }
      ipCommands.push(`ip link set ${name} master ${zone.bridge}`);
    }
  }

  return { ipCommands };
}

export function compileHostedEdge(
  state: DesiredState,
  opts?: { ztpToken?: string; caCertPem?: string; hostname?: string }
): CompiledHostedEdge {
  const edgeCfg = HostedEdgeConfigSchema.parse(state.hostedEdge ?? {});
  const slot = edgeCfg.ukiSlot || 'A';
  const sku = edgeCfg.skuProfile || 'sku-vm-virtio';
  const hostHostname = sanitizeIdentifier(opts?.hostname || state.system?.hostname || 'axonwall');
  const edgeId = `edge-${hostHostname}`;
  const ztpToken = opts?.ztpToken || 'ztp_hosted_edge_bootstrap';
  const hubIpOnly = (edgeCfg.lan.hostAddress || '10.0.0.2/24').split('/')[0] || '10.0.0.2';
  const hubPort = state.fleet?.listenPort || 2966;
  const hubUrl = `wss://${hubIpOnly}:${hubPort}/ws/satellite`;

  const wanBridgeName = edgeCfg.wan.bridgeName || 'br-wan';
  const lanBridgeName = edgeCfg.lan.bridgeName || 'br-lan';
  const wanMac =
    edgeCfg.ha.sharedWanMac ||
    edgeCfg.wan.macAddress ||
    generateDeterministicMac(100, 0);
  const lanMac = generateDeterministicMac(100, 1);

  const disabledIpv6Interfaces: string[] = [];
  if (edgeCfg.wan.ipv6Mode === 'disabled') {
    disabledIpv6Interfaces.push('eth0');
  }
  if (edgeCfg.lan.ipv6Mode === 'disabled') {
    disabledIpv6Interfaces.push('eth1');
  }

  const { nftScript: baselineNftScript } = compileSatelliteNftables({
    id: edgeId,
    role: 'edge-ngfw',
    skuProfile: sku,
    wanInterface: 'eth0',
    lanInterface: 'eth1',
    fastpathOffload: true,
    hardwareOffload: sku === 'sku-x86-enterprise-10g-25g',
    disabledIpv6Interfaces,
    portForwards: edgeCfg.portForwards,
    ipv6Allow: edgeCfg.ipv6Allow,
  });

  const edgeVm: VirtualMachine = {
    id: 'edge',
    vmid: 100,
    name: 'axonwall-edge-ngfw',
    description: 'Hosted Super-Slim Edge NGFW (UKI PID 1)',
    osType: 'linux',
    bios: 'ovmf',
    secureBoot: false,
    tpm2: false,
    sockets: 1,
    cores: edgeCfg.vcpus || 2,
    cpuType: 'host',
    memoryMb: edgeCfg.memoryMiB || 256,
    balloonMinMb: 0,
    disks: [],
    diskless: true,
    kernelPath: `/usr/lib/axonwall/edge/slot-${slot}/axonwall-edge-${sku}.efi`,
    fwCfg: [
      { name: 'opt/org.axonwall/user-data', file: '/run/axonwall/edge/user-data' },
      { name: 'opt/org.axonwall/meta-data', file: '/run/axonwall/edge/meta-data' },
    ],
    watchdog: 'i6300esb',
    nics: [
      {
        id: 'wan',
        mac: wanMac,
        bridge: wanBridgeName,
        vnet: 'tap-edge-wan',
        model: 'virtio',
        firewall: false,
        rateLimitMbps: 0,
        attachMode: edgeCfg.wan.attachMode || 'bridge',
        hostDevice: edgeCfg.wan.hostDevice || 'eth0',
        pciAddr: '0x3',
      },
      {
        id: 'lan',
        mac: lanMac,
        bridge: lanBridgeName,
        vnet: 'tap-edge-lan',
        model: 'virtio',
        firewall: false,
        rateLimitMbps: 0,
        attachMode: 'bridge',
        queues: 2,
        pciAddr: '0x4',
      },
    ],
    pciPassthrough: [],
    usbPassthrough: [],
    autostart: true,
    haManaged: edgeCfg.ha.enabled,
    agent: false,
    enabled: true,
  };

  const vmSpec = compileVmProcess(edgeVm);

  const wanAddrSpec =
    edgeCfg.wan.ipv4Mode === 'static' && edgeCfg.wan.ipv4Address
      ? edgeCfg.wan.ipv4Address
      : 'dhcp';

  const nftB64 = Buffer.from(baselineNftScript, 'utf8').toString('base64');

  const userDataLines: string[] = [
    '#cloud-config',
    `hostname: ${edgeId}`,
    'axonwall:',
    `  hub: ${hubUrl}`,
    `  id: ${edgeId}`,
    `  token: ${sanitizeCloudInitScalar(ztpToken)}`,
    `  sku: ${sku}`,
    `  slot: ${slot}`,
  ];

  if (opts?.caCertPem && opts.caCertPem.trim()) {
    userDataLines.push('  ca_cert: |');
    for (const line of opts.caCertPem.trim().split(/\r?\n/)) {
      userDataLines.push(`    ${line}`);
    }
  }

  userDataLines.push(
    '  interfaces:',
    '    - name: wan',
    '      device: eth0',
    `      address: ${wanAddrSpec}`,
  );
  if (edgeCfg.wan.ipv4Mode === 'static' && edgeCfg.wan.ipv4Gateway) {
    userDataLines.push(`      gateway: ${edgeCfg.wan.ipv4Gateway}`);
  }
  userDataLines.push(
    `      ipv6_mode: ${edgeCfg.wan.ipv6Mode}`,
    '    - name: lan',
    '      device: eth1',
    `      address: ${edgeCfg.lan.edgeAddress}`,
    `      ipv6_mode: ${edgeCfg.lan.ipv6Mode}`,
    'write_files:',
    '  - path: /etc/nftables.conf',
    '    permissions: "0600"',
    '    encoding: b64',
    `    content: ${nftB64}`,
    '',
  );

  const metaData = [
    '# Axonwall Hosted Edge NGFW Cloud-Init Meta-Data',
    `instance-id: ${edgeId}`,
    `local-hostname: ${edgeId}`,
    '',
  ].join('\n');

  const wanBridge: Bridge = {
    name: wanBridgeName,
    members: [
      {
        interface: edgeCfg.wan.hostDevice || 'eth0',
        stp: false,
        cost: 100,
        priority: 32,
      },
    ],
    vlanFiltering: false,
    stp: false,
    description: 'Hardened L2 WAN Transit Bridge (no host L3 stack)',
  };

  const lanHostDevs = (state.interfaces || [])
    .filter(
      (i) =>
        i.enabled &&
        i.role !== 'wan-delegated' &&
        i.device !== edgeCfg.wan.hostDevice &&
        i.device !== wanBridgeName &&
        i.device !== lanBridgeName,
    )
    .map((i) => ({
      interface: i.device,
      stp: false,
      cost: 100,
      priority: 32,
    }));

  const lanBridge: Bridge = {
    name: lanBridgeName,
    members: lanHostDevs,
    vlanFiltering: true,
    stp: false,
    description: 'Internal LAN & Service Bridge (Edge + Host + NAS + K3s)',
  };

  return {
    vmSpec,
    userData: userDataLines.join('\n'),
    metaData,
    baselineNftScript,
    wanBridge,
    lanBridge,
  };
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
  const libvirtDomainsXml: Record<number, string> = {};

  for (const vm of virt.vms) {
    if (!vm.enabled) continue;
    const compiledVm = compileVmProcess(vm);
    vms.push(compiledVm);
    if (virt.exportLibvirtXml !== false && compiledVm.libvirtXml) {
      libvirtDomainsXml[vm.vmid] = compiledVm.libvirtXml;
    }
    const ci = compileCloudInit(vm);
    if (ci) {
      cloudInits.push(ci);
    }
  }

  for (const ct of virt.containers) {
    if (!ct.enabled) continue;
    const compiledCt = compileLxcContainer(ct);
    containers.push({
      ...compiledCt,
      hostname: ct.hostname,
      template: ct.template,
      unprivileged: ct.unprivileged,
      cores: ct.cores,
      memoryMb: ct.memoryMb,
      swapMb: ct.swapMb,
      rootfsPool: ct.rootfsPool,
      rootfsSizeGb: ct.rootfsSizeGb,
      autostart: ct.autostart,
      haManaged: ct.haManaged,
    });
  }

  const vfio = compileVfio(virt.pciDevices);
  const vxlan = compileVxlan(virt.vxlanZones);

  return {
    vms,
    cloudInits,
    containers,
    vfio,
    vxlanCommands: vxlan.ipCommands,
    libvirtDomainsXml,
  };
}
