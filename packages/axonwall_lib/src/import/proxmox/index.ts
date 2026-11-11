import {
  DesiredStateSchema,
  type DesiredState,
  type VirtualMachine,
  type LxcContainer,
  type VmDisk,
  type VmNic,
  type Bridge,
  type VirtSecurityGroup,
  type FirewallRule,
  type ZfsPool,
} from '../../schemas/index.js';
import type { ImportReport } from '../types.js';

interface ParsedProxmoxBlock {
  kind: 'vm' | 'lxc' | 'storage' | 'interfaces' | 'firewall';
  id?: number;
  lines: string[];
}

function parseSizeToGb(raw: string | undefined, fallbackGb: number): number {
  if (!raw) return fallbackGb;
  const m = raw.trim().match(/^(\d+(?:\.\d+)?)([KMGTP])?B?$/i);
  if (!m) return fallbackGb;
  const num = Number.parseFloat(m[1]!);
  const unit = (m[2] || 'G').toUpperCase();
  if (unit === 'T') return Math.max(1, Math.round(num * 1024));
  if (unit === 'G') return Math.max(1, Math.round(num));
  if (unit === 'M') return Math.max(1, Math.ceil(num / 1024));
  return fallbackGb;
}

function parseKvPairs(val: string): Record<string, string> {
  const res: Record<string, string> = {};
  for (const token of val.split(',')) {
    const trimmed = token.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) {
      res._primary = res._primary ? `${res._primary},${trimmed}` : trimmed;
    } else {
      res[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
    }
  }
  return res;
}

function splitProxmoxSections(content: string): ParsedProxmoxBlock[] {
  const lines = content.replace(/\r\n/g, '\n').split('\n');
  const blocks: ParsedProxmoxBlock[] = [];
  let current: ParsedProxmoxBlock | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    const vmHeader = line.match(/^(?:#\s*={2,}\s*)?(?:\/etc\/pve\/)?qemu-server\/(\d+)\.conf(?:\s*={2,})?$/i) ||
      line.match(/^\[vm:(\d+)\]$/i);
    if (vmHeader) {
      current = { kind: 'vm', id: Number.parseInt(vmHeader[1]!, 10), lines: [] };
      blocks.push(current);
      continue;
    }

    const lxcHeader = line.match(/^(?:#\s*={2,}\s*)?(?:\/etc\/pve\/)?lxc\/(\d+)\.conf(?:\s*={2,})?$/i) ||
      line.match(/^\[(?:lxc|ct):(\d+)\]$/i);
    if (lxcHeader) {
      current = { kind: 'lxc', id: Number.parseInt(lxcHeader[1]!, 10), lines: [] };
      blocks.push(current);
      continue;
    }

    if (/^(?:#\s*={2,}\s*)?(?:\/etc\/pve\/)?storage\.cfg/i.test(line) || /^\[storage\]$/i.test(line)) {
      current = { kind: 'storage', lines: [] };
      blocks.push(current);
      continue;
    }

    if (/^(?:#\s*={2,}\s*)?\/etc\/network\/interfaces/i.test(line) || /^\[interfaces\]$/i.test(line)) {
      current = { kind: 'interfaces', lines: [] };
      blocks.push(current);
      continue;
    }

    if (/^(?:#\s*={2,}\s*)?(?:\/etc\/pve\/)?firewall\/.*\.fw/i.test(line) || /^\[RULES\]$/i.test(line) || /^\[securitygroup\s+/i.test(line)) {
      if (!current || current.kind !== 'firewall') {
        current = { kind: 'firewall', lines: [] };
        blocks.push(current);
      }
      current.lines.push(rawLine);
      continue;
    }

    if (!current) {
      if (!line || line.startsWith('#')) {
        continue;
      }
      // Auto-infer block type when user pastes a single unheadered Proxmox file
      const hasRootfs = lines.some((l) => /^\s*rootfs\s*:/i.test(l));
      const hasQemuMarkers = lines.some((l) => /^\s*(?:scsi0|virtio0|sata0|ide2|vmgenid|smbios1|bios|machine)\s*:/i.test(l));
      const hasStorageMarkers = lines.some((l) => /^\s*(?:zfspool|dir|pbs|nfs|cifs)\s*:\s*\S+/i.test(l));
      if (hasRootfs) {
        current = { kind: 'lxc', id: 100, lines: [] };
      } else if (hasQemuMarkers) {
        current = { kind: 'vm', id: 100, lines: [] };
      } else if (hasStorageMarkers) {
        current = { kind: 'storage', lines: [] };
      } else {
        current = { kind: 'vm', id: 100, lines: [] };
      }
      blocks.push(current);
    }

    current.lines.push(rawLine);
  }

  return blocks;
}

function parseProxmoxVm(vmid: number, lines: string[], defaultPool: string, warnings: string[]): VirtualMachine {
  let name = `pve-vm-${vmid}`;
  let cores = 2;
  let sockets = 1;
  let memoryMb = 2048;
  let bios: 'ovmf' | 'seabios' = 'seabios';
  let secureBoot = false;
  let tpm2 = false;
  let cpuType: 'host' | 'x86-64-v2-AES' | 'kvm64' | 'qemu64' = 'host';
  let osType: 'linux' | 'windows' | 'freebsd' | 'other' = 'linux';
  let numaEnabled = false;
  let hugepages: 'off' | '2M' | '1G' = 'off';
  let isTemplate = false;
  let autostart = false;
  let agent = true;
  const disks: VmDisk[] = [];
  const nics: VmNic[] = [];
  const pciPassthrough: string[] = [];
  const usbPassthrough: string[] = [];
  let ciUser = 'axonadmin';
  let ciPassword: string | undefined;
  let ciIpConfig = 'dhcp';
  let ciGateway: string | undefined;
  const ciSshKeys: string[] = [];
  let hasCloudInit = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    // Stop at snapshot sections [snapname]
    if (line.startsWith('[') && line.endsWith(']')) break;

    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const val = line.slice(colonIdx + 1).trim();

    if (key === 'name') {
      name = val.replace(/[^a-zA-Z0-9_.-]/g, '-') || name;
    } else if (key === 'cores') {
      cores = Math.max(1, Math.min(128, Number.parseInt(val, 10) || 2));
    } else if (key === 'sockets') {
      sockets = Math.max(1, Math.min(8, Number.parseInt(val, 10) || 1));
    } else if (key === 'memory') {
      memoryMb = Math.max(128, Number.parseInt(val, 10) || 2048);
    } else if (key === 'bios') {
      bios = val.toLowerCase().includes('ovmf') ? 'ovmf' : 'seabios';
    } else if (key === 'efidisk0') {
      bios = 'ovmf';
      if (val.includes('pre-enrolled-keys=1')) {
        secureBoot = true;
      }
    } else if (key === 'tpmstate0') {
      tpm2 = true;
    } else if (key === 'cpu') {
      const cleanCpu = val.split(',')[0]!.replace(/^cputype=/, '').trim();
      if (cleanCpu === 'x86-64-v2-AES' || cleanCpu === 'kvm64' || cleanCpu === 'qemu64' || cleanCpu === 'host') {
        cpuType = cleanCpu;
      } else {
        cpuType = 'host';
      }
    } else if (key === 'ostype') {
      if (val.startsWith('win')) osType = 'windows';
      else if (val.includes('bsd')) osType = 'freebsd';
      else if (val.startsWith('l2')) osType = 'linux';
      else osType = 'other';
    } else if (key === 'numa') {
      numaEnabled = val === '1' || val === 'true';
    } else if (key === 'hugepages') {
      if (val === '1024' || val === '1G') hugepages = '1G';
      else if (val === '2' || val === '2M' || val === 'any') hugepages = '2M';
    } else if (key === 'template') {
      isTemplate = val === '1' || val === 'true';
    } else if (key === 'onboot') {
      autostart = val === '1' || val === 'true';
    } else if (key === 'agent') {
      agent = !val.startsWith('0');
    } else if (/^(scsi|virtio|sata|ide)\d+$/.test(key)) {
      if (val.includes('media=cdrom') || val.includes('cloudinit')) {
        if (val.includes('cloudinit')) hasCloudInit = true;
        continue;
      }
      const kv = parseKvPairs(val);
      const primary = kv._primary || '';
      const storageParts = primary.split(':');
      const rawPool = storageParts.length > 1 ? storageParts[0]!.replace(/[^a-zA-Z0-9_.-]/g, '') : defaultPool;
      const pool = rawPool === 'local-zfs' || rawPool === 'local-lvm' || !rawPool ? defaultPool : rawPool;
      const busPrefix = key.replace(/\d+$/, '') as 'scsi' | 'virtio' | 'sata' | 'ide';
      disks.push({
        name: key,
        pool,
        sizeGb: parseSizeToGb(kv.size, 32),
        bus: busPrefix,
        cache: 'none',
        discard: kv.discard === 'on' || kv.ssd === '1' || true,
        iopsReadLimit: Number.parseInt(kv.iops_rd || '0', 10) || 0,
        iopsWriteLimit: Number.parseInt(kv.iops_wr || '0', 10) || 0,
        readOnly: kv.ro === '1',
        backup: kv.backup !== '0',
      });
    } else if (/^net\d+$/.test(key)) {
      const kv = parseKvPairs(val);
      let model: 'virtio' | 'e1000' | 'e1000e' | 'vmxnet3' = 'virtio';
      let mac = '';
      for (const candidate of ['virtio', 'e1000', 'e1000e', 'vmxnet3'] as const) {
        if (kv[candidate]) {
          model = candidate;
          mac = kv[candidate]!.toLowerCase();
          break;
        }
      }
      nics.push({
        mac: /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac) ? mac : '',
        bridge: kv.bridge || 'vmbr0',
        vlanTag: kv.tag ? Number.parseInt(kv.tag, 10) : undefined,
        model,
        firewall: kv.firewall !== '0',
        rateLimitMbps: kv.rate ? Math.round(Number.parseFloat(kv.rate) * 8) : 0,
      });
    } else if (/^hostpci\d+$/.test(key)) {
      const rawBdf = val.split(',')[0]!.trim();
      const normalizedBdf = rawBdf.split(':').length === 2 ? `0000:${rawBdf}` : rawBdf;
      const fullBdf = /\.\d$/.test(normalizedBdf) ? normalizedBdf : `${normalizedBdf}.0`;
      if (/^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$/.test(fullBdf)) {
        pciPassthrough.push(fullBdf);
      } else {
        warnings.push(`VM ${vmid}: skipped unrecognized PCI BDF '${rawBdf}'`);
      }
    } else if (/^usb\d+$/.test(key)) {
      const kv = parseKvPairs(val);
      const hostUsb = kv.host || kv._primary || '';
      if (/^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$/.test(hostUsb)) {
        usbPassthrough.push(hostUsb.toLowerCase());
      }
    } else if (key === 'ciuser') {
      ciUser = val;
      hasCloudInit = true;
    } else if (key === 'cipassword') {
      ciPassword = val;
      hasCloudInit = true;
    } else if (key === 'ipconfig0') {
      const kv = parseKvPairs(val);
      if (kv.ip) ciIpConfig = kv.ip;
      if (kv.gw) ciGateway = kv.gw;
      hasCloudInit = true;
    } else if (key === 'sshkeys') {
      try {
        const decoded = decodeURIComponent(val);
        for (const k of decoded.split('\n').map((s) => s.trim()).filter(Boolean)) {
          ciSshKeys.push(k);
        }
        hasCloudInit = true;
      } catch {
        // Ignore malformed percent-encoding
      }
    }
  }

  return {
    vmid: Math.max(100, Math.min(99999, vmid)),
    name,
    description: `Imported from Proxmox VE (VMID ${vmid})`,
    osType,
    bios,
    secureBoot,
    tpm2,
    sockets,
    cores,
    cpuType,
    numaEnabled,
    memoryMb,
    hugepages,
    balloonMinMb: 0,
    disks,
    nics,
    pciPassthrough,
    usbPassthrough,
    ...(hasCloudInit
      ? {
          cloudInit: {
            user: ciUser,
            ...(ciPassword ? { password: ciPassword } : {}),
            sshAuthorizedKeys: ciSshKeys,
            ipConfig: ciIpConfig,
            ...(ciGateway ? { gateway: ciGateway } : {}),
            nameservers: [],
          },
        }
      : {}),
    isTemplate,
    autostart,
    haManaged: false,
    agent,
    enabled: !isTemplate,
  };
}

function parseProxmoxLxc(ctid: number, lines: string[], defaultPool: string): LxcContainer {
  let hostname = `pve-ct-${ctid}`;
  let template = 'debian-12-standard';
  let unprivileged = true;
  let cores = 1;
  let memoryMb = 1024;
  let swapMb = 512;
  let rootfsPool = defaultPool;
  let rootfsSizeGb = 8;
  let autostart = false;
  const mountPoints: Array<{ mountPath: string; hostPath: string; readOnly: boolean }> = [];
  const nics: VmNic[] = [];
  const features: Array<'nesting' | 'keyctl' | 'fuse'> = ['nesting'];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('[') && line.endsWith(']')) break;
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const val = line.slice(colonIdx + 1).trim();

    if (key === 'hostname') {
      hostname = val.replace(/[^a-zA-Z0-9_.-]/g, '-') || hostname;
    } else if (key === 'ostype') {
      template = `${val}-standard`;
    } else if (key === 'unprivileged') {
      unprivileged = val !== '0';
    } else if (key === 'cores') {
      cores = Math.max(1, Math.min(128, Number.parseInt(val, 10) || 1));
    } else if (key === 'memory') {
      memoryMb = Math.max(256, Number.parseInt(val, 10) || 1024);
    } else if (key === 'swap') {
      swapMb = Math.max(0, Number.parseInt(val, 10) || 512);
    } else if (key === 'onboot') {
      autostart = val === '1' || val === 'true';
    } else if (key === 'rootfs') {
      const kv = parseKvPairs(val);
      const rawPool = (kv._primary || '').split(':')[0]?.replace(/[^a-zA-Z0-9_.-]/g, '') || defaultPool;
      rootfsPool = rawPool === 'local-zfs' || rawPool === 'local-lvm' ? defaultPool : rawPool;
      rootfsSizeGb = parseSizeToGb(kv.size, 8);
    } else if (/^mp\d+$/.test(key)) {
      const kv = parseKvPairs(val);
      if (kv._primary && kv.mp) {
        mountPoints.push({
          hostPath: kv._primary,
          mountPath: kv.mp,
          readOnly: kv.ro === '1',
        });
      }
    } else if (/^net\d+$/.test(key)) {
      const kv = parseKvPairs(val);
      nics.push({
        mac: kv.hwaddr && /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(kv.hwaddr) ? kv.hwaddr.toLowerCase() : '',
        bridge: kv.bridge || 'vmbr0',
        vlanTag: kv.tag ? Number.parseInt(kv.tag, 10) : undefined,
        vnet: kv.ip && kv.ip !== 'dhcp' ? kv.ip : undefined,
        model: 'virtio',
        firewall: kv.firewall !== '0',
        rateLimitMbps: 0,
      });
    } else if (key === 'features') {
      const kv = parseKvPairs(val);
      if (kv.keyctl === '1' && !features.includes('keyctl')) features.push('keyctl');
      if (kv.fuse === '1' && !features.includes('fuse')) features.push('fuse');
    }
  }

  return {
    ctid: Math.max(100, Math.min(99999, ctid)),
    hostname,
    description: `Imported from Proxmox VE LXC (CTID ${ctid})`,
    template,
    unprivileged,
    cores,
    memoryMb,
    swapMb,
    rootfsPool,
    rootfsSizeGb,
    mountPoints,
    nics,
    dnsServers: [],
    features,
    autostart,
    haManaged: false,
    enabled: true,
  };
}

export function importProxmoxConfig(content: string): ImportReport {
  const warnings: string[] = [];
  const trimmed = content.trim();

  let defaultPool = 'tank';
  const pools: ZfsPool[] = [];
  const vms: VirtualMachine[] = [];
  const containers: LxcContainer[] = [];
  const bridges: Bridge[] = [];
  const securityGroups: VirtSecurityGroup[] = [];
  const rules: FirewallRule[] = [];

  if (trimmed.startsWith('{')) {
    try {
      const parsedJson = JSON.parse(trimmed) as Record<string, unknown>;
      if (Array.isArray(parsedJson.vms)) {
        for (const v of parsedJson.vms as Array<Record<string, unknown>>) {
          vms.push(
            parseProxmoxVm(
              Number(v.vmid) || 100 + vms.length,
              Object.entries(v).map(([k, val]) => `${k}: ${String(val)}`),
              defaultPool,
              warnings,
            ),
          );
        }
      }
    } catch {
      warnings.push('Input started with { but was not valid JSON; falling back to Proxmox conf parser.');
    }
  }

  if (vms.length === 0) {
    const blocks = splitProxmoxSections(content);

    // First pass: storage & network bridges
    for (const blk of blocks) {
      if (blk.kind === 'storage') {
        let curType = '';
        let curPoolName = '';
        for (const raw of blk.lines) {
          const l = raw.trim();
          const hdr = l.match(/^(zfspool|dir|pbs|lvmthin)\s*:\s*(\S+)/i);
          if (hdr) {
            curType = hdr[1]!.toLowerCase();
            curPoolName = hdr[2]!;
            continue;
          }
          if (curType === 'zfspool') {
            const pm = l.match(/^pool\s+(\S+)/i);
            if (pm) {
              const rootPool = pm[1]!.split('/')[0]!.replace(/[^a-zA-Z0-9_.-]/g, '') || 'tank';
              defaultPool = rootPool;
              if (!pools.some((p) => p.name === rootPool)) {
                pools.push({
                  name: rootPool,
                  topology: 'mirror',
                  dataDisks: ['/dev/sda', '/dev/sdb'],
                  cacheDisks: [],
                  logDisks: [],
                  spareDisks: [],
                  ashift: 12,
                  autotrim: true,
                  compression: 'zstd',
                  scrubScheduleCron: '0 2 * * 0',
                  description: `Imported from Proxmox storage '${curPoolName}' (${pm[1]})`,
                });
              }
            }
          }
        }
      } else if (blk.kind === 'interfaces') {
        let curBridge: Bridge | null = null;
        for (const raw of blk.lines) {
          const l = raw.trim();
          const ifaceHdr = l.match(/^iface\s+(vmbr\d+)\s+inet\s+/i);
          if (ifaceHdr) {
            const newBridge: Bridge = {
              name: ifaceHdr[1]!,
              members: [],
              stp: false,
              vlanFiltering: true,
              description: `Imported Proxmox Linux Bridge ${ifaceHdr[1]}`,
            };
            curBridge = newBridge;
            bridges.push(newBridge);
            continue;
          }
          if (curBridge) {
            const bp = l.match(/^bridge[-_]ports\s+(.+)$/i);
            if (bp) {
              curBridge.members = bp[1]!
                .split(/\s+/)
                .filter((p) => p && p !== 'none')
                .map((iface) => ({ interface: iface, stp: false, cost: 100, priority: 32 }));
            }
            const stp = l.match(/^bridge[-_]stp\s+(on|yes|1)/i);
            if (stp) curBridge.stp = true;
          }
        }
      } else if (blk.kind === 'firewall') {
        let activeSg: VirtSecurityGroup | null = null;
        for (const raw of blk.lines) {
          const l = raw.trim();
          if (!l || l.startsWith('#')) continue;
          const sgMatch = l.match(/^\[securitygroup\s+([a-zA-Z0-9_-]+)\]$/i);
          if (sgMatch) {
            activeSg = {
              name: sgMatch[1]!,
              description: `Imported Proxmox Security Group ${sgMatch[1]}`,
              rules: [],
            };
            securityGroups.push(activeSg);
            continue;
          }
          if (l.startsWith('[')) {
            activeSg = null;
            continue;
          }
          const fwMatch = l.match(/^(IN|OUT)\s+(ACCEPT|DROP|REJECT)(?:\s+(.*))?$/i);
          if (fwMatch) {
            const dir = fwMatch[1]!.toLowerCase() as 'in' | 'out';
            const actRaw = fwMatch[2]!.toUpperCase();
            const rest = fwMatch[3] || '';
            const protoMatch = rest.match(/-p\s+(tcp|udp|icmp)/i);
            const dportMatch = rest.match(/-dport\s+([0-9,-:]+)/i);
            const srcMatch = rest.match(/-source\s+(\S+)/i);
            const dstMatch = rest.match(/-dest\s+(\S+)/i);
            const proto = (protoMatch?.[1]?.toLowerCase() || 'any') as 'any' | 'tcp' | 'udp' | 'icmp';
            const portSpec = (dportMatch?.[1] || '').replace(':', '-');

            if (activeSg) {
              activeSg.rules.push({
                direction: dir,
                action: actRaw === 'ACCEPT' ? 'accept' : actRaw === 'REJECT' ? 'reject' : 'drop',
                protocol: proto,
                cidr: (dir === 'in' ? srcMatch?.[1] : dstMatch?.[1]) || 'any',
                port: portSpec,
                description: 'Imported Proxmox SG rule',
              });
            } else {
              rules.push({
                action: actRaw === 'ACCEPT' ? 'pass' : actRaw === 'REJECT' ? 'reject' : 'block',
                direction: dir,
                interface: 'lan',
                quick: true,
                protocol: proto,
                source: srcMatch?.[1] || 'any',
                sourcePort: '',
                destination: dstMatch?.[1] || 'any',
                destinationPort: portSpec,
                log: false,
                enabled: true,
                description: 'Imported Proxmox VE firewall rule',
                sortOrder: (rules.length + 1) * 10,
              });
            }
          }
        }
      }
    }

    // Second pass: VMs and LXC containers
    let nextAutoId = 100;
    for (const blk of blocks) {
      if (blk.kind === 'vm') {
        const vmid = blk.id ?? nextAutoId++;
        vms.push(parseProxmoxVm(vmid, blk.lines, defaultPool, warnings));
      } else if (blk.kind === 'lxc') {
        const ctid = blk.id ?? nextAutoId++;
        containers.push(parseProxmoxLxc(ctid, blk.lines, defaultPool));
      }
    }
  }

  // Ensure all bridges referenced by VMs/LXCs exist in state.bridges
  const knownBridges = new Set(bridges.map((b) => b.name));
  for (const nic of [...vms.flatMap((v) => v.nics), ...containers.flatMap((c) => c.nics)]) {
    if (nic.bridge && !knownBridges.has(nic.bridge)) {
      knownBridges.add(nic.bridge);
      bridges.push({
        name: nic.bridge,
        members: [{ interface: 'eth1', stp: false, cost: 100, priority: 32 }],
        stp: false,
        vlanFiltering: true,
        description: `Auto-synthesized bridge for Proxmox ${nic.bridge}`,
      });
    }
  }

  const baseState = DesiredStateSchema.parse({
    plugins: [
      { id: 'core-firewall', enabled: true },
      { id: 'core-virt', enabled: true },
      ...(pools.length > 0 ? [{ id: 'core-nas', enabled: true }] : []),
    ],
    bridges,
    rules,
    ...(pools.length > 0
      ? {
          nas: {
            enabled: true,
            pools,
          },
        }
      : {}),
    virt: {
      enabled: true,
      defaultPool,
      isoPool: defaultPool,
      exportLibvirtXml: true,
      vms,
      containers,
      securityGroups,
    },
  });

  return {
    success: true,
    vendor: 'proxmox',
    version: 'Proxmox VE 8.x',
    sourceFormat: 'Proxmox VE qemu-server / lxc / storage.cfg / pve-firewall',
    interfacesCount: baseState.interfaces.length + bridges.length,
    vlansCount: baseState.vlans.length,
    aliasesCount: baseState.aliases.length,
    rulesCount: rules.length,
    natRulesCount: 0,
    dhcpSubnetsCount: 0,
    dnsOverridesCount: 0,
    routesCount: 0,
    vmsCount: vms.length,
    containersCount: containers.length,
    zfsPoolsCount: pools.length,
    warnings,
    state: baseState,
  };
}
