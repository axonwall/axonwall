import {
  DesiredStateSchema,
  InterfaceSchema,
  inferInterfaceRole,
  isInterfaceAuthoritativeDhcp,
  type DesiredState,
  type InterfaceRole,
} from '@axonwall/lib/schemas';
import { isValidDevice } from '@axonwall/lib/util';
import {
  AXONWALL_YAML_FILENAMES,
  parseDesiredStateFromYamlFiles,
  serializeDesiredStateToYamlFiles,
} from '@axonwall/lib/yaml';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  discoverHostPrimaryDevices,
  getEtcConfigDir,
  getPersistConfigDir,
  getStateJsonPath,
  isApplianceRuntime,
  readHostOSRelease,
} from './dev-paths';

export const ETC_CONFIG_DIR = getEtcConfigDir();
export const PERSIST_CONFIG_DIR = getPersistConfigDir();
export const YAML_CONFIG_DIRS = Array.from(new Set([PERSIST_CONFIG_DIR, ETC_CONFIG_DIR]));

export type OnDiskConfigSnapshotEntry = {
  path: string;
  existed: boolean;
  content: string | null;
};

export function ipToUint32(ipStr: string): number | null {
  const octets = ipStr.trim().split('.').map((n) => parseInt(n, 10));
  if (octets.length !== 4 || octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return null;
  }
  return (((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3]) >>> 0;
}

export function uint32ToIp(val: number): string {
  return `${(val >>> 24) & 255}.${(val >>> 16) & 255}.${(val >>> 8) & 255}.${val & 255}`;
}

export function computeSubnetAndDefaultPool(ipv4Cidr?: string): {
  routerIp: string;
  subnetCidr: string;
  poolStart: string;
  poolEnd: string;
  firstUsableInt: number;
  lastUsableInt: number;
} | null {
  if (!ipv4Cidr) return null;
  const parts = ipv4Cidr.trim().split('/');
  const ipStr = parts[0] || '';
  const prefix = parts[1] ? parseInt(parts[1], 10) : 24;
  const ipInt = ipToUint32(ipStr);
  if (ipInt === null || Number.isNaN(prefix) || prefix < 8 || prefix > 30) {
    return null;
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const netInt = (ipInt & mask) >>> 0;
  const bcastInt = (netInt | (~mask >>> 0)) >>> 0;
  const firstUsableInt = (netInt + 1) >>> 0;
  const lastUsableInt = (bcastInt - 1) >>> 0;

  const subnetCidr = `${uint32ToIp(netInt)}/${prefix}`;
  if (prefix <= 24) {
    const base24 = (ipInt & 0xffffff00) >>> 0;
    let startInt = (base24 + 100) >>> 0;
    let endInt = (base24 + 200) >>> 0;
    if (ipInt >= startInt && ipInt <= endInt) {
      startInt = (base24 + 10) >>> 0;
      endInt = (base24 + 99) >>> 0;
    }
    return {
      routerIp: ipStr,
      subnetCidr,
      poolStart: uint32ToIp(startInt),
      poolEnd: uint32ToIp(endInt),
      firstUsableInt,
      lastUsableInt,
    };
  }
  let startInt = firstUsableInt;
  let endInt = lastUsableInt;
  if (ipInt === firstUsableInt && firstUsableInt < lastUsableInt) {
    startInt = (firstUsableInt + 1) >>> 0;
  } else if (ipInt === lastUsableInt && lastUsableInt > firstUsableInt) {
    endInt = (lastUsableInt - 1) >>> 0;
  } else if (ipInt > firstUsableInt && ipInt < lastUsableInt) {
    const lowerSpan = ipInt - firstUsableInt;
    const upperSpan = lastUsableInt - ipInt;
    if (upperSpan >= lowerSpan) {
      startInt = (ipInt + 1) >>> 0;
    } else {
      endInt = (ipInt - 1) >>> 0;
    }
  }
  return {
    routerIp: ipStr,
    subnetCidr,
    poolStart: uint32ToIp(Math.min(startInt, endInt)),
    poolEnd: uint32ToIp(Math.max(startInt, endInt)),
    firstUsableInt,
    lastUsableInt,
  };
}

function isMinimalEditionHost(): boolean {
  try {
    const etcDir = getEtcConfigDir();
    if (fs.existsSync(path.join(etcDir, '.minimal-edition'))) {
      return true;
    }
    const edPath = path.join(etcDir, 'edition');
    if (fs.existsSync(edPath)) {
      return fs.readFileSync(edPath, 'utf8').trim() === 'minimal';
    }
  } catch {}
  return false;
}

function readSystemHostname(fallback: string): string {
  try {
    if (fs.existsSync('/etc/hostname')) {
      const hn = fs.readFileSync('/etc/hostname', 'utf8').trim();
      if (hn) return hn;
    }
  } catch {}
  return fallback;
}

function buildBaselineState(): DesiredState {
  const hostDevices = !isApplianceRuntime() ? discoverHostPrimaryDevices() : [];
  let wanDev = hostDevices[0] || 'eth0';
  let wanMode: 'dhcp' | 'static' = 'dhcp';
  let wanIp: string | undefined;
  let wanGw: string | undefined;
  let lanDev = hostDevices.length >= 2 ? hostDevices[1] : isApplianceRuntime() || hostDevices.length === 0 ? 'eth1' : '';
  let lanMode: 'dhcp' | 'static' = 'static';
  let lanIp = '192.168.1.1/24';
  let opt1Dev = '';
  let opt1Mode: 'dhcp' | 'static' = 'dhcp';
  let opt1Ip: string | undefined;
  let opt2Dev = '';
  let opt2Mode: 'dhcp' | 'static' = 'dhcp';
  let opt2Ip: string | undefined;

  try {
    const confPath = path.join(getEtcConfigDir(), 'interfaces.conf');
    if (fs.existsSync(confPath)) {
      const conf = fs.readFileSync(confPath, 'utf8');
      for (const rawLine of conf.split('\n')) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#') || !line.includes('=')) continue;
        const idx = line.indexOf('=');
        const k = line.slice(0, idx).trim();
        const v = line.slice(idx + 1).trim();
        if (k === 'WAN_INTERFACE') wanDev = isValidDevice(v) ? v : '';
        else if (k === 'WAN_MODE' && (v === 'dhcp' || v === 'static')) wanMode = v;
        else if (k === 'WAN_IPV4_ADDRESS' && v) wanIp = v;
        else if (k === 'WAN_IPV4_GATEWAY' && v) wanGw = v;
        else if (k === 'LAN_INTERFACE') lanDev = isValidDevice(v) ? v : '';
        else if (k === 'LAN_MODE' && (v === 'dhcp' || v === 'static')) lanMode = v;
        else if (k === 'LAN_IPV4_ADDRESS' && v) lanIp = v;
        else if (k === 'OPT1_INTERFACE') opt1Dev = isValidDevice(v) ? v : '';
        else if (k === 'OPT1_MODE' && (v === 'dhcp' || v === 'static')) opt1Mode = v;
        else if (k === 'OPT1_IPV4_ADDRESS' && v) opt1Ip = v;
        else if (k === 'OPT2_INTERFACE') opt2Dev = isValidDevice(v) ? v : '';
        else if (k === 'OPT2_MODE' && (v === 'dhcp' || v === 'static')) opt2Mode = v;
        else if (k === 'OPT2_IPV4_ADDRESS' && v) opt2Ip = v;
      }
    }
  } catch {}

  const antiLockoutIfaces = ['lan'];
  if (opt1Dev) antiLockoutIfaces.push('opt1');
  if (opt2Dev) antiLockoutIfaces.push('opt2');

  const isMinimal = isMinimalEditionHost();
  const hostname = isMinimal ? readSystemHostname('axonwall-minimal') : 'axonwall-core';

  return DesiredStateSchema.parse({
    version: 1,
    ...(isMinimal
      ? {
          capabilities: {
            firewallEnabled: false,
            nasEnabled: false,
            k3sEnabled: false,
            virtEnabled: false,
            vigilanteEnabled: false,
          },
          plugins: [
            { id: 'core-firewall', enabled: false },
            { id: 'core-nas', enabled: false },
            { id: 'core-k3s', enabled: false },
            { id: 'core-virt', enabled: false },
            { id: 'core-vigilante', enabled: false },
            { id: 'cli-workstation', enabled: false },
            { id: 'host-malware-rootkit', enabled: false },
            { id: 'coroot-ebpf-apm', enabled: false },
          ],
        }
      : {}),
    system: {
      hostname,
      domain: 'axonwall.local',
      dnsServers: ['1.1.1.1', '8.8.8.8'],
      timezone: 'UTC',
      flowtableOffload: true,
      antiLockout: {
        enabled: true,
        interface: 'lan',
        interfaces: antiLockoutIfaces,
        ports: [22, 80, 443, 2966, 3000],
      },
    },
    interfaces: [
      {
        name: 'wan',
        role: 'wan',
        device: wanDev || 'none',
        type: wanMode,
        enabled: Boolean(wanDev),
        dhcpServer: false,
        ...(wanMode === 'static' && wanIp ? { ipv4Address: wanIp } : {}),
        ...(wanMode === 'static' && wanGw ? { ipv4Gateway: wanGw } : {}),
        mtu: 1500,
        description: 'WAN Gateway',
      },
      {
        name: 'lan',
        role: 'lan',
        device: lanDev || 'none',
        type: lanMode,
        enabled: Boolean(lanDev),
        dhcpServer: !isMinimal && lanMode === 'static',
        ...(lanMode === 'static' && lanIp ? { ipv4Address: lanIp } : {}),
        mtu: 1500,
        description: 'LAN Network',
      },
      ...(opt1Dev
        ? [
            {
              name: 'opt1',
              role: 'lan' as const,
              device: opt1Dev,
              type: opt1Mode,
              enabled: true,
              dhcpServer: false,
              ...(opt1Mode === 'static' && opt1Ip ? { ipv4Address: opt1Ip } : {}),
              mtu: 1500,
              description: 'OPT1 (Attached Network / Non-authoritative)',
            },
          ]
        : []),
      ...(opt2Dev
        ? [
            {
              name: 'opt2',
              role: 'lan' as const,
              device: opt2Dev,
              type: opt2Mode,
              enabled: true,
              dhcpServer: false,
              ...(opt2Mode === 'static' && opt2Ip ? { ipv4Address: opt2Ip } : {}),
              mtu: 1500,
              description: 'OPT2 (Attached Network / Non-authoritative)',
            },
          ]
        : []),
    ],
    aliases: [],
    rules: [],
    nat: [],
    gateways: [],
    gatewayGroups: [],
    vlans: [],
    bridges: [],
    bonds: [],
    virtualIps: [],
    vrfs: [],
    dhcp: { enabled: !isMinimal, subnets: [] },
    dns: {
      enabled: !isMinimal,
      listenPort: 53,
      dnssec: true,
      dotEnabled: !isMinimal,
      dotUpstreams: [],
      hostOverrides: [],
    },
    routes: [],
  });
}

export const BASELINE_STATE: DesiredState = buildBaselineState();

let cachedDesiredState: DesiredState | null = null;
let lastLoadedFingerprint = '';

export function invalidateDesiredStateCacheInternal(): void {
  cachedDesiredState = null;
  lastLoadedFingerprint = '';
}

export function readAllYamlConfigFiles(): {
  files: Record<string, string>;
  fingerprint: string;
} {
  const files: Record<string, string> = {};

  for (const dir of [PERSIST_CONFIG_DIR, ETC_CONFIG_DIR]) {
    if (!fs.existsSync(dir)) continue;
    for (const filename of AXONWALL_YAML_FILENAMES) {
      const fullPath = path.join(dir, filename);
      if (fs.existsSync(fullPath)) {
        try {
          files[filename] = fs.readFileSync(fullPath, 'utf8');
        } catch {}
      }
    }
    const singlePath = path.join(dir, 'axonwall.yaml');
    if (fs.existsSync(singlePath)) {
      try {
        files['axonwall.yaml'] = fs.readFileSync(singlePath, 'utf8');
      } catch {}
    }
    const confD = path.join(dir, 'conf.d');
    if (fs.existsSync(confD)) {
      try {
        for (const entry of fs.readdirSync(confD).sort()) {
          if (entry.endsWith('.yaml') || entry.endsWith('.yml')) {
            const entryPath = path.join(confD, entry);
            files[`conf.d/${entry}`] = fs.readFileSync(entryPath, 'utf8');
          }
        }
      } catch {}
    }
  }

  const hash = crypto.createHash('sha256');
  for (const [k, v] of Object.entries(files).sort()) {
    hash.update(`${k}:${v}\n`);
  }

  return { files, fingerprint: hash.digest('hex') };
}

export function writeConfigFileSafe(targetPath: string, content: string, mode = 0o660): boolean {
  try {
    const parent = path.dirname(targetPath);
    if (!fs.existsSync(parent)) {
      fs.mkdirSync(parent, { recursive: true, mode: 0o775 });
    }
    try {
      fs.writeFileSync(targetPath, content, { mode });
      return true;
    } catch {
      try {
        if (fs.existsSync(targetPath)) {
          fs.unlinkSync(targetPath);
        }
        fs.writeFileSync(targetPath, content, { mode });
        return true;
      } catch {}
    }
  } catch {}
  return false;
}

export function syncNetworkInterfacesFiles(state: DesiredState): { ifacesContent: string; confContent: string } {
  const wanIface =
    state.interfaces?.find((i) => i.name === 'wan') ||
    state.interfaces?.find((i) => inferInterfaceRole(i) === 'wan' && i.enabled);
  const lanIface =
    state.interfaces?.find((i) => i.name === 'lan') ||
    state.interfaces?.find((i) => inferInterfaceRole(i) === 'lan' && i.enabled);
  const opt1Iface = state.interfaces?.find((i) => i.name === 'opt1');
  const opt2Iface = state.interfaces?.find((i) => i.name === 'opt2');

  const cleanDev = (iface?: typeof wanIface): string => {
    if (!iface || !iface.enabled || !isValidDevice(iface.device)) return '';
    return iface.device;
  };

  const confLines = [
    `WAN_INTERFACE=${cleanDev(wanIface)}`,
    `WAN_MODE=${wanIface?.type || 'dhcp'}`,
    `WAN_IPV4_ADDRESS=${wanIface?.ipv4Address || ''}`,
    `WAN_IPV4_GATEWAY=${wanIface?.ipv4Gateway || ''}`,
    `WAN_DNS1=${state.system?.dnsServers?.[0] || '1.1.1.1'}`,
    `WAN_DNS2=${state.system?.dnsServers?.[1] || '8.8.8.8'}`,
    `LAN_INTERFACE=${cleanDev(lanIface)}`,
    `LAN_MODE=${lanIface?.type || 'static'}`,
    `LAN_IPV4_ADDRESS=${lanIface?.ipv4Address || '192.168.1.1/24'}`,
    `LAN_DHCP_ENABLED=${Boolean(cleanDev(lanIface)) && isInterfaceAuthoritativeDhcp(lanIface || { name: 'lan', type: 'static' }, state.dhcp)}`,
    `OPT1_INTERFACE=${cleanDev(opt1Iface)}`,
    `OPT1_MODE=${opt1Iface?.type || 'dhcp'}`,
    `OPT1_IPV4_ADDRESS=${opt1Iface?.ipv4Address || ''}`,
    `OPT2_INTERFACE=${cleanDev(opt2Iface)}`,
    `OPT2_MODE=${opt2Iface?.type || 'dhcp'}`,
    `OPT2_IPV4_ADDRESS=${opt2Iface?.ipv4Address || ''}`,
  ];

  const allIfaces = state.interfaces || [];
  const activeNames = allIfaces.filter((i) => Boolean(cleanDev(i))).map((i) => i.name);
  confLines.push(`AXONWALL_INTERFACES=${activeNames.join(',')}`);
  for (const iface of allIfaces) {
    const dev = cleanDev(iface);
    if (!dev) continue;
    const keyPrefix = `IFACE_${iface.name.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}`;
    const role = inferInterfaceRole(iface);
    const authDhcp = isInterfaceAuthoritativeDhcp(iface, state.dhcp);
    confLines.push(`${keyPrefix}_NAME=${iface.name}`);
    confLines.push(`${keyPrefix}_DEVICE=${dev}`);
    confLines.push(`${keyPrefix}_ROLE=${role}`);
    confLines.push(`${keyPrefix}_MODE=${iface.type}`);
    confLines.push(`${keyPrefix}_IPV4_ADDRESS=${iface.ipv4Address || ''}`);
    confLines.push(`${keyPrefix}_IPV4_GATEWAY=${iface.ipv4Gateway || ''}`);
    confLines.push(`${keyPrefix}_DHCP_SERVER=${authDhcp ? 'true' : 'false'}`);
  }

  const confContent = confLines.join('\n') + '\n';

  for (const dir of YAML_CONFIG_DIRS) {
    writeConfigFileSafe(path.join(dir, 'interfaces.conf'), confContent, 0o664);
  }

  const cidrToNetmask = (cidr: number): string => {
    const mask = [];
    for (let i = 0; i < 4; i++) {
      const bits = Math.max(0, Math.min(8, cidr - i * 8));
      mask.push(256 - Math.pow(2, 8 - bits));
    }
    return mask.join('.');
  };

  const routes = (state.routes || []).filter((r) => r.enabled ?? true);

  const renderIfaceStanza = (label: string, ifaceObj?: typeof wanIface) => {
    if (!ifaceObj || !ifaceObj.device || !ifaceObj.enabled || !isValidDevice(ifaceObj.device)) return '';
    const roleLabel = inferInterfaceRole(ifaceObj).toUpperCase();
    let s = `# ${label} (${roleLabel}) Interface\nauto ${ifaceObj.device}\n`;
    if (ifaceObj.type === 'static' && ifaceObj.ipv4Address) {
      const parts = ifaceObj.ipv4Address.split('/');
      const ip = parts[0];
      const cidr = parts[1] ? parseInt(parts[1], 10) : 24;
      s += `iface ${ifaceObj.device} inet static\n`;
      s += `    address ${ip}\n`;
      s += `    netmask ${cidrToNetmask(cidr)}\n`;
      if (ifaceObj.ipv4Gateway) {
        s += `    gateway ${ifaceObj.ipv4Gateway}\n`;
      }
      if (state.system?.dnsServers && state.system.dnsServers.length > 0) {
        s += `    dns-nameservers ${state.system.dnsServers.join(' ')}\n`;
      }
    } else {
      s += `iface ${ifaceObj.device} inet dhcp\n`;
    }

    const ifaceRoutes = routes.filter((r) => {
      const iface = (r.interface || '').toLowerCase().trim();
      return iface === label.toLowerCase() || iface === ifaceObj.name?.toLowerCase() || iface === ifaceObj.device.toLowerCase();
    });

    for (const r of ifaceRoutes) {
      if (r.network && r.gateway) {
        s += `    up ip route replace ${r.network} via ${r.gateway} dev ${ifaceObj.device} proto static || true\n`;
        s += `    down ip route del ${r.network} proto static || true\n`;
      }
    }

    return s + '\n';
  };

  let ifaces = '# /etc/network/interfaces -- Generated by Axonwall\n';
  ifaces += '# This file is managed by Axonwall. Manual changes will be overwritten.\n\n';
  ifaces += 'auto lo\niface lo inet loopback\n\n';

  const seenDevices = new Set<string>();
  for (const ifaceObj of allIfaces) {
    if (!ifaceObj || !ifaceObj.device || !ifaceObj.enabled || !isValidDevice(ifaceObj.device)) continue;
    if (seenDevices.has(ifaceObj.device)) continue;
    seenDevices.add(ifaceObj.device);
    ifaces += renderIfaceStanza(ifaceObj.name.toUpperCase(), ifaceObj);
  }

  const unboundRoutes = routes.filter((r) => {
    const iface = (r.interface || '').toLowerCase().trim();
    return !iface || iface === 'auto';
  });

  if (unboundRoutes.length > 0) {
    ifaces += '# System-wide Static Routes\n';
    for (const r of unboundRoutes) {
      if (r.network && r.gateway) {
        ifaces += `# Route ${r.network} via ${r.gateway}\n`;
      }
    }
  }

  if (isApplianceRuntime() && readHostOSRelease().family === 'debian') {
    try {
      if (!fs.existsSync('/etc/network')) {
        fs.mkdirSync('/etc/network', { recursive: true });
      }
      fs.writeFileSync('/etc/network/interfaces', ifaces, 'utf8');
      if (fs.existsSync('/etc/network/interfaces.d/axonwall')) {
        try {
          fs.unlinkSync('/etc/network/interfaces.d/axonwall');
        } catch {}
      }
    } catch {}
  }

  return { ifacesContent: ifaces, confContent };
}

export function persistDesiredStateToDisk(state: DesiredState): Record<string, string> {
  const normalized = DesiredStateSchema.parse(state);

  if (normalized.dhcp?.enabled !== false) {
    if (!normalized.dhcp) {
      normalized.dhcp = { enabled: true, subnets: [] };
    }
    for (const iface of normalized.interfaces || []) {
      if (!iface.enabled || !isValidDevice(iface.device)) continue;
      if (inferInterfaceRole(iface) === 'wan') continue;
      if (iface.type !== 'static' || iface.dhcpServer !== true || !iface.ipv4Address) continue;
      const hasSubnet = (normalized.dhcp.subnets || []).some((s) => s.interface === iface.name);
      if (!hasSubnet) {
        const subnetInfo = computeSubnetAndDefaultPool(iface.ipv4Address);
        if (subnetInfo) {
          normalized.dhcp.subnets.push({
            id: crypto.randomUUID(),
            interface: iface.name,
            subnet: subnetInfo.subnetCidr,
            poolStart: subnetInfo.poolStart,
            poolEnd: subnetInfo.poolEnd,
            routers: [subnetInfo.routerIp],
            dnsServers: [subnetInfo.routerIp],
            staticMappings: [],
            enabled: true,
          });
        }
      }
    }
  }

  const yamlFiles = serializeDesiredStateToYamlFiles(normalized);
  const daemonFileMap: Record<string, string> = {};

  for (const [filename, content] of Object.entries(yamlFiles)) {
    daemonFileMap[`/etc/axonwall/${filename}`] = content;
  }

  for (const dir of [PERSIST_CONFIG_DIR, ETC_CONFIG_DIR]) {
    try {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o775 });
      }
      for (const [filename, content] of Object.entries(yamlFiles)) {
        writeConfigFileSafe(path.join(dir, filename), content, 0o660);
      }
      const legacyMonolithic = path.join(dir, 'axonwall.yaml');
      if (fs.existsSync(legacyMonolithic)) {
        try {
          fs.unlinkSync(legacyMonolithic);
        } catch {}
      }
    } catch {}
  }

  const jsonSerialized = JSON.stringify(normalized, null, 2);
  for (const jsonPath of Array.from(
    new Set([
      getStateJsonPath(),
      path.join(PERSIST_CONFIG_DIR, 'state.json'),
      path.join(ETC_CONFIG_DIR, 'state.json'),
    ])
  )) {
    writeConfigFileSafe(jsonPath, jsonSerialized, 0o660);
  }

  const { confContent } = syncNetworkInterfacesFiles(normalized);
  daemonFileMap['/etc/axonwall/interfaces.conf'] = confContent;

  cachedDesiredState = normalized;
  const { fingerprint } = readAllYamlConfigFiles();
  lastLoadedFingerprint = fingerprint;
  return daemonFileMap;
}

function reconcileStateWithInterfacesConf(state: DesiredState): boolean {
  let rawConf = '';
  let activeConfPath = '';
  for (const confPath of Array.from(
    new Set([path.join(PERSIST_CONFIG_DIR, 'interfaces.conf'), path.join(ETC_CONFIG_DIR, 'interfaces.conf')])
  )) {
    try {
      if (fs.existsSync(confPath)) {
        const text = fs.readFileSync(confPath, 'utf8');
        if (text && text.includes('AXONWALL_INTERFACES=')) {
          rawConf = text;
          activeConfPath = confPath;
          break;
        }
        if (!rawConf && text) {
          rawConf = text;
          activeConfPath = confPath;
        }
      }
    } catch {}
  }
  if (!rawConf) return false;

  try {
    if (activeConfPath && fs.existsSync(activeConfPath) && Array.isArray(state.interfaces) && state.interfaces.length > 0) {
      const confMtimeMs = fs.statSync(activeConfPath).mtimeMs;
      for (const yamlPath of Array.from(
        new Set([path.join(ETC_CONFIG_DIR, 'interfaces.yaml'), path.join(PERSIST_CONFIG_DIR, 'interfaces.yaml')])
      )) {
        if (fs.existsSync(yamlPath)) {
          const yamlMtimeMs = fs.statSync(yamlPath).mtimeMs;
          if (yamlMtimeMs > confMtimeMs + 2000) {
            return false;
          }
        }
      }
    }
  } catch {}

  const kv: Record<string, string> = {};
  for (const line of rawConf.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
    const idx = trimmed.indexOf('=');
    kv[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
  }

  if (!('AXONWALL_INTERFACES' in kv)) return false;

  const activeNames = (kv.AXONWALL_INTERFACES || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (activeNames.length === 0) return false;

  let changed = false;
  if (!Array.isArray(state.interfaces)) {
    state.interfaces = [];
  }

  for (const name of activeNames) {
    const keyPrefix = `IFACE_${name.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}`;
    const dev = (kv[`${keyPrefix}_DEVICE`] || '').trim();
    if (!isValidDevice(dev)) continue;

    const rawRole = (kv[`${keyPrefix}_ROLE`] || '').trim().toLowerCase();
    const role: InterfaceRole = rawRole === 'wan' ? 'wan' : rawRole === 'lan' ? 'lan' : name.startsWith('wan') ? 'wan' : 'lan';
    const rawMode = (kv[`${keyPrefix}_MODE`] || '').trim().toLowerCase();
    const mode: 'dhcp' | 'static' = rawMode === 'static' ? 'static' : 'dhcp';
    const ipv4Address = (kv[`${keyPrefix}_IPV4_ADDRESS`] || '').trim() || undefined;
    const ipv4Gateway = (kv[`${keyPrefix}_IPV4_GATEWAY`] || '').trim() || undefined;
    const dhcpServer = role === 'lan' && mode === 'static' && (kv[`${keyPrefix}_DHCP_SERVER`] || '').trim().toLowerCase() === 'true';

    const existingIdx = state.interfaces.findIndex((i) => i.name.toLowerCase() === name);
    const devUsedElsewhere = state.interfaces.some(
      (i, idx) => idx !== existingIdx && i.enabled && i.device === dev,
    );
    if (devUsedElsewhere) continue;

    const defaultDesc =
      role === 'wan'
        ? `${name.toUpperCase()} WAN Uplink`
        : dhcpServer
          ? `${name.toUpperCase()} LAN (Authoritative DHCP)`
          : `${name.toUpperCase()} LAN (Joined Network)`;

    if (existingIdx < 0) {
      state.interfaces.push(
        InterfaceSchema.parse({
          name,
          role,
          device: dev,
          enabled: true,
          type: mode,
          dhcpServer,
          ipv4Address: mode === 'static' ? ipv4Address : undefined,
          ipv4Gateway: mode === 'static' ? ipv4Gateway : undefined,
          description: defaultDesc,
          mtu: 1500,
        }),
      );
      changed = true;
    } else {
      const cur = state.interfaces[existingIdx];
      if (!cur.enabled || !isValidDevice(cur.device)) {
        state.interfaces[existingIdx] = InterfaceSchema.parse({
          ...cur,
          name,
          role,
          device: dev,
          enabled: true,
          type: mode,
          dhcpServer,
          ipv4Address: mode === 'static' ? ipv4Address || cur.ipv4Address : undefined,
          ipv4Gateway: mode === 'static' ? ipv4Gateway || cur.ipv4Gateway : undefined,
          description: cur.description || defaultDesc,
          mtu: cur.mtu || 1500,
        });
        changed = true;
      }
    }

    if (role === 'lan' && mode === 'static' && dhcpServer && ipv4Address) {
      if (!state.dhcp) {
        state.dhcp = { enabled: true, subnets: [] };
      }
      const hasSubnet = (state.dhcp.subnets || []).some((s) => s.interface === name);
      if (!hasSubnet) {
        const subnetInfo = computeSubnetAndDefaultPool(ipv4Address);
        if (subnetInfo) {
          state.dhcp.subnets.push({
            id: crypto.randomUUID(),
            interface: name,
            subnet: subnetInfo.subnetCidr,
            poolStart: subnetInfo.poolStart,
            poolEnd: subnetInfo.poolEnd,
            routers: [subnetInfo.routerIp],
            dnsServers: [subnetInfo.routerIp],
            staticMappings: [],
            enabled: true,
          });
          state.dhcp.enabled = true;
          changed = true;
        }
      }
    }
  }

  if (changed && state.system?.antiLockout) {
    const lanNames = state.interfaces
      .filter((i) => inferInterfaceRole(i) === 'lan' && i.enabled && isValidDevice(i.device))
      .map((i) => i.name);
    if (lanNames.length > 0) {
      state.system.antiLockout.interfaces = Array.from(new Set(lanNames));
      state.system.antiLockout.interface = lanNames[0] || 'lan';
    }
  }

  return changed;
}

/**
 * Internal server-only unredacted desired state loader (never put `'use server'` in this file).
 * Callers must validate session/RBAC before accessing secrets.
 */
export async function getDesiredStateInternal(): Promise<DesiredState> {
  const { files, fingerprint } = readAllYamlConfigFiles();

  if (Object.keys(files).length > 0) {
    if (cachedDesiredState && fingerprint === lastLoadedFingerprint) {
      return structuredClone(cachedDesiredState);
    }
    try {
      const parsed = parseDesiredStateFromYamlFiles(files);
      if (reconcileStateWithInterfacesConf(parsed)) {
        persistDesiredStateToDisk(parsed);
      } else {
        cachedDesiredState = parsed;
        lastLoadedFingerprint = fingerprint;
      }
      return structuredClone(cachedDesiredState!);
    } catch (err: any) {
      console.error('[axonwall] Failed to parse YAML files:', err?.message || err);
    }
  }

  if (cachedDesiredState) {
    return structuredClone(cachedDesiredState);
  }

  for (const jsonPath of Array.from(
    new Set([getStateJsonPath(), path.join(ETC_CONFIG_DIR, 'state.json'), './state.json'])
  )) {
    try {
      if (fs.existsSync(jsonPath)) {
        const raw = fs.readFileSync(jsonPath, 'utf8');
        const parsed = DesiredStateSchema.parse(JSON.parse(raw));
        persistDesiredStateToDisk(parsed);
        return structuredClone(parsed);
      }
    } catch {}
  }

  const baseline = buildBaselineState();
  persistDesiredStateToDisk(baseline);
  return structuredClone(baseline);
}

export function snapshotDesiredStateOnDisk(): OnDiskConfigSnapshotEntry[] {
  const paths = new Set<string>();
  for (const dir of YAML_CONFIG_DIRS) {
    for (const filename of AXONWALL_YAML_FILENAMES) {
      paths.add(path.join(dir, filename));
    }
    paths.add(path.join(dir, 'interfaces.conf'));
  }
  for (const jsonPath of [
    getStateJsonPath(),
    path.join(PERSIST_CONFIG_DIR, 'state.json'),
    path.join(ETC_CONFIG_DIR, 'state.json'),
    ...(isApplianceRuntime() && readHostOSRelease().family === 'debian' ? ['/etc/network/interfaces'] : []),
  ]) {
    paths.add(jsonPath);
  }
  const snapshot: OnDiskConfigSnapshotEntry[] = [];
  for (const filePath of paths) {
    try {
      if (fs.existsSync(filePath)) {
        snapshot.push({ path: filePath, existed: true, content: fs.readFileSync(filePath, 'utf8') });
      } else {
        snapshot.push({ path: filePath, existed: false, content: null });
      }
    } catch {
      snapshot.push({ path: filePath, existed: false, content: null });
    }
  }
  return snapshot;
}

export function restoreDesiredStateSnapshot(snapshot: OnDiskConfigSnapshotEntry[]): boolean {
  let ok = true;
  for (const entry of snapshot) {
    try {
      if (entry.existed && entry.content !== null) {
        fs.writeFileSync(entry.path, entry.content, 'utf8');
      } else if (fs.existsSync(entry.path)) {
        fs.unlinkSync(entry.path);
      }
    } catch {
      ok = false;
    }
  }
  return ok;
}
