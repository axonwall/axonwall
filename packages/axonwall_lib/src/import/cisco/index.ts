import type {
  DesiredState,
  Interface,
  Vlan,
  Alias,
  FirewallRule,
  NatRule,
  StaticRoute,
} from '../../schemas/index.js';
import type { ImportReport } from '../types.js';

function maskToPrefix(mask: string): number {
  const parts = mask.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4) return 32;
  const num = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  let count = 0;
  for (let i = 31; i >= 0; i--) {
    if ((num & (1 << i)) !== 0) count++;
    else break;
  }
  return count;
}

export function importCiscoAsaConfig(configText: string): ImportReport {
  const warnings: string[] = [];
  const lines = configText.split(/\r?\n/);

  const rawInterfaces: Record<
    string,
    { device: string; nameif?: string; ip?: string; mask?: string; vlan?: number; descr?: string }
  > = {};
  const aliases: Alias[] = [];
  const rules: FirewallRule[] = [];
  const nat: NatRule[] = [];
  const routes: StaticRoute[] = [];

  let currentIface: string | null = null;
  let currentObjNetwork: { name: string; ip?: string; descr?: string } | null = null;
  let currentObjGroup: { name: string; entries: string[]; descr?: string } | null = null;

  for (let rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('!') || line.startsWith('#')) {
      continue;
    }

    const tokens = line.split(/\s+/);

    // 1. Interfaces
    if (tokens[0] === 'interface') {
      currentIface = tokens[1];
      rawInterfaces[currentIface] = { device: currentIface };
      continue;
    }

    if (currentIface && rawInterfaces[currentIface]) {
      if (tokens[0] === 'nameif') {
        rawInterfaces[currentIface].nameif = tokens[1];
        continue;
      }
      if (tokens[0] === 'vlan') {
        rawInterfaces[currentIface].vlan = Number.parseInt(tokens[1], 10);
        continue;
      }
      if (tokens[0] === 'ip' && tokens[1] === 'address') {
        if (tokens[2] === 'dhcp') {
          rawInterfaces[currentIface].ip = 'dhcp';
        } else if (tokens[2] && tokens[3]) {
          rawInterfaces[currentIface].ip = tokens[2];
          rawInterfaces[currentIface].mask = tokens[3];
        }
        continue;
      }
      if (tokens[0] === 'description') {
        rawInterfaces[currentIface].descr = tokens.slice(1).join(' ');
        continue;
      }
    }

    // 2. Object Network
    if (tokens[0] === 'object' && tokens[1] === 'network') {
      currentIface = null;
      if (currentObjNetwork) {
        if (currentObjNetwork.ip) {
          aliases.push({
            name: currentObjNetwork.name,
            type: 'host',
            entries: [currentObjNetwork.ip],
            description: currentObjNetwork.descr || '',
            enabled: true,
          });
        }
      }
      currentObjNetwork = { name: tokens[2] };
      continue;
    }

    if (currentObjNetwork) {
      if (tokens[0] === 'host') {
        currentObjNetwork.ip = tokens[1];
        continue;
      }
      if (tokens[0] === 'subnet' && tokens[1] && tokens[2]) {
        currentObjNetwork.ip = `${tokens[1]}/${maskToPrefix(tokens[2])}`;
        continue;
      }
      if (tokens[0] === 'description') {
        currentObjNetwork.descr = tokens.slice(1).join(' ');
        continue;
      }
    }

    // 3. Object Group Network
    if (tokens[0] === 'object-group' && tokens[1] === 'network') {
      currentIface = null;
      if (currentObjGroup && currentObjGroup.entries.length > 0) {
        aliases.push({
          name: currentObjGroup.name,
          type: 'network',
          entries: currentObjGroup.entries,
          description: currentObjGroup.descr || '',
          enabled: true,
        });
      }
      currentObjGroup = { name: tokens[2], entries: [] };
      continue;
    }

    if (currentObjGroup) {
      if (tokens[0] === 'network-object') {
        if (tokens[1] === 'host' && tokens[2]) {
          currentObjGroup.entries.push(tokens[2]);
        } else if (tokens[1] && tokens[2]) {
          currentObjGroup.entries.push(`${tokens[1]}/${maskToPrefix(tokens[2])}`);
        }
        continue;
      }
      if (tokens[0] === 'description') {
        currentObjGroup.descr = tokens.slice(1).join(' ');
        continue;
      }
    }

    // 4. Access Lists
    if (tokens[0] === 'access-list' && tokens[2] === 'extended') {
      currentIface = null;
      const aclName = tokens[1];
      const action = tokens[3] === 'permit' ? 'pass' : 'block';
      let proto = tokens[4] || 'any';
      let idx = 5;

      // Source
      let src = 'any';
      if (tokens[idx] === 'any' || tokens[idx] === 'any4' || tokens[idx] === 'any6') {
        src = 'any';
        idx++;
      } else if (tokens[idx] === 'host' && tokens[idx + 1]) {
        src = tokens[idx + 1];
        idx += 2;
      } else if ((tokens[idx] === 'object-group' || tokens[idx] === 'object') && tokens[idx + 1]) {
        src = `$${tokens[idx + 1]}`;
        idx += 2;
      } else if (tokens[idx] && tokens[idx + 1]) {
        src = `${tokens[idx]}/${maskToPrefix(tokens[idx + 1])}`;
        idx += 2;
      }

      // Destination
      let dst = 'any';
      let dstPort = '';
      if (tokens[idx] === 'any' || tokens[idx] === 'any4' || tokens[idx] === 'any6') {
        dst = 'any';
        idx++;
      } else if (tokens[idx] === 'host' && tokens[idx + 1]) {
        dst = tokens[idx + 1];
        idx += 2;
      } else if ((tokens[idx] === 'object-group' || tokens[idx] === 'object') && tokens[idx + 1]) {
        dst = `$${tokens[idx + 1]}`;
        idx += 2;
      } else if (tokens[idx] && tokens[idx + 1] && !tokens[idx].startsWith('eq')) {
        dst = `${tokens[idx]}/${maskToPrefix(tokens[idx + 1])}`;
        idx += 2;
      }

      // Port
      if (tokens[idx] === 'eq' && tokens[idx + 1]) {
        const portToken = tokens[idx + 1];
        if (portToken === 'www' || portToken === 'http') dstPort = '80';
        else if (portToken === 'https') dstPort = '443';
        else if (portToken === 'ssh') dstPort = '22';
        else dstPort = portToken;
      }

      let iface = 'any';
      if (aclName.includes('outside')) iface = 'wan';
      else if (aclName.includes('inside')) iface = 'lan';

      let ruleProto: any = 'any';
      if (['tcp', 'udp', 'icmp', 'esp', 'ah', 'gre'].includes(proto)) {
        ruleProto = proto;
      }

      rules.push({
        action,
        direction: 'in',
        interface: iface,
        quick: true,
        protocol: ruleProto,
        source: src,
        sourcePort: '',
        destination: dst,
        destinationPort: dstPort,
        log: false,
        sortOrder: rules.length + 1,
        enabled: true,
        description: `Imported from Cisco ACL ${aclName}`,
      });
      continue;
    }

    // 5. NAT
    if (tokens[0] === 'nat') {
      const ifaceMatch = tokens[1]?.match(/\(([^,]+),([^)]+)\)/);
      const inIface = ifaceMatch ? ifaceMatch[1] : 'lan';
      const outIface = ifaceMatch ? ifaceMatch[2] : 'wan';

      if (line.includes('dynamic')) {
        nat.push({
          type: 'masquerade',
          interface: outIface === 'outside' ? 'wan' : outIface,
          protocol: 'any',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '',
          log: false,
          sortOrder: nat.length + 1,
          enabled: true,
          description: `Cisco dynamic PAT (${inIface} -> ${outIface})`,
        });
      } else if (line.includes('static')) {
        nat.push({
          type: 'dnat',
          interface: inIface === 'outside' ? 'wan' : inIface,
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'wan_ip',
          destinationPort: '',
          log: false,
          sortOrder: nat.length + 1,
          enabled: true,
          description: `Cisco static NAT (${inIface} -> ${outIface})`,
        });
      }
      continue;
    }

    // 6. Routes
    if (tokens[0] === 'route' && tokens[1] && tokens[2] && tokens[3] && tokens[4]) {
      const routeIface = tokens[1];
      const destNet = tokens[2];
      const destMask = tokens[3];
      const gw = tokens[4];

      if (destNet === '0.0.0.0' && destMask === '0.0.0.0') {
        // Default gateway
        warnings.push(`Cisco default route via ${gw} mapped as uplink gateway.`);
      } else {
        routes.push({
          network: `${destNet}/${maskToPrefix(destMask)}`,
          gateway: gw,
          interface: routeIface.includes('outside') ? 'wan' : 'lan',
          description: `Cisco static route on ${routeIface}`,
          enabled: true,
        });
      }
      continue;
    }
  }

  // Flush trailing objects
  if (currentObjNetwork && currentObjNetwork.ip) {
    aliases.push({
      name: currentObjNetwork.name,
      type: 'host',
      entries: [currentObjNetwork.ip],
      description: currentObjNetwork.descr || '',
      enabled: true,
    });
  }
  if (currentObjGroup && currentObjGroup.entries.length > 0) {
    aliases.push({
      name: currentObjGroup.name,
      type: 'network',
      entries: currentObjGroup.entries,
      description: currentObjGroup.descr || '',
      enabled: true,
    });
  }

  // Format interfaces and VLANs
  const interfaces: Interface[] = [];
  const vlans: Vlan[] = [];

  for (const [dev, data] of Object.entries(rawInterfaces)) {
    const isWan = data.nameif === 'outside' || dev.toLowerCase().includes('outside');
    const name = isWan ? 'wan' : data.nameif || dev.toLowerCase().replace(/[^a-z0-9]/g, '');

    let cidr = '';
    if (data.ip && data.ip !== 'dhcp' && data.mask) {
      cidr = `${data.ip}/${maskToPrefix(data.mask)}`;
    }

    interfaces.push({
      name,
      device: dev,
      type: data.ip === 'dhcp' ? 'dhcp' : 'static',
      ipv4Address: cidr || undefined,
      enabled: true,
      description: data.descr || data.nameif || dev,
      mtu: 1500,
    });

    if (data.vlan) {
      const parent = dev.split('.')[0] || 'eth0';
      vlans.push({
        tag: data.vlan,
        parentInterface: parent,
        vlanInterface: dev,
        priority: 0,
        description: data.descr || `VLAN ${data.vlan}`,
      });
    }
  }

  if (interfaces.length === 0) {
    interfaces.push(
      { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, description: 'WAN', mtu: 1500 },
      { name: 'lan', device: 'eth1', type: 'static', ipv4Address: '192.168.1.1/24', enabled: true, description: 'LAN', mtu: 1500 }
    );
  }

  const state: DesiredState = {
    version: 1,
    system: {
      hostname: 'axonwall',
      domain: 'local',
      dnsServers: ['1.1.1.1', '8.8.8.8'],
      timezone: 'UTC',
      flowtableOffload: true,
      antiLockout: {
        enabled: true,
        interface: 'lan',
        ports: [80, 443, 22, 3000, 2966],
      },
    },
    interfaces,
    rules,
    nat,
    gateways: [],
    gatewayGroups: [],
    aliases,
    vlans,
    bridges: [],
    bonds: [],
    virtualIps: [],
    vrfs: [],
    dhcp: {
      enabled: false,
      subnets: [],
    },
    dns: {
      enabled: true,
      listenPort: 53,
      dnssec: true,
      dotEnabled: true,
      dotUpstreams: [],
      hostOverrides: [],
    },
    routes,
  };

  return {
    success: true,
    vendor: 'cisco' as any,
    version: 'ASA 9.x',
    sourceFormat: 'Cisco ASA / FTD Configuration',
    interfacesCount: interfaces.length,
    vlansCount: vlans.length,
    aliasesCount: aliases.length,
    rulesCount: rules.length,
    natRulesCount: nat.length,
    dhcpSubnetsCount: 0,
    dnsOverridesCount: 0,
    routesCount: routes.length,
    warnings,
    state,
  };
}
