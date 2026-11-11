import {
  type DhcpConfig,
  type DhcpSubnet,
  type Dhcp6Subnet,
  type Interface,
  inferInterfaceRole,
} from '../../schemas/index.js';
import { isValidDevice } from '../../util/index.js';

export interface KeaCompileResult {
  keaDhcp4Config: string;
  keaDhcp6Config?: string;
  radvdConfig?: string;
}

function ipToUint32(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const n = Number.parseInt(p, 10);
    if (Number.isNaN(n) || n < 0 || n > 255) return null;
    val = ((val << 8) | n) >>> 0;
  }
  return val >>> 0;
}

function uint32ToIp(val: number): string {
  return `${(val >>> 24) & 255}.${(val >>> 16) & 255}.${(val >>> 8) & 255}.${val & 255}`;
}

export function synthesizeDefaultDhcpSubnet(iface: Interface): DhcpSubnet | null {
  if (!iface.ipv4Address) return null;
  const parts = iface.ipv4Address.trim().split('/');
  const ipStr = parts[0] || '';
  const prefix = parts[1] ? Number.parseInt(parts[1], 10) : 24;
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

  let startInt = firstUsableInt;
  let endInt = lastUsableInt;
  if (prefix <= 24) {
    const base24 = (ipInt & 0xffffff00) >>> 0;
    startInt = (base24 + 100) >>> 0;
    endInt = (base24 + 200) >>> 0;
    if (ipInt >= startInt && ipInt <= endInt) {
      startInt = (base24 + 10) >>> 0;
      endInt = (base24 + 99) >>> 0;
    }
  } else if (ipInt === firstUsableInt && firstUsableInt < lastUsableInt) {
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
    interface: iface.name,
    subnet: subnetCidr,
    poolStart: uint32ToIp(Math.min(startInt, endInt)),
    poolEnd: uint32ToIp(Math.max(startInt, endInt)),
    routers: [ipStr],
    dnsServers: [ipStr],
    staticMappings: [],
    enabled: true,
  };
}

export function compileKeaDhcp4(dhcp: DhcpConfig, interfaces: Interface[]): KeaCompileResult {
  const ifDeviceMap = new Map<string, string>();
  const ifaceByName = new Map<string, Interface>();
  for (const iface of interfaces) {
    ifDeviceMap.set(iface.name, iface.device);
    ifaceByName.set(iface.name, iface);
  }

  const candidateSubnets: DhcpSubnet[] = [...(dhcp.subnets || [])];
  if (dhcp.enabled !== false) {
    for (const iface of interfaces) {
      if (!iface.enabled || !isValidDevice(iface.device)) continue;
      if (inferInterfaceRole(iface) === 'wan') continue;
      if (iface.type !== 'static' || iface.dhcpServer !== true || !iface.ipv4Address) continue;
      const alreadyConfigured = candidateSubnets.some((s) => s.interface === iface.name);
      if (!alreadyConfigured) {
        const synthesized = synthesizeDefaultDhcpSubnet(iface);
        if (synthesized) {
          candidateSubnets.push(synthesized);
        }
      }
    }
  }

  const activeSubnets =
    dhcp.enabled === false
      ? []
      : candidateSubnets.filter((s) => {
          if (!s.enabled) return false;
          const iface = ifaceByName.get(s.interface);
          if (iface) {
            if (!iface.enabled || !isValidDevice(iface.device)) return false;
            if (inferInterfaceRole(iface) === 'wan') return false;
            if (iface.type !== 'static') return false;
            if (iface.dhcpServer === false) return false;
          }
          const dev = ifDeviceMap.get(s.interface) || s.interface;
          return isValidDevice(dev);
        });
  const activeInterfaces = Array.from(
    new Set(activeSubnets.map((s) => ifDeviceMap.get(s.interface) || s.interface).filter(isValidDevice))
  );

  const keaConfig = {
    Dhcp4: {
      'interfaces-config': {
        interfaces: activeInterfaces,
        'dhcp-socket-type': 'raw',
      },
      'lease-database': {
        type: 'memfile',
        persist: true,
        name: '/var/lib/kea/kea-leases4.csv',
      },
      'valid-lifetime': 7200,
      'renew-timer': 1800,
      'rebind-timer': 3600,
      'subnet4': activeSubnets.map((sub, idx) => {
        const optionData: Array<{ name: string; data: string }> = [];

        if (sub.routers.length > 0) {
          optionData.push({
            name: 'routers',
            data: sub.routers.join(', '),
          });
        }
        if (sub.dnsServers.length > 0) {
          optionData.push({
            name: 'domain-name-servers',
            data: sub.dnsServers.join(', '),
          });
        }

        return {
          id: idx + 1,
          subnet: sub.subnet,
          interface: ifDeviceMap.get(sub.interface) || sub.interface,
          pools: [
            {
              pool: `${sub.poolStart} - ${sub.poolEnd}`,
            },
          ],
          'option-data': optionData,
          reservations: sub.staticMappings.map((m) => ({
            'hw-address': m.mac,
            'ip-address': m.ip,
            hostname: m.hostname || undefined,
          })),
        };
      }),
    },
  };

  const dhcp6Result = compileKeaDhcp6AndRadvd(dhcp, interfaces);

  return {
    keaDhcp4Config: JSON.stringify(keaConfig, null, 2),
    ...(dhcp6Result.keaDhcp6Config ? { keaDhcp6Config: dhcp6Result.keaDhcp6Config } : {}),
    ...(dhcp6Result.radvdConfig ? { radvdConfig: dhcp6Result.radvdConfig } : {}),
  };
}

export function compileKeaDhcp6AndRadvd(
  dhcp: DhcpConfig,
  interfaces: Interface[],
): { keaDhcp6Config?: string; radvdConfig?: string } {
  const subnets6: Dhcp6Subnet[] = (dhcp.subnets6 ?? []).filter((s) => s.enabled !== false);
  if (!dhcp.dhcp6Enabled && subnets6.length === 0) {
    return {};
  }

  const ifDeviceMap = new Map<string, string>();
  const ifaceByName = new Map<string, Interface>();
  for (const iface of interfaces) {
    ifDeviceMap.set(iface.name, iface.device);
    ifaceByName.set(iface.name, iface);
  }

  const activeSubnets6 = subnets6.filter((s) => {
    const iface = ifaceByName.get(s.interface);
    if (iface) {
      if (!iface.enabled || !isValidDevice(iface.device)) return false;
      if (inferInterfaceRole(iface) === 'wan') return false;
    }
    const dev = ifDeviceMap.get(s.interface) || s.interface;
    return isValidDevice(dev);
  });

  const dhcp6Subnets = activeSubnets6.filter(
    (s) => s.raMode === 'managed' || s.raMode === 'assisted' || s.raMode === 'stateless_dhcp',
  );
  const dhcp6Interfaces = Array.from(
    new Set(dhcp6Subnets.map((s) => ifDeviceMap.get(s.interface) || s.interface).filter(isValidDevice)),
  );

  let keaDhcp6Config: string | undefined;
  if (dhcp.dhcp6Enabled || dhcp6Subnets.length > 0) {
    const kea6 = {
      Dhcp6: {
        'interfaces-config': {
          interfaces: dhcp6Interfaces,
        },
        'lease-database': {
          type: 'memfile',
          persist: true,
          name: '/var/lib/kea/kea-leases6.csv',
        },
        'preferred-lifetime': 3600,
        'valid-lifetime': 7200,
        'renew-timer': 1000,
        'rebind-timer': 2000,
        subnet6: dhcp6Subnets.map((sub, idx) => {
          const optionData: Array<{ name: string; data: string }> = [];
          if (sub.dnsServers.length > 0) {
            optionData.push({
              name: 'dns-servers',
              data: sub.dnsServers.join(', '),
            });
          }
          if (sub.domainSearchList.length > 0) {
            optionData.push({
              name: 'domain-search',
              data: sub.domainSearchList.join(', '),
            });
          }

          const pdPools: Array<{ prefix: string; 'prefix-len': number; 'delegated-len': number }> = [];
          if (sub.delegatedPrefix && sub.delegatedPrefix.includes('/')) {
            const [pdNet, pdLenStr] = sub.delegatedPrefix.split('/');
            const pdLen = Number.parseInt(pdLenStr || '56', 10);
            if (pdNet && !Number.isNaN(pdLen)) {
              pdPools.push({
                prefix: pdNet,
                'prefix-len': pdLen,
                'delegated-len': sub.delegatedLen ?? 60,
              });
            }
          }

          return {
            id: idx + 1,
            subnet: sub.subnet,
            interface: ifDeviceMap.get(sub.interface) || sub.interface,
            pools:
              sub.raMode !== 'stateless_dhcp' && sub.poolStart && sub.poolEnd
                ? [{ pool: `${sub.poolStart} - ${sub.poolEnd}` }]
                : [],
            ...(pdPools.length > 0 ? { 'pd-pools': pdPools } : {}),
            'option-data': optionData,
            reservations: (sub.staticMappings ?? []).map((m) => ({
              duid: m.duid,
              'ip-addresses': [m.ip6],
              hostname: m.hostname || undefined,
            })),
          };
        }),
      },
    };
    keaDhcp6Config = JSON.stringify(kea6, null, 2);
  }

  const raSubnets = activeSubnets6.filter((s) => s.raMode !== 'disabled');
  let radvdConfig: string | undefined;
  if (raSubnets.length > 0) {
    const lines: string[] = ['# Axonwall Auto-Generated IPv6 Router Advertisement (radvd) Configuration'];
    for (const sub of raSubnets) {
      const dev = ifDeviceMap.get(sub.interface) || sub.interface;
      const managed = sub.raMode === 'managed' || sub.raMode === 'assisted' ? 'on' : 'off';
      const otherCfg =
        sub.raMode === 'managed' || sub.raMode === 'assisted' || sub.raMode === 'stateless_dhcp' ? 'on' : 'off';
      const autonomous = sub.raMode === 'slaac' || sub.raMode === 'assisted' || sub.raMode === 'stateless_dhcp' ? 'on' : 'off';

      lines.push(`interface ${dev} {`);
      lines.push('  AdvSendAdvert on;');
      lines.push('  MinRtrAdvInterval 10;');
      lines.push('  MaxRtrAdvInterval 30;');
      lines.push(`  AdvManagedFlag ${managed};`);
      lines.push(`  AdvOtherConfigFlag ${otherCfg};`);
      lines.push(`  prefix ${sub.subnet} {`);
      lines.push('    AdvOnLink on;');
      lines.push(`    AdvAutonomous ${autonomous};`);
      lines.push('    AdvRouterAddr on;');
      lines.push('  };');
      if (sub.dnsServers.length > 0) {
        const safeDns = sub.dnsServers.map((d) => d.replace(/[^0-9a-fA-F:]/g, '')).filter(Boolean);
        if (safeDns.length > 0) {
          lines.push(`  RDNSS ${safeDns.join(' ')} {`);
          lines.push('    AdvRDNSSLifetime 3600;');
          lines.push('  };');
        }
      }
      if (sub.domainSearchList.length > 0) {
        const safeDomains = sub.domainSearchList.map((d) => d.replace(/[^a-zA-Z0-9.-]/g, '')).filter(Boolean);
        if (safeDomains.length > 0) {
          lines.push(`  DNSSL ${safeDomains.join(' ')} {`);
          lines.push('    AdvDNSSLLifetime 3600;');
          lines.push('  };');
        }
      }
      lines.push('};');
      lines.push('');
    }
    radvdConfig = lines.join('\n');
  }

  return { keaDhcp6Config, radvdConfig };
}
