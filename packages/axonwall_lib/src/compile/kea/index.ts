import { type DhcpConfig, type DhcpSubnet, type Interface, inferInterfaceRole } from '../../schemas/index.js';
import { isValidDevice } from '../../util/index.js';

export interface KeaCompileResult {
  keaDhcp4Config: string;
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

  return {
    keaDhcp4Config: JSON.stringify(keaConfig, null, 2),
  };
}
