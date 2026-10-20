import type { DhcpConfig, Interface } from '../../schemas/index.js';
import { isValidDevice } from '../../util/index.js';

export interface KeaCompileResult {
  keaDhcp4Config: string;
}

export function compileKeaDhcp4(dhcp: DhcpConfig, interfaces: Interface[]): KeaCompileResult {
  const ifDeviceMap = new Map<string, string>();
  for (const iface of interfaces) {
    ifDeviceMap.set(iface.name, iface.device);
  }

  const activeSubnets = dhcp.subnets.filter((s) => s.enabled);
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
        name: '/var/lib/axonwall/kea/dhcp4.leases',
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
