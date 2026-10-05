import { PluginManifestSchema, type PluginManifest } from '../schemas/index.js';
export type { PluginManifest };

export const BUILTIN_PLUGINS: PluginManifest[] = [
  {
    id: 'haproxy',
    name: 'HAProxy Load Balancer & Reverse Proxy',
    version: '2.8.3',
    description: 'High performance TCP/HTTP load balancer, reverse proxy, and SSL/TLS termination with ACME integration.',
    author: 'HAProxy Technologies / Axonwall Core',
    systemdUnits: ['haproxy.service'],
    privileges: ['services.haproxy', 'system.certificates'],
    nftHooks: [
      { table: 'inet axonwall', chain: 'input', priority: 0 },
    ],
    menuEntry: {
      title: 'HAProxy Reverse Proxy',
      path: '/services/haproxy',
      icon: 'Network',
    },
  },
  {
    id: 'freeradius',
    name: 'FreeRADIUS AAA Suite',
    version: '3.2.3',
    description: 'High-performance RADIUS authentication and accounting server integrated with internal OpenLDAP.',
    author: 'Network RADIUS / Axonwall Core',
    systemdUnits: ['freeradius.service'],
    privileges: ['services.freeradius', 'system.users'],
    menuEntry: {
      title: 'FreeRADIUS Server',
      path: '/services/freeradius',
      icon: 'ShieldCheck',
    },
  },
  {
    id: 'snmp',
    name: 'Net-SNMP Daemon & MIBs',
    version: '5.9.3',
    description: 'SNMPv2c and SNMPv3 monitoring agent with standard MIBs for network management systems.',
    author: 'Net-SNMP Team / Axonwall Core',
    systemdUnits: ['snmpd.service'],
    privileges: ['system.monitoring'],
    menuEntry: {
      title: 'SNMP Monitoring',
      path: '/services/snmp',
      icon: 'Radio',
    },
  },
  {
    id: 'nut-ups',
    name: 'Network UPS Tools (NUT)',
    version: '2.8.0',
    description: 'Reliable UPS monitoring and automated graceful shutdown for battery backups over USB and serial.',
    author: 'NUT Project / Axonwall Core',
    systemdUnits: ['nut-server.service', 'nut-client.service'],
    privileges: ['system.hardware', 'system.power'],
    menuEntry: {
      title: 'UPS Battery (NUT)',
      path: '/system/ups',
      icon: 'BatteryCharging',
    },
  },
  {
    id: 'tailscale',
    name: 'Tailscale Mesh VPN',
    version: '1.74.0',
    description: 'Zero-config WireGuard mesh VPN for secure fleet connectivity and subnet routing.',
    author: 'Tailscale Inc. / Axonwall Community',
    systemdUnits: ['tailscaled.service'],
    privileges: ['vpn.tailscale', 'network.interfaces'],
    menuEntry: {
      title: 'Tailscale Mesh',
      path: '/vpn/tailscale',
      icon: 'Globe',
    },
  },
  {
    id: 'ntopng',
    name: 'ntopng High-Speed Flow Analysis',
    version: '5.6.0',
    description: 'Next-generation web-based traffic analysis and flow visibility.',
    author: 'ntop / Axonwall Community',
    systemdUnits: ['ntopng.service'],
    privileges: ['reporting.flows', 'system.monitoring'],
    menuEntry: {
      title: 'ntopng Flow Analyzer',
      path: '/reporting/ntopng',
      icon: 'Activity',
    },
  },
];

export function validatePluginManifest(manifest: unknown): PluginManifest {
  return PluginManifestSchema.parse(manifest);
}

export function findPluginById(id: string): PluginManifest | undefined {
  return BUILTIN_PLUGINS.find((p) => p.id === id);
}

export function isPluginAllowed(manifest: PluginManifest, grantedPrivileges: string[]): boolean {
  if (grantedPrivileges.includes('system.superuser') || grantedPrivileges.includes('*')) {
    return true;
  }
  return manifest.privileges.every((priv) => grantedPrivileges.includes(priv));
}
