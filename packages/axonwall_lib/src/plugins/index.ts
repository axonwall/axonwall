import { PluginManifestSchema, type PluginManifest, type DesiredState, type CoreCapabilities } from '../schemas/index.js';
export type { PluginManifest };

export const BUILTIN_PLUGINS: PluginManifest[] = [
  {
    id: 'core-firewall',
    name: 'Axonwall Enterprise NGFW & Router Engine',
    version: '0.3.1',
    category: 'core_role',
    description: 'Stateful nftables firewall, NAT/PAT, Multi-WAN SD-WAN, BGP/OSPF (FRR), Suricata IDS/IPS, CrowdSec, VPN concentrator, and Kea DHCP.',
    author: 'Axonwall Core',
    systemdUnits: ['nftables.service', 'suricata.service', 'frr.service', 'kea-dhcp4-server.service', 'conntrackd.service'],
    privileges: ['firewall.rules', 'network.routing', 'vpn.admin'],
    nftHooks: [
      { table: 'inet axonwall', chain: 'forward', priority: 0 },
      { table: 'ip axonwall_nat', chain: 'postrouting', priority: 100 },
    ],
    menuEntry: {
      title: 'Firewall Rules',
      path: '/firewall/rules',
      icon: 'Shield',
    },
  },
  {
    id: 'core-nas',
    name: 'Axonwall TrueNAS-Grade OpenZFS Storage & Shares',
    version: '0.3.1',
    category: 'core_role',
    description: 'Full OpenZFS pool/vdev manager (Stripe, Mirror, RAID-Z1/2/3, dRAID), datasets, zvols, automated snapshots, real-time HA ZFS replication, and SMB/NFSv4/iSCSI/S3 sharing.',
    author: 'Axonwall Core',
    systemdUnits: ['zfs-import.target', 'zfs-mount.service', 'smbd.service', 'nfs-server.service', 'iscsid.service'],
    privileges: ['storage.zfs', 'storage.shares', 'system.hardware'],
    nftHooks: [
      { table: 'inet axonwall', chain: 'input', priority: 0 },
    ],
    menuEntry: {
      title: 'ZFS Storage Pools',
      path: '/storage/pools',
      icon: 'HardDrive',
    },
  },
  {
    id: 'core-k3s',
    name: 'Kubernetes (K3s) & OpenEBS Distributed Storage',
    version: '1.31.2',
    category: 'core_role',
    description: 'Lightweight multi-node Kubernetes control plane with automatic HA second-node cluster join, OpenEBS ZFS-LocalPV, and synchronous 2-node Replicated Persistent Volumes.',
    author: 'CNCF / OpenEBS / Axonwall Core',
    systemdUnits: ['k3s.service'],
    privileges: ['k3s.cluster', 'storage.openebs'],
    nftHooks: [
      { table: 'inet axonwall', chain: 'input', priority: 0 },
    ],
    menuEntry: {
      title: 'K3s & OpenEBS Cluster',
      path: '/k3s/cluster',
      icon: 'Boxes',
    },
  },
  {
    id: 'haproxy',
    name: 'HAProxy Load Balancer & Reverse Proxy',
    version: '2.8.3',
    category: 'extension',
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
    category: 'extension',
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
    category: 'extension',
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
    category: 'extension',
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
    category: 'extension',
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
    category: 'extension',
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

export function resolveCapabilities(state?: Partial<DesiredState>): CoreCapabilities {
  const plugins = state?.plugins ?? [];
  const fwPlugin = plugins.find((p) => p.id === 'core-firewall');
  const nasPlugin = plugins.find((p) => p.id === 'core-nas');
  const k3sPlugin = plugins.find((p) => p.id === 'core-k3s');

  const firewallEnabled =
    state?.capabilities?.firewallEnabled !== undefined
      ? state.capabilities.firewallEnabled
      : fwPlugin !== undefined
        ? fwPlugin.enabled
        : true;

  const nasEnabled =
    state?.capabilities?.nasEnabled !== undefined
      ? state.capabilities.nasEnabled
      : nasPlugin !== undefined
        ? nasPlugin.enabled
        : Boolean(state?.nas?.enabled);

  const k3sEnabled =
    state?.capabilities?.k3sEnabled !== undefined
      ? state.capabilities.k3sEnabled
      : k3sPlugin !== undefined
        ? k3sPlugin.enabled
        : Boolean(state?.k3s?.enabled);

  return {
    firewallEnabled,
    nasEnabled,
    k3sEnabled,
  };
}

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
