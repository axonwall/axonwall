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
    id: 'core-virt',
    name: 'Axonwall Hypervisor (KVM/QEMU & LXC Containers)',
    version: '0.3.1',
    category: 'core_role',
    description: 'Proxmox VE parity hypervisor with KVM hardware virtualization, Cloud-Init, LXC system containers, PCIe VFIO passthrough, and deduplicated backup engine.',
    author: 'Axonwall Core',
    systemdUnits: ['qemu-kvm.service', 'lxc.service'],
    privileges: ['virt.vms', 'virt.containers', 'system.hardware'],
    nftHooks: [
      { table: 'inet axonwall', chain: 'forward', priority: 0 },
    ],
    menuEntry: {
      title: 'Virtual Machines',
      path: '/compute/vms',
      icon: 'Cpu',
    },
  },
  {
    id: 'core-vigilante',
    name: 'Vigilante Cyber Defense, SOAR & Autonomous SOC',
    version: '0.1.0',
    category: 'core_role',
    description: 'Autonomous Cyber Defense Operations, real-time SOAR active containment, honeynet deception mesh, embedded security data lake, PCAP forensics, eBPF lineage, and 12 modular security packages.',
    author: 'DeployCoop / Axonwall Core',
    systemdUnits: ['axonwall-vigilante.service', 'k3s.service'],
    privileges: ['security.vigilante', 'security.soar', 'security.forensics', 'k3s.cluster', 'firewall.rules'],
    nftHooks: [
      { table: 'inet axonwall', chain: 'input', priority: -10 },
      { table: 'inet axonwall', chain: 'forward', priority: -10 },
    ],
    menuEntry: {
      title: 'Vigilante SOC & SOAR',
      path: '/vigilante/battlestation',
      icon: 'Radar',
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
  {
    id: 'cli-workstation',
    name: 'Modern Operator Shell & Editor (ZSH, Starship & VIM)',
    version: '1.0.0',
    category: 'extension',
    description: 'Pre-configured productivity environment with ZSH, Starship cyber-emerald prompt, live Commit-Confirm rollback indicator, VIM syntax defaults, and Tmux terminal multiplexer.',
    author: 'Axonwall Core',
    systemdUnits: [],
    privileges: ['system.users', 'system.hardware'],
    packages: {
      debian: ['zsh', 'vim', 'tmux'],
      alpine: ['zsh', 'vim', 'starship', 'tmux'],
    },
    cliBinaries: ['zsh', 'vim', 'starship', 'tmux'],
  },
  {
    id: 'cli-diagnostics-nastymap',
    name: 'NastyMap & Live CLI Telemetry Suite',
    version: '1.0.0',
    category: 'extension',
    description: 'Autonomous host discovery and vulnerability auditing with NastyMap & Nmap, plus real-time system/network monitors (btop, htop, iftop, iotop, slurm, sysstat, dnsutils).',
    author: 'Axonwall Core / NastyMap',
    systemdUnits: [],
    privileges: ['system.monitoring', 'network.interfaces'],
    packages: {
      debian: ['nmap', 'dnsutils', 'net-tools', 'btop', 'htop', 'iftop', 'iotop', 'slurm', 'sysstat'],
      alpine: ['nmap', 'bind-tools', 'net-tools', 'btop', 'htop', 'iftop', 'sysstat'],
    },
    cliBinaries: ['nmap', 'dig', 'netstat', 'btop', 'htop', 'iftop', 'iostat', 'mpstat'],
    menuEntry: {
      title: 'Diagnostics & NastyMap',
      path: '/diagnostics',
      icon: 'Terminal',
    },
  },
];

export function resolveCapabilities(state?: Partial<DesiredState>): CoreCapabilities {
  const plugins = state?.plugins ?? [];
  const fwPlugin = plugins.find((p) => p.id === 'core-firewall');
  const nasPlugin = plugins.find((p) => p.id === 'core-nas');
  const k3sPlugin = plugins.find((p) => p.id === 'core-k3s');
  const virtPlugin = plugins.find((p) => p.id === 'core-virt');
  const vigilantePlugin = plugins.find((p) => p.id === 'core-vigilante');

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

  const virtEnabled =
    state?.capabilities?.virtEnabled !== undefined
      ? state.capabilities.virtEnabled
      : virtPlugin !== undefined
        ? virtPlugin.enabled
        : Boolean(state?.virt?.enabled);

  const vigilanteEnabled =
    state?.capabilities?.vigilanteEnabled !== undefined
      ? state.capabilities.vigilanteEnabled
      : vigilantePlugin !== undefined
        ? vigilantePlugin.enabled
        : Boolean(state?.vigilante?.enabled);

  return {
    firewallEnabled,
    nasEnabled,
    k3sEnabled,
    virtEnabled,
    vigilanteEnabled,
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
