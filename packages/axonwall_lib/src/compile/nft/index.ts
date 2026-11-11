import {
  type DesiredState,
  type FirewallRule,
  type NatRule,
  type Alias,
  type Interface,
  type MdnsReflectorConfig,
  type UpnpConfig,
  normalizeAntiLockoutInterfaces,
  inferInterfaceRole,
  isValidFirewallEndpoint,
} from '../../schemas/index.js';
import { sanitizeIdentifier, isValidDevice, isValidIPv4, isValidIPv6, isValidCIDR, isValidMAC, isValidPortRange } from '../../util/index.js';
import { resolveCapabilities } from '../../plugins/index.js';
import { compileSuricata } from '../suricata/index.js';
import { compileCrowdSec } from '../crowdsec/index.js';
import { compileGeoIp, COUNTRY_CIDR_TABLE } from '../geoip/index.js';
import { compileNas } from '../nas/index.js';
import { compileK3s } from '../k3s/index.js';
import { compileKeaDhcp4 } from '../kea/index.js';
import { compileFrr } from '../frr/index.js';
import { compileUnbound, type UnboundConvergedRecord } from '../unbound/index.js';
import { compileWireGuard } from '../wireguard/index.js';
import { compileRosenpass } from '../rosenpass/index.js';
import { compileVigilanteBundle } from '../vigilante/index.js';
import { compileVowBundle } from '../vow/index.js';
import { compileHaProxy } from '../haproxy/index.js';
import { compileFreeRadiusClients } from '../freeradius/index.js';
import { compileSnmpd } from '../snmp/index.js';
import { compileNutUps } from '../nut/index.js';
import { compileTrafficShaper } from '../tc/index.js';
import { compileIpsec } from '../ipsec/index.js';
import { compileOpenVpn } from '../openvpn/index.js';
import { compileVirtBundle } from '../virt/index.js';

export interface CompileResult {
  nftScript: string;
  files: { path: string; content: string; fileMode: number }[];
  reloadServices: string[];
  warnings: string[];
}

function buildNasAndK3sInputRules(
  state: DesiredState,
  ifDeviceMap: Map<string, string>,
  nasEnabled: boolean,
  k3sEnabled: boolean,
  firewallEnabled = true,
): string[] {
  const hostRules: string[] = [];
  // In Host Mode (core-firewall disabled), there is no WAN perimeter: all enabled host interfaces
  // (including eth0 on 1-NIC nodes) are trusted cluster/storage interfaces.
  const trustedDevs = state.interfaces
    .filter((i) => i.enabled && (!firewallEnabled || inferInterfaceRole(i) !== 'wan') && isValidDevice(i.device))
    .map((i) => `"${i.device}"`);

  if (state.ha?.enabled && state.ha.syncInterface) {
    const syncDev = ifDeviceMap.get(state.ha.syncInterface) || state.ha.syncInterface;
    if (isValidDevice(syncDev)) {
      if (!trustedDevs.includes(`"${syncDev}"`)) {
        trustedDevs.push(`"${syncDev}"`);
      }
      // Open the port the unified HA sync server actually listens on
      // (sqliteSync.listenPort, default 9876 — state, DB, ZFS and K3s-token
      // endpoints all share it). The previous hardcoded { 8443, 9443 } pair
      // matched no listener in the tree and left the real sync port closed
      // under the compiled input-drop policy (audit S-04).
      const configuredPort = state.ha.sqliteSync?.listenPort;
      const syncPort =
        typeof configuredPort === 'number' && Number.isInteger(configuredPort) && configuredPort >= 1 && configuredPort <= 65535
          ? configuredPort
          : 9876;
      const configuredCtPort = state.ha.conntrackSync?.port;
      const conntrackPort =
        typeof configuredCtPort === 'number' && Number.isInteger(configuredCtPort) && configuredCtPort >= 1 && configuredCtPort <= 65535
          ? configuredCtPort
          : 3780;
      const ctRawIf = state.ha.conntrackSync?.interface || state.ha.syncInterface;
      const ctDev = ctRawIf ? ifDeviceMap.get(ctRawIf) || ctRawIf : syncDev;
      hostRules.push(`    iifname "${syncDev}" tcp dport ${syncPort} accept comment "ha-state-and-zfs-sync"`);
      hostRules.push(`    iifname "${syncDev}" tcp dport 636 accept comment "ha-openldap-ldaps-syncrepl"`);
      hostRules.push(`    iifname "${syncDev}" udp dport 123 accept comment "ha-chrony-ntp-sync"`);
      hostRules.push(`    iifname "${syncDev}" udp dport ${conntrackPort} accept comment "ha-conntrackd-sync"`);
      hostRules.push(`    iifname "${syncDev}" ip protocol igmp accept comment "ha-igmp"`);
      if (isValidDevice(ctDev) && ctDev !== syncDev) {
        hostRules.push(`    iifname "${ctDev}" udp dport ${conntrackPort} accept comment "ha-conntrackd-sync"`);
        hostRules.push(`    iifname "${ctDev}" ip protocol igmp accept comment "ha-igmp"`);
      }
    }
  }

  if (state.ha?.enabled) {
    const vrrpDevs = new Set<string>();
    if (state.ha.syncInterface) {
      const syncDev = ifDeviceMap.get(state.ha.syncInterface) || state.ha.syncInterface;
      if (isValidDevice(syncDev)) {
        vrrpDevs.add(syncDev);
      }
    }
    for (const vi of state.ha.vrrpInstances ?? []) {
      const rawIf = vi.interface || state.ha.syncInterface;
      if (!rawIf) continue;
      const vrrpDev = ifDeviceMap.get(rawIf) || rawIf;
      if (isValidDevice(vrrpDev)) {
        vrrpDevs.add(vrrpDev);
      }
    }
    for (const dev of vrrpDevs) {
      hostRules.push(`    iifname "${dev}" ip protocol 112 accept comment "ha-vrrp"`);
    }
  }

  if (firewallEnabled && trustedDevs.length === 0) {
    return hostRules;
  }
  const devSet = trustedDevs.length > 0 ? `iifname { ${trustedDevs.join(', ')} } ` : '';

  if (nasEnabled) {
    hostRules.push('    # NAS Plugin (core-nas): SMB, NFSv4, iSCSI, and S3 Service Ports');
    hostRules.push(`    ${devSet}tcp dport { 139, 445 } accept comment "nas-smb"`);
    if (state.nas?.wsddEnabled !== false && (state.nas?.smbShares?.length ?? 0) > 0) {
      hostRules.push(`    ${devSet}udp dport 3702 accept comment "nas-wsdd-discovery"`);
      hostRules.push(`    ${devSet}tcp dport 5357 accept comment "nas-wsdd-http"`);
    }
    hostRules.push(`    ${devSet}meta l4proto { tcp, udp } th dport { 111, 2049 } accept comment "nas-nfsv4"`);
    hostRules.push(`    ${devSet}tcp dport 3260 accept comment "nas-iscsi"`);
    if (state.nas?.s3?.enabled) {
      const s3Port = state.nas.s3.listenPort || 9000;
      const s3Console = state.nas.s3.consolePort || 9001;
      hostRules.push(`    ${devSet}tcp dport { ${s3Port}, ${s3Console} } accept comment "nas-s3-minio"`);
    }
  }

  if (k3sEnabled) {
    hostRules.push('    # Kubernetes Plugin (core-k3s): K3s Control Plane & OpenEBS Distributed Storage');
    hostRules.push(`    ${devSet}tcp dport { 6443, 10250, 2379, 2380, 10124, 9500 } accept comment "k3s-and-openebs-tcp"`);
    hostRules.push(`    ${devSet}udp dport { 8472, 51820, 51821 } accept comment "k3s-flannel-mesh"`);
    hostRules.push('    iifname "cni0" accept comment "k3s-cni0"');
    hostRules.push('    iifname "flannel*" accept comment "k3s-flannel"');
    if (state.k3s?.cniPlugin === 'cilium-ebpf') {
      hostRules.push(`    ${devSet}tcp dport { 4240, 4244, 4245 } accept comment "k3s-cilium-health-hubble"`);
      hostRules.push(`    ${devSet}udp dport { 8472, 6081 } accept comment "k3s-cilium-overlay"`);
      hostRules.push('    iifname "cilium*" accept comment "k3s-cilium-host"');
      hostRules.push('    iifname "lxc*" accept comment "k3s-cilium-pod"');
    }
  }

  return hostRules;
}

function synthesizeConvergedDnsRecords(state: DesiredState): UnboundConvergedRecord[] {
  const records: UnboundConvergedRecord[] = [];
  const baseDomain = (state.system?.domain || 'axonwall.local').replace(/^\.+|\.+$/g, '');

  const dhcpMacToIp = new Map<string, string>();
  for (const sub of state.dhcp?.subnets ?? []) {
    for (const m of sub.staticMappings ?? []) {
      if (m.mac && m.ip) {
        dhcpMacToIp.set(m.mac.toLowerCase(), m.ip);
      }
    }
  }

  if (state.dns?.autoRegisterVirtHosts !== false && state.virt) {
    for (const vm of state.virt.vms ?? []) {
      if (!vm.enabled) continue;
      const ipCfg = vm.cloudInit?.ipConfig || '';
      const m = ipCfg.match(/(?:^|,|ip=)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:\/\d+)?/);
      const staticIp =
        (m && m[1] ? m[1] : '') ||
        (vm.nics ?? []).map((n) => (n.mac ? dhcpMacToIp.get(n.mac.toLowerCase()) : undefined)).find(Boolean) ||
        '';
      if (staticIp && isValidIPv4(staticIp)) {
        const cleanHost = vm.name.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase();
        if (cleanHost) {
          records.push({
            fqdn: `${cleanHost}.${baseDomain}`,
            ip: staticIp,
            comment: `kvm-vm-${vm.vmid}`,
          });
        }
      }
    }
    for (const ct of state.virt.containers ?? []) {
      if (!ct.enabled) continue;
      const staticIp =
        (ct.nics ?? [])
          .map((n) => {
            if (n.mac && dhcpMacToIp.has(n.mac.toLowerCase())) {
              return dhcpMacToIp.get(n.mac.toLowerCase());
            }
            const maybeIp = (n.vnet || '').split('/')[0]?.trim();
            return maybeIp && isValidIPv4(maybeIp) ? maybeIp : undefined;
          })
          .find(Boolean) || '';
      const rawHost = (ct.hostname || '').replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase();
      if (staticIp && rawHost) {
        records.push({
          fqdn: `${rawHost}.${baseDomain}`,
          ip: staticIp,
          comment: `lxc-ct-${ct.ctid}`,
        });
      }
    }
  }

  if (state.dns?.autoRegisterK3sIngresses !== false && state.k3s?.workloads?.length) {
    const lanIface =
      state.interfaces.find((i) => i.enabled && i.name === 'lan' && i.ipv4Address) ||
      state.interfaces.find((i) => i.enabled && inferInterfaceRole(i) === 'lan' && i.ipv4Address);
    const vipIp = state.virtualIps?.[0]?.ip?.split('/')[0]?.trim();
    const targetIp = vipIp || lanIface?.ipv4Address?.split('/')[0]?.trim();
    if (targetIp) {
      for (const wl of state.k3s.workloads) {
        if (!wl.enabled || !wl.ingressHostname) continue;
        const cleanFqdn = wl.ingressHostname.trim().replace(/\.$/, '');
        if (cleanFqdn) {
          records.push({
            fqdn: cleanFqdn,
            ip: targetIp,
            comment: `k3s-ingress-${wl.name}`,
          });
        }
      }
    }
  }

  return records;
}

function compileAvahiReflectorConf(cfg: MdnsReflectorConfig, ifDeviceMap: Map<string, string>): string {
  const devs = (cfg.interfaces ?? [])
    .map((n) => ifDeviceMap.get(n) || n)
    .filter(isValidDevice);
  const lines = [
    '# Axonwall mDNS / Bonjour Reflector (/etc/avahi/avahi-daemon.conf)',
    '[server]',
    `use-ipv4=yes`,
    `use-ipv6=${cfg.enableIpv6 !== false ? 'yes' : 'no'}`,
    ...(devs.length > 0 ? [`allow-interfaces=${devs.join(',')}`] : []),
    'ratelimit-interval-usec=1000000',
    'ratelimit-burst=1000',
    '',
    '[reflector]',
    `enable-reflector=${cfg.enabled ? 'yes' : 'no'}`,
    'reflect-ipv=no',
    '',
    '[publish]',
    'disable-publishing=yes',
    '',
  ];
  return lines.join('\n');
}

function compileMiniupnpdConf(cfg: UpnpConfig, ifDeviceMap: Map<string, string>): string {
  const extDev = ifDeviceMap.get(cfg.externalInterface || 'wan') || cfg.externalInterface || 'eth0';
  const intDevs = (cfg.internalInterfaces ?? ['lan'])
    .map((n) => ifDeviceMap.get(n) || n)
    .filter(isValidDevice);
  const lines = [
    '# Axonwall UPnP IGD & NAT-PMP/PCP (/etc/miniupnpd/miniupnpd.conf)',
    `ext_ifname=${isValidDevice(extDev) ? extDev : 'eth0'}`,
    ...intDevs.map((d) => `listening_ip=${d}`),
    `enable_natpmp=${cfg.enableNatPmp !== false ? 'yes' : 'no'}`,
    `enable_upnp=${cfg.enableUpnp !== false ? 'yes' : 'no'}`,
    `secure_mode=${cfg.secureMode !== false ? 'yes' : 'no'}`,
    'system_uptime=yes',
    'clean_ruleset_interval=600',
    ...(cfg.stunHost ? [`ext_perform_stun=yes`, `ext_stun_host=${cfg.stunHost.replace(/[^a-zA-Z0-9_.-]/g, '')}`] : []),
    'upnp_table_name=axonwall',
    'upnp_nat_table_name=axonwall',
    'upnp_forward_chain=upnp_forward',
    'upnp_nat_chain=upnp_prerouting',
    'upnp_nat_postrouting_chain=upnp_postrouting',
  ];
  for (const acl of cfg.acls ?? []) {
    const safePorts = acl.externalPorts.replace(/[^0-9-]/g, '');
    const safeIntPorts = (acl.internalPorts || '1024-65535').replace(/[^0-9-]/g, '');
    const safeSub = acl.internalCidr.replace(/[^0-9a-fA-F:./]/g, '');
    if (safePorts && safeSub) {
      lines.push(`${acl.action} ${safePorts} ${safeSub} ${safeIntPorts}`);
    }
  }
  lines.push('deny 0-65535 0.0.0.0/0 0-65535', '');
  return lines.join('\n');
}

export function compileNftables(state: DesiredState): CompileResult {
  const lines: string[] = [];
  const warnings: string[] = [];
  const files: { path: string; content: string; fileMode: number }[] = [];
  const reloadServices: string[] = [];

  const capabilities = resolveCapabilities(state);

  // Helper to map interfaces to system devices and roles early for service compilers
  const ifDeviceMap = new Map<string, string>();
  const ifRoleMap = new Map<string, 'wan' | 'lan'>();
  for (const iface of state.interfaces) {
    ifDeviceMap.set(iface.name, iface.device);
    ifRoleMap.set(iface.name, inferInterfaceRole(iface));
  }
  const isWanInterfaceName = (ifaceName: string): boolean => {
    const mapped = ifRoleMap.get(ifaceName);
    if (mapped) return mapped === 'wan';
    return inferInterfaceRole({ name: ifaceName }) === 'wan';
  };

  // Emit core-firewall runtime state so axonwalld can stop NGFW-only daemons in Host Mode
  files.push({
    path: '/etc/axonwall/managed/firewall_config.json',
    content: JSON.stringify(
      {
        enabled: capabilities.firewallEnabled,
      },
      null,
      2,
    ),
    fileMode: 0o600,
  });

  // Emit NAS and K3s runtime bundles whenever state is compiled
  if (state.nas || capabilities.nasEnabled) {
    const nasCompiled = compileNas(state.nas);
    files.push({
      path: '/etc/axonwall/managed/nas_config.json',
      content: JSON.stringify(
        {
          enabled: capabilities.nasEnabled,
          pools: state.nas?.pools ?? [],
          datasets: state.nas?.datasets ?? [],
          snapshotPolicies: state.nas?.snapshotPolicies ?? [],
          cloudSyncTasks: state.nas?.cloudSyncTasks ?? [],
          smartSchedule: state.nas?.smartSchedule,
          s3: state.nas?.s3,
          wsddEnabled: state.nas?.wsddEnabled !== false,
          smbConf: nasCompiled.smbConf,
          nfsExports: nasCompiled.nfsExports,
          iscsiConf: nasCompiled.iscsiConf,
          lioSaveconfigJson: nasCompiled.lioSaveconfigJson,
          s3EnvConf: nasCompiled.s3EnvConf,
          cloudSyncCommands: nasCompiled.cloudSyncCommands,
        },
        null,
        2,
      ),
      fileMode: 0o600,
    });
    if (capabilities.nasEnabled && (state.nas?.iscsiTargets?.length ?? 0) > 0) {
      files.push({
        path: '/etc/rtslib-fb-target/saveconfig.json',
        content: nasCompiled.lioSaveconfigJson,
        fileMode: 0o600,
      });
    }
    if (capabilities.nasEnabled && state.nas?.s3?.enabled && nasCompiled.s3EnvConf) {
      files.push({
        path: '/etc/default/minio',
        content: nasCompiled.s3EnvConf,
        fileMode: 0o600,
      });
    }
  }

  if (state.k3s || capabilities.k3sEnabled) {
    const k3sCompiled = compileK3s(state);
    const effectiveRole = state.ha?.role || state.ha?.nodeRole || 'master';
    const effectivePeer = state.ha?.peerIp || state.ha?.peerAddress || '';
    const effectiveSecret =
      state.ha?.sqliteSync?.authToken ||
      state.ha?.vrrpInstances?.[0]?.authPassword ||
      '';
    files.push({
      path: '/etc/axonwall/managed/k3s_config.json',
      content: JSON.stringify(
        {
          enabled: capabilities.k3sEnabled,
          haEnabled: Boolean(state.ha?.enabled),
          role: effectiveRole,
          haRole: effectiveRole,
          peerIp: effectivePeer,
          haPeerAddress: effectivePeer,
          syncPort: state.ha?.sqliteSync?.listenPort ?? state.ha?.peerPort ?? 9876,
          authToken: effectiveSecret,
          haSharedSecret: effectiveSecret,
          autoJoinHaPeer: state.k3s?.autoJoinHaPeer !== false,
          cniPlugin: state.k3s?.cniPlugin || 'flannel',
          haTopology: state.k3s?.haTopology || 'embedded-etcd',
          etcdSnapshots: state.k3s?.etcdSnapshots,
          zfsLocalPvPool: state.k3s?.openEbs?.zfsLocalPvPool || 'tank',
          replicatedPool: state.k3s?.openEbs?.replicatedBackingPool || 'tank/openebs-replicated',
          k3sConfigYaml: k3sCompiled.k3sConfigYaml,
          openEbsManifestYaml: k3sCompiled.openEbsManifestYaml,
          workloadsManifestYaml: k3sCompiled.workloadsManifestYaml,
          ciliumManifestYaml: k3sCompiled.ciliumManifestYaml,
          serviceLbManifestYaml: k3sCompiled.serviceLbManifestYaml,
        },
        null,
        2,
      ),
      fileMode: 0o600,
    });
  }

  // Emit KVM / LXC Hypervisor (core-virt) runtime configuration
  let virtCompiledBundle: ReturnType<typeof compileVirtBundle> | undefined;
  if (state.virt || capabilities.virtEnabled) {
    virtCompiledBundle = compileVirtBundle(state);
    files.push({
      path: '/etc/axonwall/managed/virt_config.json',
      content: JSON.stringify(
        {
          enabled: capabilities.virtEnabled,
          defaultPool: state.virt?.defaultPool ?? 'tank',
          isoPool: state.virt?.isoPool ?? 'tank',
          backupJobs: state.virt?.backupJobs ?? [],
          securityGroups: state.virt?.securityGroups ?? [],
          ...virtCompiledBundle,
        },
        null,
        2,
      ),
      fileMode: 0o600,
    });
  }

  // Compile IPsec & Traffic Shaper early so XFRM/TC commands are included in netdev reconciliation
  const ipsecCompiled = state.ipsec?.enabled ? compileIpsec(state.ipsec) : undefined;
  const tcCompiled = state.trafficShaper?.enabled ? compileTrafficShaper(state.trafficShaper) : undefined;

  if (
    (state.vlans?.length ?? 0) > 0 ||
    (state.bonds?.length ?? 0) > 0 ||
    (state.bridges?.length ?? 0) > 0 ||
    (state.virtualIps?.length ?? 0) > 0 ||
    (state.vrfs?.length ?? 0) > 0 ||
    (state.routes?.length ?? 0) > 0 ||
    Boolean(tcCompiled) ||
    Boolean(ipsecCompiled?.xfrmSetupCommands.length) ||
    Boolean(virtCompiledBundle?.vxlanCommands.length)
  ) {
    files.push({
      path: '/etc/axonwall/managed/netdev_config.json',
      content: JSON.stringify(
        {
          vlans: state.vlans ?? [],
          bonds: state.bonds ?? [],
          bridges: state.bridges ?? [],
          virtualIps: state.virtualIps ?? [],
          vrfs: state.vrfs ?? [],
          routes: state.routes ?? [],
          tcCommands: tcCompiled?.commands ?? [],
          xfrmCommands: ipsecCompiled?.xfrmSetupCommands ?? [],
          vxlanCommands: virtCompiledBundle?.vxlanCommands ?? [],
        },
        null,
        2,
      ),
      fileMode: 0o600,
    });
  }

  // Emit High Availability runtime configuration
  if (state.ha) {
    files.push({
      path: '/etc/axonwall/managed/ha_config.json',
      content: JSON.stringify(state.ha, null, 2),
      fileMode: 0o600,
    });
  }

  // Emit SD-WAN Gateway & probe configuration (only when core-firewall is enabled)
  if (
    capabilities.firewallEnabled &&
    ((state.gateways && state.gateways.length > 0) || (state.gatewayGroups && state.gatewayGroups.length > 0))
  ) {
    files.push({
      path: '/etc/axonwall/managed/sdwan_config.json',
      content: JSON.stringify(
        {
          enabled: true,
          gateways: state.gateways || [],
          gatewayGroups: state.gatewayGroups || [],
        },
        null,
        2,
      ),
      fileMode: 0o600,
    });
  }

  // Emit Zero Trust Identity-Aware Proxy (IAP) configuration
  if (state.zeroTrust) {
    files.push({
      path: '/etc/axonwall/managed/zero_trust_apps.json',
      content: JSON.stringify(state.zeroTrust, null, 2),
      fileMode: 0o600,
    });
  }

  // Emit Vigilante threat defense configuration and K3s manifests
  if (state.vigilante || capabilities.vigilanteEnabled) {
    const vigilanteCompiled = compileVigilanteBundle(state);
    files.push({
      path: '/etc/axonwall/managed/vigilante_config.json',
      content: JSON.stringify(
        {
          ...(state.vigilante ?? { enabled: capabilities.vigilanteEnabled }),
          k3sEnabled: capabilities.k3sEnabled,
          compiledBundle: vigilanteCompiled,
        },
        null,
        2,
      ),
      fileMode: 0o600,
    });
    if (capabilities.firewallEnabled && state.dns?.enabled && state.vigilante?.enabled) {
      files.push({
        path: '/etc/unbound/unbound.conf.d/vigilante.conf',
        content: vigilanteCompiled.unboundOverrides,
        fileMode: 0o644,
      });
    }
  }

  // Emit Vigilant Octo Waffle (VOW) K3s GitOps & App Platform configuration
  if (state.vow?.enabled || state.plugins?.some((p) => p.id === 'vigilant-octo-waffle' && p.enabled)) {
    const vowCompiled = compileVowBundle(state);
    files.push({
      path: '/etc/axonwall/managed/vow_config.json',
      content: JSON.stringify(vowCompiled, null, 2),
      fileMode: 0o600,
    });
    if (capabilities.firewallEnabled && state.dns?.enabled && vowCompiled.enabled && state.vow?.syncUnboundDns !== false) {
      files.push({
        path: '/etc/unbound/unbound.conf.d/vow.conf',
        content: vowCompiled.unboundOverrides,
        fileMode: 0o644,
      });
    }
  }

  // Emit Kea DHCPv4 + DHCPv6 + radvd configurations only when core-firewall is enabled
  if (capabilities.firewallEnabled && state.dhcp) {
    const kea = compileKeaDhcp4(state.dhcp, state.interfaces);
    files.push({
      path: '/etc/kea/kea-dhcp4.conf',
      content: kea.keaDhcp4Config,
      fileMode: 0o644,
    });
    reloadServices.push('kea-dhcp4-server');
    if (kea.keaDhcp6Config) {
      files.push({
        path: '/etc/kea/kea-dhcp6.conf',
        content: kea.keaDhcp6Config,
        fileMode: 0o644,
      });
      reloadServices.push('kea-dhcp6-server');
    }
    if (kea.radvdConfig) {
      files.push({
        path: '/etc/radvd.conf',
        content: kea.radvdConfig,
        fileMode: 0o644,
      });
      reloadServices.push('radvd');
    }
  }

  // Emit Unbound DNS Resolver configuration (with Converged KVM/LXC/K3s Auto-DNS)
  if (capabilities.firewallEnabled && state.dns?.enabled) {
    const convergedRecords = synthesizeConvergedDnsRecords(state);
    const unbound = compileUnbound(state.dns, state.headscale, convergedRecords);
    files.push({
      path: '/etc/unbound/unbound.conf.d/axonwall.conf',
      content: unbound.unboundConfig,
      fileMode: 0o644,
    });
    reloadServices.push('unbound');
  }

  // Emit FRRouting (FRR) configuration (only when core-firewall is enabled),
  // automatically integrating K3s Bare-Metal ServiceLB BGP pools when BGP is active.
  if (capabilities.firewallEnabled && state.frr?.enabled) {
    let effectiveFrr = state.frr;
    const bgpLbPools = (state.k3s?.serviceLbPools ?? []).filter(
      (p) => p.mode === 'bgp' || p.mode === 'both',
    );
    if (effectiveFrr.bgp?.enabled && bgpLbPools.length > 0) {
      const mergedNetworks = [...effectiveFrr.bgp.networks];
      for (const pool of bgpLbPools) {
        if (pool.cidr && !mergedNetworks.includes(pool.cidr)) {
          mergedNetworks.push(pool.cidr);
        }
      }
      const mergedNeighbors = [...effectiveFrr.bgp.neighbors];
      if (!mergedNeighbors.some((n) => n.peerIp === '127.0.0.1')) {
        mergedNeighbors.push({
          peerIp: '127.0.0.1',
          remoteAs: effectiveFrr.bgp.asNumber,
          description: 'Axonwall K3s Cilium BGP Speaker',
          bfd: false,
          nextHopSelf: true,
          softReconfiguration: true,
        });
      }
      effectiveFrr = {
        ...effectiveFrr,
        bgp: {
          ...effectiveFrr.bgp,
          networks: mergedNetworks,
          neighbors: mergedNeighbors,
        },
      };
    }
    const frr = compileFrr(effectiveFrr);
    files.push({
      path: '/etc/frr/frr.conf',
      content: frr.frrConf,
      fileMode: 0o640,
    });
    files.push({
      path: '/etc/frr/daemons',
      content: frr.daemonsConf,
      fileMode: 0o640,
    });
    reloadServices.push('frr');
  }

  // Emit strongSwan IKEv2 IPsec configuration when enabled
  if (ipsecCompiled) {
    files.push({
      path: '/etc/swanctl/conf.d/axonwall.conf',
      content: ipsecCompiled.swanctlConf,
      fileMode: 0o600,
    });
    reloadServices.push('strongswan');
  }

  // Emit OpenVPN 2.6 DCO server configurations when enabled
  if (state.openvpn?.enabled) {
    const ovpnCompiled = compileOpenVpn(state.openvpn);
    for (const srv of ovpnCompiled.servers) {
      const safeSrv = srv.name.replace(/[^a-zA-Z0-9_-]/g, '_');
      files.push({
        path: `/etc/openvpn/server/${safeSrv}.conf`,
        content: srv.serverConf,
        fileMode: 0o600,
      });
      reloadServices.push(`openvpn-server@${safeSrv}`);
    }
  }

  // Emit mDNS Reflector, UPnP IGD, and DDNS configurations when enabled
  if (capabilities.firewallEnabled && state.mdnsReflector?.enabled) {
    files.push({
      path: '/etc/avahi/avahi-daemon.conf',
      content: compileAvahiReflectorConf(state.mdnsReflector, ifDeviceMap),
      fileMode: 0o644,
    });
    reloadServices.push('avahi-daemon');
  }
  if (capabilities.firewallEnabled && state.upnp?.enabled) {
    files.push({
      path: '/etc/miniupnpd/miniupnpd.conf',
      content: compileMiniupnpdConf(state.upnp, ifDeviceMap),
      fileMode: 0o644,
    });
    reloadServices.push('miniupnpd');
  }
  if (capabilities.firewallEnabled && state.ddns?.enabled) {
    files.push({
      path: '/etc/axonwall/managed/ddns_config.json',
      content: JSON.stringify(state.ddns, null, 2),
      fileMode: 0o600,
    });
  }

  // Emit WireGuard configuration (including Rosenpass Fail-Closed PostUp seed when enabled)
  if (state.wireguard?.enabled) {
    const wgCompiled = compileWireGuard(state.wireguard, state.rosenpass);
    files.push({
      path: '/etc/wireguard/wg0.conf',
      content: wgCompiled.wgConfig,
      fileMode: 0o600,
    });
    reloadServices.push('wg-quick@wg0');
  }

  // Emit Rosenpass Post-Quantum Hybrid Dual-KEM configuration
  if (state.rosenpass?.enabled) {
    const rpCompiled = compileRosenpass(state.rosenpass);
    files.push({
      path: '/etc/rosenpass/config.toml',
      content: rpCompiled.configToml,
      fileMode: 0o600,
    });
    reloadServices.push('rosenpass');
  }

  // Emit HAProxy configuration (merging converged K3s exposeViaHaproxy & ingressHostname TLS workloads if present)
  const k3sHaproxyWorkloads = (state.k3s?.workloads ?? []).filter(
    (w) => w.enabled && (w.exposeViaHaproxy || Boolean(w.ingressHostname)) && w.port > 0,
  );
  if (state.haproxy?.enabled || k3sHaproxyWorkloads.length > 0) {
    const baseHaproxy = state.haproxy ?? {
      enabled: true,
      mode: 'http' as const,
      frontends: [],
      backends: [],
    };
    const mergedFrontends = baseHaproxy.frontends.map((fe) => ({
      ...fe,
      hostRules: [...(fe.hostRules ?? [])],
    }));
    const mergedBackends = [...baseHaproxy.backends];
    const convergedHostRules: Array<{ hostname: string; backend: string }> = [];

    for (const wl of k3sHaproxyWorkloads) {
      const beName = `k3s_${wl.name.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
      if (!mergedBackends.some((b) => b.name === beName)) {
        mergedBackends.push({
          name: beName,
          mode: baseHaproxy.mode,
          balance: 'roundrobin',
          servers: [{ name: 'local_k3s', address: '127.0.0.1', port: wl.port, check: true }],
        });
      }
      if (wl.exposeViaHaproxy) {
        const feName = `fe_${beName}`;
        if (!mergedFrontends.some((f) => f.name === feName || f.bindPort === wl.port)) {
          mergedFrontends.push({
            name: feName,
            bindPort: wl.port,
            ssl: false,
            defaultBackend: beName,
            hostRules: [],
          });
        }
      }
      if (wl.ingressHostname) {
        convergedHostRules.push({ hostname: wl.ingressHostname.trim(), backend: beName });
      }
    }

    if (convergedHostRules.length > 0 && baseHaproxy.mode === 'http') {
      const existingTlsFe = mergedFrontends.find((f) => f.bindPort === 8443 || (f.ssl && f.bindPort === 443));
      if (existingTlsFe) {
        for (const hr of convergedHostRules) {
          if (!existingTlsFe.hostRules.some((r) => r.hostname === hr.hostname)) {
            existingTlsFe.hostRules.push(hr);
          }
        }
      } else {
        mergedFrontends.push({
          name: 'fe_converged_tls',
          bindPort: 8443,
          ssl: true,
          certName: 'hub',
          defaultBackend: convergedHostRules[0]!.backend,
          hostRules: convergedHostRules,
        });
      }
    }

    files.push({
      path: '/etc/haproxy/haproxy.cfg',
      content: compileHaProxy({ ...baseHaproxy, enabled: true, frontends: mergedFrontends, backends: mergedBackends }),
      fileMode: 0o644,
    });
    reloadServices.push('haproxy');
  }

  // Emit FreeRADIUS clients configuration when enabled
  if (state.freeradius?.enabled) {
    files.push({
      path: '/etc/freeradius/3.0/clients.conf',
      content: compileFreeRadiusClients(state.freeradius),
      fileMode: 0o640,
    });
    reloadServices.push('freeradius');
  }

  // Emit Net-SNMP snmpd configuration when enabled
  if (state.snmp?.enabled) {
    files.push({
      path: '/etc/snmp/snmpd.conf',
      content: compileSnmpd(state.snmp),
      fileMode: 0o640,
    });
    reloadServices.push('snmpd');
  }

  // Emit Network UPS Tools (NUT) configuration when enabled
  if (state.ups?.enabled) {
    const nutCompiled = compileNutUps(state.ups);
    files.push({
      path: '/etc/nut/ups.conf',
      content: nutCompiled.upsConf,
      fileMode: 0o640,
    });
    files.push({
      path: '/etc/nut/nut.conf',
      content: nutCompiled.nutConf,
      fileMode: 0o640,
    });
    reloadServices.push('nut-server');
    reloadServices.push('nut-client');
  }

  // When core-firewall plugin is disabled, emit a clean Host-Mode Appliance Ruleset
  if (!capabilities.firewallEnabled) {
    lines.push('#!/usr/sbin/nft -f');
    lines.push('# Axonwall Host-Mode Appliance Ruleset (core-firewall plugin disabled)');
    lines.push(`# Active Roles: NAS=${capabilities.nasEnabled} | K3s=${capabilities.k3sEnabled} | Virt=${capabilities.virtEnabled}`);
    lines.push(`# Version: ${state.version} | Generated: ${new Date().toISOString()}`);
    lines.push('');
    lines.push('table inet axonwall {}');
    lines.push('flush table inet axonwall');
    lines.push('table inet axonwall {');
    lines.push('  chain input {');
    lines.push('    type filter hook input priority filter; policy drop;');
    lines.push('    ct state established,related accept');
    lines.push('    ct state invalid drop');
    lines.push('    iif "lo" accept');
    lines.push('    icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept');
    lines.push('    icmpv6 type { echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept');

    if (state.system.antiLockout?.enabled) {
      const ifaceList = normalizeAntiLockoutInterfaces(state.system.antiLockout);
      const ports = state.system.antiLockout.ports.join(', ');
      const seenDevs = new Set<string>();

      // In Host Mode (core-firewall disabled), there is no untrusted WAN router perimeter:
      // allow anti-lockout on configured anti-lockout interfaces AND all enabled host interfaces
      // so 1-NIC nodes (where eth0 is named 'wan') are never locked out of SSH/Web Console.
      const hostCandidates = [
        ...ifaceList,
        ...state.interfaces.filter((i) => i.enabled).map((i) => i.name),
      ];
      for (const ifaceName of hostCandidates) {
        const dev = ifDeviceMap.get(ifaceName) || ifaceName;
        if (isValidDevice(dev) && !seenDevs.has(dev)) {
          seenDevs.add(dev);
          const comment = ifaceName === 'lan' ? 'anti-lockout' : `anti-lockout-${ifaceName}`;
          lines.push(`    iifname "${dev}" tcp dport { ${ports} } accept comment "${comment}"`);
        }
      }
    }

    lines.push(...buildNasAndK3sInputRules(state, ifDeviceMap, capabilities.nasEnabled, capabilities.k3sEnabled, false));

    // WireGuard listener & tunnel input in Host Mode
    if (state.wireguard?.enabled) {
      lines.push(`    udp dport ${state.wireguard.listenPort} accept comment "wireguard-service"`);
      lines.push('    iifname "wg*" accept comment "wireguard-tunnel-input"');
    }

    // Rosenpass Post-Quantum Dual-KEM listener in Host Mode
    if (state.rosenpass?.enabled) {
      const rpPort =
        typeof state.rosenpass.listenPort === 'number' &&
        Number.isInteger(state.rosenpass.listenPort) &&
        state.rosenpass.listenPort >= 1 &&
        state.rosenpass.listenPort <= 65535
          ? state.rosenpass.listenPort
          : 9999;
      lines.push(`    udp dport ${rpPort} accept comment "rosenpass-pq-kem"`);
    }

    // Headscale / Tailscale mesh in Host Mode
    if (state.headscale?.enabled) {
      lines.push('    udp dport 41641 accept comment "headscale-mesh"');
      lines.push('    iifname "tailscale0" accept comment "tailscale-mesh-input"');
    }

    // Hypervisor (core-virt) bridge input in Host Mode
    if (capabilities.virtEnabled) {
      lines.push('    iifname "vmbr*" accept comment "virt-bridge-input"');
    }

    lines.push('  }');
    lines.push('');
    lines.push('  chain forward {');
    lines.push('    type filter hook forward priority filter; policy drop;');
    lines.push('    ct state established,related accept');
    lines.push('    ct state invalid drop');
    if (capabilities.k3sEnabled) {
      lines.push('    iifname "cni0" accept comment "k3s-pod-forward"');
      lines.push('    oifname "cni0" accept comment "k3s-pod-forward"');
      lines.push('    iifname "flannel*" accept comment "k3s-flannel-forward"');
      lines.push('    oifname "flannel*" accept comment "k3s-flannel-forward"');
    }
    if (capabilities.virtEnabled) {
      lines.push('    iifname "vmbr*" accept comment "virt-bridge-forward"');
      lines.push('    oifname "vmbr*" accept comment "virt-bridge-forward"');
    }
    if (state.wireguard?.enabled) {
      lines.push('    iifname "wg*" accept comment "wireguard-forward"');
      lines.push('    oifname "wg*" accept comment "wireguard-forward"');
    }
    if (state.headscale?.enabled) {
      lines.push('    iifname "tailscale0" accept comment "tailscale-forward"');
      lines.push('    oifname "tailscale0" accept comment "tailscale-forward"');
    }
    lines.push('  }');
    lines.push('');
    lines.push('  chain output {');
    lines.push('    type filter hook output priority filter; policy accept;');
    lines.push('  }');
    lines.push('}');
    lines.push('');

    return {
      nftScript: lines.join('\n'),
      files,
      reloadServices,
      warnings,
    };
  }

  const suricataConfig = state.suricata
    ? {
        ...state.suricata,
        interfaces: state.suricata.interfaces
          .map((i) => ifDeviceMap.get(i) || i)
          .filter(isValidDevice),
      }
    : undefined;
  const suricataCompiled = compileSuricata(suricataConfig);
  const crowdsecCompiled = compileCrowdSec(state.crowdsec);
  const geoipCompiled = compileGeoIp(state.geoip);

  if (state.suricata?.enabled) {
    files.push({
      path: '/etc/suricata/suricata.yaml',
      content: suricataCompiled.suricataYaml,
      fileMode: 0o644,
    });
    reloadServices.push('suricata');
  }

  if (state.crowdsec?.enabled) {
    files.push({
      path: '/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml',
      content: crowdsecCompiled.bouncerYaml,
      fileMode: 0o644,
    });
    reloadServices.push('crowdsec-firewall-bouncer');
  }

  lines.push('#!/usr/sbin/nft -f');
  lines.push('# Axonwall Auto-Generated nftables configuration');
  lines.push(`# Version: ${state.version} | Generated: ${new Date().toISOString()}`);
  lines.push('');

  // 1. Table definition (isolated namespace, never flushes other tables)
  lines.push('table inet axonwall {}');
  lines.push('flush table inet axonwall');
  lines.push('table inet axonwall {');

  // 2. Named sets for Aliases & Dynamic Quarantine
  lines.push('  # Dynamic quarantine sets');
  lines.push('  set blocked_ips {');
  lines.push('    type ipv4_addr;');
  lines.push('    flags interval;');
  lines.push('  }');
  lines.push('  set blocked_ips6 {');
  lines.push('    type ipv6_addr;');
  lines.push('    flags interval;');
  lines.push('  }');
  lines.push('  set blocked_macs {');
  lines.push('    type ether_addr;');
  lines.push('  }');
  lines.push('');

  if (state.crowdsec?.enabled) {
    lines.push('  # CrowdSec integration');
    lines.push(crowdsecCompiled.nftSetDefinition.split('\n').map(l => '  ' + l).join('\n'));
    lines.push('');
  }

  if (state.geoip?.enabled && geoipCompiled.nftSetDefinitions.length > 0) {
    lines.push('  # GeoIP Location-based Sets');
    lines.push(...geoipCompiled.nftSetDefinitions);
    lines.push('');
  }

  const emittedSets = new Map<string, { setType: string; isV6: boolean; hasDualV6?: boolean }>();

  if (state.aliases.length > 0) {
    lines.push('  # Aliases & Dynamic Sets');
    for (const alias of state.aliases) {
      if (!alias.enabled || alias.entries.length === 0) continue;
      const setName = `set_${sanitizeIdentifier(alias.name)}`;

      // Expand geoip country codes before validating set elements
      const rawExpanded: string[] = [];
      for (const rawEntry of alias.entries) {
        const trimmed = rawEntry.trim();
        if (!trimmed) continue;
        if (alias.type === 'geoip' && COUNTRY_CIDR_TABLE[trimmed.toUpperCase()]) {
          rawExpanded.push(...COUNTRY_CIDR_TABLE[trimmed.toUpperCase()]);
        } else {
          rawExpanded.push(trimmed);
        }
      }

      const emitSetBlock = (targetSetName: string, setType: string, entries: string[]) => {
        const elements = entries.join(', ');
        lines.push(`  set ${targetSetName} {`);
        lines.push(`    type ${setType};`);
        if (
          alias.type === 'network' ||
          alias.type === 'host' ||
          alias.type === 'port' ||
          alias.type === 'urltable' ||
          alias.type === 'geoip' ||
          alias.type === 'asn'
        ) {
          lines.push('    flags interval;');
        }
        lines.push(`    elements = { ${elements} };`);
        lines.push('  }');
      };

      if (alias.type === 'port') {
        const validPorts = rawExpanded.filter((e) => isValidPortRange(e));
        if (validPorts.length === 0) continue;
        emitSetBlock(setName, 'inet_service', validPorts);
        emittedSets.set(setName, { setType: 'inet_service', isV6: false });
      } else if (alias.type === 'mac') {
        const validMacs = rawExpanded.filter((e) => isValidMAC(e));
        if (validMacs.length === 0) continue;
        emitSetBlock(setName, 'ether_addr', validMacs);
        emittedSets.set(setName, { setType: 'ether_addr', isV6: false });
      } else {
        const v4Entries = rawExpanded.filter((e) => !e.includes(':') && (isValidIPv4(e) || isValidCIDR(e)));
        const v6Entries = rawExpanded.filter((e) => e.includes(':') && (isValidIPv6(e) || isValidCIDR(e)));
        if (v4Entries.length > 0 && v6Entries.length > 0) {
          emitSetBlock(setName, 'ipv4_addr', v4Entries);
          emitSetBlock(`${setName}_v6`, 'ipv6_addr', v6Entries);
          emittedSets.set(setName, { setType: 'ipv4_addr', isV6: false, hasDualV6: true });
          emittedSets.set(`${setName}_v6`, { setType: 'ipv6_addr', isV6: true });
        } else if (v6Entries.length > 0) {
          emitSetBlock(setName, 'ipv6_addr', v6Entries);
          emittedSets.set(setName, { setType: 'ipv6_addr', isV6: true });
        } else if (v4Entries.length > 0) {
          emitSetBlock(setName, 'ipv4_addr', v4Entries);
          emittedSets.set(setName, { setType: 'ipv4_addr', isV6: false });
        }
      }
    }
    lines.push('');
  }

  // 3. Flowtable for hardware/software fastpath offloading
  const enabledDevices = state.interfaces
    .filter((i) => i.enabled && isValidDevice(i.device))
    .map((i) => `"${i.device}"`);

  if (state.system.flowtableOffload && enabledDevices.length > 0) {
    lines.push('  # Flowtable Fastpath');
    lines.push('  flowtable ft_fastpath {');
    lines.push('    hook ingress priority filter;');
    lines.push(`    devices = { ${enabledDevices.join(', ')} };`);
    lines.push('  }');
    lines.push('');
  }

  // Optional UPnP isolated anchor chains (miniupnpd writes only to these subchains)
  if (state.upnp?.enabled) {
    lines.push('  chain upnp_prerouting {}');
    lines.push('  chain upnp_forward {}');
    lines.push('  chain upnp_postrouting {}');
    lines.push('');
  }

  // Helper to resolve WAN IPv4 and LAN interfaces/CIDRs for Hairpin NAT & BINAT
  const resolveWanIpv4 = (preferredIfaceName?: string): string => {
    const candidate =
      (preferredIfaceName
        ? state.interfaces.find((i) => i.enabled && i.name === preferredIfaceName && i.ipv4Address)
        : undefined) ||
      state.interfaces.find((i) => i.enabled && inferInterfaceRole(i) === 'wan' && i.ipv4Address) ||
      state.interfaces.find((i) => inferInterfaceRole(i) === 'wan' && i.ipv4Address);
    const ip = candidate?.ipv4Address?.split('/')[0]?.trim() || '';
    return isValidIPv4(ip) ? ip : '';
  };
  const lanInterfaces = state.interfaces.filter(
    (i) => i.enabled && inferInterfaceRole(i) !== 'wan' && isValidDevice(i.device),
  );
  const lanDevicesSet = lanInterfaces.map((i) => `"${i.device}"`);

  // 4. Chains definition
  const sortedNat = [...state.nat].sort((a, b) => (a.sortOrder ?? 0) - (b.sortOrder ?? 0));
  const hairpinPostroutingLines: string[] = [];

  // Prerouting (DNAT, 1:1 BINAT, NPTv6, Hairpin NAT Reflection)
  lines.push('  chain prerouting {');
  lines.push('    type nat hook prerouting priority dstnat - 10; policy accept;');

  const tlsDecryption = state.tlsDecryption?.enabled ? state.tlsDecryption : state.suricata?.tlsDecryption;
  if (tlsDecryption?.enabled) {
    const tlsConfig = tlsDecryption;
    lines.push(`    # TLS Decryption Interception`);
    for (const iface of state.interfaces) {
      if (iface.enabled && inferInterfaceRole(iface) !== 'wan' && isValidDevice(iface.device)) {
        const dev = iface.device;
        lines.push(`    iifname "${dev}" tcp dport 443 redirect to :${tlsConfig.transparentProxyPort} comment "tls-decryption-intercept"`);
      }
    }
  }

  for (const nat of sortedNat) {
    if (!nat.enabled || !nat.targetIp) continue;
    if (/[;\r\n#{}'"]/.test(nat.targetIp)) continue;
    const ifaceDev = ifDeviceMap.get(nat.interface) || nat.interface;
    if (!isValidDevice(ifaceDev)) continue;

    if (nat.type === 'nptv6') {
      const srcHasV6 = Boolean(nat.source && nat.source !== 'any' && nat.source.includes(':'));
      const dstHasV6 = Boolean(nat.destination && nat.destination !== 'any' && nat.destination.includes(':'));
      const intPrefix = srcHasV6 ? nat.source.trim() : nat.targetIp.trim();
      const extPrefix = srcHasV6 ? nat.targetIp.trim() : dstHasV6 ? nat.destination.trim() : '';
      if (
        intPrefix &&
        extPrefix &&
        isValidCIDR(intPrefix) &&
        isValidCIDR(extPrefix) &&
        !/[;\r\n#{}'"]/.test(intPrefix) &&
        !/[;\r\n#{}'"]/.test(extPrefix)
      ) {
        lines.push(`    iifname "${ifaceDev}" ip6 daddr ${extPrefix} dnat ip6 prefix to ${intPrefix} comment "nptv6-inbound"`);
      }
      continue;
    }

    if (nat.type === 'binat') {
      const extIp =
        nat.destination === 'wan_ip'
          ? resolveWanIpv4(nat.interface)
          : (nat.destination || '').trim();
      const intIp = nat.targetIp.trim();
      if (!extIp || extIp === 'any' || /[;\r\n#{}'"]/.test(extIp)) continue;
      const isV6 = intIp.includes(':') || extIp.includes(':');
      if (isV6 ? !(isValidIPv6(extIp) && isValidIPv6(intIp)) : !(isValidIPv4(extIp) && isValidIPv4(intIp))) continue;
      const family = isV6 ? 'ip6' : 'ip';
      lines.push(`    iifname "${ifaceDev}" ${family} daddr ${extIp} dnat ${family} to ${intIp} comment "binat-inbound"`);
      continue;
    }

    if (nat.type !== 'dnat') continue;
    if (nat.sourcePort?.startsWith('$') && !emittedSets.has(`set_${sanitizeIdentifier(nat.sourcePort.slice(1))}`)) continue;
    if (nat.destinationPort?.startsWith('$') && !emittedSets.has(`set_${sanitizeIdentifier(nat.destinationPort.slice(1))}`)) continue;

    const addrClauses: string[] = [];
    if (nat.source && nat.source !== 'any') {
      const srcClause = resolveEndpointClause(nat.source, 'saddr', state.interfaces, state.aliases, emittedSets);
      if (srcClause === null) continue;
      if (srcClause) addrClauses.push(srcClause);
    }
    if (nat.destination && nat.destination !== 'any' && nat.destination !== 'wan_ip') {
      const dstClause = resolveEndpointClause(nat.destination, 'daddr', state.interfaces, state.aliases, emittedSets);
      if (dstClause === null) continue;
      if (dstClause) addrClauses.push(dstClause);
    }

    const hasDport = Boolean(nat.destinationPort && nat.destinationPort !== 'any');
    const hasSport = Boolean(nat.sourcePort && nat.sourcePort !== 'any');
    let protoMatch = '';
    if (nat.protocol === 'any' || nat.protocol === 'tcp_udp') {
      const portClauses: string[] = [];
      if (hasSport) portClauses.push(`th sport ${formatPort(nat.sourcePort)}`);
      if (hasDport) portClauses.push(`th dport ${formatPort(nat.destinationPort)}`);
      protoMatch = portClauses.length > 0
        ? `meta l4proto { tcp, udp } ${portClauses.join(' ')}`
        : 'meta l4proto { tcp, udp }';
    } else if (nat.protocol === 'tcp' || nat.protocol === 'udp') {
      const portClauses: string[] = [];
      if (hasSport) portClauses.push(`${nat.protocol} sport ${formatPort(nat.sourcePort)}`);
      if (hasDport) portClauses.push(`${nat.protocol} dport ${formatPort(nat.destinationPort)}`);
      protoMatch = portClauses.length > 0
        ? portClauses.join(' ')
        : `meta l4proto ${nat.protocol}`;
    } else {
      protoMatch = `meta l4proto ${nat.protocol}`;
    }
    const hasTargetPort = Boolean(nat.targetPort && nat.targetPort !== 'any');
    const isV6 = nat.targetIp.includes(':');
    const family = isV6 ? 'ip6' : 'ip';
    const formattedIp = isV6 && hasTargetPort ? `[${nat.targetIp}]` : nat.targetIp;
    const dnatTarget = hasTargetPort ? `${formattedIp}:${nat.targetPort}` : formattedIp;
    const prefixMatch = [`iifname "${ifaceDev}"`, ...addrClauses, protoMatch].filter(Boolean).join(' ');
    lines.push(`    ${prefixMatch} dnat ${family} to ${dnatTarget}`);

    // Hairpin NAT Reflection for internal LAN clients hitting external WAN IP / VIP
    if (nat.natReflection && !isV6 && lanDevicesSet.length > 0 && isValidIPv4(nat.targetIp)) {
      const extIp =
        !nat.destination || nat.destination === 'wan_ip' || nat.destination === 'any'
          ? resolveWanIpv4(nat.interface)
          : isValidIPv4(nat.destination)
            ? nat.destination
            : '';
      if (extIp) {
        const lanIifExpr = lanDevicesSet.length === 1 ? lanDevicesSet[0]! : `{ ${lanDevicesSet.join(', ')} }`;
        lines.push(
          `    iifname ${lanIifExpr} ip daddr ${extIp} ${protoMatch} dnat ip to ${dnatTarget} comment "nat-reflection-dnat"`,
        );
        for (const lanIf of lanInterfaces) {
          if (!lanIf.ipv4Address) continue;
          const lanCidr = ipv4ToNetworkCidr(lanIf.ipv4Address);
          hairpinPostroutingLines.push(
            `    oifname "${lanIf.device}" ip saddr ${lanCidr} ip daddr ${nat.targetIp} masquerade comment "nat-reflection-snat"`,
          );
        }
      }
    }
  }
  if (state.upnp?.enabled) {
    lines.push('    jump upnp_prerouting');
  }
  lines.push('  }');
  lines.push('');

  // Input chain (traffic to the firewall host itself)
  lines.push('  chain input {');
  lines.push('    type filter hook input priority filter; policy drop;');
  lines.push('    ct state established,related accept');
  lines.push('    ct state invalid drop');
  lines.push('    iif "lo" accept');
  lines.push('    icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept');
  lines.push('    icmpv6 type { echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept');

  // Anti-Lockout Rule (Evaluated BEFORE dynamic AI/SOAR blocklists so management access can never be locked out)
  if (state.system.antiLockout?.enabled) {
    const ifaceList = normalizeAntiLockoutInterfaces(state.system.antiLockout);
    const ports = state.system.antiLockout.ports.join(', ');
    for (const ifaceName of ifaceList) {
      if (!isWanInterfaceName(ifaceName)) {
        const dev = ifDeviceMap.get(ifaceName) || ifaceName;
        if (isValidDevice(dev)) {
          lines.push(`    # Anti-Lockout: Allow management access from ${ifaceName}`);
          const comment = ifaceName === 'lan' ? 'anti-lockout' : `anti-lockout-${ifaceName}`;
          lines.push(`    iifname "${dev}" tcp dport { ${ports} } accept comment "${comment}"`);
        }
      } else {
        warnings.push("Anti-Lockout interface was set to 'wan'; suppressed generation on WAN for appliance security.");
      }
    }
  }

  if (state.crowdsec?.enabled) {
    lines.push(`    ${crowdsecCompiled.nftRule} comment "crowdsec-drop"`);
  }
  if (state.geoip?.enabled && geoipCompiled.inputRules.length > 0) {
    for (const rule of geoipCompiled.inputRules) {
      lines.push(`    ${rule}`);
    }
  }
  lines.push('    ip saddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip6 saddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ether saddr @blocked_macs drop comment "ai-micro-segmentation"');

  // NAS & K3s Core Role Listeners (when enabled alongside Firewall)
  lines.push(...buildNasAndK3sInputRules(state, ifDeviceMap, capabilities.nasEnabled, capabilities.k3sEnabled));

  // DHCPv6 server, mDNS reflector, UPnP IGD, IPsec IKEv2, and OpenVPN DCO listeners
  if ((state.dhcp?.dhcp6Enabled || (state.dhcp?.subnets6?.length ?? 0) > 0) && lanDevicesSet.length > 0) {
    const lanExpr = lanDevicesSet.length === 1 ? lanDevicesSet[0]! : `{ ${lanDevicesSet.join(', ')} }`;
    lines.push(`    iifname ${lanExpr} udp dport 547 accept comment "kea-dhcp6-server"`);
  }
  if (state.mdnsReflector?.enabled && lanDevicesSet.length > 0) {
    const lanExpr = lanDevicesSet.length === 1 ? lanDevicesSet[0]! : `{ ${lanDevicesSet.join(', ')} }`;
    lines.push(`    iifname ${lanExpr} udp dport 5353 accept comment "mdns-avahi-reflector"`);
  }
  if (state.upnp?.enabled && lanDevicesSet.length > 0) {
    const lanExpr = lanDevicesSet.length === 1 ? lanDevicesSet[0]! : `{ ${lanDevicesSet.join(', ')} }`;
    lines.push(`    iifname ${lanExpr} udp dport { 1900, 5351 } accept comment "upnp-natpmp-discovery"`);
  }
  if (state.ipsec?.enabled) {
    lines.push('    udp dport { 500, 4500 } accept comment "ipsec-ikev2"');
    lines.push('    meta l4proto esp accept comment "ipsec-esp"');
  }
  if (state.openvpn?.enabled) {
    for (const srv of state.openvpn.servers ?? []) {
      if (!srv.enabled) continue;
      lines.push(`    ${srv.protocol} dport ${srv.port} accept comment "openvpn-${sanitizeIdentifier(srv.name)}"`);
    }
  }

  // WireGuard listener
  if (state.wireguard?.enabled) {
    lines.push(`    udp dport ${state.wireguard.listenPort} accept comment "wireguard-service"`);
  }

  // Rosenpass Post-Quantum Dual-KEM listener
  if (state.rosenpass?.enabled) {
    const rpPort =
      typeof state.rosenpass.listenPort === 'number' &&
      Number.isInteger(state.rosenpass.listenPort) &&
      state.rosenpass.listenPort >= 1 &&
      state.rosenpass.listenPort <= 65535
        ? state.rosenpass.listenPort
        : 9999;
    lines.push(`    udp dport ${rpPort} accept comment "rosenpass-pq-kem"`);
  }

  // Headscale listener (WireGuard hole punching)
  if (state.headscale?.enabled) {
    lines.push(`    udp dport 41641 accept comment "headscale-mesh"`);
  }

  // Interface dispatcher for input
  for (const iface of state.interfaces) {
    if (!iface.enabled || !isValidDevice(iface.device)) continue;
    const dev = iface.device;
    const safeChainName = sanitizeIdentifier(iface.name);
    lines.push(`    iifname "${dev}" jump input_${safeChainName}`);
  }
  if (state.headscale?.enabled) {
    lines.push(`    iifname "tailscale0" jump input_tailscale`);
  }
  lines.push('  }');
  lines.push('');

  // Collect per-VNIC Hypervisor Security Group bindings
  const virtSecGroups = state.virt?.securityGroups ?? [];
  const virtSgNames = new Set(virtSecGroups.map((sg) => sg.name));
  const vnicSgJumps: Array<{ devName: string; sgChain: string }> = [];
  if (virtSecGroups.length > 0 && state.virt) {
    for (const vm of state.virt.vms ?? []) {
      if (!vm.enabled) continue;
      (vm.nics ?? []).forEach((nic, idx) => {
        for (const sgName of nic.securityGroups ?? []) {
          if (virtSgNames.has(sgName)) {
            vnicSgJumps.push({
              devName: `tap${vm.vmid}i${idx}`,
              sgChain: sanitizeIdentifier(sgName),
            });
          }
        }
      });
    }
    for (const ct of state.virt.containers ?? []) {
      if (!ct.enabled) continue;
      (ct.nics ?? []).forEach((nic, idx) => {
        for (const sgName of nic.securityGroups ?? []) {
          if (virtSgNames.has(sgName)) {
            vnicSgJumps.push({
              devName: `veth${ct.ctid}i${idx}`,
              sgChain: sanitizeIdentifier(sgName),
            });
          }
        }
      });
    }
  }

  // Forward chain (routed traffic between interfaces)
  lines.push('  chain forward {');
  lines.push('    type filter hook forward priority filter; policy drop;');
  // Suricata IPS rules
  lines.push(...suricataCompiled.nftRules.map(r => '    ' + r));
  if (state.geoip?.enabled && geoipCompiled.forwardRules.length > 0) {
    for (const rule of geoipCompiled.forwardRules) {
      lines.push(`    ${rule}`);
    }
  }
  lines.push('    ip saddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip daddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip6 saddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ip6 daddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ether saddr @blocked_macs drop comment "ai-micro-segmentation"');

  // Per-VNIC Micro-Segmentation Security Groups (evaluated BEFORE bridge blanket accept!)
  for (const binding of vnicSgJumps) {
    lines.push(`    iifname "${binding.devName}" jump virt_sg_${binding.sgChain}_out`);
    lines.push(`    oifname "${binding.devName}" jump virt_sg_${binding.sgChain}_in`);
  }

  if (state.system.flowtableOffload && enabledDevices.length > 0) {
    lines.push('    meta l4proto { tcp, udp } flow add @ft_fastpath');
  }
  lines.push('    ct state established,related accept');
  lines.push('    ct state invalid drop');
  if (state.upnp?.enabled) {
    lines.push('    jump upnp_forward');
  }
  if (capabilities.k3sEnabled) {
    lines.push('    iifname "cni0" accept comment "k3s-pod-forward"');
    lines.push('    oifname "cni0" accept comment "k3s-pod-forward"');
    lines.push('    iifname "flannel*" accept comment "k3s-flannel-forward"');
    lines.push('    oifname "flannel*" accept comment "k3s-flannel-forward"');
    if (state.k3s?.cniPlugin === 'cilium-ebpf') {
      lines.push('    iifname "cilium*" accept comment "k3s-cilium-forward"');
      lines.push('    oifname "cilium*" accept comment "k3s-cilium-forward"');
      lines.push('    iifname "lxc*" accept comment "k3s-cilium-pod-forward"');
      lines.push('    oifname "lxc*" accept comment "k3s-cilium-pod-forward"');
    }
  }
  if (capabilities.virtEnabled) {
    lines.push('    iifname "vmbr*" accept comment "virt-bridge-forward"');
    lines.push('    oifname "vmbr*" accept comment "virt-bridge-forward"');
  }
  if (state.ipsec?.enabled) {
    lines.push('    iifname "xfrm*" accept comment "ipsec-xfrm-forward"');
    lines.push('    oifname "xfrm*" accept comment "ipsec-xfrm-forward"');
  }
  if (state.openvpn?.enabled) {
    lines.push('    iifname "ovpn*" accept comment "openvpn-dco-forward"');
    lines.push('    oifname "ovpn*" accept comment "openvpn-dco-forward"');
  }

  const isFloating = (ifaceName: string) => ifaceName === 'any' || ifaceName === 'floating';
  const hasOutboundRulesFor = (ifaceName: string) =>
    state.rules.some((r) => r.enabled && r.direction === 'out' && (r.interface === ifaceName || isFloating(r.interface)));

  // Outbound interface dispatcher for transit traffic (evaluated before inbound accept jumps)
  for (const iface of state.interfaces) {
    if (!iface.enabled || !isValidDevice(iface.device)) continue;
    if (hasOutboundRulesFor(iface.name)) {
      const safeChainName = sanitizeIdentifier(iface.name);
      lines.push(`    oifname "${iface.device}" jump forward_out_${safeChainName}`);
    }
  }

  // Inbound interface dispatcher for forward
  for (const iface of state.interfaces) {
    if (!iface.enabled || !isValidDevice(iface.device)) continue;
    const dev = iface.device;
    const safeChainName = sanitizeIdentifier(iface.name);
    lines.push(`    iifname "${dev}" jump forward_${safeChainName}`);
  }
  if (state.headscale?.enabled) {
    lines.push(`    iifname "tailscale0" jump forward_tailscale`);
  }
  lines.push('  }');
  lines.push('');

  // Output chain
  lines.push('  chain output {');
  lines.push('    type filter hook output priority filter; policy accept;');
  for (const iface of state.interfaces) {
    if (!iface.enabled || !isValidDevice(iface.device)) continue;
    if (hasOutboundRulesFor(iface.name)) {
      const safeChainName = sanitizeIdentifier(iface.name);
      lines.push(`    oifname "${iface.device}" jump output_${safeChainName}`);
    }
  }
  lines.push('  }');
  lines.push('');

  // Postrouting chain (SNAT, Masquerade, 1:1 BINAT, NPTv6, Hairpin NAT)
  lines.push('  chain postrouting {');
  lines.push('    type nat hook postrouting priority srcnat; policy accept;');
  for (const hpLine of hairpinPostroutingLines) {
    lines.push(hpLine);
  }
  for (const nat of sortedNat) {
    if (!nat.enabled) continue;
    const ifaceDev = ifDeviceMap.get(nat.interface) || nat.interface;
    if (!isValidDevice(ifaceDev)) continue;

    if (nat.type === 'nptv6' && nat.targetIp) {
      const srcHasV6 = Boolean(nat.source && nat.source !== 'any' && nat.source.includes(':'));
      const dstHasV6 = Boolean(nat.destination && nat.destination !== 'any' && nat.destination.includes(':'));
      const intPrefix = srcHasV6 ? nat.source.trim() : nat.targetIp.trim();
      const extPrefix = srcHasV6 ? nat.targetIp.trim() : dstHasV6 ? nat.destination.trim() : '';
      if (
        intPrefix &&
        extPrefix &&
        isValidCIDR(intPrefix) &&
        isValidCIDR(extPrefix) &&
        !/[;\r\n#{}'"]/.test(intPrefix) &&
        !/[;\r\n#{}'"]/.test(extPrefix)
      ) {
        lines.push(`    oifname "${ifaceDev}" ip6 saddr ${intPrefix} snat ip6 prefix to ${extPrefix} comment "nptv6-outbound"`);
      }
      continue;
    }

    if (nat.type === 'binat' && nat.targetIp) {
      const extIp =
        nat.destination === 'wan_ip'
          ? resolveWanIpv4(nat.interface)
          : (nat.destination || '').trim();
      const intIp = nat.targetIp.trim();
      if (!extIp || extIp === 'any' || /[;\r\n#{}'"]/.test(extIp)) continue;
      const isV6 = intIp.includes(':') || extIp.includes(':');
      if (isV6 ? !(isValidIPv6(extIp) && isValidIPv6(intIp)) : !(isValidIPv4(extIp) && isValidIPv4(intIp))) continue;
      const family = isV6 ? 'ip6' : 'ip';
      lines.push(`    oifname "${ifaceDev}" ${family} saddr ${intIp} snat ${family} to ${extIp} comment "binat-outbound"`);
      continue;
    }

    if (nat.type !== 'masquerade' && !(nat.type === 'snat' && nat.targetIp)) continue;

    const matchClauses: string[] = [`oifname "${ifaceDev}"`];
    if (nat.source && nat.source !== 'any') {
      const srcClause = resolveEndpointClause(nat.source, 'saddr', state.interfaces, state.aliases, emittedSets);
      if (srcClause === null) continue;
      if (srcClause) matchClauses.push(srcClause);
    }
    if (nat.destination && nat.destination !== 'any' && nat.destination !== 'wan_ip') {
      const dstClause = resolveEndpointClause(nat.destination, 'daddr', state.interfaces, state.aliases, emittedSets);
      if (dstClause === null) continue;
      if (dstClause) matchClauses.push(dstClause);
    }

    if (nat.type === 'masquerade') {
      lines.push(`    ${matchClauses.join(' ')} masquerade comment "outbound-nat"`);
    } else if (nat.type === 'snat' && nat.targetIp) {
      let resolvedTarget = nat.targetIp;
      if (resolvedTarget === 'wan_ip') {
        resolvedTarget = resolveWanIpv4(nat.interface);
      }
      if (!resolvedTarget || /[;\r\n#{}'"]/.test(resolvedTarget)) continue;
      const family = resolvedTarget.includes(':') ? 'ip6' : 'ip';
      lines.push(`    ${matchClauses.join(' ')} snat ${family} to ${resolvedTarget} comment "outbound-snat"`);
    }
  }
  if (state.upnp?.enabled) {
    lines.push('    jump upnp_postrouting');
  }
  // Default WAN/Gateway masquerade if no outbound rules configured
  if (!state.nat.some((n) => n.enabled && (n.type === 'masquerade' || n.type === 'snat'))) {
    const gatewayIfaces = new Set((state.gateways || []).filter((g) => g.enabled).map((g) => g.interface));
    for (const iface of state.interfaces) {
      if (iface.enabled && inferInterfaceRole(iface) === 'wan') {
        gatewayIfaces.add(iface.name);
      }
    }
    if (gatewayIfaces.size === 0) {
      gatewayIfaces.add('wan');
    }
    for (const gwIfaceName of gatewayIfaces) {
      const iface = state.interfaces.find((i) => i.name === gwIfaceName);
      if (iface && isValidDevice(iface.device)) {
        lines.push(`    oifname "${iface.device}" masquerade comment "default-gateway-masquerade"`);
      }
    }
  }
  lines.push('  }');
  lines.push('');

  // 5. Per-Interface Input, Forward, and Outbound Chains
  for (const iface of state.interfaces) {
    if (!iface.enabled) continue;
    const isWan = inferInterfaceRole(iface) === 'wan';
    const safeChainName = sanitizeIdentifier(iface.name);

    // For WAN interfaces, local input rules MUST be explicitly assigned to the WAN interface.
    // Floating ('any' / 'floating') rules apply to forwarded transit traffic, but do not open local host input on WAN.
    const inputRules = state.rules
      .filter((r) => r.enabled && (r.interface === iface.name || (!isWan && isFloating(r.interface))))
      .sort((a, b) => a.sortOrder - b.sortOrder);

    // Forward chain evaluates interface-specific and floating transit rules
    const forwardRules = state.rules
      .filter((r) => r.enabled && (r.interface === iface.name || isFloating(r.interface)))
      .sort((a, b) => a.sortOrder - b.sortOrder);

    const outboundRules = forwardRules.filter((r) => r.direction === 'out');

    // Input chain for interface
    lines.push(`  chain input_${safeChainName} {`);
    for (const rule of inputRules) {
      if (rule.direction === 'in') {
        for (const stmt of formatRuleStatements(rule, state.aliases, state.interfaces, emittedSets)) {
          lines.push(`    ${stmt}`);
        }
      }
    }
    lines.push('  }');
    lines.push('');

    // Inbound Forward chain for interface
    lines.push(`  chain forward_${safeChainName} {`);
    for (const rule of forwardRules) {
      if (rule.direction !== 'out') {
        for (const stmt of formatRuleStatements(rule, state.aliases, state.interfaces, emittedSets)) {
          lines.push(`    ${stmt}`);
        }
      }
    }
    lines.push('  }');
    lines.push('');

    // Outbound Forward & Output chains when direction === 'out' rules exist
    if (outboundRules.length > 0) {
      lines.push(`  chain forward_out_${safeChainName} {`);
      for (const rule of outboundRules) {
        for (const stmt of formatRuleStatements(rule, state.aliases, state.interfaces, emittedSets)) {
          lines.push(`    ${stmt}`);
        }
      }
      lines.push('  }');
      lines.push('');

      lines.push(`  chain output_${safeChainName} {`);
      for (const rule of outboundRules) {
        for (const stmt of formatRuleStatements(rule, state.aliases, state.interfaces, emittedSets)) {
          lines.push(`    ${stmt}`);
        }
      }
      lines.push('  }');
      lines.push('');
    }
  }

  // Per-VNIC Hypervisor Security Group subchains
  const formatSgRule = (
    sgRule: {
      direction: 'in' | 'out';
      action: 'accept' | 'drop' | 'reject';
      protocol: 'any' | 'tcp' | 'udp' | 'icmp' | 'ipv6-icmp';
      cidr: string;
      port: string;
      description: string;
    },
    addrDir: 'saddr' | 'daddr',
  ): string => {
    const parts: string[] = [];
    if (sgRule.cidr && sgRule.cidr !== 'any' && !/[;\r\n#{}'"]/.test(sgRule.cidr)) {
      const fam = sgRule.cidr.includes(':') ? 'ip6' : 'ip';
      parts.push(`${fam} ${addrDir} ${sgRule.cidr}`);
    }
    const hasPort = Boolean(sgRule.port && sgRule.port !== 'any' && !/[;\r\n#{}'"]/.test(sgRule.port));
    if (sgRule.protocol === 'tcp' || sgRule.protocol === 'udp') {
      if (hasPort) {
        parts.push(`${sgRule.protocol} dport ${formatPort(sgRule.port)}`);
      } else {
        parts.push(`meta l4proto ${sgRule.protocol}`);
      }
    } else if (sgRule.protocol !== 'any') {
      parts.push(`meta l4proto ${sgRule.protocol}`);
    }
    parts.push(sgRule.action);
    if (sgRule.description) {
      const safeDesc = sgRule.description.replace(/[\r\n]+/g, ' ').replace(/[\\"]/g, "'").trim();
      parts.push(`comment "${safeDesc}"`);
    }
    return parts.join(' ');
  };

  for (const sg of virtSecGroups) {
    const sgChain = sanitizeIdentifier(sg.name);
    lines.push(`  chain virt_sg_${sgChain}_in {`);
    for (const rule of (sg.rules ?? []).filter((r) => r.direction === 'in')) {
      lines.push(`    ${formatSgRule(rule, 'saddr')}`);
    }
    lines.push('  }');
    lines.push('');

    lines.push(`  chain virt_sg_${sgChain}_out {`);
    for (const rule of (sg.rules ?? []).filter((r) => r.direction === 'out')) {
      lines.push(`    ${formatSgRule(rule, 'daddr')}`);
    }
    lines.push('  }');
    lines.push('');
  }

  // Tailscale pseudo-interface chains
  if (state.headscale?.enabled) {
    const tsRules = state.rules
      .filter((r) => r.enabled && (r.interface === 'tailscale' || isFloating(r.interface)))
      .sort((a, b) => a.sortOrder - b.sortOrder);

    lines.push(`  chain input_tailscale {`);
    for (const rule of tsRules) {
      if (rule.direction === 'in') {
        for (const stmt of formatRuleStatements(rule, state.aliases, state.interfaces, emittedSets)) {
          lines.push(`    ${stmt}`);
        }
      }
    }
    lines.push('  }');
    lines.push('');

    lines.push(`  chain forward_tailscale {`);
    for (const rule of tsRules) {
      if (rule.direction !== 'out') {
        for (const stmt of formatRuleStatements(rule, state.aliases, state.interfaces, emittedSets)) {
          lines.push(`    ${stmt}`);
        }
      }
    }
    lines.push('  }');
    lines.push('');
  }

  lines.push('}');
  lines.push('');

  return {
    nftScript: lines.join('\n'),
    files,
    reloadServices,
    warnings,
  };
}

export function compileSatelliteNftables(node: any): CompileResult {
  const lines: string[] = [];
  const warnings: string[] = [];
  const files: { path: string; content: string; fileMode: number }[] = [];
  const reloadServices: string[] = [];

  const isEdgeNgfw = node?.role === 'edge-ngfw';
  const wanDev = isValidDevice(node?.wanInterface || 'eth0') ? (node?.wanInterface || 'eth0') : 'eth0';
  const lanDev = isValidDevice(node?.lanInterface || 'eth1') ? (node?.lanInterface || 'eth1') : 'eth1';
  const fastpathOffload = isEdgeNgfw ? node?.fastpathOffload !== false : Boolean(node?.fastpathOffload);
  const hwOffload = Boolean(node?.hardwareOffload || node?.skuProfile === 'sku-x86-enterprise-10g-25g');

  const disabledV6Set = new Set<string>();
  if (Array.isArray(node?.disabledIpv6Interfaces)) {
    for (const dev of node.disabledIpv6Interfaces) {
      if (typeof dev === 'string' && isValidDevice(dev)) {
        disabledV6Set.add(dev);
      }
    }
  }
  if (node?.ipv6Mode === 'disabled') {
    disabledV6Set.add(wanDev);
    disabledV6Set.add(lanDev);
  }
  const zones: Array<{
    name: string;
    vlanId: number;
    ipv4Cidr: string;
    ipv6Mode?: string;
    isolateClients?: boolean;
    allowInternet?: boolean;
  }> = Array.isArray(node?.zones) ? node.zones : [];
  for (const zone of zones) {
    if (zone && typeof zone.vlanId === 'number' && zone.vlanId >= 1 && zone.vlanId <= 4094) {
      const zDev = `${lanDev}.${zone.vlanId}`;
      if (zone.ipv6Mode === 'disabled' && isValidDevice(zDev)) {
        disabledV6Set.add(zDev);
      }
    }
  }
  const disabledV6Devs = Array.from(disabledV6Set);

  const portForwards: Array<{
    proto: 'tcp' | 'udp';
    wanPort: number;
    targetIp: string;
    targetPort: number;
    comment?: string;
  }> = Array.isArray(node?.portForwards) ? node.portForwards : [];

  const ipv6Allow: Array<{
    proto: 'tcp' | 'udp' | 'ipv6-icmp';
    dstIp6: string;
    dstPort?: number;
    comment?: string;
  }> = Array.isArray(node?.ipv6Allow) ? node.ipv6Allow : [];

  lines.push('#!/usr/sbin/nft -f');
  lines.push(
    isEdgeNgfw
      ? `# Axonwall Auto-Generated Super-Slim Edge NGFW (PID 1 UKI) nftables configuration`
      : '# Axonwall Auto-Generated Satellite nftables configuration',
  );
  lines.push(`# Node: ${node.id} | Role: ${isEdgeNgfw ? 'edge-ngfw' : 'satellite'} | SKU: ${node.skuProfile || 'generic'} | Generated: ${new Date().toISOString()}`);
  lines.push('');
  lines.push('flush ruleset');
  lines.push('table inet axonwall {');
  lines.push('  set blocked_ips {');
  lines.push('    type ipv4_addr;');
  lines.push('    flags interval;');
  lines.push('  }');
  lines.push('  set blocked_ips6 {');
  lines.push('    type ipv6_addr;');
  lines.push('    flags interval;');
  lines.push('  }');
  lines.push('  set blocked_macs {');
  lines.push('    type ether_addr;');
  lines.push('  }');
  lines.push('');

  if (fastpathOffload && wanDev !== lanDev) {
    lines.push('  flowtable fastpath {');
    lines.push('    hook ingress priority 0;');
    lines.push(`    devices = { "${wanDev}", "${lanDev}" };`);
    if (hwOffload) {
      lines.push('    flags offload;');
    }
    lines.push('  }');
    lines.push('');
  }

  if (isEdgeNgfw && portForwards.length > 0) {
    lines.push('  chain prerouting {');
    lines.push('    type nat hook prerouting priority dstnat; policy accept;');
    for (const pf of portForwards) {
      if (!pf || (pf.proto !== 'tcp' && pf.proto !== 'udp')) continue;
      if (!Number.isInteger(pf.wanPort) || pf.wanPort < 1 || pf.wanPort > 65535) continue;
      if (!Number.isInteger(pf.targetPort) || pf.targetPort < 1 || pf.targetPort > 65535) continue;
      if (!pf.targetIp || /[;\r\n#{}'"]/.test(pf.targetIp)) continue;
      const safeComment = pf.comment
        ? pf.comment.replace(/[\r\n]+/g, ' ').replace(/[\\"]/g, "'").trim()
        : `port-forward-${pf.wanPort}`;
      lines.push(
        `    iifname "${wanDev}" ${pf.proto} dport ${pf.wanPort} dnat ip to ${pf.targetIp}:${pf.targetPort} comment "${safeComment}"`,
      );
    }
    lines.push('  }');
    lines.push('');
  }

  lines.push('  chain input {');
  lines.push('    type filter hook input priority filter; policy drop;');
  for (const dev of disabledV6Devs) {
    lines.push(`    iifname "${dev}" meta nfproto ipv6 drop comment "ipv6-disabled-on-interface"`);
  }
  lines.push('    ip saddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip6 saddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ether saddr @blocked_macs drop comment "ai-micro-segmentation"');

  lines.push('    ct state established,related accept');
  lines.push('    ct state invalid drop');
  lines.push('    iif "lo" accept');

  if (!isEdgeNgfw) {
    lines.push('    # Allow management protocols');
    lines.push('    tcp dport 22 accept comment "allow-ssh"');
  } else {
    lines.push('    # Zero-Shell Edge NGFW UKI: no SSH daemon; permit RFC 4890 ICMPv6, DHCPv6 client & LAN control-plane');
    lines.push(
      '    icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept comment "rfc4890-icmpv6"',
    );
    lines.push(
      `    iifname "${wanDev}" meta l4proto udp udp sport 547 udp dport 546 accept comment "allow-dhcpv6-client"`,
    );
    lines.push(`    iifname "${lanDev}" accept comment "allow-lan-control-plane"`);
  }

  const wgTunnelIp = node.wireguard?.tunnelIp || node.tunnelIp;
  if (wgTunnelIp) {
    lines.push('    udp dport 51820 accept comment "allow-wireguard"');
    lines.push('    iifname "wg-axon0" accept comment "allow-wg-mesh-traffic"');
  }

  // Headscale listener (WireGuard hole punching)
  lines.push('    udp dport 41641 accept comment "headscale-mesh"');
  lines.push('    iifname "tailscale0" accept comment "allow-tailscale-mesh-traffic"');

  if (isEdgeNgfw) {
    // Must be the LAST input rule: a terminal drop placed earlier would shadow the
    // WireGuard / Headscale accepts above and cut the edge off from the Hub.
    lines.push(`    iifname "${wanDev}" limit rate 10/second log prefix "axonwall-rule:wan-drop: " drop comment "log-and-drop-wan-input"`);
  }

  lines.push('  }');
  lines.push('');

  lines.push('  chain forward {');
  lines.push('    type filter hook forward priority filter; policy drop;');
  for (const dev of disabledV6Devs) {
    lines.push(`    iifname "${dev}" meta nfproto ipv6 drop comment "ipv6-disabled-on-interface"`);
    lines.push(`    oifname "${dev}" meta nfproto ipv6 drop comment "ipv6-disabled-on-interface"`);
  }
  lines.push('    ip saddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip daddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip6 saddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ip6 daddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ether saddr @blocked_macs drop comment "ai-micro-segmentation"');

  if (fastpathOffload && wanDev !== lanDev) {
    // Only offload flows conntrack has already confirmed; offloading on the first
    // packet would bypass the accept/drop decision below.
    lines.push('    meta l4proto { tcp, udp } ct state established flow add @fastpath comment "wire-speed-flowtable-offload"');
  }

  lines.push('    ct state established,related accept');
  lines.push('    ct state invalid drop');
  if (isEdgeNgfw) {
    lines.push(
      '    icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply } accept comment "rfc4890-icmpv6-forward"',
    );
    lines.push(`    iifname "${lanDev}" oifname "${wanDev}" accept comment "allow-lan-to-wan"`);

    for (const zone of zones) {
      if (!zone || typeof zone.vlanId !== 'number' || zone.vlanId < 1 || zone.vlanId > 4094) continue;
      const zDev = `${lanDev}.${zone.vlanId}`;
      if (!isValidDevice(zDev)) continue;
      const zName = sanitizeIdentifier(zone.name || `vlan${zone.vlanId}`);
      const isIsolated =
        Boolean(zone.isolateClients) ||
        zName.toLowerCase() === 'iot' ||
        zName.toLowerCase() === 'guest';
      if (zone.allowInternet !== false) {
        lines.push(`    iifname "${zDev}" oifname "${wanDev}" accept comment "zone-${zName}-to-wan"`);
      }
      if (isIsolated) {
        lines.push(`    iifname "${zDev}" oifname != "${wanDev}" drop comment "zone-${zName}-east-west-drop"`);
      }
    }

    for (const pf of portForwards) {
      if (!pf || (pf.proto !== 'tcp' && pf.proto !== 'udp')) continue;
      if (!Number.isInteger(pf.targetPort) || pf.targetPort < 1 || pf.targetPort > 65535) continue;
      if (!pf.targetIp || /[;\r\n#{}'"]/.test(pf.targetIp)) continue;
      const safeComment = pf.comment
        ? pf.comment.replace(/[\r\n]+/g, ' ').replace(/[\\"]/g, "'").trim()
        : `allow-dnat-${pf.wanPort}`;
      lines.push(
        `    iifname "${wanDev}" ip daddr ${pf.targetIp} ${pf.proto} dport ${pf.targetPort} accept comment "${safeComment}"`,
      );
    }

    for (const rule of ipv6Allow) {
      if (!rule || !rule.dstIp6 || /[;\r\n#{}'"]/.test(rule.dstIp6)) continue;
      const safeComment = rule.comment
        ? rule.comment.replace(/[\r\n]+/g, ' ').replace(/[\\"]/g, "'").trim()
        : 'ipv6-pinhole';
      if (rule.proto === 'ipv6-icmp') {
        lines.push(`    ip6 daddr ${rule.dstIp6} meta l4proto ipv6-icmp accept comment "${safeComment}"`);
      } else if ((rule.proto === 'tcp' || rule.proto === 'udp') && rule.dstPort) {
        lines.push(`    ip6 daddr ${rule.dstIp6} ${rule.proto} dport ${rule.dstPort} accept comment "${safeComment}"`);
      } else if (rule.proto === 'tcp' || rule.proto === 'udp') {
        lines.push(`    ip6 daddr ${rule.dstIp6} meta l4proto ${rule.proto} accept comment "${safeComment}"`);
      }
    }
  }
  lines.push('    iifname "wg-axon0" accept');
  lines.push('    iifname "tailscale0" accept');
  lines.push('  }');
  lines.push('');

  lines.push('  chain output {');
  lines.push('    type filter hook output priority filter; policy accept;');
  for (const dev of disabledV6Devs) {
    lines.push(`    oifname "${dev}" meta nfproto ipv6 drop comment "ipv6-disabled-on-interface"`);
  }
  lines.push('  }');

  if (isEdgeNgfw) {
    lines.push('');
    lines.push('  chain postrouting {');
    lines.push('    type nat hook postrouting priority srcnat; policy accept;');
    lines.push(`    oifname "${wanDev}" masquerade comment "edge-ngfw-wan-masquerade"`);
    lines.push('  }');
  }

  lines.push('}');
  lines.push('');

  return {
    nftScript: lines.join('\n'),
    files,
    reloadServices,
    warnings,
  };
}

function ipv4ToNetworkCidr(addrOrCidr: string): string {
  const parts = addrOrCidr.trim().split('/');
  const ip = parts[0];
  const parsedPrefix = Number.parseInt(parts[1] ?? '', 10);
  const prefix = Number.isNaN(parsedPrefix) ? 24 : Math.max(0, Math.min(32, parsedPrefix));
  if (!isValidIPv4(ip)) return '192.168.1.0/24';
  const octets = ip.split('.').map((o) => Number.parseInt(o, 10));
  const num = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const net = (num & mask) >>> 0;
  const netIp = `${(net >>> 24) & 255}.${(net >>> 16) & 255}.${(net >>> 8) & 255}.${net & 255}`;
  return `${netIp}/${prefix}`;
}

function resolveEndpointClause(
  endpoint: string,
  dir: 'saddr' | 'daddr',
  interfaces: Interface[],
  aliases: Alias[],
  emittedSets?: Map<string, { setType: string; isV6: boolean; hasDualV6?: boolean }>,
  invert = false,
  forceV6Set = false,
): string | null {
  if (!endpoint || endpoint === 'any') return '';
  const op = invert ? '!= ' : '';
  if (endpoint.startsWith('$')) {
    const rawName = endpoint.slice(1);
    const aliasName = sanitizeIdentifier(rawName);
    const baseSetName = `set_${aliasName}`;
    const setName = forceV6Set ? `${baseSetName}_v6` : baseSetName;
    if (emittedSets) {
      const setInfo = emittedSets.get(setName);
      if (!setInfo) return null;
      if (setInfo.setType === 'ether_addr') {
        return `ether ${dir} ${op}@${setName}`;
      }
      return `${setInfo.isV6 ? 'ip6' : 'ip'} ${dir} ${op}@${setName}`;
    }
    const matchedAlias = aliases.find((a) => a.name.toLowerCase() === rawName.toLowerCase());
    if (!matchedAlias || !matchedAlias.enabled || matchedAlias.entries.length === 0) return null;
    if (matchedAlias.type === 'mac') {
      return `ether ${dir} ${op}@${setName}`;
    }
    const isV6 = forceV6Set || matchedAlias.entries.some((e) => e.includes(':'));
    return `${isV6 ? 'ip6' : 'ip'} ${dir} ${op}@${setName}`;
  }

  if (endpoint === 'wan_ip') {
    const wanIface =
      interfaces.find((i) => i.enabled && inferInterfaceRole(i) === 'wan' && i.ipv4Address) ||
      interfaces.find((i) => inferInterfaceRole(i) === 'wan' && i.ipv4Address);
    const wanIp = wanIface?.ipv4Address?.split('/')[0]?.trim();
    if (wanIp && isValidIPv4(wanIp)) {
      return `ip ${dir} ${op}${wanIp}`;
    }
    return `fib ${dir} type ${invert ? '!= ' : ''}local`;
  }

  if (endpoint === 'self') {
    return `fib ${dir} type ${invert ? '!= ' : ''}local`;
  }

  if (endpoint === 'lan_net') {
    const lanIface =
      interfaces.find((i) => i.enabled && i.name === 'lan' && i.ipv4Address) ||
      interfaces.find((i) => i.enabled && inferInterfaceRole(i) === 'lan' && i.ipv4Address) ||
      interfaces.find((i) => inferInterfaceRole(i) === 'lan' && i.ipv4Address);
    const lanCidr = lanIface?.ipv4Address ? ipv4ToNetworkCidr(lanIface.ipv4Address) : '192.168.1.0/24';
    return `ip ${dir} ${op}${lanCidr}`;
  }

  if (endpoint.includes(':')) {
    return `ip6 ${dir} ${op}${endpoint}`;
  }
  return `ip ${dir} ${op}${endpoint}`;
}

function formatPort(val: string): string {
  if (val.startsWith('$')) return `@set_${sanitizeIdentifier(val.slice(1))}`;
  if (val.includes(',') && !val.trim().startsWith('{')) return `{ ${val} }`;
  return val;
}

const SAFE_DSCP_REGEX = /^(?:[0-9]|[1-5][0-9]|6[0-3]|cs[0-7]|ef|af[1-4][1-3]|va|le)$/i;

function formatRuleStatements(
  rule: FirewallRule,
  aliases: Alias[],
  interfaces: Interface[] = [],
  emittedSets?: Map<string, { setType: string; isV6: boolean; hasDualV6?: boolean }>,
): string[] {
  const srcDual =
    Boolean(rule.source?.startsWith('$')) &&
    Boolean(emittedSets?.get(`set_${sanitizeIdentifier(rule.source!.slice(1))}`)?.hasDualV6);
  const dstDual =
    Boolean(rule.destination?.startsWith('$')) &&
    Boolean(emittedSets?.get(`set_${sanitizeIdentifier(rule.destination!.slice(1))}`)?.hasDualV6);

  if (srcDual || dstDual) {
    const v4Stmt = formatSingleRuleStatement(rule, aliases, interfaces, emittedSets, false);
    const v6Stmt = formatSingleRuleStatement(rule, aliases, interfaces, emittedSets, true);
    return [v4Stmt, v6Stmt].filter(Boolean);
  }

  const single = formatSingleRuleStatement(rule, aliases, interfaces, emittedSets, false);
  return single ? [single] : [];
}

function formatSingleRuleStatement(
  rule: FirewallRule,
  aliases: Alias[],
  interfaces: Interface[] = [],
  emittedSets?: Map<string, { setType: string; isV6: boolean; hasDualV6?: boolean }>,
  forceDualV6 = false,
): string {
  const parts: string[] = [];

  if (
    (rule.source && (!isValidFirewallEndpoint(rule.source) || /[;\r\n#{}'"]/.test(rule.source))) ||
    (rule.destination && (!isValidFirewallEndpoint(rule.destination) || /[;\r\n#{}'"]/.test(rule.destination))) ||
    (rule.sourcePort && /[;\r\n#{}'"]/.test(rule.sourcePort)) ||
    (rule.destinationPort && /[;\r\n#{}'"]/.test(rule.destinationPort))
  ) {
    return '';
  }

  // Verify port aliases exist in emittedSets before emitting rule
  if (rule.sourcePort?.startsWith('$')) {
    const setName = `set_${sanitizeIdentifier(rule.sourcePort.slice(1))}`;
    if (emittedSets && !emittedSets.has(setName)) return '';
  }
  if (rule.destinationPort?.startsWith('$')) {
    const setName = `set_${sanitizeIdentifier(rule.destinationPort.slice(1))}`;
    if (emittedSets && !emittedSets.has(setName)) return '';
  }

  // Source Address
  if (rule.source && rule.source !== 'any') {
    const srcUseV6 =
      forceDualV6 &&
      rule.source.startsWith('$') &&
      Boolean(emittedSets?.get(`set_${sanitizeIdentifier(rule.source.slice(1))}`)?.hasDualV6);
    const srcClause = resolveEndpointClause(
      rule.source,
      'saddr',
      interfaces,
      aliases,
      emittedSets,
      Boolean(rule.invertSource),
      srcUseV6,
    );
    if (srcClause === null) return '';
    if (srcClause) parts.push(srcClause);
  }

  // Destination Address
  if (rule.destination && rule.destination !== 'any') {
    const dstUseV6 =
      forceDualV6 &&
      rule.destination.startsWith('$') &&
      Boolean(emittedSets?.get(`set_${sanitizeIdentifier(rule.destination.slice(1))}`)?.hasDualV6);
    const dstClause = resolveEndpointClause(
      rule.destination,
      'daddr',
      interfaces,
      aliases,
      emittedSets,
      Boolean(rule.invertDestination),
      dstUseV6,
    );
    if (dstClause === null) return '';
    if (dstClause) parts.push(dstClause);
  }

  // Reject mixed IPv4 + IPv6 in a single nftables rule statement
  const hasIp4Clause = parts.some((p) => p.startsWith('ip '));
  const hasIp6Clause = parts.some((p) => p.startsWith('ip6 '));
  if (hasIp4Clause && hasIp6Clause) {
    return '';
  }

  // DSCP / DiffServ matching
  if (rule.dscp !== undefined && SAFE_DSCP_REGEX.test(String(rule.dscp).trim())) {
    const dscpToken = String(rule.dscp).trim().toLowerCase();
    const dscpFamily = hasIp6Clause || rule.protocol === 'ipv6-icmp' ? 'ip6' : 'ip';
    parts.push(`${dscpFamily} dscp ${dscpToken}`);
  }

  // Protocol & Ports
  const hasSport = Boolean(rule.sourcePort && rule.sourcePort !== 'any');
  const hasDport = Boolean(rule.destinationPort && rule.destinationPort !== 'any');

  if (rule.protocol === 'tcp' || rule.protocol === 'udp') {
    if (hasSport || hasDport) {
      if (hasSport) parts.push(`${rule.protocol} sport ${formatPort(rule.sourcePort!)}`);
      if (hasDport) parts.push(`${rule.protocol} dport ${formatPort(rule.destinationPort!)}`);
    } else {
      parts.push(`meta l4proto ${rule.protocol}`);
    }
  } else if (rule.protocol === 'tcp_udp') {
    parts.push('meta l4proto { tcp, udp }');
    if (hasSport) parts.push(`th sport ${formatPort(rule.sourcePort!)}`);
    if (hasDport) parts.push(`th dport ${formatPort(rule.destinationPort!)}`);
  } else if (rule.protocol === 'ipv6-icmp') {
    parts.push('meta l4proto ipv6-icmp');
  } else if (rule.protocol !== 'any') {
    parts.push(`meta l4proto ${rule.protocol}`);
  }

  // Per-rule PPS Rate Limiting
  if (rule.rateLimitPps && Number.isInteger(rule.rateLimitPps) && rule.rateLimitPps > 0) {
    if (rule.action === 'pass') {
      parts.push(`limit rate ${rule.rateLimitPps}/second`);
    } else {
      parts.push(`limit rate over ${rule.rateLimitPps}/second`);
    }
  }

  // Logging
  if (rule.log) {
    const safeRuleId = (rule.id || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 8) || 'log';
    parts.push(`log prefix "axonwall-rule:${safeRuleId}: " group 0`);
  }

  // Policy Routing: Mark packets for Linux ip rule / multi-WAN routing tables
  if (rule.action === 'pass') {
    if (rule.gatewayGroup) {
      const markHex = `0x${hashStringToInt(rule.gatewayGroup, 0x1000, 0x7fff).toString(16)}`;
      parts.push(`meta mark set ${markHex}`);
    } else if (rule.gateway) {
      const markHex = `0x${hashStringToInt(rule.gateway, 0x100, 0xfff).toString(16)}`;
      parts.push(`meta mark set ${markHex}`);
    }
  }

  // Action
  const actionMap: Record<string, string> = {
    pass: 'accept',
    block: 'drop',
    reject: 'reject',
  };
  parts.push(actionMap[rule.action] || 'drop');

  // Comment
  if (rule.description) {
    const safeDesc = rule.description.replace(/[\r\n]+/g, ' ').replace(/[\\"]/g, "'").trim();
    parts.push(`comment "${safeDesc}"`);
  }

  return parts.join(' ');
}

function hashStringToInt(str: string, min: number, max: number): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  const span = max - min + 1;
  return min + (Math.abs(hash) % span);
}
