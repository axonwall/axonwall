import { type DesiredState, type FirewallRule, type NatRule, type Alias, normalizeAntiLockoutInterfaces, inferInterfaceRole, isValidFirewallEndpoint } from '../../schemas/index.js';
import { sanitizeIdentifier, isValidDevice } from '../../util/index.js';
import { resolveCapabilities } from '../../plugins/index.js';
import { compileSuricata } from '../suricata/index.js';
import { compileCrowdSec } from '../crowdsec/index.js';
import { compileGeoIp } from '../geoip/index.js';
import { compileNas } from '../nas/index.js';
import { compileK3s } from '../k3s/index.js';
import { compileKeaDhcp4 } from '../kea/index.js';
import { compileFrr } from '../frr/index.js';
import { compileUnbound } from '../unbound/index.js';
import { compileWireGuard } from '../wireguard/index.js';
import { compileRosenpass } from '../rosenpass/index.js';

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
      hostRules.push(`    iifname "${syncDev}" tcp dport ${syncPort} accept comment "ha-state-and-zfs-sync"`);
      hostRules.push(`    iifname "${syncDev}" tcp dport 636 accept comment "ha-openldap-ldaps-syncrepl"`);
      hostRules.push(`    iifname "${syncDev}" udp dport 123 accept comment "ha-chrony-ntp-sync"`);
    }
  }

  if (firewallEnabled && trustedDevs.length === 0) {
    return [];
  }
  const devSet = trustedDevs.length > 0 ? `iifname { ${trustedDevs.join(', ')} } ` : '';

  if (nasEnabled) {
    hostRules.push('    # NAS Plugin (core-nas): SMB, NFSv4, iSCSI, and S3 Service Ports');
    hostRules.push(`    ${devSet}tcp dport { 139, 445 } accept comment "nas-smb"`);
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
  }

  return hostRules;
}

export function compileNftables(state: DesiredState): CompileResult {
  const lines: string[] = [];
  const warnings: string[] = [];
  const files: { path: string; content: string; fileMode: number }[] = [];
  const reloadServices: string[] = [];

  const capabilities = resolveCapabilities(state);

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
          smbConf: nasCompiled.smbConf,
          nfsExports: nasCompiled.nfsExports,
          iscsiConf: nasCompiled.iscsiConf,
        },
        null,
        2,
      ),
      fileMode: 0o600,
    });
  }

  if (state.k3s || capabilities.k3sEnabled) {
    const k3sCompiled = compileK3s(state);
    const effectiveRole = state.ha?.role || state.ha?.nodeRole || 'master';
    const effectivePeer = state.ha?.peerIp || state.ha?.peerAddress || '';
    files.push({
      path: '/etc/axonwall/managed/k3s_config.json',
      content: JSON.stringify(
        {
          enabled: capabilities.k3sEnabled,
          haEnabled: Boolean(state.ha?.enabled),
          haRole: effectiveRole,
          haPeerAddress: effectivePeer,
          haSharedSecret:
            state.ha?.sqliteSync?.authToken ||
            state.ha?.vrrpInstances?.[0]?.authPassword ||
            '',
          autoJoinHaPeer: state.k3s?.autoJoinHaPeer !== false,
          zfsLocalPvPool: state.k3s?.openEbs?.zfsLocalPvPool || 'tank',
          replicatedPool: state.k3s?.openEbs?.replicatedBackingPool || 'tank/openebs-replicated',
          k3sConfigYaml: k3sCompiled.k3sConfigYaml,
          openEbsManifestYaml: k3sCompiled.openEbsManifestYaml,
          workloadsManifestYaml: k3sCompiled.workloadsManifestYaml,
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

  // Emit Vigilante threat defense configuration
  if (state.vigilante) {
    files.push({
      path: '/etc/axonwall/managed/vigilante_config.json',
      content: JSON.stringify(state.vigilante, null, 2),
      fileMode: 0o600,
    });
  }

  // Emit Kea DHCPv4 Server configuration only when core-firewall is enabled
  // (Host-Mode storage/K3s nodes must never run a rogue DHCP server on the attached network)
  if (capabilities.firewallEnabled && state.dhcp) {
    const kea = compileKeaDhcp4(state.dhcp, state.interfaces);
    files.push({
      path: '/etc/kea/kea-dhcp4.conf',
      content: kea.keaDhcp4Config,
      fileMode: 0o644,
    });
    reloadServices.push('kea-dhcp4-server');
  }

  // Emit Unbound DNS Resolver configuration (only when core-firewall is enabled)
  if (capabilities.firewallEnabled && state.dns?.enabled) {
    const unbound = compileUnbound(state.dns, state.headscale);
    files.push({
      path: '/etc/unbound/unbound.conf.d/axonwall.conf',
      content: unbound.unboundConfig,
      fileMode: 0o644,
    });
    reloadServices.push('unbound');
  }

  // Emit FRRouting (FRR) configuration (only when core-firewall is enabled)
  if (capabilities.firewallEnabled && state.frr?.enabled) {
    const frr = compileFrr(state.frr);
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

  // Helper to map interfaces to system devices and roles
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

  if (state.aliases.length > 0) {
    lines.push('  # Aliases & Dynamic Sets');
    for (const alias of state.aliases) {
      if (!alias.enabled || alias.entries.length === 0) continue;
      const setName = `set_${sanitizeIdentifier(alias.name)}`;

      let setType = 'ipv4_addr';
      if (alias.type === 'port') {
        setType = 'inet_service';
      } else if (alias.type === 'mac') {
        setType = 'ether_addr';
      } else if (alias.type === 'network' || alias.type === 'host') {
        setType = alias.entries.some((e) => e.includes(':')) ? 'ipv6_addr' : 'ipv4_addr';
      }

      const elements = alias.entries.join(', ');
      lines.push(`  set ${setName} {`);
      lines.push(`    type ${setType};`);
      if (alias.type === 'network' || alias.type === 'host' || alias.type === 'port') {
        lines.push('    flags interval;');
      }
      lines.push(`    elements = { ${elements} };`);
      lines.push('  }');
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

  // 4. Chains definition

  // Prerouting (DNAT)
  lines.push('  chain prerouting {');
  lines.push('    type nat hook prerouting priority dstnat - 10; policy accept;');
  
  if (state.suricata?.tlsDecryption?.enabled) {
    const tlsConfig = state.suricata.tlsDecryption;
    lines.push(`    # TLS Decryption Interception`);
    for (const iface of state.interfaces) {
      if (iface.enabled && inferInterfaceRole(iface) !== 'wan' && isValidDevice(iface.device)) {
        const dev = iface.device;
        lines.push(`    iifname "${dev}" tcp dport 443 redirect to :${tlsConfig.transparentProxyPort} comment "tls-decryption-intercept"`);
      }
    }
  }

  for (const nat of state.nat) {
    if (!nat.enabled || nat.type !== 'dnat' || !nat.targetIp) continue;
    if (/[;\r\n#{}'"]/.test(nat.targetIp)) continue;
    const ifaceDev = ifDeviceMap.get(nat.interface) || nat.interface;
    if (!isValidDevice(ifaceDev)) continue;
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
    lines.push(`    iifname "${ifaceDev}" ${protoMatch} dnat ${family} to ${dnatTarget}`);
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

  if (state.system.flowtableOffload && enabledDevices.length > 0) {
    lines.push('    meta l4proto { tcp, udp } flow add @ft_fastpath');
  }
  lines.push('    ct state established,related accept');
  lines.push('    ct state invalid drop');

  // Interface dispatcher for forward
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
  lines.push('  }');
  lines.push('');

  // Postrouting chain (SNAT & Masquerade)
  lines.push('  chain postrouting {');
  lines.push('    type nat hook postrouting priority srcnat; policy accept;');
  for (const nat of state.nat) {
    if (!nat.enabled) continue;
    const ifaceDev = ifDeviceMap.get(nat.interface) || nat.interface;
    if (!isValidDevice(ifaceDev)) continue;
    if (nat.type === 'masquerade') {
      lines.push(`    oifname "${ifaceDev}" masquerade comment "outbound-nat"`);
    } else if (nat.type === 'snat' && nat.targetIp) {
      const family = nat.targetIp.includes(':') ? 'ip6' : 'ip';
      lines.push(`    oifname "${ifaceDev}" snat ${family} to ${nat.targetIp} comment "outbound-snat"`);
    }
  }
  // Default WAN/Gateway masquerade if no outbound rules configured
  if (!state.nat.some((n) => n.type === 'masquerade' || n.type === 'snat')) {
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

  const isFloating = (ifaceName: string) => ifaceName === 'any' || ifaceName === 'floating';

  // 5. Per-Interface Input and Forward Chains
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

    // Input chain for interface
    lines.push(`  chain input_${safeChainName} {`);
    for (const rule of inputRules) {
      if (rule.direction === 'in') {
        const stmt = formatRuleStatement(rule, state.aliases);
        if (stmt) lines.push(`    ${stmt}`);
      }
    }
    lines.push('  }');
    lines.push('');

    // Forward chain for interface
    lines.push(`  chain forward_${safeChainName} {`);
    for (const rule of forwardRules) {
      const stmt = formatRuleStatement(rule, state.aliases);
      if (stmt) lines.push(`    ${stmt}`);
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
        const stmt = formatRuleStatement(rule, state.aliases);
        if (stmt) lines.push(`    ${stmt}`);
      }
    }
    lines.push('  }');
    lines.push('');

    lines.push(`  chain forward_tailscale {`);
    for (const rule of tsRules) {
      const stmt = formatRuleStatement(rule, state.aliases);
      if (stmt) lines.push(`    ${stmt}`);
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

function formatPort(val: string): string {
  if (val.startsWith('$')) return `@set_${sanitizeIdentifier(val.slice(1))}`;
  if (val.includes(',') && !val.trim().startsWith('{')) return `{ ${val} }`;
  return val;
}

function formatRuleStatement(rule: FirewallRule, aliases: Alias[]): string {
  const parts: string[] = [];

  if (
    (rule.source && (!isValidFirewallEndpoint(rule.source) || /[;\r\n#{}'"]/.test(rule.source))) ||
    (rule.destination && (!isValidFirewallEndpoint(rule.destination) || /[;\r\n#{}'"]/.test(rule.destination))) ||
    (rule.sourcePort && /[;\r\n#{}'"]/.test(rule.sourcePort)) ||
    (rule.destinationPort && /[;\r\n#{}'"]/.test(rule.destinationPort))
  ) {
    return '';
  }

  // Source Address
  if (rule.source && rule.source !== 'any') {
    if (rule.source.startsWith('$')) {
      const rawName = rule.source.slice(1);
      const aliasName = sanitizeIdentifier(rawName);
      const matchedAlias = aliases.find((a) => a.name.toLowerCase() === rawName.toLowerCase());
      const isV6 = matchedAlias?.entries.some((e) => e.includes(':'));
      parts.push(`${isV6 ? 'ip6' : 'ip'} saddr @set_${aliasName}`);
    } else if (rule.source.includes(':')) {
      parts.push(`ip6 saddr ${rule.source}`);
    } else {
      parts.push(`ip saddr ${rule.source}`);
    }
  }

  // Destination Address
  if (rule.destination && rule.destination !== 'any') {
    if (rule.destination.startsWith('$')) {
      const rawName = rule.destination.slice(1);
      const aliasName = sanitizeIdentifier(rawName);
      const matchedAlias = aliases.find((a) => a.name.toLowerCase() === rawName.toLowerCase());
      const isV6 = matchedAlias?.entries.some((e) => e.includes(':'));
      parts.push(`${isV6 ? 'ip6' : 'ip'} daddr @set_${aliasName}`);
    } else if (rule.destination.includes(':')) {
      parts.push(`ip6 daddr ${rule.destination}`);
    } else {
      parts.push(`ip daddr ${rule.destination}`);
    }
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
