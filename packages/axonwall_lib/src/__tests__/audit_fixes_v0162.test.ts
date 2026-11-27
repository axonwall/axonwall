import { describe, expect, it, vi } from 'vitest';
import {
  DesiredStateSchema,
  InterfaceSchema,
  K3sBpfTokenProfileSchema,
  LibreNmsConfigSchema,
  McpServerConfigSchema,
  NatRuleSchema,
  BUILTIN_PLUGINS,
  compileAcme,
  compileBpfLsmGuardC,
  compileCaptivePortal,
  compileConntrackd,
  compileGeoIp,
  compileKeepalived,
  compileKeaDhcp4,
  compileLibreNmsBundle,
  compileLibvirtDomainXml,
  compileLldpdConfig,
  compileNftables,
  compileOpenVpn,
  compileSnmpd,
  compileSuricata,
  compileTrafficShaper,
  disablePluginWithDependents,
  enablePluginWithDependencies,
  isIpInCidr,
  isPluginAllowed,
  isPluginEnabled,
  lintRuleset,
  prepareDesiredStateForCloudInit,
  REDACTED_KEY32_PLACEHOLDER,
  REDACTED_SECRET_PLACEHOLDER,
  resolveCapabilities,
  simulatePacket,
  validateMcpTarget,
  type HighAvailabilityConfig,
  type McpGuardContext,
} from '../index.js';
import { analyzeRuleShadowing } from '../import/analyzer.js';
import { mergeFirewallConfigs } from '../import/merge.js';
import { importMikrotikConfig } from '../import/mikrotik/index.js';
import { importOpnsenseConfig } from '../import/opnsense/index.js';
import { importPfsenseConfig } from '../import/pfsense/index.js';
import { importVyosConfig } from '../import/vyos/index.js';

describe('Axonwall v0.16.2 verified bug fixes', () => {
  it('splits rate-limited NFLog rules from verdicts and gates group on observability offload', () => {
    const baseState = DesiredStateSchema.parse({
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'dhcp', role: 'wan', enabled: true },
        { name: 'lan', device: 'eth1', type: 'static', role: 'lan', enabled: true, ipv4Address: '10.10.0.1/24' },
      ],
      rules: [
        {
          id: '11111111-1111-4111-8111-111111111111',
          interface: 'wan',
          direction: 'in',
          action: 'block',
          protocol: 'tcp',
          destinationPort: '22',
          rateLimitPps: 10,
          log: true,
          enabled: true,
          sortOrder: 10,
          description: 'Block SSH flood',
        },
      ],
    });

    const withoutOffload = compileNftables(baseState);
    expect(withoutOffload.nftScript).toContain('tcp dport 22 limit rate 50/second log prefix "axonwall-rule:11111111: "');
    expect(withoutOffload.nftScript).not.toContain('log prefix "axonwall-rule:11111111: " group');
    expect(withoutOffload.nftScript).toContain('tcp dport 22 limit rate over 10/second drop comment "Block SSH flood"');
    expect(withoutOffload.nftScript).not.toContain('limit rate 50/second log prefix "axonwall-rule:11111111: " limit rate over');

    const withOffload = compileNftables(
      DesiredStateSchema.parse({
        ...baseState,
        observability: {
          offload: {
            enabled: true,
            logs: { enabled: true, nflog: { enabled: true, group: 3, rateLimitPerSec: 25 } },
          },
        },
      }),
    );
    expect(withOffload.nftScript).toContain('tcp dport 22 limit rate 25/second log prefix "axonwall-rule:11111111: " group 3');
    expect(withOffload.nftScript).toContain('tcp dport 22 limit rate over 10/second drop comment "Block SSH flood"');
  });

  it('places Suricata IPS in post-filter forward_suricata base chain and avoids policy-route mark bit0 collision', () => {
    const suri = compileSuricata({
      enabled: true,
      mode: 'ips',
      interfaces: ['wan'],
      nfqueueBypass: true,
      nfqueueFailOpen: true,
      homeNet: ['10.20.0.0/24'],
      rulesets: ['et-open'],
      customRules: '',
    });
    expect(suri.suricataYaml).toContain('mode: repeat');
    expect(suri.nftRules[0]).toContain('meta mark & 0x1 == 0 iifname "wan" queue num 0-3 bypass');

    const state = DesiredStateSchema.parse({
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'dhcp', role: 'wan', enabled: true },
        { name: 'lan', device: 'eth1', type: 'static', role: 'lan', enabled: true, ipv4Address: '10.20.0.1/24' },
      ],
      suricata: { enabled: true, mode: 'ips', interfaces: ['wan'], nfqueueBypass: true },
      plugins: [{ id: 'suricata-ids', enabled: true }],
      rules: [
        {
          id: '22222222-2222-4222-8222-222222222222',
          interface: 'lan',
          direction: 'in',
          action: 'pass',
          protocol: 'tcp',
          destinationPort: '443',
          gatewayGroup: 'wan_balance',
          enabled: true,
          sortOrder: 10,
        },
        {
          id: '33333333-3333-4333-8333-333333333333',
          interface: 'wan',
          direction: 'out',
          action: 'pass',
          protocol: 'any',
          enabled: true,
          sortOrder: 20,
        },
      ],
    });

    const nft = compileNftables(state);
    const forwardChainBody = nft.nftScript.split('  chain forward {')[1]!.split('  }')[0]!;
    expect(forwardChainBody).not.toContain('queue num');
    expect(forwardChainBody).not.toContain('jump forward_out_wan');
    expect(nft.nftScript).toContain('chain forward_egress {\n    type filter hook forward priority filter + 5; policy accept;');
    expect(nft.nftScript).toContain('oifname "eth0" jump forward_out_wan');
    expect(nft.nftScript).toContain('chain forward_suricata {\n    type filter hook forward priority filter + 10; policy accept;');

    const markMatch = nft.nftScript.match(/meta mark set (0x[0-9a-f]+)/i);
    expect(markMatch).not.toBeNull();
    expect(Number.parseInt(markMatch![1]!, 16) & 0x1).toBe(0);
  });

  it('enforces per-VNIC security groups with custom nic.vnet, explicit drop, and bridge table axonwall_virt', () => {
    const state = DesiredStateSchema.parse({
      capabilities: { firewallEnabled: true, virtEnabled: true },
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'dhcp', role: 'wan', enabled: true },
        { name: 'lan', device: 'eth1', type: 'static', role: 'lan', enabled: true, ipv4Address: '10.30.0.1/24' },
      ],
      aliases: [{ name: 'web_ports', type: 'port', entries: ['80', '443'], enabled: true }],
      virt: {
        enabled: true,
        securityGroups: [
          {
            name: 'app_sg',
            rules: [
              { direction: 'in', protocol: 'tcp', port: '$web_ports', cidr: '10.30.0.0/24', action: 'accept', description: 'Allow web' },
            ],
          },
        ],
        vms: [
          {
            vmid: 105,
            name: 'app-vm',
            nics: [{ bridge: 'vmbr0', vnet: 'tap-custom0', model: 'virtio', securityGroups: ['app_sg', 'app_sg'] }],
            disks: [{ name: 'disk0', pool: 'tank', sizeGb: 20, bus: 'nvme' }],
            enabled: true,
          },
        ],
        containers: [
          {
            ctid: 205,
            hostname: 'app-ct',
            nics: [{ bridge: 'vmbr0', vnet: 'eth0', model: 'virtio', securityGroups: ['app_sg'] }],
            enabled: true,
          },
        ],
      },
    });

    const nft = compileNftables(state);
    expect(nft.nftScript).toContain('iifname "tap-custom0" jump virt_sg_app_sg_out');
    expect(nft.nftScript).toContain('oifname "tap-custom0" jump virt_sg_app_sg_in');
    // Proxmox-imported guest 'eth0' on LXC falls back to host veth205i0
    expect(nft.nftScript).toContain('iifname "veth205i0" jump virt_sg_app_sg_out');
    expect(nft.nftScript).not.toContain('iifname "eth0" jump virt_sg_app_sg_out');
    // Terminates with explicit drop
    expect(nft.nftScript).toContain('drop comment "virt-sg-default-drop"');
    // Dedicated L2 bridge table with port alias set & ARP allow
    expect(nft.nftScript).toContain('table bridge axonwall_virt {');
    expect(nft.nftScript).toContain('ether type arp accept');
    expect(nft.nftScript).toContain('set set_web_ports {');
  });

  it('handles Headscale WAN invite non-http collision, healthCheckPath, port-knocking, wg0/tailscale, GeoIP, and NAT parity', () => {
    const nonHttpCollide = DesiredStateSchema.parse({
      interfaces: [{ name: 'wan', device: 'eth0', type: 'dhcp', role: 'wan', enabled: true }],
      haproxy: { enabled: true, mode: 'tcp' },
      headscale: {
        enabled: true,
        wanInvite: { enabled: true, hostname: 'join.example.com', bindPort: 8443 },
      },
    });
    const collidedCompiled = compileNftables(nonHttpCollide);
    expect(collidedCompiled.nftScript).not.toContain('chain headscale_wan_invite');
    const wanCfgFile = collidedCompiled.files.find((f) => f.path === '/etc/axonwall/managed/headscale_wan_config.json');
    expect(JSON.parse(wanCfgFile!.content).enabled).toBe(false);

    const wgAndGeoState = DesiredStateSchema.parse({
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'dhcp', role: 'wan', enabled: true, ipv4Address: '198.51.100.1/24' },
        { name: 'lan', device: 'eth1', type: 'static', role: 'lan', enabled: true, ipv4Address: '192.168.10.1/24' },
      ],
      aliases: [
        { name: 'bad_macs', type: 'mac', entries: ['AA-BB-CC-DD-EE-FF', 'aa:bb:cc:dd:ee:ff'], enabled: true },
      ],
      wireguard: { enabled: true, listenPort: 51820, address: '10.8.0.1/24', peers: [] },
      headscale: {
        enabled: true,
        wanInvite: {
          enabled: true,
          hostname: 'join.example.com',
          bindPort: 9443,
          exposeHeadscaleControl: true,
          portKnocking: { enabled: true, protocol: 'udp', sequence: [40001, 40002], stepTimeoutSec: 10, openDurationSec: 60 },
        },
      },
      geoip: { enabled: true, mode: 'allow', direction: 'in', countries: ['US'] },
      ipsec: { enabled: true, tunnels: [] },
      openvpn: {
        enabled: true,
        servers: [
          {
            name: 'corp_vpn',
            enabled: true,
            port: 1194,
            protocol: 'udp',
            tunnelNetwork: '10.9.0.0/24',
            cso: [{ commonName: 'alice', assignedIp: '10.9.0.10', pushRoutes: [], description: '' }],
          },
        ],
      },
      plugins: [
        { id: 'ipsec-strongswan', enabled: false },
        { id: 'openvpn', enabled: true },
      ],
      rules: [
        {
          id: '44444444-4444-4444-8444-444444444444',
          interface: 'wg0',
          direction: 'out',
          action: 'block',
          protocol: 'tcp',
          destinationPort: '25',
          enabled: true,
          sortOrder: 10,
        },
      ],
      nat: [
        {
          type: 'dnat',
          interface: 'wan',
          protocol: 'tcp',
          source: '2001:db8::1',
          destinationPort: '80',
          targetIp: '192.168.10.50', // IPv6 source + IPv4 targetIp must be skipped
          targetPort: '80',
          enabled: true,
          sortOrder: 1,
        },
        {
          type: 'snat',
          interface: 'wan',
          protocol: 'any',
          source: '192.168.10.0/24',
          targetIp: '2001:db8::2', // IPv4 source + IPv6 targetIp must be skipped
          enabled: true,
          sortOrder: 2,
        },
      ],
    });

    const wgCompiled = compileNftables(wgAndGeoState);
    // wg0 outbound-only rule does NOT lock out wg0 tunnel input or emit input_wireguard
    expect(wgCompiled.nftScript).toContain('iifname "wg0" accept comment "wireguard-tunnel-input"');
    expect(wgCompiled.nftScript).not.toContain('jump input_wireguard');
    expect(wgCompiled.nftScript).toContain('oifname "wg0" jump forward_out_wireguard');
    expect(wgCompiled.nftScript).toContain('chain output_wireguard');
    // tailscale0 default parity when no explicit rules exist
    expect(wgCompiled.nftScript).toContain('iifname "tailscale0" accept comment "tailscale-mesh-input"');
    expect(wgCompiled.nftScript).toContain('iifname "tailscale0" accept comment "tailscale-forward"');
    // Disabled ipsec plugin does not emit IKEv2/xfrm rules; enabled openvpn emits ovpn* & CCD files
    expect(wgCompiled.nftScript).not.toContain('ipsec-ikev2');
    expect(wgCompiled.nftScript).not.toContain('ipsec-xfrm-forward');
    expect(wgCompiled.nftScript).toContain('openvpn-dco-forward');
    const aliceCcd = wgCompiled.files.find((f) => f.path === '/etc/openvpn/ccd/corp_vpn/alice');
    expect(aliceCcd).toBeDefined();
    expect(aliceCcd!.content).toContain('ifconfig-push 10.9.0.10 255.255.255.0');
    // OpenVPN config points client-config-dir under /etc/openvpn/ccd/
    const ovpnCompiled = compileOpenVpn(wgAndGeoState.openvpn!);
    expect(ovpnCompiled.servers[0]!.serverConf).toContain('client-config-dir /etc/openvpn/ccd/corp_vpn');
    // GeoIP forwardRules placed AFTER ct state established,related accept
    const fwdBody = wgCompiled.nftScript.split('  chain forward {')[1]!.split('  }')[0]!;
    expect(fwdBody.indexOf('geoip-inbound-whitelist-drop')).toBeGreaterThan(fwdBody.indexOf('ct state invalid drop'));
    // GeoIP excludedSubnets includes 100.64.0.0/10 and 127.0.0.0/8
    const geo = compileGeoIp({ enabled: true, mode: 'allow', direction: 'in', countries: ['US'], excludedSubnets: [], log: true, description: '' });
    expect(geo.nftSetDefinitions.join('\n')).toContain('100.64.0.0/10');
    expect(geo.nftSetDefinitions.join('\n')).toContain('127.0.0.0/8');
    // MAC normalized & deduplicated
    expect(wgCompiled.nftScript).toContain('elements = { aa:bb:cc:dd:ee:ff };');
    // Mismatched IPv4/IPv6 NAT rules rejected
    expect(wgCompiled.nftScript).not.toContain('dnat ip to 192.168.10.50');
    expect(wgCompiled.nftScript).not.toContain('snat ip6 to 2001:db8::2');
    // Knock uses meter + separate unconditional drop
    expect(wgCompiled.nftScript).toContain('meter headscale_knock_rl_');
    expect(wgCompiled.nftScript).toContain('udp dport 40001 drop comment "headscale-knock-s1-drop"');
    expect(wgCompiled.nftScript).toContain('udp dport 40002 drop comment "headscale-knock-unlock-drop"');
    // HAProxy backend healthcheck /health
    const hapCfg = wgCompiled.files.find((f) => f.path === '/etc/haproxy/haproxy.cfg')!.content;
    expect(hapCfg).toContain('option httpchk GET /health');
  });

  it('fixes standalone compilers, schemas, Kea MACs, and cloud-init secret redaction', async () => {
    // 1. NatRuleSchema rejects comma in targetPort
    expect(() =>
      NatRuleSchema.parse({ type: 'dnat', interface: 'wan', targetIp: '10.0.0.1', targetPort: '80,443' }),
    ).toThrow();
    expect(() => InterfaceSchema.parse({ name: 'lan', device: 'verylonginterfacename', type: 'static' })).toThrow();
    expect(McpServerConfigSchema.parse({}).enabled).toBe(false);
    expect(() => LibreNmsConfigSchema.parse({ externalUrl: 'javascript:alert(1)' })).toThrow();
    expect(() =>
      K3sBpfTokenProfileSchema.parse({
        id: 'unsafe',
        preset: 'custom',
        allowCmds: ['map_create'],
        allowProgs: ['xdp'],
      }),
    ).toThrow();
    expect(() =>
      K3sBpfTokenProfileSchema.parse({
        id: 'unsafe-ring0',
        preset: 'custom',
        delegateCmds: 'prog_load:map_create',
        delegateProgs: 'xdp:kprobe',
        delegateMaps: 'hash',
        delegateAttachs: 'xdp',
      }),
    ).toThrow();
    expect(() =>
      K3sBpfTokenProfileSchema.parse({
        id: 'unsafe-wildcard',
        preset: 'network-dataplane',
        delegateCmds: 'any',
      }),
    ).toThrow();
    expect(
      K3sBpfTokenProfileSchema.parse({
        id: 'safe-xdp',
        preset: 'custom',
        delegateCmds: 'prog_load:map_create',
        delegateProgs: 'xdp',
        delegateMaps: 'hash',
        delegateAttachs: 'xdp',
      }).delegateProgs,
    ).toBe('xdp');

    // 2. Kea MAC normalization
    const kea = compileKeaDhcp4(
      {
        enabled: true,
        subnets: [
          {
            interface: 'lan',
            subnet: '192.168.1.0/24',
            poolStart: '192.168.1.10',
            poolEnd: '192.168.1.20',
            routers: ['192.168.1.1'],
            dnsServers: [],
            enabled: true,
            staticMappings: [{ mac: 'AA-BB-CC-11-22-33', ip: '192.168.1.5', hostname: 'box', description: '' }],
          },
        ],
      } as any,
      [{ name: 'lan', device: 'eth1', type: 'static', enabled: true, ipv4Address: '192.168.1.1/24' }] as any,
    );
    expect(JSON.parse(kea.keaDhcp4Config).Dhcp4.subnet4[0].reservations[0]['hw-address']).toBe('aa:bb:cc:11:22:33');

    // 3. Rootkit C token_detail buffer & blocked flag
    const bpfC = compileBpfLsmGuardC({
      hostDefense: { enabled: true, allowDelegatedBpfTokens: true, auditDelegatedBpfTokens: true },
    } as any);
    expect(bpfC).toContain('const char token_detail[SALG_NAME_LEN] = "BPF_TOKEN_DELEGATED";');
    expect(bpfC).toContain('emit_lsm_denial(2, &id, token_detail, 0);');

    // 4. Topology LLDP wan-delegated + sanitization
    expect(() =>
      DesiredStateSchema.parse({
        topology: {
          enabled: true,
          lldp: { enabled: true, excludeWan: true, interfaces: ['eth0', 'eth1', 'eth2\nevil'] },
        },
      }),
    ).toThrow();
    const lldp = compileLldpdConfig({
      interfaces: [
        { name: 'ext', device: 'eth0', type: 'dhcp', role: 'wan-delegated', enabled: true, mtu: 1500, description: '' },
        { name: 'lan', device: 'eth1', type: 'static', role: 'lan', enabled: true, mtu: 1500, description: '' },
        { name: 'bad', device: 'eth2\nevil', type: 'static', role: 'lan', enabled: true, mtu: 1500, description: '' },
      ],
      topology: {
        enabled: true,
        lldp: { enabled: true, excludeWan: true, interfaces: [] },
      } as any,
    });
    expect(lldp.excludedWanInterfaces).toContain('eth0');
    expect(lldp.allowedInterfaces).toEqual(['eth1']);
    expect(lldp.confContent).not.toContain('evil');

    // 5. HA keepalived nopreempt: false vs true + conntrackd FTFW gating
    const haCfg: HighAvailabilityConfig = {
      enabled: true,
      nodeRole: 'master',
      peerAddress: '10.0.0.2',
      peerPort: 2966,
      vrrpInstances: [
        { name: 'VI_1', vrid: 10, interface: 'eth1', priority: 150, nopreempt: false, virtualIps: ['10.0.0.1/24'] },
      ],
      conntrackSync: { enabled: true, interface: 'eth2', protocol: 'unicast', port: 3780, mode: 'NOTRACK' },
      sqliteSync: { enabled: false, mode: 'direct_stream', databases: [], syncIntervalSeconds: 5, listenPort: 9876, transport: 'mtls', requireSignedPayloads: false },
      syncSections: { interfaces: false, firewall: true, dhcp: true, dns: true, aliases: true, vpn: true, sqlite: true },
    };
    const kaMaster = compileKeepalived(haCfg, 'node1');
    expect(kaMaster).toContain('state MASTER');
    expect(kaMaster).not.toContain('nopreempt');
    const ctdNoTrack = compileConntrackd(haCfg, '10.0.0.1');
    expect(ctdNoTrack).toContain('Mode NOTRACK');
    expect(ctdNoTrack).not.toContain('ResendQueueSize');
    expect(ctdNoTrack).not.toContain('ACKWindowSize');

    // 6. SNMP backslash + empty community
    const snmpOut = compileSnmpd({
      enabled: true,
      version: 'v2c',
      community: '   ',
      sysLocation: 'DC1',
      sysContact: 'ops@example.com',
      listenPort: 161,
      bindAddresses: [],
      v3Users: [],
    });
    expect(snmpOut).not.toContain('rocommunity');
    const { compileSnmpdPersistentUsers } = await import('../compile/snmp/index.js');
    const snmpV3Cfg = {
      enabled: true,
      version: 'v3' as const,
      community: '',
      sysLocation: 'DC1',
      sysContact: 'ops@example.com',
      listenPort: 161,
      v3Users: [{ username: 'mon\\user', authProtocol: 'SHA-256' as const, authPassword: 'auth\\pass123', privProtocol: 'AES' as const, privPassword: 'priv\\pass123', securityLevel: 'authPriv' as const }],
    };
    const snmpV3 = compileSnmpd(snmpV3Cfg);
    expect(snmpV3).not.toContain('createUser');
    expect(snmpV3).toContain('rouser monuser priv -V all');
    expect(compileSnmpdPersistentUsers(snmpV3Cfg)).toContain('createUser monuser SHA-256 "authpass123" AES "privpass123"');

    // 7. TC HTB default 1:99 + tc filter
    const tcOut = compileTrafficShaper({
      enabled: true,
      interfaces: [
        {
          interface: 'eth0',
          downloadBandwidthMbps: 0,
          uploadBandwidthMbps: 100,
          scheduler: 'htb',
          cakeDiffserv: 'diffserv4',
          cakeAckFilter: false,
          enabled: true,
          queues: [{ name: 'voice', priority: 1, bandwidthPercent: 20, burst: '15k', codel: true, description: '' }],
        },
      ],
    });
    expect(tcOut.shScript).toContain('classid 1:99 htb');
    expect(tcOut.shScript).toContain('tc filter add dev eth0 parent 1: protocol all prio 1 handle 10 fw flowid 1:10');

    // 8. ACME email + openvpn-server@*.service
    const acmeOut = compileAcme({
      enabled: true,
      accounts: [{ name: 'def', email: 'certs@example.com', caDirectoryUrl: 'https://acme-v02.api.letsencrypt.org/directory', enabled: true }],
      certificates: [{ name: 'gw', domain: 'gw.example.com', altNames: [], challengeType: 'http-01', deployServices: ['openvpn'], autoRenew: true, renewDaysBeforeExpiry: 30, status: 'pending' }],
      internalCAs: [],
    });
    expect(acmeOut.renewScript).toContain("--email 'certs@example.com'");
    expect(acmeOut.hookScripts.openvpn).toBe('systemctl reload-or-restart openvpn-server@*.service || true');
    const acmeNoEmail = compileAcme({
      enabled: true,
      accounts: [],
      certificates: [{ name: 'gw', domain: 'gw.example.com', altNames: [], challengeType: 'http-01', deployServices: ['webgui'], autoRenew: true, renewDaysBeforeExpiry: 30, status: 'pending' }],
      internalCAs: [],
    });
    expect(acmeNoEmail.renewScript).toContain('--register-unsafely-without-email');

    // 9. LibreNMS IPv6 + custom port URL parsing
    const lnms = compileLibreNmsBundle(
      DesiredStateSchema.parse({
        interfaces: [{ name: 'lan', device: 'eth1', role: 'lan', enabled: true, ipv4Address: '10.1.0.1/24' }],
        librenms: { enabled: true, mode: 'k3s', ldapAuth: { enabled: true, url: 'ldaps://[fd00::55]:1636' } },
      }),
    );
    expect(lnms.ldapConfigPhp).toContain("$config['auth_ldap_server'] = 'fd00::55';");
    expect(lnms.ldapConfigPhp).toContain("$config['auth_ldap_port'] = 1636;");

    // 10. Libvirt custom CPU model + nvme->vda target
    const xml = compileLibvirtDomainXml({
      vmid: 110,
      name: 'kvm-node',
      description: '',
      osType: 'linux',
      bios: 'ovmf',
      secureBoot: false,
      tpm2: false,
      sockets: 1,
      cores: 2,
      cpuType: 'x86-64-v2-AES',
      memoryMb: 1024,
      balloonMinMb: 0,
      disks: [{ name: 'd0', pool: 'tank', sizeGb: 10, bus: 'nvme', cache: 'none', discard: true, iopsReadLimit: 0, iopsWriteLimit: 0, readOnly: false, backup: true }],
      nics: [],
      pciPassthrough: [],
      usbPassthrough: [],
      autostart: false,
      haManaged: false,
      agent: false,
      enabled: true,
    });
    expect(xml).toContain("<model fallback='allow'>x86-64-v2-AES</model>");
    expect(xml).toContain("<target dev='vda' bus='virtio'/>");

    // 11. Cloud-init redaction completeness + metadata preservation
    const ciState = DesiredStateSchema.parse({
      wireguard: { enabled: true, privateKey: 'WG_PRIV_KEY_SECRET_32_CHARS_AAAAAA', peers: [] },
      observability: {
        victoriaMetrics: { enabled: true, bearerToken: 'vm-secret-token' },
        victoriaLogs: { enabled: true, bearerToken: 'vl-secret-token' },
        offload: { enabled: true, ingestToken: 'ingest-secret', metrics: { scrapeToken: 'scrape-secret' } },
      },
      snmp: {
        enabled: true,
        version: 'v3',
        v3Users: [{ username: 'u1', authProtocol: 'SHA-256', authPassword: 'auth-secret-pw', privProtocol: 'AES', privPassword: 'priv-secret-pw', securityLevel: 'authPriv' }],
      },
      netflow: {
        enabled: true,
        storage: { clickhouse: { password: 'nf-ch-password' } },
        selfExport: { enabled: true, targets: [], metadataSync: { enabled: true, target: 'netbox', apiUrl: 'https://nb.local', apiToken: 'nf-meta-tok' } },
      },
      netbox: { enabled: true, superuserPassword: 'nb-admin-password', apiToken: 'nb-api-token' },
      librenms: {
        enabled: true,
        adminPassword: 'ln-admin-password',
        apiToken: 'ln-api-token',
        webhookSecret: 'ln-webhook-secret',
        snmpDefaults: { v3AuthPass: 'ln-v3-auth', v3CryptoPass: 'ln-v3-priv', community: 'ln-comm' },
      },
      topology: { enabled: true, peers: [{ id: 'p1', name: 'p1', apiUrl: 'https://p1', apiToken: 'topo-peer-tok' }] },
      threatHarvester: { enabled: true, anonymizationSalt: 'th-salt-secret' },
      ha: { enabled: true, sqliteSync: { litestreamAccessKeyId: 'AKIASECRETID', litestreamSecretAccessKey: 'SECRETS3KEY' } },
      rosenpass: { enabled: true, publicKeyPath: '/etc/rosenpass/pq.pk', secretKeyPath: '/etc/rosenpass/pq.sk' },
    });
    const prepared = prepareDesiredStateForCloudInit(ciState);
    const json = JSON.stringify(prepared);
    for (const leaked of [
      'WG_PRIV_KEY_SECRET_32_CHARS_AAAAAA',
      'vm-secret-token',
      'vl-secret-token',
      'ingest-secret',
      'scrape-secret',
      'auth-secret-pw',
      'priv-secret-pw',
      'nf-ch-password',
      'nf-meta-tok',
      'nb-admin-password',
      'nb-api-token',
      'ln-admin-password',
      'ln-api-token',
      'ln-webhook-secret',
      'ln-v3-auth',
      'ln-v3-priv',
      'ln-comm',
      'topo-peer-tok',
      'th-salt-secret',
      'AKIASECRETID',
      'SECRETS3KEY',
    ]) {
      expect(json).not.toContain(leaked);
    }
    expect(prepared.wireguard?.privateKey).toBe(REDACTED_KEY32_PLACEHOLDER);
    expect(prepared.observability?.victoriaMetrics?.bearerToken).toBe(REDACTED_SECRET_PLACEHOLDER);
    expect(prepared.rosenpass?.publicKeyPath).toBe('/etc/rosenpass/pq.pk');
    expect(prepared.rosenpass?.secretKeyPath).toBe('/etc/rosenpass/pq.sk');
  });

  it('fixes MCP hex IPv4-mapped IPv6, plugin permissions/capabilities, importers, analyzer, captive, lint, and sim', () => {
    // 1. MCP hex IPv4-mapped IPv6
    expect(isIpInCidr('::ffff:7f00:0001', '127.0.0.0/8')).toBe(true);
    const mcpCtx: McpGuardContext = {
      applianceHostIps: [],
      gatewayAndHaIps: [],
      callerIp: '::ffff:c633:6405', // 198.51.100.5
      policyLimits: { allowInternalRFC1918Targets: false, allowPublicInternetBlock: true, maxBlockPrefixV4: 24, maxBlockPrefixV6: 64, protectedBypassAllowed: false },
    };
    expect(validateMcpTarget('198.51.100.5', mcpCtx).valid).toBe(false);

    // 2. Plugins RBAC, capabilities alignment, external LibreNMS, enableUserNamespaces
    const fwPlugin = BUILTIN_PLUGINS.find((p) => p.id === 'firewall') ?? {
      id: 'test-fw',
      name: 'Test',
      version: '1.0.0',
      category: 'extension' as const,
      description: '',
      privileges: ['firewall.rules'],
      dependencies: [],
      systemdUnits: [],
      packages: { debian: [], alpine: [], arch: [] },
      cliBinaries: [],
      supportedRoles: ['firewall'],
      defaultEnabled: false,
      configNamespace: 'rules',
    };
    expect(isPluginAllowed(fwPlugin as any, ['firewall.rules.read'])).toBe(false);
    expect(isPluginAllowed(fwPlugin as any, ['firewall.rules.write'])).toBe(true);
    const monitoringManifest = BUILTIN_PLUGINS.find((p) => p.id === 'netflow-collector')!;
    expect(isPluginAllowed(monitoringManifest, ['diagnostics.read', 'system.status.read'])).toBe(false);
    expect(isPluginAllowed(monitoringManifest, ['system.config.write', 'firewall.rules.write'])).toBe(true);

    const conflictingCapsState = DesiredStateSchema.parse({
      capabilities: { k3sEnabled: true },
      plugins: [{ id: 'core-k3s', enabled: false }],
    });
    expect(resolveCapabilities(conflictingCapsState).k3sEnabled).toBe(isPluginEnabled('core-k3s', conflictingCapsState));

    const k3sEnabled = enablePluginWithDependencies('core-k3s', DesiredStateSchema.parse({}));
    expect(k3sEnabled.state.k3s?.enableUserNamespaces).toBe(true);

    const extLnmsState = DesiredStateSchema.parse({
      capabilities: { k3sEnabled: true },
      k3s: { enabled: true },
      librenms: { enabled: true, mode: 'external', externalUrl: 'https://nms.corp.internal' },
      plugins: [
        { id: 'core-k3s', enabled: true },
        { id: 'librenms', enabled: true },
      ],
    });
    const disabledK3s = disablePluginWithDependents('core-k3s', extLnmsState);
    expect(disabledK3s.autoDisabledDependents).not.toContain('librenms');
    expect(isPluginEnabled('librenms', disabledK3s.state)).toBe(true);

    // 3. Importers + Merge + Analyzer
    const mtReport = importMikrotikConfig(`
/ip firewall filter
add action=fasttrack-connection chain=forward connection-state=established,related
add action=accept chain=forward connection-state=established,related,untracked
add action=log chain=input log-prefix="audit"
add action=accept chain=output out-interface=ether1 protocol=udp dst-port=53 comment="DNS out"
`);
    expect(mtReport.rulesCount).toBe(1);
    expect(mtReport.state.rules[0]!.direction).toBe('out');
    expect(mtReport.state.rules[0]!.interface).toBe('wan');

    const pfXml = `<pfsense><vlans><vlan><if>vtnet1</if><tag>55</tag></vlan></vlans><filter><rule><type>pass</type><interface>lan</interface><log/></rule><rule><type>block</type><interface>wan</interface><log>0</log></rule></filter></pfsense>`;
    const pfReport = importPfsenseConfig(pfXml);
    expect(pfReport.state.vlans[0]!.tag).toBe(55);
    expect(pfReport.state.rules[0]!.log).toBe(true);
    expect(pfReport.state.rules[1]!.log).toBe(false);

    const opnXml = `<opnsense><vlans><vlan><if>vtnet1</if><tag>66</tag></vlan></vlans><filter><rule><type>pass</type><interface>lan</interface><log/></rule></filter></opnsense>`;
    const opnReport = importOpnsenseConfig(opnXml);
    expect(opnReport.vlansCount).toBe(1);
    expect(opnReport.state.vlans[0]!.tag).toBe(66);
    expect(opnReport.state.rules[0]!.log).toBe(true);

    const vyReport = importVyosConfig(`
firewall {
    name WAN_IN {
        rule 10 {
            action accept
            protocol tcp
            source { address !10.0.0.0/8 }
        }
    }
}
`);
    expect(vyReport.state.rules[0]!.invertSource).toBe(true);
    expect(vyReport.state.rules[0]!.source).toBe('10.0.0.0/8');
    expect(vyReport.state.rules[0]!.enabled).toBe(false);
    expect(vyReport.reviewItems?.length).toBe(1);

    const activeMerge = DesiredStateSchema.parse({
      aliases: [
        { name: 'Servers', type: 'host', entries: ['10.0.0.1'], enabled: true },
        { name: 'Servers_imported', type: 'host', entries: ['10.0.0.2'], enabled: true },
      ],
      rules: [{ action: 'pass', direction: 'in', interface: 'lan', sortOrder: 50 }],
    });
    const impMerge = DesiredStateSchema.parse({
      aliases: [{ name: 'Servers', type: 'host', entries: ['10.0.0.3'], enabled: true }],
      rules: [{ action: 'block', direction: 'in', interface: 'wan', destination: '$Servers', sortOrder: 10 }],
    });
    const merged = mergeFirewallConfigs(activeMerge, impMerge, { rulePlacement: 'prepend' });
    expect(merged.aliases.map((a) => a.name)).toContain('Servers_imported_2');
    expect(merged.rules.map((r) => r.sortOrder)).toEqual([10, 20]);

    // Analyzer: sortOrder + directional iface/protocol + quick:false + invertSource
    const analysis = analyzeRuleShadowing([
      { action: 'pass', direction: 'in', interface: 'lan', protocol: 'tcp', source: 'any', sourcePort: '', destination: 'any', destinationPort: '443', enabled: true, quick: true, log: false, description: '', sortOrder: 20 },
      { action: 'block', direction: 'in', interface: 'lan', protocol: 'any', source: 'any', sourcePort: '', destination: 'any', destinationPort: '', enabled: true, quick: true, log: false, description: '', sortOrder: 10 },
      { action: 'block', direction: 'in', interface: 'lan', protocol: 'tcp', source: 'any', sourcePort: '', destination: 'any', destinationPort: '', enabled: true, quick: false, log: false, description: '', sortOrder: 5 },
      { action: 'pass', direction: 'in', interface: 'wan', protocol: 'any', source: '198.51.100.1', invertSource: true, sourcePort: '', destination: 'any', destinationPort: '', enabled: true, quick: true, log: false, description: '', sortOrder: 30 },
      { action: 'block', direction: 'in', interface: 'wan', protocol: 'tcp', source: '198.51.100.1', invertSource: false, sourcePort: '', destination: 'any', destinationPort: '22', enabled: true, quick: true, log: false, description: '', sortOrder: 40 },
    ]);
    // Rule #1 (sortOrder 20) shadowed by Rule #2 (sortOrder 10), NOT by quick:false Rule #3; inverted source Rule #4 does NOT shadow non-disjoint Rule #5
    expect(analysis.issues.some((i) => i.type === 'shadowed' && i.ruleIndex === 1 && i.shadowedByIndex === 2)).toBe(true);
    expect(analysis.issues.some((i) => i.shadowedByIndex === 3)).toBe(false);
    expect(analysis.issues.some((i) => i.ruleIndex === 5)).toBe(false);

    // 4. Captive portal wired into compileNftables + strict IP validation
    const capInvalid = compileCaptivePortal({
      enabled: true,
      zones: [{ name: 'guest', interface: 'eth2', listenPort: 8999, enabled: true, passThroughMacs: ['bad-mac'], passThroughIps: ['999.999.1.1'], sessionTimeoutMinutes: 60, landingRedirectUrl: '', authMode: 'clickthrough' }],
    });
    expect(capInvalid.nftRules.some((r) => r.includes('999.999.1.1'))).toBe(false);
    const capNft = compileNftables(
      DesiredStateSchema.parse({
        interfaces: [
          { name: 'wan', device: 'eth0', type: 'dhcp', role: 'wan', enabled: true },
          { name: 'guest', device: 'eth2', type: 'static', role: 'lan', enabled: true, ipv4Address: '10.99.0.1/24' },
        ],
        captivePortal: {
          enabled: true,
          zones: [{ name: 'guest_zone', interface: 'guest', listenPort: 8999, enabled: true }],
        },
        plugins: [{ id: 'captive-portal', enabled: true }],
      }),
    );
    expect(capNft.nftScript).toContain('iifname "eth2" tcp dport 80 redirect to :8999');
    expect(capNft.nftScript).toContain('iifname "eth2" tcp dport 8999 accept comment "captive-guest_zone-portal"');

    // 5. Lint: wg0/wireguard/tailscale allowed + invertSource catch-all/WAN check
    const lintIssues = lintRuleset(
      DesiredStateSchema.parse({
        interfaces: [
          { name: 'wan', device: 'eth0', type: 'dhcp', role: 'wan', enabled: true },
          { name: 'lan', device: 'eth1', type: 'static', role: 'lan', enabled: true, ipv4Address: '10.0.0.1/24' },
        ],
        rules: [
          { interface: 'wg0', direction: 'in', action: 'pass', enabled: true, sortOrder: 10 },
          { interface: 'wireguard', direction: 'out', action: 'pass', enabled: true, sortOrder: 20 },
          { interface: 'tailscale', direction: 'in', action: 'pass', enabled: true, sortOrder: 30 },
          { interface: 'wan', direction: 'in', action: 'pass', protocol: 'tcp', source: '198.51.100.1', invertSource: true, destinationPort: '443', enabled: true, sortOrder: 40 },
        ],
      }),
    );
    expect(lintIssues.some((i) => i.type === 'missing_interface')).toBe(false);
    expect(lintIssues.some((i) => i.type === 'wan_management_exposed')).toBe(true);

    // 6. Sim: targetPort: 'any' no NaN + invertSource/IPv6 + floating self on WAN
    const simState = DesiredStateSchema.parse({
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'static', role: 'wan', enabled: true, ipv4Address: '203.0.113.1/24' },
        { name: 'lan', device: 'eth1', type: 'static', role: 'lan', enabled: true, ipv4Address: '10.0.0.1/24' },
      ],
      nat: [
        { type: 'dnat', interface: 'wan', protocol: 'tcp', destinationPort: '443', targetIp: '10.0.0.10', targetPort: 'any', enabled: true, sortOrder: 1 },
      ],
      rules: [
        { interface: 'wan', direction: 'in', action: 'pass', protocol: 'tcp', destination: '10.0.0.10', destinationPort: '443', enabled: true, sortOrder: 10 },
        { interface: 'floating', direction: 'in', action: 'pass', protocol: 'tcp', destination: 'self', destinationPort: '22', enabled: true, sortOrder: 20 },
      ],
    });
    const simDnatAny = simulatePacket(
      { inInterface: 'wan', protocol: 'tcp', srcIp: '198.51.100.50', srcPort: 50000, dstIp: '203.0.113.1', dstPort: 443 },
      simState,
    );
    expect(simDnatAny.nat?.translatedPort).toBe(443);
    expect(simDnatAny.verdict).toBe('ALLOW');

    const simWanSelf = simulatePacket(
      { inInterface: 'wan', protocol: 'tcp', srcIp: '198.51.100.50', srcPort: 50001, dstIp: '203.0.113.1', dstPort: 22 },
      simState,
    );
    expect(simWanSelf.verdict).toBe('DROP');
  });
});
