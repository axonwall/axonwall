import { describe, expect, it } from 'vitest';
import { type DesiredState, type PacketTracerQuery, OpenVpnCsoSchema } from '../schemas/index.js';
import { compileNftables } from './nft/index.js';
import { compileTrafficShaper } from './tc/index.js';
import { compileIpsec } from './ipsec/index.js';
import { compileOpenVpn, generateClientOvpnProfile } from './openvpn/index.js';
import { compileWireGuard } from './wireguard/index.js';
import { compileFrr } from './frr/index.js';
import { simulatePacket } from '../sim/index.js';

describe('Phase 2: Linux Traffic Shaper (tc CAKE & HTB)', () => {
  it('compiles CAKE QoS with IFB ingress redirection', () => {
    const res = compileTrafficShaper({
      enabled: true,
      interfaces: [
        {
          id: 'ts-1',
          interface: 'eth0',
          downloadBandwidthMbps: 200,
          uploadBandwidthMbps: 50,
          scheduler: 'cake',
          cakeDiffserv: 'diffserv4',
          cakeAckFilter: true,
          enabled: true,
          queues: [],
        },
      ],
    });

    expect(res.shScript).toContain('tc qdisc add dev eth0 root cake bandwidth 50mbit diffserv4 ack-filter');
    expect(res.shScript).toContain('ip link add name ifb-eth0 type ifb');
    expect(res.shScript).toContain('action mirred egress redirect dev ifb-eth0');
    expect(res.shScript).toContain('tc qdisc add dev ifb-eth0 root cake bandwidth 200mbit diffserv4');
  });

  it('compiles HTB with custom queues and priorities', () => {
    const res = compileTrafficShaper({
      enabled: true,
      interfaces: [
        {
          id: 'ts-2',
          interface: 'eth1',
          downloadBandwidthMbps: 0,
          uploadBandwidthMbps: 100,
          scheduler: 'htb',
          cakeDiffserv: 'diffserv4',
          cakeAckFilter: false,
          enabled: true,
          queues: [
            {
              id: 'q-voip',
              name: 'VoIP',
              priority: 1,
              bandwidthPercent: 10,
              burst: '15k',
              codel: true,
              description: 'VoIP high priority',
            },
            {
              id: 'q-default',
              name: 'Default',
              priority: 3,
              bandwidthPercent: 50,
              burst: '15k',
              codel: true,
              description: 'General traffic',
            },
          ],
        },
      ],
    });

    expect(res.shScript).toContain('tc qdisc add dev eth1 root handle 1: htb default 99');
    expect(res.shScript).toContain('classid 1:1 htb rate 100mbit ceil 100mbit');
    expect(res.shScript).toContain('classid 1:10 htb rate 10mbit ceil 100mbit prio 1');
    expect(res.shScript).toContain('handle 100: fq_codel');
  });
});

describe('Phase 2: strongSwan IPsec Compiler', () => {
  it('compiles route-based XFRM tunnel and pre-shared key', () => {
    const res = compileIpsec({
      enabled: true,
      tunnels: [
        {
          id: 'ipsec-1',
          name: 'HQ_Branch_Tunnel',
          enabled: true,
          routeBased: true,
          xfrmInterfaceId: 42,
          localAddress: '198.51.100.1',
          remoteAddress: '203.0.113.1',
          authMethod: 'psk',
          presharedKey: 'SuperSecretKey123',
          ikeProposals: ['aes256-sha256-modp2048'],
          espProposals: ['aes256gcm16-ecp256'],
          localTs: ['10.0.0.0/16'],
          remoteTs: ['10.1.0.0/16'],
          dpdDelay: 30,
          dpdAction: 'restart',
          description: 'HQ to Branch IPsec VPN',
        },
      ],
    });

    expect(res.swanctlConf).toContain('HQ_Branch_Tunnel {');
    expect(res.swanctlConf).toContain('if_id_in = 42');
    expect(res.swanctlConf).toContain('if_id_out = 42');
    expect(res.swanctlConf).toContain('secret = "SuperSecretKey123"');
    expect(res.xfrmSetupCommands).toContain('ip link add xfrm42 type xfrm if_id 42 2>/dev/null || true');
    expect(res.xfrmSetupCommands).toContain('ip link set dev xfrm42 up');
  });

  it('escapes quotes, backslashes, and newlines in presharedKey', () => {
    const res = compileIpsec({
      enabled: true,
      tunnels: [
        {
          id: 'ipsec-inj',
          name: 'Tunnel_Inj',
          enabled: true,
          routeBased: false,
          xfrmInterfaceId: 1,
          localAddress: '198.51.100.1',
          remoteAddress: '203.0.113.1',
          authMethod: 'psk',
          presharedKey: 'key"with"quotes\nand\\backslashes',
          ikeProposals: ['aes256-sha256-modp2048'],
          espProposals: ['aes256gcm16-ecp256'],
          localTs: ['10.0.0.0/16'],
          remoteTs: ['10.1.0.0/16'],
          dpdDelay: 30,
          dpdAction: 'restart',
          description: 'Tunnel with special chars in PSK',
        },
      ],
    });
    expect(res.swanctlConf).toContain('secret = "key\\"with\\"quotesand\\\\backslashes"');
    expect(res.swanctlConf).not.toContain('\nand\\backslashes');
  });
});

describe('Phase 2: OpenVPN 2.6 with DCO & CSO Compiler', () => {
  it('compiles OpenVPN server with DCO and Client-Specific Overrides', () => {
    const res = compileOpenVpn({
      enabled: true,
      servers: [
        {
          id: 'ovpn-1',
          name: 'RemoteAccessVPN',
          enabled: true,
          protocol: 'udp',
          port: 1194,
          deviceType: 'tun',
          devName: 'ovpn-dco0',
          dcoEnabled: true,
          tunnelNetwork: '10.8.0.0/24',
          localNetwork: '192.168.100.0/24',
          cipher: 'AES-256-GCM',
          authDigest: 'SHA256',
          clientToClient: true,
          duplicateCn: false,
          cso: [
            {
              id: 'cso-alice',
              commonName: 'alice-laptop',
              assignedIp: '10.8.0.50',
              pushRoutes: ['192.168.200.0/24'],
              description: 'Alice Static IP',
            },
          ],
          description: 'Road Warrior Access',
        },
      ],
    });

    expect(res.servers).toHaveLength(1);
    const s = res.servers[0];
    expect(s.serverConf).toContain('dev ovpn-dco0');
    expect(s.serverConf).toContain('server 10.8.0.0 255.255.255.0');
    expect(s.serverConf).toContain('push "route 192.168.100.0 255.255.255.0"');
    expect(s.serverConf).toContain('client-to-client');
    expect(s.ccdFiles['alice-laptop']).toContain('ifconfig-push 10.8.0.50 255.255.255.0');
    expect(s.ccdFiles['alice-laptop']).toContain('push "route 192.168.200.0 255.255.255.0"');

    const clientProfile = generateClientOvpnProfile({
      serverHost: 'vpn.axonwall.net',
      serverPort: 1194,
      caCert: '-----BEGIN CERTIFICATE-----\nSAMPLE\n-----END CERTIFICATE-----',
    });
    expect(clientProfile).toContain('remote vpn.axonwall.net 1194');
    expect(clientProfile).toContain('<ca>');
  });

  it('prevents path traversal in OpenVPN CSO commonName', () => {
    expect(() => OpenVpnCsoSchema.parse({ commonName: '../../etc/shadow' })).toThrow();
    expect(() => OpenVpnCsoSchema.parse({ commonName: '.hidden' })).toThrow();

    const res = compileOpenVpn({
      enabled: true,
      servers: [
        {
          id: 'ovpn-1',
          name: 'VPN\nInjection',
          enabled: true,
          protocol: 'udp',
          port: 1194,
          deviceType: 'tun',
          devName: 'ovpn;rm',
          dcoEnabled: true,
          tunnelNetwork: '10.8.0.0/24',
          cipher: 'AES-256-GCM',
          authDigest: 'SHA256',
          clientToClient: false,
          duplicateCn: false,
          description: '',
          cso: [
            {
              commonName: '../../etc/passwd',
              pushRoutes: ['192.168.1.0/24'],
              description: 'Traversal attempt',
            },
            {
              commonName: 'valid-client.1',
              pushRoutes: ['192.168.2.0/24'],
              description: 'Valid client',
            },
          ],
        },
      ],
    });

    expect(res.servers[0].serverConf).not.toContain('VPN\nInjection');
    expect(res.servers[0].serverConf).toContain('dev ovpnrm');
    expect(res.servers[0].ccdFiles['../../etc/passwd']).toBeUndefined();
    expect(res.servers[0].ccdFiles['valid-client.1']).toBeDefined();
  });
});

describe('Phase 2: FRRouting (BGP / OSPF / BFD) Compiler', () => {
  it('compiles BGP and OSPF with BFD peering', () => {
    const res = compileFrr({
      enabled: true,
      bgp: {
        enabled: true,
        asNumber: 64512,
        routerId: '1.1.1.1',
        networks: ['10.0.0.0/16'],
        neighbors: [
          {
            peerIp: '192.168.1.254',
            remoteAs: 65000,
            description: 'Upstream Transit',
            password: 'bgpPassword',
            bfd: true,
            nextHopSelf: true,
            softReconfiguration: true,
          },
        ],
      },
      ospf: {
        enabled: true,
        routerId: '1.1.1.1',
        redistributeConnected: true,
        redistributeDefault: true,
        areas: [
          {
            areaId: '0.0.0.0',
            interfaces: ['eth1'],
            networks: ['192.168.100.0/24'],
          },
        ],
      },
    });

    expect(res.frrConf).toContain('router bgp 64512');
    expect(res.frrConf).toContain('network 10.0.0.0/16');
    expect(res.frrConf).toContain('neighbor 192.168.1.254 bfd');
    expect(res.frrConf).toContain('router ospf');
    expect(res.frrConf).toContain('network 192.168.100.0/24 area 0.0.0.0');
    expect(res.daemons.bgpd).toBe(true);
    expect(res.daemons.ospfd).toBe(true);
    expect(res.daemons.bfdd).toBe(true);
    expect(res.daemonsConf).toContain('bgpd=yes');
    expect(res.daemonsConf).toContain('ospfd=yes');
    expect(res.daemonsConf).toContain('bfdd=yes');
  });

  it('strips newlines from BGP neighbor description and password', () => {
    const res = compileFrr({
      enabled: true,
      bgp: {
        enabled: true,
        asNumber: 64512,
        routerId: '1.1.1.1',
        networks: ['10.0.0.0/16\nnetwork 0.0.0.0/0'],
        neighbors: [
          {
            peerIp: '192.168.1.254',
            remoteAs: 65000,
            description: 'Transit\n neighbor 192.168.1.254 shutdown',
            password: 'secret\npass',
            bfd: false,
            nextHopSelf: false,
            softReconfiguration: false,
          },
        ],
      },
      ospf: {
        enabled: false,
        routerId: '1.1.1.1',
        redistributeConnected: false,
        redistributeDefault: false,
        areas: [],
      },
    });

    expect(res.frrConf).not.toContain('\n neighbor 192.168.1.254 shutdown');
    expect(res.frrConf).toContain('description Transit  neighbor 192.168.1.254 shutdown');
    expect(res.frrConf).toContain('password secretpass');
    expect(res.frrConf).not.toContain('\nnetwork 0.0.0.0/0');
  });

  it('strips newlines from WireGuard peer names and keys', () => {
    const res = compileWireGuard({
      enabled: true,
      address: '10.0.0.1/24\nPostUp = echo pwned',
      listenPort: 51820,
      privateKey: 'privatekey\nPostUp = echo pwned2',
      peers: [
        {
          name: 'Peer 1\n[Peer]\nPublicKey = attacker',
          publicKey: 'key1\nAllowedIPs = 0.0.0.0/0',
          allowedIps: ['10.0.0.2/32\nAllowedIPs = 0.0.0.0/0'],
          enabled: true,
          persistentKeepalive: 25,
        },
      ],
    });

    expect(res.wgConfig).not.toContain('\nPostUp = echo pwned');
    expect(res.wgConfig).not.toContain('# Peer: Peer 1\n[Peer]');
    expect(res.wgConfig).toContain('# Peer: Peer 1 [Peer] PublicKey = attacker');
    expect(res.wgConfig).not.toContain('key1\nAllowedIPs');
  });
});

describe('Phase 2: Policy Routing in nftables Compiler', () => {
  it('adds meta mark set for policy routed rules with gatewayGroup', () => {
    const state: DesiredState = {
      version: 1,
      system: {
        hostname: 'axonwall',
        domain: 'local',
        dnsServers: ['1.1.1.1'],
        timezone: 'UTC',
        flowtableOffload: false,
        antiLockout: { enabled: true, interface: 'lan', ports: [3000] },
      },
      interfaces: [
        { name: 'lan', device: 'eth1', type: 'static', enabled: true, ipv4Address: '192.168.100.1/24', mtu: 1500, description: 'LAN' },
        { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, mtu: 1500, description: 'WAN' },
      ],
      vlans: [],
      bridges: [],
      bonds: [],
      virtualIps: [],
      vrfs: [],
      aliases: [],
      rules: [
        {
          id: 'rule-policy-route',
          action: 'pass',
          direction: 'in',
          interface: 'lan',
          quick: true,
          protocol: 'tcp',
          source: 'any',
          sourcePort: '',
          destination: 'any',
          destinationPort: '80',
          gatewayGroup: 'wan_tier_failover',
          log: false,
          enabled: true,
          description: 'Route Web to WAN Tier Failover',
          sortOrder: 10,
        },
      ],
      nat: [],
      gateways: [],
      gatewayGroups: [
        {
          name: 'wan_tier_failover',
          trigger: 'down',
          members: [{ gatewayName: 'wan_gw1', tier: 1, weight: 1 }],
          description: 'Failover Group',
        },
      ],
      dhcp: { enabled: true, subnets: [] },
      dns: { enabled: true, listenPort: 53, dnssec: true, dotEnabled: true, dotUpstreams: [], hostOverrides: [] },
      routes: [],
    };

    const res = compileNftables(state);
    expect(res.nftScript).toContain('meta mark set 0x');
    expect(res.nftScript).toContain('Route Web to WAN Tier Failover');
  });
});

describe('Phase 2: Packet Tracer & Policy Simulator (E5)', () => {
  const simState: DesiredState = {
    version: 1,
    system: {
      hostname: 'axonwall-core',
      domain: 'axonwall.local',
      dnsServers: ['1.1.1.1'],
      timezone: 'UTC',
      flowtableOffload: true,
      antiLockout: {
        enabled: true,
        interface: 'lan',
        ports: [22, 80, 443, 3000],
      },
    },
    interfaces: [
      { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, mtu: 1500, description: 'WAN' },
      { name: 'lan', device: 'eth1', type: 'static', enabled: true, ipv4Address: '192.168.100.1/24', mtu: 1500, description: 'LAN' },
    ],
    vlans: [],
    bridges: [],
    bonds: [],
    virtualIps: [],
    vrfs: [],
    aliases: [
      {
        name: 'blocked_ips',
        type: 'host',
        entries: ['198.51.100.99'],
        description: 'Malicious hosts',
        enabled: true,
      },
    ],
    rules: [
      {
        id: 'r-drop-blocked',
        action: 'block',
        direction: 'in',
        interface: 'lan',
        quick: true,
        protocol: 'any',
        source: 'any',
        sourcePort: '',
        destination: '$blocked_ips',
        destinationPort: '',
        log: true,
        enabled: true,
        description: 'Block Bad IPs',
        sortOrder: 10,
      },
      {
        id: 'r-allow-web',
        action: 'pass',
        direction: 'in',
        interface: 'lan',
        quick: true,
        protocol: 'tcp',
        source: '192.168.100.0/24',
        sourcePort: '',
        destination: 'any',
        destinationPort: '443',
        gatewayGroup: 'wan_balance',
        log: false,
        enabled: true,
        description: 'Allow LAN to HTTPS with WAN Balance',
        sortOrder: 20,
      },
    ],
    nat: [
      {
        id: 'dnat-http',
        type: 'dnat',
        interface: 'wan',
        protocol: 'tcp',
        source: 'any',
        sourcePort: '',
        destination: 'wan_ip',
        destinationPort: '8080',
        targetIp: '192.168.100.200',
        targetPort: '80',
        log: false,
        enabled: true,
        description: 'Forward WAN 8080 to Web Server 80',
        sortOrder: 10,
      },
      {
        id: 'snat-wan',
        type: 'masquerade',
        interface: 'wan',
        protocol: 'any',
        source: 'any',
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        log: false,
        enabled: true,
        description: 'Outbound Masquerade',
        sortOrder: 100,
      },
    ],
    gateways: [],
    gatewayGroups: [],
    dhcp: { enabled: true, subnets: [] },
    dns: { enabled: true, listenPort: 53, dnssec: true, dotEnabled: true, dotUpstreams: [], hostOverrides: [] },
    routes: [],
  };

  it('allows and policy routes LAN traffic to HTTPS', () => {
    const q: PacketTracerQuery = {
      inInterface: 'lan',
      srcIp: '192.168.100.45',
      dstIp: '142.250.190.46',
      protocol: 'tcp',
      srcPort: 54321,
      dstPort: 443,
    };
    const res = simulatePacket(q, simState);
    expect(res.allowed).toBe(true);
    expect(res.verdict).toBe('ALLOW');
    expect(res.matchedRule?.description).toBe('Allow LAN to HTTPS with WAN Balance');
    expect(res.policyRouting?.gatewayGroup).toBe('wan_balance');
  });

  it('drops traffic to blocked IP from alias set', () => {
    const q: PacketTracerQuery = {
      inInterface: 'lan',
      srcIp: '192.168.100.45',
      dstIp: '198.51.100.99',
      protocol: 'tcp',
      srcPort: 54321,
      dstPort: 80,
    };
    const res = simulatePacket(q, simState);
    expect(res.allowed).toBe(false);
    expect(res.verdict).toBe('DROP');
    expect(res.matchedRule?.description).toBe('Block Bad IPs');
  });

  it('verifies anti-lockout protection for LAN console port 3000', () => {
    const q: PacketTracerQuery = {
      inInterface: 'lan',
      srcIp: '192.168.100.45',
      dstIp: '192.168.100.1',
      protocol: 'tcp',
      srcPort: 54321,
      dstPort: 3000,
    };
    const res = simulatePacket(q, simState);
    expect(res.allowed).toBe(true);
    expect(res.verdict).toBe('ALLOW');
    expect(res.steps.some((s) => s.description.includes('Anti-Lockout'))).toBe(true);
  });

  it('translates destination IP and port on DNAT match', () => {
    const q: PacketTracerQuery = {
      inInterface: 'wan',
      srcIp: '203.0.113.50',
      dstIp: '198.51.100.1',
      protocol: 'tcp',
      srcPort: 45678,
      dstPort: 8080,
    };
    const res = simulatePacket(q, simState);
    expect(res.nat?.type).toBe('dnat');
    expect(res.nat?.translatedIp).toBe('192.168.100.200');
    expect(res.nat?.translatedPort).toBe(80);
  });
});
