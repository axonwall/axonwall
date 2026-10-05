import { z } from 'zod';
import { isValidIPv4, isValidIPv6, isValidCIDR, isValidMAC, isValidPortRange } from '../util/index.js';

export const InterfaceTypeSchema = z.enum([
  'static',
  'dhcp',
  'pppoe',
  'track6',
  'vlan',
  'bridge',
  'wireguard',
  'loopback',
]);

export const InterfaceSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1).max(32), // e.g. "wan", "lan", "opt1"
  device: z.string().min(1).max(32), // e.g. "eth0", "enp1s0"
  type: InterfaceTypeSchema.default('static'),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
  ipv4Address: z.string().refine((val) => val === '' || isValidCIDR(val) || isValidIPv4(val), {
    message: 'Invalid IPv4 address or CIDR',
  }).optional(),
  ipv4Gateway: z.string().optional(),
  ipv6Address: z.string().refine((val) => val === '' || isValidCIDR(val) || isValidIPv6(val), {
    message: 'Invalid IPv6 address or CIDR',
  }).optional(),
  ipv6Gateway: z.string().optional(),
  mtu: z.number().int().min(576).max(65535).default(1500),
  macAddress: z.string().refine((val) => val === '' || isValidMAC(val), {
    message: 'Invalid MAC address',
  }).optional(),
});
export type Interface = z.infer<typeof InterfaceSchema>;

export const AliasTypeSchema = z.enum(['host', 'network', 'port', 'mac', 'urltable', 'geoip', 'asn', 'fqdn']);

export const AliasSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().regex(/^[a-zA-Z0-9_]+$/, 'Alias name must be alphanumeric or underscore'),
  type: AliasTypeSchema,
  entries: z.array(z.string().min(1)),
  url: z.string().optional(),
  refreshIntervalHours: z.number().int().optional(),
  description: z.string().max(255).default(''),
  enabled: z.boolean().default(true),
});
export type Alias = z.infer<typeof AliasSchema>;

export const RuleActionSchema = z.enum(['pass', 'block', 'reject']);
export const RuleDirectionSchema = z.enum(['in', 'out']);
export const RuleProtocolSchema = z.enum(['any', 'tcp', 'udp', 'tcp_udp', 'icmp', 'ipv6-icmp', 'esp', 'ah', 'gre']);

export const FirewallRuleSchema = z.object({
  id: z.string().uuid().optional(),
  action: RuleActionSchema.default('pass'),
  direction: RuleDirectionSchema.default('in'),
  interface: z.string().min(1).default('lan'), // interface name or 'any' or 'floating'
  quick: z.boolean().default(true),
  protocol: RuleProtocolSchema.default('any'),
  source: z.string().default('any'), // 'any', IP, CIDR, or '$alias_name'
  sourcePort: z.string().refine((val) => val === '' || val === 'any' || isValidPortRange(val) || val.startsWith('$'), {
    message: 'Invalid source port range or alias',
  }).default(''),
  destination: z.string().default('any'),
  destinationPort: z.string().refine((val) => val === '' || val === 'any' || isValidPortRange(val) || val.startsWith('$'), {
    message: 'Invalid destination port range or alias',
  }).default(''),
  gateway: z.string().optional(), // for policy routing
  gatewayGroup: z.string().optional(), // for multi-WAN policy routing
  log: z.boolean().default(false),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
  sortOrder: z.number().int().default(100),
});
export type FirewallRule = z.infer<typeof FirewallRuleSchema>;

export const NatTypeSchema = z.enum(['dnat', 'snat', 'masquerade', 'nptv6']);

export const NatRuleSchema = z.object({
  id: z.string().uuid().optional(),
  type: NatTypeSchema.default('dnat'),
  interface: z.string().min(1).default('wan'),
  protocol: RuleProtocolSchema.default('tcp'),
  source: z.string().default('any'),
  sourcePort: z.string().default(''),
  destination: z.string().default('wan_ip'),
  destinationPort: z.string().default(''),
  targetIp: z.string().optional(), // translated internal IP
  targetPort: z.string().optional(), // translated internal port
  log: z.boolean().default(false),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
  sortOrder: z.number().int().default(100),
});
export type NatRule = z.infer<typeof NatRuleSchema>;

export const GatewaySchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1).max(32),
  interface: z.string().min(1),
  gatewayIp: z.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), {
    message: 'Invalid gateway IP',
  }),
  monitorIp: z.string().optional(),
  weight: z.number().int().min(1).max(30).default(1),
  isDefault: z.boolean().default(false),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type Gateway = z.infer<typeof GatewaySchema>;

export const WireGuardPeerSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  publicKey: z.string().min(32),
  presharedKey: z.string().optional(),
  allowedIps: z.array(z.string()),
  endpoint: z.string().optional(), // host:port
  persistentKeepalive: z.number().int().min(0).max(3600).default(25),
  enabled: z.boolean().default(true),
});

export const WireGuardConfigSchema = z.object({
  enabled: z.boolean().default(false),
  listenPort: z.number().int().min(1).max(65535).default(51820),
  privateKey: z.string().min(32).optional(),
  address: z.string().default('10.10.0.1/24'),
  peers: z.array(WireGuardPeerSchema).default([]),
});

export const AntiLockoutSchema = z.object({
  enabled: z.boolean().default(true),
  interface: z.string().default('lan'),
  ports: z.array(z.number()).default([80, 443, 22, 3000]),
});

export const SystemSettingsSchema = z.object({
  hostname: z.string().default('axonwall'),
  domain: z.string().default('local'),
  dnsServers: z.array(z.string()).default(['1.1.1.1', '8.8.8.8']),
  timezone: z.string().default('UTC'),
  flowtableOffload: z.boolean().default(true),
  antiLockout: AntiLockoutSchema.default({
    enabled: true,
    interface: 'lan',
    ports: [80, 443, 22, 3000],
  }),
});

export const DhcpStaticMappingSchema = z.object({
  id: z.string().uuid().optional(),
  mac: z.string().refine(isValidMAC, { message: 'Invalid MAC address' }),
  ip: z.string().refine(isValidIPv4, { message: 'Invalid IPv4 address' }),
  hostname: z.string().optional(),
  description: z.string().max(255).default(''),
});
export type DhcpStaticMapping = z.infer<typeof DhcpStaticMappingSchema>;

export const DhcpSubnetSchema = z.object({
  id: z.string().uuid().optional(),
  interface: z.string().min(1),
  subnet: z.string().refine(isValidCIDR, { message: 'Invalid subnet CIDR' }),
  poolStart: z.string().refine(isValidIPv4, { message: 'Invalid pool start IPv4' }),
  poolEnd: z.string().refine(isValidIPv4, { message: 'Invalid pool end IPv4' }),
  routers: z.array(z.string()).default([]),
  dnsServers: z.array(z.string()).default([]),
  staticMappings: z.array(DhcpStaticMappingSchema).default([]),
  enabled: z.boolean().default(true),
});
export type DhcpSubnet = z.infer<typeof DhcpSubnetSchema>;

export const DhcpConfigSchema = z.object({
  enabled: z.boolean().default(true),
  subnets: z.array(DhcpSubnetSchema).default([]),
});
export type DhcpConfig = z.infer<typeof DhcpConfigSchema>;

export const DnsHostOverrideSchema = z.object({
  id: z.string().uuid().optional(),
  hostname: z.string().min(1),
  domain: z.string().min(1),
  ip: z.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: 'Invalid IP address' }),
  description: z.string().max(255).default(''),
});
export type DnsHostOverride = z.infer<typeof DnsHostOverrideSchema>;

export const DnsBlocklistFeedSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  url: z.string(),
  entriesCount: z.number().int().default(0),
  enabled: z.boolean().default(true),
});
export type DnsBlocklistFeed = z.infer<typeof DnsBlocklistFeedSchema>;

export const DnsBlocklistConfigSchema = z.object({
  enabled: z.boolean().default(false),
  feeds: z.array(DnsBlocklistFeedSchema).default([]),
  whitelist: z.array(z.string()).default([]),
  blacklist: z.array(z.string()).default([]),
  action: z.enum(['always_null', 'always_nxdomain']).default('always_null'),
});
export type DnsBlocklistConfig = z.infer<typeof DnsBlocklistConfigSchema>;

export const DnsConfigSchema = z.object({
  enabled: z.boolean().default(true),
  listenPort: z.number().int().min(1).max(65535).default(53),
  dnssec: z.boolean().default(true),
  dotEnabled: z.boolean().default(true),
  dotUpstreams: z.array(z.string()).default(['1.1.1.1@853#cloudflare-dns.com', '9.9.9.9@853#dns.quad9.net']),
  hostOverrides: z.array(DnsHostOverrideSchema).default([]),
  blocklist: DnsBlocklistConfigSchema.optional(),
});
export type DnsConfig = z.infer<typeof DnsConfigSchema>;

export const StaticRouteSchema = z.object({
  id: z.string().uuid().optional(),
  network: z.string().refine(isValidCIDR, { message: 'Invalid route network CIDR' }),
  gateway: z.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: 'Invalid route gateway IP' }),
  interface: z.string().optional(),
  description: z.string().max(255).default(''),
  enabled: z.boolean().default(true),
});
export type StaticRoute = z.infer<typeof StaticRouteSchema>;

export const GatewayGroupMemberSchema = z.object({
  gatewayName: z.string().min(1),
  tier: z.number().int().min(1).max(5).default(1),
  weight: z.number().int().min(1).max(30).default(1),
});
export type GatewayGroupMember = z.infer<typeof GatewayGroupMemberSchema>;

export const GatewayGroupSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  trigger: z.enum(['down', 'loss', 'latency', 'both']).default('down'),
  members: z.array(GatewayGroupMemberSchema).min(1),
  description: z.string().max(255).default(''),
});
export type GatewayGroup = z.infer<typeof GatewayGroupSchema>;

export const VlanSchema = z.object({
  id: z.string().uuid().optional(),
  tag: z.number().int().min(1).max(4094),
  parentInterface: z.string().min(1),
  vlanInterface: z.string().min(1),
  priority: z.number().int().min(0).max(7).default(0),
  description: z.string().max(255).default(''),
});
export type Vlan = z.infer<typeof VlanSchema>;

export const BridgeMemberSchema = z.object({
  interface: z.string().min(1),
  stp: z.boolean().default(true),
  cost: z.number().int().default(100),
  priority: z.number().int().default(32),
});
export type BridgeMember = z.infer<typeof BridgeMemberSchema>;

export const BridgeSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  members: z.array(BridgeMemberSchema).default([]),
  vlanFiltering: z.boolean().default(true),
  stp: z.boolean().default(false),
  description: z.string().max(255).default(''),
});
export type Bridge = z.infer<typeof BridgeSchema>;

export const BondModeSchema = z.enum([
  '802.3ad',
  'active-backup',
  'balance-rr',
  'balance-xor',
  'broadcast',
  'balance-tlb',
  'balance-alb',
]);
export type BondMode = z.infer<typeof BondModeSchema>;

export const BondSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  members: z.array(z.string()).min(1),
  mode: BondModeSchema.default('802.3ad'),
  lacpRate: z.enum(['slow', 'fast']).default('fast'),
  xmitHashPolicy: z.enum(['layer2', 'layer2+3', 'layer3+4']).default('layer2+3'),
  miimon: z.number().int().default(100),
  description: z.string().max(255).default(''),
});
export type Bond = z.infer<typeof BondSchema>;

export const VirtualIpTypeSchema = z.enum(['alias', 'carp', 'proxyarp']);
export type VirtualIpType = z.infer<typeof VirtualIpTypeSchema>;

export const VirtualIpSchema = z.object({
  id: z.string().uuid().optional(),
  interface: z.string().min(1),
  ip: z.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: 'Invalid IP address' }),
  subnetBits: z.number().int().min(1).max(128).default(32),
  type: VirtualIpTypeSchema.default('alias'),
  vhid: z.number().int().min(1).max(255).optional(),
  password: z.string().optional(),
  description: z.string().max(255).default(''),
});
export type VirtualIp = z.infer<typeof VirtualIpSchema>;

export const VrfSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  tableId: z.number().int().min(1).max(65535),
  interfaces: z.array(z.string()).default([]),
  description: z.string().max(255).default(''),
});
export type Vrf = z.infer<typeof VrfSchema>;

export const IpsecTunnelSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  routeBased: z.boolean().default(true),
  xfrmInterfaceId: z.number().int().min(1).max(65535).default(1),
  localAddress: z.string().default('%any'),
  remoteAddress: z.string().min(1),
  authMethod: z.enum(['psk', 'pubkey']).default('psk'),
  presharedKey: z.string().optional(),
  ikeProposals: z.array(z.string()).default(['aes256-sha256-modp2048', 'aes256gcm16-prfsha256-ecp256']),
  espProposals: z.array(z.string()).default(['aes256gcm16-ecp256', 'aes256-sha256']),
  localTs: z.array(z.string()).default(['0.0.0.0/0']),
  remoteTs: z.array(z.string()).default(['0.0.0.0/0']),
  dpdDelay: z.number().int().default(30),
  dpdAction: z.enum(['restart', 'clear', 'hold']).default('restart'),
  description: z.string().max(255).default(''),
});
export type IpsecTunnel = z.infer<typeof IpsecTunnelSchema>;

export const IpsecConfigSchema = z.object({
  enabled: z.boolean().default(false),
  tunnels: z.array(IpsecTunnelSchema).default([]),
});
export type IpsecConfig = z.infer<typeof IpsecConfigSchema>;

export const OpenVpnCsoSchema = z.object({
  id: z.string().uuid().optional(),
  commonName: z.string().min(1),
  assignedIp: z.string().refine(isValidIPv4, { message: 'Invalid IPv4' }).optional(),
  pushRoutes: z.array(z.string()).default([]),
  description: z.string().max(255).default(''),
});
export type OpenVpnCso = z.infer<typeof OpenVpnCsoSchema>;

export const OpenVpnServerSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  protocol: z.enum(['udp', 'tcp']).default('udp'),
  port: z.number().int().min(1).max(65535).default(1194),
  deviceType: z.enum(['tun', 'tap']).default('tun'),
  devName: z.string().default('ovpn-dco0'),
  dcoEnabled: z.boolean().default(true),
  tunnelNetwork: z.string().refine(isValidCIDR, { message: 'Invalid tunnel CIDR' }).default('10.8.0.0/24'),
  localNetwork: z.string().optional(),
  cipher: z.string().default('AES-256-GCM'),
  authDigest: z.string().default('SHA256'),
  caCert: z.string().optional(),
  serverCert: z.string().optional(),
  serverKey: z.string().optional(),
  dhParams: z.string().optional(),
  clientToClient: z.boolean().default(false),
  duplicateCn: z.boolean().default(false),
  cso: z.array(OpenVpnCsoSchema).default([]),
  description: z.string().max(255).default(''),
});
export type OpenVpnServer = z.infer<typeof OpenVpnServerSchema>;

export const OpenVpnConfigSchema = z.object({
  enabled: z.boolean().default(false),
  servers: z.array(OpenVpnServerSchema).default([]),
});
export type OpenVpnConfig = z.infer<typeof OpenVpnConfigSchema>;

export const TrafficShaperQueueSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  priority: z.number().int().min(1).max(7).default(3),
  bandwidthPercent: z.number().min(1).max(100).default(20),
  burst: z.string().default('15k'),
  codel: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type TrafficShaperQueue = z.infer<typeof TrafficShaperQueueSchema>;

export const TrafficShaperInterfaceSchema = z.object({
  id: z.string().uuid().optional(),
  interface: z.string().min(1),
  downloadBandwidthMbps: z.number().min(0).default(100),
  uploadBandwidthMbps: z.number().min(0).default(50),
  scheduler: z.enum(['cake', 'fq_codel', 'htb']).default('cake'),
  cakeDiffserv: z.enum(['diffserv3', 'diffserv4', 'besteffort']).default('diffserv4'),
  cakeAckFilter: z.boolean().default(true),
  enabled: z.boolean().default(true),
  queues: z.array(TrafficShaperQueueSchema).default([]),
});
export type TrafficShaperInterface = z.infer<typeof TrafficShaperInterfaceSchema>;

export const TrafficShaperConfigSchema = z.object({
  enabled: z.boolean().default(false),
  interfaces: z.array(TrafficShaperInterfaceSchema).default([]),
});
export type TrafficShaperConfig = z.infer<typeof TrafficShaperConfigSchema>;

export const BgpNeighborSchema = z.object({
  peerIp: z.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: 'Invalid peer IP' }),
  remoteAs: z.number().int().min(1).max(4294967295),
  description: z.string().max(255).default(''),
  password: z.string().optional(),
  bfd: z.boolean().default(true),
  nextHopSelf: z.boolean().default(false),
  softReconfiguration: z.boolean().default(true),
});
export type BgpNeighbor = z.infer<typeof BgpNeighborSchema>;

export const BgpConfigSchema = z.object({
  enabled: z.boolean().default(false),
  asNumber: z.number().int().min(1).max(4294967295).default(64512),
  routerId: z.string().refine(isValidIPv4, { message: 'Invalid router ID' }).default('1.1.1.1'),
  networks: z.array(z.string()).default([]),
  neighbors: z.array(BgpNeighborSchema).default([]),
});
export type BgpConfig = z.infer<typeof BgpConfigSchema>;

export const OspfAreaSchema = z.object({
  areaId: z.string().default('0.0.0.0'),
  interfaces: z.array(z.string()).default([]),
  networks: z.array(z.string()).default([]),
});
export type OspfArea = z.infer<typeof OspfAreaSchema>;

export const OspfConfigSchema = z.object({
  enabled: z.boolean().default(false),
  routerId: z.string().refine(isValidIPv4, { message: 'Invalid router ID' }).default('1.1.1.1'),
  redistributeConnected: z.boolean().default(true),
  redistributeDefault: z.boolean().default(false),
  areas: z.array(OspfAreaSchema).default([]),
});
export type OspfConfig = z.infer<typeof OspfConfigSchema>;

export const FrrConfigSchema = z.object({
  enabled: z.boolean().default(false),
  bgp: BgpConfigSchema.default({}),
  ospf: OspfConfigSchema.default({}),
});
export type FrrConfig = z.infer<typeof FrrConfigSchema>;

export const PacketTracerQuerySchema = z.object({
  inInterface: z.string().min(1),
  srcIp: z.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: 'Invalid source IP' }),
  dstIp: z.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: 'Invalid destination IP' }),
  protocol: z.enum(['tcp', 'udp', 'icmp']).default('tcp'),
  srcPort: z.number().int().min(1).max(65535).default(12345),
  dstPort: z.number().int().min(1).max(65535).default(80),
});
export type PacketTracerQuery = z.infer<typeof PacketTracerQuerySchema>;

export const SuricataModeSchema = z.enum(['ids', 'ips']);
export const SuricataRuleSourceSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  url: z.string(),
  enabled: z.boolean().default(true),
});
export type SuricataRuleSource = z.infer<typeof SuricataRuleSourceSchema>;

export const SuricataConfigSchema = z.object({
  enabled: z.boolean().default(false),
  mode: SuricataModeSchema.default('ips'),
  interfaces: z.array(z.string()).default(['wan']),
  nfqueueFailOpen: z.boolean().default(true),
  nfqueueBypass: z.boolean().default(true),
  ruleSources: z.array(SuricataRuleSourceSchema).default([
    {
      name: 'ET Open Ruleset',
      url: 'https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz',
      enabled: true,
    },
  ]),
  homeNet: z.array(z.string()).default(['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']),
});
export type SuricataConfig = z.infer<typeof SuricataConfigSchema>;

export const CaptivePortalZoneSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  interface: z.string().min(1),
  listenPort: z.number().int().default(8999),
  authServers: z.array(z.string()).default(['ldap_internal']),
  sessionTimeoutMinutes: z.number().int().min(1).default(720),
  idleTimeoutMinutes: z.number().int().min(1).default(60),
  passThroughMacs: z.array(z.string()).default([]),
  passThroughIps: z.array(z.string()).default([]),
  enableBandwidthQuotas: z.boolean().default(false),
  downloadLimitKbps: z.number().int().default(10000),
  uploadLimitKbps: z.number().int().default(5000),
  enabled: z.boolean().default(true),
});
export type CaptivePortalZone = z.infer<typeof CaptivePortalZoneSchema>;

export const CaptivePortalConfigSchema = z.object({
  enabled: z.boolean().default(false),
  zones: z.array(CaptivePortalZoneSchema).default([]),
});
export type CaptivePortalConfig = z.infer<typeof CaptivePortalConfigSchema>;

export const AcmeAccountSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  email: z.string().email(),
  caDirectoryUrl: z.string().default('https://acme-v02.api.letsencrypt.org/directory'),
  eabKid: z.string().optional(),
  eabHmacKey: z.string().optional(),
  enabled: z.boolean().default(true),
});
export type AcmeAccount = z.infer<typeof AcmeAccountSchema>;

export const AcmeCertificateSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  domain: z.string().min(1),
  altNames: z.array(z.string()).default([]),
  challengeType: z.enum(['http-01', 'dns-01']).default('http-01'),
  dnsProvider: z.string().optional(),
  autoRenew: z.boolean().default(true),
  renewDaysBeforeExpiry: z.number().int().default(30),
  deployServices: z.array(z.enum(['webgui', 'openvpn', 'ipsec', 'haproxy'])).default(['webgui']),
  status: z.enum(['pending', 'valid', 'expired', 'error']).default('pending'),
  expiresAt: z.string().optional(),
});
export type AcmeCertificate = z.infer<typeof AcmeCertificateSchema>;

export const AcmeConfigSchema = z.object({
  enabled: z.boolean().default(false),
  accounts: z.array(AcmeAccountSchema).default([]),
  certificates: z.array(AcmeCertificateSchema).default([]),
});
export type AcmeConfig = z.infer<typeof AcmeConfigSchema>;

export const CrowdSecConfigSchema = z.object({
  enabled: z.boolean().default(false),
  lapiUrl: z.string().default('http://127.0.0.1:8080/'),
  apiKey: z.string().optional(),
  remediationSetName: z.string().default('set_crowdsec_blacklists'),
  action: z.enum(['drop', 'reject']).default('drop'),
  logBanned: z.boolean().default(true),
});
export type CrowdSecConfig = z.infer<typeof CrowdSecConfigSchema>;

export const DesiredStateSchema = z.object({
  version: z.number().int().default(1),
  system: SystemSettingsSchema.default({}),
  interfaces: z.array(InterfaceSchema).default([]),
  vlans: z.array(VlanSchema).default([]),
  bridges: z.array(BridgeSchema).default([]),
  bonds: z.array(BondSchema).default([]),
  virtualIps: z.array(VirtualIpSchema).default([]),
  vrfs: z.array(VrfSchema).default([]),
  aliases: z.array(AliasSchema).default([]),
  rules: z.array(FirewallRuleSchema).default([]),
  nat: z.array(NatRuleSchema).default([]),
  gateways: z.array(GatewaySchema).default([]),
  gatewayGroups: z.array(GatewayGroupSchema).default([]),
  dhcp: DhcpConfigSchema.default({ enabled: true, subnets: [] }),
  dns: DnsConfigSchema.default({ enabled: true, hostOverrides: [] }),
  routes: z.array(StaticRouteSchema).default([]),
  trafficShaper: TrafficShaperConfigSchema.optional(),
  wireguard: WireGuardConfigSchema.optional(),
  ipsec: IpsecConfigSchema.optional(),
  openvpn: OpenVpnConfigSchema.optional(),
  frr: FrrConfigSchema.optional(),
  suricata: SuricataConfigSchema.optional(),
  captivePortal: CaptivePortalConfigSchema.optional(),
  acme: AcmeConfigSchema.optional(),
  crowdsec: CrowdSecConfigSchema.optional(),
});
export type DesiredState = z.infer<typeof DesiredStateSchema>;


