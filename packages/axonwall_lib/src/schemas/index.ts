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
  device: z.string().min(1).max(32).regex(/^[a-zA-Z0-9_.:-]+$/, 'Invalid device identifier'), // e.g. "eth0", "enp1s0"
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
  ports: z.array(z.number()).default([80, 443, 22, 3000, 2966]),
});

export const SystemSettingsSchema = z.object({
  hostname: z.string().default('axonwall'),
  domain: z.string().default('local'),
  dnsServers: z.array(z.string()).default(['1.1.1.1', '8.8.8.8']),
  timezone: z.string().default('UTC'),
  flowtableOffload: z.boolean().default(true),
  sshEnabled: z.boolean().optional(),
  sshPort: z.number().int().min(1).max(65535).optional(),
  webGuiPort: z.number().int().min(1).max(65535).optional(),
  antiLockout: AntiLockoutSchema.default({
    enabled: true,
    interface: 'lan',
    ports: [80, 443, 22, 3000, 2966],
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

export const TlsDecryptionSchema = z.object({
  enabled: z.boolean().default(false),
  caCertificateId: z.string().uuid().optional(),
  transparentProxyPort: z.number().int().default(3129),
  bypassedDomains: z.array(z.string()).default([]), // Don't intercept banks, healthcare
});
export type TlsDecryptionConfig = z.infer<typeof TlsDecryptionSchema>;

export const SuricataConfigSchema = z.object({
  enabled: z.boolean().default(false),
  mode: SuricataModeSchema.default('ips'),
  interfaces: z.array(z.string()).default(['wan']),
  nfqueueFailOpen: z.boolean().default(true),
  nfqueueBypass: z.boolean().default(true),
  tlsDecryption: TlsDecryptionSchema.optional(),
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

export const InternalCASchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  commonName: z.string(),
  organization: z.string().optional(),
  privateKeyBase64: z.string().optional(),
  certificateBase64: z.string().optional(),
  isDecryptionRoot: z.boolean().default(false),
});
export type InternalCA = z.infer<typeof InternalCASchema>;

export const AcmeConfigSchema = z.object({
  enabled: z.boolean().default(false),
  accounts: z.array(AcmeAccountSchema).default([]),
  certificates: z.array(AcmeCertificateSchema).default([]),
  internalCAs: z.array(InternalCASchema).default([]),
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

export const VrrpInstanceSchema = z.object({
  name: z.string().min(1).default('VI_WAN'),
  vrid: z.number().int().min(1).max(255).default(1),
  interface: z.string().min(1).default('eth0'),
  priority: z.number().int().min(1).max(255).default(100),
  virtualIps: z.array(z.string()).default([]),
  authPassword: z.string().optional(),
});
export type VrrpInstance = z.infer<typeof VrrpInstanceSchema>;

export const ConntrackSyncSchema = z.object({
  enabled: z.boolean().default(false),
  interface: z.string().default('eth0'),
  protocol: z.enum(['multicast', 'unicast']).default('unicast'),
  peerAddress: z.string().optional(),
  port: z.number().int().default(3780),
  multicastGroup: z.string().optional(),
  bufferSize: z.number().int().optional(),
  filterIgnoreIps: z.array(z.string()).optional(),
  mode: z.enum(['FTFW', 'NOTRACK', 'ALARM']).optional(),
});
export type ConntrackSync = z.infer<typeof ConntrackSyncSchema>;

export const HaSyncSectionsSchema = z.object({
  interfaces: z.boolean().default(false),
  firewall: z.boolean().default(true),
  dhcp: z.boolean().default(true),
  dns: z.boolean().default(true),
  aliases: z.boolean().default(true),
  vpn: z.boolean().default(true),
  sqlite: z.boolean().optional().default(true),
  nas: z.boolean().optional(),
  zfs: z.boolean().optional(),
  k3s: z.boolean().optional(),
});
export type HaSyncSections = z.infer<typeof HaSyncSectionsSchema>;

export const HaSqliteSyncConfigSchema = z.object({
  enabled: z.boolean().default(false),
  mode: z.enum(['direct_stream', 'litestream']).default('direct_stream'),
  databases: z.array(z.string()).default([
    '/var/lib/axonwall/headscale/db.sqlite',
  ]),
  syncIntervalSeconds: z.number().int().min(1).default(5),
  listenPort: z.number().int().min(1).max(65535).default(9876),
  peerAddress: z.string().optional(),
  peerPort: z.number().int().min(1).max(65535).optional(),
  authToken: z.string().optional(),
  litestreamBucket: z.string().optional(),
  litestreamEndpoint: z.string().optional(),
  litestreamAccessKeyId: z.string().optional(),
  litestreamSecretAccessKey: z.string().optional(),
});
export type HaSqliteSyncConfig = z.infer<typeof HaSqliteSyncConfigSchema>;

export const HighAvailabilityConfigSchema = z.object({
  enabled: z.boolean().default(false),
  nodeRole: z.enum(['master', 'backup']).default('master'),
  role: z.enum(['master', 'backup']).optional(),
  peerAddress: z.string().default(''),
  peerIp: z.string().optional(),
  syncInterface: z.string().optional(),
  peerPort: z.number().int().default(2966),
  mtlsCert: z.string().optional(),
  mtlsKey: z.string().optional(),
  vrrpInstances: z.array(VrrpInstanceSchema).default([]),
  conntrackSync: ConntrackSyncSchema.default({ enabled: false }),
  sqliteSync: HaSqliteSyncConfigSchema.optional().default({
    enabled: false,
    mode: 'direct_stream',
    databases: ['/var/lib/axonwall/headscale/db.sqlite'],
    syncIntervalSeconds: 5,
    listenPort: 9876,
  }),
  syncSections: HaSyncSectionsSchema.default({
    interfaces: false,
    firewall: true,
    dhcp: true,
    dns: true,
    aliases: true,
    vpn: true,
    sqlite: true,
  }),
  maintenanceMode: z.boolean().optional(),
});
export type HighAvailabilityConfig = z.infer<typeof HighAvailabilityConfigSchema>;

export const ObservabilityConfigSchema = z.object({
  metrics: z.object({
    enabled: z.boolean().default(true),
    port: z.number().int().default(9090),
    retentionDays: z.number().int().default(30),
    scrapeIntervalSeconds: z.number().int().default(10),
  }).default({ enabled: true, port: 9090, retentionDays: 30, scrapeIntervalSeconds: 10 }),
  flowExport: z.object({
    enabled: z.boolean().default(false),
    version: z.enum(['ipfix', 'netflow9']).default('ipfix'),
    collectorHost: z.string().optional(),
    collectorPort: z.number().int().default(2055),
    interfaces: z.array(z.string()).default([]),
  }).default({ enabled: false, version: 'ipfix', collectorPort: 2055, interfaces: [] }),
  alerting: z.object({
    enabled: z.boolean().default(false),
    webhookUrl: z.string().optional(),
    emailRecipient: z.string().optional(),
    notifyOnFailover: z.boolean().default(true),
    notifyOnThreshold: z.boolean().default(true),
  }).default({ enabled: false, notifyOnFailover: true, notifyOnThreshold: true }),
  clickhouse: z.object({
    enabled: z.boolean().default(false),
    url: z.string().default('http://127.0.0.1:8123'),
    database: z.string().default('axonwall'),
    username: z.string().default('admin'),
    password: z.string().optional(),
  }).default({ enabled: false, url: 'http://127.0.0.1:8123', database: 'axonwall', username: 'admin' }),
});
export type ObservabilityConfig = z.infer<typeof ObservabilityConfigSchema>;

export const NutUpsConfigSchema = z.object({
  enabled: z.boolean().default(false),
  name: z.string().default('axonups'),
  driver: z.string().default('usbhid-ups'),
  port: z.string().default('auto'),
  shutdownBatteryPct: z.number().int().min(1).max(50).default(20),
  lowBatteryRuntimeSec: z.number().int().default(300),
});
export type NutUpsConfig = z.infer<typeof NutUpsConfigSchema>;

export const HaProxyFrontendSchema = z.object({
  name: z.string().min(1),
  bindPort: z.number().int().min(1).max(65535),
  ssl: z.boolean().default(false),
  defaultBackend: z.string().min(1),
  certName: z.string().optional(),
});
export type HaProxyFrontend = z.infer<typeof HaProxyFrontendSchema>;

export const HaProxyBackendServerSchema = z.object({
  name: z.string().min(1),
  address: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  check: z.boolean().default(true),
});
export type HaProxyBackendServer = z.infer<typeof HaProxyBackendServerSchema>;

export const HaProxyBackendSchema = z.object({
  name: z.string().min(1),
  mode: z.enum(['http', 'tcp']).default('http'),
  balance: z.enum(['roundrobin', 'leastconn', 'source']).default('roundrobin'),
  servers: z.array(HaProxyBackendServerSchema).default([]),
});
export type HaProxyBackend = z.infer<typeof HaProxyBackendSchema>;

export const HaProxyPluginConfigSchema = z.object({
  enabled: z.boolean().default(false),
  mode: z.enum(['http', 'tcp']).default('http'),
  frontends: z.array(HaProxyFrontendSchema).default([]),
  backends: z.array(HaProxyBackendSchema).default([]),
});
export type HaProxyPluginConfig = z.infer<typeof HaProxyPluginConfigSchema>;

export const FreeRadiusClientSchema = z.object({
  name: z.string().min(1),
  ipAddress: z.string().min(1),
  secret: z.string().min(1),
});
export type FreeRadiusClient = z.infer<typeof FreeRadiusClientSchema>;

export const FreeRadiusPluginConfigSchema = z.object({
  enabled: z.boolean().default(false),
  authPort: z.number().int().default(1812),
  acctPort: z.number().int().default(1813),
  clients: z.array(FreeRadiusClientSchema).default([]),
  ldapSync: z.boolean().default(true),
});
export type FreeRadiusPluginConfig = z.infer<typeof FreeRadiusPluginConfigSchema>;

export const SnmpPluginConfigSchema = z.object({
  enabled: z.boolean().default(false),
  community: z.string().default('public'),
  sysLocation: z.string().default('Axonwall Gateway'),
  sysContact: z.string().default('admin@local'),
  listenPort: z.number().int().default(161),
});
export type SnmpPluginConfig = z.infer<typeof SnmpPluginConfigSchema>;

export const PluginCategorySchema = z.enum(['core_role', 'extension']);
export type PluginCategory = z.infer<typeof PluginCategorySchema>;

export const PluginManifestSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  version: z.string().min(1),
  category: PluginCategorySchema.default('extension').optional(),
  description: z.string().default(''),
  author: z.string().default('Axonwall Community'),
  systemdUnits: z.array(z.string()).default([]),
  privileges: z.array(z.string()).default([]),
  nftHooks: z.array(z.object({
    table: z.string(),
    chain: z.string(),
    priority: z.number().int(),
  })).optional(),
  menuEntry: z.object({
    title: z.string(),
    path: z.string(),
    icon: z.string().optional(),
  }).optional(),
});
export type PluginManifest = z.infer<typeof PluginManifestSchema>;

export const InstalledPluginRecordSchema = z.object({
  id: z.string(),
  enabled: z.boolean().default(true),
  installedAt: z.string().optional(),
  config: z.record(z.string(), z.any()).optional(),
});
export type InstalledPluginRecord = z.infer<typeof InstalledPluginRecordSchema>;

export const AiProviderTypeSchema = z.enum([
  'antigravity',
  'ollama',
  'claude-code',
  'codex',
  'vllm',
]);
export type AiProviderType = z.infer<typeof AiProviderTypeSchema>;

export const AntigravitySettingsSchema = z.object({
  endpoint: z.string().default('https://generativelanguage.googleapis.com/v1beta'),
  apiKey: z.string().optional(),
  model: z.string().default('gemini-2.5-pro'),
  thinkingBudget: z.number().int().default(1024),
});
export type AntigravitySettings = z.infer<typeof AntigravitySettingsSchema>;

export const OllamaSettingsSchema = z.object({
  endpoint: z.string().default('http://127.0.0.1:11434'),
  model: z.string().default('llama3.3:latest'),
  temperature: z.number().min(0).max(2).default(0.2),
});
export type OllamaSettings = z.infer<typeof OllamaSettingsSchema>;

export const ClaudeCodeSettingsSchema = z.object({
  endpoint: z.string().default('https://api.anthropic.com/v1'),
  apiKey: z.string().optional(),
  model: z.string().default('claude-3-7-sonnet-20250219'),
  extendedThinking: z.boolean().default(true),
});
export type ClaudeCodeSettings = z.infer<typeof ClaudeCodeSettingsSchema>;

export const CodexSettingsSchema = z.object({
  endpoint: z.string().default('https://api.openai.com/v1'),
  apiKey: z.string().optional(),
  model: z.string().default('gpt-4o'),
  temperature: z.number().min(0).max(2).default(0.2),
});
export type CodexSettings = z.infer<typeof CodexSettingsSchema>;

export const VllmSettingsSchema = z.object({
  endpoint: z.string().default('http://127.0.0.1:8000/v1'),
  apiKey: z.string().optional(),
  model: z.string().default('qwen2.5-coder-32b-instruct'),
  maxTokens: z.number().int().default(4096),
});
export type VllmSettings = z.infer<typeof VllmSettingsSchema>;

export const AiConfigSchema = z.object({
  enabled: z.boolean().default(false),
  activeProvider: AiProviderTypeSchema.default('antigravity'),
  systemContextInference: z.boolean().default(true),
  autoAuditOnSave: z.boolean().default(false),
  providers: z.object({
    antigravity: AntigravitySettingsSchema.default({}),
    ollama: OllamaSettingsSchema.default({}),
    claudeCode: ClaudeCodeSettingsSchema.default({}),
    codex: CodexSettingsSchema.default({}),
    vllm: VllmSettingsSchema.default({}),
  }).default({}),
});
export type AiConfig = z.infer<typeof AiConfigSchema>;

export const SatelliteNodeSchema = z.object({
  id: z.string(),
  name: z.string(),
  arch: z.enum(['mipsle', 'arm64', 'amd64', 'armv7', 'unknown']).default('unknown'),
  os: z.string().default('Linux'),
  ip: z.string().default('127.0.0.1'),
  lastSeen: z.string().optional(),
  status: z.enum(['online', 'offline', 'enrolling', 'degraded']).default('enrolling'),
  ztpToken: z.string().optional(),
  wireguard: z.object({
    tunnelIp: z.string().default('10.99.0.2/24'),
    publicKey: z.string().optional(),
    endpoint: z.string().optional(),
    connected: z.boolean().default(false),
  }).default({}),
  wifi: z.array(z.object({
    radio: z.string(),
    ssid: z.string(),
    channel: z.number().int().optional(),
    security: z.enum(['wpa2-psk', 'wpa3-sae', 'wpa3-enterprise', 'open']).default('wpa3-sae'),
    fastRoaming: z.object({
      enabled: z.boolean().default(false),
      mobilityDomain: z.string().optional(), // 4 hex digits, e.g. "a1b2"
    }).optional(),
    clientsCount: z.number().int().default(0),
    enabled: z.boolean().default(true),
  })).optional(),
  metrics: z.object({
    cpuUsagePercent: z.number().default(0),
    memUsagePercent: z.number().default(0),
    uptimeSeconds: z.number().int().default(0),
    activeConns: z.number().int().default(0),
    rxBytesTotal: z.number().int().default(0),
    txBytesTotal: z.number().int().default(0),
  }).optional(),
  activePolicyVersion: z.number().int().default(1),
});
export type SatelliteNode = z.infer<typeof SatelliteNodeSchema>;

export const SatelliteFleetConfigSchema = z.object({
  enabled: z.boolean().default(true),
  listenPort: z.number().int().default(2966),
  defaultHeartbeatIntervalSec: z.number().int().default(30),
  watchdogTimeoutSec: z.number().int().default(60),
  nodes: z.array(SatelliteNodeSchema).default([]),
});
export type SatelliteFleetConfig = z.infer<typeof SatelliteFleetConfigSchema>;

export const ZeroTrustAppSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  publicHostname: z.string().min(1),
  internalUpstream: z.string().min(1), // e.g. "http://10.0.0.5:8080"
  allowedRoles: z.array(z.string()).default(['admin', 'user']),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type ZeroTrustApp = z.infer<typeof ZeroTrustAppSchema>;

export const ZeroTrustConfigSchema = z.object({
  enabled: z.boolean().default(false),
  apps: z.array(ZeroTrustAppSchema).default([]),
});
export type ZeroTrustConfig = z.infer<typeof ZeroTrustConfigSchema>;

export const HeadscaleConfigSchema = z.object({
  enabled: z.boolean().default(false),
  magicDnsDomain: z.string().default('tailnet.axonwall.local'),
});
export type HeadscaleConfig = z.infer<typeof HeadscaleConfigSchema>;

export const GeoIpModeSchema = z.enum(['block', 'allow']);
export const GeoIpDirectionSchema = z.enum(['in', 'out', 'both']);

export const GeoIpConfigSchema = z.object({
  enabled: z.boolean().default(false),
  mode: GeoIpModeSchema.default('block'),
  direction: GeoIpDirectionSchema.default('in'),
  countries: z.array(z.string().length(2)).default([]),
  excludedSubnets: z.array(z.string()).default(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']),
  log: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type GeoIpConfig = z.infer<typeof GeoIpConfigSchema>;

export const SsoProviderSchema = z.enum(['oidc', 'entra', 'okta', 'google']);

export const SsoRoleMappingSchema = z.object({
  idpGroup: z.string().min(1),
  role: z.enum(['admin', 'operator', 'readonly']),
});
export type SsoRoleMapping = z.infer<typeof SsoRoleMappingSchema>;

export const SsoConfigSchema = z.object({
  enabled: z.boolean().default(false),
  provider: SsoProviderSchema.default('oidc'),
  displayName: z.string().default('Enterprise SSO'),
  issuerUrl: z.string().default(''),
  clientId: z.string().default(''),
  clientSecret: z.string().default(''),
  redirectUri: z.string().default(''),
  scopes: z.array(z.string()).default(['openid', 'profile', 'email', 'groups']),
  groupClaim: z.string().default('groups'),
  roleMappings: z.array(SsoRoleMappingSchema).default([
    { idpGroup: 'Axonwall-Admins', role: 'admin' },
    { idpGroup: 'Axonwall-Operators', role: 'operator' },
    { idpGroup: 'Axonwall-Auditors', role: 'readonly' },
  ]),
});
export type SsoConfig = z.infer<typeof SsoConfigSchema>;

// =============================================================================
// Core Appliance Capabilities & Modular Roles (Firewall / NAS / K3s + OpenEBS)
// =============================================================================

export const CoreCapabilitiesSchema = z.object({
  firewallEnabled: z.boolean().default(true),
  nasEnabled: z.boolean().default(false),
  k3sEnabled: z.boolean().default(false),
});
export type CoreCapabilities = z.infer<typeof CoreCapabilitiesSchema>;

export const ZfsTopologySchema = z.enum([
  'stripe',
  'mirror',
  'raidz1',
  'raidz2',
  'raidz3',
  'draid1',
  'draid2',
  'draid3',
]);
export type ZfsTopology = z.infer<typeof ZfsTopologySchema>;

export const ZfsCompressionSchema = z.enum(['lz4', 'zstd', 'gzip', 'off']);
export type ZfsCompression = z.infer<typeof ZfsCompressionSchema>;

export const ZfsPoolSchema = z.object({
  name: z.string().min(1).regex(/^[a-zA-Z][a-zA-Z0-9_-]*$/),
  topology: ZfsTopologySchema.default('mirror'),
  dataDisks: z.array(z.string()).min(1),
  cacheDisks: z.array(z.string()).default([]),
  logDisks: z.array(z.string()).default([]),
  spareDisks: z.array(z.string()).default([]),
  ashift: z.number().int().min(9).max(16).default(12),
  autotrim: z.boolean().default(true),
  compression: ZfsCompressionSchema.default('lz4'),
  scrubScheduleCron: z.string().default('0 2 * * 0'),
  description: z.string().max(255).default(''),
});
export type ZfsPool = z.infer<typeof ZfsPoolSchema>;

export const ZfsDatasetSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1),
  pool: z.string().min(1).default('tank'),
  type: z.enum(['filesystem', 'zvol']).default('filesystem'),
  compression: ZfsCompressionSchema.default('lz4'),
  dedup: z.enum(['off', 'on']).default('off'),
  quotaGb: z.number().nonnegative().default(0),
  recordSize: z.enum(['4K', '16K', '64K', '128K', '512K', '1M']).default('128K'),
  volSizeGb: z.number().nonnegative().default(10),
  encryption: z.enum(['off', 'aes-256-gcm']).default('off'),
  aclMode: z.enum(['passthrough', 'restricted']).default('passthrough'),
  replicateToHaPeer: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type ZfsDataset = z.infer<typeof ZfsDatasetSchema>;

export const ZfsSnapshotPolicySchema = z.object({
  id: z.string().optional(),
  dataset: z.string().min(1),
  interval: z.enum(['hourly', 'daily', 'weekly']).default('hourly'),
  keepCount: z.number().int().min(1).max(1000).default(24),
  replicateToHaPeer: z.boolean().default(true),
  enabled: z.boolean().default(true),
});
export type ZfsSnapshotPolicy = z.infer<typeof ZfsSnapshotPolicySchema>;

export const SmbShareSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1),
  path: z.string().min(1),
  comment: z.string().max(255).default(''),
  readOnly: z.boolean().default(false),
  guestOk: z.boolean().default(false),
  browseable: z.boolean().default(true),
  timeMachine: z.boolean().default(false),
  shadowCopies: z.boolean().default(true),
  validUsers: z.array(z.string()).default([]),
  hostsAllow: z.array(z.string()).default([]),
  enabled: z.boolean().default(true),
});
export type SmbShare = z.infer<typeof SmbShareSchema>;

export const NfsExportSchema = z.object({
  id: z.string().optional(),
  path: z.string().min(1),
  allowedNetworks: z.array(z.string()).default(['192.168.1.0/24']),
  readOnly: z.boolean().default(false),
  mapRootUser: z.enum(['root', 'nobody']).default('root'),
  async: z.boolean().default(false),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type NfsExport = z.infer<typeof NfsExportSchema>;

export const IscsiLunSchema = z.object({
  lunId: z.number().int().min(0).default(0),
  zvolPath: z.string().min(1),
  blockSize: z.enum(['512', '4096']).default('4096'),
  readOnly: z.boolean().default(false),
});
export type IscsiLun = z.infer<typeof IscsiLunSchema>;

export const IscsiTargetSchema = z.object({
  id: z.string().optional(),
  iqn: z.string().min(1).default('iqn.2026-10.io.axonwall:storage.target0'),
  portalIp: z.string().default('0.0.0.0'),
  portalPort: z.number().int().default(3260),
  allowedInitiators: z.array(z.string()).default([]),
  chapUser: z.string().default(''),
  chapSecret: z.string().default(''),
  luns: z.array(IscsiLunSchema).default([]),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type IscsiTarget = z.infer<typeof IscsiTargetSchema>;

export const S3ServerConfigSchema = z.object({
  enabled: z.boolean().default(false),
  listenPort: z.number().int().default(9000),
  consolePort: z.number().int().default(9001),
  rootDataset: z.string().default('/mnt/tank/s3'),
  accessKey: z.string().default('axonwall-admin'),
  secretKey: z.string().default(''),
  buckets: z.array(z.string()).default([]),
});
export type S3ServerConfig = z.infer<typeof S3ServerConfigSchema>;

export const NasConfigSchema = z.object({
  enabled: z.boolean().default(false),
  workgroup: z.string().default('WORKGROUP'),
  serverString: z.string().default('Axonwall Enterprise ZFS NAS'),
  pools: z.array(ZfsPoolSchema).default([]),
  datasets: z.array(ZfsDatasetSchema).default([]),
  snapshotPolicies: z.array(ZfsSnapshotPolicySchema).default([]),
  smbShares: z.array(SmbShareSchema).default([]),
  nfsExports: z.array(NfsExportSchema).default([]),
  iscsiTargets: z.array(IscsiTargetSchema).default([]),
  s3: S3ServerConfigSchema.optional(),
});
export type NasConfig = z.infer<typeof NasConfigSchema>;

export const OpenEbsConfigSchema = z.object({
  enabled: z.boolean().default(true),
  zfsLocalPvEnabled: z.boolean().default(true),
  zfsLocalPvPool: z.string().default('tank'),
  replicatedStorageEnabled: z.boolean().default(true),
  defaultReplicaCount: z.number().int().min(1).max(5).default(2),
  replicatedBackingPool: z.string().default('tank/openebs-replicated'),
});
export type OpenEbsConfig = z.infer<typeof OpenEbsConfigSchema>;

export const K3sWorkloadSpecSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1),
  namespace: z.string().default('default'),
  image: z.string().min(1),
  replicas: z.number().int().min(1).max(32).default(1),
  port: z.number().int().min(1).max(65535).default(80),
  storageClass: z.enum(['axonwall-replicated-ha', 'axonwall-zfs-local', 'none']).default('axonwall-replicated-ha'),
  storageSizeGb: z.number().int().min(1).default(10),
  mountPath: z.string().default('/data'),
  enabled: z.boolean().default(true),
});
export type K3sWorkloadSpec = z.infer<typeof K3sWorkloadSpecSchema>;

export const K3sConfigSchema = z.object({
  enabled: z.boolean().default(false),
  clusterCidr: z.string().default('10.42.0.0/16'),
  serviceCidr: z.string().default('10.43.0.0/16'),
  nodeIpInterface: z.string().default('lan'),
  flannelBackend: z.enum(['wireguard-native', 'vxlan', 'host-gw']).default('wireguard-native'),
  disableTraefik: z.boolean().default(false),
  autoJoinHaPeer: z.boolean().default(true),
  openEbs: OpenEbsConfigSchema.optional(),
  workloads: z.array(K3sWorkloadSpecSchema).default([]),
});
export type K3sConfig = z.infer<typeof K3sConfigSchema>;

export const DesiredStateSchema = z.object({
  version: z.number().int().default(1),
  capabilities: CoreCapabilitiesSchema.optional(),
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
  headscale: HeadscaleConfigSchema.optional(),
  frr: FrrConfigSchema.optional(),
  suricata: SuricataConfigSchema.optional(),
  captivePortal: CaptivePortalConfigSchema.optional(),
  acme: AcmeConfigSchema.optional(),
  crowdsec: CrowdSecConfigSchema.optional(),
  geoip: GeoIpConfigSchema.optional(),
  sso: SsoConfigSchema.optional(),
  tlsDecryption: TlsDecryptionSchema.optional(),
  ha: HighAvailabilityConfigSchema.optional(),
  observability: ObservabilityConfigSchema.optional(),
  ups: NutUpsConfigSchema.optional(),
  haproxy: HaProxyPluginConfigSchema.optional(),
  freeradius: FreeRadiusPluginConfigSchema.optional(),
  snmp: SnmpPluginConfigSchema.optional(),
  plugins: z.array(InstalledPluginRecordSchema).optional(),
  ai: AiConfigSchema.optional(),
  fleet: SatelliteFleetConfigSchema.optional(),
  zeroTrust: ZeroTrustConfigSchema.optional(),
  nas: NasConfigSchema.optional(),
  k3s: K3sConfigSchema.optional(),
});
export type DesiredState = z.infer<typeof DesiredStateSchema>;




