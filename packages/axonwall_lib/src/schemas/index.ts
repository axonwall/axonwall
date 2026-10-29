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

export const InterfaceRoleSchema = z.enum(['wan', 'wan-delegated', 'lan', 'dmz', 'opt', 'mgmt', 'ha-sync']);
export type InterfaceRole = z.infer<typeof InterfaceRoleSchema>;

export const InterfaceSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1).max(32).regex(/^[a-zA-Z0-9_.-]+$/, 'Invalid interface name'), // e.g. "wan1", "wan2", "lan1", "lan2"
  device: z.string().min(1).max(32).regex(/^[a-zA-Z0-9_.:-]+$/, 'Invalid device identifier'), // e.g. "eth0", "enp1s0", "ens18"
  role: InterfaceRoleSchema.optional(),
  ipv6Mode: z.enum(['disabled', 'auto', 'static', 'delegated', 'ula-only']).optional(),
  dhcpServer: z.boolean().optional(),
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

export function inferInterfaceRole(iface: { name: string; role?: InterfaceRole }): 'wan' | 'lan' {
  if (iface.role === 'wan' || iface.role === 'wan-delegated') return 'wan';
  if (iface.role === 'lan' || iface.role === 'dmz' || iface.role === 'opt' || iface.role === 'mgmt' || iface.role === 'ha-sync') return 'lan';
  const n = (iface.name || '').toLowerCase().trim();
  if (n === 'wan' || n.startsWith('wan')) return 'wan';
  return 'lan';
}

export function isInterfaceAuthoritativeDhcp(
  iface: { name: string; role?: InterfaceRole; type?: string; dhcpServer?: boolean },
  dhcp?: { enabled?: boolean; subnets?: Array<{ interface: string; enabled?: boolean }> },
): boolean {
  if (inferInterfaceRole(iface) === 'wan') return false;
  if (iface.type && iface.type !== 'static') return false;
  if (typeof iface.dhcpServer === 'boolean') return iface.dhcpServer;
  if (dhcp?.subnets && dhcp.subnets.length > 0) {
    return dhcp.subnets.some((s) => s.interface === iface.name && (s.enabled ?? true));
  }
  const n = (iface.name || '').toLowerCase().trim();
  if (n.startsWith('opt')) return false;
  return n === 'lan' || n === 'lan1';
}

export const AliasTypeSchema = z.enum(['host', 'network', 'port', 'mac', 'urltable', 'geoip', 'asn', 'fqdn']);

export function isValidFirewallEndpoint(val: string): boolean {
  if (!val || /[;#\r\n"'{}]/.test(val)) return false;
  if (val === 'any' || val === 'wan_ip' || val === 'lan_net' || val === 'self') return true;
  if (isValidIPv4(val) || isValidIPv6(val) || isValidCIDR(val)) return true;
  if (/^\$[a-zA-Z0-9_-]+$/.test(val)) return true;
  return false;
}

export function isValidPortSpec(val: string): boolean {
  if (!val || /[;#\r\n"'{}]/.test(val)) return false;
  return isValidPortRange(val) || /^\$[a-zA-Z0-9_-]+$/.test(val);
}

export const AliasSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().regex(/^[a-zA-Z0-9_]+$/, 'Alias name must be alphanumeric or underscore'),
  type: AliasTypeSchema,
  entries: z.array(
    z.string().min(1).refine((v) => !/[;\r\n{}"']/.test(v), {
      message: 'Alias entry contains invalid characters',
    }),
  ),
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
  source: z.string().refine(isValidFirewallEndpoint, {
    message: 'Invalid source endpoint (must be any, wan_ip, lan_net, self, IP, CIDR, or $alias)',
  }).default('any'), // 'any', IP, CIDR, or '$alias_name'
  sourcePort: z.string().refine((val) => val === '' || val === 'any' || isValidPortSpec(val), {
    message: 'Invalid source port range or alias',
  }).default(''),
  destination: z.string().refine(isValidFirewallEndpoint, {
    message: 'Invalid destination endpoint (must be any, wan_ip, lan_net, self, IP, CIDR, or $alias)',
  }).default('any'),
  destinationPort: z.string().refine((val) => val === '' || val === 'any' || isValidPortSpec(val), {
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
  source: z.string().refine(isValidFirewallEndpoint, {
    message: 'Invalid NAT source endpoint',
  }).default('any'),
  sourcePort: z.string().refine((v) => !v || isValidPortSpec(v) || v === 'any', {
    message: 'Invalid NAT source port',
  }).default(''),
  destination: z.string().refine(isValidFirewallEndpoint, {
    message: 'Invalid NAT destination endpoint',
  }).default('wan_ip'),
  destinationPort: z.string().refine((v) => !v || isValidPortSpec(v) || v === 'any', {
    message: 'Invalid NAT destination port',
  }).default(''),
  targetIp: z.string().refine((v) => !v || isValidIPv4(v) || isValidIPv6(v) || isValidCIDR(v) || v === 'wan_ip', {
    message: 'Invalid NAT target IP',
  }).optional(), // translated internal IP
  targetPort: z.string().refine((v) => !v || isValidPortSpec(v) || v === 'any', {
    message: 'Invalid NAT target port',
  }).optional(), // translated internal port
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
  description: z.union([z.string(), z.number().transform(String), z.null().transform(() => '')]).default(''),
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
export type WireGuardConfig = z.infer<typeof WireGuardConfigSchema>;
export type WireGuardPeer = z.infer<typeof WireGuardPeerSchema>;

export const RosenpassPeerSchema = z.object({
  id: z.string().optional(),
  name: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-zA-Z0-9_-]+$/, 'Peer name must only contain alphanumeric characters, hyphens, and underscores'),
  wgPeerPublicKey: z.string().min(32),
  endpoint: z.string().optional(), // host:port e.g. 203.0.113.20:9999
  pqPublicKeyPath: z.string().default('/etc/rosenpass/peers/peer-pq.pk'),
  pqPublicKeySha256: z.string().optional(),
  wgDevice: z.string().default('wg0'),
  keyOut: z.string().optional(),
  enabled: z.boolean().default(true),
});
export type RosenpassPeer = z.infer<typeof RosenpassPeerSchema>;

export const RosenpassConfigSchema = z.object({
  enabled: z.boolean().default(false),
  listenPort: z.number().int().min(1).max(65535).default(9999),
  listenAddresses: z.array(z.string()).default(['0.0.0.0:9999', '[::]:9999']),
  wgDevice: z.string().default('wg0'),
  verbosity: z.enum(['Quiet', 'Verbose']).default('Quiet'),
  rekeyIntervalSeconds: z.number().int().min(30).max(300).default(120),
  failClosedBootGuard: z.boolean().default(true),
  memfdSecret: z.boolean().default(true),
  publicKeyPath: z.string().default('/etc/rosenpass/pq.pk'),
  secretKeyPath: z.string().default('/etc/rosenpass/pq.sk'),
  publicKeySha256: z.string().optional(),
  peers: z.array(RosenpassPeerSchema).default([]),
});
export type RosenpassConfig = z.infer<typeof RosenpassConfigSchema>;

export const AntiLockoutSchema = z.object({
  enabled: z.boolean().default(true),
  interface: z.string().optional(),
  interfaces: z.array(z.string()).optional(),
  ports: z.array(z.number()).default([80, 443, 22, 3000, 2966]),
});
export type AntiLockout = z.infer<typeof AntiLockoutSchema>;

export function normalizeAntiLockoutInterfaces(a?: { interface?: string; interfaces?: string[] }): string[] {
  if (!a) return ['lan'];
  if (a.interfaces && a.interfaces.length > 0) return a.interfaces;
  if (a.interface) return [a.interface];
  return ['lan'];
}

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
  mcpEnabled: z.boolean().optional(),
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
  description: z.union([z.string(), z.number().transform(String), z.null().transform(() => '')]).default(''),
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
  commonName: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[a-zA-Z0-9_.-]+$/, 'Common Name must only contain alphanumeric characters, dots, hyphens, and underscores')
    .refine((val) => !val.includes('..') && !val.startsWith('.'), {
      message: 'Common Name cannot contain .. or start with .',
    }),
  assignedIp: z.string().refine(isValidIPv4, { message: 'Invalid IPv4' }).optional(),
  pushRoutes: z.array(z.string()).default([]),
  description: z.string().max(255).default(''),
});
export type OpenVpnCso = z.infer<typeof OpenVpnCsoSchema>;

export const OpenVpnServerSchema = z.object({
  id: z.string().uuid().optional(),
  name: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-zA-Z0-9_.-]+$/, 'Server name must only contain alphanumeric characters, dots, hyphens, and underscores'),
  enabled: z.boolean().default(true),
  protocol: z.enum(['udp', 'tcp']).default('udp'),
  port: z.number().int().min(1).max(65535).default(1194),
  deviceType: z.enum(['tun', 'tap']).default('tun'),
  devName: z
    .string()
    .regex(/^[a-zA-Z0-9_-]+$/, 'Device name must only contain alphanumeric characters, hyphens, and underscores')
    .default('ovpn-dco0'),
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
  bgp: BgpConfigSchema.prefault({}),
  ospf: OspfConfigSchema.prefault({}),
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
  radiusSecret: z.string().optional(),
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
  radiusSecret: z.string().optional(),
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
  name: z.string().min(1).regex(/^[a-zA-Z0-9_.-]+$/, 'Certificate name must contain only alphanumeric, dot, dash, or underscore characters'),
  domain: z.string().min(1).regex(/^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/, 'Invalid domain name'),
  altNames: z.array(z.string().regex(/^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/, 'Invalid altName')).default([]),
  challengeType: z.enum(['http-01', 'dns-01']).default('http-01'),
  dnsProvider: z.string().regex(/^[a-zA-Z0-9_-]+$/).optional(),
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
  transport: z.enum(['token-http', 'mtls']).default('mtls'),
  requireSignedPayloads: z.boolean().default(false),
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
  conntrackSync: ConntrackSyncSchema.prefault({ enabled: false }),
  sqliteSync: HaSqliteSyncConfigSchema.optional().default({
    enabled: false,
    mode: 'direct_stream',
    databases: ['/var/lib/axonwall/headscale/db.sqlite'],
    syncIntervalSeconds: 5,
    listenPort: 9876,
    transport: 'mtls',
    requireSignedPayloads: false,
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
  defaultEnabled: z.boolean().optional(),
  dependencies: z.array(z.string()).default([]).optional(),
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
  packages: z.object({
    debian: z.array(z.string()).default([]),
    alpine: z.array(z.string()).default([]),
  }).optional(),
  cliBinaries: z.array(z.string()).optional(),
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
    antigravity: AntigravitySettingsSchema.prefault({}),
    ollama: OllamaSettingsSchema.prefault({}),
    claudeCode: ClaudeCodeSettingsSchema.prefault({}),
    codex: CodexSettingsSchema.prefault({}),
    vllm: VllmSettingsSchema.prefault({}),
  }).prefault({}),
});
export type AiConfig = z.infer<typeof AiConfigSchema>;

export const SatelliteNodeSchema = z.object({
  id: z.string(),
  name: z.string(),
  role: z.enum(['satellite', 'edge-ngfw']).default('satellite').optional(),
  edgePlacement: z.enum(['hosted', 'dedicated']).default('hosted').optional(),
  haState: z.enum(['active', 'standby', 'standalone']).default('standalone').optional(),
  ipv6Mode: z.enum(['disabled', 'auto', 'static', 'delegated', 'ula-only']).default('auto').optional(),
  wanIpv6Prefix: z.string().optional(),
  disabledIpv6Interfaces: z.array(z.string()).optional(),
  hardwareOffload: z.boolean().default(false).optional(),
  portForwards: z.array(z.object({
    proto: z.enum(['tcp', 'udp']),
    wanPort: z.number().int().min(1).max(65535),
    targetIp: z.string(),
    targetPort: z.number().int().min(1).max(65535),
    comment: z.string().optional(),
  })).optional(),
  ipv6Allow: z.array(z.object({
    proto: z.enum(['tcp', 'udp', 'ipv6-icmp']),
    dstIp6: z.string(),
    dstPort: z.number().int().min(1).max(65535).optional(),
    comment: z.string().optional(),
  })).optional(),
  zones: z.array(z.object({
    name: z.string(),
    vlanId: z.number().int().min(1).max(4094),
    ipv4Cidr: z.string(),
    ipv6Mode: z.enum(['disabled', 'auto', 'static', 'delegated', 'ula-only']).default('delegated'),
    isolateClients: z.boolean().default(false).optional(),
    allowInternet: z.boolean().default(true).optional(),
  })).optional(),
  skuProfile: z.enum([
    'sku-vm-virtio',
    'sku-x86-intel-n100-i226',
    'sku-x86-enterprise-10g-25g',
    'sku-arm64-router',
    'generic-edge',
  ]).default('sku-vm-virtio').optional(),
  fastpathOffload: z.boolean().default(true).optional(),
  wanInterface: z.string().default('eth0').optional(),
  lanInterface: z.string().default('eth1').optional(),
  wanAddress: z.string().optional(),
  lanAddress: z.string().optional(),
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
  }).prefault({}),
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
    offloadedConns: z.number().int().default(0).optional(),
    rxBytesTotal: z.number().int().default(0),
    txBytesTotal: z.number().int().default(0),
    pid1Mode: z.boolean().optional(),
    kernelVersion: z.string().optional(),
    skuProfile: z.string().optional(),
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
  allowedRoles: z.array(z.string()).default(['admin']),
  // Deliberate open access: any authenticated session may use the app.
  // Distinct from an empty allowedRoles list, which the gateway
  // authorizer treats as admin-only (fail closed, audit B-S3); the
  // previous 'user' default entry was dropped — it is not an
  // appliance role (admin | operator | readonly) and never matched.
  allowAnyAuthenticated: z.boolean().default(false),
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
  virtEnabled: z.boolean().default(false),
  vigilanteEnabled: z.boolean().default(false),
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

// =============================================================================
// Vigilant Octo Waffle (VOW) — K8s GitOps & App Platform (Requires core-k3s)
// =============================================================================

export const VowCdRunnerSchema = z.enum(['argocd', 'flux', 'both']);
export type VowCdRunner = z.infer<typeof VowCdRunnerSchema>;

export const VowAppOverrideSchema = z.object({
  appId: z.string().min(1),
  namespace: z.string().default('default'),
  storageClass: z.enum(['axonwall-replicated-ha', 'axonwall-zfs-local', 'openebs-hostpath', 'default']).default('axonwall-zfs-local'),
  customValuesYaml: z.string().default(''),
  customSubdomain: z.string().optional(),
});
export type VowAppOverride = z.infer<typeof VowAppOverrideSchema>;

export const VowConfigSchema = z.object({
  enabled: z.boolean().default(false),
  cdRunner: VowCdRunnerSchema.default('argocd'),
  domain: z.string().default('vow.axonwall.local'),
  gitRepoUrl: z.string().default('https://github.com/DeployCoop/vigilant-octo-waffle.git'),
  gitBranch: z.string().default('main'),
  fluxInterval: z.string().default('5m'),
  localTlsMkcert: z.boolean().default(true),
  syncUnboundDns: z.boolean().default(true),
  authzEnabled: z.boolean().default(false),
  defaultRole: z.enum(['owner', 'admin', 'operator', 'viewer', 'webhook']).default('admin'),
  activePreset: z.enum(['minimal', 'storage', 'observability', 'ai', 'collaboration', 'full', 'custom']).default('minimal'),
  activeBlueprint: z.string().optional(),
  enabledApps: z.array(z.string()).default(['argocd', 'certmanager']),
  appOverrides: z.array(VowAppOverrideSchema).default([]),
});
export type VowConfig = z.infer<typeof VowConfigSchema>;

// =============================================================================
// Virtualization, KVM/QEMU VMs, LXC Containers, VFIO & Deduplicated Backups
// =============================================================================

export const VmDiskBusSchema = z.enum(['virtio', 'scsi', 'sata', 'ide', 'nvme']);
export type VmDiskBus = z.infer<typeof VmDiskBusSchema>;

export const VmDiskCacheSchema = z.enum(['none', 'writethrough', 'writeback', 'unsafe']);
export type VmDiskCache = z.infer<typeof VmDiskCacheSchema>;

export const VmDiskSchema = z.object({
  id: z.string().optional(),
  name: z.string().default('disk0'),
  pool: z.string().default('tank'),
  zvol: z.string().optional(),
  sizeGb: z.number().int().min(1).default(32),
  bus: VmDiskBusSchema.default('virtio'),
  cache: VmDiskCacheSchema.default('none'),
  discard: z.boolean().default(true),
  iopsReadLimit: z.number().int().min(0).default(0),
  iopsWriteLimit: z.number().int().min(0).default(0),
  readOnly: z.boolean().default(false),
  backup: z.boolean().default(true),
});
export type VmDisk = z.infer<typeof VmDiskSchema>;

export const VmNicModelSchema = z.enum(['virtio', 'e1000', 'e1000e', 'vmxnet3']);
export type VmNicModel = z.infer<typeof VmNicModelSchema>;

export const VmNicSchema = z.object({
  id: z.string().optional(),
  mac: z.string().default(''),
  bridge: z.string().default('br0'),
  vlanTag: z.number().int().min(0).max(4094).optional(),
  vnet: z.string().optional(),
  model: VmNicModelSchema.default('virtio'),
  firewall: z.boolean().default(true),
  rateLimitMbps: z.number().int().min(0).default(0),
  attachMode: z.enum(['bridge', 'macvtap-passthru', 'vfio']).default('bridge').optional(),
  hostDevice: z.string().optional(),
  queues: z.number().int().min(1).max(16).optional(),
  pciAddr: z.string().optional(),
});
export type VmNic = z.infer<typeof VmNicSchema>;

export const CloudInitConfigSchema = z.object({
  user: z.string().default('axonadmin'),
  password: z.string().optional(),
  sshAuthorizedKeys: z.array(z.string()).default([]),
  ipConfig: z.string().default('dhcp'),
  gateway: z.string().optional(),
  nameservers: z.array(z.string()).default([]),
  searchDomain: z.string().optional(),
  customUserData: z.string().optional(),
});
export type CloudInitConfig = z.infer<typeof CloudInitConfigSchema>;

export const VirtualMachineSchema = z.object({
  id: z.string().optional(),
  vmid: z.number().int().min(100).max(99999),
  name: z.string().min(1).regex(/^[a-zA-Z0-9_.-]+$/),
  description: z.string().max(255).default(''),
  osType: z.enum(['linux', 'windows', 'freebsd', 'other']).default('linux'),
  bios: z.enum(['ovmf', 'seabios']).default('ovmf'),
  secureBoot: z.boolean().default(false),
  tpm2: z.boolean().default(false),
  sockets: z.number().int().min(1).max(8).default(1),
  cores: z.number().int().min(1).max(128).default(2),
  cpuType: z.enum(['host', 'x86-64-v2-AES', 'kvm64', 'qemu64']).default('host'),
  memoryMb: z.number().int().min(128).default(2048),
  balloonMinMb: z.number().int().min(0).default(0),
  disks: z.array(VmDiskSchema).default([]),
  diskless: z.boolean().default(false).optional(),
  kernelPath: z.string().optional(),
  initrdPath: z.string().optional(),
  kernelArgs: z.string().optional(),
  fwCfg: z.array(z.object({ name: z.string(), file: z.string() })).optional(),
  watchdog: z.enum(['none', 'i6300esb', 'ib700']).default('none').optional(),
  nics: z.array(VmNicSchema).default([]),
  iso: z.string().optional(),
  cloudInit: CloudInitConfigSchema.optional(),
  pciPassthrough: z.array(z.string()).default([]),
  usbPassthrough: z.array(z.string()).default([]),
  autostart: z.boolean().default(false),
  haManaged: z.boolean().default(false),
  agent: z.boolean().default(true),
  enabled: z.boolean().default(true),
});
export type VirtualMachine = z.infer<typeof VirtualMachineSchema>;

export const LxcMountPointSchema = z.object({
  id: z.string().optional(),
  mountPath: z.string().min(1),
  hostPath: z.string().min(1),
  readOnly: z.boolean().default(false),
});
export type LxcMountPoint = z.infer<typeof LxcMountPointSchema>;

export const LxcContainerSchema = z.object({
  id: z.string().optional(),
  ctid: z.number().int().min(100).max(99999),
  hostname: z.string().min(1).regex(/^[a-zA-Z0-9_.-]+$/),
  description: z.string().max(255).default(''),
  template: z.string().min(1).default('debian-12-standard'),
  unprivileged: z.boolean().default(true),
  cores: z.number().int().min(1).max(128).default(1),
  memoryMb: z.number().int().min(256).default(1024),
  swapMb: z.number().int().min(0).default(512),
  rootfsPool: z.string().default('tank'),
  rootfsSizeGb: z.number().int().min(1).default(8),
  mountPoints: z.array(LxcMountPointSchema).default([]),
  nics: z.array(VmNicSchema).default([]),
  dnsServers: z.array(z.string()).default([]),
  searchDomain: z.string().optional(),
  features: z.array(z.enum(['nesting', 'keyctl', 'fuse'])).default(['nesting']),
  autostart: z.boolean().default(false),
  haManaged: z.boolean().default(false),
  enabled: z.boolean().default(true),
});
export type LxcContainer = z.infer<typeof LxcContainerSchema>;

export const IsoImageSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1),
  url: z.string().optional(),
  sha256: z.string().optional(),
  pool: z.string().default('tank'),
  path: z.string().optional(),
  sizeBytes: z.number().nonnegative().default(0),
});
export type IsoImage = z.infer<typeof IsoImageSchema>;

export const PciPassthroughDeviceSchema = z.object({
  id: z.string().optional(),
  bdf: z.string().regex(/^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$/),
  vendorId: z.string().optional(),
  deviceId: z.string().optional(),
  deviceClass: z.string().optional(),
  iommuGroup: z.number().int().min(0).default(0),
  driver: z.enum(['vfio-pci', 'host', 'other']).default('vfio-pci'),
  sriovNumVfs: z.number().int().min(0).default(0),
  description: z.string().max(255).default(''),
});
export type PciPassthroughDevice = z.infer<typeof PciPassthroughDeviceSchema>;

export const BackupRetentionSchema = z.object({
  keepLast: z.number().int().min(1).default(5),
  keepDaily: z.number().int().min(0).default(7),
  keepWeekly: z.number().int().min(0).default(4),
  keepMonthly: z.number().int().min(0).default(12),
});
export type BackupRetention = z.infer<typeof BackupRetentionSchema>;

export const WorkloadBackupJobSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1),
  scheduleCron: z.string().default('0 1 * * *'),
  targetType: z.enum(['all', 'selected']).default('all'),
  targetVmids: z.array(z.number().int()).default([]),
  targetCtids: z.array(z.number().int()).default([]),
  storagePool: z.string().default('tank'),
  destinationType: z.enum(['local-zfs', 's3', 'pbs']).default('local-zfs'),
  s3Bucket: z.string().optional(),
  s3Endpoint: z.string().optional(),
  pbsServer: z.string().optional(),
  pbsDatastore: z.string().optional(),
  encryptionKey: z.string().optional(),
  compression: z.enum(['zstd', 'lz4', 'gzip', 'none']).default('zstd'),
  retention: BackupRetentionSchema.default({ keepLast: 5, keepDaily: 7, keepWeekly: 4, keepMonthly: 12 }),
  enabled: z.boolean().default(true),
});
export type WorkloadBackupJob = z.infer<typeof WorkloadBackupJobSchema>;

export const VxlanZoneSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1).regex(/^[a-zA-Z0-9_-]+$/),
  vni: z.number().int().min(1).max(16777215),
  peers: z.array(z.string()).default([]),
  underlayInterface: z.string().default('lan'),
  multicastGroup: z.string().optional(),
  port: z.number().int().default(4789),
  bridge: z.string().default(''),
  mtu: z.number().int().min(1200).max(9000).default(1450),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type VxlanZone = z.infer<typeof VxlanZoneSchema>;

export const VirtConfigSchema = z.object({
  enabled: z.boolean().default(false),
  defaultPool: z.string().default('tank'),
  isoPool: z.string().default('tank'),
  vms: z.array(VirtualMachineSchema).default([]),
  containers: z.array(LxcContainerSchema).default([]),
  isos: z.array(IsoImageSchema).default([]),
  pciDevices: z.array(PciPassthroughDeviceSchema).default([]),
  backupJobs: z.array(WorkloadBackupJobSchema).default([]),
  vxlanZones: z.array(VxlanZoneSchema).default([]),
});
export type VirtConfig = z.infer<typeof VirtConfigSchema>;

// =============================================================================
// Vigilante Cyber Defense, SOAR, Deception, Forensics & Modular SOC
// =============================================================================

export const VigilanteModuleIdSchema = z.enum([
  'vigil-soc',
  'vigil-local',
  'opensearch',
  'wazuh',
  'bloodhound',
  'falco',
  'suricata',
  'zeek',
  'zap',
  'flamingo',
  'kctf',
  'openvas',
]);
export type VigilanteModuleId = z.infer<typeof VigilanteModuleIdSchema>;

export const VigilanteModuleConfigSchema = z.object({
  id: VigilanteModuleIdSchema,
  name: z.string().optional(),
  enabled: z.boolean().default(false),
  namespace: z.string().default('vigilante-soc'),
  storageClass: z.enum(['axonwall-replicated-ha', 'axonwall-zfs-local', 'default']).default('axonwall-zfs-local'),
  storageSizeGb: z.number().int().min(1).default(10),
  ingressHostname: z.string().optional(),
  customValuesYaml: z.string().default(''),
});
export type VigilanteModuleConfig = z.infer<typeof VigilanteModuleConfigSchema>;

export const VigilanteSoarPolicySchema = z.object({
  autoBlockC2Ips: z.boolean().default(true),
  autoIsolateCompromisedPods: z.boolean().default(true),
  autoFreezeRansomwarePods: z.boolean().default(true),
  ransomwareEntropyDeltaThreshold: z.number().default(2.0),
  warRoomQuorumThreshold: z.number().min(0.5).max(1.0).default(0.75),
  blocklistTimeoutSeconds: z.number().int().min(0).default(86400),
});
export type VigilanteSoarPolicy = z.infer<typeof VigilanteSoarPolicySchema>;

export const McpServerConfigSchema = z.object({
  enabled: z.boolean().default(true),
  disabledReason: z.string().optional(),
});
export type McpServerConfig = z.infer<typeof McpServerConfigSchema>;

// =============================================================================
// Host Malware, Rootkit & Ring-0 ("Ghost in the Ring") Defense Suite
// =============================================================================

export const HostMalwareDefenseConfigSchema = z.object({
  enabled: z.boolean().default(true),
  // Classic Host Malware, Rootkit & File Integrity Scanners
  rkhunterEnabled: z.boolean().default(true),
  chkrootkitEnabled: z.boolean().default(true),
  clamavEnabled: z.boolean().default(false),
  aideEnabled: z.boolean().default(true),
  lynisEnabled: z.boolean().default(true),
  yaraEnabled: z.boolean().default(true),
  unhideEnabled: z.boolean().default(true),
  debsumsEnabled: z.boolean().default(true),
  scheduledScanCron: z.string().regex(
    /^[0-9*,/-]+\s+[0-9*,/-]+\s+[0-9*,/-]+\s+[0-9*,/-]+\s+[0-9*,/-]+$/,
    'Invalid 5-field cron expression',
  ).default('0 3 * * *'),
  // Ghost in the Ring: io_uring Syscall-Less Implant Hardening & Hunting (Curing / RingReaper)
  ioUringDisabledMode: z.enum(['0', '1', '2']).default('1'),
  ioUringAllowedGid: z.number().int().min(0).max(65535).default(994),
  blockIoUringSqpoll: z.boolean().default(true),
  // Ghost in the Ring: Offensive eBPF Rootkit Lockdown & Out-of-Band Detection (TripleCross / Boopkit / Symbiote)
  unprivilegedBpfDisabled: z.boolean().default(true),
  bpfJitHardenMode: z.enum(['0', '1', '2']).default('2'),
  kernelLockdownMode: z.enum(['none', 'integrity', 'confidentiality']).default('confidentiality'),
  bpfLsmGuardEnabled: z.boolean().default(true),
  trustedBpfLoaderPaths: z.array(
    z.string().regex(/^\/[a-zA-Z0-9._/-]+$/, 'Trusted BPF loader path must be a safe absolute path'),
  ).default([
    '/usr/sbin/bpftool',
    '/usr/local/bin/axonwalld',
  ]),
  progIdrKcoreDiffEnabled: z.boolean().default(true),
  pmuLbrBranchTracingEnabled: z.boolean().default(true),
  autoQuarantineOnCritical: z.boolean().default(true),
});
export type HostMalwareDefenseConfig = z.infer<typeof HostMalwareDefenseConfigSchema>;

export const VigilanteDeceptionConfigSchema = z.object({
  enabled: z.boolean().default(true),
  canaryServiceAccounts: z.array(z.string()).default(['cluster-admin-backup', 'vault-sync-sa']),
  honeytokens: z.array(z.enum(['aws-sts', 'github-pat', 'slack-webhook', 'kubeconfig'])).default(['aws-sts', 'kubeconfig']),
  decoyServices: z.array(z.enum(['smb', 'ssh', 'redis', 'mssql'])).default([]),
  ransomwareCanaryDirs: z.array(z.string()).default(['/mnt/tank/shares']),
});
export type VigilanteDeceptionConfig = z.infer<typeof VigilanteDeceptionConfigSchema>;

export const VigilanteEvidenceVaultConfigSchema = z.object({
  zfsPool: z.string().default('tank'),
  datasetName: z.string().default('vigilante-evidence'),
  dataLakeBackend: z.enum(['sqlite', 'duckdb']).default('sqlite'),
  gpgEnabled: z.boolean().default(false),
  gpgKeyId: z.string().default(''),
  merkleLedgerEnabled: z.boolean().default(true),
});
export type VigilanteEvidenceVaultConfig = z.infer<typeof VigilanteEvidenceVaultConfigSchema>;

export const VigilanteFederationConfigSchema = z.object({
  enabled: z.boolean().default(false),
  nodeName: z.string().default('axonwall-soc-primary'),
  peers: z.array(z.string()).default([]),
  autoIngestPeerBlocks: z.boolean().default(true),
});
export type VigilanteFederationConfig = z.infer<typeof VigilanteFederationConfigSchema>;

export const VigilanteConfigSchema = z.object({
  enabled: z.boolean().default(false),
  posture: z.enum(['monitoring', 'hybrid', 'enforcing']).default('hybrid'),
  domain: z.string().default('vigilante.local'),
  modules: z.array(VigilanteModuleConfigSchema).default([
    { id: 'vigil-soc', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 20, customValuesYaml: '' },
    { id: 'opensearch', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 50, customValuesYaml: '' },
    { id: 'wazuh', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 30, customValuesYaml: '' },
    { id: 'falco', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 5, customValuesYaml: '' },
    { id: 'suricata', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 10, customValuesYaml: '' },
    { id: 'zeek', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 10, customValuesYaml: '' },
    { id: 'bloodhound', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 15, customValuesYaml: '' },
    { id: 'zap', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 5, customValuesYaml: '' },
    { id: 'flamingo', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 5, customValuesYaml: '' },
    { id: 'kctf', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 20, customValuesYaml: '' },
    { id: 'openvas', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 30, customValuesYaml: '' },
    { id: 'vigil-local', enabled: false, namespace: 'vigilante-soc', storageClass: 'axonwall-zfs-local', storageSizeGb: 5, customValuesYaml: '' },
  ]),
  soar: VigilanteSoarPolicySchema.default({
    autoBlockC2Ips: true,
    autoIsolateCompromisedPods: true,
    autoFreezeRansomwarePods: true,
    ransomwareEntropyDeltaThreshold: 2.0,
    warRoomQuorumThreshold: 0.75,
    blocklistTimeoutSeconds: 86400,
  }),
  deception: VigilanteDeceptionConfigSchema.default({
    enabled: true,
    canaryServiceAccounts: ['cluster-admin-backup', 'vault-sync-sa'],
    honeytokens: ['aws-sts', 'kubeconfig'],
    decoyServices: [],
    ransomwareCanaryDirs: ['/mnt/tank/shares'],
  }),
  evidenceVault: VigilanteEvidenceVaultConfigSchema.default({
    zfsPool: 'tank',
    datasetName: 'vigilante-evidence',
    dataLakeBackend: 'sqlite',
    gpgEnabled: false,
    gpgKeyId: '',
    merkleLedgerEnabled: true,
  }),
  federation: VigilanteFederationConfigSchema.default({
    enabled: false,
    nodeName: 'axonwall-soc-primary',
    peers: [],
    autoIngestPeerBlocks: true,
  }),
});
export type VigilanteConfig = z.infer<typeof VigilanteConfigSchema>;

export const ApplianceRoleSchema = z.enum(['admin', 'operator', 'readonly', 'os_only']);
export type ApplianceRole = z.infer<typeof ApplianceRoleSchema>;

export const LocalUserSchema = z.object({
  username: z.string().min(1).max(32).regex(/^[a-z_][a-z0-9_-]{0,31}$/, 'Invalid Linux username'),
  uid: z.number().int().nonnegative(),
  gid: z.number().int().nonnegative(),
  comment: z.string().default(''),
  homeDir: z.string().default(''),
  shell: z.string().default(''),
  groups: z.array(z.string()).default([]),
  primaryGroup: z.string().default(''),
  isSystem: z.boolean().default(false),
  protected: z.boolean().default(false),
  applianceRole: ApplianceRoleSchema.default('os_only'),
  hasSSHKeys: z.boolean().default(false),
  sshKeysCount: z.number().int().default(0),
  sshKeys: z.array(z.string()).optional(),
  hasPassword: z.boolean().default(false),
  passwordLocked: z.boolean().default(false),
});
export type LocalUser = z.infer<typeof LocalUserSchema>;

export const LocalGroupSchema = z.object({
  name: z.string().min(1).max(32),
  gid: z.number().int().nonnegative(),
  members: z.array(z.string()).default([]),
  isSystem: z.boolean().default(false),
  protected: z.boolean().default(false),
});
export type LocalGroup = z.infer<typeof LocalGroupSchema>;

export const CreateLocalUserRequestSchema = z.object({
  username: z.string().min(1).max(32).regex(/^[a-z_][a-z0-9_-]{0,31}$/, 'Invalid Linux username'),
  comment: z.string().optional(),
  password: z.string().optional(),
  shell: z.string().optional(),
  applianceRole: ApplianceRoleSchema.optional(),
  groups: z.array(z.string()).optional(),
  sshKeys: z.array(z.string()).optional(),
});
export type CreateLocalUserRequest = z.infer<typeof CreateLocalUserRequestSchema>;

export const UpdateLocalUserRequestSchema = z.object({
  comment: z.string().optional(),
  password: z.string().optional(),
  shell: z.string().optional(),
  applianceRole: ApplianceRoleSchema.optional(),
  groups: z.array(z.string()).optional(),
  sshKeys: z.array(z.string()).optional(),
  passwordLocked: z.boolean().optional(),
});
export type UpdateLocalUserRequest = z.infer<typeof UpdateLocalUserRequestSchema>;

export const AuthLocalUserRequestSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});
export type AuthLocalUserRequest = z.infer<typeof AuthLocalUserRequestSchema>;

export const AuthLocalUserResponseSchema = z.object({
  success: z.boolean(),
  username: z.string(),
  applianceRole: ApplianceRoleSchema,
  groups: z.array(z.string()),
  message: z.string().optional(),
});
export type AuthLocalUserResponse = z.infer<typeof AuthLocalUserResponseSchema>;

export const PasswordPolicySchema = z.object({
  minLength: z.number().int().min(8).max(128).default(12),
  maxFailures: z.number().int().min(0).max(50).default(5),
  lockoutDurationSeconds: z.number().int().min(60).max(86400).default(900),
  historyCount: z.number().int().min(0).max(24).default(5),
  maxAgeDays: z.number().int().min(0).max(3650).default(0), // 0 = no expiry
});
export type PasswordPolicy = z.infer<typeof PasswordPolicySchema>;

export const IdentityConfigSchema = z.object({
  baseDn: z.string().optional(), // Derived from system.domain on first bootstrap
  disableRootSshWhenAdminExists: z.boolean().default(true),
  passwordPolicy: PasswordPolicySchema.default({
    minLength: 12,
    maxFailures: 5,
    lockoutDurationSeconds: 900,
    historyCount: 5,
    maxAgeDays: 0,
  }),
});
export type IdentityConfig = z.infer<typeof IdentityConfigSchema>;

// =============================================================================
// Eluvix Sovereign AI Router, Enterprise Tokenomics & Prompt/PII Guard Suite
// =============================================================================

export const EluvixTokenomicsSchema = z.object({
  strategy: z.enum(['cost-complexity', 'prefill-isolation', 'lowest-latency', 'round-robin', 'priority']).default('cost-complexity'),
  semanticCacheEnabled: z.boolean().default(true),
  semanticCacheSimilarityThreshold: z.number().min(0.5).max(1.0).default(0.92),
  semanticCacheBackend: z.enum(['sqlite', 'redis', 'milvus']).default('sqlite'),
  kvPrefixAffinityEnabled: z.boolean().default(true),
  prefillIsolationThresholdTokens: z.number().int().min(128).max(131072).default(1024),
  kvArchitecture: z.enum(['deepseek-mla-fp8', 'gqa-fp8', 'gqa-bf16']).default('deepseek-mla-fp8'),
  rdmaConnector: z.enum(['none', 'vllm-nixl', 'sglang-mooncake']).default('vllm-nixl'),
  monthlyPromptVolumeMillions: z.number().min(0.1).max(100000).default(50),
  localOffloadTargetPct: z.number().min(0).max(100).default(70),
});
export type EluvixTokenomics = z.infer<typeof EluvixTokenomicsSchema>;

export const EluvixPromptGuardSchema = z.object({
  enabled: z.boolean().default(true),
  mode: z.enum(['heuristic', 'classifier', 'llm-guard']).default('heuristic'),
  threshold: z.number().min(0.1).max(1.0).default(0.80),
  enforcementAction: z.enum(['block', 'strip', 'divert', 'warn']).default('block'),
  instructionOverride: z.boolean().default(true),
  danJailbreak: z.boolean().default(true),
  systemPromptLeak: z.boolean().default(true),
  obfuscation: z.boolean().default(true),
  bannedPhrases: z.array(z.string()).default([]),
});
export type EluvixPromptGuard = z.infer<typeof EluvixPromptGuardSchema>;

export const EluvixPrivacyGuardSchema = z.object({
  enabled: z.boolean().default(true),
  action: z.enum(['anonymize', 'block', 'warn']).default('anonymize'),
  redactionStyle: z.enum(['token', 'asterisk', 'hash']).default('token'),
  detectEmail: z.boolean().default(true),
  detectSsn: z.boolean().default(true),
  detectCreditCard: z.boolean().default(true),
  detectApiKey: z.boolean().default(true),
  detectIpAddress: z.boolean().default(false),
  detectPhone: z.boolean().default(true),
  auditLogging: z.boolean().default(true),
  whitelist: z.array(z.string()).default([]),
});
export type EluvixPrivacyGuard = z.infer<typeof EluvixPrivacyGuardSchema>;

export const EluvixHarnessMeshSchema = z.object({
  enabled: z.boolean().default(true),
  defaultHarness: z.enum(['opencode', 'trueforge', 'acp', 'openhands', 'mastra', 'letta', 'a2a', 'hermes']).default('opencode'),
  enabledHarnesses: z.array(
    z.enum(['opencode', 'trueforge', 'acp', 'openhands', 'mastra', 'letta', 'a2a', 'hermes']),
  ).default(['opencode', 'trueforge', 'acp', 'openhands']),
  approvalPolicy: z.enum(['auto-deny', 'auto-approve-readonly', 'read-only', 'surface']).default('auto-approve-readonly'),
  sandboxBackend: z.enum(['docker-local', 'gvisor', 'firecracker']).default('gvisor'),
  memoryEngine: z.enum(['graphiti', 'mem0', 'letta', 'lightrag']).default('graphiti'),
  injectAxonwallMcp: z.boolean().default(true),
});
export type EluvixHarnessMesh = z.infer<typeof EluvixHarnessMeshSchema>;

export const EluvixConfigSchema = z.object({
  enabled: z.boolean().default(false),
  deploymentMode: z.enum(['systemd', 'docker', 'k3s-helm']).default('systemd'),
  listenPort: z.number().int().min(1).max(65535).default(3588),
  switchyardPort: z.number().int().min(1).max(65535).default(8080),
  domain: z.string().default('eluvix.axonwall.local'),
  gitRepoUrl: z.string().default('git@github.com:Eluvixrouter/eluvix.git'),
  samePortTlsAutoUpgrade: z.boolean().default(true),
  syncUnboundDns: z.boolean().default(true),
  routeAxonwallCopilotThroughEluvix: z.boolean().default(true),
  teePolicy: z.enum(['disabled', 'prefer-tee', 'require-tee', 'require-dual-attestation']).default('prefer-tee'),
  tokenomics: EluvixTokenomicsSchema.default({
    strategy: 'cost-complexity',
    semanticCacheEnabled: true,
    semanticCacheSimilarityThreshold: 0.92,
    semanticCacheBackend: 'sqlite',
    kvPrefixAffinityEnabled: true,
    prefillIsolationThresholdTokens: 1024,
    kvArchitecture: 'deepseek-mla-fp8',
    rdmaConnector: 'vllm-nixl',
    monthlyPromptVolumeMillions: 50,
    localOffloadTargetPct: 70,
  }),
  promptGuard: EluvixPromptGuardSchema.default({
    enabled: true,
    mode: 'heuristic',
    threshold: 0.80,
    enforcementAction: 'block',
    instructionOverride: true,
    danJailbreak: true,
    systemPromptLeak: true,
    obfuscation: true,
    bannedPhrases: [],
  }),
  privacyGuard: EluvixPrivacyGuardSchema.default({
    enabled: true,
    action: 'anonymize',
    redactionStyle: 'token',
    detectEmail: true,
    detectSsn: true,
    detectCreditCard: true,
    detectApiKey: true,
    detectIpAddress: false,
    detectPhone: true,
    auditLogging: true,
    whitelist: [],
  }),
  harnessMesh: EluvixHarnessMeshSchema.default({
    enabled: true,
    defaultHarness: 'opencode',
    enabledHarnesses: ['opencode', 'trueforge', 'acp', 'openhands'],
    approvalPolicy: 'auto-approve-readonly',
    sandboxBackend: 'gvisor',
    memoryEngine: 'graphiti',
    injectAxonwallMcp: true,
  }),
});
export type EluvixConfig = z.infer<typeof EluvixConfigSchema>;

export const HostedEdgeConfigSchema = z.object({
  enabled: z.boolean().default(false),
  placement: z.enum(['hosted', 'dedicated']).default('hosted'),
  ukiSlot: z.enum(['A', 'B']).default('A'),
  skuProfile: z.enum(['sku-vm-virtio', 'sku-x86-intel-n100-i226', 'sku-x86-enterprise-10g-25g', 'sku-arm64-router']).default('sku-vm-virtio'),
  vcpus: z.number().int().min(1).max(64).default(2),
  memoryMiB: z.number().int().min(128).max(65536).default(256),
  wan: z.object({
    hostDevice: z.string().default('eth0'),
    bridgeName: z.string().default('br-wan'),
    attachMode: z.enum(['bridge', 'macvtap-passthru', 'vfio']).default('bridge'),
    macAddress: z.string().optional(),
    ipv4Mode: z.enum(['dhcp', 'static', 'disabled']).default('dhcp'),
    ipv4Address: z.string().optional(),
    ipv4Gateway: z.string().optional(),
    ipv6Mode: z.enum(['disabled', 'auto', 'static']).default('auto'),
    ipv6RequestPrefix: z.number().int().min(48).max(64).default(56),
  }).prefault({}),
  lan: z.object({
    bridgeName: z.string().default('br-lan'),
    edgeAddress: z.string().default('10.0.0.1/24'),
    hostAddress: z.string().default('10.0.0.2/24'),
    ipv6Mode: z.enum(['disabled', 'delegated', 'ula-only', 'static']).default('delegated'),
    ulaPrefix: z.string().optional(),
  }).prefault({}),
  ha: z.object({
    enabled: z.boolean().default(true),
    role: z.enum(['active', 'standby']).default('active'),
    syncVlanId: z.number().int().min(1).max(4094).default(4001),
    wanTransitVlanId: z.number().int().min(1).max(4094).default(4000),
    sharedWanMac: z.string().optional(),
  }).prefault({}),
  portForwards: z.array(z.object({
    proto: z.enum(['tcp', 'udp']),
    wanPort: z.number().int().min(1).max(65535),
    targetIp: z.string(),
    targetPort: z.number().int().min(1).max(65535),
    comment: z.string().optional(),
  })).default([]),
  ipv6Allow: z.array(z.object({
    proto: z.enum(['tcp', 'udp', 'ipv6-icmp']),
    dstIp6: z.string(),
    dstPort: z.number().int().min(1).max(65535).optional(),
    comment: z.string().optional(),
  })).default([]),
});
export type HostedEdgeConfig = z.infer<typeof HostedEdgeConfigSchema>;

export const DesiredStateSchema = z.object({
  version: z.number().int().default(1),
  capabilities: CoreCapabilitiesSchema.optional(),
  system: SystemSettingsSchema.prefault({}),
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
  dns: DnsConfigSchema.prefault({ enabled: true, hostOverrides: [] }),
  routes: z.array(StaticRouteSchema).default([]),
  trafficShaper: TrafficShaperConfigSchema.optional(),
  wireguard: WireGuardConfigSchema.optional(),
  rosenpass: RosenpassConfigSchema.optional(),
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
  identity: IdentityConfigSchema.optional(),
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
  vow: VowConfigSchema.optional(),
  virt: VirtConfigSchema.optional(),
  hostedEdge: HostedEdgeConfigSchema.optional(),
  vigilante: VigilanteConfigSchema.optional(),
  hostDefense: HostMalwareDefenseConfigSchema.optional(),
  eluvix: EluvixConfigSchema.optional(),
  mcp: McpServerConfigSchema.optional(),
});
export type DesiredState = z.infer<typeof DesiredStateSchema>;




