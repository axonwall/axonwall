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
  device: z.string().min(1).max(15).regex(/^[a-zA-Z0-9_.:-]+$/, 'Invalid device identifier'), // e.g. "eth0", "enp1s0", "ens18"
  role: InterfaceRoleSchema.optional(),
  ipv6Mode: z.enum(['disabled', 'auto', 'static', 'delegated', 'ula-only']).optional(),
  dhcpServer: z.boolean().optional(),
  type: InterfaceTypeSchema.default('static'),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
  ipv4Address: z.string().refine((val) => val === '' || isValidCIDR(val) || isValidIPv4(val), {
    message: 'Invalid IPv4 address or CIDR',
  }).optional(),
  ipv4Gateway: z.string().refine((val) => val === '' || isValidIPv4(val), {
    message: 'Invalid IPv4 gateway',
  }).optional(),
  ipv6Address: z.string().refine((val) => val === '' || isValidCIDR(val) || isValidIPv6(val), {
    message: 'Invalid IPv6 address or CIDR',
  }).optional(),
  ipv6Gateway: z.string().refine((val) => val === '' || isValidIPv6(val), {
    message: 'Invalid IPv6 gateway',
  }).optional(),
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
  if (!val || /[;#\r\n"'{}]|[\s]/.test(val)) return false;
  if (val === 'any' || val === 'wan_ip' || val === 'lan_net' || val === 'self') return true;
  if (isValidIPv4(val) || isValidIPv6(val) || isValidCIDR(val)) return true;
  if (/^\$[a-zA-Z0-9_-]+$/.test(val)) return true;
  return false;
}

export function isValidPortSpec(val: string): boolean {
  if (!val || /[;#\r\n\t"'{}]/.test(val)) return false;
  if (/^\$[a-zA-Z0-9_-]+$/.test(val)) return true;
  if (/\s/.test(val.replace(/, */g, ','))) return false;
  return isValidPortRange(val);
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
  invertSource: z.boolean().default(false).optional(),
  sourcePort: z.string().refine((val) => val === '' || val === 'any' || isValidPortSpec(val), {
    message: 'Invalid source port range or alias',
  }).default(''),
  destination: z.string().refine(isValidFirewallEndpoint, {
    message: 'Invalid destination endpoint (must be any, wan_ip, lan_net, self, IP, CIDR, or $alias)',
  }).default('any'),
  invertDestination: z.boolean().default(false).optional(),
  destinationPort: z.string().refine((val) => val === '' || val === 'any' || isValidPortSpec(val), {
    message: 'Invalid destination port range or alias',
  }).default(''),
  gateway: z.string().optional(), // for policy routing
  gatewayGroup: z.string().optional(), // for multi-WAN policy routing
  dscp: z
    .union([
      z.number().int().min(0).max(63),
      z.string().regex(/^(?:[0-9]|[1-5][0-9]|6[0-3]|cs[0-7]|ef|af[1-4][1-3]|va|le)$/i),
    ])
    .optional(), // QoS DSCP codepoint or DiffServ class match
  rateLimitPps: z.number().int().min(0).max(10000000).optional(), // per-rule PPS limit
  schedule: z.string().max(128).optional(), // time schedule e.g. 08:00-18:00
  log: z.boolean().default(false),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
  sortOrder: z.number().int().default(100),
});
export type FirewallRule = z.infer<typeof FirewallRuleSchema>;

export const NatTypeSchema = z.enum(['dnat', 'snat', 'masquerade', 'binat', 'nptv6']);

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
  }).optional(), // translated internal IP or NPTv6 prefix
  targetPort: z.string().refine((v) => !v || v === 'any' || (!v.includes(',') && !v.startsWith('$') && isValidPortRange(v)), {
    message: 'Invalid NAT target port',
  }).optional(), // translated internal port (single port or start-end range)
  natReflection: z.boolean().optional(), // hairpin NAT reflection override
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
  dnsServers: z
    .array(
      z.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), {
        message: 'Invalid DNS server IP',
      }),
    )
    .default(['1.1.1.1', '8.8.8.8']),
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

export const Dhcp6StaticMappingSchema = z.object({
  id: z.string().uuid().optional(),
  duid: z.string().min(4).max(128).regex(/^[0-9a-fA-F:-]+$/, 'Invalid DHCPv6 DUID'),
  ip6: z.string().refine(isValidIPv6, { message: 'Invalid IPv6 address' }),
  hostname: z.string().optional(),
  description: z.string().max(255).default(''),
});
export type Dhcp6StaticMapping = z.infer<typeof Dhcp6StaticMappingSchema>;

export const Dhcp6SubnetSchema = z.object({
  id: z.string().uuid().optional(),
  interface: z.string().min(1),
  subnet: z.string().refine((val) => val.includes(':') && isValidCIDR(val), {
    message: 'Invalid IPv6 subnet CIDR',
  }),
  poolStart: z.string().refine(isValidIPv6, { message: 'Invalid IPv6 pool start' }).optional(),
  poolEnd: z.string().refine(isValidIPv6, { message: 'Invalid IPv6 pool end' }).optional(),
  delegatedPrefix: z.string().refine((val) => !val || (val.includes(':') && isValidCIDR(val)), {
    message: 'Invalid IA_PD delegated prefix CIDR',
  }).optional(),
  delegatedLen: z.number().int().min(48).max(64).default(60),
  raMode: z.enum(['slaac', 'managed', 'assisted', 'stateless_dhcp', 'disabled']).default('assisted'),
  dnsServers: z.array(z.string().refine(isValidIPv6, { message: 'Invalid IPv6 DNS server' })).default([]),
  domainSearchList: z.array(z.string()).default([]),
  staticMappings: z.array(Dhcp6StaticMappingSchema).default([]),
  enabled: z.boolean().default(true),
});
export type Dhcp6Subnet = z.infer<typeof Dhcp6SubnetSchema>;

export const DhcpConfigSchema = z.object({
  enabled: z.boolean().default(true),
  subnets: z.array(DhcpSubnetSchema).default([]),
  dhcp6Enabled: z.boolean().default(false).optional(),
  subnets6: z.array(Dhcp6SubnetSchema).default([]).optional(),
  logLeases: z.boolean().default(false).optional(),
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
  autoRegisterVirtHosts: z.boolean().default(true).optional(),
  autoRegisterK3sIngresses: z.boolean().default(true).optional(),
  logQueries: z.boolean().default(false).optional(),
});
export type DnsConfig = z.infer<typeof DnsConfigSchema>;

export const MdnsReflectorConfigSchema = z.object({
  enabled: z.boolean().default(false),
  interfaces: z.array(z.string().min(1).regex(/^[a-zA-Z0-9_.-]+$/)).default([]),
  enableIpv6: z.boolean().default(true),
  allowSsdpDiscovery: z.boolean().default(false),
  description: z.string().max(255).default('Cross-VLAN mDNS / Bonjour / Matter Reflector'),
});
export type MdnsReflectorConfig = z.infer<typeof MdnsReflectorConfigSchema>;

export const UpnpAclRuleSchema = z.object({
  id: z.string().optional(),
  action: z.enum(['allow', 'deny']).default('allow'),
  externalPorts: z.string().regex(/^\d+(?:-\d+)?$/, 'Port or range e.g. 1024-65535').default('1024-65535'),
  internalCidr: z.string().refine(isValidCIDR, { message: 'Invalid internal subnet CIDR' }),
  internalPorts: z.string().regex(/^\d+(?:-\d+)?$/, 'Port or range e.g. 1024-65535').default('1024-65535'),
  description: z.string().max(128).default(''),
});
export type UpnpAclRule = z.infer<typeof UpnpAclRuleSchema>;

export const UpnpConfigSchema = z.object({
  enabled: z.boolean().default(false),
  externalInterface: z.string().default('wan'),
  internalInterfaces: z.array(z.string().min(1).regex(/^[a-zA-Z0-9_.-]+$/)).default(['lan']),
  enableUpnp: z.boolean().default(true),
  enableNatPmp: z.boolean().default(true),
  secureMode: z.boolean().default(true),
  stunHost: z.string().optional(),
  acls: z.array(UpnpAclRuleSchema).default([]),
});
export type UpnpConfig = z.infer<typeof UpnpConfigSchema>;

export const DdnsEntrySchema = z.object({
  id: z.string().optional(),
  provider: z.enum(['cloudflare', 'route53', 'duckdns', 'desec', 'linode', 'custom']).default('cloudflare'),
  hostname: z.string().min(1).regex(/^[a-zA-Z0-9_.-]+$/, 'Invalid DDNS hostname'),
  zone: z.string().optional(),
  interface: z.string().default('wan'),
  ipVersion: z.enum(['ipv4', 'ipv6', 'dual']).default('ipv4'),
  apiToken: z.string().optional(),
  customUpdateUrl: z.string().optional(),
  checkIntervalSeconds: z.number().int().min(60).max(86400).default(300),
  proxied: z.boolean().default(false),
  enabled: z.boolean().default(true),
});
export type DdnsEntry = z.infer<typeof DdnsEntrySchema>;

export const DdnsConfigSchema = z.object({
  enabled: z.boolean().default(false),
  entries: z.array(DdnsEntrySchema).default([]),
});
export type DdnsConfig = z.infer<typeof DdnsConfigSchema>;

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
  name: z.string().min(1).regex(/^[a-zA-Z0-9_-]+$/),
  interface: z.string().min(1).regex(/^[a-zA-Z0-9_.:-]+$/),
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
  nopreempt: z.boolean().optional(),
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

export const ObservabilityOffloadSchema = z.object({
  enabled: z.boolean().default(false),
  nodeId: z.string().max(128).optional(),
  hubUrl: z.string().optional(),
  collectorHost: z.string().optional(),
  collectorPort: z.number().int().min(1).max(65535).default(2055),
  ipfixTransport: z.enum(['udp', 'tcp', 'tls']).default('udp'),
  ingestToken: z.string().optional(),
  useHaMtls: z.boolean().default(false),
  tlsCaCert: z.string().optional(),
  tlsInsecureSkipVerify: z.boolean().default(false),
  ipfix: z
    .object({
      enabled: z.boolean().default(true),
      version: z.enum(['ipfix', 'netflow9']).default('ipfix'),
      activeTimeoutSec: z.number().int().min(5).max(300).default(15),
      samplingRate: z.number().int().min(1).max(65535).default(1),
      interfaces: z.array(z.string()).default([]),
      pushMetadata: z.boolean().default(true),
    })
    .prefault({}),
  metrics: z
    .object({
      enabled: z.boolean().default(true),
      remoteWriteUrl: z.string().optional(),
      intervalSec: z.number().int().min(5).max(300).default(15),
      exposeScrape: z.boolean().default(false),
      scrapeBind: z.string().default('127.0.0.1'),
      scrapePort: z.number().int().min(1).max(65535).default(9100),
      scrapeToken: z.string().optional(),
    })
    .prefault({}),
  logs: z
    .object({
      enabled: z.boolean().default(true),
      victoriaLogsUrl: z.string().optional(),
      flushIntervalSec: z.number().int().min(1).max(60).default(5),
      batchSize: z.number().int().min(10).max(5000).default(256),
      nflog: z
        .object({
          enabled: z.boolean().default(true),
          group: z.number().int().min(0).max(65535).default(0),
          rateLimitPerSec: z.number().int().min(0).max(100000).default(50),
        })
        .prefault({}),
      journald: z
        .object({
          enabled: z.boolean().default(true),
          units: z.array(z.string()).default([]),
        })
        .prefault({}),
      suricata: z
        .object({
          enabled: z.boolean().default(true),
        })
        .prefault({}),
      crowdsec: z
        .object({
          enabled: z.boolean().default(true),
        })
        .prefault({}),
      keaDhcp: z
        .object({
          enabled: z.boolean().default(true),
        })
        .prefault({}),
      unboundDns: z
        .object({
          enabled: z.boolean().default(false),
        })
        .prefault({}),
    })
    .prefault({}),
  buffer: z
    .object({
      maxMemoryMB: z.number().int().min(4).max(256).default(24),
      diskSpoolEnabled: z.boolean().default(false),
      diskSpoolDir: z.string().default('/var/lib/axonwall/telemetry-spool'),
      diskSpoolMaxMB: z.number().int().min(16).max(4096).default(256),
    })
    .prefault({}),
  activeMitigation: z
    .object({
      acceptRemoteBlocks: z.boolean().default(false),
      maxTtlSec: z.number().int().min(60).max(86400).default(3600),
      protectedCidrs: z.array(z.string()).default(['127.0.0.0/8', '10.8.0.0/24']),
    })
    .prefault({}),
});
export type ObservabilityOffloadConfig = z.infer<typeof ObservabilityOffloadSchema>;

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
  victoriaMetrics: z.object({
    enabled: z.boolean().default(false),
    url: z.string().default('http://127.0.0.1:8428'),
    bearerToken: z.string().optional(),
  }).optional(),
  victoriaLogs: z.object({
    enabled: z.boolean().default(false),
    url: z.string().default('http://127.0.0.1:9428'),
    bearerToken: z.string().optional(),
  }).optional(),
  offload: ObservabilityOffloadSchema.optional(),
  ebpfApm: z.object({
    enabled: z.boolean().default(false),
    serviceMapEnabled: z.boolean().default(true),
    l7ProtocolDissection: z.boolean().default(true),
    tlsUprobesEnabled: z.boolean().default(false),
    continuousProfilingEnabled: z.boolean().default(false),
    profilingSampleHz: z.number().int().min(19).max(999).default(99),
    automatedRcaInspections: z.boolean().default(true),
    xdpDualStackVlanEnabled: z.boolean().default(true),
    xdpLpmCidrDropEnabled: z.boolean().default(true).optional(),
    xdpSynFloodRateLimitPps: z.number().int().min(0).max(10000000).default(0).optional(),
    zfsArcZilTelemetryEnabled: z.boolean().default(true),
  }).default({
    enabled: false,
    serviceMapEnabled: true,
    l7ProtocolDissection: true,
    tlsUprobesEnabled: false,
    continuousProfilingEnabled: false,
    profilingSampleHz: 99,
    automatedRcaInspections: true,
    xdpDualStackVlanEnabled: true,
    xdpLpmCidrDropEnabled: true,
    xdpSynFloodRateLimitPps: 0,
    zfsArcZilTelemetryEnabled: true,
  }),
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

export const HaProxyHostRuleSchema = z.object({
  hostname: z.string().min(1),
  backend: z.string().min(1),
});
export type HaProxyHostRule = z.infer<typeof HaProxyHostRuleSchema>;

export const HaProxyPathRuleSchema = z.object({
  matchType: z.enum(['beg', 'exact']).default('beg'),
  path: z.string().min(1),
  methods: z.array(z.enum(['GET', 'POST', 'HEAD', 'OPTIONS'])).optional(),
  backend: z.string().min(1),
});
export type HaProxyPathRule = z.infer<typeof HaProxyPathRuleSchema>;

export const HaProxyFrontendSchema = z.object({
  name: z.string().min(1),
  bindPort: z.number().int().min(1).max(65535),
  ssl: z.boolean().default(false),
  defaultBackend: z.string().min(1),
  certName: z.string().optional(),
  hostRules: z.array(HaProxyHostRuleSchema).default([]).optional(),
  strictHost: z.string().optional(),
  pathRules: z.array(HaProxyPathRuleSchema).optional(),
  silentDropUnmatched: z.boolean().optional(),
  sanitizeProxyHeaders: z.boolean().optional(),
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
  healthCheckPath: z.string().optional(),
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

export const SnmpV3UserSchema = z.object({
  username: z.string().min(1).max(64),
  authProtocol: z.enum(['SHA', 'SHA-256', 'SHA-512']).default('SHA-256'),
  authPassword: z.string().min(8).max(128),
  privProtocol: z.enum(['AES', 'AES-256']).default('AES'),
  privPassword: z.string().min(8).max(128),
  securityLevel: z.enum(['authPriv', 'authNoPriv']).default('authPriv'),
});
export type SnmpV3User = z.infer<typeof SnmpV3UserSchema>;

export const SnmpPluginConfigSchema = z.object({
  enabled: z.boolean().default(false),
  version: z.enum(['v2c', 'v3']).default('v2c').optional(),
  community: z.string().default('public'),
  sysLocation: z.string().default('Axonwall Gateway'),
  sysContact: z.string().default('admin@local'),
  listenPort: z.number().int().default(161),
  bindAddresses: z.array(z.string()).default([]).optional(),
  v3Users: z.array(SnmpV3UserSchema).default([]).optional(),
});
export type SnmpPluginConfig = z.infer<typeof SnmpPluginConfigSchema>;

export const PluginCategorySchema = z.enum(['core_role', 'extension']);
export type PluginCategory = z.infer<typeof PluginCategorySchema>;

export const PluginLdapGroupSpecSchema = z.object({
  cn: z.string().min(1),
  gidNumber: z.number().int().min(1000).max(65535),
  description: z.string().default(''),
  role: z.enum(['admin', 'operator', 'readonly']),
});
export type PluginLdapGroupSpec = z.infer<typeof PluginLdapGroupSpecSchema>;

export const PluginLdapIntegrationSpecSchema = z.object({
  enabledByDefault: z.boolean().default(true),
  serviceAccountCn: z.string().min(1),
  groups: z.array(PluginLdapGroupSpecSchema).default([]),
  inheritApplianceRoleGroups: z.boolean().default(true),
  envPrefix: z.string().optional(),
});
export type PluginLdapIntegrationSpec = z.infer<typeof PluginLdapIntegrationSpecSchema>;

// Plugin-bundled binaries: a general capability (not emacs-only) for
// shipping a binary with a plugin instead of installing it system-wide.
// The daemon downloads each entry into the plugin's own directory
// (<baseDataDir>/<plugin-id>/), verifies its sha256, and extracts it
// there; it never installs anything into the system. `binDirs` (below)
// then puts the extracted tree's bin directories on PATH, for both
// daemon invocations and interactive shells.
//
// `name` is the artifact identifier: for `kind: 'archive'` it is the
// binary the archive provides (e.g. 'rosenpass'); for
// `kind: 'binary'` it is the binary the raw file provides (e.g.
// 'k3s'); for `kind: 'distroPackage'` it is the distro package name
// (e.g. 'emacs-nox') — the binaries it contributes are found via
// `binDirs` after extraction, not via `name`.
// An archive entry extracts exactly one binary by default
// (`extract: 'binary'`); with `extract: 'tree'` the whole archive is
// extracted into the plugin dir after stripping `stripComponents`
// leading path components, and every extracted file is recorded in
// bundled.json. `oses` gates an entry to the listed host OS families;
// a gated-out entry is skipped at install and ignored by
// verification, never an error.
// The `kind` discriminator is what lets the daemon tell the source
// kinds apart unambiguously: an archive entry MUST carry `url` and
// MUST NOT carry distro fields; a raw-binary entry MUST carry `url`
// and MUST NOT carry distro fields, `format`, or `pathInArchive` (a
// single file has no container and no member path); a
// distro-package entry MUST carry `distro`/`package`/`version`/`arch`
// and MUST NOT carry `url`.
//
// sha256 is REQUIRED on every entry (never optional). It must be a
// 64-char lowercase/uppercase hex digest, except for the temporary
// `SHA256_TODO_<name>` markers used while a hash is still being
// resolved from the upstream index — those markers MUST be replaced
// with the real digest before install, and the daemon MUST fail
// closed (refuse to download/extract) on any entry whose sha256 is
// still a SHA256_TODO_* marker or is not 64 hex chars.
export const PluginBundledBinarySha256Schema = z
  .string()
  .regex(
    /^(?:[0-9a-fA-F]{64}|SHA256_TODO_[A-Za-z0-9_-]+)$/,
    'sha256 must be a 64-char hex digest, or a temporary SHA256_TODO_<name> marker to be replaced before install',
  );

const isValidHttpUrl = (val: string): boolean => {
  if (!val || /\s/.test(val)) return false;
  try {
    const parsed = new URL(val);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.hostname.length > 0;
  } catch {
    return false;
  }
};

const PluginBundledBinaryNameSchema = z
  .string()
  .min(1)
  .regex(/^[a-zA-Z0-9._-]+$/, 'binary name must be a plain file name')
  .refine((v) => v !== '.' && v !== '..', 'binary name must not be "." or ".."');

const PluginBundledOSListSchema = z
  .array(z.enum(['debian', 'alpine', 'arch']))
  .refine((arr) => new Set(arr).size === arr.length, 'oses entries must be unique')
  .optional();

const isValidRelativeArchivePath = (val: string): boolean => {
  if (!val || val.startsWith('/') || val.includes('\\') || /\s/.test(val)) return false;
  const segments = val.split('/');
  return !segments.some((seg) => seg === '' || seg === '..' || seg === '.');
};

export const PluginBundledArchiveBinarySchema = z
  .object({
    kind: z.literal('archive'),
    name: PluginBundledBinaryNameSchema,
    url: z
      .string()
      .min(1)
      .refine(isValidHttpUrl, 'archive url must be an http(s) URL'),
    sha256: PluginBundledBinarySha256Schema,
    // Archive container: 'tar' (uncompressed tar, e.g. the rosenpass
    // v0.2.3 release tarball), 'tar.gz'/'tgz', or 'zip'. Defaults to
    // 'tar' when omitted.
    format: z.enum(['tar', 'tar.gz', 'tgz', 'zip']).optional(),
    // Path of the binary inside the archive, relative, no '..'. Defaults
    // to `name` when omitted. Must be omitted with extract 'tree'
    // (the strip selects the tree root there).
    pathInArchive: z
      .string()
      .min(1)
      .refine(isValidRelativeArchivePath, 'pathInArchive must be a clean relative path with no ".."')
      .optional(),
    // Extraction mode: 'binary' (default — exactly one member,
    // pathInArchive, into bin/) or 'tree' (the whole archive into
    // the plugin dir, preserving member paths after stripping
    // stripComponents leading components — e.g. the neovim release
    // tarball wraps everything under 'nvim-linux-x86_64/', so
    // stripComponents 1 lands bin/nvim, lib/... and share/... at
    // the plugin root). The whole tree is recorded in bundled.json
    // and re-verified on use.
    extract: z.enum(['binary', 'tree']).optional(),
    // Leading path components stripped from every member during
    // tree extraction. Only meaningful with extract 'tree'.
    stripComponents: z.number().int().min(0).max(8).optional(),
    // Host OS families this entry applies to ('debian', 'alpine',
    // 'arch'). Omitted means every OS. An entry gated away from
    // this host is skipped at install and ignored by verification
    // (e.g. the glibc-linked neovim tarball is debian-only; on
    // Alpine/Arch vim/neovim keep coming from the system packages).
    oses: PluginBundledOSListSchema,
  })
  .refine((v) => v.extract !== 'tree' || v.pathInArchive === undefined, {
    message: 'pathInArchive must be omitted with extract "tree" (the strip selects the tree root)',
  })
  .refine((v) => v.extract === 'tree' || v.stripComponents === undefined, {
    message: 'stripComponents is only meaningful with extract "tree"',
  });
export type PluginBundledArchiveBinary = z.infer<typeof PluginBundledArchiveBinarySchema>;

// Raw single-file binary: a direct download (no archive container),
// sha256-verified and placed at <plugindir>/bin/<name> with mode
// 0755 (e.g. k3s, which upstream ships as a bare static binary).
// Strict: `format`, `pathInArchive` and every distro field are
// rejected outright — they are meaningless for a single file — so a
// manifest that confuses this kind with 'archive' or
// 'distroPackage' fails validation instead of silently dropping
// fields (zod objects strip unknown keys by default; the older
// archive/distroPackage schemas rely on the daemon's validation for
// that check).
export const PluginBundledRawBinarySchema = z
  .object({
    kind: z.literal('binary'),
    name: PluginBundledBinaryNameSchema,
    url: z
      .string()
      .min(1)
      .refine(isValidHttpUrl, 'binary url must be an http(s) URL'),
    sha256: PluginBundledBinarySha256Schema,
    oses: PluginBundledOSListSchema,
  })
  .strict();
export type PluginBundledRawBinary = z.infer<typeof PluginBundledRawBinarySchema>;

export const PluginBundledDistroPackageBinarySchema = z.object({
  kind: z.literal('distroPackage'),
  name: PluginBundledBinaryNameSchema,
  sha256: PluginBundledBinarySha256Schema,
  distro: z.literal('debian'),
  // Distro package name, e.g. 'emacs-nox'. The .deb/.apk filename is
  // derived from package + version + arch by the daemon (Debian
  // filenames drop the epoch, e.g. version '1:30.1+1-6' becomes
  // 'emacs-nox_30.1+1-6_amd64.deb' under pool/main/e/emacs/).
  package: z.string().regex(/^[a-z0-9][a-z0-9+.-]*$/, 'Invalid Debian package name'),
  // Debian *source* package name, e.g. 'gcc-14' for the binary
  // package libgccjit0, or 'emacs' for emacs-nox /
  // emacs-bin-common / emacs-common. The pool path is derived from
  // the source, not the binary package name; when omitted it
  // defaults to `package`. Required whenever the binary package is
  // built from a differently-named source (libgccjit0 ← gcc-14,
  // libisl23 ← isl, libmpc3 ← mpclib3, libmpfr6 ← mpfr4,
  // libasound2t64 / libasound2-data ← alsa-lib, liblcms2-2 ←
  // lcms2) — without it the daemon builds the wrong pool URL and
  // the download 404s.
  source: z.string().regex(/^[a-z0-9][a-z0-9+.-]*$/, 'Invalid Debian source package name').optional(),
  // Full version including epoch where the distro uses one, e.g.
  // '1:30.1+1-6' for Debian trixie emacs-nox.
  version: z.string().regex(/^(?:\d+:)?[0-9][a-zA-Z0-9.+~:-]*$/, 'Invalid Debian version'),
  // Target architecture, e.g. 'amd64' — or 'all' for
  // architecture-independent packages such as emacs-common.
  arch: z.string().regex(/^[a-z0-9][a-z0-9-]*$/, 'Invalid Debian architecture'),
  oses: PluginBundledOSListSchema,
});
export type PluginBundledDistroPackageBinary = z.infer<typeof PluginBundledDistroPackageBinarySchema>;

export const PluginBundledBinarySchema = z.discriminatedUnion('kind', [
  PluginBundledArchiveBinarySchema,
  PluginBundledRawBinarySchema,
  PluginBundledDistroPackageBinarySchema,
]);
export type PluginBundledBinary = z.infer<typeof PluginBundledBinarySchema>;

// Directories the plugin owns that go on PATH, relative to the
// per-plugin directory (e.g. 'usr/bin' for a tree extracted from
// .debs with dpkg-deb -x, or 'bin' for an archive extracted at the
// plugin root). Guard rules, enforced here: relative only — no
// absolute paths, no '..' segments (no escaping the plugin dir), no
// empty segments, no backslashes, no empty string.
export const PluginBinDirSchema = z
  .string()
  .min(1)
  .refine(
    (v) =>
      !v.startsWith('/') &&
      !v.includes('\\') &&
      !v.split('/').some((seg) => seg === '' || seg === '..'),
    'binDirs entries must be relative paths with no ".." and no absolute paths',
  );
export type PluginBinDir = z.infer<typeof PluginBinDirSchema>;

// Extra environment variables the plugin's processes (and interactive
// shells) get, on top of PATH. Keys MUST be valid env-var names
// ([A-Za-z_][A-Za-z0-9_]*), enforced below. Values may reference the
// plugin's own directory via the ${PLUGIN_DIR} placeholder, which the
// daemon/shell integration expands to the per-plugin directory
// (e.g. EMACSDATA='${PLUGIN_DIR}/usr/share/emacs/30.1' points at the
// bundled Emacs data tree). Values are otherwise taken literally.
export const PluginEnvSchema = z
  .record(z.string(), z.string())
  .refine(
    (env) => Object.keys(env).every((k) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(k)),
    'env keys must be valid environment variable names ([A-Za-z_][A-Za-z0-9_]*)',
  );
export type PluginEnv = z.infer<typeof PluginEnvSchema>;

export const PluginManifestSchema = z.object({
  id: z.string().regex(/^[a-z0-9-]+$/, 'plugin id must match ^[a-z0-9-]+$'),
  name: z.string().min(1),
  version: z.string().min(1),
  category: PluginCategorySchema.default('extension').optional(),
  defaultEnabled: z.boolean().optional(),
  dependencies: z.array(z.string()).default([]).optional(),
  description: z.string().default(''),
  author: z.string().default('Axonwall Community'),
  systemdUnits: z.array(z.string()).default([]),
  privileges: z.array(z.string()).default([]),
  ldapIntegration: PluginLdapIntegrationSpecSchema.optional(),
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
    arch: z.array(z.string()).default([]),
  }).optional(),
  cliBinaries: z.array(z.string()).optional(),
  // Bundled binaries shipped with the plugin (downloaded + verified +
  // extracted into the plugin's own directory, never installed into
  // the system). Additive alongside cliBinaries/RequiredBinaries,
  // which keep working as-is.
  binaries: z
    .array(PluginBundledBinarySchema)
    .refine(
      (arr) => new Set(arr.map((b) => b.name)).size === arr.length,
      'binaries entries must have unique names',
    )
    .optional(),
  // Plugin-owned directories (relative to the per-plugin directory)
  // added to PATH for daemon invocations and interactive shells.
  binDirs: z.array(PluginBinDirSchema).optional(),
  // Extra per-plugin environment variables (see PluginEnvSchema).
  env: PluginEnvSchema.optional(),
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
  // D16: no invented defaults. A node whose address was never reported
  // persists as unknown (undefined) instead of 127.0.0.1 — the loopback
  // default used to be written to fleet.yaml as if it were the node's
  // real address.
  ip: z.string().optional(),
  lastSeen: z.string().optional(),
  status: z.enum(['online', 'offline', 'enrolling', 'degraded']).default('enrolling'),
  ztpToken: z.string().optional(),
  wireguard: z.object({
    // D16: same — no invented 10.99.0.2/24 default. Tunnel IPs are
    // allocated explicitly (with a collision check) at enrollment time.
    tunnelIp: z.string().optional(),
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

export const HeadscalePortKnockSchema = z.object({
  enabled: z.boolean().default(false),
  protocol: z.enum(['tcp', 'udp']).default('udp'),
  sequence: z.array(z.number().int().min(1024).max(65535)).min(2).max(5).default([41821, 52913, 38477]),
  stepTimeoutSec: z.number().int().min(3).max(60).default(15),
  openDurationSec: z.number().int().min(60).max(86400).default(900),
});
export type HeadscalePortKnock = z.infer<typeof HeadscalePortKnockSchema>;

export const HeadscaleWanInviteSchema = z.object({
  enabled: z.boolean().default(false),
  hostname: z.string().max(253).default(''),
  bindPort: z.number().int().min(1).max(65535).default(8443),
  certName: z.string().max(128).default('hub'),
  autoWindow: z.boolean().default(true),
  requirePin: z.boolean().default(false),
  allowedCidrs: z.array(z.string()).default([]),
  exposeHeadscaleControl: z.boolean().default(false),
  portKnocking: HeadscalePortKnockSchema.optional(),
});
export type HeadscaleWanInvite = z.infer<typeof HeadscaleWanInviteSchema>;

export const HeadscaleConfigSchema = z.object({
  enabled: z.boolean().default(false),
  magicDnsDomain: z.string().default('tailnet.axonwall.local'),
  serverUrl: z.string().optional(),
  portalUrl: z.string().optional(),
  allowSelfRegistration: z.boolean().optional(),
  defaultKeyExpiryHours: z.number().int().min(1).max(720).optional(),
  wanInvite: HeadscaleWanInviteSchema.optional(),
});
export type HeadscaleConfig = z.infer<typeof HeadscaleConfigSchema>;

export const GeoIpModeSchema = z.enum(['block', 'allow']);
export const GeoIpDirectionSchema = z.enum(['in', 'out', 'both']);

export const GeoIpConfigSchema = z.object({
  enabled: z.boolean().default(false),
  mode: GeoIpModeSchema.default('block'),
  direction: GeoIpDirectionSchema.default('in'),
  countries: z.array(z.string().length(2)).default([]),
  excludedSubnets: z.array(z.string()).default(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8']),
  log: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type GeoIpConfig = z.infer<typeof GeoIpConfigSchema>;

export const SsoProviderSchema = z.enum(['oidc', 'entra', 'okta', 'google']);

export const SsoRoleMappingSchema = z.object({
  idpGroup: z.string().min(1),
  role: z.enum(['admin', 'operator', 'readonly', 'vpn_user']),
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

export const ZfsSpecialSmallBlocksSchema = z.enum([
  '0',
  '4K',
  '8K',
  '16K',
  '32K',
  '64K',
  '128K',
]);
export type ZfsSpecialSmallBlocks = z.infer<typeof ZfsSpecialSmallBlocksSchema>;

export const ZfsPoolSchema = z.object({
  name: z.string().min(1).regex(/^[a-zA-Z][a-zA-Z0-9_-]*$/),
  topology: ZfsTopologySchema.default('mirror'),
  dataDisks: z.array(z.string()).min(1),
  cacheDisks: z.array(z.string()).default([]),
  logDisks: z.array(z.string()).default([]),
  spareDisks: z.array(z.string()).default([]),
  specialDisks: z.array(z.string()).default([]).optional(),
  dedupDisks: z.array(z.string()).default([]).optional(),
  specialSmallBlocks: ZfsSpecialSmallBlocksSchema.default('0').optional(),
  ashift: z.number().int().min(9).max(16).default(12),
  autotrim: z.boolean().default(true),
  trimScheduleCron: z.string().default('0 4 * * 6').optional(),
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
  refQuotaGb: z.number().nonnegative().default(0).optional(),
  refReservationGb: z.number().nonnegative().default(0).optional(),
  recordSize: z.enum(['4K', '16K', '64K', '128K', '512K', '1M']).default('128K'),
  specialSmallBlocks: ZfsSpecialSmallBlocksSchema.optional(),
  atime: z.enum(['on', 'off']).default('off').optional(),
  sync: z.enum(['standard', 'always', 'disabled']).default('standard').optional(),
  volSizeGb: z.number().nonnegative().default(10),
  encryption: z.enum(['off', 'aes-256-gcm', 'aes-256-ccm']).default('off'),
  keyFormat: z.enum(['passphrase', 'hex', 'raw']).default('hex').optional(),
  keyLocation: z
    .string()
    .regex(/^(prompt|file:\/\/\/etc\/axonwall\/zfs-keys\/[a-zA-Z0-9._-]+)$/, 'Key location must be prompt or file:///etc/axonwall/zfs-keys/<id>')
    .optional(),
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
  recycleBin: z.boolean().default(false).optional(),
  auditLog: z.boolean().default(false).optional(),
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
  secFlavor: z.enum(['sys', 'krb5', 'krb5i', 'krb5p']).default('sys').optional(),
  async: z.boolean().default(false),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type NfsExport = z.infer<typeof NfsExportSchema>;

export const CloudSyncTaskSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1).regex(/^[a-zA-Z0-9_-]+$/),
  provider: z.enum(['s3', 'b2', 'gcs', 'sftp', 'webdav']).default('s3'),
  direction: z.enum(['push', 'pull']).default('push'),
  transferMode: z.enum(['sync', 'copy']).default('sync'),
  localPath: z.string().regex(/^\/mnt\/[a-zA-Z0-9._/-]+$/, 'localPath must reside under /mnt/<pool>'),
  remoteBucket: z.string().min(1).regex(/^[a-zA-Z0-9._:/-]+$/),
  endpoint: z.string().optional(),
  scheduleCron: z.string().default('0 3 * * *'),
  bandwidthLimitMbps: z.number().int().min(0).default(0),
  clientSideEncrypt: z.boolean().default(true),
  enabled: z.boolean().default(true),
  description: z.string().max(255).default(''),
});
export type CloudSyncTask = z.infer<typeof CloudSyncTaskSchema>;

export const SmartScheduleSchema = z.object({
  enabled: z.boolean().default(true),
  shortTestCron: z.string().default('0 1 * * *'),
  longTestCron: z.string().default('0 3 1 * *'),
  tempWarnCelsius: z.number().int().min(25).max(85).default(45),
  tempCritCelsius: z.number().int().min(30).max(95).default(55),
});
export type SmartSchedule = z.infer<typeof SmartScheduleSchema>;

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
  smbMultichannel: z.boolean().default(true).optional(),
  wsddEnabled: z.boolean().default(true).optional(),
  pools: z.array(ZfsPoolSchema).default([]),
  datasets: z.array(ZfsDatasetSchema).default([]),
  snapshotPolicies: z.array(ZfsSnapshotPolicySchema).default([]),
  smbShares: z.array(SmbShareSchema).default([]),
  nfsExports: z.array(NfsExportSchema).default([]),
  iscsiTargets: z.array(IscsiTargetSchema).default([]),
  s3: S3ServerConfigSchema.optional(),
  cloudSyncTasks: z.array(CloudSyncTaskSchema).default([]).optional(),
  smartSchedule: SmartScheduleSchema.optional(),
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
  serviceType: z.enum(['ClusterIP', 'NodePort', 'LoadBalancer']).default('ClusterIP').optional(),
  ingressHostname: z.string().regex(/^[a-zA-Z0-9_.-]+$/).optional(),
  exposeViaHaproxy: z.boolean().default(false).optional(),
  bpfTokenProfileId: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/).optional(),
  storageClass: z.enum(['axonwall-replicated-ha', 'axonwall-zfs-local', 'none']).default('axonwall-replicated-ha'),
  storageSizeGb: z.number().int().min(1).default(10),
  mountPath: z.string().default('/data'),
  enabled: z.boolean().default(true),
});
export type K3sWorkloadSpec = z.infer<typeof K3sWorkloadSpecSchema>;

// =============================================================================
// Linux 6.9+ BPF_TOKEN_CREATE & bpffs Delegation Schemas (K3s + LXC UserNS)
// =============================================================================

export const FORBIDDEN_RING0_BPF_PROGS = [
  'kprobe',
  'tracepoint',
  'perf_event',
  'raw_tracepoint',
  'raw_tracepoint_writable',
  'tracing',
  'struct_ops',
  'ext',
  'lsm',
  'syscall',
] as const;

export const BpfTokenPresetSchema = z.enum([
  'disabled',
  'socket-observability',
  'network-dataplane',
  'cgroup-microsegmentation',
  'custom',
]);
export type BpfTokenPreset = z.infer<typeof BpfTokenPresetSchema>;

function validateBpfTokenDelegationFields(
  val: {
    enabled?: boolean;
    preset: BpfTokenPreset;
    delegateCmds?: string;
    delegateProgs?: string;
    delegateMaps?: string;
    delegateAttachs?: string;
  },
  ctx: z.RefinementCtx,
): void {
  if (val.enabled === false || val.preset === 'disabled') return;
  if (val.preset === 'custom') {
    for (const field of ['delegateCmds', 'delegateProgs', 'delegateMaps', 'delegateAttachs'] as const) {
      const tokens = (val[field] ?? '')
        .split(':')
        .map((s) => s.trim())
        .filter(Boolean);
      if (tokens.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [field],
          message: `Custom BPF_TOKEN preset requires explicit non-empty ${field}`,
        });
      }
    }
  }
  if (val.delegateProgs) {
    const progs = val.delegateProgs.split(':').map((s) => s.trim().toLowerCase()).filter(Boolean);
    for (const p of progs) {
      if ((FORBIDDEN_RING0_BPF_PROGS as readonly string[]).includes(p) || p === 'any') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['delegateProgs'],
          message: `BPF_TOKEN delegation rejects Ring-0 program type '${p}' (prevents bpf_probe_read_kernel() arbitrary host memory access)`,
        });
      }
    }
  }
  for (const field of ['delegateCmds', 'delegateMaps', 'delegateAttachs'] as const) {
    const v = val[field];
    if (v && v.split(':').some((tok) => tok.trim().toLowerCase() === 'any')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [field],
        message: `${field} cannot use wildcard 'any'; specify explicit least-privilege bitmasks`,
      });
    }
  }
}

export const BpfTokenDelegationSpecSchema = z
  .object({
    enabled: z.boolean().default(false),
    preset: BpfTokenPresetSchema.default('network-dataplane'),
    delegateCmds: z.string().regex(/^[a-z0-9_:]*$/).optional(),
    delegateProgs: z.string().regex(/^[a-z0-9_:]*$/).optional(),
    delegateMaps: z.string().regex(/^[a-z0-9_:]*$/).optional(),
    delegateAttachs: z.string().regex(/^[a-z0-9_:]*$/).optional(),
    auditViaBpfLsm: z.boolean().default(true),
  })
  .superRefine(validateBpfTokenDelegationFields);
export type BpfTokenDelegationSpec = z.infer<typeof BpfTokenDelegationSpecSchema>;

export const K3sBpfTokenProfileSchema = z
  .object({
    id: z.string().min(2).max(63).regex(/^[a-z0-9][a-z0-9._-]*$/),
    preset: BpfTokenPresetSchema.default('network-dataplane'),
    enabled: z.boolean().default(true),
    delegateCmds: z.string().regex(/^[a-z0-9_:]*$/).optional(),
    delegateProgs: z.string().regex(/^[a-z0-9_:]*$/).optional(),
    delegateMaps: z.string().regex(/^[a-z0-9_:]*$/).optional(),
    delegateAttachs: z.string().regex(/^[a-z0-9_:]*$/).optional(),
    auditViaBpfLsm: z.boolean().default(true),
    description: z.string().max(255).optional(),
  })
  .superRefine(validateBpfTokenDelegationFields);
export type K3sBpfTokenProfile = z.infer<typeof K3sBpfTokenProfileSchema>;

export const K3sServiceLbPoolSchema = z.object({
  name: z.string().min(1).regex(/^[a-z0-9][a-z0-9-]*$/),
  cidr: z.string().refine(isValidCIDR, { message: 'Invalid ServiceLB CIDR pool' }),
  mode: z.enum(['bgp', 'l2-arp', 'both']).default('both'),
  autoAssign: z.boolean().default(true),
});
export type K3sServiceLbPool = z.infer<typeof K3sServiceLbPoolSchema>;

export const K3sEtcdSnapshotConfigSchema = z.object({
  enabled: z.boolean().default(true),
  scheduleCron: z.string().default('0 */6 * * *'),
  retention: z.number().int().min(1).max(365).default(14),
  snapshotDir: z.string().regex(/^\/[a-zA-Z0-9._/-]+$/).default('/var/lib/rancher/k3s/server/db/snapshots'),
  s3Enabled: z.boolean().default(false),
  s3Endpoint: z.string().optional(),
  s3Bucket: z.string().optional(),
  s3Region: z.string().default('us-east-1'),
});
export type K3sEtcdSnapshotConfig = z.infer<typeof K3sEtcdSnapshotConfigSchema>;

export const K3sConfigSchema = z.object({
  enabled: z.boolean().default(false),
  profile: z.enum(['standard', 'barebones-storage']).default('standard').optional(),
  role: z.enum(['server', 'agent']).default('server').optional(),
  serverUrl: z.string().optional(),
  datastore: z.enum(['sqlite', 'etcd']).optional(),
  clusterCidr: z.string().default('10.42.0.0/16'),
  serviceCidr: z.string().default('10.43.0.0/16'),
  nodeIpInterface: z.string().default('lan'),
  cniPlugin: z.enum(['flannel', 'cilium-ebpf']).default('flannel').optional(),
  flannelBackend: z.enum(['wireguard-native', 'vxlan', 'host-gw']).default('wireguard-native'),
  ciliumKubeProxyReplacement: z.boolean().default(true).optional(),
  ciliumHubbleEnabled: z.boolean().default(true).optional(),
  haTopology: z.enum(['embedded-etcd', 'single-server-ha-agent', 'external-datastore']).default('embedded-etcd').optional(),
  externalDatastoreEndpoint: z.string().optional(),
  disableTraefik: z.boolean().default(false),
  disableServiceLb: z.boolean().default(false).optional(),
  disableLocalStorage: z.boolean().default(false).optional(),
  disableMetricsServer: z.boolean().default(false).optional(),
  kubeletEvictionHard: z.string().optional(),
  zfsArcMaxMb: z.number().int().min(0).default(0).optional(),
  autoJoinHaPeer: z.boolean().default(true),
  enableUserNamespaces: z.boolean().default(true),
  gpuRuntimeEnabled: z.boolean().default(false).optional(),
  etcdSnapshots: K3sEtcdSnapshotConfigSchema.optional(),
  serviceLbPools: z.array(K3sServiceLbPoolSchema).default([]).optional(),
  bpfTokenProfiles: z.array(K3sBpfTokenProfileSchema).default([]),
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

export const VowLdapAuthSchema = z.object({
  enabled: z.boolean().default(true),
  autoBindLocalLdap: z.boolean().default(true),
  allowLocalBreakGlass: z.boolean().default(true),
  autoProvisionPrincipals: z.boolean().default(true),
  syncKeycloakUserFederation: z.boolean().default(true),
  url: z.string().default('ldap://127.0.0.1:389'),
  baseDn: z.string().optional(),
  bindDn: z.string().optional(),
  userSearchBase: z.string().optional(),
  groupSearchBase: z.string().optional(),
  ownerGroups: z.array(z.string()).default(['axonwall-admin']),
  adminGroups: z.array(z.string()).default(['vow-admin']),
  operatorGroups: z.array(z.string()).default(['axonwall-operator', 'vow-operator']),
  viewerGroups: z.array(z.string()).default(['axonwall-readonly', 'vow-readonly']),
  defaultRole: z.enum(['owner', 'admin', 'operator', 'viewer', 'none']).default('viewer'),
});
export type VowLdapAuth = z.infer<typeof VowLdapAuthSchema>;

export const VowConfigSchema = z.object({
  enabled: z.boolean().default(false),
  cdRunner: VowCdRunnerSchema.default('argocd'),
  domain: z.string().default('vow.axonwall.local'),
  gitRepoUrl: z.string().default('https://github.com/DeployCoop/vigilant-octo-waffle.git'),
  gitBranch: z.string().default('main'),
  fluxInterval: z.string().default('5m'),
  localTlsMkcert: z.boolean().default(true),
  syncUnboundDns: z.boolean().default(true),
  authzEnabled: z.boolean().default(true),
  defaultRole: z.enum(['owner', 'admin', 'operator', 'viewer', 'webhook']).default('admin'),
  ldapAuth: VowLdapAuthSchema.default({
    enabled: true,
    autoBindLocalLdap: true,
    allowLocalBreakGlass: true,
    autoProvisionPrincipals: true,
    syncKeycloakUserFederation: true,
    url: 'ldap://127.0.0.1:389',
    ownerGroups: ['axonwall-admin'],
    adminGroups: ['vow-admin'],
    operatorGroups: ['axonwall-operator', 'vow-operator'],
    viewerGroups: ['axonwall-readonly', 'vow-readonly'],
    defaultRole: 'viewer',
  }),
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

export const VirtioFsShareSchema = z.object({
  id: z.string().optional(),
  tag: z.string().min(1).max(36).regex(/^[a-zA-Z0-9_-]+$/, 'Invalid VirtioFS mount tag'),
  hostPath: z
    .string()
    .regex(/^\/(?:mnt|tank|rpool|var\/lib\/axonwall)\/[a-zA-Z0-9._/-]+$/, 'VirtioFS hostPath must reside under /mnt, /tank, /rpool, or /var/lib/axonwall'),
  cacheMode: z.enum(['auto', 'always', 'none']).default('auto'),
  readOnly: z.boolean().default(false),
});
export type VirtioFsShare = z.infer<typeof VirtioFsShareSchema>;

export const VirtSecurityGroupRuleSchema = z.object({
  id: z.string().optional(),
  direction: z.enum(['in', 'out']).default('in'),
  action: z.enum(['accept', 'drop', 'reject']).default('accept'),
  protocol: z.enum(['any', 'tcp', 'udp', 'icmp', 'ipv6-icmp']).default('tcp'),
  cidr: z.string().refine((v) => v === 'any' || isValidCIDR(v) || isValidIPv4(v) || isValidIPv6(v), {
    message: 'Invalid security group CIDR/IP',
  }).default('any'),
  port: z.string().refine((v) => !v || v === 'any' || isValidPortSpec(v), {
    message: 'Invalid security group port specification',
  }).default(''),
  description: z.string().max(128).default(''),
});
export type VirtSecurityGroupRule = z.infer<typeof VirtSecurityGroupRuleSchema>;

export const VirtSecurityGroupSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1).max(48).regex(/^[a-zA-Z][a-zA-Z0-9_-]*$/, 'Invalid security group name'),
  description: z.string().max(255).default(''),
  rules: z.array(VirtSecurityGroupRuleSchema).default([]),
});
export type VirtSecurityGroup = z.infer<typeof VirtSecurityGroupSchema>;

export const VmNicSchema = z.object({
  id: z.string().optional(),
  mac: z.string().default(''),
  bridge: z.string().default('br0'),
  vlanTag: z.number().int().min(0).max(4094).optional(),
  vnet: z.string().optional(),
  model: VmNicModelSchema.default('virtio'),
  firewall: z.boolean().default(true),
  securityGroups: z.array(z.string().regex(/^[a-zA-Z][a-zA-Z0-9_-]*$/)).default([]).optional(),
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
  cpuPinning: z.string().regex(/^[0-9,-]*$/, 'Invalid CPU affinity list (e.g. 0-3,8-11)').optional(),
  numaEnabled: z.boolean().default(false).optional(),
  memoryMb: z.number().int().min(128).default(2048),
  hugepages: z.enum(['off', '2M', '1G']).default('off').optional(),
  balloonMinMb: z.number().int().min(0).default(0),
  disks: z.array(VmDiskSchema).default([]),
  virtioFsShares: z.array(VirtioFsShareSchema).default([]).optional(),
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
  isTemplate: z.boolean().default(false).optional(),
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

export const LxcContainerSchema = z
  .object({
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
    bpfToken: BpfTokenDelegationSpecSchema.optional(),
    autostart: z.boolean().default(false),
    haManaged: z.boolean().default(false),
    enabled: z.boolean().default(true),
  })
  .refine(
    (ct) => !(ct.bpfToken?.enabled && ct.bpfToken.preset !== 'disabled' && !ct.unprivileged),
    {
      message:
        'BPF_TOKEN delegation requires an unprivileged User-Namespaced LXC container (unprivileged: true / CLONE_NEWUSER)',
      path: ['bpfToken'],
    },
  );
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
  vendorId: z.string().regex(/^[0-9a-fA-F]{4}$/).optional(),
  deviceId: z.string().regex(/^[0-9a-fA-F]{4}$/).optional(),
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
  exportLibvirtXml: z.boolean().default(true).optional(),
  vms: z.array(VirtualMachineSchema).default([]),
  containers: z.array(LxcContainerSchema).default([]),
  isos: z.array(IsoImageSchema).default([]),
  pciDevices: z.array(PciPassthroughDeviceSchema).default([]),
  backupJobs: z.array(WorkloadBackupJobSchema).default([]),
  vxlanZones: z.array(VxlanZoneSchema).default([]),
  securityGroups: z.array(VirtSecurityGroupSchema).default([]).optional(),
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
  ingressHostname: z.string().regex(/^[a-zA-Z0-9.-]+$/).optional(),
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
  enabled: z.boolean().default(false),
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
  allowDelegatedBpfTokens: z.boolean().default(true),
  auditDelegatedBpfTokens: z.boolean().default(true),
  trustedBpfLoaderPaths: z.array(
    z.string().regex(/^\/[a-zA-Z0-9._/-]+$/, 'Trusted BPF loader path must be a safe absolute path'),
  ).default([
    '/usr/sbin/bpftool',
    '/usr/bin/bpftool',
    '/usr/local/bin/axonwalld',
    '/usr/bin/axonwalld',
  ]),
  blockAfAlgAeadCopyfail: z.boolean().default(true),
  trustedAfAlgPaths: z.array(
    z.string().regex(/^\/[a-zA-Z0-9._/-]+$/, 'Trusted AF_ALG path must be a safe absolute path'),
  ).default([
    '/usr/sbin/cryptsetup',
    '/usr/bin/cryptsetup',
  ]),
  progIdrKcoreDiffEnabled: z.boolean().default(true),
  pmuLbrBranchTracingEnabled: z.boolean().default(true),
  autoQuarantineOnCritical: z.boolean().default(true),
});
export type HostMalwareDefenseConfig = z.infer<typeof HostMalwareDefenseConfigSchema>;

// =============================================================================
// Axonwall Blackbox: Extreme eBPF Threat-LLM Harvester (Opt-In Dataset Engine)
// =============================================================================

export const ThreatTeacherLlmConfigSchema = z.object({
  enabled: z.boolean().default(false),
  endpoint: z.string().default('http://127.0.0.1:4100/v1/chat/completions'),
  model: z.string().default('qwen2.5-14b-instruct'),
  apiKey: z.string().optional(),
  maxCallsPerHour: z.number().int().min(1).max(10000).default(30),
});
export type ThreatTeacherLlmConfig = z.infer<typeof ThreatTeacherLlmConfigSchema>;

export const ThreatFleetShipperConfigSchema = z.object({
  enabled: z.boolean().default(false),
  endpoint: z.string().default(''),
  region: z.string().default('us-east-1'),
  bucket: z.string().default('axonwall-threat-corpus'),
  prefix: z.string().default('nodes/'),
  accessKey: z.string().optional(),
  secretKey: z.string().optional(),
  usePathStyle: z.boolean().default(true),
  lastShippedAt: z.string().optional(),
  lastShippedKey: z.string().optional(),
  lastError: z.string().optional(),
});
export type ThreatFleetShipperConfig = z.infer<typeof ThreatFleetShipperConfigSchema>;

export const ThreatHarvesterConfigSchema = z.object({
  enabled: z.boolean().default(false),
  captureMode: z.enum(['adaptive', 'firehose', 'honeypot_only']).default('adaptive'),
  watchedInterfaces: z.array(z.string()).default([]),
  firehoseInterfaces: z.array(z.string()).default([]),
  firehoseNamespaces: z.array(z.string()).default([]),
  canaryPorts: z
    .array(z.number().int().min(1).max(65535))
    .default([23, 2323, 3389, 4444, 5900, 6379, 9200, 27017]),
  maxPayloadBytes: z.number().int().min(256).max(65536).default(4096),
  correlationWindowSec: z.number().int().min(5).max(300).default(45),
  benignSampleRate: z.number().min(0).max(1).default(0.005),
  spoolDir: z.string().default('/var/lib/axonwall/threat-corpus'),
  maxSpoolGb: z.number().int().min(1).max(10000).default(10),
  pinGoldEpisodes: z.boolean().default(true),
  enableTlsUprobes: z.boolean().default(false),
  autoHoneypotTlsUprobes: z.boolean().default(true),
  tlsUprobeAllowlist: z.array(z.string()).default([]),
  anonymizeOnExport: z.boolean().default(true),
  anonymizationSalt: z.string().optional(),
  teacherLlm: ThreatTeacherLlmConfigSchema.prefault({}),
  fleetShipper: ThreatFleetShipperConfigSchema.prefault({}),
});
export type ThreatHarvesterConfig = z.infer<typeof ThreatHarvesterConfigSchema>;

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

export const VigilanteLdapAuthSchema = z.object({
  enabled: z.boolean().default(true),
  autoProvisionPrincipals: z.boolean().default(true),
  allowLocalBreakGlass: z.boolean().default(true),
  defaultRole: z.enum(['owner', 'admin', 'operator', 'viewer']).default('viewer'),
  syncModuleSso: z.boolean().default(true),
});
export type VigilanteLdapAuthConfig = z.infer<typeof VigilanteLdapAuthSchema>;

export const VigilanteConfigSchema = z.object({
  enabled: z.boolean().default(false),
  posture: z.enum(['monitoring', 'hybrid', 'enforcing']).default('hybrid'),
  domain: z.string().regex(/^[a-zA-Z0-9.-]+$/).default('vigilante.local'),
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
  ldapAuth: VigilanteLdapAuthSchema.default({
    enabled: true,
    autoProvisionPrincipals: true,
    allowLocalBreakGlass: true,
    defaultRole: 'viewer',
    syncModuleSso: true,
  }),
});
export type VigilanteConfig = z.infer<typeof VigilanteConfigSchema>;

export const ApplianceRoleSchema = z.enum(['admin', 'operator', 'readonly', 'vpn_user', 'os_only']);
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
  ldapEnabled: z.boolean().optional(),
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

export const EluvixLdapAuthSchema = z.object({
  enabled: z.boolean().default(true),
  autoBindLocalLdap: z.boolean().default(true),
  allowLocalBreakGlass: z.boolean().default(true),
  url: z.string().default('ldap://127.0.0.1:389'),
  baseDn: z.string().optional(),
  bindDn: z.string().optional(),
  userSearchBase: z.string().optional(),
  groupSearchBase: z.string().optional(),
  adminGroups: z.array(z.string()).default(['axonwall-admin', 'eluvix-admin']),
  operatorGroups: z.array(z.string()).default(['axonwall-operator', 'eluvix-operator']),
  readonlyGroups: z.array(z.string()).default(['axonwall-readonly', 'eluvix-readonly']),
  defaultRole: z.enum(['admin', 'operator', 'readonly', 'none']).default('readonly'),
});
export type EluvixLdapAuth = z.infer<typeof EluvixLdapAuthSchema>;

export const EluvixConfigSchema = z.object({
  enabled: z.boolean().default(false),
  deploymentMode: z.enum(['systemd', 'docker', 'k3s-helm']).default('systemd'),
  listenPort: z.number().int().min(1).max(65535).default(3588),
  switchyardPort: z.number().int().min(1).max(65535).default(8080),
  domain: z.string().regex(/^[a-zA-Z0-9.-]+$/).default('eluvix.axonwall.local'),
  gitRepoUrl: z.string().default('git@github.com:Eluvixrouter/eluvix.git'),
  samePortTlsAutoUpgrade: z.boolean().default(true),
  syncUnboundDns: z.boolean().default(true),
  routeAxonwallCopilotThroughEluvix: z.boolean().default(true),
  teePolicy: z.enum(['disabled', 'prefer-tee', 'require-tee', 'require-dual-attestation']).default('prefer-tee'),
  ldapAuth: EluvixLdapAuthSchema.default({
    enabled: true,
    autoBindLocalLdap: true,
    allowLocalBreakGlass: true,
    url: 'ldap://127.0.0.1:389',
    adminGroups: ['axonwall-admin', 'eluvix-admin'],
    operatorGroups: ['axonwall-operator', 'eluvix-operator'],
    readonlyGroups: ['axonwall-readonly', 'eluvix-readonly'],
    defaultRole: 'readonly',
  }),
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

export const NetBoxLdapAuthSchema = z.object({
  enabled: z.boolean().default(true),
  autoBindLocalLdap: z.boolean().default(true),
  url: z.string().default('ldap://127.0.0.1:389'),
  baseDn: z.string().optional(),
  bindDn: z.string().optional(),
  adminGroups: z.array(z.string()).default(['axonwall-admin', 'netbox-admin']),
  operatorGroups: z.array(z.string()).default(['axonwall-operator', 'netbox-operator']),
  readonlyGroups: z.array(z.string()).default(['axonwall-readonly', 'netbox-readonly']),
});
export type NetBoxLdapAuth = z.infer<typeof NetBoxLdapAuthSchema>;

export const NetBoxSyncConfigSchema = z.object({
  enabled: z.boolean().default(true),
  autoSyncOnApply: z.boolean().default(false),
  syncInterfaces: z.boolean().default(true),
  syncVlans: z.boolean().default(true),
  syncVrfs: z.boolean().default(true),
  syncPrefixes: z.boolean().default(true),
  syncDhcpLeases: z.boolean().default(true),
  syncVirtualIps: z.boolean().default(true),
  syncVirtualMachines: z.boolean().default(true),
  syncK3sNodes: z.boolean().default(true),
});
export type NetBoxSyncConfig = z.infer<typeof NetBoxSyncConfigSchema>;

const isOptionalHttpUrl = (v: string): boolean => {
  const trimmed = v.trim();
  if (!trimmed) return true;
  if (/[\r\n\0\s]/.test(trimmed)) return false;
  try {
    const u = new URL(trimmed);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
};

export const NetBoxConfigSchema = z.object({
  enabled: z.boolean().default(false),
  namespace: z.string().regex(/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/).default('netbox'),
  domain: z.string().regex(/^[a-zA-Z0-9.-]+$/).default('netbox.axonwall.local'),
  image: z.string().min(1).regex(/^[^\s\r\n]+$/).default('netboxcommunity/netbox:v4.2'),
  postgresImage: z.string().min(1).regex(/^[^\s\r\n]+$/).default('postgres:16-alpine'),
  valkeyImage: z.string().min(1).regex(/^[^\s\r\n]+$/).default('valkey/valkey:8-alpine'),
  storageClass: z.string().regex(/^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/).default('axonwall-zfs-local'),
  postgresStorageGb: z.number().int().min(1).max(2000).default(20),
  mediaStorageGb: z.number().int().min(1).max(2000).default(10),
  replicas: z.number().int().min(1).max(5).default(1),
  workerReplicas: z.number().int().min(1).max(5).default(1),
  servicePort: z.number().int().min(1).max(65535).default(8080),
  ingressEnabled: z.boolean().default(true),
  ingressTls: z.boolean().default(true),
  syncUnboundDns: z.boolean().default(true),
  superuserUsername: z.string().regex(/^[a-zA-Z0-9._-]+$/).default('admin'),
  superuserEmail: z.string().email().default('admin@axonwall.local'),
  superuserPassword: z.string().optional(),
  apiToken: z.string().optional(),
  externalUrl: z
    .string()
    .refine(isOptionalHttpUrl, { message: 'externalUrl must be an http:// or https:// URL' })
    .optional(),
  siteName: z.string().min(1).max(100).default('Axonwall Appliance'),
  siteSlug: z.string().regex(/^[a-z0-9-]+$/).default('axonwall-appliance'),
  ldapAuth: NetBoxLdapAuthSchema.prefault({}),
  sync: NetBoxSyncConfigSchema.prefault({}),
});
export type NetBoxConfig = z.infer<typeof NetBoxConfigSchema>;

export const LibreNmsLdapAuthSchema = z.object({
  enabled: z.boolean().default(true),
  autoBindLocalLdap: z.boolean().default(true),
  url: z.string().default('ldap://127.0.0.1:389'),
  baseDn: z.string().optional(),
  bindDn: z.string().optional(),
  adminGroup: z.string().min(1).default('librenms-admin'),
  operatorGroup: z.string().min(1).default('librenms-operator'),
  readonlyGroup: z.string().min(1).default('librenms-readonly'),
  inheritApplianceAdmins: z.boolean().default(true),
});
export type LibreNmsLdapAuth = z.infer<typeof LibreNmsLdapAuthSchema>;

export const LibreNmsSnmpDefaultsSchema = z.object({
  version: z.enum(['v2c', 'v3']).default('v2c'),
  community: z.string().default('public'),
  port: z.number().int().min(1).max(65535).default(161),
  v3AuthLevel: z.enum(['noAuthNoPriv', 'authNoPriv', 'authPriv']).default('authPriv'),
  v3AuthUser: z.string().optional(),
  v3AuthAlgo: z.enum(['SHA', 'SHA-256', 'SHA-512', 'MD5']).default('SHA-256'),
  v3AuthPass: z.string().optional(),
  v3CryptoAlgo: z.enum(['AES', 'AES-256', 'DES']).default('AES'),
  v3CryptoPass: z.string().optional(),
});
export type LibreNmsSnmpDefaults = z.infer<typeof LibreNmsSnmpDefaultsSchema>;

export const LibreNmsDiscoverySubnetSchema = z.object({
  cidr: z.string().min(1),
  label: z.string().default(''),
  enabled: z.boolean().default(true),
});
export type LibreNmsDiscoverySubnet = z.infer<typeof LibreNmsDiscoverySubnetSchema>;

export const LibreNmsSyncConfigSchema = z.object({
  enabled: z.boolean().default(true),
  autoEnrollAxonwallHosts: z.boolean().default(true),
  autoEnrollFleetSatellites: z.boolean().default(true),
  autoEnrollTopologyPeers: z.boolean().default(true),
  syncToNetBox: z.boolean().default(true),
  pollIntervalSec: z.number().int().min(10).max(3600).default(300),
});
export type LibreNmsSyncConfig = z.infer<typeof LibreNmsSyncConfigSchema>;

export const LibreNmsConfigSchema = z.object({
  enabled: z.boolean().default(false),
  mode: z.enum(['k3s', 'external']).default('k3s'),
  namespace: z.string().regex(/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/).default('librenms'),
  domain: z.string().regex(/^[a-zA-Z0-9.-]+$/).default('librenms.axonwall.local'),
  image: z.string().min(1).regex(/^[^\s\r\n]+$/).default('librenms/librenms:25.10.0'),
  dbImage: z.string().min(1).regex(/^[^\s\r\n]+$/).default('mariadb:11.4'),
  valkeyImage: z.string().min(1).regex(/^[^\s\r\n]+$/).default('valkey/valkey:8-alpine'),
  servicePort: z.number().int().min(1).max(65535).default(8000),
  storageClass: z.string().regex(/^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/).default('axonwall-zfs-local'),
  dataVolumeSizeGb: z.number().int().min(5).max(4096).default(20),
  dbVolumeSizeGb: z.number().int().min(5).max(4096).default(15),
  syslogEnabled: z.boolean().default(true),
  snmpTrapEnabled: z.boolean().default(true),
  ingressEnabled: z.boolean().default(true),
  ingressTls: z.boolean().default(true),
  unboundAutoDns: z.boolean().default(true),
  adminUsername: z.string().regex(/^[a-zA-Z0-9._-]+$/).default('admin'),
  adminEmail: z.string().email().default('admin@axonwall.local'),
  adminPassword: z.string().optional(),
  externalUrl: z
    .string()
    .refine(isOptionalHttpUrl, { message: 'externalUrl must be an http:// or https:// URL' })
    .optional(),
  apiToken: z.string().optional(),
  webhookSecret: z.string().optional(),
  timezone: z.string().default('UTC'),
  snmpDefaults: LibreNmsSnmpDefaultsSchema.prefault({}),
  discoverySubnets: z.array(LibreNmsDiscoverySubnetSchema).default([]),
  ldapAuth: LibreNmsLdapAuthSchema.prefault({}),
  sync: LibreNmsSyncConfigSchema.prefault({}),
});
export type LibreNmsConfig = z.infer<typeof LibreNmsConfigSchema>;

export const TopologyLayerSchema = z.enum(['physical', 'l2-l3', 'vpn', 'k3s', 'virt']);
export type TopologyLayer = z.infer<typeof TopologyLayerSchema>;

export const TopologyPortKindSchema = z.enum([
  'physical-nic',
  'sfp',
  'wan-uplink',
  'switch-port',
  'vlan-if',
  'tunnel',
  'ingress',
  'service',
  'storage',
  'virtual-nic',
  'generic',
]);
export type TopologyPortKind = z.infer<typeof TopologyPortKindSchema>;

export const TopologyPortSpecSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  kind: TopologyPortKindSchema.default('physical-nic'),
  speedMbps: z.number().int().min(1).optional(),
  mtu: z.number().int().min(68).max(65535).optional(),
  vlanIds: z.array(z.number().int().min(1).max(4094)).default([]),
  subnetCidr: z.string().optional(),
  planned: z.boolean().default(false),
});
export type TopologyPortSpec = z.infer<typeof TopologyPortSpecSchema>;

export const TopologyLldpConfigSchema = z.object({
  enabled: z.boolean().default(false),
  excludeWan: z.boolean().default(true),
  interfaces: z
    .array(z.string().regex(/^[a-zA-Z0-9_.:*-]+$/, 'Invalid LLDP interface pattern'))
    .default([]),
  systemDescription: z.string().optional(),
});
export type TopologyLldpConfig = z.infer<typeof TopologyLldpConfigSchema>;

export const TopologyPollingConfigSchema = z.object({
  localIntervalSec: z.number().int().min(2).max(300).default(5),
  peerIntervalSec: z.number().int().min(5).max(600).default(10),
  pauseWhenHidden: z.boolean().default(true),
});
export type TopologyPollingConfig = z.infer<typeof TopologyPollingConfigSchema>;

export const TopologyPeerRoleSchema = z.enum([
  'edge-ngfw',
  'k3s-storage',
  'vault',
  'nas',
  'satellite',
  'generic',
]);
export type TopologyPeerRole = z.infer<typeof TopologyPeerRoleSchema>;

export const TopologyPeerHostSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  role: TopologyPeerRoleSchema.default('generic'),
  apiUrl: z.string().min(1),
  apiToken: z.string().optional(),
  tlsCaCert: z.string().optional(),
  tlsCertSha256: z.string().optional(),
  useHaMtls: z.boolean().default(false),
  enabled: z.boolean().default(true),
  site: z.string().optional(),
  rack: z.string().optional(),
});
export type TopologyPeerHost = z.infer<typeof TopologyPeerHostSchema>;

export const TopologyNodeKindSchema = z.enum([
  'wan',
  'switch',
  'patch-panel',
  'edge-ngfw',
  'k3s-node',
  'vault',
  'nas',
  'satellite',
  'generic-host',
  'vlan',
  'bridge-bond',
  'vip',
  'vpn-overlay',
  'haproxy',
  'k3s-ingress',
  'k3s-service',
  'k3s-workload',
  'k3s-pvc',
  'k3s-netpol',
  'k3s-crd',
  'kvm-vm',
  'lxc-container',
]);
export type TopologyNodeKind = z.infer<typeof TopologyNodeKindSchema>;

export const TopologyCanvasNodeSchema = z.object({
  id: z.string().min(1),
  kind: TopologyNodeKindSchema,
  label: z.string().min(1),
  position: z.object({ x: z.number(), y: z.number() }).default({ x: 0, y: 0 }),
  hostRef: z.string().optional(),
  layer: TopologyLayerSchema.default('physical'),
  managed: z.boolean().default(false),
  ports: z.array(TopologyPortSpecSchema).default([]),
  metadata: z.record(z.string(), z.unknown()).default({}),
});
export type TopologyCanvasNode = z.infer<typeof TopologyCanvasNodeSchema>;

export const TopologyCableMediumSchema = z.enum([
  'rj45-cat6a',
  'sfp-dac',
  'fiber-om4',
  'fiber-os2',
  'ont-coax',
  'vlan-trunk',
  'l3-route',
  'wireguard',
  'headscale',
  'ipsec',
  'k3s-route',
  'k3s-storage',
  'virt-bridge',
]);
export type TopologyCableMedium = z.infer<typeof TopologyCableMediumSchema>;

export const TopologyCableEdgeSchema = z.object({
  id: z.string().min(1),
  sourceNodeId: z.string().min(1),
  sourcePortId: z.string().min(1),
  targetNodeId: z.string().min(1),
  targetPortId: z.string().min(1),
  layer: TopologyLayerSchema.default('physical'),
  medium: TopologyCableMediumSchema.default('rj45-cat6a'),
  status: z.enum(['planned', 'installed', 'virtual']).default('planned'),
  speedMbps: z.number().int().min(1).optional(),
  lengthMeters: z.number().min(0).optional(),
  color: z.string().optional(),
  cableLabel: z.string().optional(),
  vlanIds: z.array(z.number().int().min(1).max(4094)).default([]),
  mtu: z.number().int().min(68).max(65535).optional(),
  notes: z.string().optional(),
});
export type TopologyCableEdge = z.infer<typeof TopologyCableEdgeSchema>;

export const TopologyScenarioSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().default(''),
  createdAt: z.string(),
  updatedAt: z.string(),
  nodes: z.array(TopologyCanvasNodeSchema).default([]),
  cables: z.array(TopologyCableEdgeSchema).default([]),
});
export type TopologyScenario = z.infer<typeof TopologyScenarioSchema>;

export const TopologyLayerDefaultsSchema = z.object({
  physical: z.boolean().default(true),
  l2L3: z.boolean().default(true),
  vpn: z.boolean().default(true),
  k3s: z.boolean().default(true),
  virt: z.boolean().default(false),
});
export type TopologyLayerDefaults = z.infer<typeof TopologyLayerDefaultsSchema>;

export const TopologyConfigSchema = z.object({
  enabled: z.boolean().default(false),
  lldp: TopologyLldpConfigSchema.prefault({}),
  polling: TopologyPollingConfigSchema.prefault({}),
  peers: z.array(TopologyPeerHostSchema).default([]),
  nodes: z.array(TopologyCanvasNodeSchema).default([]),
  cables: z.array(TopologyCableEdgeSchema).default([]),
  scenarios: z.array(TopologyScenarioSchema).default([]),
  activeScenarioId: z.string().optional(),
  layerDefaults: TopologyLayerDefaultsSchema.prefault({}),
});
export type TopologyConfig = z.infer<typeof TopologyConfigSchema>;

export const NetFlowListenerProtocolSchema = z.enum(['auto', 'netflow', 'ipfix', 'sflow']);
export type NetFlowListenerProtocol = z.infer<typeof NetFlowListenerProtocolSchema>;

export const NetFlowTlsConfigSchema = z.object({
  useHaPki: z.boolean().default(true),
  requireClientCert: z.boolean().default(true),
  certPath: z.string().default(''),
  keyPath: z.string().default(''),
  caPath: z.string().default(''),
  serverName: z.string().optional(),
  insecureSkipVerify: z.boolean().optional(),
});
export type NetFlowTlsConfig = z.infer<typeof NetFlowTlsConfigSchema>;

export const NetFlowListenerSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  protocol: NetFlowListenerProtocolSchema.default('auto'),
  transport: z.enum(['udp', 'tcp', 'tls']).default('udp'),
  bindAddress: z.string().min(1).default('0.0.0.0'),
  port: z.number().int().min(1).max(65535).default(2055),
  socketRecvBufferKB: z.number().int().min(64).max(131072).default(8192),
  workers: z.number().int().min(1).max(32).default(4),
  allowedExporters: z.array(z.string()).default([]),
  dropUnknownTemplates: z.boolean().default(false),
  tls: NetFlowTlsConfigSchema.optional(),
});
export type NetFlowListener = z.infer<typeof NetFlowListenerSchema>;

export const NetFlowExporterVendorSchema = z.enum([
  'axonwall',
  'cisco',
  'juniper',
  'arista',
  'mikrotik',
  'paloalto',
  'fortinet',
  'ubiquiti',
  'linux',
  'other',
]);
export type NetFlowExporterVendor = z.infer<typeof NetFlowExporterVendorSchema>;

export const NetFlowExporterProfileSchema = z.object({
  id: z.string().min(1),
  ip: z.string().min(1),
  name: z.string().min(1),
  site: z.string().optional(),
  vendor: NetFlowExporterVendorSchema.default('other'),
  samplingRateOverride: z.number().int().min(0).max(1000000).default(0),
  ifIndexAliases: z.record(z.string(), z.string()).default({}),
  enabled: z.boolean().default(true),
  expectedFpsMin: z.number().min(0).default(0),
});
export type NetFlowExporterProfile = z.infer<typeof NetFlowExporterProfileSchema>;

export const NetFlowMetadataSyncSchema = z.object({
  enabled: z.boolean().default(false),
  targetUrl: z.string().optional(),
  apiToken: z.string().optional(),
  intervalSec: z.number().int().min(15).max(3600).default(60),
});
export type NetFlowMetadataSync = z.infer<typeof NetFlowMetadataSyncSchema>;

export const NetFlowSelfExportTargetSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  version: z.enum(['ipfix', 'netflow9']).default('ipfix'),
  host: z.string().min(1).default('127.0.0.1'),
  port: z.number().int().min(1).max(65535).default(2055),
  transport: z.enum(['udp', 'tcp', 'tls']).default('udp'),
  interfaces: z.array(z.string()).default([]),
  activeTimeoutSec: z.number().int().min(5).max(3600).default(60),
  inactiveTimeoutSec: z.number().int().min(5).max(600).default(15),
  templateRefreshSec: z.number().int().min(30).max(3600).default(300),
  samplingRate: z.number().int().min(1).max(100000).default(1),
  observationDomainId: z.number().int().min(1).max(4294967295).default(1),
  tls: NetFlowTlsConfigSchema.optional(),
});
export type NetFlowSelfExportTarget = z.infer<typeof NetFlowSelfExportTargetSchema>;

export const NetFlowReplicatorProtocolSchema = z.enum(['netflow5', 'netflow9', 'ipfix', 'sflow5']);

export const NetFlowReplicatorTargetSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  destinationHost: z.string().min(1),
  destinationPort: z.number().int().min(1).max(65535).default(2055),
  spoofSourceIp: z.boolean().default(false),
  filterExporters: z.array(z.string()).default([]),
  filterProtocols: z.array(NetFlowReplicatorProtocolSchema).default([]),
  rateLimitPps: z.number().int().min(0).default(0),
});
export type NetFlowReplicatorTarget = z.infer<typeof NetFlowReplicatorTargetSchema>;

export const NetFlowStorageClickHouseSchema = z.object({
  enabled: z.boolean().default(false),
  url: z.string().default('http://127.0.0.1:8123'),
  database: z.string().default('axonwall'),
  table: z.string().default('netflow_flows'),
  username: z.string().default('admin'),
  password: z.string().optional(),
  batchSize: z.number().int().min(100).max(100000).default(5000),
  ttlDays: z.number().int().min(1).max(3650).default(30),
});

export const NetFlowStorageConfigSchema = z.object({
  mode: z.enum(['local', 'clickhouse', 'hybrid']).default('local'),
  dataDir: z.string().default('/var/lib/axonwall/netflow'),
  retentionHours: z.number().int().min(1).max(8760).default(168),
  maxDiskMB: z.number().int().min(64).max(1048576).default(4096),
  hotRingSize: z.number().int().min(1000).max(500000).default(50000),
  flushIntervalSec: z.number().int().min(5).max(300).default(15),
  compression: z.enum(['zstd', 'gzip', 'none']).default('zstd'),
  rollupIntervals: z.array(z.enum(['1m', '5m', '1h'])).default(['1m', '5m', '1h']),
  clickhouse: NetFlowStorageClickHouseSchema.prefault({}),
});
export type NetFlowStorageConfig = z.infer<typeof NetFlowStorageConfigSchema>;

export const NetFlowEnrichmentConfigSchema = z.object({
  reverseDns: z.boolean().default(true),
  dnsCacheTtlSec: z.number().int().min(60).max(86400).default(3600),
  keaDhcpLeases: z.boolean().default(true),
  unboundOverrides: z.boolean().default(true),
  librenmsIfNames: z.boolean().default(true),
  netboxInventory: z.boolean().default(true),
  k3sPodServiceTagging: z.boolean().default(true),
  frrBgpLookup: z.boolean().default(true),
  natConntrackCorrelation: z.boolean().default(true),
  geoipAsn: z.boolean().default(true),
  geoipCityDbPath: z.string().default('/var/lib/axonwall/geoip/GeoLite2-City.mmdb'),
  geoipAsnDbPath: z.string().default('/var/lib/axonwall/geoip/GeoLite2-ASN.mmdb'),
  geoipAutoUpdate: z.boolean().default(false),
  geoipUpdateIntervalHours: z.number().int().min(1).max(720).default(168),
  geoipCityDownloadUrl: z.string().default(''),
  geoipAsnDownloadUrl: z.string().default(''),
  threatIntelMatch: z.boolean().default(true),
  customPortApps: z.record(z.string(), z.string()).default({}),
  internalCidrs: z
    .array(z.string())
    .default(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7']),
});
export type NetFlowEnrichmentConfig = z.infer<typeof NetFlowEnrichmentConfigSchema>;

export const NetFlowAlertRuleKindSchema = z.enum([
  'volumetric_bps',
  'volumetric_pps',
  'port_scan',
  'host_sweep',
  'exfiltration',
  'c2_beacon',
  'syn_flood',
  'threat_ioc',
  'exporter_silent',
  'baseline_zscore',
  'first_seen_pair',
  'custom_fql',
]);
export type NetFlowAlertRuleKind = z.infer<typeof NetFlowAlertRuleKindSchema>;

export const NetFlowReportingConfigSchema = z.object({
  enabled: z.boolean().default(false),
  intervalHours: z.number().int().min(1).max(720).default(24),
  format: z.enum(['json', 'csv', 'markdown']).default('markdown'),
  groupBy: z.enum(['interface', 'exporter', 'vlan', 'subnet']).default('interface'),
  rangeDays: z.number().int().min(1).max(90).default(7),
  retentionCount: z.number().int().min(1).max(365).default(30),
  webhookUrl: z.string().default(''),
});
export type NetFlowReportingConfig = z.infer<typeof NetFlowReportingConfigSchema>;

export const NetFlowAlertActionSchema = z.enum([
  'alert_log',
  'webhook',
  'vigilante_soar',
  'xdp_block',
]);
export type NetFlowAlertAction = z.infer<typeof NetFlowAlertActionSchema>;

export const NetFlowAlertRuleSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  kind: NetFlowAlertRuleKindSchema.default('volumetric_bps'),
  severity: z.enum(['info', 'warning', 'high', 'critical']).default('high'),
  fqlFilter: z.string().optional(),
  threshold: z.number().min(0).default(0),
  windowSec: z.number().int().min(10).max(3600).default(60),
  cooldownSec: z.number().int().min(30).max(86400).default(300),
  actions: z.array(NetFlowAlertActionSchema).default(['alert_log']),
  xdpBlockTtlSec: z.number().int().min(60).max(86400).default(900),
  remoteEdgeMitigation: z.boolean().default(false).optional(),
  webhookUrl: z.string().optional(),
});
export type NetFlowAlertRule = z.infer<typeof NetFlowAlertRuleSchema>;

export const NetFlowSavedViewSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  fql: z.string().default(''),
  range: z.string().default('1h'),
  groupBy: z.string().default('protocol'),
});
export type NetFlowSavedView = z.infer<typeof NetFlowSavedViewSchema>;

const DEFAULT_NETFLOW_LISTENERS: NetFlowListener[] = [
  {
    id: 'default-auto-2055',
    name: 'Primary Multi-Protocol (v5/v9/IPFIX/sFlow)',
    enabled: true,
    protocol: 'auto',
    transport: 'udp',
    bindAddress: '0.0.0.0',
    port: 2055,
    socketRecvBufferKB: 8192,
    workers: 4,
    allowedExporters: [],
    dropUnknownTemplates: false,
  },
];

const DEFAULT_NETFLOW_SELF_TARGETS: NetFlowSelfExportTarget[] = [
  {
    id: 'local-loopback-ipfix',
    name: 'Local Axonwall Collector (Loopback IPFIX)',
    enabled: true,
    version: 'ipfix',
    host: '127.0.0.1',
    port: 2055,
    transport: 'udp',
    interfaces: [],
    activeTimeoutSec: 60,
    inactiveTimeoutSec: 15,
    templateRefreshSec: 300,
    samplingRate: 1,
    observationDomainId: 1,
  },
];

const DEFAULT_NETFLOW_ALERT_RULES: NetFlowAlertRule[] = [
  {
    id: 'builtin-port-scan',
    name: 'Port Scan (Unique Dst Ports / Source)',
    enabled: true,
    kind: 'port_scan',
    severity: 'high',
    threshold: 40,
    windowSec: 60,
    cooldownSec: 300,
    actions: ['alert_log'],
    xdpBlockTtlSec: 900,
  },
  {
    id: 'builtin-volumetric-spike',
    name: 'Volumetric Spike (>= 500 Mbps per Source)',
    enabled: true,
    kind: 'volumetric_bps',
    severity: 'warning',
    threshold: 500_000_000,
    windowSec: 60,
    cooldownSec: 300,
    actions: ['alert_log'],
    xdpBlockTtlSec: 900,
  },
  {
    id: 'builtin-threat-ioc',
    name: 'Threat Intel / Blocklist IOC Match',
    enabled: true,
    kind: 'threat_ioc',
    severity: 'critical',
    threshold: 1,
    windowSec: 60,
    cooldownSec: 300,
    actions: ['alert_log'],
    xdpBlockTtlSec: 900,
  },
];

export const NetFlowConfigSchema = z.object({
  enabled: z.boolean().default(false),
  mode: z.enum(['collector', 'exporter', 'both']).default('both').optional(),
  nodeId: z.string().max(128).optional(),
  listeners: z.array(NetFlowListenerSchema).default(DEFAULT_NETFLOW_LISTENERS),
  exporterProfiles: z.array(NetFlowExporterProfileSchema).default([]),
  selfExport: z
    .object({
      enabled: z.boolean().default(true),
      targets: z.array(NetFlowSelfExportTargetSchema).default(DEFAULT_NETFLOW_SELF_TARGETS),
      metadataSync: NetFlowMetadataSyncSchema.optional(),
    })
    .default({ enabled: true, targets: DEFAULT_NETFLOW_SELF_TARGETS }),
  replicator: z
    .object({
      enabled: z.boolean().default(false),
      targets: z.array(NetFlowReplicatorTargetSchema).default([]),
    })
    .default({ enabled: false, targets: [] }),
  storage: NetFlowStorageConfigSchema.prefault({}),
  enrichment: NetFlowEnrichmentConfigSchema.prefault({}),
  alerting: z
    .object({
      enabled: z.boolean().default(true),
      rules: z.array(NetFlowAlertRuleSchema).default(DEFAULT_NETFLOW_ALERT_RULES),
    })
    .default({ enabled: true, rules: DEFAULT_NETFLOW_ALERT_RULES }),
  topologyOverlay: z
    .object({
      enabled: z.boolean().default(true),
      windowSec: z.number().int().min(10).max(600).default(60),
    })
    .default({ enabled: true, windowSec: 60 }),
  reporting: NetFlowReportingConfigSchema.prefault({}),
  savedViews: z.array(NetFlowSavedViewSchema).default([]),
});
export type NetFlowConfig = z.infer<typeof NetFlowConfigSchema>;

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
  dhcp: DhcpConfigSchema.prefault({ enabled: true, subnets: [] }),
  dns: DnsConfigSchema.prefault({ enabled: true, hostOverrides: [] }),
  mdnsReflector: MdnsReflectorConfigSchema.optional(),
  upnp: UpnpConfigSchema.optional(),
  ddns: DdnsConfigSchema.optional(),
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
  threatHarvester: ThreatHarvesterConfigSchema.optional(),
  eluvix: EluvixConfigSchema.optional(),
  netbox: NetBoxConfigSchema.optional(),
  librenms: LibreNmsConfigSchema.optional(),
  topology: TopologyConfigSchema.optional(),
  netflow: NetFlowConfigSchema.optional(),
  mcp: McpServerConfigSchema.optional(),
});
export type DesiredState = z.infer<typeof DesiredStateSchema>;




