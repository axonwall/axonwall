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
export const AliasTypeSchema = z.enum(['host', 'network', 'port', 'mac', 'urltable']);
export const AliasSchema = z.object({
    id: z.string().uuid().optional(),
    name: z.string().regex(/^[a-zA-Z0-9_]+$/, 'Alias name must be alphanumeric or underscore'),
    type: AliasTypeSchema,
    entries: z.array(z.string().min(1)),
    description: z.string().max(255).default(''),
    enabled: z.boolean().default(true),
});
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
    log: z.boolean().default(false),
    enabled: z.boolean().default(true),
    description: z.string().max(255).default(''),
    sortOrder: z.number().int().default(100),
});
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
export const DesiredStateSchema = z.object({
    version: z.number().int().default(1),
    system: SystemSettingsSchema.default({}),
    interfaces: z.array(InterfaceSchema).default([]),
    aliases: z.array(AliasSchema).default([]),
    rules: z.array(FirewallRuleSchema).default([]),
    nat: z.array(NatRuleSchema).default([]),
    gateways: z.array(GatewaySchema).default([]),
    wireguard: WireGuardConfigSchema.optional(),
});
