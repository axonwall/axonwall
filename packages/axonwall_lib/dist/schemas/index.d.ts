import { z } from 'zod';
export declare const InterfaceTypeSchema: z.ZodEnum<["static", "dhcp", "pppoe", "track6", "vlan", "bridge", "wireguard", "loopback"]>;
export declare const InterfaceSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    name: z.ZodString;
    device: z.ZodString;
    type: z.ZodDefault<z.ZodEnum<["static", "dhcp", "pppoe", "track6", "vlan", "bridge", "wireguard", "loopback"]>>;
    enabled: z.ZodDefault<z.ZodBoolean>;
    description: z.ZodDefault<z.ZodString>;
    ipv4Address: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    ipv4Gateway: z.ZodOptional<z.ZodString>;
    ipv6Address: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    ipv6Gateway: z.ZodOptional<z.ZodString>;
    mtu: z.ZodDefault<z.ZodNumber>;
    macAddress: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
}, "strip", z.ZodTypeAny, {
    name: string;
    device: string;
    type: "static" | "dhcp" | "pppoe" | "track6" | "vlan" | "bridge" | "wireguard" | "loopback";
    enabled: boolean;
    description: string;
    mtu: number;
    id?: string | undefined;
    ipv4Address?: string | undefined;
    ipv4Gateway?: string | undefined;
    ipv6Address?: string | undefined;
    ipv6Gateway?: string | undefined;
    macAddress?: string | undefined;
}, {
    name: string;
    device: string;
    id?: string | undefined;
    type?: "static" | "dhcp" | "pppoe" | "track6" | "vlan" | "bridge" | "wireguard" | "loopback" | undefined;
    enabled?: boolean | undefined;
    description?: string | undefined;
    ipv4Address?: string | undefined;
    ipv4Gateway?: string | undefined;
    ipv6Address?: string | undefined;
    ipv6Gateway?: string | undefined;
    mtu?: number | undefined;
    macAddress?: string | undefined;
}>;
export type Interface = z.infer<typeof InterfaceSchema>;
export declare const AliasTypeSchema: z.ZodEnum<["host", "network", "port", "mac", "urltable"]>;
export declare const AliasSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    name: z.ZodString;
    type: z.ZodEnum<["host", "network", "port", "mac", "urltable"]>;
    entries: z.ZodArray<z.ZodString, "many">;
    description: z.ZodDefault<z.ZodString>;
    enabled: z.ZodDefault<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    entries: string[];
    name: string;
    type: "host" | "network" | "port" | "mac" | "urltable";
    enabled: boolean;
    description: string;
    id?: string | undefined;
}, {
    entries: string[];
    name: string;
    type: "host" | "network" | "port" | "mac" | "urltable";
    id?: string | undefined;
    enabled?: boolean | undefined;
    description?: string | undefined;
}>;
export type Alias = z.infer<typeof AliasSchema>;
export declare const RuleActionSchema: z.ZodEnum<["pass", "block", "reject"]>;
export declare const RuleDirectionSchema: z.ZodEnum<["in", "out"]>;
export declare const RuleProtocolSchema: z.ZodEnum<["any", "tcp", "udp", "tcp_udp", "icmp", "ipv6-icmp", "esp", "ah", "gre"]>;
export declare const FirewallRuleSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    action: z.ZodDefault<z.ZodEnum<["pass", "block", "reject"]>>;
    direction: z.ZodDefault<z.ZodEnum<["in", "out"]>>;
    interface: z.ZodDefault<z.ZodString>;
    quick: z.ZodDefault<z.ZodBoolean>;
    protocol: z.ZodDefault<z.ZodEnum<["any", "tcp", "udp", "tcp_udp", "icmp", "ipv6-icmp", "esp", "ah", "gre"]>>;
    source: z.ZodDefault<z.ZodString>;
    sourcePort: z.ZodDefault<z.ZodEffects<z.ZodString, string, string>>;
    destination: z.ZodDefault<z.ZodString>;
    destinationPort: z.ZodDefault<z.ZodEffects<z.ZodString, string, string>>;
    gateway: z.ZodOptional<z.ZodString>;
    log: z.ZodDefault<z.ZodBoolean>;
    enabled: z.ZodDefault<z.ZodBoolean>;
    description: z.ZodDefault<z.ZodString>;
    sortOrder: z.ZodDefault<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    enabled: boolean;
    description: string;
    action: "pass" | "block" | "reject";
    direction: "in" | "out";
    interface: string;
    quick: boolean;
    protocol: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre";
    source: string;
    sourcePort: string;
    destination: string;
    destinationPort: string;
    log: boolean;
    sortOrder: number;
    id?: string | undefined;
    gateway?: string | undefined;
}, {
    id?: string | undefined;
    enabled?: boolean | undefined;
    description?: string | undefined;
    action?: "pass" | "block" | "reject" | undefined;
    direction?: "in" | "out" | undefined;
    interface?: string | undefined;
    quick?: boolean | undefined;
    protocol?: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre" | undefined;
    source?: string | undefined;
    sourcePort?: string | undefined;
    destination?: string | undefined;
    destinationPort?: string | undefined;
    gateway?: string | undefined;
    log?: boolean | undefined;
    sortOrder?: number | undefined;
}>;
export type FirewallRule = z.infer<typeof FirewallRuleSchema>;
export declare const NatTypeSchema: z.ZodEnum<["dnat", "snat", "masquerade", "nptv6"]>;
export declare const NatRuleSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    type: z.ZodDefault<z.ZodEnum<["dnat", "snat", "masquerade", "nptv6"]>>;
    interface: z.ZodDefault<z.ZodString>;
    protocol: z.ZodDefault<z.ZodEnum<["any", "tcp", "udp", "tcp_udp", "icmp", "ipv6-icmp", "esp", "ah", "gre"]>>;
    source: z.ZodDefault<z.ZodString>;
    sourcePort: z.ZodDefault<z.ZodString>;
    destination: z.ZodDefault<z.ZodString>;
    destinationPort: z.ZodDefault<z.ZodString>;
    targetIp: z.ZodOptional<z.ZodString>;
    targetPort: z.ZodOptional<z.ZodString>;
    log: z.ZodDefault<z.ZodBoolean>;
    enabled: z.ZodDefault<z.ZodBoolean>;
    description: z.ZodDefault<z.ZodString>;
    sortOrder: z.ZodDefault<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    type: "dnat" | "snat" | "masquerade" | "nptv6";
    enabled: boolean;
    description: string;
    interface: string;
    protocol: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre";
    source: string;
    sourcePort: string;
    destination: string;
    destinationPort: string;
    log: boolean;
    sortOrder: number;
    id?: string | undefined;
    targetIp?: string | undefined;
    targetPort?: string | undefined;
}, {
    id?: string | undefined;
    type?: "dnat" | "snat" | "masquerade" | "nptv6" | undefined;
    enabled?: boolean | undefined;
    description?: string | undefined;
    interface?: string | undefined;
    protocol?: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre" | undefined;
    source?: string | undefined;
    sourcePort?: string | undefined;
    destination?: string | undefined;
    destinationPort?: string | undefined;
    log?: boolean | undefined;
    sortOrder?: number | undefined;
    targetIp?: string | undefined;
    targetPort?: string | undefined;
}>;
export type NatRule = z.infer<typeof NatRuleSchema>;
export declare const GatewaySchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    name: z.ZodString;
    interface: z.ZodString;
    gatewayIp: z.ZodEffects<z.ZodString, string, string>;
    monitorIp: z.ZodOptional<z.ZodString>;
    weight: z.ZodDefault<z.ZodNumber>;
    isDefault: z.ZodDefault<z.ZodBoolean>;
    enabled: z.ZodDefault<z.ZodBoolean>;
    description: z.ZodDefault<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    name: string;
    enabled: boolean;
    description: string;
    interface: string;
    gatewayIp: string;
    weight: number;
    isDefault: boolean;
    id?: string | undefined;
    monitorIp?: string | undefined;
}, {
    name: string;
    interface: string;
    gatewayIp: string;
    id?: string | undefined;
    enabled?: boolean | undefined;
    description?: string | undefined;
    monitorIp?: string | undefined;
    weight?: number | undefined;
    isDefault?: boolean | undefined;
}>;
export type Gateway = z.infer<typeof GatewaySchema>;
export declare const WireGuardPeerSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    name: z.ZodString;
    publicKey: z.ZodString;
    presharedKey: z.ZodOptional<z.ZodString>;
    allowedIps: z.ZodArray<z.ZodString, "many">;
    endpoint: z.ZodOptional<z.ZodString>;
    persistentKeepalive: z.ZodDefault<z.ZodNumber>;
    enabled: z.ZodDefault<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    name: string;
    enabled: boolean;
    publicKey: string;
    allowedIps: string[];
    persistentKeepalive: number;
    id?: string | undefined;
    presharedKey?: string | undefined;
    endpoint?: string | undefined;
}, {
    name: string;
    publicKey: string;
    allowedIps: string[];
    id?: string | undefined;
    enabled?: boolean | undefined;
    presharedKey?: string | undefined;
    endpoint?: string | undefined;
    persistentKeepalive?: number | undefined;
}>;
export declare const WireGuardConfigSchema: z.ZodObject<{
    enabled: z.ZodDefault<z.ZodBoolean>;
    listenPort: z.ZodDefault<z.ZodNumber>;
    privateKey: z.ZodOptional<z.ZodString>;
    address: z.ZodDefault<z.ZodString>;
    peers: z.ZodDefault<z.ZodArray<z.ZodObject<{
        id: z.ZodOptional<z.ZodString>;
        name: z.ZodString;
        publicKey: z.ZodString;
        presharedKey: z.ZodOptional<z.ZodString>;
        allowedIps: z.ZodArray<z.ZodString, "many">;
        endpoint: z.ZodOptional<z.ZodString>;
        persistentKeepalive: z.ZodDefault<z.ZodNumber>;
        enabled: z.ZodDefault<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        name: string;
        enabled: boolean;
        publicKey: string;
        allowedIps: string[];
        persistentKeepalive: number;
        id?: string | undefined;
        presharedKey?: string | undefined;
        endpoint?: string | undefined;
    }, {
        name: string;
        publicKey: string;
        allowedIps: string[];
        id?: string | undefined;
        enabled?: boolean | undefined;
        presharedKey?: string | undefined;
        endpoint?: string | undefined;
        persistentKeepalive?: number | undefined;
    }>, "many">>;
}, "strip", z.ZodTypeAny, {
    enabled: boolean;
    listenPort: number;
    address: string;
    peers: {
        name: string;
        enabled: boolean;
        publicKey: string;
        allowedIps: string[];
        persistentKeepalive: number;
        id?: string | undefined;
        presharedKey?: string | undefined;
        endpoint?: string | undefined;
    }[];
    privateKey?: string | undefined;
}, {
    enabled?: boolean | undefined;
    listenPort?: number | undefined;
    privateKey?: string | undefined;
    address?: string | undefined;
    peers?: {
        name: string;
        publicKey: string;
        allowedIps: string[];
        id?: string | undefined;
        enabled?: boolean | undefined;
        presharedKey?: string | undefined;
        endpoint?: string | undefined;
        persistentKeepalive?: number | undefined;
    }[] | undefined;
}>;
export declare const AntiLockoutSchema: z.ZodObject<{
    enabled: z.ZodDefault<z.ZodBoolean>;
    interface: z.ZodDefault<z.ZodString>;
    ports: z.ZodDefault<z.ZodArray<z.ZodNumber, "many">>;
}, "strip", z.ZodTypeAny, {
    enabled: boolean;
    interface: string;
    ports: number[];
}, {
    enabled?: boolean | undefined;
    interface?: string | undefined;
    ports?: number[] | undefined;
}>;
export declare const SystemSettingsSchema: z.ZodObject<{
    hostname: z.ZodDefault<z.ZodString>;
    domain: z.ZodDefault<z.ZodString>;
    dnsServers: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
    timezone: z.ZodDefault<z.ZodString>;
    flowtableOffload: z.ZodDefault<z.ZodBoolean>;
    antiLockout: z.ZodDefault<z.ZodObject<{
        enabled: z.ZodDefault<z.ZodBoolean>;
        interface: z.ZodDefault<z.ZodString>;
        ports: z.ZodDefault<z.ZodArray<z.ZodNumber, "many">>;
    }, "strip", z.ZodTypeAny, {
        enabled: boolean;
        interface: string;
        ports: number[];
    }, {
        enabled?: boolean | undefined;
        interface?: string | undefined;
        ports?: number[] | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    hostname: string;
    domain: string;
    dnsServers: string[];
    timezone: string;
    flowtableOffload: boolean;
    antiLockout: {
        enabled: boolean;
        interface: string;
        ports: number[];
    };
}, {
    hostname?: string | undefined;
    domain?: string | undefined;
    dnsServers?: string[] | undefined;
    timezone?: string | undefined;
    flowtableOffload?: boolean | undefined;
    antiLockout?: {
        enabled?: boolean | undefined;
        interface?: string | undefined;
        ports?: number[] | undefined;
    } | undefined;
}>;
export declare const DesiredStateSchema: z.ZodObject<{
    version: z.ZodDefault<z.ZodNumber>;
    system: z.ZodDefault<z.ZodObject<{
        hostname: z.ZodDefault<z.ZodString>;
        domain: z.ZodDefault<z.ZodString>;
        dnsServers: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
        timezone: z.ZodDefault<z.ZodString>;
        flowtableOffload: z.ZodDefault<z.ZodBoolean>;
        antiLockout: z.ZodDefault<z.ZodObject<{
            enabled: z.ZodDefault<z.ZodBoolean>;
            interface: z.ZodDefault<z.ZodString>;
            ports: z.ZodDefault<z.ZodArray<z.ZodNumber, "many">>;
        }, "strip", z.ZodTypeAny, {
            enabled: boolean;
            interface: string;
            ports: number[];
        }, {
            enabled?: boolean | undefined;
            interface?: string | undefined;
            ports?: number[] | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        hostname: string;
        domain: string;
        dnsServers: string[];
        timezone: string;
        flowtableOffload: boolean;
        antiLockout: {
            enabled: boolean;
            interface: string;
            ports: number[];
        };
    }, {
        hostname?: string | undefined;
        domain?: string | undefined;
        dnsServers?: string[] | undefined;
        timezone?: string | undefined;
        flowtableOffload?: boolean | undefined;
        antiLockout?: {
            enabled?: boolean | undefined;
            interface?: string | undefined;
            ports?: number[] | undefined;
        } | undefined;
    }>>;
    interfaces: z.ZodDefault<z.ZodArray<z.ZodObject<{
        id: z.ZodOptional<z.ZodString>;
        name: z.ZodString;
        device: z.ZodString;
        type: z.ZodDefault<z.ZodEnum<["static", "dhcp", "pppoe", "track6", "vlan", "bridge", "wireguard", "loopback"]>>;
        enabled: z.ZodDefault<z.ZodBoolean>;
        description: z.ZodDefault<z.ZodString>;
        ipv4Address: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        ipv4Gateway: z.ZodOptional<z.ZodString>;
        ipv6Address: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
        ipv6Gateway: z.ZodOptional<z.ZodString>;
        mtu: z.ZodDefault<z.ZodNumber>;
        macAddress: z.ZodOptional<z.ZodEffects<z.ZodString, string, string>>;
    }, "strip", z.ZodTypeAny, {
        name: string;
        device: string;
        type: "static" | "dhcp" | "pppoe" | "track6" | "vlan" | "bridge" | "wireguard" | "loopback";
        enabled: boolean;
        description: string;
        mtu: number;
        id?: string | undefined;
        ipv4Address?: string | undefined;
        ipv4Gateway?: string | undefined;
        ipv6Address?: string | undefined;
        ipv6Gateway?: string | undefined;
        macAddress?: string | undefined;
    }, {
        name: string;
        device: string;
        id?: string | undefined;
        type?: "static" | "dhcp" | "pppoe" | "track6" | "vlan" | "bridge" | "wireguard" | "loopback" | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
        ipv4Address?: string | undefined;
        ipv4Gateway?: string | undefined;
        ipv6Address?: string | undefined;
        ipv6Gateway?: string | undefined;
        mtu?: number | undefined;
        macAddress?: string | undefined;
    }>, "many">>;
    aliases: z.ZodDefault<z.ZodArray<z.ZodObject<{
        id: z.ZodOptional<z.ZodString>;
        name: z.ZodString;
        type: z.ZodEnum<["host", "network", "port", "mac", "urltable"]>;
        entries: z.ZodArray<z.ZodString, "many">;
        description: z.ZodDefault<z.ZodString>;
        enabled: z.ZodDefault<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        entries: string[];
        name: string;
        type: "host" | "network" | "port" | "mac" | "urltable";
        enabled: boolean;
        description: string;
        id?: string | undefined;
    }, {
        entries: string[];
        name: string;
        type: "host" | "network" | "port" | "mac" | "urltable";
        id?: string | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
    }>, "many">>;
    rules: z.ZodDefault<z.ZodArray<z.ZodObject<{
        id: z.ZodOptional<z.ZodString>;
        action: z.ZodDefault<z.ZodEnum<["pass", "block", "reject"]>>;
        direction: z.ZodDefault<z.ZodEnum<["in", "out"]>>;
        interface: z.ZodDefault<z.ZodString>;
        quick: z.ZodDefault<z.ZodBoolean>;
        protocol: z.ZodDefault<z.ZodEnum<["any", "tcp", "udp", "tcp_udp", "icmp", "ipv6-icmp", "esp", "ah", "gre"]>>;
        source: z.ZodDefault<z.ZodString>;
        sourcePort: z.ZodDefault<z.ZodEffects<z.ZodString, string, string>>;
        destination: z.ZodDefault<z.ZodString>;
        destinationPort: z.ZodDefault<z.ZodEffects<z.ZodString, string, string>>;
        gateway: z.ZodOptional<z.ZodString>;
        log: z.ZodDefault<z.ZodBoolean>;
        enabled: z.ZodDefault<z.ZodBoolean>;
        description: z.ZodDefault<z.ZodString>;
        sortOrder: z.ZodDefault<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        enabled: boolean;
        description: string;
        action: "pass" | "block" | "reject";
        direction: "in" | "out";
        interface: string;
        quick: boolean;
        protocol: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre";
        source: string;
        sourcePort: string;
        destination: string;
        destinationPort: string;
        log: boolean;
        sortOrder: number;
        id?: string | undefined;
        gateway?: string | undefined;
    }, {
        id?: string | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
        action?: "pass" | "block" | "reject" | undefined;
        direction?: "in" | "out" | undefined;
        interface?: string | undefined;
        quick?: boolean | undefined;
        protocol?: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre" | undefined;
        source?: string | undefined;
        sourcePort?: string | undefined;
        destination?: string | undefined;
        destinationPort?: string | undefined;
        gateway?: string | undefined;
        log?: boolean | undefined;
        sortOrder?: number | undefined;
    }>, "many">>;
    nat: z.ZodDefault<z.ZodArray<z.ZodObject<{
        id: z.ZodOptional<z.ZodString>;
        type: z.ZodDefault<z.ZodEnum<["dnat", "snat", "masquerade", "nptv6"]>>;
        interface: z.ZodDefault<z.ZodString>;
        protocol: z.ZodDefault<z.ZodEnum<["any", "tcp", "udp", "tcp_udp", "icmp", "ipv6-icmp", "esp", "ah", "gre"]>>;
        source: z.ZodDefault<z.ZodString>;
        sourcePort: z.ZodDefault<z.ZodString>;
        destination: z.ZodDefault<z.ZodString>;
        destinationPort: z.ZodDefault<z.ZodString>;
        targetIp: z.ZodOptional<z.ZodString>;
        targetPort: z.ZodOptional<z.ZodString>;
        log: z.ZodDefault<z.ZodBoolean>;
        enabled: z.ZodDefault<z.ZodBoolean>;
        description: z.ZodDefault<z.ZodString>;
        sortOrder: z.ZodDefault<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        type: "dnat" | "snat" | "masquerade" | "nptv6";
        enabled: boolean;
        description: string;
        interface: string;
        protocol: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre";
        source: string;
        sourcePort: string;
        destination: string;
        destinationPort: string;
        log: boolean;
        sortOrder: number;
        id?: string | undefined;
        targetIp?: string | undefined;
        targetPort?: string | undefined;
    }, {
        id?: string | undefined;
        type?: "dnat" | "snat" | "masquerade" | "nptv6" | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
        interface?: string | undefined;
        protocol?: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre" | undefined;
        source?: string | undefined;
        sourcePort?: string | undefined;
        destination?: string | undefined;
        destinationPort?: string | undefined;
        log?: boolean | undefined;
        sortOrder?: number | undefined;
        targetIp?: string | undefined;
        targetPort?: string | undefined;
    }>, "many">>;
    gateways: z.ZodDefault<z.ZodArray<z.ZodObject<{
        id: z.ZodOptional<z.ZodString>;
        name: z.ZodString;
        interface: z.ZodString;
        gatewayIp: z.ZodEffects<z.ZodString, string, string>;
        monitorIp: z.ZodOptional<z.ZodString>;
        weight: z.ZodDefault<z.ZodNumber>;
        isDefault: z.ZodDefault<z.ZodBoolean>;
        enabled: z.ZodDefault<z.ZodBoolean>;
        description: z.ZodDefault<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        name: string;
        enabled: boolean;
        description: string;
        interface: string;
        gatewayIp: string;
        weight: number;
        isDefault: boolean;
        id?: string | undefined;
        monitorIp?: string | undefined;
    }, {
        name: string;
        interface: string;
        gatewayIp: string;
        id?: string | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
        monitorIp?: string | undefined;
        weight?: number | undefined;
        isDefault?: boolean | undefined;
    }>, "many">>;
    wireguard: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodDefault<z.ZodBoolean>;
        listenPort: z.ZodDefault<z.ZodNumber>;
        privateKey: z.ZodOptional<z.ZodString>;
        address: z.ZodDefault<z.ZodString>;
        peers: z.ZodDefault<z.ZodArray<z.ZodObject<{
            id: z.ZodOptional<z.ZodString>;
            name: z.ZodString;
            publicKey: z.ZodString;
            presharedKey: z.ZodOptional<z.ZodString>;
            allowedIps: z.ZodArray<z.ZodString, "many">;
            endpoint: z.ZodOptional<z.ZodString>;
            persistentKeepalive: z.ZodDefault<z.ZodNumber>;
            enabled: z.ZodDefault<z.ZodBoolean>;
        }, "strip", z.ZodTypeAny, {
            name: string;
            enabled: boolean;
            publicKey: string;
            allowedIps: string[];
            persistentKeepalive: number;
            id?: string | undefined;
            presharedKey?: string | undefined;
            endpoint?: string | undefined;
        }, {
            name: string;
            publicKey: string;
            allowedIps: string[];
            id?: string | undefined;
            enabled?: boolean | undefined;
            presharedKey?: string | undefined;
            endpoint?: string | undefined;
            persistentKeepalive?: number | undefined;
        }>, "many">>;
    }, "strip", z.ZodTypeAny, {
        enabled: boolean;
        listenPort: number;
        address: string;
        peers: {
            name: string;
            enabled: boolean;
            publicKey: string;
            allowedIps: string[];
            persistentKeepalive: number;
            id?: string | undefined;
            presharedKey?: string | undefined;
            endpoint?: string | undefined;
        }[];
        privateKey?: string | undefined;
    }, {
        enabled?: boolean | undefined;
        listenPort?: number | undefined;
        privateKey?: string | undefined;
        address?: string | undefined;
        peers?: {
            name: string;
            publicKey: string;
            allowedIps: string[];
            id?: string | undefined;
            enabled?: boolean | undefined;
            presharedKey?: string | undefined;
            endpoint?: string | undefined;
            persistentKeepalive?: number | undefined;
        }[] | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    version: number;
    system: {
        hostname: string;
        domain: string;
        dnsServers: string[];
        timezone: string;
        flowtableOffload: boolean;
        antiLockout: {
            enabled: boolean;
            interface: string;
            ports: number[];
        };
    };
    interfaces: {
        name: string;
        device: string;
        type: "static" | "dhcp" | "pppoe" | "track6" | "vlan" | "bridge" | "wireguard" | "loopback";
        enabled: boolean;
        description: string;
        mtu: number;
        id?: string | undefined;
        ipv4Address?: string | undefined;
        ipv4Gateway?: string | undefined;
        ipv6Address?: string | undefined;
        ipv6Gateway?: string | undefined;
        macAddress?: string | undefined;
    }[];
    aliases: {
        entries: string[];
        name: string;
        type: "host" | "network" | "port" | "mac" | "urltable";
        enabled: boolean;
        description: string;
        id?: string | undefined;
    }[];
    rules: {
        enabled: boolean;
        description: string;
        action: "pass" | "block" | "reject";
        direction: "in" | "out";
        interface: string;
        quick: boolean;
        protocol: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre";
        source: string;
        sourcePort: string;
        destination: string;
        destinationPort: string;
        log: boolean;
        sortOrder: number;
        id?: string | undefined;
        gateway?: string | undefined;
    }[];
    nat: {
        type: "dnat" | "snat" | "masquerade" | "nptv6";
        enabled: boolean;
        description: string;
        interface: string;
        protocol: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre";
        source: string;
        sourcePort: string;
        destination: string;
        destinationPort: string;
        log: boolean;
        sortOrder: number;
        id?: string | undefined;
        targetIp?: string | undefined;
        targetPort?: string | undefined;
    }[];
    gateways: {
        name: string;
        enabled: boolean;
        description: string;
        interface: string;
        gatewayIp: string;
        weight: number;
        isDefault: boolean;
        id?: string | undefined;
        monitorIp?: string | undefined;
    }[];
    wireguard?: {
        enabled: boolean;
        listenPort: number;
        address: string;
        peers: {
            name: string;
            enabled: boolean;
            publicKey: string;
            allowedIps: string[];
            persistentKeepalive: number;
            id?: string | undefined;
            presharedKey?: string | undefined;
            endpoint?: string | undefined;
        }[];
        privateKey?: string | undefined;
    } | undefined;
}, {
    wireguard?: {
        enabled?: boolean | undefined;
        listenPort?: number | undefined;
        privateKey?: string | undefined;
        address?: string | undefined;
        peers?: {
            name: string;
            publicKey: string;
            allowedIps: string[];
            id?: string | undefined;
            enabled?: boolean | undefined;
            presharedKey?: string | undefined;
            endpoint?: string | undefined;
            persistentKeepalive?: number | undefined;
        }[] | undefined;
    } | undefined;
    version?: number | undefined;
    system?: {
        hostname?: string | undefined;
        domain?: string | undefined;
        dnsServers?: string[] | undefined;
        timezone?: string | undefined;
        flowtableOffload?: boolean | undefined;
        antiLockout?: {
            enabled?: boolean | undefined;
            interface?: string | undefined;
            ports?: number[] | undefined;
        } | undefined;
    } | undefined;
    interfaces?: {
        name: string;
        device: string;
        id?: string | undefined;
        type?: "static" | "dhcp" | "pppoe" | "track6" | "vlan" | "bridge" | "wireguard" | "loopback" | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
        ipv4Address?: string | undefined;
        ipv4Gateway?: string | undefined;
        ipv6Address?: string | undefined;
        ipv6Gateway?: string | undefined;
        mtu?: number | undefined;
        macAddress?: string | undefined;
    }[] | undefined;
    aliases?: {
        entries: string[];
        name: string;
        type: "host" | "network" | "port" | "mac" | "urltable";
        id?: string | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
    }[] | undefined;
    rules?: {
        id?: string | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
        action?: "pass" | "block" | "reject" | undefined;
        direction?: "in" | "out" | undefined;
        interface?: string | undefined;
        quick?: boolean | undefined;
        protocol?: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre" | undefined;
        source?: string | undefined;
        sourcePort?: string | undefined;
        destination?: string | undefined;
        destinationPort?: string | undefined;
        gateway?: string | undefined;
        log?: boolean | undefined;
        sortOrder?: number | undefined;
    }[] | undefined;
    nat?: {
        id?: string | undefined;
        type?: "dnat" | "snat" | "masquerade" | "nptv6" | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
        interface?: string | undefined;
        protocol?: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp" | "esp" | "ah" | "gre" | undefined;
        source?: string | undefined;
        sourcePort?: string | undefined;
        destination?: string | undefined;
        destinationPort?: string | undefined;
        log?: boolean | undefined;
        sortOrder?: number | undefined;
        targetIp?: string | undefined;
        targetPort?: string | undefined;
    }[] | undefined;
    gateways?: {
        name: string;
        interface: string;
        gatewayIp: string;
        id?: string | undefined;
        enabled?: boolean | undefined;
        description?: string | undefined;
        monitorIp?: string | undefined;
        weight?: number | undefined;
        isDefault?: boolean | undefined;
    }[] | undefined;
}>;
export type DesiredState = z.infer<typeof DesiredStateSchema>;
//# sourceMappingURL=index.d.ts.map