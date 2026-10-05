import { sanitizeIdentifier } from '../../util/index.js';
export function compileNftables(state) {
    const lines = [];
    const warnings = [];
    lines.push('#!/usr/sbin/nft -f');
    lines.push('# Axonwall Auto-Generated nftables configuration');
    lines.push(`# Version: ${state.version} | Generated: ${new Date().toISOString()}`);
    lines.push('');
    // 1. Table definition (isolated namespace, never flushes other tables)
    lines.push('table inet axonwall {');
    // 2. Named sets for Aliases
    if (state.aliases.length > 0) {
        lines.push('  # Aliases & Dynamic Sets');
        for (const alias of state.aliases) {
            if (!alias.enabled || alias.entries.length === 0)
                continue;
            const setName = `set_${sanitizeIdentifier(alias.name)}`;
            let setType = 'ipv4_addr';
            if (alias.type === 'port') {
                setType = 'inet_service';
            }
            else if (alias.type === 'mac') {
                setType = 'ether_addr';
            }
            else if (alias.type === 'network') {
                setType = 'ipv4_addr';
            }
            const elements = alias.entries.join(', ');
            lines.push(`  set ${setName} {`);
            lines.push(`    type ${setType};`);
            if (alias.type === 'network' || alias.type === 'host') {
                lines.push('    flags interval;');
            }
            lines.push(`    elements = { ${elements} };`);
            lines.push('  }');
        }
        lines.push('');
    }
    // 3. Flowtable for hardware/software fastpath offloading
    const enabledDevices = state.interfaces
        .filter((i) => i.enabled && i.device)
        .map((i) => `"${i.device}"`);
    if (state.system.flowtableOffload && enabledDevices.length > 0) {
        lines.push('  # Flowtable Fastpath');
        lines.push('  flowtable ft_fastpath {');
        lines.push('    hook ingress priority filter;');
        lines.push(`    devices = { ${enabledDevices.join(', ')} };`);
        lines.push('  }');
        lines.push('');
    }
    // Helper to map interfaces to system devices
    const ifDeviceMap = new Map();
    for (const iface of state.interfaces) {
        ifDeviceMap.set(iface.name, iface.device);
    }
    // 4. Chains definition
    // Prerouting (DNAT)
    lines.push('  chain prerouting {');
    lines.push('    type nat hook prerouting priority dstnat - 10; policy accept;');
    for (const nat of state.nat) {
        if (!nat.enabled || nat.type !== 'dnat')
            continue;
        const ifaceDev = ifDeviceMap.get(nat.interface) || nat.interface;
        const proto = nat.protocol === 'any' ? 'ip protocol { tcp, udp }' : `${nat.protocol}`;
        const portMatch = nat.destinationPort ? `dport ${nat.destinationPort}` : '';
        const dnatTarget = nat.targetPort ? `${nat.targetIp}:${nat.targetPort}` : `${nat.targetIp}`;
        lines.push(`    iifname "${ifaceDev}" ${proto} ${portMatch} dnat to ${dnatTarget}`);
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
    // Anti-Lockout Rule
    if (state.system.antiLockout?.enabled) {
        const lanIface = state.system.antiLockout.interface;
        const lanDev = ifDeviceMap.get(lanIface) || lanIface;
        const ports = state.system.antiLockout.ports.join(', ');
        lines.push(`    # Anti-Lockout: Allow management access from ${lanIface}`);
        lines.push(`    iifname "${lanDev}" tcp dport { ${ports} } accept comment "anti-lockout"`);
    }
    // WireGuard listener
    if (state.wireguard?.enabled) {
        lines.push(`    udp dport ${state.wireguard.listenPort} accept comment "wireguard-service"`);
    }
    // Interface dispatcher for input
    for (const iface of state.interfaces) {
        if (!iface.enabled)
            continue;
        const dev = iface.device;
        lines.push(`    iifname "${dev}" jump input_${iface.name}`);
    }
    lines.push('  }');
    lines.push('');
    // Forward chain (routed traffic between interfaces)
    lines.push('  chain forward {');
    lines.push('    type filter hook forward priority filter; policy drop;');
    if (state.system.flowtableOffload && enabledDevices.length > 0) {
        lines.push('    ip protocol { tcp, udp } flow add @ft_fastpath');
    }
    lines.push('    ct state established,related accept');
    lines.push('    ct state invalid drop');
    // Interface dispatcher for forward
    for (const iface of state.interfaces) {
        if (!iface.enabled)
            continue;
        const dev = iface.device;
        lines.push(`    iifname "${dev}" jump forward_${iface.name}`);
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
        if (!nat.enabled)
            continue;
        const ifaceDev = ifDeviceMap.get(nat.interface) || nat.interface;
        if (nat.type === 'masquerade') {
            lines.push(`    oifname "${ifaceDev}" masquerade comment "outbound-nat"`);
        }
        else if (nat.type === 'snat' && nat.targetIp) {
            lines.push(`    oifname "${ifaceDev}" snat to ${nat.targetIp} comment "outbound-snat"`);
        }
    }
    // Default WAN masquerade if no outbound rules configured
    const wanIface = state.interfaces.find((i) => i.name === 'wan');
    if (wanIface && !state.nat.some((n) => n.type === 'masquerade' || n.type === 'snat')) {
        lines.push(`    oifname "${wanIface.device}" masquerade comment "default-wan-masquerade"`);
    }
    lines.push('  }');
    lines.push('');
    // 5. Per-Interface Input and Forward Chains
    for (const iface of state.interfaces) {
        if (!iface.enabled)
            continue;
        // Filter rules belonging to this interface or 'any'
        const ifaceRules = state.rules
            .filter((r) => r.enabled && (r.interface === iface.name || r.interface === 'any'))
            .sort((a, b) => a.sortOrder - b.sortOrder);
        // Input chain for interface
        lines.push(`  chain input_${iface.name} {`);
        for (const rule of ifaceRules) {
            if (rule.direction === 'in') {
                const stmt = formatRuleStatement(rule, state.aliases);
                if (stmt)
                    lines.push(`    ${stmt}`);
            }
        }
        lines.push('  }');
        lines.push('');
        // Forward chain for interface
        lines.push(`  chain forward_${iface.name} {`);
        for (const rule of ifaceRules) {
            const stmt = formatRuleStatement(rule, state.aliases);
            if (stmt)
                lines.push(`    ${stmt}`);
        }
        lines.push('  }');
        lines.push('');
    }
    lines.push('}');
    lines.push('');
    return {
        nftScript: lines.join('\n'),
        warnings,
    };
}
function formatRuleStatement(rule, aliases) {
    const parts = [];
    // Protocol
    if (rule.protocol === 'tcp_udp') {
        parts.push('meta l4proto { tcp, udp }');
    }
    else if (rule.protocol !== 'any') {
        parts.push(`ip protocol ${rule.protocol}`);
    }
    // Source Address
    if (rule.source && rule.source !== 'any') {
        if (rule.source.startsWith('$')) {
            const aliasName = sanitizeIdentifier(rule.source.slice(1));
            parts.push(`ip saddr @set_${aliasName}`);
        }
        else {
            parts.push(`ip saddr ${rule.source}`);
        }
    }
    // Destination Address
    if (rule.destination && rule.destination !== 'any') {
        if (rule.destination.startsWith('$')) {
            const aliasName = sanitizeIdentifier(rule.destination.slice(1));
            parts.push(`ip daddr @set_${aliasName}`);
        }
        else {
            parts.push(`ip daddr ${rule.destination}`);
        }
    }
    // Ports
    const isTcpOrUdp = rule.protocol === 'tcp' || rule.protocol === 'udp' || rule.protocol === 'tcp_udp';
    if (isTcpOrUdp) {
        if (rule.sourcePort && rule.sourcePort !== 'any') {
            if (rule.sourcePort.startsWith('$')) {
                const aliasName = sanitizeIdentifier(rule.sourcePort.slice(1));
                parts.push(`sport @set_${aliasName}`);
            }
            else if (rule.sourcePort.includes('-')) {
                parts.push(`sport ${rule.sourcePort}`);
            }
            else {
                parts.push(`sport ${rule.sourcePort}`);
            }
        }
        if (rule.destinationPort && rule.destinationPort !== 'any') {
            if (rule.destinationPort.startsWith('$')) {
                const aliasName = sanitizeIdentifier(rule.destinationPort.slice(1));
                parts.push(`dport @set_${aliasName}`);
            }
            else if (rule.destinationPort.includes('-')) {
                parts.push(`dport ${rule.destinationPort}`);
            }
            else {
                parts.push(`dport ${rule.destinationPort}`);
            }
        }
    }
    // Logging
    if (rule.log) {
        parts.push(`log prefix "axonwall-rule:${rule.id?.slice(0, 8) || 'log'}: " group 0`);
    }
    // Action
    const actionMap = {
        pass: 'accept',
        block: 'drop',
        reject: 'reject',
    };
    parts.push(actionMap[rule.action] || 'accept');
    // Comment
    if (rule.description) {
        const safeDesc = rule.description.replace(/"/g, "'");
        parts.push(`comment "${safeDesc}"`);
    }
    return parts.join(' ');
}
