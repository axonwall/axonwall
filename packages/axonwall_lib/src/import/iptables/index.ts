import type {
  DesiredState,
  Interface,
  FirewallRule,
  NatRule,
} from '../../schemas/index.js';
import type { ImportReport, ImportReviewItem } from '../types.js';

function parseIptablesTokens(line: string): string[] {
  const tokens: string[] = [];
  const regex = /[^\s"']+|"([^"]*)"|'([^']*)'/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(line)) !== null) {
    if (match[1] !== undefined) {
      tokens.push(match[1]);
    } else if (match[2] !== undefined) {
      tokens.push(match[2]);
    } else {
      tokens.push(match[0]);
    }
  }
  return tokens;
}

const BUILTIN_FILTER_CHAINS = new Set(['INPUT', 'FORWARD', 'OUTPUT']);

export function importIptablesConfig(rulesContent: string): ImportReport {
  const warnings: string[] = [];
  const reviewItems: ImportReviewItem[] = [];
  const lines = rulesContent.split('\n');

  let currentTable = 'filter';
  const rules: FirewallRule[] = [];
  const nat: NatRule[] = [];
  const detectedIfaces = new Set<string>();

  let sortOrder = 10;
  let natSort = 10;

  for (let rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    if (line.startsWith('*')) {
      currentTable = line.slice(1).toLowerCase();
      continue;
    }
    if (line === 'COMMIT') continue;

    // Check for iptables rule lines starting with -A or -I
    if (line.startsWith('-A') || line.startsWith('-I')) {
      const parts = parseIptablesTokens(line);
      const chain = parts[1] || '';

      let inIface = '';
      let outIface = '';
      let proto = 'any';
      let src = 'any';
      let dst = 'any';
      let negatedSrc = false;
      let negatedDst = false;
      let hasUnsupportedNegation = false;
      let ctStateRaw = '';
      let ctStateNegated = false;
      let sport = '';
      let dport = '';
      let target = '';
      let toDest = '';
      let toSource = '';
      let comment = '';

      const stripBang = (val: string): { value: string; negated: boolean } => {
        if (val.startsWith('!')) {
          return { value: val.slice(1), negated: true };
        }
        return { value: val, negated: false };
      };

      for (let i = 2; i < parts.length; i++) {
        const p = parts[i];
        if (p === '!' && i + 1 < parts.length) {
          const next = parts[i + 1]!;
          if ((next === '-s' || next === '--source') && i + 2 < parts.length) {
            negatedSrc = true;
            src = parts[i + 2]!.replace(/^!/, '') || 'any';
            i += 2;
            continue;
          }
          if ((next === '-d' || next === '--destination') && i + 2 < parts.length) {
            negatedDst = true;
            dst = parts[i + 2]!.replace(/^!/, '') || 'any';
            i += 2;
            continue;
          }
          if ((next === '--ctstate' || next === '--state') && i + 2 < parts.length) {
            ctStateNegated = true;
            ctStateRaw = parts[i + 2]!;
            i += 2;
            continue;
          }
          if (
            [
              '-i',
              '--in-interface',
              '-o',
              '--out-interface',
              '-p',
              '--protocol',
              '--sport',
              '--source-port',
              '--sports',
              '--dport',
              '--destination-port',
              '--dports',
            ].includes(next) &&
            i + 2 < parts.length
          ) {
            hasUnsupportedNegation = true;
            // Continue letting the next token parse without crashing; rule will fail closed.
            continue;
          }
        }

        if (p === '-i' && i + 1 < parts.length) {
          const parsedVal = stripBang(parts[++i]!);
          if (parsedVal.negated) hasUnsupportedNegation = true;
          inIface = parsedVal.value.replace(/\+$/, '');
          if (inIface) detectedIfaces.add(inIface);
        } else if (p === '-o' && i + 1 < parts.length) {
          const parsedVal = stripBang(parts[++i]!);
          if (parsedVal.negated) hasUnsupportedNegation = true;
          outIface = parsedVal.value.replace(/\+$/, '');
          if (outIface) detectedIfaces.add(outIface);
        } else if (p === '-p' && i + 1 < parts.length) {
          if (parts[i + 1] === '!' && i + 2 < parts.length) {
            hasUnsupportedNegation = true;
            const rawP = parts[i + 2]!.replace(/^!/, '').toLowerCase();
            proto = rawP === 'all' ? 'any' : rawP;
            i += 2;
          } else {
            const parsedVal = stripBang(parts[++i]!);
            if (parsedVal.negated) hasUnsupportedNegation = true;
            const rawP = parsedVal.value.toLowerCase();
            proto = rawP === 'all' ? 'any' : rawP;
          }
        } else if ((p === '-s' || p === '--source') && i + 1 < parts.length) {
          if (parts[i + 1] === '!' && i + 2 < parts.length) {
            negatedSrc = true;
            src = parts[i + 2]!.replace(/^!/, '') || 'any';
            i += 2;
          } else {
            const rawVal = parts[++i]!;
            if (rawVal.startsWith('!')) {
              negatedSrc = true;
              src = rawVal.slice(1) || 'any';
            } else {
              src = rawVal;
            }
          }
        } else if ((p === '-d' || p === '--destination') && i + 1 < parts.length) {
          if (parts[i + 1] === '!' && i + 2 < parts.length) {
            negatedDst = true;
            dst = parts[i + 2]!.replace(/^!/, '') || 'any';
            i += 2;
          } else {
            const rawVal = parts[++i]!;
            if (rawVal.startsWith('!')) {
              negatedDst = true;
              dst = rawVal.slice(1) || 'any';
            } else {
              dst = rawVal;
            }
          }
        } else if ((p === '--sport' || p === '--source-port' || p === '--sports') && i + 1 < parts.length) {
          if (parts[i + 1] === '!' && i + 2 < parts.length) {
            hasUnsupportedNegation = true;
            sport = parts[i + 2]!.replace(/^!/, '').replace(/:/g, '-');
            i += 2;
          } else {
            const parsedVal = stripBang(parts[++i]!);
            if (parsedVal.negated) hasUnsupportedNegation = true;
            sport = parsedVal.value.replace(/:/g, '-');
          }
        } else if ((p === '--dport' || p === '--destination-port' || p === '--dports') && i + 1 < parts.length) {
          if (parts[i + 1] === '!' && i + 2 < parts.length) {
            hasUnsupportedNegation = true;
            dport = parts[i + 2]!.replace(/^!/, '').replace(/:/g, '-');
            i += 2;
          } else {
            const parsedVal = stripBang(parts[++i]!);
            if (parsedVal.negated) hasUnsupportedNegation = true;
            dport = parsedVal.value.replace(/:/g, '-');
          }
        } else if ((p === '--ctstate' || p === '--state') && i + 1 < parts.length) {
          if (parts[i + 1] === '!' && i + 2 < parts.length) {
            ctStateNegated = true;
            ctStateRaw = parts[i + 2]!;
            i += 2;
          } else {
            const parsedVal = stripBang(parts[++i]!);
            if (parsedVal.negated) ctStateNegated = true;
            ctStateRaw = parsedVal.value;
          }
        } else if (p === '-j' && i + 1 < parts.length) {
          target = parts[++i]!.toUpperCase();
        } else if (p === '--to-destination' && i + 1 < parts.length) {
          toDest = parts[++i]!;
        } else if (p === '--to-source' && i + 1 < parts.length) {
          toSource = parts[++i]!;
        } else if (p === '--comment' && i + 1 < parts.length) {
          comment = parts[++i]!.replace(/^["']|["']$/g, '');
        }
      }

      const parseNatEndpoint = (raw: string): { ip: string; port: string } => {
        const bracketMatch = raw.match(/^\[([^\]]+)\](?::(.+))?$/);
        if (bracketMatch) {
          return { ip: bracketMatch[1]!, port: (bracketMatch[2] || '').replace(/:/g, '-') };
        }
        const colonCount = (raw.match(/:/g) || []).length;
        if (colonCount === 1) {
          const [ip, port] = raw.split(':');
          return { ip: ip || '', port: (port || '').replace(/:/g, '-') };
        }
        return { ip: raw, port: '' };
      };
      const validProtos = new Set(['any', 'tcp', 'udp', 'tcp_udp', 'icmp', 'ipv6-icmp', 'esp', 'ah', 'gre']);
      const normalizedProto = validProtos.has(proto) ? (proto as any) : 'any';

      // Check NAT table
      if (currentTable === 'nat') {
        const hasNatNegation = (negatedSrc && src !== 'any') || (negatedDst && dst !== 'any') || hasUnsupportedNegation;
        if (target === 'MASQUERADE') {
          const iface = outIface || 'wan';
          if (hasNatNegation) {
            warnings.push(`iptables NAT MASQUERADE rule (${line}) uses negated matching which cannot be represented on NatRule; imported with enabled: false.`);
          }
          nat.push({
            type: 'masquerade',
            interface: iface.includes('eth0') ? 'wan' : iface,
            protocol: 'any',
            source: src,
            sourcePort: sport,
            destination: dst,
            destinationPort: dport,
            log: false,
            enabled: !hasNatNegation,
            description: comment || `Masquerade on ${iface}`,
            sortOrder: natSort,
          });
          natSort += 10;
        } else if (target === 'DNAT' && toDest) {
          const iface = inIface || 'wan';
          const { ip: destIp, port: destP } = parseNatEndpoint(toDest);
          if (hasNatNegation) {
            warnings.push(`iptables NAT DNAT rule (${line}) uses negated matching which cannot be represented on NatRule; imported with enabled: false.`);
          }
          nat.push({
            type: 'dnat',
            interface: iface.includes('eth0') ? 'wan' : iface,
            protocol: proto === 'any' ? 'tcp' : normalizedProto,
            source: src,
            sourcePort: sport,
            destination: 'wan_ip',
            destinationPort: dport || destP || '',
            targetIp: destIp,
            targetPort: destP || dport || '',
            log: false,
            enabled: !hasNatNegation,
            description: comment || `Port forward to ${toDest}`,
            sortOrder: natSort,
          });
          natSort += 10;
        } else if (target === 'SNAT' && toSource) {
          const iface = outIface || 'wan';
          const { ip: srcIp, port: srcP } = parseNatEndpoint(toSource);
          if (hasNatNegation) {
            warnings.push(`iptables NAT SNAT rule (${line}) uses negated matching which cannot be represented on NatRule; imported with enabled: false.`);
          }
          nat.push({
            type: 'snat',
            interface: iface.includes('eth0') ? 'wan' : iface,
            protocol: normalizedProto,
            source: src,
            sourcePort: sport,
            destination: dst,
            destinationPort: dport,
            targetIp: srcIp,
            targetPort: srcP || undefined,
            log: false,
            enabled: !hasNatNegation,
            description: comment || `SNAT to ${toSource}`,
            sortOrder: natSort,
          });
          natSort += 10;
        }
      }

      // Check FILTER table
      else if (currentTable === 'filter') {
        const isBuiltinChain = BUILTIN_FILTER_CHAINS.has(chain);

        // Skip built-in loopback ACCEPT rules
        if (
          isBuiltinChain &&
          target === 'ACCEPT' &&
          inIface === 'lo' &&
          !negatedSrc &&
          !negatedDst &&
          !hasUnsupportedNegation
        ) {
          continue;
        }

        // Skip generic built-in ACCEPT rules for ESTABLISHED,RELATED only (never skip DROP/REJECT)
        const ctStates = ctStateRaw
          .toLowerCase()
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        const hasEstRel =
          (ctStates.includes('established') && ctStates.includes('related')) ||
          line.includes('ESTABLISHED,RELATED') ||
          line.includes('RELATED,ESTABLISHED');
        const hasNewOrInvalid = ctStates.includes('new') || ctStates.includes('invalid');
        if (
          isBuiltinChain &&
          target === 'ACCEPT' &&
          !ctStateNegated &&
          !hasUnsupportedNegation &&
          hasEstRel &&
          !hasNewOrInvalid &&
          src === 'any' &&
          dst === 'any' &&
          !sport &&
          !dport
        ) {
          continue;
        }

        let action: 'pass' | 'block' | 'reject' = 'pass';
        if (target === 'DROP') action = 'block';
        else if (target === 'REJECT') action = 'reject';
        else if (target === 'ACCEPT') action = 'pass';
        else {
          if (target && !['LOG', 'ULOG', 'NFLOG', 'RETURN'].includes(target)) {
            warnings.push(
              `Skipped jump rule in chain "${chain}" to custom target "${target}" (${line}): review rules in "${target}" and recreate jump conditions manually.`,
            );
          }
          continue; // custom chain or logging jump
        }

        let iface = inIface || outIface || 'any';
        if (iface.includes('eth0')) iface = 'wan';
        else if (iface.includes('eth1')) iface = 'lan';

        let ruleProto: 'any' | 'tcp' | 'udp' | 'tcp_udp' | 'icmp' = 'any';
        if (proto === 'tcp') ruleProto = 'tcp';
        else if (proto === 'udp') ruleProto = 'udp';
        else if (proto.includes('icmp')) ruleProto = 'icmp';

        const hasNegation = (negatedSrc && src !== 'any') || (negatedDst && dst !== 'any');
        const isCustomChain = !isBuiltinChain;
        const needsReview = hasNegation || hasUnsupportedNegation || isCustomChain;
        const ruleIndex = rules.length;
        const baseDesc = comment || `Imported ${chain} rule (${target})`;
        const reviewTags: string[] = [];
        if (isCustomChain) reviewTags.push(`Custom chain ${chain}`);
        if (hasNegation) reviewTags.push('Negated match');
        if (hasUnsupportedNegation) reviewTags.push('Negated selector');
        const finalDesc = reviewTags.length > 0 ? `[REVIEW: ${reviewTags.join('; ')}] ${baseDesc}` : baseDesc;

        if (isCustomChain) {
          const matchSummary = `CHAIN ${chain}: ${action.toUpperCase()} ${ruleProto} from ${negatedSrc ? `!${src}` : src} to ${negatedDst ? `!${dst}` : dst}`;
          const explanation = `iptables rule "${baseDesc}" belongs to custom chain "${chain}" (${matchSummary}). Custom-chain rules are not flattened into active global rules without preserving caller jump guards; imported with enabled: false.`;
          const suggestedResolution = `Inline the caller jump conditions for chain "${chain}" (interface, source/destination, state) onto this rule before enabling.`;
          warnings.push(explanation + ' ' + suggestedResolution);
          reviewItems.push({
            ruleId: `rule-${ruleIndex + 1}`,
            ruleIndex,
            reason: 'manual_review',
            originalMatchSummary: matchSummary,
            explanation,
            suggestedResolution,
          });
        }

        if (hasNegation) {
          const reason: ImportReviewItem['reason'] =
            negatedSrc && negatedDst
              ? 'negated_both'
              : negatedSrc
                ? 'negated_source'
                : 'negated_destination';
          const matchSummary = `${action.toUpperCase()} ${ruleProto} from ${negatedSrc ? `!${src}` : src} to ${negatedDst ? `!${dst}` : dst}`;
          const explanation = `iptables rule "${baseDesc}" uses an inverted (!) ${reason === 'negated_both' ? 'source and destination' : reason === 'negated_source' ? 'source' : 'destination'} match (${matchSummary}). Imported with enabled: false so it cannot silently activate with inverted semantics.`;
          const suggestedResolution = `Split into an explicit preceding rule matching ${negatedSrc ? src : dst} with the opposite action, followed by a broader rule matching 'any', then enable the reviewed rules.`;
          warnings.push(explanation + ' ' + suggestedResolution);
          reviewItems.push({
            ruleId: `rule-${ruleIndex + 1}`,
            ruleIndex,
            reason,
            originalMatchSummary: matchSummary,
            explanation,
            suggestedResolution,
          });
        }

        if (hasUnsupportedNegation) {
          const explanation = `iptables rule "${baseDesc}" (${line}) uses an inverted (!) interface, protocol, or port match that Axonwall cannot represent natively. Imported with enabled: false.`;
          const suggestedResolution = `Rewrite the inverted interface/protocol/port rule using explicit positive match rules before enabling.`;
          warnings.push(explanation + ' ' + suggestedResolution);
          reviewItems.push({
            ruleId: `rule-${ruleIndex + 1}`,
            ruleIndex,
            reason: 'manual_review',
            originalMatchSummary: line,
            explanation,
            suggestedResolution,
          });
        }

        rules.push({
          action,
          direction: chain === 'OUTPUT' ? 'out' : 'in',
          interface: iface,
          quick: true,
          protocol: ruleProto,
          source: src,
          ...(negatedSrc && src !== 'any' ? { invertSource: true } : {}),
          sourcePort: sport,
          destination: dst,
          ...(negatedDst && dst !== 'any' ? { invertDestination: true } : {}),
          destinationPort: dport,
          log: false,
          enabled: !needsReview,
          description: finalDesc,
          sortOrder,
        });
        sortOrder += 10;
      }
    }
  }

  // Construct Interfaces from detected interface names
  const interfaces: Interface[] = [];
  if (detectedIfaces.size === 0) {
    interfaces.push(
      { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, description: 'WAN', mtu: 1500 },
      { name: 'lan', device: 'eth1', type: 'static', ipv4Address: '192.168.1.1/24', enabled: true, description: 'LAN', mtu: 1500 }
    );
  } else {
    for (const dev of detectedIfaces) {
      const lower = dev.toLowerCase();
      let name = lower;
      let type: 'dhcp' | 'static' = 'static';
      let ip: string | undefined;

      if (lower.includes('eth0') || lower.includes('wan') || lower.includes('enp1s0')) {
        name = 'wan';
        type = 'dhcp';
      } else if (lower.includes('eth1') || lower.includes('lan') || lower.includes('enp2s0')) {
        name = 'lan';
        ip = '192.168.1.1/24';
      }

      interfaces.push({
        name,
        device: dev,
        type,
        ipv4Address: ip,
        enabled: true,
        description: dev.toUpperCase(),
        mtu: 1500,
      });
    }
  }

  const state: DesiredState = {
    version: 1,
    system: {
      hostname: 'axonwall',
      domain: 'local',
      dnsServers: ['1.1.1.1', '8.8.8.8'],
      timezone: 'UTC',
      flowtableOffload: true,
      antiLockout: {
        enabled: true,
        interface: 'lan',
        ports: [22, 80, 443, 3000, 2966],
      },
    },
    interfaces,
    vlans: [],
    aliases: [],
    rules,
    nat,
    gateways: [],
    gatewayGroups: [],
    bridges: [],
    bonds: [],
    virtualIps: [],
    vrfs: [],
    dhcp: {
      enabled: false,
      subnets: [],
    },
    dns: {
      enabled: true,
      listenPort: 53,
      dnssec: true,
      dotEnabled: true,
      dotUpstreams: ['1.1.1.1@853#cloudflare-dns.com'],
      hostOverrides: [],
    },
    routes: [],
  };

  return {
    success: true,
    vendor: 'iptables',
    version: 'iptables-save / nftables',
    sourceFormat: 'Linux iptables (iptables-save)',
    interfacesCount: interfaces.length,
    vlansCount: 0,
    aliasesCount: 0,
    rulesCount: rules.length,
    natRulesCount: nat.length,
    dhcpSubnetsCount: 0,
    dnsOverridesCount: 0,
    routesCount: 0,
    warnings,
    reviewItems,
    state,
  };
}
