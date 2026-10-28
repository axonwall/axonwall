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

      // Skip local loopback rules
      if (line.includes('-i lo') && line.includes('-j ACCEPT')) continue;
      // Skip generic state established/related rules as Axonwall handles connection tracking automatically
      if (line.includes('ESTABLISHED,RELATED') || line.includes('RELATED,ESTABLISHED')) continue;

      let inIface = '';
      let outIface = '';
      let proto = 'any';
      let src = 'any';
      let dst = 'any';
      let negatedSrc = false;
      let negatedDst = false;
      let sport = '';
      let dport = '';
      let target = '';
      let toDest = '';
      let toSource = '';
      let comment = '';

      for (let i = 2; i < parts.length; i++) {
        const p = parts[i];
        if (p === '!' && i + 2 < parts.length && (parts[i + 1] === '-s' || parts[i + 1] === '--source')) {
          negatedSrc = true;
          src = parts[i + 2].replace(/^!/, '');
          i += 2;
        } else if (p === '!' && i + 2 < parts.length && (parts[i + 1] === '-d' || parts[i + 1] === '--destination')) {
          negatedDst = true;
          dst = parts[i + 2].replace(/^!/, '');
          i += 2;
        } else if (p === '-i' && i + 1 < parts.length) {
          inIface = parts[++i];
          detectedIfaces.add(inIface);
        } else if (p === '-o' && i + 1 < parts.length) {
          outIface = parts[++i];
          detectedIfaces.add(outIface);
        } else if (p === '-p' && i + 1 < parts.length) {
          proto = parts[++i].toLowerCase();
        } else if ((p === '-s' || p === '--source') && i + 1 < parts.length) {
          if (parts[i + 1] === '!' && i + 2 < parts.length) {
            negatedSrc = true;
            src = parts[i + 2].replace(/^!/, '');
            i += 2;
          } else {
            const rawVal = parts[++i];
            if (rawVal.startsWith('!')) {
              negatedSrc = true;
              src = rawVal.slice(1);
            } else {
              src = rawVal;
            }
          }
        } else if ((p === '-d' || p === '--destination') && i + 1 < parts.length) {
          if (parts[i + 1] === '!' && i + 2 < parts.length) {
            negatedDst = true;
            dst = parts[i + 2].replace(/^!/, '');
            i += 2;
          } else {
            const rawVal = parts[++i];
            if (rawVal.startsWith('!')) {
              negatedDst = true;
              dst = rawVal.slice(1);
            } else {
              dst = rawVal;
            }
          }
        } else if ((p === '--sport' || p === '--source-port') && i + 1 < parts.length) {
          sport = parts[++i].replace(':', '-');
        } else if ((p === '--dport' || p === '--destination-port') && i + 1 < parts.length) {
          dport = parts[++i].replace(':', '-');
        } else if (p === '-j' && i + 1 < parts.length) {
          target = parts[++i].toUpperCase();
        } else if (p === '--to-destination' && i + 1 < parts.length) {
          toDest = parts[++i];
        } else if (p === '--to-source' && i + 1 < parts.length) {
          toSource = parts[++i];
        } else if (p === '--comment' && i + 1 < parts.length) {
          comment = parts[++i].replace(/^["']|["']$/g, '');
        }
      }

      // Check NAT table
      if (currentTable === 'nat') {
        if (target === 'MASQUERADE') {
          const iface = outIface || 'wan';
          nat.push({
            type: 'masquerade',
            interface: iface.includes('eth0') ? 'wan' : iface,
            protocol: 'any',
            source: src,
            sourcePort: sport,
            destination: dst,
            destinationPort: dport,
            log: false,
            enabled: true,
            description: comment || `Masquerade on ${iface}`,
            sortOrder: natSort,
          });
          natSort += 10;
        } else if (target === 'DNAT' && toDest) {
          const iface = inIface || 'wan';
          const [destIp, destP] = toDest.split(':');
          nat.push({
            type: 'dnat',
            interface: iface.includes('eth0') ? 'wan' : iface,
            protocol: (proto as any) || 'tcp',
            source: src,
            sourcePort: sport,
            destination: 'wan_ip',
            destinationPort: dport || destP || '',
            targetIp: destIp,
            targetPort: destP || dport || '',
            log: false,
            enabled: true,
            description: comment || `Port forward to ${toDest}`,
            sortOrder: natSort,
          });
          natSort += 10;
        } else if (target === 'SNAT' && toSource) {
          const iface = outIface || 'wan';
          nat.push({
            type: 'snat',
            interface: iface.includes('eth0') ? 'wan' : iface,
            protocol: (proto as any) || 'any',
            source: src,
            sourcePort: sport,
            destination: dst,
            destinationPort: dport,
            targetIp: toSource,
            log: false,
            enabled: true,
            description: comment || `SNAT to ${toSource}`,
            sortOrder: natSort,
          });
          natSort += 10;
        }
      }

      // Check FILTER table
      else if (currentTable === 'filter') {
        let action: 'pass' | 'block' | 'reject' = 'pass';
        if (target === 'DROP') action = 'block';
        else if (target === 'REJECT') action = 'reject';
        else if (target === 'ACCEPT') action = 'pass';
        else continue; // custom chain or logging jump

        let iface = inIface || outIface || 'any';
        if (iface.includes('eth0')) iface = 'wan';
        else if (iface.includes('eth1')) iface = 'lan';

        let ruleProto: 'any' | 'tcp' | 'udp' | 'tcp_udp' | 'icmp' = 'any';
        if (proto === 'tcp') ruleProto = 'tcp';
        else if (proto === 'udp') ruleProto = 'udp';
        else if (proto.includes('icmp')) ruleProto = 'icmp';

        const hasNegation = (negatedSrc && src !== 'any') || (negatedDst && dst !== 'any');
        const ruleIndex = rules.length;
        const baseDesc = comment || `Imported ${chain} rule (${target})`;
        const finalDesc = hasNegation ? `[REVIEW: Negated match] ${baseDesc}` : baseDesc;

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

        rules.push({
          action,
          direction: chain === 'OUTPUT' ? 'out' : 'in',
          interface: iface,
          quick: true,
          protocol: ruleProto,
          source: src,
          sourcePort: sport,
          destination: dst,
          destinationPort: dport,
          log: false,
          enabled: !hasNegation,
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
