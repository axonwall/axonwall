import {
  isValidFirewallEndpoint,
  isValidPortSpec,
  type DesiredState,
  type Interface,
  type Vlan,
  type Alias,
  type FirewallRule,
  type NatRule,
  type StaticRoute,
} from '../../schemas/index.js';
import { isValidCIDR, isValidIPv4, isValidIPv6 } from '../../util/index.js';
import type { ImportReport, ImportReviewItem } from '../types.js';

interface CiscoServiceObj {
  name: string;
  proto: string;
  srcPortOp?: string;
  srcPort?: string;
  dstPortOp?: string;
  dstPort?: string;
  unsupported?: boolean;
}

const CISCO_NAMED_PORTS: Record<string, string> = {
  www: '80',
  http: '80',
  https: '443',
  ssh: '22',
  telnet: '23',
  smtp: '25',
  domain: '53',
  dns: '53',
  bootps: '67',
  bootpc: '68',
  tftp: '69',
  ftp: '21',
  'ftp-data': '20',
  ntp: '123',
  snmp: '161',
  ldap: '389',
  ldaps: '636',
  syslog: '514',
  bgp: '179',
  pop3: '110',
  imap4: '143',
  kerberos: '88',
};

const CISCO_PORT_OPS = new Set(['eq', 'lt', 'gt', 'neq', 'range']);

function normalizeCiscoPort(rawToken?: string): string | null {
  if (!rawToken) return null;
  const lower = rawToken.toLowerCase().trim();
  const mapped = CISCO_NAMED_PORTS[lower] ?? lower;
  return isValidPortSpec(mapped) ? mapped : null;
}

function parseCiscoAclEndpoint(
  tokens: string[],
  idx: number,
  maskConverter: (mask: string) => number,
): { endpoint: string; nextIdx: number; valid: boolean } {
  const tok = tokens[idx];
  if (!tok) return { endpoint: 'any', nextIdx: idx, valid: false };
  if (tok === 'any' || tok === 'any4' || tok === 'any6') {
    return { endpoint: 'any', nextIdx: idx + 1, valid: true };
  }
  if (tok === 'host' && tokens[idx + 1]) {
    const candidate = tokens[idx + 1]!;
    return {
      endpoint: isValidFirewallEndpoint(candidate) ? candidate : 'any',
      nextIdx: idx + 2,
      valid: isValidFirewallEndpoint(candidate),
    };
  }
  if ((tok === 'object-group' || tok === 'object') && tokens[idx + 1]) {
    return {
      endpoint: `$${tokens[idx + 1]!.replace(/[^a-zA-Z0-9_]/g, '_')}`,
      nextIdx: idx + 2,
      valid: true,
    };
  }
  if (
    !CISCO_PORT_OPS.has(tok) &&
    tokens[idx + 1] &&
    !CISCO_PORT_OPS.has(tokens[idx + 1]!) &&
    isValidIPv4(tok) &&
    isValidIPv4(tokens[idx + 1]!)
  ) {
    return {
      endpoint: `${tok}/${maskConverter(tokens[idx + 1]!)}`,
      nextIdx: idx + 2,
      valid: true,
    };
  }
  return { endpoint: 'any', nextIdx: idx, valid: false };
}

function parseCiscoPortClause(
  tokens: string[],
  idx: number,
): { present: boolean; op?: string; port: string; nextIdx: number; unsupported: boolean; summary?: string } {
  const op = tokens[idx]?.toLowerCase();
  if (!op || !CISCO_PORT_OPS.has(op)) {
    return { present: false, port: '', nextIdx: idx, unsupported: false };
  }
  if (op === 'range') {
    const startTok = tokens[idx + 1];
    const endTok = tokens[idx + 2];
    const startNorm = normalizeCiscoPort(startTok);
    const endNorm = normalizeCiscoPort(endTok);
    const rangePort = startNorm && endNorm && isValidPortSpec(`${startNorm}-${endNorm}`) ? `${startNorm}-${endNorm}` : '';
    return {
      present: true,
      op,
      port: rangePort,
      nextIdx: Math.min(tokens.length, idx + 3),
      unsupported: true,
      summary: `range ${startTok || ''} ${endTok || ''}`.trim(),
    };
  }
  const valTok = tokens[idx + 1];
  const norm = normalizeCiscoPort(valTok);
  return {
    present: true,
    op,
    port: op === 'eq' && norm ? norm : '',
    nextIdx: Math.min(tokens.length, idx + 2),
    unsupported: op !== 'eq' || norm === null,
    summary: `${op} ${valTok || ''}`.trim(),
  };
}

function maskToPrefix(mask: string): number {
  const parts = mask.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4) return 32;
  const num = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  let count = 0;
  for (let i = 31; i >= 0; i--) {
    if ((num & (1 << i)) !== 0) count++;
    else break;
  }
  return count;
}

export function importCiscoAsaConfig(configText: string): ImportReport {
  const warnings: string[] = [];
  const reviewItems: ImportReviewItem[] = [];
  const lines = configText.split(/\r?\n/);

  const rawInterfaces: Record<
    string,
    { device: string; nameif?: string; ip?: string; mask?: string; vlan?: number; descr?: string }
  > = {};
  const aliases: Alias[] = [];
  const serviceObjects = new Map<string, CiscoServiceObj>();
  const rules: FirewallRule[] = [];
  const nat: NatRule[] = [];
  const routes: StaticRoute[] = [];

  let currentIface: string | null = null;
  let currentObjNetwork: { name: string; ip?: string; descr?: string } | null = null;
  let currentObjGroup: { name: string; entries: string[]; descr?: string } | null = null;
  let currentObjService: CiscoServiceObj | null = null;

  const flushOpenObjects = () => {
    if (currentObjNetwork && currentObjNetwork.ip) {
      aliases.push({
        name: currentObjNetwork.name.replace(/[^a-zA-Z0-9_]/g, '_'),
        type: currentObjNetwork.ip.includes('/') ? 'network' : 'host',
        entries: [currentObjNetwork.ip],
        description: currentObjNetwork.descr || '',
        enabled: true,
      });
    }
    currentObjNetwork = null;

    if (currentObjGroup && currentObjGroup.entries.length > 0) {
      aliases.push({
        name: currentObjGroup.name.replace(/[^a-zA-Z0-9_]/g, '_'),
        type: 'network',
        entries: currentObjGroup.entries,
        description: currentObjGroup.descr || '',
        enabled: true,
      });
    }
    currentObjGroup = null;

    if (currentObjService) {
      serviceObjects.set(currentObjService.name, currentObjService);
    }
    currentObjService = null;
  };

  const resolveEndpoint = (token?: string, defaultVal = 'any'): { value: string; resolvedIp?: string; known: boolean } => {
    if (!token) return { value: defaultVal, known: true };
    const lower = token.toLowerCase();
    if (lower === 'any' || lower === 'any4' || lower === 'any6') {
      return { value: defaultVal, known: true };
    }
    if (lower === 'interface') {
      return { value: 'wan_ip', known: true };
    }
    if (isValidIPv4(token) || isValidIPv6(token) || isValidCIDR(token)) {
      return { value: token, resolvedIp: token, known: true };
    }
    const safeName = token.replace(/[^a-zA-Z0-9_]/g, '_');
    if (currentObjNetwork?.name === token && currentObjNetwork.ip) {
      return { value: `$${safeName}`, resolvedIp: currentObjNetwork.ip, known: true };
    }
    const foundAlias = aliases.find((a) => a.name === safeName || a.name === token);
    if (foundAlias) {
      return {
        value: foundAlias.entries.length === 1 ? foundAlias.entries[0]! : `$${foundAlias.name}`,
        resolvedIp: foundAlias.entries.length === 1 ? foundAlias.entries[0] : undefined,
        known: true,
      };
    }
    return { value: defaultVal, known: false };
  };

  for (let rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('!') || line.startsWith('#')) {
      continue;
    }

    const isIndented = /^\s+/.test(rawLine);
    const tokens = line.split(/\s+/);

    if (!isIndented && !['interface', 'object', 'object-group'].includes(tokens[0] || '')) {
      flushOpenObjects();
    }

    // 1. Interfaces
    if (tokens[0] === 'interface' && tokens[1]) {
      flushOpenObjects();
      const sanitizedDev = tokens[1].replace(/\//g, '_').replace(/[^a-zA-Z0-9_.:-]/g, '_');
      currentIface = sanitizedDev;
      rawInterfaces[currentIface] = { device: sanitizedDev };
      continue;
    }

    if (currentIface && rawInterfaces[currentIface]) {
      if (tokens[0] === 'nameif') {
        rawInterfaces[currentIface].nameif = tokens[1];
        continue;
      }
      if (tokens[0] === 'vlan') {
        rawInterfaces[currentIface].vlan = Number.parseInt(tokens[1], 10);
        continue;
      }
      if (tokens[0] === 'ip' && tokens[1] === 'address') {
        if (tokens[2] === 'dhcp') {
          rawInterfaces[currentIface].ip = 'dhcp';
        } else if (tokens[2] && tokens[3]) {
          rawInterfaces[currentIface].ip = tokens[2];
          rawInterfaces[currentIface].mask = tokens[3];
        }
        continue;
      }
      if (tokens[0] === 'description') {
        rawInterfaces[currentIface].descr = tokens.slice(1).join(' ');
        continue;
      }
    }

    // 2. Object Network & Object Service
    if (tokens[0] === 'object' && tokens[1] === 'network') {
      currentIface = null;
      flushOpenObjects();
      currentObjNetwork = tokens[2] ? { name: tokens[2] } : null;
      continue;
    }

    if (tokens[0] === 'object' && tokens[1] === 'service') {
      currentIface = null;
      flushOpenObjects();
      currentObjService = tokens[2] ? { name: tokens[2], proto: 'tcp' } : null;
      continue;
    }

    if (currentObjNetwork && isIndented && tokens[0] !== 'nat') {
      if (tokens[0] === 'host') {
        currentObjNetwork.ip = tokens[1];
        continue;
      }
      if (tokens[0] === 'subnet' && tokens[1] && tokens[2]) {
        currentObjNetwork.ip = `${tokens[1]}/${maskToPrefix(tokens[2])}`;
        continue;
      }
      if (tokens[0] === 'description') {
        currentObjNetwork.descr = tokens.slice(1).join(' ');
        continue;
      }
    }

    if (currentObjService && isIndented) {
      if (tokens[0] === 'service' && tokens[1]) {
        const rawP = tokens[1].toLowerCase();
        currentObjService.proto = rawP === 'tcp-udp' ? 'tcp_udp' : rawP;
        let sIdx = 2;
        if (tokens[sIdx] === 'source') {
          const srcPortClause = parseCiscoPortClause(tokens, sIdx + 1);
          if (srcPortClause.present) {
            currentObjService.srcPortOp = srcPortClause.op;
            currentObjService.srcPort = srcPortClause.port;
            if (srcPortClause.unsupported) currentObjService.unsupported = true;
            sIdx = srcPortClause.nextIdx;
          }
        }
        if (tokens[sIdx] === 'destination') {
          const dstPortClause = parseCiscoPortClause(tokens, sIdx + 1);
          if (dstPortClause.present) {
            currentObjService.dstPortOp = dstPortClause.op;
            currentObjService.dstPort = dstPortClause.port;
            if (dstPortClause.unsupported) currentObjService.unsupported = true;
          }
        }
        continue;
      }
    }

    // 3. Object Group Network
    if (tokens[0] === 'object-group' && tokens[1] === 'network') {
      currentIface = null;
      flushOpenObjects();
      currentObjGroup = tokens[2] ? { name: tokens[2], entries: [] } : null;
      continue;
    }

    if (currentObjGroup) {
      if (tokens[0] === 'network-object') {
        if (tokens[1] === 'host' && tokens[2]) {
          currentObjGroup.entries.push(tokens[2]);
        } else if (tokens[1] && tokens[2]) {
          currentObjGroup.entries.push(`${tokens[1]}/${maskToPrefix(tokens[2])}`);
        }
        continue;
      }
      if (tokens[0] === 'description') {
        currentObjGroup.descr = tokens.slice(1).join(' ');
        continue;
      }
    }

    // 4. Access Lists
    if (tokens[0] === 'access-list' && tokens[2] === 'extended') {
      currentIface = null;
      const aclName = tokens[1];
      const rawAction = (tokens[3] || '').toLowerCase();
      const action = rawAction === 'permit' ? 'pass' : 'block';
      let proto = (tokens[4] || 'any').toLowerCase();
      let idx = 5;
      const unsupportedReasons: string[] = [];

      if (proto === 'object-group' || proto === 'object') {
        unsupportedReasons.push(`service ${proto} ${tokens[5] || ''}`.trim());
        proto = 'any';
        idx = 6;
      }

      const parsedSrc = parseCiscoAclEndpoint(tokens, idx, maskToPrefix);
      const src = parsedSrc.endpoint;
      idx = parsedSrc.nextIdx;
      if (!parsedSrc.valid) {
        unsupportedReasons.push(`unparsed source endpoint near "${tokens[idx] || ''}"`);
      }

      const srcPortClause = parseCiscoPortClause(tokens, idx);
      let srcPort = '';
      if (srcPortClause.present) {
        srcPort = srcPortClause.port;
        idx = srcPortClause.nextIdx;
        unsupportedReasons.push(`source-port ACL clause (${srcPortClause.summary})`);
      }

      const parsedDst = parseCiscoAclEndpoint(tokens, idx, maskToPrefix);
      const dst = parsedDst.endpoint;
      idx = parsedDst.nextIdx;
      if (!parsedDst.valid) {
        unsupportedReasons.push(`unparsed destination endpoint near "${tokens[idx] || ''}"`);
      }

      const dstPortClause = parseCiscoPortClause(tokens, idx);
      let dstPort = '';
      if (dstPortClause.present) {
        dstPort = dstPortClause.port;
        idx = dstPortClause.nextIdx;
        if (dstPortClause.unsupported) {
          unsupportedReasons.push(`unsupported destination-port clause (${dstPortClause.summary})`);
        }
      }

      const trailingTokens = tokens.slice(idx).map((t) => t.toLowerCase());
      const isInactive = trailingTokens.includes('inactive');
      const isLogged = trailingTokens.includes('log');

      let iface = 'any';
      if (aclName.includes('outside')) iface = 'wan';
      else if (aclName.includes('inside')) iface = 'lan';

      let ruleProto: any = 'any';
      if (proto === 'ip') {
        ruleProto = 'any';
      } else if (['tcp', 'udp', 'icmp', 'esp', 'ah', 'gre'].includes(proto)) {
        ruleProto = proto;
      } else {
        unsupportedReasons.push(`unsupported protocol "${proto}"`);
      }

      const hasUnsupported = unsupportedReasons.length > 0;
      const ruleIndex = rules.length;
      const baseDesc = `Imported from Cisco ACL ${aclName}`;
      const finalDesc = hasUnsupported
        ? `[REVIEW: ${unsupportedReasons.join('; ')}] ${baseDesc}`
        : baseDesc;

      if (hasUnsupported) {
        const explanation = `Cisco ACL rule in "${aclName}" (${line}) uses unsupported clause(s): ${unsupportedReasons.join(', ')}. Imported with enabled: false rather than dropping filters.`;
        const suggestedResolution = `Manually translate the unsupported port/source-port/protocol clauses into explicit positive Axonwall rules before enabling.`;
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
        direction: 'in',
        interface: iface,
        quick: true,
        protocol: ruleProto,
        source: src,
        sourcePort: srcPort,
        destination: dst,
        destinationPort: dstPort,
        log: isLogged,
        sortOrder: rules.length + 1,
        enabled: !hasUnsupported && !isInactive,
        description: finalDesc,
      });
      continue;
    }

    // 5. NAT (Object NAT inside `object network`, or top-level Twice NAT)
    if (tokens[0] === 'nat') {
      const ifaceMatch = tokens[1]?.match(/\(([^,]+),([^)]+)\)/);
      const inIface = ifaceMatch ? ifaceMatch[1]! : 'lan';
      const outIface = ifaceMatch ? ifaceMatch[2]! : 'wan';

      const validNatProtos = new Set(['any', 'tcp', 'udp', 'tcp_udp', 'icmp', 'ipv6-icmp', 'esp', 'ah', 'gre']);
      const normNatProto = (p?: string): NatRule['protocol'] => {
        const l = (p || 'tcp').toLowerCase();
        if (l === 'ip') return 'any';
        if (validNatProtos.has(l)) return l as NatRule['protocol'];
        return 'tcp';
      };

      const dynamicIdx = tokens.indexOf('dynamic');
      if (dynamicIdx !== -1) {
        const srcTok = tokens[dynamicIdx + 1];
        const dynSrc = resolveEndpoint(srcTok, 'any');
        nat.push({
          type: 'masquerade',
          interface: outIface === 'outside' ? 'wan' : outIface,
          protocol: 'any',
          source: dynSrc.value,
          sourcePort: '',
          destination: 'any',
          destinationPort: '',
          log: false,
          sortOrder: nat.length + 1,
          enabled: dynSrc.known,
          description: dynSrc.known
            ? `Cisco dynamic PAT (${inIface} -> ${outIface})`
            : `[REVIEW: Unresolved NAT source "${srcTok}"] Cisco dynamic PAT (${inIface} -> ${outIface})`,
        });
        continue;
      }

      const staticIdx = tokens.indexOf('static');
      if (staticIdx !== -1) {
        // Object NAT: indented inside `object network <Name>` and no `source`/`destination` Twice-NAT clauses
        if (isIndented && currentObjNetwork && !tokens.includes('source') && !tokens.includes('destination')) {
          const mappedTok = tokens[staticIdx + 1];
          const mappedDst = resolveEndpoint(mappedTok, 'wan_ip');
          const svcIdx = tokens.indexOf('service');
          let natProto: NatRule['protocol'] = 'tcp';
          let dstPort = '';
          let targetPort = '';
          let natUnsupported = !currentObjNetwork.ip || !mappedDst.known;

          if (svcIdx !== -1 && tokens[svcIdx + 1]) {
            natProto = normNatProto(tokens[svcIdx + 1]);
            const realPort = normalizeCiscoPort(tokens[svcIdx + 2]);
            const mappedPort = normalizeCiscoPort(tokens[svcIdx + 3]);
            if (realPort && mappedPort) {
              targetPort = realPort;
              dstPort = mappedPort;
            } else {
              natUnsupported = true;
            }
          }

          if (natUnsupported) {
            warnings.push(`Cisco Object NAT rule (${line}) has unresolved object or unsupported service port; imported with enabled: false.`);
          }
          nat.push({
            type: 'dnat',
            interface: outIface === 'outside' ? 'wan' : inIface === 'outside' ? 'wan' : outIface,
            protocol: natProto,
            source: 'any',
            sourcePort: '',
            destination: mappedDst.value,
            destinationPort: dstPort,
            targetIp: currentObjNetwork.ip || '',
            targetPort: targetPort || undefined,
            log: false,
            sortOrder: nat.length + 1,
            enabled: !natUnsupported,
            description: `Cisco object NAT (${currentObjNetwork.name}: ${inIface} -> ${outIface})`,
          });
          continue;
        }

        // Twice NAT: `nat (inIf,outIf) source static <srcReal> <srcMapped> [destination static <dstMapped> <dstReal>] [service <svc1> <svc2>]`
        const srcKeywordIdx = tokens.indexOf('source');
        const dstKeywordIdx = tokens.indexOf('destination');
        const svcIdx = tokens.indexOf('service');

        const srcRealTok = srcKeywordIdx !== -1 && tokens[srcKeywordIdx + 1] === 'static' ? tokens[srcKeywordIdx + 2] : undefined;
        const srcMappedTok = srcKeywordIdx !== -1 && tokens[srcKeywordIdx + 1] === 'static' ? tokens[srcKeywordIdx + 3] : undefined;
        const dstMappedTok = dstKeywordIdx !== -1 && tokens[dstKeywordIdx + 1] === 'static' ? tokens[dstKeywordIdx + 2] : undefined;
        const dstRealTok = dstKeywordIdx !== -1 && tokens[dstKeywordIdx + 1] === 'static' ? tokens[dstKeywordIdx + 3] : undefined;

        let natProto: NatRule['protocol'] = 'tcp';
        let natSrcPort = '';
        let natDstPort = '';
        let natTargetPort = '';
        let svcUnsupported = false;

        if (svcIdx !== -1 && tokens[svcIdx + 1]) {
          const s1 = tokens[svcIdx + 1]!;
          const s2 = tokens[svcIdx + 2];
          const s3 = tokens[svcIdx + 3];
          if ((s1 === 'tcp' || s1 === 'udp') && s2 && s3) {
            natProto = normNatProto(s1);
            const p1 = normalizeCiscoPort(s2);
            const p2 = normalizeCiscoPort(s3);
            if (p1 && p2) {
              if (inIface === 'outside') {
                natDstPort = p1;
                natTargetPort = p2;
              } else {
                natTargetPort = p1;
                natDstPort = p2;
              }
            } else {
              svcUnsupported = true;
            }
          } else {
            const obj1 = serviceObjects.get(s1);
            const obj2 = s2 ? serviceObjects.get(s2) : undefined;
            if (!obj1 && !obj2) {
              svcUnsupported = true;
            } else {
              if (obj1?.unsupported || obj2?.unsupported) svcUnsupported = true;
              const chosenProto = obj1?.proto || obj2?.proto || 'tcp';
              natProto = normNatProto(chosenProto);
              natSrcPort = obj1?.srcPort || obj2?.srcPort || '';
              if (inIface === 'outside') {
                natDstPort = obj1?.dstPort || '';
                natTargetPort = obj2?.dstPort || obj1?.dstPort || '';
              } else {
                natTargetPort = obj1?.dstPort || '';
                natDstPort = obj2?.dstPort || obj1?.dstPort || '';
              }
            }
          }
        }

        if (dstRealTok) {
          const srcFilter = resolveEndpoint(srcRealTok, 'any');
          const dstFilter = resolveEndpoint(dstMappedTok, 'wan_ip');
          const targetObj = resolveEndpoint(dstRealTok, '');
          const resolvedTargetIp = targetObj.resolvedIp || '';
          const invalidTarget =
            !resolvedTargetIp || (!isValidIPv4(resolvedTargetIp) && !isValidIPv6(resolvedTargetIp) && !isValidCIDR(resolvedTargetIp));
          const hasReview = !srcFilter.known || !dstFilter.known || invalidTarget || svcUnsupported;
          if (hasReview) {
            warnings.push(`Cisco static NAT rule (${line}) has unresolved object or unsupported service port; imported with enabled: false.`);
          }
          nat.push({
            type: 'dnat',
            interface: inIface === 'outside' ? 'wan' : inIface,
            protocol: natProto,
            source: srcFilter.value,
            sourcePort: natSrcPort,
            destination: dstFilter.value,
            destinationPort: natDstPort,
            targetIp: resolvedTargetIp,
            ...(natTargetPort ? { targetPort: natTargetPort } : {}),
            log: false,
            sortOrder: nat.length + 1,
            enabled: !hasReview,
            description: hasReview
              ? `[REVIEW: Static NAT] Cisco static NAT (${inIface} -> ${outIface})`
              : `Cisco static NAT (${inIface} -> ${outIface})`,
          });
        } else {
          const srcReal = resolveEndpoint(srcRealTok || tokens[staticIdx + 1], 'any');
          const srcMapped = resolveEndpoint(srcMappedTok, 'wan_ip');
          const targetIp = srcReal.resolvedIp || (srcMapped.resolvedIp ?? '');
          const invalidTarget =
            !targetIp || (!isValidIPv4(targetIp) && !isValidIPv6(targetIp) && !isValidCIDR(targetIp));
          const hasReview = !srcReal.known || !srcMapped.known || invalidTarget || svcUnsupported;
          if (hasReview) {
            warnings.push(`Cisco static NAT rule (${line}) has unresolved object or unsupported service port; imported with enabled: false.`);
          }
          nat.push({
            type: 'dnat',
            interface: inIface === 'outside' ? 'wan' : outIface === 'outside' ? 'wan' : inIface,
            protocol: natProto,
            source: srcReal.value,
            sourcePort: natSrcPort,
            destination: srcMapped.value,
            destinationPort: natDstPort,
            targetIp,
            ...(natTargetPort ? { targetPort: natTargetPort } : {}),
            log: false,
            sortOrder: nat.length + 1,
            enabled: !hasReview,
            description: hasReview
              ? `[REVIEW: Static NAT] Cisco static NAT (${inIface} -> ${outIface})`
              : `Cisco static NAT (${inIface} -> ${outIface})`,
          });
        }
      }
      continue;
    }

    // 6. Routes
    if (tokens[0] === 'route' && tokens[1] && tokens[2] && tokens[3] && tokens[4]) {
      const routeIface = tokens[1];
      const destNet = tokens[2];
      const destMask = tokens[3];
      const gw = tokens[4];

      if (destNet === '0.0.0.0' && destMask === '0.0.0.0') {
        // Default gateway
        warnings.push(`Cisco default route via ${gw} mapped as uplink gateway.`);
      } else {
        routes.push({
          network: `${destNet}/${maskToPrefix(destMask)}`,
          gateway: gw,
          interface: routeIface.includes('outside') ? 'wan' : 'lan',
          description: `Cisco static route on ${routeIface}`,
          enabled: true,
        });
      }
      continue;
    }
  }

  // Flush trailing objects
  flushOpenObjects();

  // Format interfaces and VLANs
  const interfaces: Interface[] = [];
  const vlans: Vlan[] = [];

  for (const [dev, data] of Object.entries(rawInterfaces)) {
    const isWan = data.nameif === 'outside' || dev.toLowerCase().includes('outside');
    const name = isWan ? 'wan' : data.nameif || dev.toLowerCase().replace(/[^a-z0-9]/g, '');

    let cidr = '';
    if (data.ip && data.ip !== 'dhcp' && data.mask) {
      cidr = `${data.ip}/${maskToPrefix(data.mask)}`;
    }

    interfaces.push({
      name,
      device: dev,
      type: data.ip === 'dhcp' ? 'dhcp' : 'static',
      ipv4Address: cidr || undefined,
      enabled: true,
      description: data.descr || data.nameif || dev,
      mtu: 1500,
    });

    if (data.vlan) {
      const parent = dev.split('.')[0] || 'eth0';
      vlans.push({
        tag: data.vlan,
        parentInterface: parent,
        vlanInterface: dev,
        priority: 0,
        description: data.descr || `VLAN ${data.vlan}`,
      });
    }
  }

  if (interfaces.length === 0) {
    interfaces.push(
      { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, description: 'WAN', mtu: 1500 },
      { name: 'lan', device: 'eth1', type: 'static', ipv4Address: '192.168.1.1/24', enabled: true, description: 'LAN', mtu: 1500 }
    );
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
        ports: [80, 443, 22, 3000, 2966],
      },
    },
    interfaces,
    rules,
    nat,
    gateways: [],
    gatewayGroups: [],
    aliases,
    vlans,
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
      dotUpstreams: [],
      hostOverrides: [],
    },
    routes,
  };

  return {
    success: true,
    vendor: 'cisco' as any,
    version: 'ASA 9.x',
    sourceFormat: 'Cisco ASA / FTD Configuration',
    interfacesCount: interfaces.length,
    vlansCount: vlans.length,
    aliasesCount: aliases.length,
    rulesCount: rules.length,
    natRulesCount: nat.length,
    dhcpSubnetsCount: 0,
    dnsOverridesCount: 0,
    routesCount: routes.length,
    warnings,
    reviewItems,
    state,
  };
}
