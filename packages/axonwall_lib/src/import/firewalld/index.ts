import { XMLParser } from 'fast-xml-parser';
import {
  isValidFirewallEndpoint,
  isValidPortSpec,
  type DesiredState,
  type Interface,
  type Alias,
  type FirewallRule,
  type NatRule,
} from '../../schemas/index.js';
import type { ImportReport, ImportReviewItem } from '../types.js';

export interface FirewalldServiceDef {
  protocol: 'tcp' | 'udp' | 'tcp_udp' | 'icmp' | 'esp' | 'ah' | 'gre';
  ports: string;
  description: string;
}

/**
 * Built-in catalog of standard firewalld service definitions (/usr/lib/firewalld/services/*.xml)
 */
export const FIREWALLD_SERVICES: Record<string, FirewalldServiceDef> = {
  ssh: { protocol: 'tcp', ports: '22', description: 'Secure Shell (SSH)' },
  http: { protocol: 'tcp', ports: '80', description: 'HTTP Web Traffic' },
  https: { protocol: 'tcp', ports: '443', description: 'HTTPS Secure Web Traffic' },
  http3: { protocol: 'udp', ports: '443', description: 'HTTP/3 over QUIC' },
  dns: { protocol: 'tcp_udp', ports: '53', description: 'Domain Name System (DNS)' },
  'dns-over-tls': { protocol: 'tcp', ports: '853', description: 'DNS over TLS (DoT)' },
  dhcp: { protocol: 'udp', ports: '67', description: 'DHCPv4 Server' },
  dhcpv6: { protocol: 'udp', ports: '547', description: 'DHCPv6 Server' },
  'dhcpv6-client': { protocol: 'udp', ports: '546', description: 'DHCPv6 Client' },
  ntp: { protocol: 'udp', ports: '123', description: 'Network Time Protocol (NTP)' },
  smtp: { protocol: 'tcp', ports: '25', description: 'Simple Mail Transfer Protocol (SMTP)' },
  smtps: { protocol: 'tcp', ports: '465', description: 'SMTP over SSL/TLS' },
  'smtp-submission': { protocol: 'tcp', ports: '587', description: 'SMTP Mail Submission' },
  imap: { protocol: 'tcp', ports: '143', description: 'IMAP Mail' },
  imaps: { protocol: 'tcp', ports: '993', description: 'IMAP over SSL/TLS' },
  pop3: { protocol: 'tcp', ports: '110', description: 'POP3 Mail' },
  pop3s: { protocol: 'tcp', ports: '995', description: 'POP3 over SSL/TLS' },
  ftp: { protocol: 'tcp', ports: '21', description: 'File Transfer Protocol (FTP)' },
  tftp: { protocol: 'udp', ports: '69', description: 'Trivial File Transfer Protocol (TFTP)' },
  samba: { protocol: 'tcp_udp', ports: '137, 138, 139, 445', description: 'Samba / SMB File Sharing' },
  'samba-client': { protocol: 'udp', ports: '137, 138', description: 'Samba NetBIOS Client' },
  nfs: { protocol: 'tcp_udp', ports: '2049', description: 'NFSv4 Network File System' },
  nfs3: { protocol: 'tcp_udp', ports: '2049', description: 'NFSv3 Network File System' },
  mountd: { protocol: 'tcp_udp', ports: '20048', description: 'NFS mountd' },
  'rpc-bind': { protocol: 'tcp_udp', ports: '111', description: 'RPC Portmapper (rpcbind)' },
  'iscsi-target': { protocol: 'tcp', ports: '3260', description: 'iSCSI Target' },
  mysql: { protocol: 'tcp', ports: '3306', description: 'MySQL / MariaDB Database' },
  postgresql: { protocol: 'tcp', ports: '5432', description: 'PostgreSQL Database' },
  redis: { protocol: 'tcp', ports: '6379', description: 'Redis Key-Value Store' },
  mongodb: { protocol: 'tcp', ports: '27017', description: 'MongoDB Database' },
  mssql: { protocol: 'tcp', ports: '1433', description: 'Microsoft SQL Server' },
  ldap: { protocol: 'tcp_udp', ports: '389', description: 'Lightweight Directory Access Protocol (LDAP)' },
  ldaps: { protocol: 'tcp', ports: '6636', description: 'LDAP over TLS (LDAPS)' },
  kerberos: { protocol: 'tcp_udp', ports: '88', description: 'Kerberos v5 Authentication' },
  'freeipa-ldap': { protocol: 'tcp_udp', ports: '80, 443, 389, 636, 88, 464', description: 'FreeIPA LDAP Directory' },
  radius: { protocol: 'udp', ports: '1812, 1813', description: 'RADIUS Authentication & Accounting' },
  snmp: { protocol: 'udp', ports: '161', description: 'SNMP Agent' },
  snmptrap: { protocol: 'udp', ports: '162', description: 'SNMP Trap Receiver' },
  syslog: { protocol: 'udp', ports: '514', description: 'Syslog Logging' },
  cockpit: { protocol: 'tcp', ports: '9090', description: 'Red Hat Cockpit Web Console' },
  wireguard: { protocol: 'udp', ports: '51820', description: 'WireGuard VPN' },
  openvpn: { protocol: 'udp', ports: '1194', description: 'OpenVPN Tunnel' },
  ipsec: { protocol: 'udp', ports: '500, 4500', description: 'IPsec IKEv2 / NAT-T' },
  bgp: { protocol: 'tcp', ports: '179', description: 'Border Gateway Protocol (BGP)' },
  'kube-apiserver': { protocol: 'tcp', ports: '6443', description: 'Kubernetes API Server' },
  kubelet: { protocol: 'tcp', ports: '10250', description: 'Kubernetes Kubelet API' },
  'etcd-client': { protocol: 'tcp', ports: '2379', description: 'etcd Client Port' },
  'etcd-server': { protocol: 'tcp', ports: '2380', description: 'etcd Peer Server Port' },
  'vnc-server': { protocol: 'tcp', ports: '5900-5903', description: 'VNC Remote Desktop' },
  rdp: { protocol: 'tcp_udp', ports: '3389', description: 'Remote Desktop Protocol (RDP)' },
  mdns: { protocol: 'udp', ports: '5353', description: 'Multicast DNS (mDNS / Avahi)' },
  plex: { protocol: 'tcp_udp', ports: '32400', description: 'Plex Media Server' },
  prometheus: { protocol: 'tcp', ports: '9090', description: 'Prometheus Metrics' },
  grafana: { protocol: 'tcp', ports: '3000', description: 'Grafana Dashboard' },
};

// Fix standard LDAPS port 636
FIREWALLD_SERVICES.ldaps.ports = '636';

interface ParsedRichRule {
  family?: string;
  sourceAddress?: string;
  sourceIpset?: string;
  sourceNot?: boolean;
  destinationAddress?: string;
  destinationIpset?: string;
  destinationNot?: boolean;
  serviceName?: string;
  port?: string;
  portProtocol?: string;
  protocolValue?: string;
  forwardPort?: { port: string; protocol: string; toPort?: string; toAddr?: string };
  hasLog?: boolean;
  hasMasquerade?: boolean;
  action?: 'accept' | 'drop' | 'reject' | 'mark';
  rawSummary?: string;
}

interface ParsedZone {
  name: string;
  target: string; // default, ACCEPT, DROP, %%REJECT%%
  description: string;
  interfaces: string[];
  sources: string[];
  services: string[];
  ports: { port: string; protocol: string }[];
  protocols: string[];
  masquerade: boolean;
  forwardPorts: { port: string; protocol: string; toPort?: string; toAddr?: string }[];
  richRules: ParsedRichRule[];
  icmpBlocks: string[];
}

function mapZoneToAxonwallInterface(zoneName: string, boundDevs: string[]): { ifaceName: string; devName: string } {
  const lower = zoneName.toLowerCase();
  if (lower === 'public' || lower === 'external' || lower === 'untrusted' || lower === 'drop' || lower === 'block') {
    return { ifaceName: 'wan', devName: boundDevs[0] || 'eth0' };
  }
  if (lower === 'internal' || lower === 'home' || lower === 'work' || lower === 'trusted') {
    return { ifaceName: 'lan', devName: boundDevs[0] || 'eth1' };
  }
  if (lower === 'dmz') {
    return { ifaceName: 'opt1', devName: boundDevs[0] || 'eth2' };
  }
  const cleanName = lower.replace(/[^a-z0-9_]/g, '') || 'opt1';
  return { ifaceName: cleanName, devName: boundDevs[0] || 'eth2' };
}

function normalizeProtocol(proto?: string): FirewallRule['protocol'] {
  const p = (proto || 'any').toLowerCase().trim();
  if (p === 'tcp') return 'tcp';
  if (p === 'udp') return 'udp';
  if (p === 'tcp_udp' || p === 'tcp/udp') return 'tcp_udp';
  if (p === 'icmp') return 'icmp';
  if (p === 'ipv6-icmp' || p === 'icmpv6') return 'ipv6-icmp';
  if (p === 'esp') return 'esp';
  if (p === 'ah') return 'ah';
  if (p === 'gre') return 'gre';
  return 'any';
}

function sanitizeAliasName(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9_]/g, '_');
}

function parseRichRuleText(richText: string): ParsedRichRule {
  const text = richText.trim().replace(/\s+/g, ' ');
  if (!text) return {};

  const negatedSrc = /\bsource\s+not\s+/i.test(text);
  const negatedDst = /\bdestination\s+not\s+/i.test(text);
  const srcMatch = text.match(/\bsource\s+(?:not\s+)?address=["']([^"']+)["']/i);
  const srcIpsetMatch = text.match(/\bsource\s+(?:not\s+)?ipset=["']([^"']+)["']/i);
  const dstMatch = text.match(/\bdestination\s+(?:not\s+)?address=["']([^"']+)["']/i);
  const dstIpsetMatch = text.match(/\bdestination\s+(?:not\s+)?ipset=["']([^"']+)["']/i);
  const svcMatch = text.match(/\bservice\s+name=["']([^"']+)["']/i);
  const portMatch = text.match(/\bport\s+port=["']([^"']+)["']\s+protocol=["']([^"']+)["']/i)
    || text.match(/\bport\s+protocol=["']([^"']+)["']\s+port=["']([^"']+)["']/i);
  const protoMatch = text.match(/\bprotocol\s+value=["']([^"']+)["']/i);
  const fwdMatch = text.match(/\bforward-port\s+([^\n]+)/i);

  // Strip quoted attribute values so log prefix="accept" / prefix="drop" cannot spoof actions.
  const unquoted = text.replace(/"[^"]*"|'[^']*'/g, ' ');
  const hasLog = /\blog\b/i.test(unquoted);
  const hasMasq = /\bmasquerade\b/i.test(unquoted);

  let action: ParsedRichRule['action'];
  if (/\bdrop\b/i.test(unquoted)) action = 'drop';
  else if (/\breject\b/i.test(unquoted)) action = 'reject';
  else if (/\baccept\b/i.test(unquoted)) action = 'accept';
  else if (/\bmark\b/i.test(unquoted)) action = 'mark';

  let port: string | undefined;
  let portProtocol: string | undefined;
  if (portMatch) {
    const isPortFirst = /port\s+port=/i.test(portMatch[0]);
    port = isPortFirst ? portMatch[1] : portMatch[2];
    portProtocol = isPortFirst ? portMatch[2] : portMatch[1];
  }

  let forwardPort: ParsedRichRule['forwardPort'];
  if (fwdMatch) {
    const attrs = fwdMatch[1]!;
    forwardPort = {
      port: attrs.match(/port=["']([^"']+)["']/i)?.[1] || '',
      protocol: attrs.match(/protocol=["']([^"']+)["']/i)?.[1] || 'tcp',
      toPort: attrs.match(/to-port=["']([^"']+)["']/i)?.[1],
      toAddr: attrs.match(/to-addr=["']([^"']+)["']/i)?.[1],
    };
  }

  return {
    sourceAddress: srcMatch?.[1],
    sourceIpset: srcIpsetMatch?.[1],
    sourceNot: negatedSrc,
    destinationAddress: dstMatch?.[1],
    destinationIpset: dstIpsetMatch?.[1],
    destinationNot: negatedDst,
    serviceName: svcMatch?.[1],
    port,
    portProtocol,
    protocolValue: protoMatch?.[1],
    forwardPort,
    hasLog,
    hasMasquerade: hasMasq,
    action,
    rawSummary: text,
  };
}

function isXmlInvertFlag(node: any): boolean {
  if (!node || typeof node !== 'object') return false;
  const inv = node['@_invert'];
  if (inv === true || inv === '' || inv === '1' || inv === 1 || String(inv).toLowerCase() === 'true' || String(inv).toLowerCase() === 'yes') {
    return true;
  }
  return node['@_not'] !== undefined || node['@_NOT'] !== undefined || node.not !== undefined;
}

function parseXmlRichRuleElement(r: any): ParsedRichRule {
  const srcObj = Array.isArray(r.source) ? r.source[0] : r.source;
  const dstObj = Array.isArray(r.destination) ? r.destination[0] : r.destination;
  const svcObj = Array.isArray(r.service) ? r.service[0] : r.service;
  const portObj = Array.isArray(r.port) ? r.port[0] : r.port;
  const protoObj = Array.isArray(r.protocol) ? r.protocol[0] : r.protocol;
  const fpObj = Array.isArray(r['forward-port']) ? r['forward-port'][0] : r['forward-port'];

  let action: ParsedRichRule['action'];
  if (r.drop !== undefined) action = 'drop';
  else if (r.reject !== undefined) action = 'reject';
  else if (r.accept !== undefined) action = 'accept';
  else if (r.mark !== undefined) action = 'mark';

  return {
    family: r['@_family'] !== undefined ? String(r['@_family']) : undefined,
    sourceAddress: srcObj?.['@_address'] !== undefined ? String(srcObj['@_address']) : undefined,
    sourceIpset: srcObj?.['@_ipset'] !== undefined ? String(srcObj['@_ipset']) : undefined,
    sourceNot: isXmlInvertFlag(srcObj),
    destinationAddress: dstObj?.['@_address'] !== undefined ? String(dstObj['@_address']) : undefined,
    destinationIpset: dstObj?.['@_ipset'] !== undefined ? String(dstObj['@_ipset']) : undefined,
    destinationNot: isXmlInvertFlag(dstObj),
    serviceName: svcObj?.['@_name'] !== undefined ? String(svcObj['@_name']) : undefined,
    port: portObj?.['@_port'] !== undefined ? String(portObj['@_port']) : undefined,
    portProtocol: portObj?.['@_protocol'] !== undefined ? String(portObj['@_protocol']) : 'tcp',
    protocolValue: protoObj?.['@_value'] !== undefined ? String(protoObj['@_value']) : undefined,
    forwardPort: fpObj
      ? {
          port: fpObj['@_port'] !== undefined ? String(fpObj['@_port']) : '',
          protocol: fpObj['@_protocol'] !== undefined ? String(fpObj['@_protocol']) : 'tcp',
          toPort: fpObj['@_to-port'] !== undefined ? String(fpObj['@_to-port']) : undefined,
          toAddr: fpObj['@_to-addr'] !== undefined ? String(fpObj['@_to-addr']) : undefined,
        }
      : undefined,
    hasLog: r.log !== undefined,
    hasMasquerade: r.masquerade !== undefined,
    action,
  };
}

/**
 * Converts a structurally parsed firewalld rich rule into a FirewallRule or NatRule
 */
function parseRichRule(
  rr: ParsedRichRule,
  ifaceName: string,
  sortOrder: number,
  natSortOrder: number,
  customServices: Map<string, FirewalldServiceDef>,
  warnings: string[],
  ruleIndex = 0,
): { rule?: FirewallRule; natRule?: NatRule; reviewItem?: ImportReviewItem } {
  const rawSource = rr.sourceAddress
    ? rr.sourceAddress.trim()
    : rr.sourceIpset
      ? `$${sanitizeAliasName(rr.sourceIpset)}`
      : 'any';
  const rawDestination = rr.destinationAddress
    ? rr.destinationAddress.trim()
    : rr.destinationIpset
      ? `$${sanitizeAliasName(rr.destinationIpset)}`
      : 'any';

  const sourceValid = rawSource === 'any' || isValidFirewallEndpoint(rawSource);
  const destinationValid = rawDestination === 'any' || isValidFirewallEndpoint(rawDestination);
  const source = sourceValid ? rawSource : 'any';
  const destination = destinationValid ? rawDestination : 'any';
  const hasInvalidMatch = !sourceValid || !destinationValid;

  const negatedSrc = Boolean(rr.sourceNot) && source !== 'any';
  const negatedDst = Boolean(rr.destinationNot) && destination !== 'any';

  if (rr.hasMasquerade) {
    const natReview = negatedSrc || negatedDst || hasInvalidMatch;
    if (natReview) {
      warnings.push(
        `Firewalld rich rule masquerade (${ifaceName}) uses negated or invalid source/destination match; imported with enabled: false.`,
      );
    }
    return {
      natRule: {
        type: 'masquerade',
        interface: ifaceName,
        protocol: 'any',
        source,
        sourcePort: '',
        destination,
        destinationPort: '',
        log: Boolean(rr.hasLog),
        enabled: !natReview,
        description: natReview ? `[REVIEW: Negated/invalid NAT] Rich Rule Masquerade (${ifaceName})` : `Rich Rule Masquerade (${ifaceName})`,
        sortOrder: natSortOrder,
      },
    };
  }

  if (rr.forwardPort) {
    const pPort = (rr.forwardPort.port || '').replace(':', '-').trim();
    const pProto = (rr.forwardPort.protocol || 'tcp').trim();
    const toPort = (rr.forwardPort.toPort || pPort).replace(':', '-').trim();
    const toAddr = (rr.forwardPort.toAddr || '127.0.0.1').trim();
    if (!pPort || !isValidPortSpec(pPort) || (toPort && !isValidPortSpec(toPort)) || !isValidFirewallEndpoint(toAddr)) {
      warnings.push(`Skipped firewalld rich rule forward-port on "${ifaceName}" with missing or invalid port/target.`);
      return {};
    }
    const natReview = negatedSrc || negatedDst || hasInvalidMatch;
    if (natReview) {
      warnings.push(
        `Firewalld rich rule forward-port (${pProto.toUpperCase()}/${pPort} -> ${toAddr}:${toPort}) uses negated or invalid source/destination match; imported with enabled: false.`,
      );
    }
    return {
      natRule: {
        type: 'dnat',
        interface: ifaceName,
        protocol: normalizeProtocol(pProto),
        source,
        sourcePort: '',
        destination: destination === 'any' ? 'wan_ip' : destination,
        destinationPort: pPort,
        targetIp: toAddr,
        targetPort: toPort,
        log: Boolean(rr.hasLog),
        enabled: !natReview,
        description: natReview
          ? `[REVIEW: Negated/invalid NAT] Rich Rule Forward ${pProto.toUpperCase()}/${pPort} -> ${toAddr}:${toPort}`
          : `Rich Rule Forward ${pProto.toUpperCase()}/${pPort} -> ${toAddr}:${toPort}`,
        sortOrder: natSortOrder,
      },
    };
  }

  let protocol: FirewallRule['protocol'] = 'any';
  let destinationPort = '';
  let descDetail = 'Rich Rule';
  let hasInvalidPort = false;

  if (rr.serviceName) {
    const svcName = rr.serviceName.toLowerCase().trim();
    const svcDef = customServices.get(svcName) || FIREWALLD_SERVICES[svcName];
    if (svcDef) {
      protocol = svcDef.protocol;
      destinationPort = svcDef.ports;
      descDetail = `Rich Rule: ${svcName}`;
    } else {
      warnings.push(
        `Unknown firewalld service "${svcName}" in rich rule — skipped rather than expanding to protocol 'any'.`,
      );
      return {};
    }
  } else if (rr.port) {
    const rawProto = (rr.portProtocol || 'tcp').trim();
    const normPort = rr.port.trim().replace(':', '-');
    protocol = normalizeProtocol(rawProto);
    if (isValidPortSpec(normPort)) {
      destinationPort = normPort;
    } else {
      hasInvalidPort = true;
    }
    descDetail = `Rich Rule: ${rawProto.toUpperCase()}/${normPort}`;
  } else if (rr.protocolValue) {
    protocol = normalizeProtocol(rr.protocolValue);
    descDetail = `Rich Rule: proto ${rr.protocolValue}`;
  }

  let action: FirewallRule['action'];
  let hasUnsupportedAction = false;
  if (rr.action === 'drop') {
    action = 'block';
  } else if (rr.action === 'reject') {
    action = 'reject';
  } else if (rr.action === 'accept') {
    action = 'pass';
  } else {
    action = 'block';
    hasUnsupportedAction = true;
  }

  const hasNegation = negatedSrc || negatedDst;
  const needsReview = hasNegation || hasUnsupportedAction || hasInvalidMatch || hasInvalidPort;
  const baseDesc = `${descDetail} (${ifaceName})`;
  const reviewLabels: string[] = [];
  if (hasUnsupportedAction) {
    reviewLabels.push(rr.action === 'mark' ? 'Unsupported mark action' : 'Missing/unknown rich rule action');
  }
  if (hasNegation) reviewLabels.push('Negated match');
  if (hasInvalidMatch || hasInvalidPort) reviewLabels.push('Invalid endpoint/port');
  const finalDesc = reviewLabels.length > 0 ? `[REVIEW: ${reviewLabels.join('; ')}] ${baseDesc}` : baseDesc;

  let reviewItem: ImportReviewItem | undefined;
  if (needsReview) {
    const reason: ImportReviewItem['reason'] =
      hasNegation && !hasUnsupportedAction && !hasInvalidMatch && !hasInvalidPort
        ? negatedSrc && negatedDst
          ? 'negated_both'
          : negatedSrc
            ? 'negated_source'
            : 'negated_destination'
        : 'manual_review';
    const matchSummary =
      rr.rawSummary ||
      `${hasUnsupportedAction ? (rr.action || 'NO_ACTION').toUpperCase() : action.toUpperCase()} ${protocol} from ${negatedSrc ? `!${rawSource}` : rawSource} to ${negatedDst ? `!${rawDestination}` : rawDestination}`;
    const explanation = hasUnsupportedAction
      ? `Firewalld rich rule "${baseDesc}" has ${rr.action ? `unsupported action "${rr.action}"` : 'no terminal accept/drop/reject action'} (${matchSummary}). Imported fail-closed with action: block and enabled: false.`
      : hasInvalidMatch || hasInvalidPort
        ? `Firewalld rich rule "${baseDesc}" contains invalid address/port syntax (${matchSummary}). Imported fail-closed with action: block and enabled: false.`
        : `Firewalld rich rule "${baseDesc}" uses an inverted (not) ${reason === 'negated_both' ? 'source and destination' : reason === 'negated_source' ? 'source' : 'destination'} match (${matchSummary}). Imported with enabled: false so it cannot silently activate with inverted semantics.`;
    const suggestedResolution = hasUnsupportedAction || hasInvalidMatch || hasInvalidPort
      ? `Verify the intended action and valid endpoints/ports in firewalld before enabling.`
      : `Split into an explicit preceding rule matching ${negatedSrc ? source : destination} with the opposite action, followed by a broader rule matching 'any', then enable the reviewed rules.`;
    warnings.push(explanation + ' ' + suggestedResolution);
    reviewItem = {
      ruleId: `rule-${ruleIndex + 1}`,
      ruleIndex,
      reason,
      originalMatchSummary: matchSummary,
      explanation,
      suggestedResolution,
    };
  }

  return {
    rule: {
      action,
      direction: 'in',
      interface: ifaceName,
      quick: true,
      protocol,
      source,
      ...(negatedSrc ? { invertSource: true } : {}),
      sourcePort: '',
      destination,
      ...(negatedDst ? { invertDestination: true } : {}),
      destinationPort,
      log: Boolean(rr.hasLog),
      enabled: !needsReview,
      description: finalDesc,
      sortOrder,
    },
    reviewItem,
  };
}

/**
 * Parses XML-based firewalld configuration (<zone>, <policy>, <ipset>, <service>, or <firewalld> bundle)
 */
function parseFirewalldXml(
  xmlContent: string,
  zones: Map<string, ParsedZone>,
  aliases: Alias[],
  customServices: Map<string, FirewalldServiceDef>,
  warnings: string[],
) {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    processEntities: false,
    isArray: (name) =>
      [
        'zone',
        'policy',
        'ipset',
        'service',
        'interface',
        'source',
        'port',
        'protocol',
        'forward-port',
        'rule',
        'entry',
        'icmp-block',
        'ingress-zone',
        'egress-zone',
      ].includes(name),
  });

  // Wrap multiple root elements if needed so XMLParser can parse concatenated zone/ipset files
  const cleanedXml = xmlContent.replace(/<\?xml[^?]*\?>/gi, '').trim();
  const wrappedXml = `<firewalld_bundle>${cleanedXml}</firewalld_bundle>`;

  let parsed: any;
  try {
    parsed = parser.parse(wrappedXml);
  } catch (err: any) {
    throw new Error(`Failed to parse firewalld XML configuration: ${err.message}`);
  }

  const bundle = parsed.firewalld_bundle || {};
  const root = bundle.firewalld || bundle;

  // 1. Parse IPSets (<ipset type="hash:ip">...</ipset>)
  const rawIpsets = root.ipset || [];
  for (const ipset of Array.isArray(rawIpsets) ? rawIpsets : [rawIpsets]) {
    if (!ipset || typeof ipset !== 'object') continue;
    const rawName = ipset['@_name'] || ipset.short || 'firewalld_ipset';
    const name = sanitizeAliasName(String(rawName));
    const ipsetType = String(ipset['@_type'] || 'hash:ip').toLowerCase();
    const entries: string[] = [];

    for (const entry of ipset.entry || []) {
      if (typeof entry === 'string' || typeof entry === 'number') {
        entries.push(String(entry).trim());
      } else if (entry && entry['#text']) {
        entries.push(String(entry['#text']).trim());
      }
    }

    if (entries.length > 0) {
      let aliasType: Alias['type'] = 'host';
      if (ipsetType.includes('net') || entries.some((e) => e.includes('/'))) {
        aliasType = 'network';
      } else if (ipsetType.includes('mac')) {
        aliasType = 'mac';
      } else if (ipsetType.includes('port')) {
        aliasType = 'port';
      }

      aliases.push({
        name,
        type: aliasType,
        entries,
        description: ipset.description || ipset.short || `Imported firewalld ipset (${ipsetType})`,
        enabled: true,
      });
    }
  }

  // 2. Parse Custom Service definitions if top-level <service> has <port> children
  const rawTopServices = root.service || [];
  for (const svc of Array.isArray(rawTopServices) ? rawTopServices : [rawTopServices]) {
    if (!svc || typeof svc !== 'object' || !svc.port) continue;
    const svcName = String(svc['@_name'] || svc.short || '').toLowerCase().trim();
    if (!svcName) continue;
    const portsList: string[] = [];
    let hasTcp = false;
    let hasUdp = false;

    for (const p of svc.port) {
      const portVal = String(p['@_port'] || '').replace(':', '-');
      const protoVal = String(p['@_protocol'] || 'tcp').toLowerCase();
      if (portVal) portsList.push(portVal);
      if (protoVal === 'tcp') hasTcp = true;
      if (protoVal === 'udp') hasUdp = true;
    }

    if (portsList.length > 0) {
      customServices.set(svcName, {
        protocol: hasTcp && hasUdp ? 'tcp_udp' : hasUdp ? 'udp' : 'tcp',
        ports: portsList.join(', '),
        description: svc.description || svc.short || `Custom service ${svcName}`,
      });
    }
  }

  // 3. Parse Zones (<zone>)
  const rawZones: any[] = [];
  if (root.zone) {
    rawZones.push(...(Array.isArray(root.zone) ? root.zone : [root.zone]));
  }
  // Handle single <zone> at top-level if <zone> had direct children in bundle
  if (rawZones.length === 0 && (root.service || root.port || root['forward-port'] || root.rule || root.masquerade !== undefined)) {
    rawZones.push({
      '@_name': root['@_name'] || root.short || 'public',
      '@_target': root['@_target'] || 'default',
      ...root,
    });
  }

  for (const z of rawZones) {
    if (!z || typeof z !== 'object') continue;
    const zoneName = String(z['@_name'] || z.short || 'public').toLowerCase();
    const target = String(z['@_target'] || 'default');
    const description = String(z.description || z.short || `Firewalld ${zoneName} zone`);

    const parsedZone: ParsedZone = zones.get(zoneName) || {
      name: zoneName,
      target,
      description,
      interfaces: [],
      sources: [],
      services: [],
      ports: [],
      protocols: [],
      masquerade: false,
      forwardPorts: [],
      richRules: [],
      icmpBlocks: [],
    };

    if (z.interface) {
      for (const iface of z.interface) {
        const ifName = iface?.['@_name'];
        if (ifName && !parsedZone.interfaces.includes(ifName)) {
          parsedZone.interfaces.push(String(ifName));
        }
      }
    }

    if (z.source) {
      for (const src of z.source) {
        if (src?.['@_address']) {
          parsedZone.sources.push(String(src['@_address']));
        } else if (src?.['@_ipset']) {
          parsedZone.sources.push(`$${sanitizeAliasName(String(src['@_ipset']))}`);
        }
      }
    }

    if (z.service) {
      for (const svc of z.service) {
        const sName = svc?.['@_name'];
        if (sName && !parsedZone.services.includes(String(sName))) {
          parsedZone.services.push(String(sName));
        }
      }
    }

    if (z.port) {
      for (const p of z.port) {
        const portVal = String(p?.['@_port'] || '').replace(':', '-');
        const protoVal = String(p?.['@_protocol'] || 'tcp').toLowerCase();
        if (portVal) {
          parsedZone.ports.push({ port: portVal, protocol: protoVal });
        }
      }
    }

    if (z.protocol) {
      for (const pr of z.protocol) {
        const prVal = pr?.['@_value'];
        if (prVal) parsedZone.protocols.push(String(prVal));
      }
    }

    if (z.masquerade !== undefined) {
      parsedZone.masquerade = true;
    }

    if (z['forward-port']) {
      for (const fp of z['forward-port']) {
        if (!fp?.['@_port']) continue;
        parsedZone.forwardPorts.push({
          port: String(fp['@_port']).replace(':', '-'),
          protocol: String(fp['@_protocol'] || 'tcp').toLowerCase(),
          toPort: fp['@_to-port'] ? String(fp['@_to-port']).replace(':', '-') : undefined,
          toAddr: fp['@_to-addr'] ? String(fp['@_to-addr']) : undefined,
        });
      }
    }

    if (z['icmp-block']) {
      for (const ib of z['icmp-block']) {
        const ibName = ib?.['@_name'];
        if (ibName) parsedZone.icmpBlocks.push(String(ibName));
      }
    }

    if (z.rule) {
      for (const r of z.rule) {
        if (typeof r === 'string') {
          const parsedText = parseRichRuleText(r);
          if (Object.keys(parsedText).length > 0) {
            parsedZone.richRules.push(parsedText);
          }
          continue;
        }
        if (!r || typeof r !== 'object') continue;
        parsedZone.richRules.push(parseXmlRichRuleElement(r));
      }
    }

    zones.set(zoneName, parsedZone);
  }

  // 4. Parse Policies (<policy>)
  const rawPolicies = root.policy || [];
  for (const pol of Array.isArray(rawPolicies) ? rawPolicies : [rawPolicies]) {
    if (!pol || typeof pol !== 'object') continue;
    const polName = String(pol['@_name'] || pol.short || 'policy').toLowerCase();
    const ingress = pol['ingress-zone']?.[0]?.['@_name'] || 'internal';
    const targetZoneName = String(ingress).toLowerCase() === 'any' ? 'public' : String(ingress).toLowerCase();

    const z: ParsedZone = zones.get(targetZoneName) || {
      name: targetZoneName,
      target: String(pol['@_target'] || 'default'),
      description: String(pol.description || pol.short || `Policy ${polName}`),
      interfaces: [],
      sources: [],
      services: [],
      ports: [],
      protocols: [],
      masquerade: false,
      forwardPorts: [],
      richRules: [],
      icmpBlocks: [],
    };

    if (pol.service) {
      for (const s of pol.service) {
        if (s?.['@_name'] && !z.services.includes(String(s['@_name']))) {
          z.services.push(String(s['@_name']));
        }
      }
    }
    if (pol.port) {
      for (const p of pol.port) {
        if (p?.['@_port']) {
          z.ports.push({
            port: String(p['@_port']).replace(':', '-'),
            protocol: String(p['@_protocol'] || 'tcp').toLowerCase(),
          });
        }
      }
    }
    if (pol.masquerade !== undefined) {
      z.masquerade = true;
    }

    zones.set(targetZoneName, z);
  }
}

function parseFirewalldForwardPortSpec(spec: string): { port: string; protocol: string; toPort?: string; toAddr?: string } | null {
  const pPort = spec.match(/port=([0-9]+(?:-[0-9]+)?)/i)?.[1] || '';
  if (!pPort) return null;
  const pProto = spec.match(/proto=([a-z]+)/i)?.[1]?.toLowerCase() || 'tcp';
  const toPort = spec.match(/toport=([0-9]+(?:-[0-9]+)?)/i)?.[1];
  const toAddr = spec.match(/toaddr=([0-9a-fA-F.:]+)/i)?.[1];
  return { port: pPort, protocol: pProto, toPort, toAddr };
}

/**
 * Parses `firewall-cmd --list-all-zones` / `firewall-cmd --list-all` CLI output and `firewall-cmd` shell scripts
 */
function parseFirewalldText(
  content: string,
  zones: Map<string, ParsedZone>,
  aliases: Alias[],
) {
  const lines = content.split(/\r?\n/);
  let currentZone: ParsedZone | null = null;
  let inRichRules = false;
  let inForwardPorts = false;

  const ensureZone = (name: string): ParsedZone => {
    const clean = name.toLowerCase().trim() || 'public';
    let z = zones.get(clean);
    if (!z) {
      z = {
        name: clean,
        target: 'default',
        description: `Firewalld ${clean} zone`,
        interfaces: [],
        sources: [],
        services: [],
        ports: [],
        protocols: [],
        masquerade: false,
        forwardPorts: [],
        richRules: [],
        icmpBlocks: [],
      };
      zones.set(clean, z);
    }
    return z;
  };

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // 1. Check for `firewall-cmd` CLI invocations in shell scripts
    if (trimmed.startsWith('firewall-cmd ') || trimmed.startsWith('sudo firewall-cmd ')) {
      const zoneMatch = trimmed.match(/--zone(?:=|\s+)([a-zA-Z0-9_-]+)/);
      const z = ensureZone(zoneMatch ? zoneMatch[1] : 'public');

      for (const m of trimmed.matchAll(/--add-interface(?:=|\s+)([^\s'"]+)/g)) {
        if (!z.interfaces.includes(m[1])) z.interfaces.push(m[1]);
      }
      for (const m of trimmed.matchAll(/--add-source(?:=|\s+)([^\s'"]+)/g)) {
        if (!z.sources.includes(m[1])) z.sources.push(m[1]);
      }
      for (const m of trimmed.matchAll(/--add-service(?:=|\s+)([^\s'"]+)/g)) {
        if (!z.services.includes(m[1])) z.services.push(m[1]);
      }
      for (const m of trimmed.matchAll(/--add-port(?:=|\s+)([0-9:-]+)\/(tcp|udp)/gi)) {
        z.ports.push({ port: m[1].replace(':', '-'), protocol: m[2].toLowerCase() });
      }
      if (trimmed.includes('--add-masquerade')) {
        z.masquerade = true;
      }
      for (const m of trimmed.matchAll(/--add-forward-port(?:=|\s+)([^\s'"]+)/g)) {
        const parsedFp = parseFirewalldForwardPortSpec(m[1]!);
        if (parsedFp) {
          z.forwardPorts.push(parsedFp);
        }
      }
      const richCmdMatch = trimmed.match(/--add-rich-rule(?:=|\s+)(['"])(.*?)\1/);
      if (richCmdMatch?.[2]) {
        const parsedText = parseRichRuleText(richCmdMatch[2]);
        if (Object.keys(parsedText).length > 0) {
          z.richRules.push(parsedText);
        }
      }
      continue;
    }

    // 2. Check for `firewall-cmd --list-all-zones` zone header (non-indented line like `public (active)` or `internal`)
    if (!rawLine.startsWith(' ') && !rawLine.startsWith('\t') && !trimmed.includes(':')) {
      const headerZone = trimmed.split(/\s+/)[0];
      if (headerZone && /^[a-zA-Z0-9_-]+$/.test(headerZone)) {
        currentZone = ensureZone(headerZone);
        inRichRules = false;
        inForwardPorts = false;
        continue;
      }
    }

    if (!currentZone) {
      currentZone = ensureZone('public');
    }

    // Multi-line continuations for `rich rules:` or `forward-ports:`
    if (inRichRules && trimmed.startsWith('rule ')) {
      const parsedText = parseRichRuleText(trimmed);
      if (Object.keys(parsedText).length > 0) {
        currentZone.richRules.push(parsedText);
      }
      continue;
    }
    if (inForwardPorts && trimmed.startsWith('port=')) {
      const parsedFp = parseFirewalldForwardPortSpec(trimmed);
      if (parsedFp) {
        currentZone.forwardPorts.push(parsedFp);
      }
      continue;
    }

    // Key-value lines inside `firewall-cmd --list-all`
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx !== -1) {
      const key = trimmed.slice(0, colonIdx).trim().toLowerCase();
      const val = trimmed.slice(colonIdx + 1).trim();
      inRichRules = false;
      inForwardPorts = false;

      if (key === 'target' && val) {
        currentZone.target = val;
      } else if (key === 'interfaces' && val) {
        for (const iface of val.split(/\s+/)) {
          if (iface && !currentZone.interfaces.includes(iface)) {
            currentZone.interfaces.push(iface);
          }
        }
      } else if (key === 'sources' && val) {
        for (const src of val.split(/\s+/)) {
          if (!src) continue;
          if (src.startsWith('ipset:')) {
            const setName = sanitizeAliasName(src.slice('ipset:'.length));
            currentZone.sources.push(`$${setName}`);
            if (!aliases.some((a) => a.name === setName)) {
              aliases.push({
                name: setName,
                type: 'network',
                entries: ['192.0.2.0/24'],
                description: `Placeholder for firewalld ipset:${setName}`,
                enabled: true,
              });
            }
          } else {
            currentZone.sources.push(src);
          }
        }
      } else if (key === 'services' && val) {
        for (const svc of val.split(/\s+/)) {
          if (svc && !currentZone.services.includes(svc)) {
            currentZone.services.push(svc);
          }
        }
      } else if (key === 'ports' && val) {
        for (const token of val.split(/\s+/)) {
          const [pPort, pProto] = token.split('/');
          if (pPort && pProto) {
            currentZone.ports.push({
              port: pPort.replace(':', '-'),
              protocol: pProto.toLowerCase(),
            });
          }
        }
      } else if (key === 'protocols' && val) {
        for (const pr of val.split(/\s+/)) {
          if (pr) currentZone.protocols.push(pr);
        }
      } else if (key === 'masquerade') {
        if (val.toLowerCase() === 'yes' || val.toLowerCase() === 'true') {
          currentZone.masquerade = true;
        }
      } else if (key === 'forward-ports') {
        inForwardPorts = true;
        if (val) {
          for (const spec of val.split(/\s+/)) {
            const parsedFp = parseFirewalldForwardPortSpec(spec);
            if (parsedFp) {
              currentZone.forwardPorts.push(parsedFp);
            }
          }
        }
      } else if (key === 'icmp-blocks' && val) {
        for (const ib of val.split(/\s+/)) {
          if (ib) currentZone.icmpBlocks.push(ib);
        }
      } else if (key === 'rich rules') {
        inRichRules = true;
        if (val.startsWith('rule ')) {
          const parsedText = parseRichRuleText(val);
          if (Object.keys(parsedText).length > 0) {
            currentZone.richRules.push(parsedText);
          }
        }
      }
    }
  }
}

export function importFirewalldConfig(content: string): ImportReport {
  const warnings: string[] = [];
  const zones = new Map<string, ParsedZone>();
  const aliases: Alias[] = [];
  const customServices = new Map<string, FirewalldServiceDef>();

  const trimmed = content.trim();
  const isXml =
    trimmed.startsWith('<?xml') ||
    trimmed.includes('<zone') ||
    trimmed.includes('<policy') ||
    trimmed.includes('<ipset') ||
    trimmed.includes('<firewalld');

  if (isXml) {
    parseFirewalldXml(trimmed, zones, aliases, customServices, warnings);
  } else {
    parseFirewalldText(trimmed, zones, aliases);
  }

  const interfaces: Interface[] = [];
  const rules: FirewallRule[] = [];
  const nat: NatRule[] = [];
  const reviewItems: ImportReviewItem[] = [];
  const seenIfaces = new Set<string>();

  let sortOrder = 10;
  let natSort = 10;

  for (const [, zone] of zones) {
    const { ifaceName, devName } = mapZoneToAxonwallInterface(zone.name, zone.interfaces);

    if (!seenIfaces.has(ifaceName)) {
      seenIfaces.add(ifaceName);
      interfaces.push({
        name: ifaceName,
        device: devName,
        type: ifaceName === 'wan' ? 'dhcp' : 'static',
        ipv4Address: ifaceName === 'lan' ? '192.168.1.1/24' : undefined,
        enabled: true,
        description: `${zone.name.toUpperCase()} Zone (${devName})`,
        mtu: 1500,
      });
    }

    // If zone has multiple source bindings, create an alias for the zone sources if > 1
    let defaultSource = 'any';
    if (zone.sources.length === 1) {
      defaultSource = zone.sources[0];
    } else if (zone.sources.length > 1) {
      const aliasName = sanitizeAliasName(`zone_${zone.name}_sources`);
      aliases.push({
        name: aliasName,
        type: 'network',
        entries: zone.sources.filter((s) => !s.startsWith('$')),
        description: `Bound sources for firewalld zone "${zone.name}"`,
        enabled: true,
      });
      defaultSource = `$${aliasName}`;
    }

    // 1. Services -> FirewallRules
    for (const svcRaw of zone.services) {
      const svcName = svcRaw.toLowerCase().trim();
      const svcDef = customServices.get(svcName) || FIREWALLD_SERVICES[svcName];
      if (svcDef) {
        rules.push({
          action: 'pass',
          direction: 'in',
          interface: ifaceName,
          quick: true,
          protocol: svcDef.protocol,
          source: defaultSource,
          sourcePort: '',
          destination: 'any',
          destinationPort: svcDef.ports,
          log: false,
          enabled: true,
          description: `Allow ${svcName} (${svcDef.description}) [${zone.name}]`,
          sortOrder,
        });
        sortOrder += 10;
      } else {
        warnings.push(
          `Unrecognized firewalld service "${svcRaw}" in zone "${zone.name}" — please verify destination port.`,
        );
      }
    }

    // 2. Explicit Ports -> FirewallRules
    for (const p of zone.ports) {
      rules.push({
        action: 'pass',
        direction: 'in',
        interface: ifaceName,
        quick: true,
        protocol: normalizeProtocol(p.protocol),
        source: defaultSource,
        sourcePort: '',
        destination: 'any',
        destinationPort: p.port,
        log: false,
        enabled: true,
        description: `Allow ${p.protocol.toUpperCase()} port ${p.port} [${zone.name}]`,
        sortOrder,
      });
      sortOrder += 10;
    }

    // 3. Protocols -> FirewallRules
    for (const pr of zone.protocols) {
      rules.push({
        action: 'pass',
        direction: 'in',
        interface: ifaceName,
        quick: true,
        protocol: normalizeProtocol(pr),
        source: defaultSource,
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        log: false,
        enabled: true,
        description: `Allow protocol ${pr.toUpperCase()} [${zone.name}]`,
        sortOrder,
      });
      sortOrder += 10;
    }

    // 4. ICMP Blocks -> Block rules
    if (zone.icmpBlocks.length > 0) {
      rules.push({
        action: 'block',
        direction: 'in',
        interface: ifaceName,
        quick: true,
        protocol: 'icmp',
        source: defaultSource,
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        log: false,
        enabled: true,
        description: `ICMP Block (${zone.icmpBlocks.join(', ')}) [${zone.name}]`,
        sortOrder,
      });
      sortOrder += 10;
    }

    // 5. Masquerade -> NatRule
    if (zone.masquerade) {
      nat.push({
        type: 'masquerade',
        interface: ifaceName,
        protocol: 'any',
        source: defaultSource,
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        log: false,
        enabled: true,
        description: `Zone Masquerade [${zone.name}]`,
        sortOrder: natSort,
      });
      natSort += 10;
    }

    // 6. Forward Ports -> DNAT + Filter Pass rule
    for (const fp of zone.forwardPorts) {
      const targetIp = fp.toAddr || '127.0.0.1';
      const targetPort = fp.toPort || fp.port;
      nat.push({
        type: 'dnat',
        interface: ifaceName,
        protocol: normalizeProtocol(fp.protocol),
        source: defaultSource,
        sourcePort: '',
        destination: 'wan_ip',
        destinationPort: fp.port,
        targetIp,
        targetPort,
        log: false,
        enabled: true,
        description: `Forward ${fp.protocol.toUpperCase()}/${fp.port} -> ${targetIp}:${targetPort} [${zone.name}]`,
        sortOrder: natSort,
      });
      natSort += 10;

      if (fp.toAddr) {
        rules.push({
          action: 'pass',
          direction: 'in',
          interface: ifaceName,
          quick: true,
          protocol: normalizeProtocol(fp.protocol),
          source: defaultSource,
          sourcePort: '',
          destination: targetIp,
          destinationPort: targetPort,
          log: false,
          enabled: true,
          description: `Allow forwarded ${fp.protocol.toUpperCase()}/${targetPort} to ${targetIp} [${zone.name}]`,
          sortOrder,
        });
        sortOrder += 10;
      }
    }

    // 7. Rich Rules
    for (const rr of zone.richRules) {
      const parsedRr = parseRichRule(rr, ifaceName, sortOrder, natSort, customServices, warnings, rules.length);
      if (parsedRr.rule) {
        rules.push(parsedRr.rule);
        if (parsedRr.reviewItem) {
          reviewItems.push(parsedRr.reviewItem);
        }
        sortOrder += 10;
      }
      if (parsedRr.natRule) {
        nat.push(parsedRr.natRule);
        natSort += 10;
      }
    }

    // 8. Zone Target Policy (e.g. target="ACCEPT" or zone="trusted", or target="DROP"/"%%REJECT%%")
    const upperTarget = zone.target.toUpperCase();
    if (upperTarget === 'ACCEPT' || zone.name === 'trusted') {
      rules.push({
        action: 'pass',
        direction: 'in',
        interface: ifaceName,
        quick: true,
        protocol: 'any',
        source: defaultSource,
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        log: false,
        enabled: true,
        description: `Zone Default Policy ACCEPT [${zone.name}]`,
        sortOrder,
      });
      sortOrder += 10;
    } else if (upperTarget === 'DROP' || zone.name === 'drop') {
      rules.push({
        action: 'block',
        direction: 'in',
        interface: ifaceName,
        quick: true,
        protocol: 'any',
        source: defaultSource,
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        log: false,
        enabled: true,
        description: `Zone Default Policy DROP [${zone.name}]`,
        sortOrder,
      });
      sortOrder += 10;
    } else if (upperTarget.includes('REJECT') || zone.name === 'block') {
      rules.push({
        action: 'reject',
        direction: 'in',
        interface: ifaceName,
        quick: true,
        protocol: 'any',
        source: defaultSource,
        sourcePort: '',
        destination: 'any',
        destinationPort: '',
        log: false,
        enabled: true,
        description: `Zone Default Policy REJECT [${zone.name}]`,
        sortOrder,
      });
      sortOrder += 10;
    }
  }

  // Ensure standard WAN and LAN interfaces exist if not already populated
  if (!seenIfaces.has('wan')) {
    interfaces.unshift({
      name: 'wan',
      device: 'eth0',
      type: 'dhcp',
      enabled: true,
      description: 'WAN',
      mtu: 1500,
    });
  }
  if (!seenIfaces.has('lan')) {
    interfaces.push({
      name: 'lan',
      device: 'eth1',
      type: 'static',
      ipv4Address: '192.168.1.1/24',
      enabled: true,
      description: 'LAN',
      mtu: 1500,
    });
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
    aliases,
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
    vendor: 'firewalld',
    version: isXml ? 'firewalld XML v1.x' : 'firewall-cmd CLI',
    sourceFormat: isXml ? 'firewalld XML (/etc/firewalld/zones/*.xml)' : 'firewalld CLI (firewall-cmd)',
    interfacesCount: interfaces.length,
    vlansCount: 0,
    aliasesCount: aliases.length,
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
