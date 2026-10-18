import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { DesiredStateSchema, type DesiredState } from '../schemas/index.js';

export type AxonwallYamlDomainFile =
  | 'system.yaml'
  | 'interfaces.yaml'
  | 'firewall.yaml'
  | 'routing.yaml'
  | 'services.yaml'
  | 'vpn.yaml'
  | 'security.yaml'
  | 'ha.yaml'
  | 'storage.yaml'
  | 'k3s.yaml'
  | 'virt.yaml'
  | 'vigilante.yaml';

export interface DomainYamlDefinition {
  filename: AxonwallYamlDomainFile;
  title: string;
  description: string;
  keys: Array<keyof DesiredState>;
}

export const AXONWALL_YAML_DOMAINS: DomainYamlDefinition[] = [
  {
    filename: 'system.yaml',
    title: 'Axonwall System & Appliance Configuration',
    description:
      'Controls appliance hostname, DNS, management ports, hardware capabilities, plugins, AI copilot, observability, SNMP, NUT UPS, and ACME certificates.',
    keys: ['version', 'capabilities', 'system', 'plugins', 'ai', 'observability', 'snmp', 'ups', 'acme'],
  },
  {
    filename: 'interfaces.yaml',
    title: 'Axonwall Network Interfaces & L2/L3 Topology',
    description:
      'Controls physical/logical interface assignments, 802.1Q VLANs, L2 bridges, LACP/bonding groups, CARP/VRRP Virtual IPs, and VRF routing tables.',
    keys: ['interfaces', 'vlans', 'bridges', 'bonds', 'virtualIps', 'vrfs'],
  },
  {
    filename: 'firewall.yaml',
    title: 'Axonwall Stateful Firewall, NAT & Traffic Shaper',
    description:
      'Controls firewall aliases (IP/Port/GeoIP/URL tables), stateful nftables filter rules, SNAT/DNAT/Masquerade/NPTv6 rules, and CAKE/FQ-CoDel QoS queues.',
    keys: ['aliases', 'rules', 'nat', 'trafficShaper'],
  },
  {
    filename: 'routing.yaml',
    title: 'Axonwall Gateways, SD-WAN & Dynamic Routing (FRR)',
    description:
      'Controls upstream gateways, Multi-WAN failover/load-balance groups, static routes, and FRRouting (BGP, OSPF, BFD).',
    keys: ['gateways', 'gatewayGroups', 'routes', 'frr'],
  },
  {
    filename: 'services.yaml',
    title: 'Axonwall Core Network Services (DHCP, DNS, Captive Portal, HAProxy, RADIUS)',
    description:
      'Controls DHCPv4/v6 pools & static reservations, Unbound DNS resolver & DNSBL blocklists, Captive Portal zones, HAProxy load balancer, and FreeRADIUS.',
    keys: ['dhcp', 'dns', 'captivePortal', 'haproxy', 'freeradius'],
  },
  {
    filename: 'vpn.yaml',
    title: 'Axonwall Virtual Private Networks (WireGuard, IPsec, OpenVPN, Mesh)',
    description:
      'Controls WireGuard kernel tunnels & peers, route/policy-based IPsec (strongSwan IKEv2), OpenVPN DCO servers, and Headscale Zero-Config Mesh VPN.',
    keys: ['wireguard', 'ipsec', 'openvpn', 'headscale'],
  },
  {
    filename: 'security.yaml',
    title: 'Axonwall Threat Defense & Zero-Trust Security',
    description:
      'Controls Suricata IDS/IPS, CrowdSec Threat Intelligence, GeoIP filtering, Zero-Trust Identity-Aware Proxy (IAP), Enterprise SSO (OIDC/SAML/LDAP), and TLS Decryption.',
    keys: ['suricata', 'crowdsec', 'geoip', 'zeroTrust', 'sso', 'tlsDecryption'],
  },
  {
    filename: 'ha.yaml',
    title: 'Axonwall High Availability & Fleet Management',
    description:
      'Controls active/passive HA state synchronization (VRRP + conntrackd + XML-RPC/gRPC config sync) and multi-site Satellite Fleet management.',
    keys: ['ha', 'fleet'],
  },
  {
    filename: 'storage.yaml',
    title: 'Axonwall Enterprise ZFS NAS & SAN Storage',
    description:
      'Controls ZFS storage pools (Mirror/RAIDZ/dRAID), datasets, ZVOLs, automated snapshots, SMB/CIFS shares, NFS exports, iSCSI targets, and MinIO S3 object storage.',
    keys: ['nas'],
  },
  {
    filename: 'k3s.yaml',
    title: 'Axonwall Embedded K3s Kubernetes & OpenEBS CSI Storage',
    description:
      'Controls the embedded K3s Kubernetes cluster, WireGuard flannel CNI, OpenEBS ZFS-LocalPV & Replicated StorageClasses, and container workloads.',
    keys: ['k3s'],
  },
  {
    filename: 'virt.yaml',
    title: 'Axonwall Hypervisor, Virtual Machines (KVM/QEMU) & LXC Containers',
    description:
      'Controls KVM virtual machines, Cloud-Init, LXC system containers, ISO images, PCIe VFIO / SR-IOV passthrough, VXLAN SDN zones, and deduplicated backup schedules.',
    keys: ['virt'],
  },
  {
    filename: 'vigilante.yaml',
    title: 'Vigilante Cyber Defense, SOAR, Deception, Forensics & Modular SOC',
    description:
      'Controls autonomous cyber defense operations, SOAR active containment, honeynet deception mesh, embedded security data lake, PCAP forensics, and 12 modular security packages.',
    keys: ['vigilante'],
  },
];

export const AXONWALL_YAML_FILENAMES: AxonwallYamlDomainFile[] = AXONWALL_YAML_DOMAINS.map(
  (d) => d.filename
);

function buildHeaderComment(domain: DomainYamlDefinition): string {
  return [
    `# =============================================================================`,
    `# ${domain.title}`,
    `# File: /etc/axonwall/${domain.filename}`,
    `# =============================================================================`,
    `# ${domain.description}`,
    `#`,
    `# CLI Workflow:`,
    `#   1. Edit this file by hand (e.g., vim /etc/axonwall/${domain.filename})`,
    `#   2. Validate syntax & schema:  axonwallctl validate`,
    `#   3. View pending changes:      axonwallctl diff`,
    `#   4. Apply to live system:      axonwallctl apply`,
    `#`,
    `# Bidirectional Sync: Any edits saved here automatically appear in the Web GUI,`,
    `# and any changes saved in the Web GUI are written back to /etc/axonwall/*.yaml.`,
    `# =============================================================================`,
    ``,
  ].join('\n');
}

/**
 * Serializes a validated DesiredState into the 10 modular /etc/axonwall/*.yaml files.
 */
export function serializeDesiredStateToYamlFiles(
  inputState: DesiredState
): Record<AxonwallYamlDomainFile, string> {
  const state = DesiredStateSchema.parse(inputState);
  const result = {} as Record<AxonwallYamlDomainFile, string>;

  for (const domain of AXONWALL_YAML_DOMAINS) {
    const partialObj: Record<string, unknown> = {};
    for (const key of domain.keys) {
      const value = state[key];
      if (value !== undefined) {
        partialObj[key] = value;
      }
    }
    const yamlBody = stringifyYaml(partialObj, {
      indent: 2,
      lineWidth: 120,
      nullStr: '~',
    });
    result[domain.filename] = `${buildHeaderComment(domain)}${yamlBody}`;
  }

  return result;
}

/**
 * Serializes the entire DesiredState into a single combined YAML string (e.g. for full backup export).
 */
export function serializeDesiredStateToSingleYaml(inputState: DesiredState): string {
  const state = DesiredStateSchema.parse(inputState);
  const header = [
    `# =============================================================================`,
    `# Axonwall Unified Configuration Export (axonwall.yaml)`,
    `# =============================================================================`,
    `# Complete desired state across all Axonwall subsystems.`,
    `# Can be imported via Web GUI (System -> Backup) or split into /etc/axonwall/*.yaml.`,
    `# =============================================================================`,
    ``,
  ].join('\n');
  const body = stringifyYaml(state, {
    indent: 2,
    lineWidth: 120,
  });
  return `${header}${body}`;
}

export interface YamlValidationIssue {
  file: string;
  path: string;
  message: string;
}

export interface YamlValidationResult {
  valid: boolean;
  state?: DesiredState;
  errors: YamlValidationIssue[];
}

/**
 * Parses and merges a map of YAML filename -> YAML content into a validated DesiredState.
 * Supports both the 10 modular domain files and optional conf.d/*.yaml or axonwall.yaml overrides.
 */
export function validateYamlConfigFiles(files: Record<string, string>): YamlValidationResult {
  const mergedRaw: Record<string, unknown> = {};
  const errors: YamlValidationIssue[] = [];
  const keyToSourceFile = new Map<string, string>();

  // Sort filenames so standard domain files are processed first, followed by conf.d/* or axonwall.yaml overrides
  const sortedEntries = Object.entries(files).sort(([a], [b]) => {
    const aIdx = AXONWALL_YAML_FILENAMES.indexOf(a as AxonwallYamlDomainFile);
    const bIdx = AXONWALL_YAML_FILENAMES.indexOf(b as AxonwallYamlDomainFile);
    if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
    if (aIdx !== -1) return -1;
    if (bIdx !== -1) return 1;
    return a.localeCompare(b);
  });

  for (const [filename, content] of sortedEntries) {
    if (!content || !content.trim()) continue;
    try {
      const parsed = parseYaml(content);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
          if (v !== undefined) {
            mergedRaw[k] = v;
            keyToSourceFile.set(k, filename);
          }
        }
      }
    } catch (err: any) {
      errors.push({
        file: filename,
        path: 'syntax',
        message: err?.message || 'Invalid YAML syntax',
      });
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  const parsedResult = DesiredStateSchema.safeParse(mergedRaw);
  if (!parsedResult.success) {
    for (const issue of parsedResult.error.issues) {
      const topKey = String(issue.path[0] || '');
      const sourceFile =
        keyToSourceFile.get(topKey) ||
        AXONWALL_YAML_DOMAINS.find((d) => d.keys.includes(topKey as keyof DesiredState))?.filename ||
        'axonwall.yaml';
      errors.push({
        file: sourceFile,
        path: issue.path.join('.'),
        message: issue.message,
      });
    }
    return { valid: false, errors };
  }

  return {
    valid: true,
    state: parsedResult.data,
    errors: [],
  };
}

/**
 * Parses and merges a map of YAML filename -> YAML content into a validated DesiredState,
 * throwing a detailed Error if validation fails.
 */
export function parseDesiredStateFromYamlFiles(files: Record<string, string>): DesiredState {
  const res = validateYamlConfigFiles(files);
  if (!res.valid || !res.state) {
    const summary = res.errors
      .map((e) => `[${e.file}${e.path ? ` -> ${e.path}` : ''}] ${e.message}`)
      .join('; ');
    throw new Error(`Invalid Axonwall YAML configuration: ${summary}`);
  }
  return res.state;
}
