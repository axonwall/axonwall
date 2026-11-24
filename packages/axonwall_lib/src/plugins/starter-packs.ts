export interface PluginStarterPack {
  id: string;
  name: string;
  tagline: string;
  description: string;
  pluginIds: string[];
}

export const PLUGIN_STARTER_PACKS: PluginStarterPack[] = [
  {
    id: 'enterprise-ngfw',
    name: 'Enterprise NGFW Pack',
    tagline: 'IDS/IPS, CrowdSec, BGP/OSPF, HA, OpenLDAP & Etckeeper',
    description:
      'Elevates the Lean Router Core into a full redundant enterprise perimeter NGFW with Suricata IDS/IPS, CrowdSec bouncer, FRRouting (BGP/OSPF), 2-node VRRP+conntrackd HA, OpenLDAP/SSSD identity directory, and Git /etc audit trails.',
    pluginIds: [
      'suricata-ids',
      'crowdsec-bouncer',
      'frr-routing',
      'high-availability',
      'directory-ldap',
      'etckeeper-audit',
    ],
  },
  {
    id: 'remote-access-vpn',
    name: 'Remote Access & PQ VPN Pack',
    tagline: 'OpenVPN DCO, strongSwan IPsec, Headscale Mesh & Rosenpass PQ',
    description:
      'Adds multi-protocol site-to-site and remote-access VPN engines alongside the built-in WireGuard core: OpenVPN 2.6 DCO, strongSwan IKEv2 IPsec, self-hosted Headscale coordination, and Post-Quantum Rosenpass PSK rotation.',
    pluginIds: ['openvpn', 'ipsec-strongswan', 'headscale', 'rosenpass'],
  },
  {
    id: 'operator-diagnostics',
    name: 'Operator Workstation & Diagnostics Pack',
    tagline: 'ZSH/Neovim Shell, Packet Capture/Tracer, Web PTY & Etckeeper',
    description:
      'Installs the interactive operator toolset: ZSH + Oh My Zsh + Neovim Super Configurator, tcpdump packet capture & packet tracer, browser Web Shell, and /etc Git revision tracking.',
    pluginIds: ['cli-workstation', 'packet-diagnostics', 'web-terminal', 'etckeeper-audit'],
  },
  {
    id: 'ai-observability',
    name: 'Sovereign AI & Observability Pack',
    tagline: 'AI Copilot, MCP Control, Coroot eBPF APM, NetFlow & Topology',
    description:
      'Enables the Sovereign AI control plane and deep kernel/flow visibility: multi-provider AI Network Copilot, MCP Security AI server, Coroot eBPF L7 APM, NetFlow/IPFIX/sFlow collector, and live Topology Studio.',
    pluginIds: [
      'ai-copilot',
      'mcp-ai-control',
      'coroot-ebpf-apm',
      'netflow-collector',
      'topology-studio',
    ],
  },
];

export function findStarterPackById(id: string): PluginStarterPack | undefined {
  return PLUGIN_STARTER_PACKS.find((pack) => pack.id === id);
}
