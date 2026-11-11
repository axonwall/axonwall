'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  BookOpen,
  Cpu,
  Layers,
  Shield,
  ShieldAlert,
  ArrowRightLeft,
  FileCode,
  Activity,
  Terminal,
  GitBranch,
  Code2,
  Search,
  X,
  Palette,
  Database,
  HardDrive,
  KeyRound,
  Bug,
  Boxes,
  Crosshair,
  Users,
  Sparkles,
} from 'lucide-react';

export interface DocItem {
  title: string;
  href: string;
  badge?: string;
}

export interface DocCategory {
  title: string;
  icon: any;
  items: DocItem[];
}

export const DOCS_NAVIGATION: DocCategory[] = [
  {
    title: 'Getting Started',
    icon: BookOpen,
    items: [
      { title: 'Overview & Introduction', href: '/docs' },
      { title: 'Installation Guide (ISO, UKI, Cloud)', href: '/docs#installation' },
      { title: 'Multi-Disk RAID & ZFSBootMenu', href: '/docs/installer-raid-zfs', badge: 'ZBM' },
      { title: 'Quickstart & First Boot', href: '/docs#quickstart' },
      { title: 'Hardware Compatibility List', href: '/docs#hardware' },
    ],
  },
  {
    title: 'Architecture & Engine',
    icon: Cpu,
    items: [
      { title: 'Linux nftables Architecture', href: '/docs/architecture' },
      { title: 'Super-Slim Edge NGFW (UEFI UKI)', href: '/docs/edge-uki-ngfw', badge: 'PID-1' },
      { title: 'Modular Core Roles (5 Roles)', href: '/docs/modular-architecture', badge: 'Core' },
      { title: 'Multi-Core vs FreeBSD pf', href: '/docs/architecture#comparison' },
      { title: 'Junos Commit-Confirm Rollback', href: '/docs/architecture#commit-confirm' },
      { title: 'A/B Dual-Root & ZFSBootMenu Modes', href: '/docs/architecture#ab-dual-root' },
      { title: 'Privileged Go Daemon (axonwalld)', href: '/docs/architecture#daemon' },
    ],
  },
  {
    title: 'High Availability (HA)',
    icon: ArrowRightLeft,
    items: [
      { title: 'Cluster Overview & 6-Plane Sync', href: '/docs/high-availability' },
      { title: '2-Host Setup Walkthrough', href: '/docs/high-availability#two-host-setup', badge: 'Guide' },
      { title: 'HA PKI & mTLS Security', href: '/docs/high-availability#pki-mtls' },
      { title: 'Keepalived VRRP v2/v3', href: '/docs/high-availability#keepalived' },
      { title: 'conntrackd Stateful Sync', href: '/docs/high-availability#conntrackd' },
      { title: 'ZFS, OpenLDAP, SQLite & K3s Sync', href: '/docs/high-availability#zfs-k3s-sync', badge: 'HA' },
      { title: 'Zero-Drop TCP & VoIP Failover', href: '/docs/high-availability#failover' },
    ],
  },
  {
    title: 'Ring-0 & Host Defense',
    icon: Bug,
    items: [
      { title: 'Ghost-in-the-Ring & rkhunter', href: '/docs/ghost-in-the-ring-rootkits', badge: 'Ring-0' },
      { title: 'Host Malware & Integrity Suite', href: '/docs/ghost-in-the-ring-rootkits#host-scanners' },
      { title: 'io_uring Syscall-Less Implants', href: '/docs/ghost-in-the-ring-rootkits#io-uring' },
      { title: 'eBPF Rootkits & /proc/kcore Audit', href: '/docs/ghost-in-the-ring-rootkits#ebpf-pmu' },
      { title: 'CO-RE BPF-LSM & CVE-2026-31431', href: '/docs/ghost-in-the-ring-rootkits#lsm-bpf', badge: 'LSM' },
    ],
  },
  {
    title: 'Post-Quantum & VPN',
    icon: KeyRound,
    items: [
      { title: 'Rosenpass Dual-KEM VPN', href: '/docs/post-quantum-rosenpass', badge: 'PQ-KEM' },
      { title: 'McEliece 460896 + ML-KEM-512', href: '/docs/post-quantum-rosenpass#architecture' },
      { title: 'Peer & PSK Rotation (vpn.yaml)', href: '/docs/post-quantum-rosenpass#configuration' },
    ],
  },
  {
    title: 'Identity, OpenLDAP & SSO',
    icon: Users,
    items: [
      { title: 'Unified Identity Overview', href: '/docs/identity-openldap-sso', badge: 'LDAP' },
      { title: 'Embedded OpenLDAP & SSSD', href: '/docs/identity-openldap-sso#openldap-sssd' },
      { title: 'RBAC Roles & axonwall-opshell', href: '/docs/identity-openldap-sso#roles-opshell' },
      { title: 'Zero-Touch Plugin Federation', href: '/docs/identity-openldap-sso#plugin-federation' },
      { title: 'Multi-Provider LDAPS HA Sync', href: '/docs/identity-openldap-sso#ha-syncrepl' },
      { title: 'Enterprise OIDC SSO & IAP', href: '/docs/identity-openldap-sso#enterprise-sso' },
    ],
  },
  {
    title: 'ZFS NAS & Vault Storage',
    icon: Database,
    items: [
      { title: 'ZFS Storage & Vault Overview', href: '/docs/zfs-nas-storage' },
      { title: 'ZFS Pools, Special VDEV & TRIM', href: '/docs/zfs-nas-storage#pools' },
      { title: 'Datasets, AES-256 & Zvols', href: '/docs/zfs-nas-storage#datasets', badge: 'AES' },
      { title: 'SMB3, Time Machine & WSDD2', href: '/docs/zfs-nas-storage#smb' },
      { title: 'NFSv4 Exports & iSCSI Targets', href: '/docs/zfs-nas-storage#nfs-iscsi' },
      { title: 'Snapshots, Rollback & Cloud Sync', href: '/docs/zfs-nas-storage#snapshots' },
      { title: 'ARC/L2ARC/ZIL Kstats & MCP', href: '/docs/zfs-nas-storage#arc-zil-telemetry', badge: 'Kstat' },
    ],
  },
  {
    title: 'Kubernetes (K3s) & VOW',
    icon: Layers,
    items: [
      { title: 'K3s & OpenEBS Overview', href: '/docs/k3s-kubernetes' },
      { title: 'Cilium eBPF CNI & Etcd Snapshots', href: '/docs/k3s-kubernetes#cilium-etcd', badge: 'eBPF' },
      { title: 'Vigilant Octo Waffle GitOps PaaS', href: '/docs/vigilant-octo-waffle', badge: 'GitOps' },
      { title: 'WireGuard Flannel Mesh', href: '/docs/k3s-kubernetes#wireguard' },
      { title: 'Automated 2-Node HA Join', href: '/docs/k3s-kubernetes#ha-join', badge: 'HA' },
      { title: 'Kubeconfig Sync (axonwall-kubeconfig)', href: '/docs/k3s-kubernetes#kubeconfig', badge: 'CLI' },
      { title: 'UserNS & BPF_TOKEN Pods (6.9+)', href: '/docs/k3s-kubernetes#userns-bpf-tokens', badge: 'BPF' },
      { title: 'OpenEBS ZFS-LocalPV CSI', href: '/docs/k3s-kubernetes#zfs-localpv' },
      { title: 'OpenEBS Mayastor NVMe-oF HA', href: '/docs/k3s-kubernetes#mayastor' },
    ],
  },
  {
    title: 'KVM & LXC Hypervisor',
    icon: Boxes,
    items: [
      { title: 'Hypervisor Overview (core-virt)', href: '/docs/kvm-lxc-hypervisor', badge: 'KVM' },
      { title: 'KVM/QEMU VMs, TPM2 & noVNC', href: '/docs/kvm-lxc-hypervisor#kvm-vms' },
      { title: 'VirtioFS, Clones, Migrate & XML', href: '/docs/kvm-lxc-hypervisor#clones-migration-xml', badge: 'Libvirt' },
      { title: 'LXC System Containers', href: '/docs/kvm-lxc-hypervisor#lxc-containers' },
      { title: 'Unprivileged LXC BPF_TOKEN', href: '/docs/kvm-lxc-hypervisor#lxc-bpf-token', badge: '6.9+' },
      { title: 'PCIe VFIO, SR-IOV & VXLAN SDN', href: '/docs/kvm-lxc-hypervisor#vfio-sriov' },
      { title: 'Hosted Virtual Edge NGFW UKI', href: '/docs/kvm-lxc-hypervisor#hosted-edge' },
      { title: 'Cloud-Init Export & ZFS Backups', href: '/docs/kvm-lxc-hypervisor#cloud-init-backups' },
    ],
  },
  {
    title: 'Vigilante Autonomous SOC',
    icon: Crosshair,
    items: [
      { title: 'Vigilante Cyber Ops (core-vigilante)', href: '/docs/vigilante-cyber-ops', badge: 'SOC' },
      { title: 'BattleStation & 12 K3s Modules', href: '/docs/vigilante-cyber-ops#battlestation' },
      { title: 'Kernel SOAR & Ransomware Freeze', href: '/docs/vigilante-cyber-ops#soar-containment' },
      { title: 'Deception Mesh & Honeytokens', href: '/docs/vigilante-cyber-ops#deception-mesh' },
      { title: 'Merkle ZFS Evidence Vault & Lake', href: '/docs/vigilante-cyber-ops#evidence-vault' },
      { title: 'Threat Federation & 106-Tool MCP', href: '/docs/vigilante-cyber-ops#federation-mcp' },
    ],
  },
  {
    title: 'Sovereign AI, MCP & CLI',
    icon: Sparkles,
    items: [
      { title: 'MCP Security AI Control & Leases', href: '/docs/mcp-ai-control', badge: 'MCP' },
      { title: 'Kill Switch, Scopes & Blast Radius', href: '/docs/mcp-ai-control#blast-radius' },
      { title: 'Tactical Leases & Hash Audit Chain', href: '/docs/mcp-ai-control#tactical-leases' },
      { title: 'Eluvix Sovereign AI Router & DLP', href: '/docs/eluvix-ai-router', badge: 'DLP' },
      { title: 'Neovim Super Configurator & TUI', href: '/docs/cli-super-configurator', badge: 'TUI' },
      { title: 'NastyMap Topology Simulator', href: '/docs/cli-super-configurator#nastymap-tui' },
      { title: 'ZSH Power-User Workstation', href: '/docs/cli-super-configurator#zsh-workstation' },
    ],
  },
  {
    title: 'Threat Defense & DNS',
    icon: ShieldAlert,
    items: [
      { title: 'Threat Defense Suite', href: '/docs/threat-defense' },
      { title: 'Dynamic Threat Feeds', href: '/docs/threat-defense#threat-feeds' },
      { title: 'CIDR Minimization & Sets', href: '/docs/threat-defense#cidr-optimization' },
      { title: 'DNS Sinkhole (Unbound RPZ)', href: '/docs/threat-defense#dns-sinkhole' },
      { title: 'Subdomain Pruning & Overrides', href: '/docs/threat-defense#subdomain-pruning' },
      { title: 'Suricata 7+, XDP & CrowdSec', href: '/docs/threat-defense#suricata-crowdsec' },
    ],
  },
  {
    title: 'Migration Studio',
    icon: FileCode,
    items: [
      { title: '9-Vendor Appliance Importer', href: '/docs/migration', badge: '9x' },
      { title: 'Proxmox VE & TrueNAS SCALE', href: '/docs/migration#proxmox-truenas', badge: 'New' },
      { title: 'pfSense & OPNsense XML', href: '/docs/migration#pfsense-opnsense' },
      { title: 'Cisco, VyOS, MikroTik & Linux', href: '/docs/migration#cisco-asa' },
      { title: 'Rule Shadowing & Dead Rules', href: '/docs/migration#shadowing-algorithm' },
      { title: 'Subnet Collision Detection', href: '/docs/migration#subnet-collisions' },
      { title: 'Cherry-Pick Selective Merge', href: '/docs/migration#selective-merge' },
    ],
  },
  {
    title: 'Live Observability',
    icon: Activity,
    items: [
      { title: 'Observability & Tracing', href: '/docs/observability', badge: 'eBPF' },
      { title: 'Metrics, Logs & Traces', href: '/docs/observability#metrics-logs-traces' },
      { title: 'Container Network & FS I/O', href: '/docs/observability#container-tracking' },
      { title: 'K3s Cluster Troubleshooting', href: '/docs/observability#kubernetes-troubleshooting' },
      { title: 'Coroot eBPF APM & RCA', href: '/docs/observability#coroot-apm', badge: 'APM' },
      { title: 'Linux 6.9+ BPF_TOKEN & Dual XDP', href: '/docs/observability#bpf-token-delegation', badge: '6.9+' },
      { title: 'eBPF & NFLOG Kernel Tap', href: '/docs/observability#kernel-tap' },
      { title: 'Real-Time Protocol Dissectors', href: '/docs/observability#dissectors' },
      { title: 'SSE Packet Stream Endpoint', href: '/docs/observability#sse-streaming' },
      { title: 'VictoriaMetrics & ClickHouse Flows', href: '/docs/observability#victoriametrics' },
    ],
  },
  {
    title: 'Appliance & Telemetry',
    icon: HardDrive,
    items: [
      { title: 'Hardware Monitoring Overview', href: '/docs/hardware-telemetry' },
      { title: 'HWMON Sensors (Temp/Fan/Volt)', href: '/docs/hardware-telemetry#hwmon' },
      { title: 'SFP+/QSFP Optical DOM (ethtool)', href: '/docs/hardware-telemetry#optical-dom' },
      { title: 'Diagnostic Shell & Serial Console', href: '/docs/hardware-telemetry#web-terminal' },
    ],
  },
  {
    title: 'GitOps & /etc Audit',
    icon: GitBranch,
    items: [
      { title: 'GitOps Architecture', href: '/docs/gitops-audit' },
      { title: 'Automated Git Versioning', href: '/docs/gitops-audit#versioning' },
      { title: 'Etckeeper (/etc Git Audit & Diffs)', href: '/docs/gitops-audit#etckeeper', badge: 'Git' },
      { title: 'Unified Diff Inspection', href: '/docs/gitops-audit#diff-inspection' },
      { title: '1-Click Rollback Lifecycle', href: '/docs/gitops-audit#rollback' },
    ],
  },
  {
    title: 'API & Terraform',
    icon: Code2,
    items: [
      { title: 'REST, SSE & IPC Reference', href: '/docs/api-reference' },
      { title: 'Live Packet Stream (/events/packets)', href: '/docs/api-reference#packets' },
      { title: 'Fleet ZTP & MCP Endpoints', href: '/docs/api-reference#fleet-mcp' },
      { title: 'Privileged Agent Socket IPC', href: '/docs/api-reference#agent-socket' },
      { title: 'Terraform / OpenTofu Provider', href: '/docs/api-reference#terraform', badge: 'IaC' },
    ],
  },
  {
    title: 'Theming & Ecosystem',
    icon: Palette,
    items: [
      { title: 'Theme Architecture & Engine', href: '/docs/themes' },
      { title: 'Creating Custom Themes', href: '/docs/themes#creating-themes' },
      { title: 'Building a Theme Repository', href: '/docs/themes#theme-repositories' },
      { title: 'Importing via Repo URL / File', href: '/docs/themes#importing' },
      { title: 'Winnegans Compatibility', href: '/docs/themes#winnegans-compatibility' },
    ],
  },
];

interface DocsSidebarProps {
  onClose?: () => void;
}

export function DocsSidebar({ onClose }: DocsSidebarProps) {
  const pathname = usePathname();
  const [search, setSearch] = useState('');

  const filteredNavigation = useMemo(() => {
    if (!search.trim()) return DOCS_NAVIGATION;
    const q = search.toLowerCase();

    return DOCS_NAVIGATION.map((cat) => {
      const matchingItems = cat.items.filter((item) =>
        item.title.toLowerCase().includes(q)
      );
      if (matchingItems.length > 0 || cat.title.toLowerCase().includes(q)) {
        return {
          ...cat,
          items: matchingItems.length > 0 ? matchingItems : cat.items,
        };
      }
      return null;
    }).filter(Boolean) as DocCategory[];
  }, [search]);

  return (
    <aside className="w-full h-full flex flex-col bg-[#080c14] border-r border-slate-800/80">
      {/* Search Header */}
      <div className="p-4 border-b border-slate-800/80">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search documentation..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-8 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Nav Link Tree */}
      <nav className="flex-1 overflow-y-auto p-4 space-y-6 text-xs">
        {filteredNavigation.map((cat) => {
          const Icon = cat.icon;
          return (
            <div key={cat.title} className="space-y-1.5">
              <div className="flex items-center gap-2 px-2 py-1 text-slate-400 font-semibold tracking-wider uppercase text-[11px]">
                <Icon className="w-3.5 h-3.5 text-emerald-400" />
                <span>{cat.title}</span>
              </div>
              <ul className="space-y-0.5 ml-2 border-l border-slate-800/60 pl-2">
                {cat.items.map((item) => {
                  const isActive = pathname === item.href.split('#')[0];
                  return (
                    <li key={item.title}>
                      <Link
                        href={item.href}
                        onClick={onClose}
                        className={`flex items-center justify-between px-2.5 py-1.5 rounded-md transition ${
                          isActive
                            ? 'bg-emerald-500/10 text-emerald-400 font-semibold border-l-2 border-emerald-400 rounded-l-none'
                            : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                        }`}
                      >
                        <span className="truncate">{item.title}</span>
                        {item.badge && (
                          <span className="text-[9px] px-1 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono">
                            {item.badge}
                          </span>
                        )}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </nav>

      {/* Footer Status */}
      <div className="p-3 border-t border-slate-800/80 text-[11px] text-slate-500 flex items-center justify-between">
        <span className="font-mono">Axonwall v0.11.64</span>
        <span className="text-emerald-400 font-medium">24 Guides</span>
      </div>
    </aside>
  );
}
