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
  ChevronRight,
  Palette,
  Database,
  HardDrive,
  KeyRound,
  Bug,
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
      { title: 'Installation Guide (ISO, KVM, Docker)', href: '/docs#installation' },
      { title: 'Multi-Disk RAID & ZFS Install', href: '/docs/installer-raid-zfs', badge: 'RAID' },
      { title: 'Quickstart & First Boot', href: '/docs#quickstart' },
      { title: 'Hardware Compatibility List', href: '/docs#hardware' },
    ],
  },
  {
    title: 'Architecture & Engine',
    icon: Cpu,
    items: [
      { title: 'Linux nftables Architecture', href: '/docs/architecture' },
      { title: 'Modular Roles (FW, ZFS, K3s)', href: '/docs/modular-architecture', badge: 'Core' },
      { title: 'Multi-Core vs FreeBSD pf', href: '/docs/architecture#comparison' },
      { title: 'Junos Commit-Confirm Rollback', href: '/docs/architecture#commit-confirm' },
      { title: 'A/B Dual-Root & Single-Root Modes', href: '/docs/architecture#ab-dual-root' },
      { title: 'Privileged Go Daemon (axonwalld)', href: '/docs/architecture#daemon' },
    ],
  },
  {
    title: 'High Availability (HA)',
    icon: ArrowRightLeft,
    items: [
      { title: 'Cluster Overview & Full Sync', href: '/docs/high-availability' },
      { title: '2-Host Setup Walkthrough', href: '/docs/high-availability#two-host-setup', badge: 'Guide' },
      { title: 'HA PKI & mTLS Security', href: '/docs/high-availability#pki-mtls' },
      { title: 'Keepalived VRRP v2/v3', href: '/docs/high-availability#keepalived' },
      { title: 'conntrackd Stateful Sync', href: '/docs/high-availability#conntrackd' },
      { title: 'ZFS, SQLite, NTP & K3s Sync', href: '/docs/high-availability#zfs-k3s-sync', badge: 'HA' },
      { title: 'Zero-Drop TCP & VoIP Failover', href: '/docs/high-availability#failover' },
    ],
  },
  {
    title: 'Ring-0 & Host Defense',
    icon: Bug,
    items: [
      { title: 'Ghost-in-the-Ring & rkhunter', href: '/docs/ghost-in-the-ring-rootkits', badge: 'Ring-0' },
      { title: '6-Engine Malware Suite', href: '/docs/ghost-in-the-ring-rootkits#host-scanners' },
      { title: 'io_uring Syscall-Less Implants', href: '/docs/ghost-in-the-ring-rootkits#io-uring' },
      { title: 'eBPF Rootkits & Silicon PMU LBR', href: '/docs/ghost-in-the-ring-rootkits#ebpf-pmu' },
      { title: 'Preventive BPF_LSM Lockdown', href: '/docs/ghost-in-the-ring-rootkits#lsm-bpf' },
    ],
  },
  {
    title: 'Post-Quantum & VPN',
    icon: KeyRound,
    items: [
      { title: 'Rosenpass Dual-KEM VPN', href: '/docs/post-quantum-rosenpass', badge: 'PQ-KEM' },
      { title: 'McEliece 460896 + Kyber-768', href: '/docs/post-quantum-rosenpass#architecture' },
      { title: 'Peer & PSK Rotation Setup', href: '/docs/post-quantum-rosenpass#configuration' },
    ],
  },
  {
    title: 'ZFS NAS Storage',
    icon: Database,
    items: [
      { title: 'ZFS Storage Management', href: '/docs/zfs-nas-storage' },
      { title: 'ZFS Pools & RAID Topologies', href: '/docs/zfs-nas-storage#pools' },
      { title: 'Datasets, Quotas & Zvols', href: '/docs/zfs-nas-storage#datasets' },
      { title: 'Samba SMB3 & VSS Shadow Copies', href: '/docs/zfs-nas-storage#smb' },
      { title: 'NFSv4 Exports & iSCSI Targets', href: '/docs/zfs-nas-storage#nfs-iscsi' },
      { title: 'Snapshot Retention & HA Send/Recv', href: '/docs/zfs-nas-storage#snapshots' },
    ],
  },
  {
    title: 'Kubernetes (K3s) & VOW',
    icon: Layers,
    items: [
      { title: 'K3s & OpenEBS Overview', href: '/docs/k3s-kubernetes' },
      { title: 'Vigilant Octo Waffle & SOC', href: '/docs/vigilant-octo-waffle', badge: 'New' },
      { title: 'WireGuard Flannel Mesh', href: '/docs/k3s-kubernetes#wireguard' },
      { title: 'Automated 2-Node HA Join', href: '/docs/k3s-kubernetes#ha-join', badge: 'HA' },
      { title: 'OpenEBS ZFS-LocalPV CSI', href: '/docs/k3s-kubernetes#zfs-localpv' },
      { title: 'OpenEBS Mayastor NVMe-oF HA', href: '/docs/k3s-kubernetes#mayastor' },
    ],
  },
  {
    title: 'CLI & Super Configurator',
    icon: Terminal,
    items: [
      { title: 'Neovim Super Configurator', href: '/docs/cli-super-configurator', badge: 'TUI' },
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
      { title: 'Suricata 7+ & CrowdSec', href: '/docs/threat-defense#suricata-crowdsec' },
    ],
  },
  {
    title: 'Migration Studio',
    icon: FileCode,
    items: [
      { title: 'Multi-Vendor Importer', href: '/docs/migration' },
      { title: 'pfSense & OPNsense XML', href: '/docs/migration#pfsense-opnsense' },
      { title: 'Cisco ASA / FTD CLI Parser', href: '/docs/migration#cisco-asa' },
      { title: 'Rule Shadowing & Dead Rules', href: '/docs/migration#shadowing-algorithm' },
      { title: 'Subnet Collision Detection', href: '/docs/migration#subnet-collisions' },
      { title: 'Cherry-Pick Selective Merge', href: '/docs/migration#selective-merge' },
    ],
  },
  {
    title: 'Live Observability',
    icon: Activity,
    items: [
      { title: 'Observability & Tracing', href: '/docs/observability' },
      { title: 'eBPF & NFLOG Kernel Tap', href: '/docs/observability#kernel-tap' },
      { title: 'Real-Time Protocol Dissectors', href: '/docs/observability#dissectors' },
      { title: 'SSE Packet Stream Endpoint', href: '/docs/observability#sse-streaming' },
      { title: 'VictoriaMetrics & Flow Insight', href: '/docs/observability#victoriametrics' },
    ],
  },
  {
    title: 'Appliance & Telemetry',
    icon: HardDrive,
    items: [
      { title: 'Hardware Monitoring Overview', href: '/docs/hardware-telemetry' },
      { title: 'HWMON Sensors (Temp/Fan/Volt)', href: '/docs/hardware-telemetry#hwmon' },
      { title: 'SFP+/QSFP Optical DOM (ethtool)', href: '/docs/hardware-telemetry#optical-dom' },
      { title: 'Embedded PTY Web Terminal', href: '/docs/hardware-telemetry#web-terminal' },
    ],
  },
  {
    title: 'GitOps & Audit Trail',
    icon: GitBranch,
    items: [
      { title: 'GitOps Architecture', href: '/docs/gitops-audit' },
      { title: 'Automated Git Versioning', href: '/docs/gitops-audit#versioning' },
      { title: 'Unified Diff Inspection', href: '/docs/gitops-audit#diff-inspection' },
      { title: '1-Click Rollback Lifecycle', href: '/docs/gitops-audit#rollback' },
    ],
  },
  {
    title: 'API Reference',
    icon: Code2,
    items: [
      { title: 'REST & SSE Endpoints', href: '/docs/api-reference' },
      { title: 'Live Packet Stream (/events/packets)', href: '/docs/api-reference#packets' },
      { title: 'Web PTY Terminal API', href: '/docs/api-reference#terminal' },
      { title: 'GitOps Revisions API', href: '/docs/api-reference#gitops' },
      { title: 'Privileged Agent Socket IPC', href: '/docs/api-reference#agent-socket' },
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
        <span className="font-mono">Axonwall v0.11.28</span>
        <span className="text-emerald-400 font-medium">Docs 2.0</span>
      </div>
    </aside>
  );
}
