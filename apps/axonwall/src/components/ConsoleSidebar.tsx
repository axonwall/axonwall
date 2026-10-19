'use client';

import React, { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Logo } from './Logo';
import { getCurrentDesiredState } from '@/server/agent';
import {
  Shield,
  LayoutDashboard,
  Network,
  Flame,
  Route,
  Server,
  KeyRound,
  FileText,
  Activity,
  Settings,
  Gauge,
  Layers,
  ShieldCheck,
  Compass,
  ShieldAlert,
  Users,
  Ban,
  Lock,
  Globe,
  Radio,
  ArrowRightLeft,
  Boxes,
  BatteryCharging,
  Sparkles,
  Wifi,
  Binary,
  MapPin,
  Building2,
  HardDrive,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Search,
  X,
  Eye,
  Wrench,
  Terminal,
  Database,
  FolderKanban,
  Camera,
  Cpu,
  BookOpen,
  Power,
  Target,
  GitBranch,
  Crosshair,
} from 'lucide-react';

export interface SubItem {
  name: string;
  href: string;
  icon?: any;
  badge?: string;
}

export interface NavSection {
  id: string;
  name: string;
  icon: any;
  href?: string;
  capability?: 'firewall' | 'nas' | 'k3s' | 'virt' | 'vigilante';
  items?: SubItem[];
}

export const NAV_SECTIONS: NavSection[] = [
  {
    id: 'lobby',
    name: 'Lobby / Dashboard',
    icon: LayoutDashboard,
    href: '/lobby',
  },
  {
    id: 'system',
    name: 'System',
    icon: Settings,
    items: [
      { name: 'Configuration & Revisions', href: '/system', icon: Settings },
      { name: 'Local Users & Groups', href: '/system/users', icon: Users },
      { name: 'Enterprise SSO', href: '/system/sso', icon: Building2 },
      { name: 'High Availability (HA)', href: '/ha', icon: ArrowRightLeft },
      { name: 'Backup & Recovery', href: '/system/backup', icon: HardDrive },
      { name: 'A/B System Updates', href: '/system/updates', icon: RefreshCw },
      { name: 'Enterprise SSO', href: '/system/sso', icon: Building2 },
      { name: 'Service Supervisor', href: '/system/services', icon: Server },
      { name: 'Plugin Store & Roles', href: '/system/plugins', icon: Boxes, badge: 'Core' },
      { name: 'UPS Battery (NUT)', href: '/system/ups', icon: BatteryCharging },
      { name: 'Firewall Importer', href: '/system/import', icon: FileText },
      { name: 'Web Shell & Sensors', href: '/system/terminal', icon: Terminal },
      { name: 'Power & Reboot', href: '/system/power', icon: Power },
    ],
  },
  {
    id: 'interfaces',
    name: 'Interfaces',
    icon: Network,
    items: [
      { name: 'Assignments & Status', href: '/interfaces', icon: Network },
      { name: 'Advanced Topologies', href: '/interfaces/advanced', icon: Layers },
    ],
  },
  {
    id: 'firewall',
    name: 'Firewall',
    icon: Flame,
    capability: 'firewall',
    items: [
      { name: 'Rules & NAT', href: '/firewall', icon: Flame },
      { name: 'Threat Feeds & Aliases', href: '/security/aliases', icon: Globe },
      { name: 'GeoIP Location Filter', href: '/security/geoip', icon: MapPin },
      { name: 'Traffic Shaper (QoS)', href: '/traffic/shaper', icon: Gauge },
    ],
  },
  {
    id: 'security',
    name: 'Threat Defense',
    icon: ShieldAlert,
    capability: 'firewall',
    items: [
      { name: 'Suricata IDS/IPS', href: '/security/ids', icon: ShieldAlert },
      { name: 'CrowdSec Bouncer', href: '/security/crowdsec', icon: Radio },
      { name: 'DNS Sinkhole (RPZ)', href: '/security/dns-blocklist', icon: Ban },
      { name: 'TLS Decryption', href: '/security/tls-decryption', icon: Eye },
      { name: 'Identity-Aware Proxy', href: '/security/iap', icon: Lock },
    ],
  },
  {
    id: 'routing',
    name: 'Routing',
    icon: Route,
    capability: 'firewall',
    items: [
      { name: 'Routing Overview', href: '/routing', icon: Route },
      { name: 'Gateways & Multi-WAN', href: '/routing/gateways', icon: Compass },
      { name: 'Dynamic Routing (FRR)', href: '/routing/dynamic', icon: Compass },
    ],
  },
  {
    id: 'services',
    name: 'Services',
    icon: Server,
    capability: 'firewall',
    items: [
      { name: 'DHCP Server (Kea)', href: '/services/dhcp', icon: Server },
      { name: "ACME / Let's Encrypt", href: '/security/acme', icon: Lock },
      { name: 'Captive Portal', href: '/security/captive-portal', icon: Users },
    ],
  },
  {
    id: 'vpn',
    name: 'VPN',
    icon: KeyRound,
    capability: 'firewall',
    items: [
      { name: 'WireGuard VPN', href: '/vpn/wireguard', icon: KeyRound },
      { name: 'Mesh VPN (Headscale)', href: '/vpn/mesh', icon: Network },
      { name: 'IPsec (strongSwan)', href: '/vpn/ipsec', icon: ShieldCheck },
      { name: 'OpenVPN (DCO)', href: '/vpn/openvpn', icon: KeyRound },
    ],
  },
  {
    id: 'storage',
    name: 'Storage (ZFS NAS)',
    icon: Database,
    capability: 'nas',
    items: [
      { name: 'Disks & RAID Inventory', href: '/storage/disks', icon: HardDrive },
      { name: 'ZFS Pools & RAID-Z', href: '/storage/pools', icon: Database, badge: 'ZFS' },
      { name: 'Datasets & Zvols', href: '/storage/datasets', icon: Layers },
      { name: 'Shares (SMB / NFS / iSCSI)', href: '/storage/shares', icon: FolderKanban },
      { name: 'Snapshots & HA Sync', href: '/storage/snapshots', icon: Camera },
    ],
  },
  {
    id: 'k3s',
    name: 'Kubernetes (K3s)',
    icon: Cpu,
    capability: 'k3s',
    items: [
      { name: 'Cluster & HA Join', href: '/k3s/cluster', icon: Cpu, badge: 'HA' },
      { name: 'OpenEBS Storage', href: '/k3s/storage', icon: Database },
      { name: 'Workloads & Apps', href: '/k3s/workloads', icon: Boxes },
    ],
  },
  {
    id: 'compute',
    name: 'Compute & VMs',
    icon: Cpu,
    capability: 'virt',
    items: [
      { name: 'Virtual Machines (KVM)', href: '/compute/vms', icon: Cpu, badge: 'KVM' },
      { name: 'LXC Containers', href: '/compute/lxc', icon: Boxes, badge: 'LXC' },
      { name: 'ISO Images & Media', href: '/compute/isos', icon: HardDrive },
      { name: 'PCIe VFIO & SR-IOV', href: '/compute/pci', icon: Network },
      { name: 'Deduplicated Backups', href: '/compute/backups', icon: Camera },
    ],
  },
  {
    id: 'vigilante',
    name: 'Vigilante Cyber Ops',
    icon: Crosshair,
    capability: 'vigilante',
    items: [
      { name: 'BattleStation & SOAR', href: '/vigilante/battlestation', icon: Crosshair, badge: 'SOAR' },
      { name: 'Security Modules (12)', href: '/vigilante/modules', icon: Boxes, badge: '12' },
      { name: 'Attack Graph & AD', href: '/vigilante/attack-graph', icon: GitBranch },
      { name: 'Deception & Honeynets', href: '/vigilante/deception', icon: Radio, badge: 'Mesh' },
      { name: 'Purple Team Matrix', href: '/vigilante/purpleteam', icon: Target },
      { name: 'Forensics & Vault', href: '/vigilante/forensics', icon: Camera, badge: 'ZFS' },
      { name: 'Security Data Lake', href: '/vigilante/datalake', icon: Database },
    ],
  },
  {
    id: 'reporting',
    name: 'Reporting',
    icon: Activity,
    items: [
      { name: 'System Telemetry', href: '/reporting/health', icon: Activity },
      { name: 'Insight Flow Analytics', href: '/reporting/insight', icon: Compass },
      { name: 'Live Flow Monitor', href: '/reporting/flows', icon: Binary },
    ],
  },
  {
    id: 'diagnostics',
    name: 'Diagnostics',
    icon: Wrench,
    items: [
      { name: 'Network Diagnostics', href: '/diagnostics', icon: Activity },
      { name: 'Live Packet Capture', href: '/diagnostics/packet-capture', icon: Binary },
      { name: 'Packet Tracer (E5)', href: '/diagnostics/packet-tracer', icon: Layers },
    ],
  },
  {
    id: 'cloud_ai',
    name: 'Cloud & AI',
    icon: Sparkles,
    items: [
      { name: 'AI Copilot', href: '/ai', icon: Sparkles },
      { name: 'Fleet & Satellites', href: '/fleet', icon: Wifi },
    ],
  },
  {
    id: 'docs',
    name: 'Documentation',
    icon: BookOpen,
    items: [
      { name: 'Docs Home & Quickstart', href: '/docs', icon: BookOpen },
      { name: 'Modular Architecture', href: '/docs/modular-architecture', icon: Cpu, badge: 'Core' },
      { name: 'Multi-Disk RAID & ZFS Install', href: '/docs/installer-raid-zfs', icon: HardDrive },
      { name: 'ZFS Storage Management', href: '/docs/zfs-nas-storage', icon: Database },
      { name: 'K3s & OpenEBS', href: '/docs/k3s-kubernetes', icon: Layers },
      { name: 'High Availability (HA)', href: '/docs/high-availability', icon: ArrowRightLeft },
      { name: 'Threat Defense & RPZ', href: '/docs/threat-defense', icon: ShieldAlert },
      { name: 'Migration Studio', href: '/docs/migration', icon: FileText },
      { name: 'Observability & eBPF', href: '/docs/observability', icon: Activity },
      { name: 'Hardware & Web Shell', href: '/docs/hardware-telemetry', icon: Terminal },
      { name: 'GitOps Audit Trail', href: '/docs/gitops-audit', icon: RefreshCw },
      { name: 'API Reference', href: '/docs/api-reference', icon: Server },
    ],
  },
];

export function ConsoleSidebar() {
  const pathname = usePathname();
  const [search, setSearch] = useState('');
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({});
  // Defaults mirror CoreCapabilitiesSchema (firewall on, NAS/K3s opt-in)
  // and the pre-fetch state must not advertise menus for roles that are
  // not enabled.
  const [capabilities, setCapabilities] = useState<{
    firewallEnabled: boolean;
    nasEnabled: boolean;
    k3sEnabled: boolean;
    virtEnabled: boolean;
    vigilanteEnabled: boolean;
  }>({
    firewallEnabled: true,
    nasEnabled: false,
    k3sEnabled: false,
    virtEnabled: false,
    vigilanteEnabled: false,
  });

  useEffect(() => {
    let mounted = true;
    const loadCaps = () => {
      getCurrentDesiredState()
        .then((st) => {
          if (!mounted) return;
          // Derive exactly like the Plugin Store and the server-side
          // consumers: an unset capability means the role is DISABLED
          // (CoreCapabilitiesSchema defaults nasEnabled/k3sEnabled/virtEnabled to
          // false, and baseline state carries no capabilities key at
          // all).
          setCapabilities({
            firewallEnabled: st.capabilities?.firewallEnabled !== false,
            nasEnabled: Boolean(st.capabilities?.nasEnabled ?? st.nas?.enabled),
            k3sEnabled: Boolean(st.capabilities?.k3sEnabled ?? st.k3s?.enabled),
            virtEnabled: Boolean(st.capabilities?.virtEnabled ?? st.virt?.enabled),
            vigilanteEnabled: Boolean(st.capabilities?.vigilanteEnabled ?? st.vigilante?.enabled),
          });
        })
        .catch(() => {});
    };
    loadCaps();
    window.addEventListener('axonwall-capabilities-updated', loadCaps);
    return () => {
      mounted = false;
      window.removeEventListener('axonwall-capabilities-updated', loadCaps);
    };
  }, [pathname]);

  const roleFilteredSections = useMemo(() => {
    return NAV_SECTIONS.filter((sec) => {
      if (sec.capability === 'firewall' && !capabilities.firewallEnabled) return false;
      if (sec.capability === 'nas' && !capabilities.nasEnabled) return false;
      if (sec.capability === 'k3s' && !capabilities.k3sEnabled) return false;
      if (sec.capability === 'virt' && !capabilities.virtEnabled) return false;
      if (sec.capability === 'vigilante' && !capabilities.vigilanteEnabled) return false;
      return true;
    });
  }, [capabilities]);

  // Auto-expand the section containing the active pathname
  useEffect(() => {
    for (const section of roleFilteredSections) {
      if (
        section.items?.some(
          (item) => pathname === item.href || (item.href !== '/' && pathname.startsWith(`${item.href}/`))
        )
      ) {
        setOpenSections((prev) => ({ ...prev, [section.id]: true }));
        break;
      }
    }
  }, [pathname, roleFilteredSections]);

  const toggleSection = (id: string) => {
    setOpenSections((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // Filter sections and items based on search query
  const isSearching = search.trim().length > 0;
  const filteredSections = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return roleFilteredSections;

    return roleFilteredSections.map((section) => {
      // If direct link matches
      if (section.href && section.name.toLowerCase().includes(q)) {
        return section;
      }

      // If category name matches, keep all sub-items
      if (section.name.toLowerCase().includes(q)) {
        return section;
      }

      // Check sub items
      const matchingItems = section.items?.filter(
        (item) =>
          item.name.toLowerCase().includes(q) ||
          item.href.toLowerCase().includes(q)
      );

      if (matchingItems && matchingItems.length > 0) {
        return {
          ...section,
          items: matchingItems,
        };
      }

      return null;
    }).filter(Boolean) as NavSection[];
  }, [search, roleFilteredSections]);

  const activeRoleSummary = [
    capabilities.firewallEnabled ? 'FW' : null,
    capabilities.nasEnabled ? 'ZFS' : null,
    capabilities.k3sEnabled ? 'K3s' : null,
  ]
    .filter(Boolean)
    .join(' + ') || 'Host Mode';

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0 h-screen sticky top-0">
      {/* Brand Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <Logo variant="badge" size="sm" showSubtext={false} />
          <div>
            <span className="font-bold text-base tracking-tight text-white block">Axonwall</span>
            <span className="text-[10px] text-emerald-400 font-mono tracking-wider uppercase">
              {activeRoleSummary}
            </span>
          </div>
        </div>
      </div>

      {/* OPNsense-Style Real-time Search Box */}
      <div className="p-3 border-b border-slate-800/80 shrink-0">
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') setSearch('');
            }}
            placeholder="Search menu..."
            className="w-full bg-slate-950/70 border border-slate-800 rounded-lg pl-8 pr-7 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/30 transition"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition"
              aria-label="Clear search"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Navigation Tree Container */}
      <nav className="p-2 space-y-1 flex-1 min-h-0 overflow-y-auto">
        {filteredSections.length === 0 ? (
          <div className="px-4 py-8 text-center text-xs text-slate-500">
            No matching menu items
          </div>
        ) : (
          filteredSections.map((section) => {
            const SectionIcon = section.icon;

            // Direct link section (e.g. Lobby / Dashboard)
            if (section.href) {
              const isActive =
                pathname === section.href || pathname.startsWith(`${section.href}/`);
              return (
                <Link
                  key={section.id}
                  href={section.href}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition ${
                    isActive
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <SectionIcon className="w-4 h-4 shrink-0" />
                  <span className="flex-1">{section.name}</span>
                </Link>
              );
            }

            // Collapsible Submenu section
            const isOpen = isSearching || !!openSections[section.id];
            const hasActiveChild = section.items?.some(
              (item) =>
                pathname === item.href ||
                (item.href !== '/' && pathname.startsWith(`${item.href}/`))
            );

            return (
              <div key={section.id} className="space-y-0.5">
                <button
                  type="button"
                  onClick={() => toggleSection(section.id)}
                  className={`w-full flex items-center justify-between gap-2 px-3 py-2 rounded-lg text-xs font-medium transition ${
                    hasActiveChild && !isOpen
                      ? 'text-emerald-400 bg-slate-800/40'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <SectionIcon
                      className={`w-4 h-4 shrink-0 ${
                        hasActiveChild ? 'text-emerald-400' : 'text-slate-400'
                      }`}
                    />
                    <span className="truncate">{section.name}</span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {hasActiveChild && !isOpen && (
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    )}
                    {isOpen ? (
                      <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                    )}
                  </div>
                </button>

                {isOpen && section.items && (
                  <div className="ml-3.5 pl-2.5 border-l border-slate-800/80 space-y-0.5 py-0.5">
                    {section.items.map((item) => {
                      const ItemIcon = item.icon;
                      const isItemActive =
                        pathname === item.href ||
                        (item.href !== '/' && pathname.startsWith(`${item.href}/`));

                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          className={`flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition ${
                            isItemActive
                              ? 'bg-emerald-500/10 text-emerald-400 font-semibold border-l-2 border-emerald-400 rounded-l-none'
                              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                          }`}
                        >
                          {ItemIcon && (
                            <ItemIcon
                              className={`w-3.5 h-3.5 shrink-0 ${
                                isItemActive ? 'text-emerald-400' : 'text-slate-500'
                              }`}
                            />
                          )}
                          <span className="truncate">{item.name}</span>
                          {item.badge && (
                            <span className="ml-auto px-1.5 py-0.5 text-[9px] rounded bg-emerald-500/20 text-emerald-400">
                              {item.badge}
                            </span>
                          )}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })
        )}
      </nav>

      {/* Footer Info */}
      <div className="p-3 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between shrink-0">
        <span className="font-mono">Axonwall v0.9.1</span>
        <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          Active
        </span>
      </div>
    </aside>
  );
}
