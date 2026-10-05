'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
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
} from 'lucide-react';

interface NavItem {
  name: string;
  href: string;
  icon: any;
}

const NAV_ITEMS: NavItem[] = [
  { name: 'Lobby / Dashboard', href: '/lobby', icon: LayoutDashboard },
  { name: 'Interfaces', href: '/interfaces', icon: Network },
  { name: 'Advanced Topologies', href: '/interfaces/advanced', icon: Layers },
  { name: 'Firewall Rules & NAT', href: '/firewall', icon: Flame },
  { name: 'Threat Feeds & Aliases', href: '/security/aliases', icon: Globe },
  { name: 'Suricata IDS/IPS', href: '/security/ids', icon: ShieldAlert },
  { name: 'CrowdSec Bouncer', href: '/security/crowdsec', icon: Radio },
  { name: 'DNS Sinkhole (RPZ)', href: '/security/dns-blocklist', icon: Ban },
  { name: 'Captive Portal', href: '/security/captive-portal', icon: Users },
  { name: 'Routing & Multi-WAN', href: '/routing/gateways', icon: Route },
  { name: 'Dynamic Routing (FRR)', href: '/routing/dynamic', icon: Compass },
  { name: 'Smart QoS & Shaper', href: '/traffic/shaper', icon: Gauge },
  { name: 'DHCP Server (Kea)', href: '/services/dhcp', icon: Server },
  { name: 'WireGuard VPN', href: '/vpn/wireguard', icon: KeyRound },
  { name: 'IPsec (strongSwan)', href: '/vpn/ipsec', icon: ShieldCheck },
  { name: 'OpenVPN (DCO)', href: '/vpn/openvpn', icon: KeyRound },
  { name: 'ACME / Let\'s Encrypt', href: '/security/acme', icon: Lock },
  { name: 'High Availability (HA)', href: '/ha', icon: ArrowRightLeft },
  { name: 'System Telemetry', href: '/reporting/health', icon: Activity },
  { name: 'Insight Flow Analytics', href: '/reporting/insight', icon: Compass },
  { name: 'Plugin Store', href: '/system/plugins', icon: Boxes },
  { name: 'Service Supervisor', href: '/system/services', icon: Server },
  { name: 'UPS Battery (NUT)', href: '/system/ups', icon: BatteryCharging },
  { name: 'Network Diagnostics', href: '/diagnostics', icon: Activity },
  { name: 'Packet Tracer (E5)', href: '/diagnostics/packet-tracer', icon: Layers },
  { name: 'OPNsense Importer', href: '/system/import', icon: FileText },
  { name: 'System & Revisions', href: '/system', icon: Settings },
];

export function ConsoleSidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0 min-h-screen">
      <div className="p-4 border-b border-slate-800 flex items-center gap-3">
        <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <span className="font-bold text-base tracking-tight text-white block">Axonwall</span>
          <span className="text-[10px] text-emerald-400 font-mono tracking-wider uppercase">
            Linux + nftables
          </span>
        </div>
      </div>

      <nav className="p-3 space-y-1 flex-1">
        <div className="px-3 py-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
          Management
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
                isActive
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
        <span>OPNsense Parity v1</span>
        <span className="flex items-center gap-1 text-emerald-400">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Active
        </span>
      </div>
    </aside>
  );
}
