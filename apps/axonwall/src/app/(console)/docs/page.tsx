import React from 'react';
import Link from 'next/link';
import {
  Shield,
  Zap,
  ArrowRight,
  Server,
  Layers,
  Cpu,
  ArrowRightLeft,
  FileCode,
  Activity,
  Terminal,
  GitBranch,
  ShieldAlert,
  Download,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import { Callout } from './components/Callout';
import { CodeBlock } from './components/CodeBlock';

export const metadata = {
  title: 'Axonwall Documentation | Overview & Quickstart',
  description:
    'Comprehensive documentation for Axonwall, the modern Linux-based Next-Generation Firewall and Router powered by nftables, commit-confirm rollback, and autonomous observability.',
};

export default function DocsOverviewPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Documentation Portal
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Axonwall Documentation
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Welcome to the official Axonwall documentation. Axonwall is an enterprise-grade open-source router and Next-Generation Firewall (NGFW) engineered on modern Linux, <code className="text-emerald-400 font-mono">nftables</code>, and Next.js.
        </p>
      </div>

      {/* Feature Navigation Grid */}
      <section className="space-y-6">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Layers className="w-5 h-5 text-emerald-400" /> Explore Core Subsystems
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Link
            href="/docs/modular-architecture"
            className="p-5 rounded-xl bg-slate-900/60 border border-emerald-500/40 hover:border-emerald-500 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Cpu className="w-4 h-4 text-emerald-400" />
                <span>Modular Core Roles (FW, ZFS, K3s)</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Run Axonwall as a dedicated NGFW, a pure TrueNAS-grade ZFS NAS, or a hyper-converged Kubernetes (K3s) node.
            </p>
          </Link>

          <Link
            href="/docs/zfs-nas-storage"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Layers className="w-4 h-4 text-emerald-400" />
                <span>ZFS NAS Storage Management</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              OpenZFS Stripe/Mirror/RAID-Z pools, datasets, POSIX ACLs, Samba SMB3 with VSS shadow copies, and NFSv4/iSCSI.
            </p>
          </Link>

          <Link
            href="/docs/k3s-kubernetes"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Server className="w-4 h-4 text-emerald-400" />
                <span>Kubernetes (K3s) & OpenEBS</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              WireGuard flannel mesh, 2-node HA automatic cluster join over mTLS, and OpenEBS replicated Mayastor NVMe-oF storage.
            </p>
          </Link>

          <Link
            href="/docs/installer-raid-zfs"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Download className="w-4 h-4 text-emerald-400" />
                <span>Multi-Disk RAID & ZFS Install</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              mdadm RAID-1 system disk mirroring across Slot A, Slot B, Swap, and Data, plus dedicated ZFS storage partitioning.
            </p>
          </Link>

          <Link
            href="/docs/architecture"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Cpu className="w-4 h-4 text-emerald-400" />
                <span>Architecture & nftables</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Why Linux multi-core line-rate scaling replaces FreeBSD pf, A/B dual-root unbrickable updates, and Junos-style commit-confirm.
            </p>
          </Link>

          <Link
            href="/docs/high-availability"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <ArrowRightLeft className="w-4 h-4 text-emerald-400" />
                <span>High Availability (HA)</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Keepalived VRRP v2/v3 failover paired with conntrackd stateful connection replication over FTFW multicast & unicast links.
            </p>
          </Link>

          <Link
            href="/docs/threat-defense"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <ShieldAlert className="w-4 h-4 text-emerald-400" />
                <span>Threat Feeds & DNS RPZ</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Dynamic IP blocklist sets with CIDR interval minimization, and Unbound RPZ sinkhole compiler with subdomain pruning.
            </p>
          </Link>

          <Link
            href="/docs/migration"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <FileCode className="w-4 h-4 text-emerald-400" />
                <span>Migration Studio</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              One-click migration from pfSense, OPNsense, and Cisco ASA/FTD with mathematical rule shadowing and dead-rule detection.
            </p>
          </Link>

          <Link
            href="/docs/observability"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Activity className="w-4 h-4 text-emerald-400" />
                <span>Live Observability & eBPF</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Real-time NFLOG/eBPF kernel packet tracing, SSE live protocol dissector, VictoriaMetrics time-series, and Insight Flow.
            </p>
          </Link>

          <Link
            href="/docs/hardware-telemetry"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>Hardware Sensors & Web Shell</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              HWMON thermal & fan telemetry, SFP+/QSFP optical transceiver DOM diagnostics, and root web PTY terminal.
            </p>
          </Link>

          <Link
            href="/docs/gitops-audit"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <GitBranch className="w-4 h-4 text-emerald-400" />
                <span>GitOps Configuration Versioning</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Automated Git repository backing for every configuration commit, unified diff previews, and 1-click historical rollback.
            </p>
          </Link>

          <Link
            href="/docs/api-reference"
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 hover:bg-slate-900 transition group block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2.5 font-bold text-white text-base">
                <Server className="w-4 h-4 text-emerald-400" />
                <span>REST & Agent API Reference</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition transform group-hover:translate-x-1" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Programmatic OpenAPI / REST endpoints, SSE streams, and privileged Unix socket IPC (/run/axonwall/agent.sock).
            </p>
          </Link>
        </div>
      </section>

      {/* Installation Guide */}
      <section id="installation" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Download className="w-6 h-6 text-emerald-400" /> Installation & Deployment
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall can be installed as bare-metal appliance firmware via bootable UEFI ISO, deployed inside standard virtualization platforms (Proxmox VE, KVM, ESXi), or run as a containerized network router via Docker Compose.
        </p>

        <div className="space-y-4">
          <h3 className="text-base font-semibold text-white">Option 1: Bare Metal UEFI Appliance (Recommended)</h3>
          <p className="text-xs text-slate-400">
            Flash the Axonwall ISO to a USB flash drive using BalenaEtcher, Rufus (DD mode), or the Linux <code className="text-slate-300">dd</code> utility:
          </p>
          <CodeBlock
            title="Flash ISO to USB Drive"
            language="bash"
            code={`# Replace /dev/sdX with your destination USB drive
sudo dd if=axonwall-v0.1.7-amd64.iso of=/dev/sdX bs=4M status=progress conv=fsync`}
          />
          <Callout type="tip" title="Interactive A/B Dual-Root Partitioning">
            During installation, the installer prompts you to select your target disk and choose your preferred system partition size:
            <ul className="list-disc list-inside mt-2 space-y-1 text-slate-300">
              <li><strong>Standard (16 GB per slot):</strong> Recommended default for SSD appliances.</li>
              <li><strong>Compact (8 GB per slot):</strong> For embedded systems, eMMC, or 16-32 GB flash drives.</li>
              <li><strong>Expanded (32 GB per slot):</strong> For enterprise systems with high telemetry or container loads.</li>
              <li><strong>Custom:</strong> User-defined size in gigabytes.</li>
            </ul>
            <p className="mt-2 text-slate-400">
              <strong>Why Two Identical Slots?</strong> Axonwall maintains an active and standby system slot (<code className="text-emerald-300 font-mono">axon_root_a</code> and <code className="text-emerald-300 font-mono">axon_root_b</code>). When firmware upgrades are installed, they are flashed to the inactive slot. If an upgrade encounters a kernel panic or failure, the watchdog automatically falls back to the alternate slot, preventing appliance lockouts. The chosen size is allocated twice, and the rest of the disk is dedicated to persistent storage (<code className="text-emerald-300 font-mono">/var/lib/axonwall</code>).
            </p>
          </Callout>

          <h3 className="text-base font-semibold text-white pt-4">Option 2: Proxmox VE / KVM Virtual Machine</h3>
          <p className="text-xs text-slate-400">
            Create a VM with standard VirtIO hardware acceleration:
          </p>
          <ul className="list-disc list-inside text-xs text-slate-300 space-y-1.5 ml-2">
            <li><strong>CPU:</strong> Host (minimum 2 vCPUs, 4+ recommended)</li>
            <li><strong>Memory:</strong> 4096 MB RAM (minimum 2048 MB)</li>
            <li><strong>Disk:</strong> 32 GB+ SCSI (VirtIO SCSI single with discard enabled)</li>
            <li><strong>Network:</strong> VirtIO (net0 mapped to WAN bridge, net1 mapped to LAN bridge)</li>
          </ul>

          <h3 className="text-base font-semibold text-white pt-4">Option 3: Debian / Ubuntu Package (.deb)</h3>
          <p className="text-xs text-slate-400">
            For existing Debian 12 (Bookworm) / 13 (Trixie) or Ubuntu 24.04 LTS servers, install Axonwall directly using the official standalone package:
          </p>
          <CodeBlock
            title="Install Debian Package"
            language="bash"
            code={`# Download the latest .deb release artifact from GitHub Releases
wget https://github.com/axonwall/axonwall/releases/latest/download/axonwall_0.1.7_amd64.deb

# Install package with dependencies
sudo apt-get update
sudo apt-get install -y ./axonwall_0.1.7_amd64.deb

# Verify running services
sudo systemctl status axonwalld axonwall-ui axonwall-controller`}
          />

          <h3 className="text-base font-semibold text-white pt-4">Option 4: Docker Compose Testing Container</h3>
          <CodeBlock
            title="compose.yaml"
            language="yaml"
            code={`services:
  axonwall:
    image: ghcr.io/axonwall/axonwall:v0.1.7
    cap_add:
      - NET_ADMIN
      - NET_RAW
    network_mode: host
    volumes:
      - /etc/axonwall:/etc/axonwall
      - /run/axonwall:/run/axonwall
    restart: unless-stopped`}
          />
        </div>
      </section>

      {/* Quickstart Guide */}
      <section id="quickstart" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Zap className="w-6 h-6 text-emerald-400" /> Quickstart & First Boot
        </h2>
        <div className="space-y-4 text-xs sm:text-sm text-slate-300 leading-relaxed">
          <p>
            Upon initial startup, Axonwall configures the primary Ethernet adapter (usually the first physical port) as LAN with DHCP server enabled:
          </p>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-slate-500 font-medium">Default Web Console:</span>
              <p className="font-mono text-emerald-400 font-semibold mt-0.5">https://192.168.1.1:2966</p>
            </div>
            <div>
              <span className="text-slate-500 font-medium">Default Credentials:</span>
              <p className="font-mono text-white mt-0.5">Username: <code className="text-emerald-400">admin</code> | Password: <code className="text-emerald-400">axonwall</code></p>
            </div>
          </div>

          <Callout type="warning" title="Commit-Confirm Safety">
            Whenever you modify interface assignments, IP addresses, or firewall rules in the console, Axonwall initiates a <strong>60-second Commit-Confirm timer</strong>. If your changes interrupt connectivity, the system automatically rolls back to the previous verified configuration bundle without locking you out.
          </Callout>
        </div>
      </section>

      {/* Hardware Requirements */}
      <section id="hardware" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Server className="w-6 h-6 text-emerald-400" /> Hardware Compatibility & Sizing
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-slate-800 rounded-xl overflow-hidden">
            <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Deployment Tier</th>
                <th className="p-3">Throughput Target</th>
                <th className="p-3">Processor</th>
                <th className="p-3">Memory</th>
                <th className="p-3">NIC Architecture</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Edge / Satellite</td>
                <td className="p-3 text-emerald-400">Up to 1 Gbps</td>
                <td className="p-3">Quad-Core ARM64 or Intel N100 / J4125</td>
                <td className="p-3">2 GB - 4 GB</td>
                <td className="p-3">Realtek 8125B / Intel i225-V</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">SMB / Branch Office</td>
                <td className="p-3 text-emerald-400">2.5 Gbps - 10 Gbps</td>
                <td className="p-3">Intel Core i3/i5 12th+ Gen or AMD Ryzen 5</td>
                <td className="p-3">8 GB - 16 GB</td>
                <td className="p-3">Intel i226-V (2.5G) / Intel X520 (10G SFP+)</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Enterprise Core / Datacenter</td>
                <td className="p-3 text-emerald-400">10 Gbps - 100 Gbps line-rate</td>
                <td className="p-3">Intel Xeon Gold / AMD EPYC (8 - 32 cores)</td>
                <td className="p-3">32 GB - 128 GB ECC</td>
                <td className="p-3">Intel E810 / Mellanox ConnectX-5/6 (eBPF/XDP)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
