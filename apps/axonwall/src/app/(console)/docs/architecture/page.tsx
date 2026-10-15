import React from 'react';
import Link from 'next/link';
import { Cpu, Layers, ShieldCheck, RefreshCw, Terminal, CheckCircle2, ArrowRight } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Axonwall Architecture | Linux nftables Engine & A/B Dual-Root',
  description:
    'Deep-dive into the Axonwall architectural foundation: Linux nftables multi-core scaling, Junos-style commit-confirm state machine, A/B dual-root OS updates, and Go daemon IPC.',
};

export default function ArchitectureDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Core Subsystems
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          System Architecture & Engine
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall replaces the 20-year-old FreeBSD <code className="text-slate-200 font-mono">pf</code> model with the modern Linux networking stack, pure <code className="text-emerald-400 font-mono">nftables</code> packet filtering, unbrickable A/B dual-root updates, and Junos-style transactional commit-confirm.
        </p>
      </div>

      {/* Linux nftables vs FreeBSD pf */}
      <section id="comparison" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> Linux nftables vs FreeBSD pf
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Traditional open-source firewalls like pfSense® and OPNsense® are constrained by the FreeBSD <code className="text-slate-200">pf</code> packet filter. Under symmetrical 10G/25G/100G loads and high connection churn, BSD <code className="text-slate-200">pf</code> suffers from severe global mutex lock contention.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-rose-950/20 border border-rose-500/30 space-y-3">
            <h3 className="font-bold text-rose-300 text-sm flex items-center gap-2">
              Legacy FreeBSD pf (pfSense / OPNsense)
            </h3>
            <ul className="space-y-2 text-slate-300 list-disc list-inside">
              <li><strong>Single-Threaded State Table:</strong> Multi-core CPUs bottle-neck on global state table insertion locks.</li>
              <li><strong>Driver & Hardware Lag:</strong> Wi-Fi 7, modern 5G modems, and multi-queue 25G/100G NICs (Intel E810, Mellanox) often lack FreeBSD drivers.</li>
              <li><strong>Container Incompatibility:</strong> Cannot coexist natively inside Linux network namespaces, Kubernetes CNI, or Docker.</li>
              <li><strong>Monolithic PHP Re-renders:</strong> Entire rulesets are recompiled and rewritten via PHP scripts during any rule toggle.</li>
            </ul>
          </div>

          <div className="p-5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-3">
            <h3 className="font-bold text-emerald-300 text-sm flex items-center gap-2">
              Axonwall Modern Linux (nftables + eBPF)
            </h3>
            <ul className="space-y-2 text-slate-300 list-disc list-inside">
              <li><strong>Lockless Multi-Core RSS:</strong> Linux Netfilter distributes connection tracking (conntrack) and packet evaluation across all CPU cores.</li>
              <li><strong>Day-One Hardware Acceleration:</strong> Full in-tree Linux kernel driver support for all 2.5G/10G/25G/100G NICs and optical transceivers.</li>
              <li><strong>Zero-Conflict Table Isolation:</strong> Operates entirely inside <code className="text-emerald-400 font-mono">table inet axonwall</code> without disturbing Docker or Kubernetes CNI.</li>
              <li><strong>Atomic Incremental Rulesets:</strong> Atomic transactions prevent packet drops and micro-blackouts during policy updates.</li>
            </ul>
          </div>
        </div>

        <h3 className="text-base font-semibold text-white pt-2">Isolated nftables Table Architecture</h3>
        <p className="text-xs text-slate-400">
          Axonwall encapsulates all routing, NAT, and filtering policies within its own dedicated kernel table, ensuring full compatibility with co-located container workloads:
        </p>
        <CodeBlock
          title="/etc/nftables/axonwall.nft"
          language="nftables"
          code={`table inet axonwall {
  # Dynamic interval sets for high-speed IP blocklists
  set threat_feed_ips {
    type ipv4_addr
    flags interval
    auto-merge
  }

  chain prerouting {
    type filter hook prerouting priority -150; policy accept;
    # Early line-rate drop for known malicious threat intelligence feeds
    ip saddr @threat_feed_ips counter drop
  }

  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif "lo" accept
    tcp dport 2966 accept # Web Console
    tcp dport 22 accept   # SSH Administration
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    # Dynamic egress policies compiled from Axonwall JSON intent
    iifname "lan0" oifname "wan0" accept
  }

  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "wan0" masquerade
  }
}`}
        />
      </section>

      {/* Junos Commit-Confirm */}
      <section id="commit-confirm" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-emerald-400" /> Junos-Style Commit-Confirm State Machine
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The single most catastrophic risk in network administration is applying a firewall or routing change that inadvertently cuts off your own management session. Axonwall eliminates administrative lockouts by incorporating a strict Junos-style transactional commit-confirm state machine.
        </p>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4 font-mono text-xs">
          <div className="text-emerald-400 font-bold">COMMIT-CONFIRM LIFECYCLE:</div>
          <div className="space-y-2 text-slate-300">
            <p>1. [INTENT] User or API generates proposed changes (JSON state bundle).</p>
            <p>2. [LINT] Privileged agent executes pre-flight syntax validation: <code className="text-slate-100">nft -c -f /tmp/proposed.nft</code></p>
            <p>3. [APPLY & ARM] Rules applied to kernel; watchdog timer armed (default: 60s).</p>
            <p>4. [QUORUM CHECK] Browser client sends periodic heartbeat confirmations.</p>
            <p>5. [COMMIT OR REVERT] If confirmed, rule becomes permanent; if session drops, daemon reverts to <code className="text-emerald-400">last-known-good.nft</code> within 60s.</p>
          </div>
        </div>

        <Callout type="tip" title="Fail-Safe Verification">
          Even if an administrator makes a mistake that drops all WAN/LAN connections, simply waiting 60 seconds guarantees that the firewall will cleanly roll back to the previously functioning ruleset without needing physical console access.
        </Callout>
      </section>

      {/* A/B Dual-Root System */}
      <section id="ab-dual-root" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <RefreshCw className="w-6 h-6 text-emerald-400" /> A/B Dual-Root Partitioning & Watchdog
        </h2>
        <p className="text-xs text-slate-400 leading-relaxed">
          <strong>Why Two Identical Slots?</strong> In traditional firewalls, updates are applied directly to the running rootfs. If a kernel panic occurs or drivers break, the device is bricked. Axonwall stages updates onto the alternate inactive slot in the background. Because either slot can run the complete operating system and serve as active or fallback, both partitions must be identical in size and capabilities.
        </p>

        <CodeBlock
          title="Disk Partition Scheme"
          language="text"
          code={`+-----------------------------------------------------------------------------------------+
| Partition 1: EFI System Partition (ESP)  | /boot/efi       | FAT32 | 512 MB             |
+-----------------------------------------------------------------------------------------+
| Partition 2: rootfsA (Active / Standby)   | /               | ext4  | 8-32 GB [axon_root_a]|
+-----------------------------------------------------------------------------------------+
| Partition 3: rootfsB (Active / Standby)   | /mnt/standby    | ext4  | 8-32 GB [axon_root_b]|
+-----------------------------------------------------------------------------------------+
| Partition 4: Swap (Optional)             | [SWAP]          | swap  | 0-8 GB             |
+-----------------------------------------------------------------------------------------+
| Partition 5: Persistent Data & Logs      | /var/lib/axonwall| ext4  | Rest of Disk [axon_data]|
+-----------------------------------------------------------------------------------------+`}
        />

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 space-y-2">
          <span className="font-bold text-white text-sm">Installer Partition Sizing Profiles</span>
          <p className="text-slate-400">During ISO installation, the administrator chooses the rootfs size per slot:</p>
          <ul className="list-disc list-inside space-y-1 ml-2 text-slate-300">
            <li><strong>Compact (8 GB per slot):</strong> 16 GB total system allocation; ideal for eMMC, embedded CFast, and small 32 GB disks.</li>
            <li><strong>Standard (16 GB per slot):</strong> 32 GB total system allocation; default for modern SSDs with room for IDS rules and updates.</li>
            <li><strong>Expanded (32 GB per slot):</strong> 64 GB total system allocation; designed for enterprise appliances with container engines.</li>
            <li><strong>Custom:</strong> User-defined size in gigabytes (minimum 6 GB).</li>
          </ul>
        </div>

        <div className="space-y-3 text-xs sm:text-sm text-slate-300">
          <h3 className="text-base font-semibold text-white">Three-Step Autonomous Health Quorum</h3>
          <p>
            Upon booting an upgraded rootfs slot, the privileged daemon <code className="text-emerald-400 font-mono">axonwalld</code> validates three critical subsystem health checks before committing the slot:
          </p>
          <ol className="list-decimal list-inside space-y-1.5 ml-2 text-xs text-slate-300">
            <li><strong>Network Carrier Status:</strong> Loopback (<code className="text-slate-100">lo</code>) and physical link carrier states.</li>
            <li><strong>nftables Subsystem:</strong> Kernel netfilter tables and rule compilation health.</li>
            <li><strong>Control Plane IPC Quorum:</strong> Local Unix socket responsiveness (<code className="text-slate-100">/run/axonwall/agent.sock</code>).</li>
          </ol>
          <p className="text-xs text-slate-400">
            If any check fails or the system experiences a kernel panic during boot, GRUB increments <code className="text-slate-200">bootcount</code>. After 3 failed attempts, GRUB automatically falls back to the previous healthy slot.
          </p>
        </div>
      </section>

      {/* Privileged Daemon */}
      <section id="daemon" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> Privileged Go Daemon (axonwalld) & IPC
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Security best practices dictate that web applications should never run as root. The Next.js web console and Node.js controller run with restricted unprivileged credentials and communicate with <code className="text-emerald-400 font-mono">axonwalld</code> exclusively over a local Unix domain socket:
        </p>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs text-slate-300">
          <span className="text-slate-500">Socket Path:</span> <code className="text-emerald-400">/run/axonwall/agent.sock</code> (mode 0660, owned by axonwall:axonwall)
        </div>
        <p className="text-xs text-slate-400">
          The daemon handles all privileged OS interactions: atomic nftables compilation, conntrack table inspection, Keepalived reload signals, HWMON sensor queries, ethtool optical transceiver reads, and PTY web shell multiplexing.
        </p>
      </section>
    </div>
  );
}
