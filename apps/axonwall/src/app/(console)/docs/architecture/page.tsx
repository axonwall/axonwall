import React from 'react';
import { Cpu, Layers, ShieldCheck, RefreshCw, Terminal } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Axonwall Architecture | Linux nftables, 12-Domain YAML & Boot Engines',
  description:
    'Deep-dive into Axonwall v0.11.68 architecture: Linux nftables + eBPF XDP multi-core scaling, 12 declarative /etc/axonwall/*.yaml domains, Junos-style commit-confirm, A/B Dual-Root & ZFSBootMenu updates, and Go daemon IPC.',
};

export default function ArchitectureDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Core Subsystems • v0.11.68
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          System Architecture &amp; Engine
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall replaces the 20-year-old FreeBSD <code className="text-slate-200 font-mono">pf</code> model with the modern Linux 6.12 LTS networking stack, pure <code className="text-emerald-400 font-mono">nftables</code> + Ring-0 eBPF XDP packet processing, 12 declarative YAML domain manifests, unbrickable A/B Dual-Root &amp; ZFSBootMenu updates, and Junos-style transactional commit-confirm.
        </p>
      </div>

      {/* Linux nftables vs FreeBSD pf */}
      <section id="comparison" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> Linux nftables vs FreeBSD pf
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Traditional open-source firewalls are constrained by the legacy FreeBSD <code className="text-slate-200">pf</code> packet filter. Under symmetrical 10G/25G/100G loads and high connection churn, BSD <code className="text-slate-200">pf</code> suffers from severe global mutex lock contention.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-rose-950/20 border border-rose-500/30 space-y-3">
            <h3 className="font-bold text-rose-300 text-sm flex items-center gap-2">
              Legacy FreeBSD pf
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

        <h3 className="text-base font-semibold text-white pt-2">Isolated nftables Table &amp; Full Enterprise NAT/NGFW Parity</h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          Axonwall encapsulates all routing, NAT, and filtering policies within <code className="text-emerald-400 font-mono">table inet axonwall</code>{' '}
          without disturbing co-located K3s or LXC workloads—compiling stateful filter rules (inbound/outbound/both directionality, source/destination negation, floating multi-interface rules, DSCP marking, per-rule PPS rate limits, and Multi-WAN <code className="text-slate-200 font-mono">fwmark</code> gateway groups), a complete NAT engine (<strong>DNAT + Hairpin NAT Reflection</strong>, <strong>SNAT</strong>, <strong>Masquerade</strong>, <strong>1:1 Bi-Directional BINAT</strong>, and <strong>Stateless IPv6 NPTv6</strong> prefix translation), Kea DHCPv4/DHCPv6 IA_NA/IA_PD + <code className="text-slate-200 font-mono">radvd</code> SLAAC, OpenVPN <code className="text-slate-200 font-mono">ovpn-dco</code> kernel TLS offload, Avahi mDNS reflection, and <code className="text-slate-200 font-mono">miniupnpd</code> UPnP/NAT-PMP:
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

      {/* Declarative 12-Domain YAML Configuration */}
      <section id="declarative-yaml" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> 12-Domain Declarative YAML Configuration
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall decomposes its entire appliance state into <strong>12 canonical YAML domain files</strong> inside{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/</code>, merged deterministically with optional lexical drop-in overrides in{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/conf.d/*.yaml</code> and compiled into a validated runtime snapshot at{' '}
          <code className="text-slate-200 font-mono">/etc/axonwall/state.json</code>. On A/B Dual-Root appliances,{' '}
          <code className="text-slate-200 font-mono">/etc/axonwall/</code> is bidirectionally synchronized to persistent storage at{' '}
          <code className="text-emerald-400 font-mono">/mnt/axonwall-data/etc-axonwall/</code> so configurations survive slot switches seamlessly.
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">#</th>
                <th className="p-3">Canonical File</th>
                <th className="p-3">Top-Level DesiredState Keys</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono">
              <tr><td className="p-2.5 text-slate-500">1</td><td className="p-2.5 text-emerald-400">/etc/axonwall/system.yaml</td><td className="p-2.5 text-slate-300">version, capabilities, system, plugins, ai, eluvix, observability, snmp, ups, acme</td></tr>
              <tr><td className="p-2.5 text-slate-500">2</td><td className="p-2.5 text-emerald-400">/etc/axonwall/interfaces.yaml</td><td className="p-2.5 text-slate-300">interfaces, vlans, bridges, bonds, virtualIps, vrfs</td></tr>
              <tr><td className="p-2.5 text-slate-500">3</td><td className="p-2.5 text-emerald-400">/etc/axonwall/firewall.yaml</td><td className="p-2.5 text-slate-300">aliases, rules, nat, trafficShaper</td></tr>
              <tr><td className="p-2.5 text-slate-500">4</td><td className="p-2.5 text-emerald-400">/etc/axonwall/routing.yaml</td><td className="p-2.5 text-slate-300">gateways, gatewayGroups, routes, frr</td></tr>
              <tr><td className="p-2.5 text-slate-500">5</td><td className="p-2.5 text-emerald-400">/etc/axonwall/services.yaml</td><td className="p-2.5 text-slate-300">dhcp, dns, captivePortal, haproxy, freeradius</td></tr>
              <tr><td className="p-2.5 text-slate-500">6</td><td className="p-2.5 text-emerald-400">/etc/axonwall/vpn.yaml</td><td className="p-2.5 text-slate-300">wireguard, rosenpass, ipsec, openvpn, headscale</td></tr>
              <tr><td className="p-2.5 text-slate-500">7</td><td className="p-2.5 text-emerald-400">/etc/axonwall/security.yaml</td><td className="p-2.5 text-slate-300">suricata, crowdsec, geoip, zeroTrust, sso, tlsDecryption, hostDefense</td></tr>
              <tr><td className="p-2.5 text-slate-500">8</td><td className="p-2.5 text-emerald-400">/etc/axonwall/ha.yaml</td><td className="p-2.5 text-slate-300">ha, fleet</td></tr>
              <tr><td className="p-2.5 text-slate-500">9</td><td className="p-2.5 text-emerald-400">/etc/axonwall/storage.yaml</td><td className="p-2.5 text-slate-300">nas</td></tr>
              <tr><td className="p-2.5 text-slate-500">10</td><td className="p-2.5 text-emerald-400">/etc/axonwall/k3s.yaml</td><td className="p-2.5 text-slate-300">k3s, vow</td></tr>
              <tr><td className="p-2.5 text-slate-500">11</td><td className="p-2.5 text-emerald-400">/etc/axonwall/virt.yaml</td><td className="p-2.5 text-slate-300">virt, hostedEdge</td></tr>
              <tr><td className="p-2.5 text-slate-500">12</td><td className="p-2.5 text-emerald-400">/etc/axonwall/vigilante.yaml</td><td className="p-2.5 text-slate-300">vigilante</td></tr>
            </tbody>
          </table>
        </div>
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
            <p>1. [INTENT] User, TUI, or API generates proposed DesiredState bundle from <code className="text-slate-100">/etc/axonwall/*.yaml</code>.</p>
            <p>2. [LINT] Privileged agent executes pre-flight syntax validation: <code className="text-slate-100">nft -c -f /tmp/proposed.nft</code></p>
            <p>3. [APPLY &amp; ARM] Rules applied atomically to kernel; watchdog timer armed (default: 60–120s; <code className="text-slate-100">axonwallctl apply</code> defaults to 120s).</p>
            <p>4. [QUORUM CHECK] Browser client or <code className="text-slate-100">axonwallctl confirm</code> sends explicit confirmation.</p>
            <p>5. [COMMIT OR REVERT] If confirmed, bundle is persisted &amp; committed to GitOps; if session drops, daemon reverts to <code className="text-emerald-400">last-known-good.nft</code> automatically.</p>
          </div>
        </div>

        <Callout type="tip" title="Fail-Safe Verification">
          Even if an administrator makes a mistake that drops all WAN/LAN connections, simply waiting 60–120 seconds guarantees that the firewall will cleanly roll back to the previously functioning ruleset without needing physical console access.
        </Callout>
      </section>

      {/* Boot & Partition Architectures */}
      <section id="ab-dual-root" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <RefreshCw className="w-6 h-6 text-emerald-400" /> Three Boot &amp; Update Architectures: A/B Dual-Root, ZFSBootMenu &amp; Rolling
        </h2>
        <p className="text-xs text-slate-400 leading-relaxed">
          Axonwall supports three installation and firmware lifecycle architectures selectable in <code className="text-emerald-400 font-mono">axonwall-console --install</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-emerald-400">1. A/B Dual-Root Slots (Default)</div>
            <p className="text-slate-400 leading-relaxed">
              Two identical ext4 partitions (<code className="text-slate-200 font-mono">axon_root_a</code> and{' '}
              <code className="text-slate-200 font-mono">axon_root_b</code>, optionally mirrored via <code className="text-slate-200 font-mono">mdadm</code> RAID-1)
              with background OTA staging (<code className="text-slate-200 font-mono">axonwallctl update</code>) and GRUB bootcount fallback.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-cyan-400">2. ZFSBootMenu Root-on-ZFS</div>
            <p className="text-slate-400 leading-relaxed">
              Boots directly from <code className="text-slate-200 font-mono">zroot/ROOT/*</code> OpenZFS Boot Environments across Stripe, Mirror, RAID-Z, or dRAID topologies with zero-copy snapshot clones (<code className="text-slate-200 font-mono">axonwallctl zbm</code>) and pre-boot watchdog revert.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-sky-400">3. Rolling Single-Root</div>
            <p className="text-slate-400 leading-relaxed">
              Traditional single-partition Debian/Ubuntu Linux layout (<code className="text-slate-200 font-mono">axonwallctl update --apt</code>) for operators managing standard VM templates or package-driven fleets.
            </p>
          </div>
        </div>

        <CodeBlock
          title="A/B Dual-Root Disk Partition Scheme"
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
            Upon booting an upgraded rootfs slot or ZFS Boot Environment, the privileged daemon <code className="text-emerald-400 font-mono">axonwalld</code> validates three critical subsystem health checks before committing the boot slot:
          </p>
          <ol className="list-decimal list-inside space-y-1.5 ml-2 text-xs text-slate-300">
            <li><strong>Network Carrier Status:</strong> Loopback (<code className="text-slate-100">lo</code>) and physical link carrier states.</li>
            <li><strong>nftables Subsystem:</strong> Kernel netfilter tables and rule compilation health.</li>
            <li><strong>Control Plane IPC Quorum:</strong> Local Unix socket responsiveness (<code className="text-slate-100">/run/axonwall/agent.sock</code> and <code className="text-slate-100">/run/axonwall/agent-api.sock</code>).</li>
          </ol>
          <p className="text-xs text-slate-400">
            If any check fails or the system experiences a kernel panic during boot, GRUB or ZFSBootMenu increments <code className="text-slate-200">bootcount</code>. After 3 failed attempts, the bootloader automatically falls back to the previous healthy slot or Boot Environment.
          </p>
        </div>
      </section>

      {/* Privileged Daemon */}
      <section id="daemon" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> Privileged Go Daemon (axonwalld), IPC Security &amp; Ring-0 eBPF
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Security best practices dictate that web applications should never run as root. The Next.js Web Console and Node.js controller run with restricted unprivileged credentials (<code className="text-slate-200 font-mono">axonwall-api</code> group) and communicate with <code className="text-emerald-400 font-mono">axonwalld</code> exclusively over isolated Unix domain sockets:
        </p>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs text-slate-300 space-y-2">
          <div>
            <span className="text-slate-500">HTTP/SSE REST Socket:</span>{' '}
            <code className="text-emerald-400">/run/axonwall/agent-api.sock</code> (mode <code className="text-slate-200">0660 root:axonwall-api</code>, authenticated via 32-byte <code className="text-amber-300">/etc/axonwall/agent.token</code> in <code className="text-slate-200">X-Axonwall-Agent-Token</code>)
          </div>
          <div>
            <span className="text-slate-500">Internal gRPC Socket:</span>{' '}
            <code className="text-emerald-400">/run/axonwall/agent.sock</code> (high-throughput local control-plane RPC &amp; CLI bridge)
          </div>
          <div>
            <span className="text-slate-500">Root-Only HA Control Socket:</span>{' '}
            <code className="text-emerald-400">/run/axonwall/ha.sock</code> (mode <code className="text-slate-200">0600 root:root</code>, isolated for Keepalived/VRRP state transitions)
          </div>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          In addition to atomic <code className="text-slate-200 font-mono">nftables</code> compilation, HWMON sensor polling, optical DOM reads, OpenZFS <code className="text-slate-200 font-mono">/proc/spl/kstat/zfs</code> ARC/L2ARC/ZIL telemetry, and Etckeeper GitOps commits, <code className="text-emerald-400 font-mono">axonwalld</code> attaches native <strong>Dual-Stack IPv4/IPv6 + 802.1Q/802.1ad QinQ VLAN XDP programs</strong> (<code className="text-slate-200 font-mono">BPF_MAP_TYPE_LRU_HASH</code> flow tables, <code className="text-slate-200 font-mono">BPF_MAP_TYPE_LPM_TRIE</code> CIDR subnet + exact-host monotonic TTL <code className="text-slate-200 font-mono">XDP_DROP</code> blocklists, and per-source Ring-0 TCP SYN-flood PPS rate limiting before <code className="text-slate-200 font-mono">sk_buff</code> allocation), alongside <strong>5 CO-RE BPF-LSM kernel hooks</strong> (<code className="text-slate-200 font-mono">lsm/socket_bind</code>, <code className="text-slate-200 font-mono">lsm/bpf</code>, <code className="text-slate-200 font-mono">lsm/uring_sqpoll</code>, <code className="text-slate-200 font-mono">lsm/bpf_token_create</code>, <code className="text-slate-200 font-mono">lsm/bpf_token_cmd</code>) guarding <code className="text-slate-200 font-mono">AF_ALG</code>, <code className="text-slate-200 font-mono">BPF_PROG_LOAD</code>, <code className="text-slate-200 font-mono">io_uring</code> SQPOLL, and Linux 6.9+ unprivileged <code className="text-slate-200 font-mono">BPF_TOKEN_CREATE</code> UserNS delegation.
        </p>
      </section>
    </div>
  );
}
