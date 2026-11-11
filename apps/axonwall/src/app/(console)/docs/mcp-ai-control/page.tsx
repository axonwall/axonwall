import React from 'react';
import Link from 'next/link';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';
import {
  Sparkles,
  Lock,
  Shield,
  ShieldAlert,
  Activity,
  CheckCircle2,
  Database,
  KeyRound,
} from 'lucide-react';

export const metadata = {
  title: 'MCP Security AI Control Plane & Guardrailed Tactical Response | Axonwall Documentation',
  description:
    'Technical documentation for the Axonwall Model Context Protocol (MCP) Server: disabled-by-default kill switch, 16 cryptographic scopes, 16 read-only MCP resources, 25 guardrailed MCP tools across Firewall, Linux 6.9+ BPF_TOKEN_CREATE eBPF + LPM CIDR/SYN-Flood XDP, KVM/LXC Virtualization, K3s Kubernetes, OpenZFS NAS, and 9-Vendor Migration.',
};

export default function McpAiControlDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-950/60 border border-purple-500/30 text-purple-300 text-xs font-semibold">
          <Sparkles className="w-3.5 h-3.5" /> Model Context Protocol (MCP) • Guardrailed Kernel SecOps
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          MCP Security AI Server &amp; Guardrailed Tactical Response
        </h1>
        <p className="text-base text-slate-400 leading-relaxed max-w-3xl">
          Axonwall embeds a native <strong className="text-white">Model Context Protocol (MCP)</strong> server—available
          both over JSON-RPC 2.0 <code className="text-emerald-400 font-mono">axonwall-mcp</code> stdio and HTTPS/SSE at{' '}
          <code className="text-emerald-400 font-mono">/api/v1/mcp</code>—so autonomous SOC agents, Antigravity, Claude
          Code, and the{' '}
          <Link href="/docs/eluvix-ai-router#harnesses" className="text-emerald-400 hover:text-emerald-300 underline underline-offset-4">
            Eluvix Harness Mesh
          </Link>{' '}
          can inspect live telemetry and execute surgical threat containment without ever risking management lockout,
          shell injection, or unrevoked firewall drift.
        </p>
      </div>

      {/* 1. Disabled-by-Default Kill Switch & Cryptographic Auth */}
      <section id="kill-switch-auth" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <KeyRound className="w-6 h-6 text-emerald-400" /> 1. Disabled-by-Default Master Kill Switch &amp; Scoped Auth
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Giving an AI model access to a perimeter firewall demands fail-closed governance. Both the TypeScript
          controller (<code className="text-slate-200 font-mono">getMcpServerStatus()</code>) and the Go kernel daemon (
          <code className="text-slate-200 font-mono">IsMcpSubsystemEnabled()</code>) ship{' '}
          <strong className="text-white">disabled by default (<code className="font-mono">false</code>)</strong> in{' '}
          <code className="text-slate-200 font-mono">/var/lib/axonwall/mcp-settings.json</code>, with an unconditional
          process-level kill switch via <code className="text-rose-400 font-mono">AXONWALL_DISABLE_MCP=1</code>.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-emerald-400 text-sm flex items-center gap-2">
              <Lock className="w-4 h-4" /> SHA-256 Hashed Bearer Keys &amp; mTLS Pinning
            </div>
            <p className="text-slate-400 leading-relaxed">
              API keys follow the format <code className="text-slate-200 font-mono">axw_mcp_&lt;id&gt;_&lt;64hex&gt;</code>.
              Plaintext secrets are shown once at mint time; only <code className="text-slate-200 font-mono">secretHashSha256</code>{' '}
              is persisted in <code className="text-slate-200 font-mono">/var/lib/axonwall/mcp-keys.json</code>. Each
              key enforces optional <code className="text-slate-200 font-mono">allowedSourceCidrs</code>, client TLS
              certificate SHA-256 pinning (<code className="text-slate-200 font-mono">mtlsCertFingerprintSha256</code>),
              and sliding-window <code className="text-slate-200 font-mono">rateLimitPerMinute</code> /{' '}
              <code className="text-slate-200 font-mono">maxActiveLeases</code> quotas.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-sky-400 text-sm flex items-center gap-2">
              <Shield className="w-4 h-4" /> 16 Granular Capability Scopes (5 Duties)
            </div>
            <ul className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-slate-300 font-mono text-[11px] pt-1">
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-emerald-400">mcp:telemetry:read</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-sky-400">mcp:pcap:capture</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-sky-300">mcp:ebpf:read</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-sky-300">mcp:ebpf:manage</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-purple-300">mcp:virt:read</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-purple-300">mcp:virt:manage</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-emerald-300">mcp:k3s:read</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-emerald-300">mcp:k3s:manage</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-amber-300">mcp:nas:read</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-amber-300">mcp:nas:manage</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-rose-400">mcp:traffic:blackhole</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-amber-400">mcp:traffic:shape</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-purple-400">mcp:traffic:redirect</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-emerald-300">mcp:fleet:broadcast</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-amber-300">mcp:firewall:write</li>
              <li className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-rose-300">mcp:firewall:apply</li>
            </ul>
          </div>
        </div>

        <CodeBlock
          title="Master Kill Switch & Emergency Lease Flush via axonwallctl"
          language="bash"
          code={`# Inspect current MCP master switch state, source precedence, and active leases
axonwallctl mcp status

# Explicitly enable the MCP subsystem (can also be toggled in Web Console at /system/mcp)
axonwallctl mcp enable

# Immediately flush all tactical leases without disabling the subsystem
axonwallctl mcp flush

# Emergency disable: blocks all stdio + HTTP/SSE calls and flushes every kernel MCP lease
axonwallctl mcp disable`}
        />
      </section>

      {/* 2. Dual-Layer Blast-Radius & Anti-Lockout Guardrails */}
      <section id="blast-radius" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-rose-400" /> 2. Dual-Layer Blast-Radius &amp; Anti-Lockout Guardrails
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Even if an AI agent suffers a prompt injection or hallucination, Axonwall enforces{' '}
          <strong className="text-white">three independent safety layers</strong>: in TypeScript (
          <code className="text-slate-200 font-mono">packages/axonwall_lib/src/mcp/index.ts</code>), in the privileged Go
          daemon (<code className="text-slate-200 font-mono">apps/axonwalld/engine/mcp_guard.go</code>), and inside the
          kernel via accept-first <code className="text-emerald-400 font-mono">@mcp_protected_v4</code> and{' '}
          <code className="text-emerald-400 font-mono">@mcp_protected_v6</code> nftables sets:
        </p>

        <ul className="space-y-2.5 text-xs text-slate-300">
          <li className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white">1. Default-Route &amp; Prefix Blast-Radius Cap:</strong> Rejects{' '}
            <code className="text-rose-400 font-mono">0.0.0.0/0</code> and <code className="text-rose-400 font-mono">::/0</code>{' '}
            unconditionally, normalizes IPv4-mapped IPv6 bypasses (<code className="font-mono">::ffff:0:0/96</code>), and
            enforces per-key minimum CIDR prefix lengths (default <code className="text-emerald-400 font-mono">/24</code>{' '}
            IPv4 and <code className="text-emerald-400 font-mono">/64</code> IPv6).
          </li>
          <li className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white">2. Protocol, Loopback, Multicast &amp; VRRP Immunity:</strong> Hard-protects{' '}
            <code className="font-mono">127.0.0.0/8</code>, <code className="font-mono">169.254.0.0/16</code>,{' '}
            <code className="font-mono">224.0.0.0/4</code> (preserving VRRP <code className="font-mono">224.0.0.18</code>),{' '}
            <code className="font-mono">::1/128</code>, <code className="font-mono">fe80::/10</code>, and{' '}
            <code className="font-mono">ff00::/8</code>.
          </li>
          <li className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white">3. Live Posture &amp; Self-Lockout Protection:</strong> Dynamically merges
            live OS NIC addresses with <code className="font-mono">/etc/axonwall/state.json</code> and{' '}
            <code className="font-mono">/var/lib/axonwall/state.json</code> interface IPs, CARP/VRRP VIPs, upstream
            gateways, HA peers, and the <strong className="text-slate-200">MCP caller&apos;s own active source IP</strong>.
          </li>
          <li className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
            <strong className="text-white">4. RFC 1918 Toggle &amp; Management Port Shield:</strong> Blocks private East-West
            ranges (<code className="font-mono">10/8</code>, <code className="font-mono">172.16/12</code>,{' '}
            <code className="font-mono">192.168/16</code>, <code className="font-mono">100.64/10</code>,{' '}
            <code className="font-mono">fc00::/7</code>) unless <code className="font-mono">allowInternalRFC1918Targets=true</code>,
            and forbids blocking, shaping, or redirecting anti-lockout ports <code className="text-emerald-400 font-mono">2966</code>,{' '}
            <code className="text-emerald-400 font-mono">22</code>, and <code className="text-emerald-400 font-mono">9876</code>.
          </li>
        </ul>
      </section>

      {/* 3. Ephemeral TTL-Bound Tactical Leases & Kernel Janitor */}
      <section id="tactical-leases" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Activity className="w-6 h-6 text-amber-400" /> 3. Ephemeral TTL-Bound Tactical Leases &amp; Self-Healing Janitor
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Tactical AI interventions never mutate <code className="text-slate-200 font-mono">/etc/axonwall/firewall.yaml</code>{' '}
          or the primary <code className="text-slate-200 font-mono">table inet axonwall</code> ruleset. Instead,{' '}
          <code className="text-emerald-400 font-mono">McpTrafficManager</code> (<code className="text-slate-200 font-mono">engine/mcp_traffic.go</code>)
          compiles an isolated <code className="text-emerald-400 font-mono">table inet axonwall_mcp</code> ruleset,
          pre-validates every transaction via dry-run <code className="text-slate-200 font-mono">nft -c -f -</code>, and
          runs a <strong className="text-white">10-second background Go janitor</strong> that automatically reaps expired
          leases (with dirty-state retry if a kernel reload transiently fails):
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-rose-400 font-mono">mcp_blackhole_traffic</div>
            <p className="text-slate-400 leading-relaxed">
              Drops/rejects L3/L4 traffic in <code className="font-mono">inet axonwall_mcp</code> or installs a kernel{' '}
              <code className="font-mono">route_blackhole</code>, immediately severs established C2 sockets via{' '}
              <code className="text-slate-200 font-mono">conntrack -D</code>, and optionally broadcasts the block across
              all connected satellite/Edge nodes.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-amber-400 font-mono">mcp_shape_traffic</div>
            <p className="text-slate-400 leading-relaxed">
              Allocates a collision-free <code className="font-mono">ClassID</code> (<code className="font-mono">500–9000</code>)
              to throttle suspected exfiltration bandwidth via Linux <code className="font-mono">tc</code> HTB, inject
              tarpit delay/jitter/loss via <code className="font-mono">netem</code>, and stamp DSCP codepoints.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-purple-400 font-mono">mcp_redirect_traffic</div>
            <p className="text-slate-400 leading-relaxed">
              Steers only a specific attacker&apos;s flows via <code className="font-mono">dnat_honeypot</code> or{' '}
              <code className="font-mono">policy_route</code> toward isolated traps explicitly listed in the key&apos;s{' '}
              <code className="text-slate-200 font-mono">allowedRedirectTargets</code> allowlist.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-sky-400 font-mono">mcp_sinkhole_dns &amp; mcp_capture_packet_sample</div>
            <p className="text-slate-400 leading-relaxed">
              Writes TTL-bounded Unbound RPZ overrides (<code className="font-mono">/etc/unbound/unbound.conf.d/mcp-sinkhole.conf</code>)
              while protecting internal appliance domains, plus strictly bounded BPF captures (max{' '}
              <code className="font-mono">100</code> packets / <code className="font-mono">15s</code>).
            </p>
          </div>
        </div>
      </section>

      {/* 4. Persistent Firewall Rule Proposals with Mandatory Commit-Confirm */}
      <section id="persistent-rules" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <CheckCircle2 className="w-6 h-6 text-emerald-400" /> 4. Persistent Rule Proposals &amp; Mandatory Commit-Confirm
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          When permanent policy hardening is warranted, <code className="text-emerald-400 font-mono">mcp_propose_firewall_rule</code>{' '}
          acquires an exclusive state lockfile, validates the rule against <code className="text-slate-200 font-mono">FirewallRuleSchema</code>,
          and stages block/reject rules cleanly ahead of pass rules. If <code className="text-slate-200 font-mono">applyImmediately: true</code>{' '}
          is requested (requiring <code className="text-slate-200 font-mono">mcp:firewall:apply</code>),{' '}
          <code className="text-slate-200 font-mono">axonwalld</code> arms a mandatory{' '}
          <strong className="text-white">60–600 second Commit-Confirm watchdog</strong> (<code className="text-slate-200 font-mono">confirmTimeoutSeconds</code>,
          default <code className="text-slate-200 font-mono">120s</code>) and returns a unique{' '}
          <code className="text-emerald-400 font-mono">jobId</code>. Unless the agent (or a human operator) confirms
          reachability via <code className="text-emerald-400 font-mono">mcp_confirm_apply</code> before the timer expires,
          the daemon automatically rolls the kernel ruleset and YAML state back to last-known-good.
        </p>
      </section>

      {/* 5. Complete Resource & Tool Catalog + Hash-Chained Audit Trail */}
      <section id="catalog-audit" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-sky-400" /> 5. Complete Catalog (16 Resources &amp; 25 Tools) &amp; Audit Chain
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Every mutating tool requires structured <code className="text-slate-200 font-mono">audit</code> provenance (
          <code className="text-slate-200 font-mono">reason</code> &ge; 10 chars, optional{' '}
          <code className="text-slate-200 font-mono">incidentId</code>, MITRE ATT&amp;CK{' '}
          <code className="text-slate-200 font-mono">mitreTechniqueId</code> e.g. <code className="font-mono">T1071.001</code>,
          and <code className="text-slate-200 font-mono">confidence</code>). Every allowed, denied, or failed call is
          appended under lockfile serialization into <code className="text-emerald-400 font-mono">/var/lib/axonwall/mcp-audit.jsonl</code>{' '}
          with SHA-256 <code className="text-slate-200 font-mono">prevHash</code> &rarr;{' '}
          <code className="text-slate-200 font-mono">entryHash</code> chaining verified continuously by{' '}
          <code className="text-slate-200 font-mono">verifyMcpAuditChain()</code>.
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-300">
                <th className="py-3 px-4 font-bold">MCP Resource URI (16 Total)</th>
                <th className="py-3 px-4 font-bold">Payload Summary &amp; Read Scope</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-400">axonwall://system/overview</td>
                <td className="py-2.5 px-4">Appliance status, protected posture IPs/ports, and calling key policy limits (<code className="font-mono">mcp:telemetry:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-400">axonwall://telemetry/interfaces</td>
                <td className="py-2.5 px-4">Live RX/TX bytes, packets, drops, and errors across firewall interfaces (<code className="font-mono">mcp:telemetry:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-400">axonwall://telemetry/alerts/suricata</td>
                <td className="py-2.5 px-4">Recent Suricata IDS/IPS EVE JSON alerts and protocol anomalies (<code className="font-mono">mcp:telemetry:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-400">axonwall://telemetry/flows/top</td>
                <td className="py-2.5 px-4">Top active Linux kernel conntrack sessions ranked by byte volume (<code className="font-mono">mcp:telemetry:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-sky-400">axonwall://firewall/tactical-leases</td>
                <td className="py-2.5 px-4">All active TTL-bounded blackholes, tc shapers, DNAT redirects, and DNS sinkholes (<code className="font-mono">mcp:telemetry:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-sky-400">axonwall://firewall/ruleset-summary</td>
                <td className="py-2.5 px-4">Redacted summary of declarative firewall rules, NAT mappings, aliases, and QoS (<code className="font-mono">mcp:telemetry:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-purple-400">axonwall://topology/nastymap</td>
                <td className="py-2.5 px-4">Discovered LAN/OPT hosts, ARP neighbor table, and active Kea DHCP leases (<code className="font-mono">mcp:telemetry:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-amber-400">axonwall://audit/mcp-trail</td>
                <td className="py-2.5 px-4">Recent SHA-256 hash-chained audit entries plus <code className="font-mono">verifyMcpAuditChain()</code> status.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-sky-300">axonwall://ebpf/dataplane</td>
                <td className="py-2.5 px-4">Dual-stack IPv4/IPv6 + 802.1Q/802.1ad VLAN XDP verdict counters, LPM CIDR blocks, SYN-flood PPS shield, and 5-hook BPF-LSM status (<code className="font-mono">mcp:ebpf:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-sky-300">axonwall://ebpf/bpf-tokens</td>
                <td className="py-2.5 px-4">Linux 6.9+ <code className="font-mono">BPF_TOKEN_CREATE</code> capability report, presets, and active <code className="font-mono">bpffs</code> delegation mounts (<code className="font-mono">mcp:ebpf:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-purple-300">axonwall://virt/workloads</td>
                <td className="py-2.5 px-4">KVM/QEMU VM &amp; LXC container inventory, IOMMU groups, vnet/TAP XDP telemetry, and LXC token mounts (<code className="font-mono">mcp:virt:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-purple-300">axonwall://virt/libvirt-domains</td>
                <td className="py-2.5 px-4">Rendered canonical Libvirt Domain XML definitions for all configured KVM/QEMU virtual machines (<code className="font-mono">mcp:virt:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-300">axonwall://k3s/cluster</td>
                <td className="py-2.5 px-4">K3s control plane status, nodes, pods, Flannel/Cilium eBPF CNI state, UserNS readiness, and OpenEBS PVCs (<code className="font-mono">mcp:k3s:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-300">axonwall://k3s/etcd-snapshots</td>
                <td className="py-2.5 px-4">Embedded K3s etcd disaster-recovery snapshots (local &amp; S3) with timestamps and sizes (<code className="font-mono">mcp:k3s:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-amber-300">axonwall://nas/storage-telemetry</td>
                <td className="py-2.5 px-4">OpenZFS pool health, Special VDEVs, encryption key status, ARC/L2ARC hit ratios, ZIL/SLOG sync commits, and ZIO queues (<code className="font-mono">mcp:nas:read</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-rose-300">axonwall://security/rootkit-posture</td>
                <td className="py-2.5 px-4">Ring-0 rootkit posture, <code className="font-mono">io_uring</code> rings, trampoline audit, and BPF-LSM denial ring buffer (<code className="font-mono">mcp:ebpf:read</code>).</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-300">
                <th className="py-3 px-4 font-bold">MCP Tool Name (25 Total)</th>
                <th className="py-3 px-4 font-bold">Required Scope</th>
                <th className="py-3 px-4 font-bold">Operational Effect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-400">mcp_query_flows</td>
                <td className="py-2.5 px-4 font-mono">mcp:telemetry:read</td>
                <td className="py-2.5 px-4">Filter live <code className="font-mono">/proc/net/nf_conntrack</code> sessions by IP, port, protocol, state, or minBytes.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-400">mcp_query_threat_events</td>
                <td className="py-2.5 px-4 font-mono">mcp:telemetry:read</td>
                <td className="py-2.5 px-4">Search Suricata EVE threat alerts and active SOAR/MCP blocklists.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-400">mcp_inspect_host_context</td>
                <td className="py-2.5 px-4 font-mono">mcp:telemetry:read</td>
                <td className="py-2.5 px-4">360&deg; single-IP forensics: ARP MAC, DHCP hostname, flows, IDS alerts, and leases.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-sky-400">mcp_capture_packet_sample</td>
                <td className="py-2.5 px-4 font-mono">mcp:pcap:capture</td>
                <td className="py-2.5 px-4">Bounded live BPF packet capture (1–100 packets, 1–15s timeout).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-rose-400">mcp_blackhole_traffic</td>
                <td className="py-2.5 px-4 font-mono">mcp:traffic:blackhole</td>
                <td className="py-2.5 px-4">TTL-bounded nft drop/reject or blackhole route + <code className="font-mono">conntrack -D</code> (+ optional fleet broadcast).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-amber-400">mcp_shape_traffic</td>
                <td className="py-2.5 px-4 font-mono">mcp:traffic:shape</td>
                <td className="py-2.5 px-4">TTL-bounded Linux <code className="font-mono">tc</code> HTB rate limit, <code className="font-mono">netem</code> tarpit delay/loss, and DSCP mark.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-purple-400">mcp_redirect_traffic</td>
                <td className="py-2.5 px-4 font-mono">mcp:traffic:redirect</td>
                <td className="py-2.5 px-4">Attacker-scoped DNAT honeypot or policy-route steering to <code className="font-mono">allowedRedirectTargets</code>.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-purple-400">mcp_sinkhole_dns</td>
                <td className="py-2.5 px-4 font-mono">mcp:traffic:redirect</td>
                <td className="py-2.5 px-4">TTL-bounded Unbound DNS local-zone C2/phishing domain sinkhole.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-slate-200">mcp_revert_lease</td>
                <td className="py-2.5 px-4 font-mono">matching lease scope</td>
                <td className="py-2.5 px-4">Immediately remove a single tactical lease from kernel &amp; Unbound by <code className="font-mono">leaseId</code>.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-rose-300">mcp_emergency_clear_all</td>
                <td className="py-2.5 px-4 font-mono">any traffic scope</td>
                <td className="py-2.5 px-4">Panic flush of all active MCP blackholes, shapers, redirects, and DNS sinkholes.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-amber-300">mcp_propose_firewall_rule</td>
                <td className="py-2.5 px-4 font-mono">mcp:firewall:write</td>
                <td className="py-2.5 px-4">Stage persistent rule into DesiredState; optional Commit-Confirm apply returning <code className="font-mono">jobId</code>.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-300">mcp_confirm_apply</td>
                <td className="py-2.5 px-4 font-mono">mcp:firewall:apply</td>
                <td className="py-2.5 px-4">Confirm <code className="font-mono">jobId</code> within the 60–600s safety window to prevent auto-rollback.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-sky-300">mcp_inspect_ebpf_dataplane</td>
                <td className="py-2.5 px-4 font-mono">mcp:ebpf:read</td>
                <td className="py-2.5 px-4">Inspect unified Ring-0 XDP dual-stack/VLAN/LPM CIDR stats, SYN-flood PPS shield, BPF-LSM hooks, and <code className="font-mono">BPF_TOKEN</code> mounts.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-rose-400">mcp_xdp_fast_drop</td>
                <td className="py-2.5 px-4 font-mono">mcp:ebpf:manage</td>
                <td className="py-2.5 px-4">Line-rate NIC driver <code className="font-mono">XDP_DROP</code> for IPv4/IPv6 hosts &amp; LPM Trie CIDR subnets (<code className="font-mono">block</code>/<code className="font-mono">unblock</code>) plus Ring-0 TCP SYN-flood PPS rate limiter (<code className="font-mono">set_syn_limit</code>, &ge; 100 PPS self-DoS floor).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-sky-300">mcp_manage_bpf_token_profile</td>
                <td className="py-2.5 px-4 font-mono">mcp:ebpf:manage</td>
                <td className="py-2.5 px-4">Mount or delete delegated Linux 6.9+ <code className="font-mono">bpffs</code> profiles (vetoes <code className="font-mono">kprobe/tracepoint/lsm</code>).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-purple-300">mcp_inspect_virt_workloads</td>
                <td className="py-2.5 px-4 font-mono">mcp:virt:read</td>
                <td className="py-2.5 px-4">Inspect QEMU/KVM VMs, LXC containers, IOMMU groups, and vnet/TAP XDP telemetry.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-purple-300">mcp_control_virt_workload</td>
                <td className="py-2.5 px-4 font-mono">mcp:virt:manage</td>
                <td className="py-2.5 px-4">Lifecycle &amp; enterprise VM ops: <code className="font-mono">start</code>, <code className="font-mono">stop</code>, <code className="font-mono">reboot</code>, <code className="font-mono">snapshot</code>, <code className="font-mono">rollback</code>, <code className="font-mono">clone</code> (ZFS zero-copy), <code className="font-mono">live_migrate</code>, <code className="font-mono">backup</code>, <code className="font-mono">restore</code>, <code className="font-mono">qga_interfaces</code>, and <code className="font-mono">export_libvirt_xml</code>.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-purple-300">mcp_configure_lxc_bpf_token</td>
                <td className="py-2.5 px-4 font-mono">mcp:virt:manage</td>
                <td className="py-2.5 px-4">Declaratively bind or revoke safe <code className="font-mono">BPF_TOKEN</code> delegation on an unprivileged LXC container.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-300">mcp_inspect_k3s_cluster</td>
                <td className="py-2.5 px-4 font-mono">mcp:k3s:read</td>
                <td className="py-2.5 px-4">Inspect K3s control plane, nodes, pods, Flannel/Cilium eBPF CNI state, UserNS readiness, and OpenEBS PVCs.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-300">mcp_render_k3s_bpf_token_manifest</td>
                <td className="py-2.5 px-4 font-mono">mcp:k3s:read / manage</td>
                <td className="py-2.5 px-4">Render (and optionally mount) K3s <code className="font-mono">hostUsers: false</code> Pod/DaemonSet YAML with <code className="font-mono">LIBBPF_BPF_TOKEN_PATH</code>.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-emerald-300">mcp_manage_k3s_cluster</td>
                <td className="py-2.5 px-4 font-mono">mcp:k3s:read / manage</td>
                <td className="py-2.5 px-4">List, create (<code className="font-mono">etcd_snapshot_save</code>), or restore (<code className="font-mono">etcd_snapshot_restore</code>) embedded K3s etcd snapshots, or switch CNI mode (<code className="font-mono">flannel</code> vs <code className="font-mono">cilium-ebpf</code>) via Commit-Confirm.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-amber-300">mcp_inspect_nas_storage</td>
                <td className="py-2.5 px-4 font-mono">mcp:nas:read</td>
                <td className="py-2.5 px-4">Inspect OpenZFS pools, Special VDEVs, encrypted datasets, shares, ARC/L2ARC hit ratios, ZIL commits, and ZIO queues.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-amber-300">mcp_nas_snapshot_or_scrub</td>
                <td className="py-2.5 px-4 font-mono">mcp:nas:manage</td>
                <td className="py-2.5 px-4">Execute atomic ZFS <code className="font-mono">snapshot</code>, <code className="font-mono">rollback</code>, <code className="font-mono">delete_snapshot</code>, and pool <code className="font-mono">scrub</code> (Root-on-ZFS <code className="font-mono">zroot/rpool</code> protected).</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-amber-300">mcp_manage_zfs_nas</td>
                <td className="py-2.5 px-4 font-mono">mcp:nas:manage</td>
                <td className="py-2.5 px-4">Unified enterprise OpenZFS NAS lifecycle tool: <code className="font-mono">trim</code>, pool <code className="font-mono">checkpoint</code>/<code className="font-mono">discard_checkpoint</code>, <code className="font-mono">unlock_dataset</code>/<code className="font-mono">lock_dataset</code>, S.M.A.R.T. <code className="font-mono">smart_test</code>, and encrypted <code className="font-mono">cloud_sync</code>.</td>
              </tr>
              <tr>
                <td className="py-2.5 px-4 font-mono text-teal-300">mcp_import_competitor_config</td>
                <td className="py-2.5 px-4 font-mono">mcp:firewall:write (+ role scopes)</td>
                <td className="py-2.5 px-4">Dry-run parse or non-destructively stage configs from all 9 vendors (<code className="font-mono">pfSense</code>, <code className="font-mono">OPNsense</code>, <code className="font-mono">Proxmox VE</code>, <code className="font-mono">TrueNAS SCALE</code>, <code className="font-mono">Cisco ASA</code>, <code className="font-mono">VyOS</code>, <code className="font-mono">MikroTik</code>, <code className="font-mono">iptables</code>, <code className="font-mono">firewalld</code>) with cross-role RBAC checks &amp; Commit-Confirm.</td>
              </tr>
            </tbody>
          </table>
        </div>

        <CodeBlock
          title="Connecting Antigravity, Claude Code, or Eluvix Harness Mesh (stdio & HTTP/SSE)"
          language="json"
          code={`{
  "mcpServers": {
    "axonwall-ssh-stdio": {
      "command": "ssh",
      "args": [
        "secops@10.0.0.1",
        "axonwall-mcp"
      ],
      "env": {
        "AXONWALL_MCP_TOKEN": "axw_mcp_7f3a9b_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      }
    },
    "axonwall-https": {
      "url": "https://10.0.0.1:2966/api/v1/mcp",
      "headers": {
        "Authorization": "Bearer axw_mcp_7f3a9b_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      }
    }
  }
}`}
        />

        <Callout type="tip" title="Manage Scoped Keys, Live Leases & Hash-Chained Audit Logs">
          Mint scoped <code className="font-mono text-emerald-300">axw_mcp_*</code> keys, configure honeypot redirect
          allowlists, inspect countdown timers on active leases, and verify the SHA-256 audit chain in the Web Console
          at <code className="font-mono text-emerald-300">/system/mcp</code>.
        </Callout>
      </section>
    </div>
  );
}
