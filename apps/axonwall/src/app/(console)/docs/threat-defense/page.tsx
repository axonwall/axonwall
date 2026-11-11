import React from 'react';
import Link from 'next/link';
import { ShieldAlert, Globe, Ban, Radio, CheckCircle2, Zap, Layers } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Threat Defense & DNS Sinkhole | Axonwall Documentation',
  description:
    'Deep-dive into Axonwall Threat Defense: Dynamic IP blocklists with CIDR interval minimization, Unbound DNS RPZ sinkhole with subdomain pruning, Suricata 7+ IPS, and CrowdSec.',
};

export default function ThreatDefenseDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Perimeter Security • v0.11.64
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Threat Defense &amp; DNS Intelligence
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall implements a multi-layered perimeter security engine combining eBPF XDP volumetric flood mitigation, dynamic <code className="text-emerald-400 font-mono">nftables</code> IP blocklist &amp; GeoIP sets, an autonomous <code className="text-white font-mono">Unbound RPZ</code> DNS sinkhole, Suricata 7+ IPS, and CrowdSec intrusion defense.
        </p>
      </div>

      {/* Dynamic Threat Feeds */}
      <section id="threat-feeds" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Globe className="w-6 h-6 text-emerald-400" /> Dynamic Threat Feeds, XDP DDoS Drop &amp; nftables Interval Sets
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Traditional firewalls update aliases by reloading thousands of individual packet filter rules, exhausting CPU and causing micro-outages. Axonwall combines Ring-0 <strong>Dual-Stack IPv4/IPv6 + 802.1Q/802.1ad QinQ VLAN XDP fast-drop</strong> (autonomously dropping external flood source IPs exceeding <code className="text-emerald-400 font-mono">50,000 pps</code> or monotonic TTL-bounded <code className="text-emerald-400 font-mono">blocklist_map</code> / <code className="text-emerald-400 font-mono">blocklist6_map</code> entries in driver NIC memory before <code className="text-slate-200 font-mono">sk_buff</code> allocation) with aggregated intelligence feeds (Spamhaus DROP, AbuseIPDB, FireHOL, Emerging Threats) compiled into high-performance Linux kernel <code className="text-emerald-400 font-mono">interval sets</code>.
        </p>

        <section id="cidr-optimization" className="space-y-4">
          <h3 className="text-base font-semibold text-white">CIDR Normalization &amp; Interval Minimization</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Raw threat feeds frequently contain redundant, overlapping, or fragmented IP allocations. Axonwall&apos;s feed compiler runs an intelligent normalization algorithm:
          </p>
          <ul className="list-disc list-inside text-xs text-slate-300 space-y-1.5 ml-2">
            <li><strong>Syntax Sanitization:</strong> Validates IPv4 and IPv6 CIDRs, dropping malformed entries.</li>
            <li><strong>Subsumption Pruning:</strong> Automatically collapses child subnets into parent CIDRs (e.g., <code className="text-slate-100">198.51.100.0/24</code> absorbs <code className="text-slate-100">198.51.100.128/25</code>).</li>
            <li><strong>Contiguous Coalescing:</strong> Adjacent matching prefixes are combined into supernets.</li>
          </ul>

          <CodeBlock
            title="Kernel Set Definition"
            language="nftables"
            code={`table inet axonwall {
  # Interval set with auto-merge hardware tree lookup
  set threat_feed_ips {
    type ipv4_addr
    flags interval
    auto-merge
    elements = {
      1.10.16.0/20,
      1.19.0.0/16,
      14.136.0.0/15
    }
  }

  chain prerouting {
    type filter hook prerouting priority -150; policy accept;
    # Instant kernel-level packet drop before conntrack state creation
    ip saddr @threat_feed_ips counter drop
    ip daddr @threat_feed_ips counter drop
  }
}`}
          />
        </section>
      </section>

      {/* DNS Sinkhole & RPZ */}
      <section id="dns-sinkhole" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Ban className="w-6 h-6 text-emerald-400" /> DNS Sinkhole &amp; Unbound RPZ Compiler
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Malware, phishing, and ad-tracking domains are neutralized at the DNS query resolution stage before any TCP/UDP connection can be initialized. Configured under <code className="text-emerald-400 font-mono">dns.blocklist</code> in <code className="text-emerald-400 font-mono">/etc/axonwall/services.yaml</code>, Axonwall compiles domain blocklists into native <strong>Response Policy Zone (RPZ)</strong> format according to RFC 7766.
        </p>

        <section id="subdomain-pruning" className="space-y-4">
          <h3 className="text-base font-semibold text-white">Subdomain Pruning Optimization</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Public blocklists often contain hundreds of thousands of redundant subdomains (e.g. <code className="text-slate-200">tracker.ads.evil.com</code> alongside <code className="text-slate-200">evil.com</code>). Axonwall&apos;s RPZ compiler prunes these redundant entries, reducing memory consumption by over 65%:
          </p>

          <CodeBlock
            title="/etc/axonwall/services.yaml — Unbound DNS Blocklist & RPZ Sinkhole"
            language="yaml"
            code={`dns:
  enabled: true
  dnssec: true
  blocklist:
    enabled: true
    refreshIntervalHours: 12
    feeds:
      - name: stevenblack-hosts
        url: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
        enabled: true
      - name: urlhaus-rpz
        url: https://urlhaus.abuse.ch/downloads/rpz/
        enabled: true
    allowlistDomains:
      - telemetry.microsoft.com
    customBlockedDomains:
      - malware-c2.com
      - phishing-login.net`}
          />

          <CodeBlock
            title="/etc/unbound/zones/axonwall-sinkhole.zone"
            language="zonefile"
            code={`$TTL 300
@ IN SOA localhost. hostmaster.axonwall.local. (
  2026101301 ; serial
  3600       ; refresh
  1800       ; retry
  604800     ; expire
  300        ; minimum
)
@ IN NS localhost.

; Strict allowlist overrides (rpz-passthru.)
telemetry.microsoft.com CNAME rpz-passthru.
*.telemetry.microsoft.com CNAME rpz-passthru.

; Sinkholed malware and tracking domains (NXDOMAIN redirect)
malware-c2.com CNAME .
*.malware-c2.com CNAME .
phishing-login.net CNAME .
*.phishing-login.net CNAME .`}
          />

          <Callout type="tip" title="Unbound Integration">
            Axonwall configures Unbound with <code className="text-emerald-300 font-mono">module-config: &quot;respip validator iterator&quot;</code>, allowing microsecond local interception without external upstream DNS latency.
          </Callout>
        </section>
      </section>

      {/* Suricata & CrowdSec */}
      <section id="suricata-crowdsec" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Radio className="w-6 h-6 text-emerald-400" /> Suricata 7+ IPS, CrowdSec &amp; GeoIP (/etc/axonwall/security.yaml)
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-emerald-400" /> Suricata 7+ Deep Packet Inspection
            </h3>
            <p className="text-slate-400 leading-relaxed">
              Operates in inline IPS or IDS mode utilizing Linux AF_PACKET multi-queue ring buffers with eBPF/XDP hardware bypass. Inspects application payloads, TLS SNI/JA4 fingerprints, and detects protocol anomalies at line-rate.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <Zap className="w-4 h-4 text-emerald-400" /> CrowdSec Community Cyber Defense
            </h3>
            <p className="text-slate-400 leading-relaxed">
              Analyzes authentication logs and firewall drop events using behavioral heuristics (SSH brute-force, web port scanning, API credential stuffing) and injects dynamic remediation bans directly into <code className="text-slate-200 font-mono">nftables</code> sets.
            </p>
          </div>
        </div>

        <CodeBlock
          title="/etc/axonwall/security.yaml — Suricata IPS, CrowdSec & GeoIP Policy"
          language="yaml"
          code={`suricata:
  enabled: true
  mode: ips
  interfaces:
    - wan
    - lan
  rulesetAutoUpdate: true

crowdsec:
  enabled: true
  bouncerEnabled: true
  banDurationSeconds: 14400
  collections:
    - crowdsecurity/linux
    - crowdsecurity/sshd
    - crowdsecurity/http-cve

geoip:
  enabled: true
  mode: blocklist
  countries:
    - KP
    - IR
  applyToInterfaces:
    - wan`}
        />

        <Callout type="info" title="Autonomous AI Tactical Leases &amp; Ring-0 XDP Fast-Drop via MCP">
          Security operations agents and LLM SecOps workflows can issue both <strong>TTL-bounded nftables IP blackhole / DNS sinkhole leases</strong> and <strong>pre-sk_buff Dual-Stack IPv4/IPv6 + LPM Trie CIDR XDP_DROP bans</strong> (<code className="font-mono text-emerald-300">mcp_xdp_fast_drop</code> / <code className="font-mono text-emerald-300">axonwallctl ebpf xdp-drop</code>) with built-in RFC 1918 &amp; management-session anti-lockout guards through the 25-tool Axonwall MCP server. See{' '}
          <Link href="/docs/mcp-ai-control" className="font-mono text-emerald-300 underline">/docs/mcp-ai-control</Link> for full tool schemas and lease lifecycles.
        </Callout>
      </section>
    </div>
  );
}
