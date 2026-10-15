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
          Perimeter Security
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Threat Defense & DNS Intelligence
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall implements a multi-layered perimeter security engine combining dynamic <code className="text-emerald-400 font-mono">nftables</code> IP blocklist sets, an autonomous <code className="text-white font-mono">Unbound RPZ</code> DNS sinkhole, Suricata 7+ IPS, and CrowdSec intrusion defense.
        </p>
      </div>

      {/* Dynamic Threat Feeds */}
      <section id="threat-feeds" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Globe className="w-6 h-6 text-emerald-400" /> Dynamic Threat Feeds & nftables Interval Sets
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Traditional firewalls update aliases by reloading thousands of individual packet filter rules, exhausting CPU and causing micro-outages. Axonwall aggregates intelligence feeds (Spamhaus DROP, AbuseIPDB, FireHOL, Emerging Threats) into high-performance Linux kernel <code className="text-emerald-400 font-mono">interval sets</code>.
        </p>

        <div className="space-y-4">
          <h3 className="text-base font-semibold text-white">CIDR Normalization & Interval Minimization</h3>
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
        </div>
      </section>

      {/* DNS Sinkhole & RPZ */}
      <section id="dns-sinkhole" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Ban className="w-6 h-6 text-emerald-400" /> DNS Sinkhole & Unbound RPZ Compiler
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Malware, phishing, and ad-tracking domains are neutralized at the DNS query resolution stage before any TCP/UDP connection can be initialized. Axonwall compiles domain blocklists into native <strong>Response Policy Zone (RPZ)</strong> format according to RFC 7766.
        </p>

        <div className="space-y-4">
          <h3 className="text-base font-semibold text-white">Subdomain Pruning Optimization</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Public blocklists often contain hundreds of thousands of redundant subdomains (e.g. <code className="text-slate-200">tracker.ads.evil.com</code> alongside <code className="text-slate-200">evil.com</code>). Axonwall&apos;s RPZ compiler prunes these redundant entries, reducing memory consumption by over 65%:
          </p>

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
        </div>
      </section>

      {/* Suricata & CrowdSec */}
      <section id="suricata-crowdsec" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Radio className="w-6 h-6 text-emerald-400" /> Suricata 7+ IPS & CrowdSec Security Engine
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-emerald-400" /> Suricata 7+ Deep Packet Inspection
            </h3>
            <p className="text-slate-400 leading-relaxed">
              Operates in inline IPS mode utilizing Linux AF_PACKET multi-queue ring buffers with eBPF/XDP hardware bypass. Inspects application payloads, TLS SNI certificates, and detects protocol anomalies at line-rate.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <Zap className="w-4 h-4 text-emerald-400" /> CrowdSec Community Cyber Defense
            </h3>
            <p className="text-slate-400 leading-relaxed">
              Analyzes authentication logs and firewall drop events using behavioral heuristics (SSH brute-force, web port scanning, API credential stuffing). Automatically exchanges verified IP remediation decisions with the global CrowdSec intelligence community.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
