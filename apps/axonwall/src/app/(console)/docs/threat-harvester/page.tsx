import React from 'react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';
import {
  Activity,
  AlertTriangle,
  Binary,
  Cpu,
  Database,
  Layers,
  Lock,
  ShieldCheck,
  Sparkles,
  Terminal,
} from 'lucide-react';

export const metadata = {
  title: 'Axonwall Blackbox: eBPF Threat-LLM Harvester | Axonwall Documentation',
  description:
    'Architecture, pre-disk DLP privacy guardrails, Crypto-PAn anonymization, multi-oracle labeling, and Dual-Track SFT/RLVR JSONL + Apache Parquet corpus export for ebpf-threat-harvester.',
};

export default function ThreatHarvesterDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-semibold">
          <Binary className="w-3.5 h-3.5" /> Opt-In Plugin • Ring-0 TCX + Tracepoints + Uprobes • SFT/RLVR + Parquet
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Axonwall Blackbox: Extreme eBPF Threat-LLM Harvester
        </h1>
        <p className="text-base text-slate-400 leading-relaxed max-w-3xl">
          <code className="font-mono text-cyan-300">ebpf-threat-harvester</code> is Axonwall&apos;s strictly opt-in Ring-0
          flight recorder and security corpus pipeline (<code className="font-mono text-slate-200">/security/threat-harvester</code>).
          It fuses wire-plane packet kinematics, kernel process/memory-execution lineage, and optional guarded TLS
          cleartext slices into privacy-scrubbed <strong className="text-white">Causal Episode ChatML JSONL</strong> and{' '}
          <strong className="text-white">Apache Parquet 1.0</strong> datasets for training sovereign threat-detection LLMs.
        </p>
      </div>

      {/* 1. Unified Multi-Plane Ring-0 eBPF Flight Recorder */}
      <section id="architecture" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-cyan-400" /> 1. Unified Multi-Plane Ring-0 eBPF Flight Recorder
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Compiled from CO-RE C (<code className="font-mono text-slate-200">apps/axonwalld/ebpf/threat_harvester.c</code>) via{' '}
          <code className="font-mono text-slate-200">bpf2go</code>, the harvester attaches across network and host planes
          simultaneously and joins wire flows to process ancestry using kernel{' '}
          <code className="font-mono text-slate-200">socket_cookie</code>,{' '}
          <code className="font-mono text-slate-200">cgroup_id</code>, and <code className="font-mono text-slate-200">pid</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-semibold text-cyan-300 flex items-center gap-2">
              <Activity className="w-4 h-4" /> Wire Plane (<code className="font-mono">tc_harvester_ingress</code> /{' '}
              <code className="font-mono">tc_harvester_egress</code>)
            </div>
            <ul className="space-y-1 text-slate-300 list-disc pl-4">
              <li>Attached via Linux 6.6+ TCX (<code className="font-mono">link.AttachTCX</code>).</li>
              <li>Records the first 16 signed packet sizes and microsecond inter-arrival deltas (<code className="font-mono">iatUs</code>).</li>
              <li>Extracts passive TCP <code className="font-mono">JA4T</code> options/MSS/scale fingerprints, TLS ClientHello SNI, and DNS label Shannon entropy.</li>
              <li>Captures triggered Tier-1 scrubbed L7 payload slices up to <code className="font-mono">maxPayloadBytes</code> (<code className="font-mono">4096 B</code> default).</li>
            </ul>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-semibold text-amber-300 flex items-center gap-2">
              <Cpu className="w-4 h-4" /> Host / Container Execution &amp; Guarded TLS Plane
            </div>
            <ul className="space-y-1 text-slate-300 list-disc pl-4">
              <li><code className="font-mono text-slate-200">tp_harvester_exec</code> (<code className="font-mono">tracepoint/sched/sched_process_exec</code>): tracks spawning binary &amp; cgroup ownership.</li>
              <li><code className="font-mono text-slate-200">tp_harvester_memfd</code> (<code className="font-mono">tracepoint/syscalls/sys_enter_memfd_create</code>): flags fileless RAM ELF execution in real time.</li>
              <li><code className="font-mono text-slate-200">uprobe_harvester_ssl_write</code> (<code className="font-mono">uprobe/SSL_write</code>): disabled by default; attaches only to allowed non-control-plane binaries or honeypot pods.</li>
            </ul>
          </div>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/60">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Capture Mode</th>
                <th className="py-3 px-4">Tier-0 Sketches &amp; Benign Sampling</th>
                <th className="py-3 px-4">Tier-1 L7 Payload Escalation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              <tr>
                <td className="py-3 px-4 font-mono text-cyan-300 font-semibold">adaptive (default)</td>
                <td className="py-3 px-4">Always records 16-packet flow kinematics + stratified benign negative sampling (<code className="font-mono">benignSampleRate: 0.005</code>).</td>
                <td className="py-3 px-4">Escalates on canary dark-ports (<code className="font-mono">23, 2323, 3389, 4444, 5900, 6379, 9200, 27017</code>), watchlist IPs, <code className="font-mono">memfd_create</code>, or high-entropy DNS.</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-amber-300 font-semibold">firehose</td>
                <td className="py-3 px-4">Captures full flow sketches across specified <code className="font-mono">firehoseInterfaces</code> / <code className="font-mono">firehoseNamespaces</code>.</td>
                <td className="py-3 px-4">Continuous L7 slice harvesting subject to ring-buffer backpressure circuit breaking.</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-emerald-300 font-semibold">honeypot_only</td>
                <td className="py-3 px-4">Minimal overhead metadata mode ignoring standard production flows.</td>
                <td className="py-3 px-4">Harvests strictly dark-port probes and MCP <code className="font-mono">dnat_honeypot</code> targets.</td>
              </tr>
            </tbody>
          </table>
        </div>

        <Callout type="info" title="Kernel Prerequisites Audited by Custom Kernel Studio">
          The 25-check kernel audit includes rule <code className="font-mono">ebpf-tcx-uprobe-harvester</code>, verifying{' '}
          <code className="font-mono">CONFIG_NET_CLS_ACT</code>, <code className="font-mono">CONFIG_NET_SCH_INGRESS</code>,{' '}
          <code className="font-mono">CONFIG_UPROBE_EVENTS</code>, <code className="font-mono">CONFIG_TRACEPOINTS</code>, and{' '}
          <code className="font-mono">CONFIG_FTRACE_SYSCALLS</code> alongside <code className="font-mono">CONFIG_DEBUG_INFO_BTF=y</code>.
        </Callout>
      </section>

      {/* 2. Strict Opt-In, Pre-Disk DLP & Control-Plane Exclusions */}
      <section id="privacy-guardrails" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-emerald-400" /> 2. Opt-In Posture, Pre-Disk DLP &amp; Control-Plane Exclusions
        </h2>

        <Callout type="warning" title="Strictly Opt-In with Hardcoded Control-Plane Safeguards">
          <code className="font-mono">ebpf-threat-harvester</code> ships disabled (<code className="font-mono">defaultEnabled: false</code>).
          Even when enabled, dangerous wildcards (<code className="font-mono">*</code>) in <code className="font-mono">tlsUprobeAllowlist</code>{' '}
          are rejected, and <code className="font-mono">IsBinaryAllowedForTlsUprobe</code> unconditionally blocks attachment to
          control-plane daemons: <code className="font-mono">axonwalld</code>, <code className="font-mono">sshd</code>,{' '}
          <code className="font-mono">eluvix</code>, <code className="font-mono">slapd</code>, <code className="font-mono">vault</code>,{' '}
          <code className="font-mono">minio</code>, <code className="font-mono">k3s</code>, <code className="font-mono">containerd</code>,{' '}
          <code className="font-mono">systemd</code>, and <code className="font-mono">postgres</code>.
        </Callout>

        <ul className="space-y-2 text-xs text-slate-300 list-disc pl-5">
          <li>
            <strong className="text-white">Pre-Disk Structural DLP Redaction (<code className="font-mono">ScrubThreatPayload</code>):</strong>{' '}
            Secrets—including Bearer/JWT tokens, <code className="font-mono">Authorization</code> headers, cookies, API keys
            (<code className="font-mono">sk-*</code>, <code className="font-mono">AKIA*</code>), PEM private key blocks, and
            passwords—are structurally masked before any episode hits disk.
          </li>
          <li>
            <strong className="text-white">Export/Ship Anonymization (<code className="font-mono">CryptoPanAnonymizer</code>):</strong>{' '}
            Prefix-preserving AES-128 Crypto-PAn anonymizes IPv4 and IPv6 addresses (preserving subnet topology across
            packet flows and Causal DSL text) paired with HMAC-SHA256 hostname scrubbing.
          </li>
          <li>
            <strong className="text-white">Backpressure Circuit Breaker:</strong> Monitors ringbuf drops and memory bounds,
            shedding non-essential Tier-1 slices automatically before packet forwarding is impacted.
          </li>
        </ul>
      </section>

      {/* 3. Multi-Oracle Correlation, Teacher-LLM & Review Queue */}
      <section id="oracles-distillation" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Sparkles className="w-6 h-6 text-purple-400" /> 3. 45s Multi-Oracle Correlator &amp; Teacher-LLM Distiller
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-red-500/30 space-y-1.5">
            <div className="font-bold text-red-300">Gold Malicious Oracles</div>
            <p className="text-slate-400 leading-relaxed">
              Canary dark-port hits, active MCP <code className="font-mono">dnat_honeypot</code> tactical leases, and{' '}
              <code className="font-mono">lsm_guard</code> <code className="font-mono">-EPERM</code> Ring-0 blocks. Protected
              from FIFO eviction when <code className="font-mono">pinGoldEpisodes: true</code>.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-amber-500/30 space-y-1.5">
            <div className="font-bold text-amber-300">Silver Malicious Oracles</div>
            <p className="text-slate-400 leading-relaxed">
              Suricata <code className="font-mono">eve.json</code> alerts, XDP/Vigilante SOAR blocks, fileless{' '}
              <code className="font-mono">sys_enter_memfd_create</code> execution, and high-entropy DNS tunneling checks.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-cyan-500/30 space-y-1.5">
            <div className="font-bold text-cyan-300">Teacher-LLM &amp; Operator Curation</div>
            <p className="text-slate-400 leading-relaxed">
              Optional OpenAI-compatible Teacher-LLM (<code className="font-mono">maxCallsPerHour</code> budget) distills
              MITRE ATT&amp;CK chain-of-thought traces; operators curate episodes via{' '}
              <code className="font-mono">/security/threat-harvester</code> (Pin Gold, Approve Malicious, Mark Benign, Delete).
            </p>
          </div>
        </div>
      </section>

      {/* 4. Dual-Track Dataset Format & Vault S3 Lake */}
      <section id="dataset-format" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-emerald-400" /> 4. Dual-Track Corpus Format, ZFS Spool &amp; Vault S3 Shipper
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Spool storage under <code className="font-mono text-slate-200">/var/lib/axonwall/threat-corpus</code> automatically
          provisions a dedicated OpenZFS child dataset with <code className="font-mono text-slate-200">compression=zstd</code> and
          hard <code className="font-mono text-slate-200">refquota</code> when backed by OpenZFS (or byte-capped eviction that
          preserves pinned Gold/reviewed episodes on standard filesystems). Exporting produces a{' '}
          <code className="font-mono text-cyan-300">.tar.zst</code> archive containing:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 font-mono">
            <div className="text-cyan-300 font-bold">train.jsonl &amp; val.jsonl (ChatML SFT / RLVR)</div>
            <p className="text-slate-400 font-sans leading-relaxed">
              Chronological Causal Episode prompts with <code className="font-mono">system</code>, <code className="font-mono">user</code>{' '}
              (flow tuple, JA4T, pktSizes/IAT vector, cgroup/proc lineage, DLP-redacted payload), and{' '}
              <code className="font-mono">assistant</code> (MITRE ATT&amp;CK analysis + recommended Axonwall MCP tool call)
              plus <code className="font-mono">manifest.json</code> checksums.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 font-mono">
            <div className="text-emerald-300 font-bold">features.parquet (Apache Parquet 1.0)</div>
            <p className="text-slate-400 font-sans leading-relaxed">
              Pure-Go spec-compliant Parquet tabular matrix for classical GBDT / anomaly pre-filtering alongside LLM fine-tuning,
              shipped directly to MinIO / Axonwall Vault / S3 via the built-in stdlib AWS SigV4 <code className="font-mono">PUT</code>{' '}
              shipper.
            </p>
          </div>
        </div>
      </section>

      {/* 5. Declarative Configuration */}
      <section id="configuration" className="space-y-4 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-emerald-400" /> 5. Declarative <code className="font-mono">/etc/axonwall/security.yaml</code> Schema
        </h2>
        <CodeBlock
          title="/etc/axonwall/security.yaml (compiled to 0600 /etc/axonwall/managed/threat_harvester_config.json)"
          language="yaml"
          code={`threatHarvester:
  enabled: true
  captureMode: adaptive
  watchedInterfaces: ["wan0", "lan0"]
  canaryPorts: [23, 2323, 3389, 4444, 5900, 6379, 9200, 27017]
  maxPayloadBytes: 4096
  correlationWindowSec: 45
  benignSampleRate: 0.005
  spoolDir: /var/lib/axonwall/threat-corpus
  maxSpoolGb: 10
  pinGoldEpisodes: true
  enableTlsUprobes: false
  autoHoneypotTlsUprobes: true
  anonymizeOnExport: true
  teacherLlm:
    enabled: false
    endpoint: http://127.0.0.1:4100/v1/chat/completions
    model: qwen2.5-14b-instruct
    maxCallsPerHour: 30
  fleetShipper:
    enabled: false
    endpoint: https://vault.internal:9000
    region: us-east-1
    bucket: axonwall-threat-corpus
    prefix: nodes/
    usePathStyle: true`}
        />
      </section>

      {/* 6. CLI & REST API Reference */}
      <section id="cli-api" className="space-y-4 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> 6. CLI (<code className="font-mono">axonwallctl harvester</code>) &amp; API Reference
        </h2>
        <CodeBlock
          title="Enable, simulate, curate, export, and ship threat corpora from the CLI"
          language="bash"
          code={`# Enable the opt-in plugin in DesiredState and reconcile axonwalld
sudo axonwallctl plugin enable ebpf-threat-harvester && sudo axonwallctl apply --no-confirm

# Inspect live TCX/tracepoint/uprobe hook state, DLP redactions & ZFS spool quota
axonwallctl harvester status

# Synthesize safe test episodes (honeypot_rce_memfd | dns_c2_exfil | credential_stuffing_redacted | benign_k3s_egress)
sudo axonwallctl harvester simulate honeypot_rce_memfd
axonwallctl harvester episodes --limit=25 --tier=gold_malicious

# Export Crypto-PAn anonymized Dual-Track .tar.zst (pass --raw for un-anonymized export)
sudo axonwallctl harvester export ./axonwall-threat-corpus.tar.zst

# Upload anonymized bundle to configured Vault / MinIO / S3 bucket via AWS SigV4
sudo axonwallctl harvester ship`}
        />
        <Callout type="warning" title="HTTP &amp; Unix Socket Endpoints">
          Next.js Console API routes under <code className="font-mono">/api/v1/security/threat-harvester/&#123;status,episodes,export,ship&#125;</code>{' '}
          proxy authenticated RBAC sessions to <code className="font-mono">axonwalld</code> endpoints{' '}
          <code className="font-mono">/v1/security/threat-harvester/*</code> (including admin-gated raw{' '}
          <code className="font-mono">application/zstd</code> binary streaming).
        </Callout>
      </section>
    </div>
  );
}
