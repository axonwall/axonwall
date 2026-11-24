import React from 'react';
import Link from 'next/link';
import {
  Activity,
  Binary,
  Radio,
  Cpu,
  CheckCircle2,
  Zap,
  Layers,
  Boxes,
  HardDrive,
  Network,
  ShieldCheck,
  GitBranch,
  Gauge,
  ArrowRight,
} from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'eBPF Infrastructure, NetFlow/IPFIX & Kubernetes Observability | Axonwall Documentation',
  description:
    'Zero-instrumentation eBPF observability and enterprise NetFlow v5/v9, IPFIX (UDP/TCP/TLS 1.3 mTLS) & sFlow v5 telemetry in Axonwall: Ring-0 metrics/logs/traces, dual-stack eBPF self-exporter, pure-Go MMDB GeoIP/ASN, FRR BGP/K3s/conntrack enrichment, FQL ClickHouse SQL pushdown, 95th-pct reports, 7d x 24h baselines, and live NFLOG/SSE streaming.',
};

export default function ObservabilityDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Zero-Instrumentation Kernel Telemetry • eBPF &amp; K3s • v0.15.1
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          eBPF Infrastructure &amp; Kubernetes Observability
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Achieving deep observability across modern infrastructure is essential—yet traditional approaches require
          invasive application SDK instrumentation and resource-heavy sidecar proxies. Axonwall leverages{' '}
          <code className="text-emerald-400 font-mono">CO-RE eBPF</code> to gather{' '}
          <strong className="text-slate-200">metrics, logs, and traces</strong> directly inside the Linux kernel,
          tracking container network calls and filesystem operations with sub-microsecond overhead.
        </p>
        <div className="pt-2 flex flex-wrap gap-3">
          <Link
            href="/reporting/ebpf"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white transition"
          >
            Open eBPF Observability Console (/reporting/ebpf)
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
          <Link
            href="/reporting/flows"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 transition"
          >
            Live Packet &amp; Flow Stream (/reporting/flows)
          </Link>
          <Link
            href="/reporting/netflow"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-950/70 hover:bg-sky-900/70 border border-sky-500/40 text-xs font-semibold text-sky-300 transition"
          >
            NetFlow / IPFIX Studio (/reporting/netflow)
          </Link>
        </div>
      </div>

      {/* Section 1: Metrics, Logs, and Traces without Instrumentation Overhead */}
      <section id="metrics-logs-traces" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Gauge className="w-6 h-6 text-emerald-400" /> 1. Gathering Metrics, Logs &amp; Traces Without Application Overhead
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Conventional observability stacks force engineering teams to modify application code with language-specific
          SDKs and inject proxy/logging sidecars into every Kubernetes pod. Every network packet or log line traverses
          multiple user/kernel context switches, consuming 8–15% of cluster CPU and hundreds of megabytes of RAM per
          workload.
        </p>
        <p className="text-sm text-slate-300 leading-relaxed">
          With <strong className="text-white">Extended Berkeley Packet Filter (eBPF)</strong>, sandboxed, verifier-checked
          bytecode runs directly at Ring-0 hook points (`XDP`, `tc`, `kprobes`, `fentry/fexit`, `tracepoints`, and
          `BPF_LSM`). Because every container, VM, and host daemon shares the same Linux kernel, eBPF observes the
          entire stack uniformly:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-emerald-400 text-sm flex items-center gap-1.5">
              <Activity className="w-4 h-4" /> High-Cardinality Metrics
            </div>
            <p className="text-slate-400 leading-relaxed">
              Counters and latency histograms are aggregated in-place inside{' '}
              <code className="text-slate-200 font-mono">BPF_MAP_TYPE_LRU_HASH</code>,{' '}
              <code className="text-slate-200 font-mono">BPF_MAP_TYPE_HASH</code>, and{' '}
              <code className="text-slate-200 font-mono">BPF_MAP_TYPE_PERCPU_ARRAY</code> maps. User space scrapes
              pre-summarized golden signals (throughput, TCP RTT, retransmits, VFS &amp; OpenZFS ARC/ZIL IOPS) without copying raw packets.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-sky-400 text-sm flex items-center gap-1.5">
              <Binary className="w-4 h-4" /> Context-Rich Kernel Logs
            </div>
            <p className="text-slate-400 leading-relaxed">
              Structured security and network events stream asynchronously through a zero-copy{' '}
              <code className="text-slate-200 font-mono">BPF_MAP_TYPE_RINGBUF</code>. Each event carries kernel-verified
              process metadata (<code className="text-slate-200 font-mono">pid</code>,{' '}
              <code className="text-slate-200 font-mono">uid</code>,{' '}
              <code className="text-slate-200 font-mono">cgroup_id</code>, and unspoofable{' '}
              <code className="text-slate-200 font-mono">(s_dev, i_ino)</code> inode identity).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-purple-400 text-sm flex items-center gap-1.5">
              <GitBranch className="w-4 h-4" /> Zero-Code Distributed Traces
            </div>
            <p className="text-slate-400 leading-relaxed">
              Socket-level eBPF programs (<code className="text-slate-200 font-mono">sock_ops</code>,{' '}
              <code className="text-slate-200 font-mono">sk_msg</code>) and user-space TLS uprobes correlate pod-to-pod
              HTTP/gRPC/DNS calls and storage I/O spans across polyglot microservices with zero SDK rewrites.
            </p>
          </div>
        </div>
      </section>

      {/* Section 2: Tracking Container Network Calls & Filesystem Operations */}
      <section id="container-tracking" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> 2. Tracking Container Network Calls &amp; Filesystem Operations
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Containers are isolated using Linux control groups (<code className="text-emerald-400 font-mono">cgroups v2</code>)
          and namespaces (<code className="text-emerald-400 font-mono">mnt</code>,{' '}
          <code className="text-emerald-400 font-mono">pid</code>,{' '}
          <code className="text-emerald-400 font-mono">net</code>). By reading kernel task and cgroup structures via
          BTF Compile Once – Run Everywhere (<code className="text-white font-mono">CO-RE</code>), Axonwall attributes
          every network socket and filesystem operation to its exact container and Kubernetes pod:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2.5">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <Network className="w-4 h-4 text-emerald-400" /> Container Network Call Tracking
            </h3>
            <ul className="space-y-1.5 text-slate-300 leading-relaxed">
              <li>
                • <strong className="text-emerald-300">Dual-Stack &amp; QinQ VLAN XDP Wire-Speed Accounting:</strong>{' '}
                <code className="font-mono">SEC(&quot;xdp&quot;)</code> peels 2-layer <code className="font-mono">802.1Q</code> / <code className="font-mono">802.1ad</code> VLAN headers and tracks IPv4 (<code className="font-mono">flow_map</code> 131K LRU) + IPv6 (<code className="font-mono">flow6_map</code> 65K LRU) 5-tuples and monotonic TTL <code className="font-mono">XDP_DROP</code> blocklists before{' '}
                <code className="font-mono">sk_buff</code> allocation.
              </li>
              <li>
                • <strong className="text-emerald-300">Socket Connect &amp; RTT Telemetry:</strong> Hooks on{' '}
                <code className="font-mono">tcp_v4_connect</code> and <code className="font-mono">tcp_rcv_established</code>{' '}
                record container <code className="font-mono">cgroup_id</code>, destination service IP:port, and handshake RTT.
              </li>
              <li>
                • <strong className="text-emerald-300">Retransmission &amp; Drop Reasons:</strong> Tracepoints on{' '}
                <code className="font-mono">tcp_retransmit_skb</code> and <code className="font-mono">kfree_skb</code>{' '}
                expose exact kernel drop reasons (`SKB_DROP_REASON_*`).
              </li>
            </ul>
          </div>

          <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2.5">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-sky-400" /> Container Filesystem &amp; VFS Operations
            </h3>
            <ul className="space-y-1.5 text-slate-300 leading-relaxed">
              <li>
                • <strong className="text-sky-300">VFS &amp; OpenZFS ARC/L2ARC/ZIL Telemetry:</strong> BTF{' '}
                <code className="font-mono">fentry/vfs_read</code>, <code className="font-mono">fexit/vfs_write</code>,
                and <code className="font-mono">vfs_fsync</code> pair with <code className="font-mono">/proc/spl/kstat/zfs</code> ARC/L2ARC hit ratios, ZIL/SLOG sync commits, and per-pool ZIO queues.
              </li>
              <li>
                • <strong className="text-sky-300">Unspoofable (s_dev, i_ino) Identity:</strong> Resolves{' '}
                <code className="font-mono">task-&gt;mm-&gt;exe_file-&gt;f_inode</code> so renamed binaries or symlinks
                inside containers cannot evade attribution.
              </li>
              <li>
                • <strong className="text-sky-300">Sensitive File Access Auditing:</strong> Tetragon{' '}
                <code className="font-mono">security_file_open</code> selectors detect unexpected reads of TLS keys,
                service-account tokens, or `/etc/shadow`.
              </li>
            </ul>
          </div>
        </div>

        <CodeBlock
          title="CO-RE eBPF Container & Executable Attribution Pattern (apps/axonwalld/ebpf/lsm_guard.c)"
          language="c"
          code={`struct lsm_exe_id {
    __u64 dev;
    __u64 ino;
};

static __always_inline bool get_current_exe_id(struct lsm_exe_id *out) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return false;

    struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    if (!exe_file)
        return false;

    struct inode *inode = BPF_CORE_READ(exe_file, f_inode);
    if (!inode)
        return false;

    // Kernel super_block s_dev encodes (MAJOR << 20) | MINOR
    __u32 s_dev = BPF_CORE_READ(inode, i_sb, s_dev);
    __u64 i_ino = BPF_CORE_READ(inode, i_ino);

    out->dev = (__u64)s_dev;
    out->ino = i_ino;
    return true;
}`}
        />
      </section>

      {/* Section 3: Troubleshooting Kubernetes (K3s) Environments */}
      <section id="kubernetes-troubleshooting" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Boxes className="w-6 h-6 text-emerald-400" /> 3. Troubleshooting Kubernetes (K3s) Environments with eBPF
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          In Kubernetes clusters, distroless containers lack shells, `tcpdump`, `strace`, or `netstat`, and ephemeral
          pods vanish before operators can inspect them. Axonwall combines host-level eBPF telemetry with the{' '}
          <Link href="/docs/vigilant-octo-waffle" className="text-emerald-400 hover:underline">
            Vigilant Octo Waffle (VOW)
          </Link>{' '}
          observability stack (<strong className="text-white">Cilium Hubble</strong>,{' '}
          <strong className="text-white">Tetragon</strong>, <strong className="text-white">Kubeshark</strong>, and{' '}
          <strong className="text-white">OpenTelemetry</strong>) to solve four common cluster failure modes:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">1. DNS Lookup Amplification &amp; Drops</span>
            <p className="text-slate-400">
              Inspect per-pod DNS queries and `RCode` responses (`NXDOMAIN`, `SERVFAIL`) via cgroup socket filters and
              correlate UDP socket receive-buffer drops without sidecars.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">2. CNI Overlay MTU &amp; TCP Retransmissions</span>
            <p className="text-slate-400">
              Use <code className="text-slate-200 font-mono">tracepoint/tcp/tcp_retransmit_skb</code> to spot PMTU
              blackholes and congestion window drops across WireGuard-encrypted K3s node links.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">3. PVC Storage Latency (OpenEBS ZFS-LocalPV)</span>
            <p className="text-slate-400">
              Attribute slow <code className="text-slate-200 font-mono">vfs_write</code> and{' '}
              <code className="text-slate-200 font-mono">vfs_fsync</code> calls to specific stateful pods (PostgreSQL,
              etcd, ClickHouse) to separate disk contention from network latency.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-amber-400">4. Zero-Syscall &amp; Kernel Crypto Containment</span>
            <p className="text-slate-400">
              Enforce all 5 CO-RE BPF-LSM hooks—<code className="text-slate-200 font-mono">SEC(&quot;lsm/socket_bind&quot;)</code> (Copy
              Fail <code className="text-slate-200 font-mono">CVE-2026-31431</code>),{' '}
              <code className="text-slate-200 font-mono">SEC(&quot;lsm/bpf&quot;)</code>,{' '}
              <code className="text-slate-200 font-mono">SEC(&quot;lsm/uring_sqpoll&quot;)</code>,{' '}
              <code className="text-slate-200 font-mono">SEC(&quot;lsm/bpf_token_create&quot;)</code>, and{' '}
              <code className="text-slate-200 font-mono">SEC(&quot;lsm/bpf_token_cmd&quot;)</code>—across all pods.
            </p>
          </div>
        </div>

        <CodeBlock
          title="K3s eBPF Troubleshooting CLI Workflow"
          language="bash"
          code={`# 1. Inspect Dual-Stack XDP counters, 5-hook BPF-LSM & Linux 6.9+ BPF_TOKEN mounts
axonwallctl ebpf overview
axonwallctl ebpf tokens

# 2. Observe real-time L7 DNS and HTTP errors in K3s via Cilium Hubble
hubble observe --namespace vow-system --verdict DROPPED,ERROR --follow

# 3. Inspect Axonwall XDP flow_map/flow6_map and BPF-LSM allowlist maps
bpftool prog show
bpftool map dump name allowlist

# 4. Stream Tetragon container process & VFS file-access events
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f`}
        />
      </section>

      {/* Section 4: Coroot-Grade eBPF APM, Automated RCA & Continuous Profiling */}
      <section id="coroot-apm" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <GitBranch className="w-6 h-6 text-emerald-400" /> 4. Coroot-Grade eBPF APM, Automated RCA &amp; Continuous Profiling
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall integrates <strong className="text-white">Coroot-inspired eBPF Application Performance Monitoring (APM)</strong>{' '}
          both natively inside <Link href="/reporting/ebpf" className="text-emerald-400 hover:underline">/reporting/ebpf</Link>{' '}
          and as a toggleable plugin (<code className="text-slate-200 font-mono">coroot-ebpf-apm</code> / VOW catalog{' '}
          <code className="text-slate-200 font-mono">coroot</code>). Using guardrailed{' '}
          <code className="text-emerald-400 font-mono">observability.ebpfApm</code> toggles, operators can enable or disable
          higher-overhead probes on demand without restarting workloads:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">1. Auto-Discovered Service Dependency Map</span>
            <p className="text-slate-400">
              Hooks <code className="text-slate-200 font-mono">tcp_connect</code>,{' '}
              <code className="text-slate-200 font-mono">inet_csk_accept</code>, and{' '}
              <code className="text-slate-200 font-mono">sock_sendmsg</code> to construct a real-time topology graph of
              every host daemon and K3s pod alongside live connection states, RTT, and TCP retransmission rates.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">2. L7 Protocol RED Dissection + TLS Uprobes</span>
            <p className="text-slate-400">
              Automatically parses <strong className="text-slate-200">HTTP/1.1, HTTP/2, gRPC, PostgreSQL, Redis, ClickHouse, DNS, and Kafka</strong>{' '}
              payloads at socket boundaries to compute per-endpoint Rate, Errors, and Duration (`p50`/`p95`/`p99`). Optional{' '}
              <code className="text-slate-200 font-mono">uprobe/SSL_read</code>,{' '}
              <code className="text-slate-200 font-mono">uprobe/SSL_write</code>, and Go{' '}
              <code className="text-slate-200 font-mono">crypto/tls</code> hooks inspect TLS-encrypted traffic before
              ciphertext leaves user space—without MITM certificates.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">3. Automated Root-Cause Analysis (RCA) Engine</span>
            <p className="text-slate-400">
              Deterministic inspection rules evaluate SLO availability, cgroup CFS CPU throttling, OOM kills / memory
              pressure, TCP retransmit spikes, OpenEBS ZFS-LocalPV <code className="text-slate-200 font-mono">vfs_fsync</code>{' '}
              latency, and BPF-LSM security blocks—pinpointing the exact root cause of latency anomalies.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-amber-400">4. 99 Hz Continuous Stack-Trace FlameGraphs</span>
            <p className="text-slate-400">
              Samples kernel + user-space stack traces via{' '}
              <code className="text-slate-200 font-mono">perf_event</code> and{' '}
              <code className="text-slate-200 font-mono">BPF_MAP_TYPE_STACK_TRACE</code> across On-CPU cycles, Disk/ZFS I/O
              wait, Heap/ARC memory allocations, and Off-CPU mutex contention.
            </p>
          </div>
        </div>

        <CodeBlock
          title="/etc/axonwall/system.yaml — Complete ObservabilitySchema (observability: & coroot-ebpf-apm)"
          language="yaml"
          code={`plugins:
  - id: coroot-ebpf-apm
    enabled: true

observability:
  metrics:
    enabled: true
    retentionDays: 30
    remoteWriteUrl: ""
  flowExport:
    enabled: false
    protocol: ipfix
    collectorAddress: ""
  alerting:
    enabled: true
    webhookUrl: ""
  clickhouse:
    enabled: false
    endpoint: http://127.0.0.1:8123
    database: axonwall_telemetry
  ebpfApm:
    enabled: true
    serviceMapEnabled: true
    l7ProtocolDissection: true
    tlsUprobesEnabled: false
    continuousProfilingEnabled: true
    profilingSampleHz: 99
    automatedRcaInspections: true
    xdpDualStackVlanEnabled: true
    zfsArcZilTelemetryEnabled: true`}
        />
      </section>

      {/* NetFlow / IPFIX / sFlow Collector & Analytics Studio */}
      <section id="netflow-collector" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Network className="w-6 h-6 text-sky-400" /> NetFlow / IPFIX / sFlow Collector &amp; Analytics Studio (
          <code className="font-mono text-sky-400">netflow-collector</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall ships a turnkey, zero-CGO flow intelligence pipeline configured declaratively via{' '}
          <code className="text-sky-400 font-mono">/etc/axonwall/netflow.yaml</code> and explored interactively in{' '}
          <Link href="/reporting/netflow" className="text-sky-400 hover:underline">
            /reporting/netflow
          </Link>
          . Ingest NetFlow v5/v9, IPFIX (RFC 7011), and sFlow v5 from external routers/switches alongside dual-stack
          Axonwall eBPF self-export, replicate raw UDP streams to upstream SIEMs, enrich every record in flight, and
          retain multi-tier compressed rollups or push directly into ClickHouse.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">1. Multi-Protocol Ingest, TLS 1.3 mTLS &amp; Replication</span>
            <p className="text-slate-400 leading-relaxed">
              Accepts NetFlow v5, NetFlow v9, IPFIX (UDP, TCP &amp; TLS 1.3 with optional client mTLS), and sFlow v5
              with Linux <code className="text-slate-200 font-mono">SO_REUSEPORT</code> multi-worker socket scaling.
              Dual-stack eBPF self-export emits IPv4 Template <code className="text-slate-200 font-mono">256</code> and
              IPv6 Template <code className="text-slate-200 font-mono">257</code> enriched with{' '}
              <code className="text-slate-200 font-mono">NETLINK_SOCK_DIAG</code> TCP RTT &amp; retransmits, while
              the UDP fan-out replicator supports optional raw-socket source-IP spoofing (<code className="font-mono">CAP_NET_RAW</code>).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">2. Real-Time Multi-Source Enrichment Pipeline</span>
            <p className="text-slate-400 leading-relaxed">
              Every ingested flow is enriched in memory with a pure-Go MaxMind <code className="font-mono">.mmdb</code>{' '}
              v2 reader + scheduled/on-demand HTTPS updater, live FRR BGP RIB longest-prefix-match AS-Path &amp;
              next-hop, live K3s Pod/Namespace/Service attribution, Linux <code className="font-mono">conntrack</code>{' '}
              NAT/CGNAT mapping (IEs 225–228), reverse DNS, SNMP <code className="font-mono">ifAlias</code>, and
              Suricata/CrowdSec/Threat-Intel matching.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">3. Rollups, ClickHouse Pushdown, Reports &amp; Prometheus</span>
            <p className="text-slate-400 leading-relaxed">
              Persists <code className="font-mono">1m</code> / <code className="font-mono">5m</code> /{' '}
              <code className="font-mono">1h</code> Zstd rollups with parameterized FQL-to-ClickHouse SQL pushdown,
              computes 95th/99th-percentile capacity &amp; billing reports (CSV/Markdown/JSON + scheduled snapshots),
              maintains 168-slot (7d×24h) EWMA/Z-score &amp; first-seen pair anomaly baselines, executes federated
              queries across <code className="font-mono">topology.peers</code>, and exposes Prometheus metrics at{' '}
              <code className="text-emerald-300 font-mono">/api/v1/netflow/metrics</code>.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-amber-400">4. Interactive Analytics Studio &amp; Inline Pivots</span>
            <p className="text-slate-400 leading-relaxed">
              <Link href="/reporting/netflow" className="text-sky-400 hover:underline font-mono">
                /reporting/netflow
              </Link>{' '}
              combines an autocomplete Flow Query Language (FQL) bar, drag-to-zoom time-brush explorer, bidirectional
              session stitching, Source×Dest &amp; Port×Time heatmaps, an offline SVG world Geo Traffic Map, SSE live
              tail, and 1-click inline pivots to <strong className="text-slate-200">XDP Drop</strong>,{' '}
              <strong className="text-slate-200">Packet Capture</strong> (<code className="font-mono">/diagnostics/packet-capture</code>),{' '}
              <strong className="text-slate-200">Firewall Alias</strong>, and <strong className="text-slate-200">Topology Studio</strong> (<code className="font-mono">/topology</code>).
            </p>
          </div>
        </div>

        <CodeBlock
          title="/etc/axonwall/netflow.yaml — Declarative Collector, Self-Exporter, Enrichment & Baselines"
          language="yaml"
          code={`plugins:
  - id: netflow-collector
    enabled: true

netflow:
  enabled: true
  listeners:
    - name: core-ipfix-udp
      protocol: auto          # auto (NetFlow v5/v9 + IPFIX), ipfix, netflow5, netflow9, sflow5
      bindAddress: 0.0.0.0
      port: 2055
      reusePort: true         # Linux SO_REUSEPORT multi-worker scaling
      workers: 4
    - name: wan-ipfix-mtls
      protocol: ipfix
      transport: tls          # udp | tcp | tls (RFC 7011 TLS 1.3 + optional mTLS)
      port: 4740
      tlsClientAuth: true
  selfExporter:
    enabled: true
    interfaces: ["wan0", "lan0"]
    activeTimeoutSec: 30
    idleTimeoutSec: 15
    samplingRate: 1
    exportSockDiagRtt: true   # NETLINK_SOCK_DIAG kernel TCP RTT & retransmits
    exportConntrackNat: true  # IPFIX NAT/CGNAT IEs 225-228 (Templates 256 IPv4 / 257 IPv6)
  enrichment:
    mmdbAutoUpdate: true
    geoipCityPath: /var/lib/axonwall/geoip/GeoLite2-City.mmdb
    geoipAsnPath: /var/lib/axonwall/geoip/GeoLite2-ASN.mmdb
    frrBgpLpm: true
    k3sAttribution: true
    reverseDns: true
    snmpIfAlias: true
  storage:
    zstdRollups: true
    clickhousePushdown: true
  analytics:
    baselines7x24Enabled: true
    scheduledReports95th: true
    fleetFederation: true`}
        />

        <CodeBlock
          title="Flow Query Language (FQL) & axonwallctl netflow CLI Examples"
          language="bash"
          code={`# Inspect NetFlow collector pipeline status, listeners & template cache
axonwallctl netflow status --json

# Execute an FQL query with bidirectional session stitching (biflow)
axonwallctl netflow query 'src.ip == 10.0.0.0/8 and dst.port == 443 and bytes > 1000000' --biflow --minutes 60

# Run a federated threat-flow query across all topology.peers appliances
axonwallctl netflow fleet-query 'threat.matched == true or tcp.rtt_ms > 150' --limit 100

# Generate a 7-day 95th-percentile capacity & billing Markdown report
axonwallctl netflow report --range 7d --group interface --format markdown`}
        />
      </section>

      {/* Linux 6.9+ BPF_TOKEN_CREATE Delegation & Dual-Stack XDP */}
      <section id="bpf-token-delegation" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-sky-400" /> Linux 6.9+ `BPF_TOKEN_CREATE` Unprivileged Delegation &amp; Dual-Stack XDP
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Informed by Tekromancy&apos;s kernel engineering research on{' '}
          <a
            href="https://tekromancy.com/blog/ebpf-token-unprivileged-bpf-delegation-user-namespaces-linux-6-9-containers/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sky-400 hover:underline"
          >
            Linux 6.9+ `BPF_TOKEN_CREATE` &amp; User Namespace eBPF Delegation
          </a>
          , Axonwall bridges multi-tenant container isolation (`CLONE_NEWUSER`) with high-speed packet processing—allowing
          rootless K3s <code className="text-emerald-400 font-mono">hostUsers: false</code> pods and unprivileged LXC
          containers to load verified networking eBPF programs without granting host <code className="text-rose-400 font-mono">CAP_BPF</code>{' '}
          or <code className="text-rose-400 font-mono">CAP_SYS_ADMIN</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">1. Four-Pillar `bpffs` Mount Delegation</span>
            <p className="text-slate-400 leading-relaxed">
              <code className="text-slate-200 font-mono">axonwalld</code> mounts isolated token instances under{' '}
              <code className="text-slate-200 font-mono">/run/axonwall/bpffs-tokens/&lt;profile&gt;</code> with explicit{' '}
              <code className="text-slate-200 font-mono">delegate_cmds</code>,{' '}
              <code className="text-slate-200 font-mono">delegate_progs</code>,{' '}
              <code className="text-slate-200 font-mono">delegate_maps</code>, and{' '}
              <code className="text-slate-200 font-mono">delegate_attachs</code> options. Inside the container, setting{' '}
              <code className="text-emerald-300 font-mono">LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf</code> enables{' '}
              <code className="text-slate-200 font-mono">libbpf</code> and <code className="text-slate-200 font-mono">cilium/ebpf</code>{' '}
              to mint `BPF_TOKEN_CREATE` file descriptors transparently.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-rose-400">2. Ring-0 `bpf_probe_read_kernel()` Isolation Veto</span>
            <p className="text-slate-400 leading-relaxed">
              Even inside a User Namespace, eBPF tracing programs execute in shared Ring-0 address space where{' '}
              <code className="text-rose-300 font-mono">bpf_probe_read_kernel()</code> could read host credentials or sibling
              container secrets. Axonwall&apos;s CO-RE BPF-LSM hooks (<code className="text-slate-200 font-mono">SEC(&quot;lsm/bpf_token_create&quot;)</code>{' '}
              &amp; <code className="text-slate-200 font-mono">SEC(&quot;lsm/bpf_token_cmd&quot;)</code>) unconditionally block{' '}
              <code className="text-rose-300 font-mono">kprobe</code>, <code className="text-rose-300 font-mono">tracepoint</code>,{' '}
              <code className="text-rose-300 font-mono">perf_event</code>, <code className="text-rose-300 font-mono">tracing</code>,{' '}
              <code className="text-rose-300 font-mono">struct_ops</code>, and <code className="text-rose-300 font-mono">lsm</code>{' '}
              with <code className="text-rose-300 font-mono">-EPERM</code>.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">3. Dual-Stack IPv4/IPv6 + 802.1Q/802.1ad QinQ XDP</span>
            <p className="text-slate-400 leading-relaxed">
              <code className="text-slate-200 font-mono">flow_tracker.c</code> peels up to two nested{' '}
              <code className="text-slate-200 font-mono">802.1Q</code> / <code className="text-slate-200 font-mono">802.1ad</code>{' '}
              VLAN headers and tracks both IPv4 (<code className="text-slate-200 font-mono">flow_map</code>, 131K LRU) and
              IPv6 (<code className="text-slate-200 font-mono">flow6_map</code>, 65K LRU) 5-tuples, TCP SYN/RST flags, and
              per-CPU verdict counters at ~18 ns/packet.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-amber-400">4. LPM CIDR Subnet `XDP_DROP` &amp; Ring-0 TCP SYN-Flood Shield</span>
            <p className="text-slate-400 leading-relaxed">
              Dual-stack exact-host maps (<code className="text-slate-200 font-mono">blocklist_map</code> /{' '}
              <code className="text-slate-200 font-mono">blocklist6_map</code>) and{' '}
              <code className="text-slate-200 font-mono">BPF_MAP_TYPE_LPM_TRIE</code> prefix maps (<code className="text-slate-200 font-mono">cidr4_blocklist_map</code>{' '}
              / <code className="text-slate-200 font-mono">cidr6_blocklist_map</code>) store monotonic{' '}
              <code className="text-slate-200 font-mono">bpf_ktime_get_ns()</code> expiration timestamps in-kernel,
              paired with a per-source 1-second sliding-window Ring-0 TCP SYN-flood rate limiter (<code className="text-slate-200 font-mono">syn_rate_map</code>{' '}
              / <code className="text-slate-200 font-mono">syn6_rate_map</code>) that drops volumetric SYN floods before{' '}
              <code className="text-slate-200 font-mono">sk_buff</code> allocation.
            </p>
          </div>
        </div>

        <CodeBlock
          title="axonwallctl ebpf — Ring-0 Dataplane, XDP Fast-Drop & BPF_TOKEN CLI"
          language="bash"
          code={`# Unified Ring-0 eBPF, BPF_TOKEN_CREATE, KVM/LXC, K3s & OpenZFS ARC/ZIL overview
axonwallctl ebpf overview

# Inspect Linux 6.9+ BPF_TOKEN kernel support, presets, and active bpffs mounts
axonwallctl ebpf tokens

# Program a line-rate dual-stack XDP_DROP lease (IPv4 or IPv6) with 1-hour TTL
axonwallctl ebpf xdp-drop 198.51.100.77 3600
axonwallctl ebpf xdp-blocks
axonwallctl ebpf xdp-unblock 198.51.100.77

# Render a K3s UserNS (hostUsers: false) DaemonSet manifest with LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf
axonwallctl ebpf render-k3s ebpf-sensor k3s-net-safe networking-safe`}
        />
      </section>

      {/* Live eBPF Visualizations & Kernel BPF Inventory */}
      <section id="ebpf-visualizations" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Activity className="w-6 h-6 text-emerald-400" /> 5. Live eBPF Visualizations &amp; Kernel BPF Inventory
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          <code className="text-emerald-400 font-mono">GET /v1/ebpf/overview</code> (and its Web Console proxy{' '}
          <code className="text-slate-200 font-mono">GET /api/v1/ebpf/overview</code>) exposes{' '}
          <code className="text-emerald-300 font-mono">CollectKernelBpfInventory()</code> (<code className="font-mono text-slate-200">bpfInventory</code>) alongside live Ring-0 XDP counters, BPF-LSM blocks, cross-duty storage/hypervisor telemetry, and Blackbox threat sketches—powering six live visualizers across{' '}
          <code className="text-emerald-400 font-mono">/reporting/ebpf</code>, <code className="text-emerald-400 font-mono">/reporting/flows</code>, and{' '}
          <code className="text-emerald-400 font-mono">/security/threat-harvester</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">EbpfDataplaneCharts</span>
            <p className="text-slate-400 leading-relaxed">
              Six live charts: <em>Real-Time XDP Ring-0 Verdict Rate</em>, <em>Per-CPU XDP Core Load</em>, <em>Protocol, Dual-Stack &amp; VLAN Mix</em>, <em>Top Destination Services by XDP Bytes</em>, <em>XDP Blocklist Impact by Source / CIDR</em>, and <em>Per-Source TCP SYN Rate Meter</em>.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">EbpfFlowTopologyMap</span>
            <p className="text-slate-400 leading-relaxed">
              Interactive live XDP flow topology graph linking ingress NICs/VLANs, active IPv4/IPv6 tuples, blocked peers, and downstream destinations.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">EbpfKernelInventoryPanel</span>
            <p className="text-slate-400 leading-relaxed">
              Live kernel enumeration of loaded BPF programs (ID, type, JIT &amp; translated bytes, verified instructions, BTF status, cumulative <code className="font-mono text-slate-200">runCount</code>/<code className="font-mono text-slate-200">runTimeNs</code>) and BPF maps (key/value/max entries, memlock bytes, frozen flag).
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-amber-400">EbpfCrossDutyVisualizer</span>
            <p className="text-slate-400 leading-relaxed">
              Correlates OpenZFS SPL kstat ARC/L2ARC/ZIL throughput, KVM <code className="font-mono text-slate-200">vnet</code>/<code className="font-mono text-slate-200">tap</code> NIC queues, and K3s pod eBPF token metrics in a unified view.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-cyan-400">EbpfSecurityVisualizer &amp; ThreatSketchWaveform</span>
            <p className="text-slate-400 leading-relaxed">
              Visualizes 5-hook CO-RE BPF-LSM enforcement events, Linux 6.9+ <code className="font-mono text-slate-200">BPF_TOKEN</code> mounts, and signed packet-size / microsecond inter-arrival-time waveforms for Blackbox Threat-LLM episodes.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-300">FlowsLiveVisualStrip</span>
            <p className="text-slate-400 leading-relaxed">
              Heads-up protocol, direction, verdict, and burst Sparkline strip embedded above the live packet &amp; flow table at <code className="font-mono text-slate-200">/reporting/flows</code>.
            </p>
          </div>
        </div>
      </section>

      {/* Kernel Packet Tap */}
      <section id="kernel-tap" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> 6. Kernel Packet Stream Architecture (NFLOG &amp; XDP)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Traditional BSD firewalls require administrators to start a packet capture, wait for an incident to occur,
          download an unwieldy <code className="text-slate-200 font-mono">.pcap</code> file, and open Wireshark on a
          workstation. Axonwall taps directly into the Linux netfilter subsystem via{' '}
          <code className="text-emerald-400 font-mono">NFLOG</code> and <code className="text-white font-mono">eBPF</code>:
        </p>

        <CodeBlock
          title="Packet Capture & eBPF Ring-Buffer Dataflow"
          language="text"
          code={`[ Network Interface / K3s CNI (wan0 / lan0 / cni0) ]
                 |
                 v
     [ XDP Hook (xdp_flow_tracker) ]  <-- Pre-sk_buff 5-tuple metrics & blocklist drop
                 |
                 v
       [ Linux Kernel Netfilter ]
                 |
      NFLOG Group / eBPF Tap + BPF-LSM RingBuf
                 |
                 v
    [ axonwalld Packet & LSM Streamer ] <-- Ring-buffered zero-copy memory ring
                 |
                 v
      [ Unix Domain Socket ]
                 |
                 v
  [ Axonwall Web Controller (SSE) ]
   GET /api/v1/events/packets
                 |
                 v
  [ Live Browser Terminal / UI ]        <-- Instant interactive flow & security stream`}
        />
      </section>

      {/* Protocol Dissectors */}
      <section id="dissectors" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Binary className="w-6 h-6 text-emerald-400" /> 7. Deep Protocol Dissector
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The embedded Go daemon dissector analyzes raw Ethernet frames at wire-speed and parses packet headers without
          writing files to disk:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">Layer 2 (Ethernet)</span>
            <p className="text-slate-400">
              Source &amp; Destination MAC addresses, VLAN tags (802.1Q), and EtherType decoding.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">Layer 3 (IP / IPv6)</span>
            <p className="text-slate-400">
              Source/Destination IPs, TTL/Hop Limit, Type of Service (TOS), and packet length.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">Layer 4 (TCP / UDP / ICMP)</span>
            <p className="text-slate-400">
              Ports, sequence numbers, TCP flags (SYN, ACK, FIN, RST, PSH), and ICMP type/code.
            </p>
          </div>
        </div>
      </section>

      {/* SSE Streaming Endpoint */}
      <section id="sse-streaming" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Radio className="w-6 h-6 text-emerald-400" /> 8. Server-Sent Events (SSE) API
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Clients stream live packet telemetry over HTTP/2 using Server-Sent Events. The stream supports server-side
          filtering by interface, protocol, IP address, and port:
        </p>

        <CodeBlock
          title="Streaming Example"
          language="bash"
          code={`# Stream live TCP packets on interface eth0 with SYN or RST flags
curl -N "https://192.168.1.1:2966/api/v1/events/packets?iface=eth0&proto=tcp"`}
        />

        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Example Event Payload (JSON)</h4>
          <CodeBlock
            title="SSE Packet Event"
            language="json"
            code={`{
  "timestamp": "2026-10-13T07:15:22.408Z",
  "interface": "wan0",
  "direction": "in",
  "ethernet": {
    "src": "00:1a:2b:3c:4d:5e",
    "dst": "52:54:00:12:34:56",
    "type": "IPv4"
  },
  "ip": {
    "version": 4,
    "src": "198.51.100.24",
    "dst": "192.168.1.1",
    "ttl": 54,
    "proto": "TCP",
    "length": 60
  },
  "tcp": {
    "srcPort": 52414,
    "dstPort": 443,
    "seq": 284192041,
    "flags": ["SYN"]
  },
  "action": "pass"
}`}
          />
        </div>
      </section>

      {/* VictoriaMetrics */}
      <section id="victoriametrics" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Activity className="w-6 h-6 text-emerald-400" /> 9. VictoriaMetrics, ClickHouse &amp; Insight Flow Analytics
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          In addition to real-time eBPF and NFLOG streaming, historical time-series metrics are stored in an embedded,
          resource-efficient <code className="text-slate-200">VictoriaMetrics</code> engine and optional{' '}
          <code className="text-slate-200">ClickHouse</code> columnar store. This replaces legacy RRDtool graphs with
          high-speed drill-down analytics for bandwidth usage, top talkers, K3s pod flows, and application protocols.
        </p>

        <Callout type="tip" title="Web Console Dashboards">
          Explore live eBPF and flow observability in your console under{' '}
          <code className="text-emerald-300 font-mono">Reporting &gt; eBPF &amp; K3s Observability (/reporting/ebpf)</code>,{' '}
          <code className="text-emerald-300 font-mono">Reporting &gt; Live Flow Monitor (/reporting/flows)</code>,{' '}
          <code className="text-sky-300 font-mono">Reporting &gt; NetFlow Collector Studio (/reporting/netflow)</code>, and{' '}
          <code className="text-emerald-300 font-mono">Diagnostics &gt; Packet Tracer (/diagnostics/packet-tracer)</code>.
        </Callout>
      </section>
    </div>
  );
}
