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
  title: 'eBPF Infrastructure & Kubernetes Observability | Axonwall Documentation',
  description:
    'Zero-instrumentation eBPF observability in Axonwall: gathering metrics, logs, and distributed traces at Ring-0, tracking container network calls and VFS/ZFS filesystem operations, troubleshooting Kubernetes (K3s) clusters, and streaming live NFLOG/SSE packet telemetry.',
};

export default function ObservabilityDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Zero-Instrumentation Kernel Telemetry • eBPF &amp; K3s
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
              <code className="text-slate-200 font-mono">BPF_MAP_TYPE_HASH</code> and{' '}
              <code className="text-slate-200 font-mono">BPF_MAP_TYPE_PERCPU_ARRAY</code> maps. User space scrapes
              pre-summarized golden signals (throughput, TCP RTT, retransmits, VFS IOPS) without copying raw packets.
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
                • <strong className="text-emerald-300">XDP Wire-Speed Flow Accounting:</strong>{' '}
                <code className="font-mono">SEC(&quot;xdp&quot;)</code> parses Ethernet/IPv4/TCP/UDP 5-tuples before{' '}
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
                • <strong className="text-sky-300">VFS Read/Write/Fsync Latency:</strong> BTF{' '}
                <code className="font-mono">fentry/vfs_read</code>, <code className="font-mono">fexit/vfs_write</code>,
                and <code className="font-mono">vfs_fsync</code> measure per-pod storage latency on OpenEBS ZFS-LocalPV.
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
              Enforce <code className="text-slate-200 font-mono">SEC(&quot;lsm/socket_bind&quot;)</code> (blocking Copy
              Fail <code className="text-slate-200 font-mono">CVE-2026-31431</code>),{' '}
              <code className="text-slate-200 font-mono">SEC(&quot;lsm/bpf&quot;)</code>, and{' '}
              <code className="text-slate-200 font-mono">SEC(&quot;lsm/uring_sqpoll&quot;)</code> across all pods.
            </p>
          </div>
        </div>

        <CodeBlock
          title="K3s eBPF Troubleshooting CLI Workflow"
          language="bash"
          code={`# 1. Observe real-time L7 DNS and HTTP errors in K3s via Cilium Hubble
hubble observe --namespace vow-system --verdict DROPPED,ERROR --follow

# 2. Inspect Axonwall XDP flow_map and BPF-LSM allowlist/events maps
bpftool prog show
bpftool map dump name allowlist

# 3. Stream Tetragon container process & VFS file-access events
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f`}
        />
      </section>

      {/* Kernel Packet Tap */}
      <section id="kernel-tap" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> 4. Kernel Packet Stream Architecture (NFLOG &amp; XDP)
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
          <Binary className="w-6 h-6 text-emerald-400" /> 5. Deep Protocol Dissector
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
          <Radio className="w-6 h-6 text-emerald-400" /> 6. Server-Sent Events (SSE) API
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
          <Activity className="w-6 h-6 text-emerald-400" /> 7. VictoriaMetrics, ClickHouse &amp; Insight Flow Analytics
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          In addition to real-time eBPF and NFLOG streaming, historical time-series metrics are stored in an embedded,
          resource-efficient <code className="text-slate-200">VictoriaMetrics</code> engine and optional{' '}
          <code className="text-slate-200">ClickHouse</code> columnar store. This replaces legacy RRDtool graphs with
          high-speed drill-down analytics for bandwidth usage, top talkers, K3s pod flows, and application protocols.
        </p>

        <Callout type="tip" title="Web Console Dashboards">
          Explore live eBPF observability in your console under{' '}
          <code className="text-emerald-300 font-mono">Reporting &gt; eBPF &amp; K3s Observability (/reporting/ebpf)</code>,{' '}
          <code className="text-emerald-300 font-mono">Reporting &gt; Live Flow Monitor (/reporting/flows)</code>, and{' '}
          <code className="text-emerald-300 font-mono">Diagnostics &gt; Packet Tracer (/diagnostics/packet-tracer)</code>.
        </Callout>
      </section>
    </div>
  );
}
