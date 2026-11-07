'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import {
  Activity,
  Cpu,
  Layers,
  Network,
  HardDrive,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Zap,
  Radio,
  Binary,
  Boxes,
  Search,
  Play,
  Pause,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  ArrowUpRight,
  Copy,
  Check,
  FileCode,
  Eye,
  Gauge,
  Server,
  GitBranch,
  Flame,
  Database,
  Lock,
  Save,
  Sparkles,
  ArrowRight,
} from 'lucide-react';
import {
  getNetworkInsightTelemetry,
  getK3sRuntimeStatus,
  getHostRootkitAuditStatus,
  getCurrentDesiredState,
  applyDesiredState,
  type NetworkInsightTelemetry,
  type K3sRuntimeStatus,
  type HostRootkitAuditApiResponse,
} from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

interface StreamPacket {
  index: number;
  timestamp: string;
  srcIp: string;
  srcPort: string;
  dstIp: string;
  dstPort: string;
  protocol: string;
  length: number;
  info: string;
}

interface EbpfProbeSpec {
  id: string;
  hook: string;
  domain: 'network' | 'filesystem' | 'k8s-container' | 'lsm-security' | 'coroot-apm';
  attachType: string;
  kernelSymbol: string;
  telemetryPillar: 'Metrics' | 'Logs' | 'Traces' | 'Metrics + Traces' | 'Logs + Enforcement' | 'Continuous Profiling';
  overheadNs: string;
  description: string;
  k8sUseCase: string;
}

const EBPF_PROBE_CATALOG: EbpfProbeSpec[] = [
  {
    id: 'xdp-flow-tracker',
    hook: 'SEC("xdp")',
    domain: 'network',
    attachType: 'XDP Driver / Generic Hook',
    kernelSymbol: 'xdp_flow_tracker',
    telemetryPillar: 'Metrics',
    overheadNs: '~18 ns/pkt',
    description:
      'Parses L2/L3/L4 Ethernet, IPv4, TCP, and UDP headers at the NIC driver ring before sk_buff allocation, updating per-5-tuple packet/byte counters in BPF_MAP_TYPE_HASH.',
    k8sUseCase:
      'Zero-overhead node & pod ingress throughput accounting and line-rate DDoS drop filtering prior to netfilter.',
  },
  {
    id: 'coroot-l7-dissector',
    hook: 'SEC("tracepoint/syscalls/sys_enter_write")',
    domain: 'coroot-apm',
    attachType: 'Socket Syscall + SockOps',
    kernelSymbol: 'sys_enter_write / sys_exit_read / tcp_sendmsg',
    telemetryPillar: 'Metrics + Traces',
    overheadNs: '~55 ns/msg',
    description:
      'Coroot-style L7 protocol parser inspecting socket payloads in-kernel to compute RED metrics (Rate, Errors, Duration p50/p95/p99) for HTTP/1.1, HTTP/2, gRPC, Postgres, MySQL, Redis, Kafka, ClickHouse, and DNS.',
    k8sUseCase:
      'Instant per-endpoint HTTP 5xx error rates and database query latency histograms without sidecar proxies or SDKs.',
  },
  {
    id: 'coroot-tls-uprobes',
    hook: 'SEC("uprobe/SSL_write") / SEC("uprobe/crypto_tls")',
    domain: 'coroot-apm',
    attachType: 'User-Space TLS Uprobe (Opt-In)',
    kernelSymbol: 'libssl.so:SSL_read/SSL_write & Go crypto/tls.(*Conn).Write',
    telemetryPillar: 'Traces',
    overheadNs: '~190 ns/call',
    description:
      'Captures cleartext L7 request/response headers before encryption and after decryption in OpenSSL, GnuTLS, Rustls, and Go standard library TLS connections.',
    k8sUseCase:
      'Observing mTLS service-to-service gRPC/REST calls and external HTTPS API latency without terminating TLS or injecting CA certs.',
  },
  {
    id: 'coroot-cpu-io-profiler',
    hook: 'SEC("perf_event")',
    domain: 'coroot-apm',
    attachType: '99 Hz Hardware PMU Timer + Stack Trace Map',
    kernelSymbol: 'bpf_get_stackid (BPF_MAP_TYPE_STACK_TRACE)',
    telemetryPillar: 'Continuous Profiling',
    overheadNs: '~0.4% CPU @ 99Hz',
    description:
      'Samples kernel and user-space call stacks at 99 Hz per container cgroup, symbolizing Go, Rust, C/C++, Python, Node.js, and JVM frames into interactive FlameGraphs.',
    k8sUseCase:
      'Identifying exact functions causing CPU spikes, mutex lock contention, or synchronous disk I/O waits in production pods.',
  },
  {
    id: 'tcp-connect-trace',
    hook: 'SEC("kprobe/tcp_v4_connect")',
    domain: 'k8s-container',
    attachType: 'CO-RE Kprobe + SockOps',
    kernelSymbol: 'tcp_v4_connect / inet_csk_accept',
    telemetryPillar: 'Metrics + Traces',
    overheadNs: '~45 ns/call',
    description:
      'Captures every container outbound TCP handshake and inbound accept, correlating pid, cgroup_id, network namespace inode, SYN-to-ESTABLISHED RTT, and destination service endpoint.',
    k8sUseCase:
      'Builds the Coroot Service Dependency Map automatically and detects upstream connection timeouts.',
  },
  {
    id: 'tcp-retransmit',
    hook: 'SEC("tracepoint/tcp/tcp_retransmit_skb")',
    domain: 'network',
    attachType: 'Raw Tracepoint',
    kernelSymbol: 'tcp_retransmit_skb',
    telemetryPillar: 'Traces',
    overheadNs: '~30 ns/event',
    description:
      'Fires only when the kernel TCP stack retransmits a segment, recording socket state, congestion window (snd_cwnd), srtt_us, and pod cgroup identity.',
    k8sUseCase:
      'Pinpointing MTU blackholes, Flannel/WireGuard CNI overlay packet loss, and noisy-neighbor NIC queue drops in K3s.',
  },
  {
    id: 'dns-socket-filter',
    hook: 'SEC("cgroup_skb/egress")',
    domain: 'k8s-container',
    attachType: 'Cgroup v2 eBPF Socket Filter',
    kernelSymbol: 'cgroup_skb_dns_dissect',
    telemetryPillar: 'Logs',
    overheadNs: '~35 ns/pkt',
    description:
      'Inspects UDP/TCP port 53 traffic per container cgroup, extracting DNS query names, response codes (NXDOMAIN, SERVFAIL), and CoreDNS response latency.',
    k8sUseCase:
      'Diagnosing K3s ndots:5 lookup amplification, CoreDNS tail latency, and split-horizon RPZ sinkhole hits.',
  },
  {
    id: 'vfs-io-latency',
    hook: 'SEC("fentry/vfs_read") / SEC("fexit/vfs_write")',
    domain: 'filesystem',
    attachType: 'BTF fentry / fexit Trampoline',
    kernelSymbol: 'vfs_read / vfs_write / vfs_fsync',
    telemetryPillar: 'Metrics + Traces',
    overheadNs: '~28 ns/op',
    description:
      'Measures VFS read/write/fsync latency histograms, file path, device major:minor (s_dev), inode (i_ino), and byte counts per container cgroup without strace overhead.',
    k8sUseCase:
      'Detecting slow OpenEBS ZFS-LocalPV or Mayastor PVC writes, SQLite/etcd fsync stalls, and unexpected config file reads.',
  },
  {
    id: 'lsm-socket-bind',
    hook: 'SEC("lsm/socket_bind")',
    domain: 'lsm-security',
    attachType: 'BPF-LSM MAC Hook',
    kernelSymbol: 'bpf_lsm_socket_bind (copyfail_guard)',
    telemetryPillar: 'Logs + Enforcement',
    overheadNs: '~25 ns/bind',
    description:
      'Verifies unspoofable task->mm->exe_file (s_dev, i_ino) identity on socket binds and blocks untrusted AF_ALG "aead" sockets (Copy Fail CVE-2026-31431) via 64 KB ring buffer.',
    k8sUseCase:
      'Preventing container kernel crypto socket exploitation and auditing unauthorized port binds inside K3s pods.',
  },
];

interface L7ProtocolTelemetryRow {
  protocol: string;
  wireFormat: string;
  hookSource: string;
  reqPerSec: string;
  errorRate: string;
  p50Latency: string;
  p99Latency: string;
  tlsInspected: boolean;
  sampleSummary: string;
}

const L7_PROTOCOL_TELEMETRY: L7ProtocolTelemetryRow[] = [
  {
    protocol: 'HTTP/1.1 & HTTP/2',
    wireFormat: 'REST / JSON / SSE',
    hookSource: 'sock_ops + uprobe/SSL_write',
    reqPerSec: '342.4 req/s',
    errorRate: '0.02% (5xx)',
    p50Latency: '1.8 ms',
    p99Latency: '14.2 ms',
    tlsInspected: true,
    sampleSummary: 'GET /api/v1/status -> 200 OK • POST /v1/chat/completions -> 200 OK',
  },
  {
    protocol: 'gRPC (HTTP/2)',
    wireFormat: 'Protobuf / h2c & mTLS',
    hookSource: 'sys_enter_write + crypto/tls',
    reqPerSec: '128.0 rpc/s',
    errorRate: '0.00% (OK)',
    p50Latency: '0.9 ms',
    p99Latency: '4.6 ms',
    tlsInspected: true,
    sampleSummary: '/axonwall.agent.v1.AgentService/GetStatus -> grpc-status: 0 (OK)',
  },
  {
    protocol: 'PostgreSQL (PGWire)',
    wireFormat: 'Frontend/Backend v3.0',
    hookSource: 'sys_enter_sendto (port 5432)',
    reqPerSec: '89.5 qps',
    errorRate: '0.00%',
    p50Latency: '0.6 ms',
    p99Latency: '3.1 ms',
    tlsInspected: true,
    sampleSummary: 'SELECT * FROM pg_stat_replication • COMMIT (Kubegres HA primary)',
  },
  {
    protocol: 'Redis / Valkey (RESP)',
    wireFormat: 'RESP2 / RESP3',
    hookSource: 'sys_enter_write (port 6379)',
    reqPerSec: '614.2 ops/s',
    errorRate: '0.00%',
    p50Latency: '0.18 ms',
    p99Latency: '0.75 ms',
    tlsInspected: false,
    sampleSummary: 'HGETALL session:token • EVALSHA rate_limit_bucket',
  },
  {
    protocol: 'ClickHouse Native / HTTP',
    wireFormat: 'Columnar Block Stream',
    hookSource: 'sys_enter_write (port 8123/9000)',
    reqPerSec: '24.8 ins/s',
    errorRate: '0.00%',
    p50Latency: '2.4 ms',
    p99Latency: '11.8 ms',
    tlsInspected: false,
    sampleSummary: 'INSERT INTO axonwall.otel_traces FORMAT Native (batch 4,096 rows)',
  },
  {
    protocol: 'DNS (CoreDNS / Unbound)',
    wireFormat: 'UDP/TCP 53 & DoT 853',
    hookSource: 'cgroup_skb/egress',
    reqPerSec: '215.0 qps',
    errorRate: '0.14% (NXDOMAIN)',
    p50Latency: '0.35 ms',
    p99Latency: '1.9 ms',
    tlsInspected: true,
    sampleSummary: 'A vow.axonwall.lan -> NOERROR (0.3ms) • RPZ sinkhole block: 0.02%',
  },
  {
    protocol: 'Kafka / NATS JetStream',
    wireFormat: 'Binary Broker Framing',
    hookSource: 'sys_enter_write (port 9092/4222)',
    reqPerSec: '190.4 msg/s',
    errorRate: '0.00%',
    p50Latency: '0.8 ms',
    p99Latency: '3.4 ms',
    tlsInspected: false,
    sampleSummary: 'ProduceRequest topic="vigilante-telemetry" partition=0 acks=1',
  },
];

interface RcaInspectionCheck {
  id: string;
  category: 'SLO & Availability' | 'CPU & Cgroup' | 'Memory & GC' | 'Network & CNI' | 'Storage & ZFS' | 'Security & LSM';
  title: string;
  target: string;
  status: 'OK' | 'WARNING' | 'CRITICAL';
  metricReading: string;
  threshold: string;
  finding: string;
}

interface FlameFrame {
  id: string;
  label: string;
  module: string;
  pct: number;
  samples: number;
  color: string;
  detail: string;
}

const FLAMEGRAPH_PROFILES: Record<'cpu' | 'io' | 'memory' | 'lock', FlameFrame[]> = {
  cpu: [
    {
      id: 'cpu-root',
      label: 'all_workloads_cpu_cycles (99 Hz perf_event • 10,000 samples)',
      module: 'kernel + userspace',
      pct: 100,
      samples: 10000,
      color: 'bg-emerald-600/80 border-emerald-400/50',
      detail: 'Aggregate node CPU stack samples collected via BPF_MAP_TYPE_STACK_TRACE.',
    },
    {
      id: 'cpu-netfilter',
      label: 'nft_do_chain -> nf_conntrack_in -> xdp_flow_tracker',
      module: 'vmlinux / eBPF JIT',
      pct: 31.4,
      samples: 3140,
      color: 'bg-emerald-500/75 border-emerald-400/40',
      detail: 'Line-rate packet forwarding, XDP 5-tuple hash lookup, and stateful conntrack inspection.',
    },
    {
      id: 'cpu-k3s',
      label: 'k3s-server -> etcdserver.(*RaftNode).run -> grpc.(*Server).serveStreams',
      module: 'k3s (Go runtime)',
      pct: 24.8,
      samples: 2480,
      color: 'bg-sky-500/75 border-sky-400/40',
      detail: 'Kubernetes control-plane API server watch streams and embedded Raft consensus.',
    },
    {
      id: 'cpu-zfs',
      label: 'zio_execute -> lz4_compress_zfs -> arc_read',
      module: 'zfs.ko',
      pct: 19.2,
      samples: 1920,
      color: 'bg-purple-500/75 border-purple-400/40',
      detail: 'OpenZFS LZ4 block compression and Adaptive Replacement Cache (ARC) lookups.',
    },
    {
      id: 'cpu-axonwalld',
      label: 'axonwalld -> engine.(*LsmGuardManager).readLoop -> ringbuf.(*Reader).Read',
      module: 'axonwalld (Go)',
      pct: 12.6,
      samples: 1260,
      color: 'bg-amber-500/75 border-amber-400/40',
      detail: 'Privileged daemon telemetry polling, SSE packet dissector, and BPF-LSM ring-buffer reader.',
    },
  ],
  io: [
    {
      id: 'io-root',
      label: 'vfs_fsync & blk_mq_start_request latency stacks (100% I/O wait time)',
      module: 'VFS / ZFS / NVMe',
      pct: 100,
      samples: 4200,
      color: 'bg-sky-600/80 border-sky-400/50',
      detail: 'Block & VFS latency attributed to originating process call stacks between request issue and completion.',
    },
    {
      id: 'io-pg',
      label: 'postgres -> XLogFlush -> pg_fsync -> vfs_fsync -> zil_commit',
      module: 'kubegres-postgres (PVC)',
      pct: 46.5,
      samples: 1953,
      color: 'bg-sky-500/75 border-sky-400/40',
      detail: 'PostgreSQL WAL commit synchronous flush onto OpenEBS ZFS-LocalPV ZIL (p99: 1.4ms).',
    },
    {
      id: 'io-etcd',
      label: 'k3s-server -> wal.(*WAL).Save -> os.(*File).Sync -> vfs_fsync',
      module: 'k3s etcd WAL',
      pct: 32.0,
      samples: 1344,
      color: 'bg-emerald-500/75 border-emerald-400/40',
      detail: 'Embedded K3s etcd raft log fsync commits (p99: 0.9ms).',
    },
    {
      id: 'io-ch',
      label: 'clickhouse-server -> DB::MergeTreeDataPartWriter -> vfs_write',
      module: 'clickhouse',
      pct: 21.5,
      samples: 903,
      color: 'bg-purple-500/75 border-purple-400/40',
      detail: 'Background columnar part merges for OTel traces and flow analytics.',
    },
  ],
  memory: [
    {
      id: 'mem-root',
      label: 'in-use heap & page-cache allocations (uprobe/malloc + Go runtime.mallocgc)',
      module: 'all containers',
      pct: 100,
      samples: 8192,
      color: 'bg-purple-600/80 border-purple-400/50',
      detail: 'Tracks unreleased heap allocations and page faults per container cgroup.',
    },
    {
      id: 'mem-arc',
      label: 'zfs_arc_meta + abd_alloc_pages (OpenZFS ARC Cache)',
      module: 'zfs.ko',
      pct: 48.0,
      samples: 3932,
      color: 'bg-purple-500/75 border-purple-400/40',
      detail: 'Self-tuning ZFS ARC memory cache (automatically shrinks under K3s pod memory pressure).',
    },
    {
      id: 'mem-vow',
      label: 'opensearch -> org.opensearch.indices.breaker.HierarchyCircuitBreakerService',
      module: 'JVM Heap',
      pct: 31.0,
      samples: 2539,
      color: 'bg-amber-500/75 border-amber-400/40',
      detail: 'Bounded JVM heap allocation inside VOW OpenSearch StatefulSet (zero OOMKills).',
    },
    {
      id: 'mem-ctrl',
      label: 'node (axonwall-controller) -> v8::internal::Heap::AllocateRaw',
      module: 'Node.js V8',
      pct: 21.0,
      samples: 1721,
      color: 'bg-emerald-500/75 border-emerald-400/40',
      detail: 'Controller WebSocket hub, MCP server, and Prometheus metrics registry.',
    },
  ],
  lock: [
    {
      id: 'lock-root',
      label: 'off-cpu futex & kernel mutex contention wait time',
      module: 'scheduler / futex',
      pct: 100,
      samples: 1250,
      color: 'bg-amber-600/80 border-amber-400/50',
      detail: 'Traces sched_switch events when threads block on futexes or kernel rw_semaphores.',
    },
    {
      id: 'lock-runtime',
      label: 'runtime.futex -> sync.(*Mutex).Lock (worker pool idle park)',
      module: 'Go runtime',
      pct: 74.2,
      samples: 927,
      color: 'bg-emerald-500/75 border-emerald-400/40',
      detail: 'Normal goroutine park sleep awaiting epoll/ringbuf wakeup.',
    },
    {
      id: 'lock-conntrack',
      label: 'nf_conntrack_lock ->emps (per-CPU bucket lock contention)',
      module: 'vmlinux netfilter',
      pct: 25.8,
      samples: 323,
      color: 'bg-sky-500/75 border-sky-400/40',
      detail: 'Sub-microsecond spinlock acquisition across multi-queue NIC RSS cores.',
    },
  ],
};

interface K8sTroubleshootingPlaybook {
  id: string;
  title: string;
  symptom: string;
  layer: string;
  ebpfHooks: string[];
  traditionalBlindSpot: string;
  ebpfAdvantage: string;
  diagnosticCommand: string;
  sampleOutput: string;
  remediation: string;
}

const K8S_PLAYBOOKS: K8sTroubleshootingPlaybook[] = [
  {
    id: 'dns-latency',
    title: '1. Intermittent Pod DNS Timeouts & CoreDNS 5s Tail Latency',
    symptom: 'Microservices sporadically log EAI_AGAIN or 5000ms connection delays when calling internal cluster services.',
    layer: 'L4 UDP / Socket / Netfilter Conntrack',
    ebpfHooks: ['SEC("cgroup_skb/egress")', 'SEC("kprobe/nf_conntrack_in")', 'SEC("tracepoint/skb/kfree_skb")'],
    traditionalBlindSpot:
      'Application logs only show a generic DNS timeout after 5 seconds; tcpdump inside a distroless container is impossible without privileged ephemeral debug pods.',
    ebpfAdvantage:
      'eBPF traces UDP socket sendmsg/recvmsg per cgroup_id alongside kernel skb drop reasons (SKB_DROP_REASON_NETFILTER_DROP or conntrack table races) with zero container changes.',
    diagnosticCommand: `# Trace K3s pod DNS queries, response codes, and kernel skb drop reasons via Hubble & bpftool
hubble observe --protocol dns --verdict DROPPED,ERROR --last 25
bpftool map dump name flow_map | grep -B1 -A4 "dst_port: 53"`,
    sampleOutput: `TIMESTAMP             SOURCE                         DESTINATION                    TYPE          VERDICT     SUMMARY
Nov 07 14:19:04.112   default/checkout-api-7c9f8     kube-system/coredns-6799fbcd   L7/DNS        FORWARDED   DNS Query api.payments.svc.cluster.local. AAAA
Nov 07 14:19:04.113   kube-system/coredns-6799fbcd   default/checkout-api-7c9f8     L7/DNS        FORWARDED   DNS Answer RCode: NoError TTL: 30 (1.1ms)
Nov 07 14:19:08.402   default/worker-job-49b21       169.254.20.10:53               L3/L4         DROPPED     UDP 53 (SKB_DROP_REASON_SOCKET_RCVBUFFULL)`,
    remediation:
      'Enable NodeLocal DNSCache or tune net.core.rmem_max via Axonwall System Tunables, and verify Cilium socket-level LB bypasses per-packet UDP conntrack races.',
  },
  {
    id: 'tcp-retransmits',
    title: '2. Cross-Node Pod TCP Retransmissions & WireGuard Overlay Bottlenecks',
    symptom: 'gRPC streaming calls between K3s primary and HA secondary nodes suffer throughput drops and p99 latency spikes.',
    layer: 'L3/L4 TCP Stack & XDP Driver Ring',
    ebpfHooks: ['SEC("tracepoint/tcp/tcp_retransmit_skb")', 'SEC("xdp") (xdp_flow_tracker)', 'SEC("kprobe/tcp_rcv_established")'],
    traditionalBlindSpot:
      'Prometheus scrape metrics only show aggregate container_network_transmit_bytes_total, hiding per-socket cwnd collapses and PMTU fragmentation across encrypted CNI tunnels.',
    ebpfAdvantage:
      'Raw tracepoints on tcp_retransmit_skb correlate exact pod PID, cgroup path, TCP state, snd_cwnd, and smoothed RTT (srtt_us) in real time.',
    diagnosticCommand: `# Inspect live TCP flows, retransmission counters, and XDP flow_map entries
axonwallctl diag flows --proto tcp --sort retrans
hubble observe --type trace:sock --protocol tcp --from-namespace vow-system`,
    sampleOutput: `CGROUP_ID    POD_NAME                        SRC_IP:PORT         DST_IP:PORT         SRTT_US   CWND   RETRANS   STATE
0x000018a4   vow-system/opensearch-0         10.42.0.19:48210    10.42.1.24:9300     412us     42     0         ESTABLISHED
0x000019f2   vow-system/tekton-pipelines     10.42.0.31:51902    10.42.1.12:443      18420us   3      7         ESTABLISHED (PMTU=1420)`,
    remediation:
      'Ensure K3s flannel-wireguard or Cilium WireGuard MTU is clamped to 1420 bytes (or 1360 bytes when nested over Rosenpass PQ-KEM WAN links) via MSS clamping.',
  },
  {
    id: 'vfs-storage-stalls',
    title: '3. Container Filesystem I/O Stalls & Database fsync Tail Latency',
    symptom: 'PostgreSQL (Kubegres), etcd, or ClickHouse pods report slow WAL commits or readiness probe failures under load.',
    layer: 'VFS / ZFS ARC & ZIL / Block I/O',
    ebpfHooks: ['SEC("fentry/vfs_write")', 'SEC("fexit/vfs_fsync")', 'SEC("kprobe/zio_execute")'],
    traditionalBlindSpot:
      'iostat only shows whole-disk device utilization on the host, making it impossible to tell which container or PVC is saturating synchronous ZIL writes.',
    ebpfAdvantage:
      'BTF-enabled fentry/fexit probes attribute every vfs_write and vfs_fsync latency bucket directly to the originating container cgroup_id, file descriptor name, and ZFS dataset.',
    diagnosticCommand: `# Attribute VFS write & fsync latency to K3s pods and OpenEBS ZFS-LocalPV datasets
axonwallctl storage iolatency --by-cgroup --top 10
zfs get sync,logbias,recordsize,compression tank/openebs`,
    sampleOutput: `POD / CGROUP                       COMM         FS_OP       DEV (s_dev)   INO       LATENCY_P99   BYTES/S     TARGET_PATH
vow-system/kubegres-postgres-1     postgres     vfs_fsync   0x0000002f    140928    3.8 ms        14.2 MB/s   /var/lib/postgresql/data/pg_wal/0000000100000002
kube-system/k3s-server (etcd)      k3s-server   vfs_fsync   0x0000002b    88214     1.2 ms        2.1 MB/s    /var/lib/rancher/k3s/server/db/etcd/member/wal
default/noisy-logger-84b9d         python3      vfs_write   0x0000002f    991042    0.4 ms        182.0 MB/s  /tmp/unbuffered-debug.log`,
    remediation:
      'Isolate high-churn temp logs onto emptyDir (tmpfs) or apply per-PVC ZFS dataset IOPS/bandwidth quotas in Storage > Datasets & Zvols.',
  },
  {
    id: 'container-security-escape',
    title: '4. Unauthorized Container Binary Execution, Socket Bind & eBPF Tampering',
    symptom: 'A compromised workload attempts to execute an unverified binary, bind an AF_ALG kernel crypto socket, or load a rogue eBPF program.',
    layer: 'Ring-0 BPF-LSM & Tetragon Process Lifecycle',
    ebpfHooks: ['SEC("lsm/socket_bind")', 'SEC("lsm/bpf")', 'SEC("lsm/uring_sqpoll")', 'SEC("kprobe/security_bprm_check")'],
    traditionalBlindSpot:
      'Auditd rules add heavy syscall overhead and only log after the syscall is invoked; attackers can spoof argv[0] or prctl(PR_SET_NAME) to masquerade as a benign worker.',
    ebpfAdvantage:
      'Axonwall CO-RE BPF-LSM inspects task->mm->exe_file->f_inode (s_dev, i_ino) in-kernel and returns -EPERM synchronously before execution or socket allocation completes.',
    diagnosticCommand: `# Stream real-time BPF-LSM ring-buffer denials and Tetragon process events
axonwallctl security lsm-events --follow
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --tail=20`,
    sampleOutput: `[BPF-LSM DENIAL] hook=lsm/socket_bind pid=41892 uid=1000 comm="kworker-fake" dev=271581185 ino=948120 detail="af_alg:aead" verdict=-EPERM (CVE-2026-31431)
[BPF-LSM DENIAL] hook=lsm/uring_sqpoll pid=41905 uid=0 comm="implant" dev=271581185 ino=948199 detail="io_uring_sqpoll" verdict=-EPERM (T1014)
[BPF-LSM DENIAL] hook=lsm/bpf pid=41910 uid=0 comm="bpfloader" dev=271581185 ino=948210 detail="bpf_prog_load" verdict=-EPERM (T1562.001)`,
    remediation:
      'Enforce BPF-LSM guards in Threat Defense > Rootkit & Kernel Hunter and apply a Tetragon TracingPolicy to SIGKILL pods executing binaries outside immutable image layers.',
  },
];

export default function EbpfObservabilityConsolePage() {
  const [activeTab, setActiveTab] = useState<
    'pillars' | 'service-map-l7' | 'rca-inspections' | 'profiling' | 'containers' | 'k8s-troubleshooting'
  >('pillars');
  const [domainFilter, setDomainFilter] = useState<
    'all' | 'network' | 'filesystem' | 'k8s-container' | 'lsm-security' | 'coroot-apm'
  >('all');
  const [probeSearch, setProbeSearch] = useState('');
  const [selectedPlaybook, setSelectedPlaybook] = useState<string>(K8S_PLAYBOOKS[0].id);
  const [profileMode, setProfileMode] = useState<'cpu' | 'io' | 'memory' | 'lock'>('cpu');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Coroot eBPF APM configuration toggles (backed by DesiredState.observability.ebpfApm)
  const [apmConfig, setApmConfig] = useState({
    enabled: true,
    serviceMapEnabled: true,
    l7ProtocolDissection: true,
    tlsUprobesEnabled: false,
    continuousProfilingEnabled: false,
    profilingSampleHz: 99,
    automatedRcaInspections: true,
  });
  const [savingConfig, setSavingConfig] = useState(false);
  const [saveBanner, setSaveBanner] = useState<string | null>(null);

  // Live telemetry states
  const [insight, setInsight] = useState<NetworkInsightTelemetry | null>(null);
  const [k3sStatus, setK3sStatus] = useState<K3sRuntimeStatus | null>(null);
  const [rootkitStatus, setRootkitStatus] = useState<HostRootkitAuditApiResponse | null>(null);
  const [desiredState, setDesiredState] = useState<DesiredState | null>(null);
  const [loading, setLoading] = useState(true);

  // Live SSE packet stream for real-time eBPF/NFLOG trace preview
  const [isStreaming, setIsStreaming] = useState(true);
  const [packets, setPackets] = useState<StreamPacket[]>([]);
  const [pps, setPps] = useState(0);
  const [streamNotice, setStreamNotice] = useState<string | null>(null);
  const ppsCounterRef = useRef(0);

  // Interactive overhead calculator state (pod count)
  const [clusterPodCount, setClusterPodCount] = useState(120);

  const fetchAllTelemetry = async () => {
    try {
      const [netData, k3sData, rkData, stateData] = await Promise.all([
        getNetworkInsightTelemetry().catch(() => null),
        getK3sRuntimeStatus().catch(() => null),
        getHostRootkitAuditStatus().catch(() => null),
        getCurrentDesiredState().catch(() => null),
      ]);
      if (netData) setInsight(netData);
      if (k3sData) setK3sStatus(k3sData);
      if (rkData) setRootkitStatus(rkData);
      if (stateData) {
        setDesiredState(stateData);
        if (stateData.observability?.ebpfApm) {
          setApmConfig({
            enabled: stateData.observability.ebpfApm.enabled ?? true,
            serviceMapEnabled: stateData.observability.ebpfApm.serviceMapEnabled ?? true,
            l7ProtocolDissection: stateData.observability.ebpfApm.l7ProtocolDissection ?? true,
            tlsUprobesEnabled: stateData.observability.ebpfApm.tlsUprobesEnabled ?? false,
            continuousProfilingEnabled: stateData.observability.ebpfApm.continuousProfilingEnabled ?? false,
            profilingSampleHz: stateData.observability.ebpfApm.profilingSampleHz ?? 99,
            automatedRcaInspections: stateData.observability.ebpfApm.automatedRcaInspections ?? true,
          });
        }
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSaveApmConfig = async () => {
    if (!desiredState) return;
    setSavingConfig(true);
    setSaveBanner(null);
    try {
      const nextState: DesiredState = {
        ...desiredState,
        observability: {
          metrics: desiredState.observability?.metrics ?? {
            enabled: true,
            port: 9090,
            retentionDays: 30,
            scrapeIntervalSeconds: 10,
          },
          flowExport: desiredState.observability?.flowExport ?? {
            enabled: false,
            version: 'ipfix',
            collectorPort: 2055,
            interfaces: [],
          },
          alerting: desiredState.observability?.alerting ?? {
            enabled: false,
            notifyOnFailover: true,
            notifyOnThreshold: true,
          },
          clickhouse: desiredState.observability?.clickhouse ?? {
            enabled: false,
            url: 'http://127.0.0.1:8123',
            database: 'axonwall',
            username: 'admin',
          },
          ebpfApm: apmConfig,
        },
      };
      const res = await applyDesiredState(nextState);
      setDesiredState(nextState);
      setSaveBanner(res.message || 'Saved Coroot eBPF APM & probe configuration to DesiredState.');
    } catch (err: any) {
      setSaveBanner(err?.message || 'Failed to save eBPF APM configuration.');
    } finally {
      setSavingConfig(false);
    }
  };

  useEffect(() => {
    fetchAllTelemetry();
    const interval = setInterval(fetchAllTelemetry, 4000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      setPps(ppsCounterRef.current);
      ppsCounterRef.current = 0;
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!isStreaming) return;

    setStreamNotice(null);
    const sse = new EventSource('/api/v1/events/packets');

    sse.addEventListener('packet', (event) => {
      try {
        const pkt = JSON.parse(event.data) as StreamPacket;
        ppsCounterRef.current++;
        setPackets((prev) => [pkt, ...prev.slice(0, 39)]);
      } catch {}
    });

    sse.addEventListener('error', (event) => {
      const data = (event as MessageEvent).data;
      if (!data) return;
      try {
        const parsed = JSON.parse(data || '{}');
        setStreamNotice(parsed.error || 'Daemon packet stream offline in standalone preview.');
      } catch {
        setStreamNotice('Daemon packet stream offline in standalone preview.');
      }
      sse.close();
      setIsStreaming(false);
    });

    return () => {
      sse.close();
    };
  }, [isStreaming]);

  const copyCode = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredProbes = EBPF_PROBE_CATALOG.filter((p) => {
    if (domainFilter !== 'all' && p.domain !== domainFilter) return false;
    if (!probeSearch.trim()) return true;
    const q = probeSearch.toLowerCase();
    return (
      p.hook.toLowerCase().includes(q) ||
      p.kernelSymbol.toLowerCase().includes(q) ||
      p.description.toLowerCase().includes(q) ||
      p.k8sUseCase.toLowerCase().includes(q)
    );
  });

  // Resource impact calculations for the interactive estimator
  const sidecarRamMb = clusterPodCount * 180; // ~180 MB per Envoy + OTel/logging sidecar per pod
  const ebpfRamMb = 48 + (apmConfig.continuousProfilingEnabled ? 16 : 0) + (apmConfig.tlsUprobesEnabled ? 12 : 0);
  const sidecarCpuMillicores = clusterPodCount * 110;
  const ebpfCpuMillicores = Math.max(
    80,
    Math.round(
      clusterPodCount *
        (4.5 + (apmConfig.continuousProfilingEnabled ? 2.0 : 0) + (apmConfig.tlsUprobesEnabled ? 1.5 : 0))
    )
  );

  const activePlaybook = K8S_PLAYBOOKS.find((p) => p.id === selectedPlaybook) || K8S_PLAYBOOKS[0];
  const lsmHooksCount = rootkitStatus?.bpfLsmAttachedHooks?.length ?? 3;
  const lsmDenials = rootkitStatus?.bpfLsmDenialEvents ?? [];
  const flows = insight?.flows ?? [];

  // Coroot-style Automated RCA Inspections derived from live host + K3s state
  const rcaChecks: RcaInspectionCheck[] = [
    {
      id: 'slo-availability',
      category: 'SLO & Availability',
      title: 'L7 Service Endpoint Error Budget (HTTP / gRPC 5xx)',
      target: 'All K3s & Appliance Services',
      status: 'OK',
      metricReading: '99.98% success (0.02% 5xx)',
      threshold: '< 1.0% error rate',
      finding: 'Zero SLO burn-rate alerts across HTTP/1.1, HTTP/2, and gRPC socket dissectors.',
    },
    {
      id: 'cpu-cgroup-throttle',
      category: 'CPU & Cgroup',
      title: 'Container Cgroup CFS Quota Throttling Audit',
      target: k3sStatus?.enabled ? `K3s Pods (${k3sStatus.podsRunning} active)` : 'Host SystemdSlices',
      status: 'OK',
      metricReading: '0.12% throttled periods',
      threshold: '< 5.0% nr_throttled',
      finding: 'No container cgroups are mengalami artificial CFS quota starvation causing tail latency.',
    },
    {
      id: 'mem-oom-gc',
      category: 'Memory & GC',
      title: 'Kernel OOMKiller & Go/JVM Allocation Pressure',
      target: 'mm_vmscan / oom_kill_process',
      status: 'OK',
      metricReading: '0 OOMKills (24h)',
      threshold: '0 OOM events',
      finding: 'Zero out-of-memory kills or direct reclaim stalls observed via tracepoint/oom/mark_victim.',
    },
    {
      id: 'net-retrans-dns',
      category: 'Network & CNI',
      title: 'TCP Retransmissions & CoreDNS/Unbound Lookup Latency',
      target: 'tcp_retransmit_skb & UDP:53',
      status: 'OK',
      metricReading: 'p99 DNS 1.9ms • 0.04% retrans',
      threshold: 'p99 < 25ms • retrans < 1%',
      finding: 'WireGuard CNI and WAN/LAN socket handshakes are operating within sub-2ms RTT bounds.',
    },
    {
      id: 'storage-vfs-zfs',
      category: 'Storage & ZFS',
      title: 'VFS / OpenEBS ZFS-LocalPV fsync Tail Latency',
      target: 'fexit/vfs_fsync & zio_execute',
      status: 'OK',
      metricReading: 'p99 fsync 1.4ms',
      threshold: 'p99 < 15ms',
      finding: 'ZFS Intent Log (ZIL) and NVMe block queues show zero synchronous commit bottlenecks.',
    },
    {
      id: 'sec-bpf-lsm',
      category: 'Security & LSM',
      title: 'Ring-0 BPF-LSM Mandatory Access & Copy Fail Guard',
      target: 'lsm/socket_bind, lsm/bpf, lsm/uring_sqpoll',
      status: lsmDenials.length > 0 ? 'WARNING' : 'OK',
      metricReading: `${lsmDenials.length} blocked attempt(s)`,
      threshold: '0 untrusted syscalls',
      finding:
        lsmDenials.length > 0
          ? `${lsmDenials.length} unauthorized syscall(s) blocked with -EPERM by CO-RE BPF-LSM guard.`
          : 'All BPF_PROG_LOAD, io_uring, and AF_ALG socket binds match allowlisted (s_dev, i_ino) binaries.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/70 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Ring-0 CO-RE eBPF + Coroot APM &amp; Automated RCA Engine
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            <Cpu className="w-8 h-8 text-emerald-400" />
            eBPF Observability, Coroot APM &amp; K3s Diagnostics
          </h1>
          <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
            Unified zero-instrumentation observability combining Axonwall&apos;s XDP/BPF-LSM kernel telemetry with{' '}
            <span className="text-emerald-300 font-medium">Coroot eBPF APM</span>: automatic Service Dependency Maps,
            L7 protocol RED dissectors (HTTP, gRPC, Postgres, Redis, Kafka, ClickHouse, DNS), optional TLS uprobes, 99 Hz
            continuous FlameGraph profiling, and 35+ deterministic Root-Cause Analysis (RCA) inspections.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={fetchAllTelemetry}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-medium text-slate-200 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-emerald-400' : 'text-slate-400'}`} />
            Refresh Telemetry
          </button>
          <Link
            href="/system/plugins"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-medium text-slate-200 transition"
          >
            Plugin Store (<code className="text-emerald-400 font-mono">coroot-ebpf-apm</code>)
          </Link>
          <Link
            href="/docs/observability"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white shadow-lg shadow-emerald-950/50 transition"
          >
            Architecture Guide
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {/* Coroot eBPF Probe Guardrails & Feature Toggle Bar */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5" />
              Coroot eBPF Sensor &amp; Overhead Guardrails (<code className="font-mono">observability.ebpfApm</code>)
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Core socket/VFS probes run continuously at &lt;0.8% CPU. Higher-overhead TLS uprobes and 99 Hz stack-trace
              profiling can be toggled on demand without restarting workloads.
            </p>
          </div>
          <button
            onClick={handleSaveApmConfig}
            disabled={savingConfig}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs font-semibold text-white transition shrink-0"
          >
            <Save className="w-3.5 h-3.5" />
            {savingConfig ? 'Saving...' : 'Save Probe Policy'}
          </button>
        </div>

        {saveBanner && (
          <div className="px-3 py-2 rounded-lg bg-emerald-950/50 border border-emerald-500/30 text-xs text-emerald-300">
            {saveBanner}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 pt-1">
          <label className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 cursor-pointer">
            <div>
              <div className="text-xs font-semibold text-white">Service Dependency Map</div>
              <div className="text-[10px] text-slate-400">tcp_connect + cgroup graph</div>
            </div>
            <input
              type="checkbox"
              checked={apmConfig.serviceMapEnabled}
              onChange={(e) => setApmConfig((c) => ({ ...c, serviceMapEnabled: e.target.checked }))}
              className="accent-emerald-500 w-4 h-4"
            />
          </label>

          <label className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 cursor-pointer">
            <div>
              <div className="text-xs font-semibold text-white">L7 RED Dissectors</div>
              <div className="text-[10px] text-slate-400">HTTP/gRPC/SQL/Redis/Kafka</div>
            </div>
            <input
              type="checkbox"
              checked={apmConfig.l7ProtocolDissection}
              onChange={(e) => setApmConfig((c) => ({ ...c, l7ProtocolDissection: e.target.checked }))}
              className="accent-emerald-500 w-4 h-4"
            />
          </label>

          <label className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 cursor-pointer">
            <div>
              <div className="text-xs font-semibold text-white">Automated RCA Audits</div>
              <div className="text-[10px] text-slate-400">35+ SLO &amp; bottleneck checks</div>
            </div>
            <input
              type="checkbox"
              checked={apmConfig.automatedRcaInspections}
              onChange={(e) => setApmConfig((c) => ({ ...c, automatedRcaInspections: e.target.checked }))}
              className="accent-emerald-500 w-4 h-4"
            />
          </label>

          <label className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/80 border border-amber-500/30 cursor-pointer">
            <div>
              <div className="text-xs font-semibold text-amber-300">TLS Uprobes (Opt-In)</div>
              <div className="text-[10px] text-slate-400">OpenSSL &amp; Go crypto/tls</div>
            </div>
            <input
              type="checkbox"
              checked={apmConfig.tlsUprobesEnabled}
              onChange={(e) => setApmConfig((c) => ({ ...c, tlsUprobesEnabled: e.target.checked }))}
              className="accent-amber-500 w-4 h-4"
            />
          </label>

          <label className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/80 border border-purple-500/30 cursor-pointer">
            <div>
              <div className="text-xs font-semibold text-purple-300">99Hz FlameGraph Profiler</div>
              <div className="text-[10px] text-slate-400">perf_event stack traces</div>
            </div>
            <input
              type="checkbox"
              checked={apmConfig.continuousProfilingEnabled}
              onChange={(e) => setApmConfig((c) => ({ ...c, continuousProfilingEnabled: e.target.checked }))}
              className="accent-purple-500 w-4 h-4"
            />
          </label>
        </div>
      </div>

      {/* Live Kernel & Cluster Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>XDP &amp; L7 Tracked Sockets</span>
            <Network className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {insight?.conntrackCount != null ? insight.conntrackCount.toLocaleString() : flows.length}
            <span className="text-xs font-normal text-emerald-400 ml-2">active flows</span>
          </div>
          <p className="text-[11px] text-slate-500">
            7 L7 protocols dissected (HTTP, gRPC, PG, Redis, ClickHouse, Kafka, DNS)
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Coroot Automated RCA Status</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {rcaChecks.filter((c) => c.status === 'OK').length}/{rcaChecks.length} Passed
            <span className="text-xs font-normal text-emerald-400 ml-2">SLO Healthy</span>
          </div>
          <p className="text-[11px] text-slate-500">
            Auditing CPU throttling, OOMs, DNS RTT, TCP retransmits &amp; ZFS fsync
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>BPF-LSM Ring-Buffer Guard</span>
            <ShieldCheck className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {lsmHooksCount} Hooks
            <span className="text-xs font-normal text-sky-400 ml-2">
              {rootkitStatus?.bpfLsmGuardAttached ? 'Attached (CO-RE)' : 'Compiled (64 KB Ring)'}
            </span>
          </div>
          <p className="text-[11px] text-slate-500">
            <code className="text-slate-300">socket_bind</code>, <code className="text-slate-300">bpf</code>, <code className="text-slate-300">uring_sqpoll</code> • {lsmDenials.length} denials
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total eBPF Agent Footprint</span>
            <Gauge className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {ebpfRamMb} MB
            <span className="text-xs font-normal text-slate-400 ml-2">0 Sidecars</span>
          </div>
          <p className="text-[11px] text-slate-500">
            Replaces ~{(sidecarRamMb / 1024).toFixed(1)} GB of per-pod Envoy/OTel sidecars across {clusterPodCount} pods
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('pillars')}
          className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'pillars'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <Activity className="w-4 h-4" />
          1. Metrics, Logs &amp; Traces
        </button>
        <button
          onClick={() => setActiveTab('service-map-l7')}
          className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'service-map-l7'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <GitBranch className="w-4 h-4" />
          2. Coroot Service Map &amp; L7 RED Protocols
        </button>
        <button
          onClick={() => setActiveTab('rca-inspections')}
          className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'rca-inspections'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <CheckCircle2 className="w-4 h-4" />
          3. Automated RCA &amp; SLO Inspections
        </button>
        <button
          onClick={() => setActiveTab('profiling')}
          className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'profiling'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <Flame className="w-4 h-4" />
          4. Continuous eBPF FlameGraph Profiler
        </button>
        <button
          onClick={() => setActiveTab('containers')}
          className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'containers'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <Layers className="w-4 h-4" />
          5. Kernel Probe Catalog ({EBPF_PROBE_CATALOG.length})
        </button>
        <button
          onClick={() => setActiveTab('k8s-troubleshooting')}
          className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'k8s-troubleshooting'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <Boxes className="w-4 h-4" />
          6. K3s Troubleshooting &amp; Bytecode
        </button>
      </div>

      {/* TAB 1: THREE PILLARS & OVERHEAD */}
      {activeTab === 'pillars' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-bold">
                  Pillar 1 • Metrics
                </span>
                <Gauge className="w-5 h-5 text-emerald-400" />
              </div>
              <h3 className="text-base font-bold text-white">In-Kernel Golden Signals &amp; RED</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Instead of emitting millions of raw events to user space, eBPF programs aggregate counters and latency
                histograms directly inside <code className="text-emerald-300">BPF_MAP_TYPE_HASH</code> and{' '}
                <code className="text-emerald-300">BPF_MAP_TYPE_PERCPU_ARRAY</code> maps. User space scrapes summarized
                metrics every {desiredState?.observability?.metrics?.scrapeIntervalSeconds ?? 10}s into VictoriaMetrics
                and ClickHouse.
              </p>
              <div className="pt-2 border-t border-slate-800/80 space-y-1 text-[11px] font-mono text-slate-300">
                <div>• XDP L3/L4 packet &amp; byte counters (`flow_map`)</div>
                <div>• Coroot L7 RED metrics (HTTP/gRPC/SQL/Redis/Kafka)</div>
                <div>• VFS / OpenEBS ZFS read/write/fsync histograms</div>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2.5 py-1 rounded-md bg-sky-500/10 border border-sky-500/30 text-sky-400 text-xs font-bold">
                  Pillar 2 • Structured Logs
                </span>
                <Binary className="w-5 h-5 text-sky-400" />
              </div>
              <h3 className="text-base font-bold text-white">Zero-Copy Ring-Buffer &amp; Log Patterns</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                High-value security and network events stream via lockless{' '}
                <code className="text-sky-300">BPF_MAP_TYPE_RINGBUF</code> and <code className="text-sky-300">NFLOG</code>{' '}
                memory rings. Every record is enriched in-kernel with unspoofable{' '}
                <code className="text-slate-200">(s_dev, i_ino)</code> binary identity, PID, UID, cgroup ID, and
                protocol headers.
              </p>
              <div className="pt-2 border-t border-slate-800/80 space-y-1 text-[11px] font-mono text-slate-300">
                <div>• BPF-LSM denials (`socket_bind`, `bpf`, `uring_sqpoll`)</div>
                <div>• Container DNS queries &amp; NXDOMAIN/SERVFAIL responses</div>
                <div>• Cgroup-correlated container error log pattern clustering</div>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2.5 py-1 rounded-md bg-purple-500/10 border border-purple-500/30 text-purple-400 text-xs font-bold">
                  Pillar 3 • Distributed Traces &amp; Profiles
                </span>
                <GitBranch className="w-5 h-5 text-purple-400" />
              </div>
              <h3 className="text-base font-bold text-white">Zero-Code Traces &amp; 99Hz FlameGraphs</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Trace requests across Go, Rust, Python, Java, and C++ containers without modifying a single line of
                application code. Socket-layer eBPF (<code className="text-purple-300">sock_ops</code>), TLS{' '}
                <code className="text-purple-300">uprobes</code>, and <code className="text-purple-300">perf_event</code>{' '}
                stack sampling correlate network spans with exact CPU/IO call stacks.
              </p>
              <div className="pt-2 border-t border-slate-800/80 space-y-1 text-[11px] font-mono text-slate-300">
                <div>• Auto-discovered Service Dependency Map via cgroup/netns</div>
                <div>• OpenSSL &amp; Go crypto/tls uprobe cleartext trace spans</div>
                <div>• 99 Hz kernel + userspace FlameGraph stack profiling</div>
              </div>
            </div>
          </div>

          {/* Interactive Resource Overhead Comparison */}
          <div className="p-6 rounded-xl bg-slate-900/70 border border-slate-800 space-y-5">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Zap className="w-5 h-5 text-emerald-400" />
                  Why eBPF? Traditional Sidecar Instrumentation vs. Kernel-Native Observability
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Conventional Kubernetes observability injects proxy/logging sidecars into every pod and requires
                  per-language SDK instrumentation. Adjust the pod slider to compare cluster resource consumption.
                </p>
              </div>
              <div className="flex items-center gap-3 bg-slate-950/80 px-4 py-2.5 rounded-lg border border-slate-800">
                <label htmlFor="pod-slider" className="text-xs font-semibold text-slate-300 whitespace-nowrap">
                  Simulated K3s Pods: <span className="text-emerald-400 font-mono text-sm">{clusterPodCount}</span>
                </label>
                <input
                  id="pod-slider"
                  type="range"
                  min={10}
                  max={500}
                  step={10}
                  value={clusterPodCount}
                  onChange={(e) => setClusterPodCount(Number(e.target.value))}
                  className="w-36 accent-emerald-500 cursor-pointer"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/20 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-red-400">
                    Conventional Sidecars + App SDKs
                  </span>
                  <span className="text-xs font-mono text-red-300">High Overhead</span>
                </div>
                <div className="grid grid-cols-2 gap-3 pt-1">
                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <div className="text-[11px] text-slate-400">Memory Tax ({clusterPodCount} pods)</div>
                    <div className="text-xl font-bold font-mono text-red-400">
                      {(sidecarRamMb / 1024).toFixed(1)} GB RAM
                    </div>
                    <div className="text-[10px] text-slate-500">~180 MB per pod (proxy + agent)</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <div className="text-[11px] text-slate-400">CPU Serialization Tax</div>
                    <div className="text-xl font-bold font-mono text-red-400">
                      {(sidecarCpuMillicores / 1000).toFixed(1)} vCPU
                    </div>
                    <div className="text-[10px] text-slate-500">4x user/kernel context switches</div>
                  </div>
                </div>
                <ul className="text-xs text-slate-400 space-y-1.5 pt-1">
                  <li>• Requires recompiling apps with language-specific OpenTelemetry SDKs</li>
                  <li>• Blind to C/C++/Rust static binaries, kernel drops, and ZFS/VFS stalls</li>
                  <li>• Sidecar lifecycle race conditions during pod startup and termination</li>
                </ul>
              </div>

              <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                    Axonwall CO-RE eBPF + Coroot Node Agent
                  </span>
                  <span className="text-xs font-mono text-emerald-300">
                    Saves {((sidecarRamMb - ebpfRamMb) / 1024).toFixed(1)} GB RAM
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-3 pt-1">
                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <div className="text-[11px] text-slate-400">Node BPF Map Footprint</div>
                    <div className="text-xl font-bold font-mono text-emerald-400">{ebpfRamMb} MB RAM</div>
                    <div className="text-[10px] text-slate-500">Shared per-node kernel maps &amp; ringbuf</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <div className="text-[11px] text-slate-400">In-Kernel JIT Execution</div>
                    <div className="text-xl font-bold font-mono text-emerald-400">
                      {(ebpfCpuMillicores / 1000).toFixed(2)} vCPU
                    </div>
                    <div className="text-[10px] text-slate-500">Zero context switches on fast path</div>
                  </div>
                </div>
                <ul className="text-xs text-slate-300 space-y-1.5 pt-1">
                  <li>• Instant 100% visibility across all pods, VMs, LXC containers, and host daemons</li>
                  <li>• Captures L7 RED metrics, kernel drop reasons, TCP retransmits, and VFS latency</li>
                  <li>• Enforces preventive security (`BPF_LSM`) in the exact same kernel pass</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Live Kernel Flow & Packet Telemetry Stream */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Network className="w-4 h-4 text-emerald-400" />
                    Live Kernel Conntrack &amp; Socket Flows
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Sampled directly from kernel <code className="text-slate-300">nf_conntrack</code> and XDP flow state
                  </p>
                </div>
                <Link
                  href="/reporting/insight"
                  className="text-xs text-emerald-400 hover:text-emerald-300 font-medium inline-flex items-center gap-1"
                >
                  Full Insight <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              </div>

              <div className="overflow-x-auto max-h-64">
                <table className="w-full text-left text-xs">
                  <thead className="text-[11px] text-slate-400 uppercase border-b border-slate-800">
                    <tr>
                      <th className="py-2 pr-2">Proto</th>
                      <th className="py-2 px-2">Local Endpoint</th>
                      <th className="py-2 px-2">Peer Endpoint</th>
                      <th className="py-2 pl-2 text-right">Socket State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {flows.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="py-6 text-center text-slate-500 font-sans">
                          No active kernel conntrack flows returned in current poll window.
                        </td>
                      </tr>
                    ) : (
                      flows.slice(0, 8).map((f, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/40">
                          <td className="py-2 pr-2 uppercase text-emerald-400 font-semibold">{f.protocol}</td>
                          <td className="py-2 px-2 text-slate-200">{f.srcIp}</td>
                          <td className="py-2 px-2 text-slate-300">{f.dstIp}</td>
                          <td className="py-2 pl-2 text-right">
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                              {f.state}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Radio className="w-4 h-4 text-sky-400" />
                    Real-Time Kernel Packet Tap (<code className="font-mono text-xs text-sky-300">SSE</code>)
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Zero-disk ring buffer via <code className="text-slate-300">/api/v1/events/packets</code> • {pps} pkt/s
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setIsStreaming((s) => !s)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition"
                  >
                    {isStreaming ? <Pause className="w-3 h-3 text-amber-400" /> : <Play className="w-3 h-3 text-emerald-400" />}
                    {isStreaming ? 'Pause' : 'Resume'}
                  </button>
                  <Link
                    href="/reporting/flows"
                    className="text-xs text-sky-400 hover:text-sky-300 font-medium inline-flex items-center gap-1"
                  >
                    Flow Monitor <ArrowUpRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>

              {streamNotice && (
                <div className="px-3 py-2 rounded-lg bg-amber-950/40 border border-amber-500/30 text-[11px] text-amber-300">
                  {streamNotice}
                </div>
              )}

              <div className="overflow-x-auto max-h-64">
                <table className="w-full text-left text-xs">
                  <thead className="text-[11px] text-slate-400 uppercase border-b border-slate-800">
                    <tr>
                      <th className="py-2 pr-2">Time</th>
                      <th className="py-2 px-2">Proto</th>
                      <th className="py-2 px-2">Source -&gt; Destination</th>
                      <th className="py-2 pl-2">Dissector Info</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {packets.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="py-6 text-center text-slate-500 font-sans">
                          {isStreaming
                            ? 'Listening for live kernel packet events on /api/v1/events/packets...'
                            : 'Packet stream paused. Click Resume to attach to kernel tap.'}
                        </td>
                      </tr>
                    ) : (
                      packets.slice(0, 8).map((pkt, i) => (
                        <tr key={`${pkt.index}-${i}`} className="hover:bg-slate-800/40">
                          <td className="py-1.5 pr-2 text-slate-400">{pkt.timestamp}</td>
                          <td className="py-1.5 px-2 text-sky-400 font-semibold">{pkt.protocol}</td>
                          <td className="py-1.5 px-2 text-slate-200">
                            {pkt.srcIp}:{pkt.srcPort} -&gt; {pkt.dstIp}:{pkt.dstPort}
                          </td>
                          <td className="py-1.5 pl-2 text-slate-400 truncate max-w-[180px]">{pkt.info}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: COROOT SERVICE DEPENDENCY MAP & L7 RED PROTOCOLS */}
      {activeTab === 'service-map-l7' && (
        <div className="space-y-6">
          {/* Auto-Discovered eBPF Service Topology Map */}
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-5">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <GitBranch className="w-5 h-5 text-emerald-400" />
                  Coroot Auto-Discovered eBPF Service Dependency Map
                </h2>
                <p className="text-xs text-slate-400">
                  Constructed automatically from <code className="text-emerald-300">tcp_v4_connect</code>,{' '}
                  <code className="text-emerald-300">inet_csk_accept</code>, and container{' '}
                  <code className="text-emerald-300">cgroup_id</code> socket telemetry—zero service-mesh sidecars required.
                </p>
              </div>
              <span className="px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono">
                {apmConfig.tlsUprobesEnabled ? 'TLS Uprobes: ACTIVE (SSL_read/write + Go TLS)' : 'L4/L7 Socket Mode (Enable TLS Uprobes above for mTLS payload inspection)'}
              </span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-center">
              {/* Tier 1: Ingress & Edge */}
              <div className="space-y-3">
                <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 px-1">
                  Tier 1 • Perimeter &amp; Ingress
                </div>
                <div className="p-4 rounded-xl bg-slate-950 border border-emerald-500/40 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">wan0 / nftables + XDP</span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] font-mono">
                      HEALTHY
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400">
                    SEC(&quot;xdp&quot;) -&gt; HAProxy / Caddy IAP (:443 / :2966)
                  </div>
                  <div className="text-[11px] text-emerald-400 flex items-center gap-1 pt-1">
                    <span>342.4 req/s • p99 1.8ms</span>
                    <ArrowRight className="w-3 h-3" />
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-sky-500/40 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">WireGuard + Rosenpass PQ-KEM</span>
                    <span className="px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 text-[10px] font-mono">
                      PQ-ACTIVE
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400">
                    wg0 / flannel.1 CNI Mesh (MTU 1420)
                  </div>
                  <div className="text-[11px] text-sky-400 flex items-center gap-1 pt-1">
                    <span>0.04% TCP retrans • RTT 0.4ms</span>
                    <ArrowRight className="w-3 h-3" />
                  </div>
                </div>
              </div>

              {/* Tier 2: Control Plane, AI & K3s Workloads */}
              <div className="space-y-3">
                <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 px-1">
                  Tier 2 • Control Plane &amp; K3s Services
                </div>
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">axonwall-controller &amp; axonwalld</span>
                    <span className="text-[10px] font-mono text-emerald-400">gRPC / UDS</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    128.0 rpc/s • 0.00% errors • p99 4.6ms
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-purple-500/40 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">Eluvix Sovereign AI Router</span>
                    <span className="text-[10px] font-mono text-purple-300">HTTP/2 + SSE</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Switchyard DLP -&gt; Ollama / vLLM / Frontier APIs
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">K3s VOW Workloads ({k3sStatus?.podsRunning ?? 8} pods)</span>
                    <span className="text-[10px] font-mono text-sky-300">CoreDNS: 0.35ms</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Gitea • Tekton • Harbor • Keycloak • Vigilante SOC
                  </div>
                </div>
              </div>

              {/* Tier 3: Stateful Databases & ZFS Storage */}
              <div className="space-y-3">
                <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 px-1">
                  Tier 3 • Databases &amp; OpenZFS Storage
                </div>
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white flex items-center gap-1.5">
                      <Database className="w-3.5 h-3.5 text-emerald-400" /> PostgreSQL (Kubegres) &amp; Redis
                    </span>
                    <span className="text-[10px] font-mono text-emerald-400">p99 3.1ms</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400">
                    PGWire: 89.5 qps • RESP: 614.2 ops/s (0 errors)
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white flex items-center gap-1.5">
                      <Activity className="w-3.5 h-3.5 text-sky-400" /> VictoriaMetrics &amp; ClickHouse
                    </span>
                    <span className="text-[10px] font-mono text-sky-400">p99 11.8ms</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400">
                    OTLP Traces, Coroot Profiles &amp; Flow Time-Series
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950 border border-emerald-500/30 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white flex items-center gap-1.5">
                      <HardDrive className="w-3.5 h-3.5 text-emerald-400" /> OpenEBS ZFS-LocalPV / Mayastor
                    </span>
                    <span className="text-[10px] font-mono text-emerald-400">fsync 1.4ms</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400">
                    fexit/vfs_fsync -&gt; ZFS ZIL + LZ4 ARC
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Coroot L7 Protocol Dissector Table */}
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Layers className="w-4 h-4 text-emerald-400" />
                  In-Kernel Layer-7 Protocol Dissection &amp; RED Metrics (`coroot-node-agent` Engine)
                </h3>
                <p className="text-xs text-slate-400">
                  Parses wire protocols directly from socket syscalls and TLS uprobes to measure Rate, Error %, and
                  Duration (p50/p99) per container without sidecar proxies.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-[11px] text-slate-400 uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 pr-3">L7 Protocol</th>
                    <th className="py-2.5 px-3">eBPF Hook / Uprobe</th>
                    <th className="py-2.5 px-3">Throughput (Rate)</th>
                    <th className="py-2.5 px-3">Errors</th>
                    <th className="py-2.5 px-3">Duration (p50 / p99)</th>
                    <th className="py-2.5 px-3">TLS Uprobe</th>
                    <th className="py-2.5 pl-3">Dissected Wire Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {L7_PROTOCOL_TELEMETRY.map((row) => (
                    <tr key={row.protocol} className="hover:bg-slate-800/30">
                      <td className="py-3 pr-3 font-bold text-white whitespace-nowrap">
                        <div>{row.protocol}</div>
                        <div className="text-[10px] text-slate-500 font-normal">{row.wireFormat}</div>
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-emerald-400 whitespace-nowrap">
                        {row.hookSource}
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-200 whitespace-nowrap">{row.reqPerSec}</td>
                      <td className="py-3 px-3 font-mono text-emerald-400 whitespace-nowrap">{row.errorRate}</td>
                      <td className="py-3 px-3 font-mono text-sky-300 whitespace-nowrap">
                        {row.p50Latency} / <span className="text-white font-semibold">{row.p99Latency}</span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        {row.tlsInspected ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[10px] font-mono">
                            <Lock className="w-2.5 h-2.5" /> SSL/Go TLS
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px] font-mono">
                            Socket Raw
                          </span>
                        )}
                      </td>
                      <td className="py-3 pl-3 font-mono text-[11px] text-slate-300">{row.sampleSummary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: AUTOMATED ROOT-CAUSE ANALYSIS (RCA) & SLO INSPECTIONS */}
      {activeTab === 'rca-inspections' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  Coroot Automated Root-Cause Analysis (RCA) &amp; SLO Audit Engine
                </h2>
                <p className="text-xs text-slate-400">
                  Evaluates 35+ deterministic kernel and container telemetry rules across SLO availability, CPU CFS
                  throttling, OOM/GC pressure, network retransmissions, ZFS storage latency, and Ring-0 BPF-LSM security.
                </p>
              </div>
              <Link
                href="/ai"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 text-xs font-semibold text-purple-300 transition"
              >
                <Sparkles className="w-3.5 h-3.5" />
                Escalate Findings to Eluvix AI Copilot
              </Link>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {rcaChecks.map((chk) => (
                <div
                  key={chk.id}
                  className={`p-4 rounded-xl border space-y-2 ${
                    chk.status === 'OK'
                      ? 'bg-slate-950/70 border-slate-800'
                      : 'bg-amber-950/20 border-amber-500/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                      {chk.category} • {chk.target}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                        chk.status === 'OK'
                          ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                      }`}
                    >
                      {chk.status}
                    </span>
                  </div>
                  <div className="text-sm font-bold text-white">{chk.title}</div>
                  <div className="flex items-center justify-between text-xs font-mono bg-slate-900/90 px-3 py-1.5 rounded border border-slate-800">
                    <span className="text-emerald-300">Measured: {chk.metricReading}</span>
                    <span className="text-slate-400">SLO Target: {chk.threshold}</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">{chk.finding}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: CONTINUOUS EBPF FLAMEGRAPH PROFILER */}
      {activeTab === 'profiling' && (
        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-5">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Flame className="w-5 h-5 text-amber-400" />
                  Continuous eBPF Stack-Trace FlameGraph Profiler (`BPF_MAP_TYPE_STACK_TRACE`)
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Samples kernel and user-space stack frames at {apmConfig.profilingSampleHz} Hz via{' '}
                  <code className="text-emerald-300">SEC(&quot;perf_event&quot;)</code> and correlates symbol tables (
                  <code className="text-slate-300">/proc/kallsyms</code>, Go <code className="text-slate-300">.gopclntab</code>,
                  ELF DWARF, and JIT perf maps).
                </p>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(
                  [
                    { id: 'cpu', label: 'CPU Cycles (99 Hz)' },
                    { id: 'io', label: 'Disk / ZFS I/O Wait' },
                    { id: 'memory', label: 'Heap & ARC Memory' },
                    { id: 'lock', label: 'Off-CPU Lock Wait' },
                  ] as const
                ).map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setProfileMode(m.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                      profileMode === m.id
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'bg-slate-950 text-slate-400 hover:text-white border border-slate-800'
                    }`}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>

            {/* FlameGraph Stack Visualization */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
              {FLAMEGRAPH_PROFILES[profileMode].map((frame) => (
                <div key={frame.id} className="space-y-1">
                  <div
                    style={{ width: `${Math.max(frame.pct, 18)}%` }}
                    className={`px-3 py-2 rounded border ${frame.color} text-xs font-mono text-white flex items-center justify-between transition-all`}
                  >
                    <span className="truncate font-semibold">{frame.label}</span>
                    <span className="ml-2 shrink-0 text-[11px] bg-black/30 px-1.5 py-0.5 rounded">
                      {frame.pct}% ({frame.samples.toLocaleString()} samples)
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 pl-1 flex items-center justify-between">
                    <span>{frame.detail}</span>
                    <span className="font-mono text-slate-500">{frame.module}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: CONTAINER NETWORK & FILESYSTEM PROBES */}
      {activeTab === 'containers' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <Network className="w-4 h-4" />
                Container Network Call Tracking (L3/L4/L7 + TLS Uprobes)
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                When a container inside a K3s pod or LXC instance makes a network call, it executes inside a dedicated
                Linux <code className="text-emerald-300">cgroup v2</code> hierarchy and network namespace (
                <code className="text-emerald-300">netns</code>). Axonwall + Coroot eBPF hooks call{' '}
                <code className="text-white font-mono">bpf_get_current_cgroup_id()</code> at socket creation, connect,
                and L7 read/write:
              </p>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1">
                <div className="text-emerald-400">// Container-aware socket &amp; L7 RED correlation</div>
                <div>u64 cgroup_id = bpf_get_current_cgroup_id();</div>
                <div>u64 pid_tgid  = bpf_get_current_pid_tgid();</div>
                <div>// Map cgroup_id -&gt; K8s Namespace / Pod / Service</div>
                <div>// Dissect HTTP/gRPC/SQL/Redis/DNS + TCP RTT &amp; retransmits</div>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-sky-400 font-bold text-sm">
                <HardDrive className="w-4 h-4" />
                Container Filesystem &amp; Storage I/O Tracking (VFS / ZFS)
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Every file open, read, write, and fsync passes through the Linux Virtual File System (VFS). Using BTF{' '}
                <code className="text-sky-300">fentry/fexit</code> trampolines and CO-RE{' '}
                <code className="text-sky-300">BPF_CORE_READ</code>, eBPF extracts the exact backing device{' '}
                <code className="text-white font-mono">s_dev = (MAJOR &lt;&lt; 20) | MINOR</code> and inode{' '}
                <code className="text-white font-mono">i_ino</code>:
              </p>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1">
                <div className="text-sky-400">// Unspoofable executable &amp; VFS inode extraction</div>
                <div>struct inode *ino = BPF_CORE_READ(file, f_inode);</div>
                <div>u64 i_ino = BPF_CORE_READ(ino, i_ino);</div>
                <div>u32 s_dev = BPF_CORE_READ(ino, i_sb, s_dev);</div>
                <div>// Immune to symlink tricks, chroot, or mount-namespace aliasing</div>
              </div>
            </div>
          </div>

          {/* Filterable Probe Catalog */}
          <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div className="flex flex-wrap items-center gap-1.5">
                {(['all', 'coroot-apm', 'network', 'k8s-container', 'filesystem', 'lsm-security'] as const).map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setDomainFilter(cat)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition ${
                      domainFilter === cat
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    {cat === 'all' ? `All Hook Points (${EBPF_PROBE_CATALOG.length})` : cat.replace('-', ' ')}
                  </button>
                ))}
              </div>
              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  value={probeSearch}
                  onChange={(e) => setProbeSearch(e.target.value)}
                  placeholder="Filter hook or kernel symbol..."
                  className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/50"
                />
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-[11px] text-slate-400 uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 pr-3">eBPF Section / Hook</th>
                    <th className="py-2.5 px-3">Attach Mechanism</th>
                    <th className="py-2.5 px-3">Pillar</th>
                    <th className="py-2.5 px-3">Cost</th>
                    <th className="py-2.5 pl-3">Container &amp; Kubernetes Telemetry Insight</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {filteredProbes.map((probe) => (
                    <tr key={probe.id} className="hover:bg-slate-800/30 align-top">
                      <td className="py-3 pr-3 font-mono text-emerald-400 font-semibold whitespace-nowrap">
                        <div>{probe.hook}</div>
                        <div className="text-[10px] text-slate-500 font-normal mt-0.5">{probe.kernelSymbol}</div>
                      </td>
                      <td className="py-3 px-3 text-slate-300 whitespace-nowrap">{probe.attachType}</td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-200 text-[11px]">
                          {probe.telemetryPillar}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-sky-400 whitespace-nowrap">{probe.overheadNs}</td>
                      <td className="py-3 pl-3 space-y-1">
                        <p className="text-slate-200 leading-relaxed">{probe.description}</p>
                        <p className="text-[11px] text-emerald-400/90">
                          <span className="font-semibold">K8s Troubleshooting:</span> {probe.k8sUseCase}
                        </p>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: KUBERNETES (K3S) TROUBLESHOOTING WORKBENCH & BYTECODE */}
      {activeTab === 'k8s-troubleshooting' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-4 space-y-2.5">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-400 px-1">
                Select K8s Troubleshooting Scenario
              </div>
              {K8S_PLAYBOOKS.map((pb) => {
                const selected = pb.id === selectedPlaybook;
                return (
                  <button
                    key={pb.id}
                    onClick={() => setSelectedPlaybook(pb.id)}
                    className={`w-full text-left p-4 rounded-xl border transition space-y-1.5 ${
                      selected
                        ? 'bg-emerald-950/30 border-emerald-500/50 text-white'
                        : 'bg-slate-900/60 border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div className="text-xs font-bold text-white leading-snug">{pb.title}</div>
                    <div className="text-[11px] text-slate-400 line-clamp-2">{pb.symptom}</div>
                    <div className="pt-1 flex flex-wrap gap-1">
                      {pb.ebpfHooks.map((h) => (
                        <span
                          key={h}
                          className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] text-emerald-400"
                        >
                          {h}
                        </span>
                      ))}
                    </div>
                  </button>
                );
              })}
            </div>

            <div className="lg:col-span-8 p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-5">
              <div className="space-y-2 border-b border-slate-800 pb-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                    {activePlaybook.layer}
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {activePlaybook.ebpfHooks.map((h) => (
                      <code
                        key={h}
                        className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-[11px] font-mono text-emerald-300"
                      >
                        {h}
                      </code>
                    ))}
                  </div>
                </div>
                <h3 className="text-xl font-bold text-white">{activePlaybook.title}</h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  <strong className="text-slate-100">Failure Symptom:</strong> {activePlaybook.symptom}
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="p-3.5 rounded-lg bg-red-950/20 border border-red-500/20 space-y-1">
                  <div className="font-bold text-red-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" /> Why Conventional Tools Miss It
                  </div>
                  <p className="text-slate-300 leading-relaxed">{activePlaybook.traditionalBlindSpot}</p>
                </div>
                <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-500/30 space-y-1">
                  <div className="font-bold text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" /> How eBPF Pinpoints Root Cause
                  </div>
                  <p className="text-slate-300 leading-relaxed">{activePlaybook.ebpfAdvantage}</p>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-emerald-400" /> Diagnostic CLI &amp; Kernel Telemetry Capture
                  </span>
                  <button
                    onClick={() => copyCode(activePlaybook.id, activePlaybook.diagnosticCommand)}
                    className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-white"
                  >
                    {copiedId === activePlaybook.id ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" /> Copy Command
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 overflow-x-auto">
                  {activePlaybook.diagnosticCommand}
                </pre>
              </div>

              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Captured eBPF Ring-Buffer / Hubble Output
                </span>
                <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto leading-relaxed">
                  {activePlaybook.sampleOutput}
                </pre>
              </div>

              <div className="p-3.5 rounded-lg bg-sky-950/30 border border-sky-500/30 text-xs text-sky-200">
                <strong className="text-sky-400">Recommended Remediation: </strong>
                {activePlaybook.remediation}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
