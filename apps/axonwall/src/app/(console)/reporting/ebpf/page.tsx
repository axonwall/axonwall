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
} from 'lucide-react';
import {
  getNetworkInsightTelemetry,
  getK3sRuntimeStatus,
  getHostRootkitAuditStatus,
  getCurrentDesiredState,
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
  domain: 'network' | 'filesystem' | 'k8s-container' | 'lsm-security';
  attachType: string;
  kernelSymbol: string;
  telemetryPillar: 'Metrics' | 'Logs' | 'Traces' | 'Metrics + Traces' | 'Logs + Enforcement';
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
    id: 'tcp-connect-trace',
    hook: 'SEC("kprobe/tcp_v4_connect")',
    domain: 'k8s-container',
    attachType: 'CO-RE Kprobe + SockOps',
    kernelSymbol: 'tcp_v4_connect / tcp_set_state',
    telemetryPillar: 'Metrics + Traces',
    overheadNs: '~45 ns/call',
    description:
      'Captures every container outbound TCP handshake, correlating pid, cgroup_id, network namespace inode, SYN-to-ESTABLISHED RTT, and destination service endpoint.',
    k8sUseCase:
      'Service-to-service dependency mapping, detecting upstream connection timeouts, and identifying unencrypted egress.',
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
  {
    id: 'lsm-bpf-uring',
    hook: 'SEC("lsm/bpf") / SEC("lsm/uring_sqpoll")',
    domain: 'lsm-security',
    attachType: 'BPF-LSM MAC Hook',
    kernelSymbol: 'restrict_bpf_load / block_uring_sqpoll',
    telemetryPillar: 'Logs + Enforcement',
    overheadNs: '~22 ns/call',
    description:
      'Restricts BPF_PROG_LOAD to allowlisted (s_dev, i_ino) binaries and blocks zero-syscall io_uring IORING_SETUP_SQPOLL kernel busy-poll threads.',
    k8sUseCase:
      'Stopping privileged container escapes from loading rogue eBPF programs or hiding C2 traffic in io_uring rings.',
  },
];

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
  const [activeTab, setActiveTab] = useState<'pillars' | 'containers' | 'k8s-troubleshooting' | 'bytecode'>('pillars');
  const [domainFilter, setDomainFilter] = useState<'all' | 'network' | 'filesystem' | 'k8s-container' | 'lsm-security'>('all');
  const [probeSearch, setProbeSearch] = useState('');
  const [selectedPlaybook, setSelectedPlaybook] = useState<string>(K8S_PLAYBOOKS[0].id);
  const [copiedId, setCopiedId] = useState<string | null>(null);

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
      if (stateData) setDesiredState(stateData);
    } finally {
      setLoading(false);
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
  const ebpfRamMb = 48; // Single per-node kernel BPF map + ring-buffer footprint (~48 MB)
  const sidecarCpuMillicores = clusterPodCount * 110; // ~0.11 vCPU per pod in sidecar serialization/context-switches
  const ebpfCpuMillicores = Math.max(80, Math.round(clusterPodCount * 4.5)); // In-kernel CO-RE map updates

  const activePlaybook = K8S_PLAYBOOKS.find((p) => p.id === selectedPlaybook) || K8S_PLAYBOOKS[0];
  const lsmHooksCount = rootkitStatus?.bpfLsmAttachedHooks?.length ?? 3;
  const lsmDenials = rootkitStatus?.bpfLsmDenialEvents ?? [];
  const flows = insight?.flows ?? [];

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/70 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Ring-0 CO-RE eBPF Telemetry • Zero Application Instrumentation
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            <Cpu className="w-8 h-8 text-emerald-400" />
            eBPF Infrastructure &amp; Kubernetes Observability
          </h1>
          <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
            Gather high-resolution <span className="text-slate-200 font-medium">metrics, logs, and distributed traces</span> directly
            from the Linux kernel without application SDKs or sidecar proxies. Track container network calls, VFS/ZFS
            filesystem operations, and BPF-LSM security events with sub-microsecond overhead to troubleshoot Kubernetes
            (K3s) clusters at line rate.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={fetchAllTelemetry}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-medium text-slate-200 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-emerald-400' : 'text-slate-400'}`} />
            Refresh Kernel State
          </button>
          <Link
            href="/docs/observability"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white shadow-lg shadow-emerald-950/50 transition"
          >
            Architecture Guide
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {/* Live Kernel & Cluster Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>XDP &amp; Conntrack Flow Map</span>
            <Network className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {insight?.conntrackCount != null ? insight.conntrackCount.toLocaleString() : flows.length}
            <span className="text-xs font-normal text-emerald-400 ml-2">active sockets</span>
          </div>
          <p className="text-[11px] text-slate-500">
            Zero-copy <code className="text-slate-300">SEC(&quot;xdp&quot;)</code> + <code className="text-slate-300">nf_conntrack</code> kernel state
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
            <span>Kubernetes (K3s) eBPF Mesh</span>
            <Boxes className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {k3sStatus?.enabled ? `${k3sStatus.podsRunning}/${k3sStatus.podsTotal} Pods` : 'Standby'}
            <span className="text-xs font-normal text-purple-400 ml-2">
              {k3sStatus?.nodes?.length ? `${k3sStatus.nodes.length} Node(s)` : 'Cilium + Tetragon Ready'}
            </span>
          </div>
          <p className="text-[11px] text-slate-500">
            Cgroup v2 socket LB, Hubble L7 DNS/HTTP flows &amp; VFS I/O attribution
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Instrumentation Overhead</span>
            <Gauge className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            &lt; 0.8% CPU
            <span className="text-xs font-normal text-slate-400 ml-2">0 Sidecars</span>
          </div>
          <p className="text-[11px] text-slate-500">
            In-kernel JIT aggregation vs. 8–15% CPU for traditional user-space agents
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('pillars')}
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'pillars'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <Activity className="w-4 h-4" />
          1. Metrics, Logs &amp; Traces (Zero-Overhead)
        </button>
        <button
          onClick={() => setActiveTab('containers')}
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'containers'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <Layers className="w-4 h-4" />
          2. Container Network &amp; Filesystem Probes
        </button>
        <button
          onClick={() => setActiveTab('k8s-troubleshooting')}
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'k8s-troubleshooting'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <Boxes className="w-4 h-4" />
          3. Kubernetes (K3s) Troubleshooting Workbench
        </button>
        <button
          onClick={() => setActiveTab('bytecode')}
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
            activeTab === 'bytecode'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          <FileCode className="w-4 h-4" />
          4. CO-RE eBPF Programs &amp; TracingPolicy
        </button>
      </div>

      {/* TAB 1: THREE PILLARS & OVERHEAD */}
      {activeTab === 'pillars' && (
        <div className="space-y-6">
          {/* Three Pillars of eBPF Telemetry */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-bold">
                  Pillar 1 • Metrics
                </span>
                <Gauge className="w-5 h-5 text-emerald-400" />
              </div>
              <h3 className="text-base font-bold text-white">In-Kernel Golden Signals</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Instead of emitting millions of raw events to user space, eBPF programs aggregate counters and latency
                histograms directly inside <code className="text-emerald-300">BPF_MAP_TYPE_HASH</code> and{' '}
                <code className="text-emerald-300">BPF_MAP_TYPE_PERCPU_ARRAY</code> maps. User space reads summarized
                metrics at fixed intervals (`{desiredState?.observability?.metrics?.scrapeIntervalSeconds ?? 10}s`) for
                VictoriaMetrics &amp; Prometheus.
              </p>
              <div className="pt-2 border-t border-slate-800/80 space-y-1 text-[11px] font-mono text-slate-300">
                <div>• XDP L3/L4 packet &amp; byte counters (`flow_map`)</div>
                <div>• TCP handshake RTT &amp; retransmission rates</div>
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
              <h3 className="text-base font-bold text-white">Zero-Copy Ring-Buffer Events</h3>
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
                <div>• Tetragon process execve &amp; sensitive file open audit</div>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2.5 py-1 rounded-md bg-purple-500/10 border border-purple-500/30 text-purple-400 text-xs font-bold">
                  Pillar 3 • Distributed Traces
                </span>
                <GitBranch className="w-5 h-5 text-purple-400" />
              </div>
              <h3 className="text-base font-bold text-white">Language-Agnostic Kernel Tracing</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Trace requests across Go, Rust, Python, Java, and C++ containers without modifying a single line of
                application code. Socket-layer eBPF (<code className="text-purple-300">sock_ops</code> /{' '}
                <code className="text-purple-300">sk_msg</code>) and <code className="text-purple-300">uprobes</code>{' '}
                correlate ingress/egress sockets and TLS handshakes automatically.
              </p>
              <div className="pt-2 border-t border-slate-800/80 space-y-1 text-[11px] font-mono text-slate-300">
                <div>• Pod-to-pod service graph via cgroup &amp; netns inodes</div>
                <div>• Kernel-to-socket path latency (NIC -&gt; XDP -&gt; TCP -&gt; VFS)</div>
                <div>• OpenTelemetry &amp; Hubble span export without SDKs</div>
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
                    Axonwall CO-RE eBPF + Cilium/Tetragon
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
                  <li>• Captures kernel packet drop reasons, TCP retransmits, and VFS latency histograms</li>
                  <li>• Enforces preventive security (`BPF_LSM`) in the exact same kernel pass</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Live Kernel Flow & Packet Telemetry Stream */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Live Tracked Kernel Flows */}
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

            {/* Live NFLOG / eBPF Packet Stream */}
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

      {/* TAB 2: CONTAINER NETWORK & FILESYSTEM PROBES */}
      {activeTab === 'containers' && (
        <div className="space-y-6">
          {/* How eBPF Attributes Container Network & Filesystem Activity */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <Network className="w-4 h-4" />
                Container Network Call Tracking (L3/L4/L7)
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                When a container inside a K3s pod or LXC instance makes a network call, it executes inside a dedicated
                Linux <code className="text-emerald-300">cgroup v2</code> hierarchy and network namespace (
                <code className="text-emerald-300">netns</code>). Axonwall eBPF hooks call{' '}
                <code className="text-white font-mono">bpf_get_current_cgroup_id()</code> and{' '}
                <code className="text-white font-mono">bpf_get_netns_cookie()</code> at socket creation, connect, and
                packet transmission:
              </p>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1">
                <div className="text-emerald-400">// Container-aware socket telemetry correlation</div>
                <div>u64 cgroup_id = bpf_get_current_cgroup_id();</div>
                <div>u64 pid_tgid  = bpf_get_current_pid_tgid();</div>
                <div>// Map cgroup_id -&gt; K8s Namespace / Pod / Container</div>
                <div>// Track TCP SYN-&gt;ACK RTT, bytes, DNS queries &amp; drops</div>
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
                {(['all', 'network', 'k8s-container', 'filesystem', 'lsm-security'] as const).map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setDomainFilter(cat)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition ${
                      domainFilter === cat
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    {cat === 'all' ? 'All Hook Points (7)' : cat.replace('-', ' ')}
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

          {/* Live Ring-Buffer Denials & Active io_uring Rings */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-emerald-400" />
                  Live BPF-LSM Ring-Buffer Telemetry (<code className="font-mono text-xs text-emerald-300">events</code>)
                </h3>
                <Link
                  href="/security/rootkit-hunter"
                  className="text-xs text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1"
                >
                  Manage LSM Policy <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              </div>
              {lsmDenials.length === 0 ? (
                <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs text-slate-400 flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    Zero unauthorized <code className="text-slate-200">AF_ALG aead</code> socket binds, rogue{' '}
                    <code className="text-slate-200">BPF_PROG_LOAD</code> calls, or{' '}
                    <code className="text-slate-200">io_uring</code> SQPOLL threads detected in ring buffer.
                  </span>
                </div>
              ) : (
                <div className="overflow-x-auto max-h-56">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="text-[10px] text-slate-400 uppercase border-b border-slate-800">
                      <tr>
                        <th className="py-1.5 pr-2">Hook</th>
                        <th className="py-1.5 px-2">Comm (PID)</th>
                        <th className="py-1.5 px-2">(s_dev, i_ino)</th>
                        <th className="py-1.5 pl-2">Detail</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-[11px]">
                      {lsmDenials.slice(0, 6).map((ev, idx) => (
                        <tr key={idx}>
                          <td className="py-1.5 pr-2 text-red-400">{ev.hook}</td>
                          <td className="py-1.5 px-2 text-slate-200">
                            {ev.comm} ({ev.pid})
                          </td>
                          <td className="py-1.5 px-2 text-slate-400">
                            {ev.dev}:{ev.ino}
                          </td>
                          <td className="py-1.5 pl-2 text-amber-300">{ev.detail}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Eye className="w-4 h-4 text-sky-400" />
                  Allowlisted Executable Inodes (<code className="font-mono text-xs text-sky-300">allowlist</code> map)
                </h3>
                <span className="text-[11px] font-mono text-slate-400">
                  kernel s_dev = (major &lt;&lt; 20) | minor
                </span>
              </div>
              <div className="overflow-x-auto max-h-56">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="text-[10px] text-slate-400 uppercase border-b border-slate-800">
                    <tr>
                      <th className="py-1.5 pr-2">Binary Path</th>
                      <th className="py-1.5 px-2">Kernel s_dev</th>
                      <th className="py-1.5 pl-2">Inode (i_ino)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-[11px]">
                    {(rootkitStatus?.bpfLsmAllowlist && rootkitStatus.bpfLsmAllowlist.length > 0
                      ? rootkitStatus.bpfLsmAllowlist
                      : [
                          { path: '/usr/sbin/axonwalld (/proc/self/exe)', dev: 271581185, ino: 131074, flags: 1 },
                          { path: '/usr/sbin/bpftool', dev: 271581185, ino: 131490, flags: 1 },
                        ]
                    ).map((entry, idx) => (
                      <tr key={idx}>
                        <td className="py-1.5 pr-2 text-emerald-300">{entry.path}</td>
                        <td className="py-1.5 px-2 text-slate-300">0x{entry.dev.toString(16)}</td>
                        <td className="py-1.5 pl-2 text-slate-300">{entry.ino}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: KUBERNETES (K3S) TROUBLESHOOTING WORKBENCH */}
      {activeTab === 'k8s-troubleshooting' && (
        <div className="space-y-6">
          {/* K3s Cluster & Observability Stack Status Bar */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                <Server className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <div className="text-sm font-bold text-white flex items-center gap-2">
                  In-House K3s Cluster &amp; eBPF Observability Sensors
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      k3sStatus?.enabled
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {k3sStatus?.enabled ? 'ACTIVE' : 'STANDBY (Enable in K3s > Cluster)'}
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Correlates Cilium Hubble L3/L4/L7 flows, Tetragon kernel process/VFS events, and OpenEBS ZFS storage
                  latency across all K3s namespaces.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Link
                href="/k3s/cluster"
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition"
              >
                K3s Cluster
              </Link>
              <Link
                href="/k3s/vow"
                className="px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-xs font-medium text-emerald-300 transition"
              >
                VOW Observability Stack
              </Link>
            </div>
          </div>

          {/* Interactive Playbook Selector + Detail Panel */}
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

      {/* TAB 4: CO-RE EBPF PROGRAMS & TRACINGPOLICY */}
      {activeTab === 'bytecode' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Program 1: XDP Flow Tracker */}
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white font-mono">apps/axonwalld/ebpf/flow_tracker.c</h3>
                  <p className="text-xs text-slate-400">
                    Line-rate XDP 5-tuple flow counter &amp; IP blocklist drop filter (`SEC(&quot;xdp&quot;)`)
                  </p>
                </div>
                <button
                  onClick={() =>
                    copyCode(
                      'xdp-code',
                      `SEC("xdp")\nint xdp_flow_tracker(struct xdp_md *ctx) {\n    void *data_end = (void *)(long)ctx->data_end;\n    void *data = (void *)(long)ctx->data;\n    struct ethhdr *eth = data;\n    if ((void *)(eth + 1) > data_end) return XDP_PASS;\n    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;\n    struct iphdr *ip = data + sizeof(struct ethhdr);\n    if ((void *)(ip + 1) > data_end) return XDP_PASS;\n    // Atomic per-flow packet & byte accounting in BPF_MAP_TYPE_HASH\n    return XDP_PASS;\n}`
                    )
                  }
                  className="text-xs text-slate-400 hover:text-white inline-flex items-center gap-1"
                >
                  {copiedId === 'xdp-code' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  Copy
                </button>
              </div>
              <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto leading-relaxed">
{`struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
};

SEC("xdp")
int xdp_flow_tracker(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    // Parses IPv4 + TCP/UDP 5-tuple and updates flow_map atomically
    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, (data_end - data));
    return XDP_PASS;
}`}
              </pre>
            </div>

            {/* Program 2: Tetragon K8s Container Network & VFS TracingPolicy */}
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white font-mono">k3s/tetragon-container-observability.yaml</h3>
                  <p className="text-xs text-slate-400">
                    Declarative K3s <code className="text-emerald-300">TracingPolicy</code> for container socket &amp; VFS I/O tracing
                  </p>
                </div>
                <button
                  onClick={() =>
                    copyCode(
                      'tetragon-yaml',
                      `apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: axonwall-container-net-vfs-observability\nspec:\n  kprobes:\n    - call: "tcp_connect"\n      syscall: false\n      args:\n        - index: 0\n          type: "sock"\n    - call: "security_file_open"\n      syscall: false\n      args:\n        - index: 0\n          type: "file"`
                    )
                  }
                  className="text-xs text-slate-400 hover:text-white inline-flex items-center gap-1"
                >
                  {copiedId === 'tetragon-yaml' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  Copy
                </button>
              </div>
              <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto leading-relaxed">
{`apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: axonwall-container-net-vfs-observability
spec:
  kprobes:
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
    - call: "tcp_retransmit_skb"
      syscall: false
      args:
        - index: 0
          type: "sock"
    - call: "security_file_open"
      syscall: false
      args:
        - index: 0
          type: "file"
      selectors:
        - matchNamespaces:
            - namespace: Mnt
              operator: NotIn
              values: ["host_ns"]`}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
