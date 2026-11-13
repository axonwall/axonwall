import React from 'react';
import { Cpu, Database, Terminal, ShieldCheck } from 'lucide-react';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Kubernetes (K3s), Cilium eBPF CNI, Etcd Snapshots & OpenEBS | Axonwall Documentation',
  description:
    'Complete guide to running K3s Kubernetes and OpenEBS distributed storage on Axonwall v0.11.68: Cilium eBPF CNI (kube-proxy replacement + Hubble), embedded etcd snapshots & S3 backup/restore, automated HA peer join, WireGuard flannel mesh, axonwall-kubeconfig VIP sync, ZFS-LocalPV, and Mayastor NVMe-oF replication.',
};

export default function K3sKubernetesDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Container Orchestration &amp; Cloud-Native Storage • v0.11.68
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Kubernetes (K3s) &amp; OpenEBS Distributed Storage
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall provides modern, lightweight K3s alongside enterprise-grade NAS storage configured via{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/k3s.yaml</code>. Both <code className="text-slate-200 font-mono">kubectl</code> and <code className="text-slate-200 font-mono">helm</code> v3 are bundled out-of-the-box via the default <code className="text-emerald-400 font-mono">cli-workstation</code> plugin. Run containerized workloads
          directly on your appliance with encrypted WireGuard flannel networking, automated 2-node embedded-etcd HA cluster join, and
          OpenEBS replicated persistent volumes.
        </p>
      </div>

      {/* Overview */}
      <section className="space-y-6">
        <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-xs text-slate-300 leading-relaxed">
          <strong className="text-cyan-300">Barebones K3s + Storage Edition (<code className="font-mono">k3s-storage</code>):</strong>{' '}
          Deploying a dedicated headless K3s + OpenZFS/OpenEBS node without firewall/NAS bloat? Select the{' '}
          <strong className="text-white">k3s-storage</strong> edition directly from the unified ISO bootloader or installer TUI (see{' '}
          <a href="/docs/installer-raid-zfs#k3s-storage-edition" className="text-cyan-400 underline">Barebones K3s + Storage Guide</a>) and pair it with our{' '}
          <a href="/docs/custom-kernel" className="text-indigo-300 underline">Hardened Linux 6.12 LTS Kernel &amp; Custom Kernel Studio</a>.
        </div>

        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> Embedded K3s Architecture
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          K3s is packaged as a single binary with zero external dependencies, embedded SQLite/etcd consensus, and
          native Containerd. Axonwall manages K3s through the privileged Go daemon (
          <code className="text-emerald-400 font-mono">axonwalld</code>), which generates declarative control plane
          manifests and reconciles cluster state.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div id="wireguard" className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-base">WireGuard Native Flannel</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Pod-to-pod cross-node traffic is automatically encrypted using Linux kernel WireGuard (
              <code className="text-slate-200">flannelBackend: &quot;wireguard-native&quot;</code>), requiring zero
              overlay CPU overhead.
            </p>
          </div>

          <div id="ha-join" className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-base">Automatic 2-Node HA Join</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              When <code className="text-emerald-400 font-mono">autoJoinHaPeer: true</code> is enabled, the secondary HA
              node connects to the primary node over mTLS, fetches the cluster join token via{' '}
              <code className="text-slate-200">/api/v1/sync/k3s-token</code> into{' '}
              <code className="text-slate-200">/var/lib/axonwall/k3s-join.token</code>, and joins the cluster
              automatically.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-base">VIP Ingress Integration</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              K3s workloads bind directly to Axonwall VRRP Virtual IPs, ensuring that if a physical node experiences
              hardware failure, traffic routes to the surviving node in under one second.
            </p>
          </div>
        </div>

        <CodeBlock
          title="Declarative K3s, Cilium eBPF CNI, Etcd S3 Snapshots & OpenEBS (/etc/axonwall/k3s.yaml)"
          language="yaml"
          code={`k3s:
  enabled: true
  clusterCidr: 10.42.0.0/16
  serviceCidr: 10.43.0.0/16
  nodeIpInterface: lan
  cniPlugin: cilium-ebpf          # 'flannel' (WireGuard) or 'cilium-ebpf' (kube-proxy replacement)
  ciliumHubbleEnabled: true       # L7 eBPF pod flow observability when cniPlugin=cilium-ebpf
  flannelBackend: wireguard-native
  disableTraefik: false
  autoJoinHaPeer: true
  enableUserNamespaces: true
  etcdSnapshotScheduleCron: "0 */6 * * *"
  etcdSnapshotRetention: 10
  etcdS3Backup:
    enabled: true
    endpoint: s3.axonwall.lan:8333
    bucket: axonwall-k3s-etcd
  bpfTokenProfiles:
    - name: k3s-net-safe
      preset: networking-safe
  openEbs:
    enabled: true
    zfsLocalPvEnabled: true
    zfsLocalPvPool: tank
    replicatedStorageEnabled: true
    defaultReplicaCount: 2
    replicatedBackingPool: tank/openebs-replicated`}
        />
      </section>

      {/* Cilium eBPF CNI & Embedded Etcd Disaster Recovery */}
      <section id="cilium-etcd" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-emerald-400" /> Cilium eBPF CNI Mode &amp; Embedded Etcd Snapshots
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Choose between lightweight <code className="text-slate-200 font-mono">flannel</code> (WireGuard-native) for
          minimalist edge appliances or full <code className="text-emerald-400 font-mono">cniPlugin: &quot;cilium-ebpf&quot;</code>{' '}
          for high-density clusters, paired with automated embedded-etcd disaster recovery:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
          <div className="p-6 rounded-2xl bg-slate-900 border border-emerald-500/30 space-y-2.5">
            <h3 className="font-bold text-emerald-300 text-base">Kube-Proxy-Less Cilium eBPF + Hubble</h3>
            <p className="text-slate-400 leading-relaxed">
              When <code className="text-slate-200 font-mono">cniPlugin: &quot;cilium-ebpf&quot;</code> is selected,{' '}
              <code className="text-slate-200 font-mono">axonwalld</code> automatically compiles K3s with{' '}
              <code className="text-slate-200 font-mono">flannel-backend: none</code>,{' '}
              <code className="text-slate-200 font-mono">disable-network-policy: true</code>, and{' '}
              <code className="text-slate-200 font-mono">disable-kube-proxy: true</code>, deploying Cilium HelmChartConfig
              with socket-level eBPF Service load-balancing (<code className="font-mono">kubeProxyReplacement: true</code>),
              WireGuard encryption, and Hubble L7 observability.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-sky-500/30 space-y-2.5">
            <h3 className="font-bold text-sky-300 text-base">On-Demand &amp; S3 Embedded Etcd Snapshots</h3>
            <p className="text-slate-400 leading-relaxed">
              Trigger point-in-time control-plane snapshots (<code className="text-slate-200 font-mono">axonwallctl k3s etcd-save [name]</code>),
              enumerate local &amp; S3-replicated snapshots (<code className="text-slate-200 font-mono">axonwallctl k3s etcd-snapshots</code>),
              and execute guarded cluster restores (<code className="text-slate-200 font-mono">axonwallctl k3s etcd-restore &lt;name&gt;</code>)
              from the Web Console (<code className="font-mono">/k3s/cluster</code>), CLI, or{' '}
              <code className="text-purple-300 font-mono">mcp_manage_k3s_cluster</code>.
            </p>
          </div>
        </div>
      </section>

      {/* OpenEBS Storage */}
      <section className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-emerald-400" /> OpenEBS CSI StorageClasses
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall provisions two production-grade OpenEBS StorageClasses out of the box:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div id="zfs-localpv" className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm font-bold text-white">axonwall-zfs-local</span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 text-xs font-mono">Local PV</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Provisions dynamic volumes directly on your host ZFS pool (<code className="text-slate-200">zfs.csi.openebs.io</code>).
              Delivers bare-metal NVMe throughput with native ZFS compression, snapshots, and quota enforcement.
            </p>
          </div>

          <div id="mayastor" className="p-6 rounded-2xl bg-slate-900 border border-emerald-500/30 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm font-bold text-white">axonwall-replicated-ha</span>
              <span className="px-2 py-0.5 rounded bg-sky-500/15 text-sky-400 text-xs font-mono">Default CSI</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Synchronous 2-node block replication over NVMe-oF (<code className="text-slate-200">io.openebs.csi-mayastor</code>).
              Every write is mirrored across both HA Axonwall appliances in real time. If node 1 drops, stateful
              workloads restart on node 2 instantly with zero data loss.
            </p>
          </div>
        </div>

        <CodeBlock
          title="Sample PersistentVolumeClaim (PVC)"
          language="yaml"
          code={`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: database-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: axonwall-replicated-ha
  resources:
    requests:
      storage: 100Gi`}
        />
      </section>

      {/* Kubeconfig Access, Non-Root Sync & HA VIP */}
      <section id="kubeconfig" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> Kubeconfig Permissions, HA VIP Sync &amp; Remote Workstation Merge
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          By default, upstream K3s writes <code className="text-slate-200 font-mono">/etc/rancher/k3s/k3s.yaml</code> with <code className="text-slate-200 font-mono">0600 root:root</code> permissions, blocking non-root administrators and the Web Console API. When <code className="text-emerald-400 font-mono">axonwalld</code> provisions K3s, it enforces group-readable kubeconfig access (<code className="text-emerald-400 font-mono">write-kubeconfig-mode: &quot;0640&quot;</code>, <code className="text-emerald-400 font-mono">write-kubeconfig-group: &quot;axonwall-api&quot;</code>) and ships first-class kubeconfig sync utilities:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-emerald-400 text-sm">1. Local Admin Sync</h3>
            <p className="text-slate-400 leading-relaxed">
              Run <code className="text-slate-200 font-mono">axonwall-kubeconfig</code> (or <code className="text-slate-200 font-mono">axonwallctl kubeconfig</code>) as your SSH admin user to copy and chmod <code className="text-slate-200 font-mono">~/.kube/config</code> (<code className="text-slate-200 font-mono">0600</code>) for immediate <code className="text-slate-200 font-mono">kubectl</code> and <code className="text-slate-200 font-mono">helm</code> v3 usage without <code className="text-slate-200 font-mono">sudo</code>.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-sky-400 text-sm">2. HA Floating VIP Endpoint (--vip)</h3>
            <p className="text-slate-400 leading-relaxed">
              Pass <code className="text-slate-200 font-mono">--vip</code> to automatically rewrite <code className="text-slate-200 font-mono">server: https://127.0.0.1:6443</code> to your active Keepalived VRRP Virtual IP (which K3s automatically includes in its API server <code className="text-slate-200 font-mono">tls-san</code> list), keeping <code className="text-slate-200 font-mono">kubectl</code> online across Master/Backup failover.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-purple-400 text-sm">3. Remote Laptop SSH Merge</h3>
            <p className="text-slate-400 leading-relaxed">
              From a developer workstation, run <code className="text-slate-200 font-mono">./scripts/update-kubeconfig.sh</code> over SSH to fetch the cluster certificate and non-destructively merge the <code className="text-slate-200 font-mono">axonwall</code> context into your local multi-cluster <code className="text-slate-200 font-mono">~/.kube/config</code>.
            </p>
          </div>
        </div>

        <CodeBlock
          title="Local, HA VIP & Remote Workstation Kubeconfig Sync"
          language="bash"
          code={`# On the Axonwall appliance: sync ~/.kube/config for your non-root admin session
axonwall-kubeconfig
kubectl get nodes -o wide

# On a 2-Host HA cluster: bind kubeconfig server URL to the floating VRRP VIP
axonwall-kubeconfig --vip
# Equivalent axonwallctl subcommand (prints or writes VIP-rewritten kubeconfig):
axonwallctl kubeconfig --vip

# From your remote Linux/macOS workstation: fetch & merge over SSH
./scripts/update-kubeconfig.sh user@10.80.0.202 --vip
kubectl --context axonwall get pods -A`}
        />
      </section>

      {/* Linux 6.9+ User Namespaces & Unprivileged Pod BPF_TOKEN Delegation */}
      <section id="userns-bpf-tokens" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-sky-400" /> Linux 6.9+ User Namespaces (`hostUsers: false`) &amp; `BPF_TOKEN` Pods
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Setting <code className="text-emerald-400 font-mono">enableUserNamespaces: true</code> in{' '}
          <code className="text-slate-200 font-mono">/etc/axonwall/k3s.yaml</code> compiles{' '}
          <code className="text-slate-200 font-mono">UserNamespacesSupport=true</code> across{' '}
          <code className="text-slate-200 font-mono">kube-apiserver</code> and{' '}
          <code className="text-slate-200 font-mono">kubelet</code> in{' '}
          <code className="text-slate-200 font-mono">/etc/rancher/k3s/config.yaml</code>. Combined with{' '}
          <code className="text-emerald-400 font-mono">bpfTokenProfiles</code>, K3s workloads can run inside isolated
          User Namespaces (<code className="text-emerald-400 font-mono">hostUsers: false</code>) and mount a delegated{' '}
          <code className="text-sky-400 font-mono">bpffs</code> directory at <code className="text-slate-200 font-mono">/sys/fs/bpf</code>{' '}
          with <code className="text-emerald-300 font-mono">LIBBPF_BPF_TOKEN_PATH=/sys/fs/bpf</code>—loading XDP/TC/Socket
          networking eBPF programs while Axonwall BPF-LSM blocks <code className="text-rose-400 font-mono">kprobe/tracepoint/lsm</code>{' '}
          Ring-0 memory reads:
        </p>

        <CodeBlock
          title="Rootless K3s UserNS DaemonSet Using Linux 6.9+ BPF_TOKEN (axonwallctl ebpf render-k3s)"
          language="yaml"
          code={`apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-packet-sensor
  namespace: default
spec:
  selector:
    matchLabels:
      app: ebpf-packet-sensor
  template:
    metadata:
      labels:
        app: ebpf-packet-sensor
    spec:
      hostUsers: false
      containers:
        - name: ebpf-packet-sensor
          image: ghcr.io/cilium/ebpf-sensor:latest
          env:
            - name: LIBBPF_BPF_TOKEN_PATH
              value: /sys/fs/bpf
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
              add: ["BPF", "NET_ADMIN"]
          volumeMounts:
            - name: delegated-bpffs
              mountPath: /sys/fs/bpf
      volumes:
        - name: delegated-bpffs
          hostPath:
            path: /run/axonwall/bpffs-tokens/k3s-net-safe
            type: Directory`}
        />
      </section>
    </div>
  );
}
