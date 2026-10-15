import React from 'react';
import Link from 'next/link';
import { Cpu, Database, Network, ArrowRightLeft, Boxes, CheckCircle2, ShieldCheck } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Kubernetes (K3s) & OpenEBS Distributed Storage | Axonwall Documentation',
  description:
    'Complete guide to running K3s Kubernetes and OpenEBS distributed storage on Axonwall: automated HA peer join, WireGuard flannel mesh, ZFS-LocalPV, and Mayastor NVMe-oF replication.',
};

export default function K3sKubernetesDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Container Orchestration & Cloud-Native Storage
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Kubernetes (K3s) & OpenEBS Distributed Storage
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall replaces the deprecated Kubernetes stack in TrueNAS with modern, lightweight K3s. Run containerized services directly on your appliance with encrypted WireGuard flannel networking, automated 2-node HA cluster join, and OpenEBS replicated persistent volumes.
        </p>
      </div>

      {/* Overview */}
      <section className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> Embedded K3s Architecture
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          K3s is packaged as a single binary with zero external dependencies, embedded SQLite/etcd consensus, and native Containerd. Axonwall manages K3s through the privileged Go daemon (<code className="text-emerald-400 font-mono">axonwalld</code>), which generates declarative control plane manifests and reconciles cluster state.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-base">WireGuard Native Flannel</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Pod-to-pod cross-node traffic is automatically encrypted using Linux kernel WireGuard (<code className="text-slate-200">flannel-backend: "wireguard-native"</code>), requiring zero overlay CPU overhead.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-base">Automatic 2-Node HA Join</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              When a secondary HA node is brought online, it connects to the primary node over mTLS, reads the cluster join token via <code className="text-slate-200">/api/v1/sync/k3s-token</code>, and joins the cluster as a redundant control-plane server without manual token copying.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-base">VIP Ingress Integration</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              K3s workloads bind directly to Axonwall VRRP Virtual IPs, ensuring that if a physical node experiences hardware failure, traffic routes to the surviving node in under one second.
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
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm font-bold text-white">axonwall-zfs-local</span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 text-xs font-mono">Local PV</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Provisions dynamic volumes directly on your host ZFS pool (<code className="text-slate-200">zfs.csi.openebs.io</code>). Delivers bare-metal NVMe throughput with native ZFS compression, snapshots, and quota enforcement.
            </p>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-emerald-500/30 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm font-bold text-white">axonwall-replicated-ha</span>
              <span className="px-2 py-0.5 rounded bg-sky-500/15 text-sky-400 text-xs font-mono">Default CSI</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Synchronous 2-node block replication over NVMe-oF (<code className="text-slate-200">io.openebs.csi-mayastor</code>). Every write is mirrored across both HA Axonwall appliances in real time. If node 1 drops, stateful workloads restart on node 2 instantly with zero data loss.
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
    </div>
  );
}
