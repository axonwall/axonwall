import React from 'react';
import Link from 'next/link';
import { Database, HardDrive, Layers, FolderKanban, Camera, Cpu, ArrowRightLeft, ShieldCheck, Zap, Server } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Modular Appliance Architecture: Firewall, ZFS NAS & K3s | Axonwall Documentation',
  description:
    'Comprehensive documentation for Axonwall modular core roles: standalone or converged Next-Gen Firewall, TrueNAS-grade OpenZFS NAS, and lightweight Kubernetes (K3s) with OpenEBS distributed storage.',
};

export default function ModularArchitectureDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Core Appliance System Architecture
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Modular Core Roles: Firewall, TrueNAS ZFS & K3s
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall is a hyper-converged, role-modular operating system. Turn the entire firewall off to run as a dedicated, pure enterprise ZFS NAS, run as a dedicated wire-speed Next-Gen Firewall, or operate all three roles—Firewall, ZFS NAS, and Kubernetes (K3s)—simultaneously on high-availability bare-metal clusters.
        </p>
      </div>

      {/* Role Comparison Table */}
      <section className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> Feature & Architecture Comparison: Axonwall vs. TrueNAS vs. pfSense
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Traditional homelab and enterprise infrastructure forced organizations to deploy separate physical appliances or complex nested hypervisors for firewalls, storage, and container runtimes. Axonwall unifies them with native Linux kernel performance, atomic commit-confirm rollback, and zero-drop HA replication.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-slate-800 rounded-xl overflow-hidden">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Capability / Subsystem</th>
                <th className="p-3">Axonwall Converged OS</th>
                <th className="p-3">TrueNAS SCALE / CORE</th>
                <th className="p-3">pfSense / OPNsense</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Core Firewall Engine</td>
                <td className="p-3 text-emerald-400 font-medium">Modular plugin (<code className="text-emerald-300">core-firewall</code>), Linux multi-core nftables + Flowtable HW offload</td>
                <td className="p-3 text-slate-400">Basic iptables/docker bridges; no NGFW or stateful routing</td>
                <td className="p-3 text-slate-300">Monolithic FreeBSD pf (single-lock bottleneck on 10G+)</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Host-Mode Operation</td>
                <td className="p-3 text-emerald-400 font-medium">Yes: Disable firewall to run pure ZFS NAS / K3s host</td>
                <td className="p-3 text-slate-300">Default storage host mode only</td>
                <td className="p-3 text-rose-400">No (firewall is mandatory and cannot be disabled)</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Storage Subsystem</td>
                <td className="p-3 text-emerald-400 font-medium">Native OpenZFS (Stripe, Mirror, RAID-Z1/Z2/Z3, dRAID) + VSS Shadow Copies</td>
                <td className="p-3 text-emerald-400 font-medium">Native OpenZFS (ZFS pool manager)</td>
                <td className="p-3 text-rose-400">Root ZFS boot only; no NAS file sharing or RAID management</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Kubernetes Engine</td>
                <td className="p-3 text-emerald-400 font-medium">K3s + OpenEBS distributed CSI (ZFS-LocalPV & Mayastor NVMe-oF)</td>
                <td className="p-3 text-amber-400">Deprecated k3s in SCALE (migrated to standard Docker Engine)</td>
                <td className="p-3 text-rose-400">None</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">2-Node True HA</td>
                <td className="p-3 text-emerald-400 font-medium">Full state sync: VRRP, conntrackd, SQLite DBs, ZFS snapshots & K3s token auto-join</td>
                <td className="p-3 text-slate-400">TrueNAS Enterprise dual-controller SAS hardware only; no 2-node commodity HA</td>
                <td className="p-3 text-slate-400">CARP + XMLRPC config sync; no file or container replication</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Firmware Upgrades</td>
                <td className="p-3 text-emerald-400 font-medium">A/B Dual-Root partitions with hardware boot watchdog</td>
                <td className="p-3 text-slate-300">GRUB boot environment snapshots</td>
                <td className="p-3 text-amber-400">In-place package upgrade (high brick risk on power loss)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Core Role Plugins */}
      <section id="core-roles" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> Modular Role Architecture
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall encapsulates all system responsibilities into first-class systemd sandboxed plugins governed by Zod schemas and Go daemon reconcilers.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2.5 font-bold text-white text-base">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <span>core-firewall</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Provides multi-core line-rate packet filtering, stateful NAT, Suricata 7+ IPS, CrowdSec collaborative security, dynamic GeoIP sets, DNS sinkholing (RPZ), and multi-WAN routing.
            </p>
            <div className="pt-2 text-[11px] font-mono text-slate-500">
              When toggled off: Axonwall compiles an atomic Host-Mode ruleset that permits management, SMB/NFS/iSCSI shares, and K3s node communication while dropping unauthenticated ingress.
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2.5 font-bold text-white text-base">
              <Database className="w-5 h-5 text-emerald-400" />
              <span>core-nas</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Provides TrueNAS-equivalent OpenZFS storage management: zpool creation across dedicated NVMe/HDD disks or installer-partitioned slices, dataset quotas, POSIX ACLs, Samba (SMB3) with VSS Shadow Copies, NFSv4 exports, and iSCSI block targets.
            </p>
            <div className="pt-2 text-[11px] font-mono text-slate-500">
              HA Failover: Backups receive incremental ZFS streams in readonly mode; on Keepalived VRRP transition to MASTER, datasets are promoted read-write and services bind the virtual IP.
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2.5 font-bold text-white text-base">
              <Cpu className="w-5 h-5 text-emerald-400" />
              <span>core-k3s</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Replaces legacy TrueNAS Kubernetes with modern, lightweight K3s. Includes WireGuard flannel overlay mesh, etcd HA consensus, and OpenEBS dynamic storage provisioners.
            </p>
            <div className="pt-2 text-[11px] font-mono text-slate-500">
              Auto-Join HA: Standby nodes query the primary control plane over mTLS (<code className="text-slate-300">/api/v1/sync/k3s-token</code>), fetch join credentials, and join the cluster automatically without operator intervention.
            </div>
          </div>
        </div>
      </section>

      {/* Code Example */}
      <section className="space-y-4 pt-6 border-t border-slate-800/80">
        <h3 className="text-base font-semibold text-white">DesiredState Schema: Capabilities & Convergence</h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          The appliance state is completely declarative. Here is an example of a converged Axonwall node configuration running all three roles with 2-node HA replication:
        </p>

        <CodeBlock
          title="/var/lib/axonwall/state.json"
          language="json"
          code={`{
  "version": 1,
  "capabilities": {
    "firewallEnabled": true,
    "nasEnabled": true,
    "k3sEnabled": true
  },
  "nas": {
    "enabled": true,
    "workgroup": "ENTERPRISE",
    "serverString": "Axonwall HA ZFS Storage",
    "pools": [
      {
        "name": "tank",
        "topology": "mirror",
        "dataDisks": ["/dev/disk/by-partlabel/axon_zfs_1", "/dev/sdb"],
        "ashift": 12,
        "compression": "lz4",
        "autotrim": true
      }
    ],
    "datasets": [
      {
        "pool": "tank",
        "name": "shares/media",
        "type": "filesystem",
        "recordSize": "1M",
        "replicateToHaPeer": true
      }
    ]
  },
  "k3s": {
    "enabled": true,
    "flannelBackend": "wireguard-native",
    "autoJoinHaPeer": true,
    "openEbs": {
      "enabled": true,
      "zfsLocalPvEnabled": true,
      "zfsLocalPvPool": "tank",
      "replicatedStorageEnabled": true,
      "defaultReplicaCount": 2
    }
  }
}`}
        />
      </section>
    </div>
  );
}
