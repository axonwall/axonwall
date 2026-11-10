import React from 'react';
import Link from 'next/link';
import { Database, HardDrive, Layers, FolderKanban, Camera, Cpu, CheckCircle2, ShieldCheck } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'ZFS NAS Storage Management: Pools, Datasets, Shares & Snapshots | Axonwall Documentation',
  description:
    'Complete guide to configuring OpenZFS storage pools, datasets, quotas, Samba SMB3 with VSS shadow copies, NFSv4 exports, iSCSI targets, and automated snapshot policies with HA Send/Recv replication on Axonwall.',
};

export default function ZfsNasStorageDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Enterprise Storage Engine
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          ZFS NAS Storage Management
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall integrates native OpenZFS on Linux with enterprise-grade NAS file and block storage configured via{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/storage.yaml</code>. Manage physical disks,
          provision Stripe/Mirror/RAID-Z/dRAID pools, create datasets with POSIX ACLs, and serve high-speed SMB3,
          NFSv4, iSCSI targets, and S3 object storage.
        </p>
      </div>

      {/* Pools & Topologies */}
      <section id="pools" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-emerald-400" /> ZFS Storage Pools (zpools) &amp; RAID Topologies
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          OpenZFS pools combine raw block devices into unified self-healing storage pools protected by 256-bit Fletcher4
          or SHA-256 checksums. Axonwall supports all standard ZFS virtual device (VDEV) layouts:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Mirror (RAID-1 / RAID-10)</h3>
            <p className="text-slate-400">
              Optimal for databases, VMs, and iSCSI block storage. Provides maximum IOPS, fast rebuild times, and
              survives loss of one disk per mirror vdev.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">RAID-Z1 / RAID-Z2 / RAID-Z3</h3>
            <p className="text-slate-400">
              Single, double, or triple distributed parity (similar to RAID-5/6/7). Best capacity utilization for bulk
              media, backups, and file archives.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">dRAID (Distributed Spare RAID)</h3>
            <p className="text-slate-400">
              Distributes spare capacity across all member drives simultaneously, reducing multi-terabyte disk resilver
              times by up to 80%.
            </p>
          </div>
        </div>

        <CodeBlock
          title="Automated zpool create invocation by axonwalld"
          language="bash"
          code={`# Axonwall automatically invokes zpool with enterprise flags:
zpool create -f \\
  -o ashift=12 \\
  -o autotrim=on \\
  -O compression=lz4 \\
  -O acltype=posixacl \\
  -O xattr=sa \\
  -O dnodesize=auto \\
  -O normalization=formD \\
  -O mountpoint=/mnt/tank \\
  tank mirror /dev/disk/by-id/nvme-disk1 /dev/disk/by-id/nvme-disk2`}
        />
      </section>

      {/* Datasets & Zvols */}
      <section id="datasets" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> Datasets &amp; Block Volumes (Zvols)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Create granular datasets tailored to specific workload profiles:
        </p>

        <ul className="text-xs text-slate-300 list-disc list-inside space-y-1.5 ml-2">
          <li>
            <strong>PostgreSQL / MySQL Datasets:</strong> Set <code className="text-emerald-400 font-mono">recordSize: 16K</code>{' '}
            with log devices (SLOG) on high-end NVMe.
          </li>
          <li>
            <strong>Virtual Machines &amp; K3s Volumes:</strong> Set{' '}
            <code className="text-emerald-400 font-mono">recordSize: 64K</code> or create thin-provisioned{' '}
            <code className="text-emerald-400 font-mono">type: zvol</code> volumes for block access.
          </li>
          <li>
            <strong>Large Media &amp; Backup Archives:</strong> Set{' '}
            <code className="text-emerald-400 font-mono">recordSize: 1M</code> with{' '}
            <code className="text-emerald-400 font-mono">compression: zstd</code>.
          </li>
        </ul>
      </section>

      {/* File & Block Sharing */}
      <section id="smb" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <FolderKanban className="w-6 h-6 text-emerald-400" /> Samba SMB3, NFSv4 &amp; iSCSI Sharing
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-base">Samba SMB3 with VSS Shadow Copies</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Axonwall configures Samba with native <code className="text-slate-200">vfs_shadow_copy2</code> hooked
              directly into periodic ZFS snapshots. Windows clients can right-click any folder or file and browse
              historical versions directly in File Explorer.
            </p>
            <p className="text-xs text-slate-400 leading-relaxed">
              Includes Apple Time Machine support via <code className="text-slate-200">vfs_fruit</code> for
              zero-configuration macOS network backups.
            </p>
          </div>

          <div id="nfs-iscsi" className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-base">NFSv4 Exports &amp; iSCSI Targets</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Serve NFSv4 exports with CIDR restrictions and root squashing. For virtualized hypervisors (Proxmox,
              VMware ESXi), Axonwall configures Linux LIO (<code className="text-slate-200">targetcli</code>) iSCSI
              targets backed by ZFS zvols with CHAP authentication and ALUA multi-pathing.
            </p>
          </div>
        </div>
      </section>

      {/* Snapshot Retention & HA Send/Recv */}
      <section id="snapshots" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Camera className="w-6 h-6 text-emerald-400" /> Snapshot Retention &amp; HA Incremental Send/Recv
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Configure automated hourly, daily, or weekly ZFS snapshot policies in{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/storage.yaml</code>. When{' '}
          <code className="text-emerald-400 font-mono">replicateToHaPeer: true</code> is enabled,{' '}
          <code className="text-white font-mono">axonwalld</code> streams incremental raw snapshots (
          <code className="text-slate-200">zfs send -w -I</code>) over the mTLS HA channel (
          <code className="text-slate-200">/api/v1/sync/zfs</code>) and keeps the Backup node&apos;s pool{' '}
          <code className="text-slate-200">readonly=on</code> until VRRP failover promotion:
        </p>

        <CodeBlock
          title="/etc/axonwall/storage.yaml"
          language="yaml"
          code={`nas:
  enabled: true
  workgroup: WORKGROUP
  pools:
    - name: tank
      topology: mirror
      dataDisks:
        - /dev/nvme0n1
        - /dev/nvme1n1
      compression: zstd
      ashift: 12
      autotrim: true
  datasets:
    - name: shares
      pool: tank
      type: filesystem
      compression: zstd
      quotaGb: 2048
      recordSize: 128K
      replicateToHaPeer: true
  snapshotPolicies:
    - dataset: tank/shares
      interval: hourly
      keepCount: 24
      replicateToHaPeer: true
      enabled: true`}
        />
      </section>
    </div>
  );
}
