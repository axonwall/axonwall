import React from 'react';
import { Database, Layers, FolderKanban, Camera, ShieldCheck, Lock, Cloud } from 'lucide-react';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'ZFS NAS Storage & Axonwall Vault Edition | Axonwall Documentation',
  description:
    'Complete guide to configuring OpenZFS storage pools, Special NVMe VDEVs, Pool Checkpoints & TRIM, Native AES-256-GCM dataset encryption, Samba SMB3 with VSS/Time Machine mDNS/WSDD2, NFSv4 exports, iSCSI targets, rclone Cloud Sync, S.M.A.R.T. health, and Axonwall Vault SeaweedFS S3 Object-Lock COMPLIANCE storage.',
};

export default function ZfsNasStorageDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Enterprise Storage Engine &amp; Axonwall Vault • v0.11.68
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          ZFS NAS Storage &amp; Axonwall Vault Edition
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Axonwall integrates native OpenZFS on Linux with enterprise-grade NAS file, block, and immutable S3 object storage configured under <code className="text-emerald-400 font-mono">nas:</code> in{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/storage.yaml</code>. Provision Stripe/Mirror/RAID-Z/dRAID pools with NVMe SLOG/L2ARC tiers, serve SMB3, NFSv4, and iSCSI targets, or run <strong>Axonwall Vault Edition</strong> with SeaweedFS S3 Object-Lock <code className="text-emerald-400 font-mono">COMPLIANCE</code> WORM immutability.
        </p>
      </div>

      {/* Pools & Topologies */}
      <section id="pools" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-emerald-400" /> ZFS Storage Pools, Special NVMe VDEVs, Checkpoints &amp; TRIM
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          OpenZFS pools combine raw block devices into unified self-healing storage pools protected by 256-bit Fletcher4
          or SHA-256 checksums. Beyond SLOG, L2ARC, and Hot Spares, Axonwall supports <strong>Special Allocation VDEVs</strong>{' '}
          (<code className="text-emerald-400 font-mono">specialDisks</code> on mirrored NVMe to store all ZFS metadata,
          dedup tables, and small blocks below <code className="text-slate-200 font-mono">specialSmallBlocks</code>),
          point-in-time <strong>Pool Checkpoints</strong> (<code className="text-slate-200 font-mono">zpool checkpoint</code>{' '}
          / <code className="text-slate-200 font-mono">-d</code>), and on-demand <strong>NVMe TRIM</strong> (<code className="text-slate-200 font-mono">zpool trim</code>):
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
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
            <h3 className="font-bold text-white text-sm">dRAID (Distributed Spare)</h3>
            <p className="text-slate-400">
              Distributes spare capacity across all member drives simultaneously, reducing multi-terabyte disk resilver
              times by up to 80%.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-emerald-500/30 space-y-2">
            <h3 className="font-bold text-emerald-300 text-sm">Special Allocation VDEV</h3>
            <p className="text-slate-400">
              Dedicated mirrored NVMe VDEV storing ZFS metadata, DDT, and small files (<code className="text-slate-200">special_small_blocks</code>) so HDD RAID-Z pools browse at flash speed.
            </p>
          </div>
        </div>

        <CodeBlock
          title="Automated zpool create invocation with Special NVMe VDEV by axonwalld"
          language="bash"
          code={`# Axonwall automatically invokes zpool with enterprise flags & optional Special VDEV:
zpool create -f \\
  -o ashift=12 \\
  -o autotrim=on \\
  -O compression=zstd \\
  -O acltype=posixacl \\
  -O xattr=sa \\
  -O dnodesize=auto \\
  -O normalization=formD \\
  -O mountpoint=/mnt/tank \\
  tank raidz2 /dev/disk/by-id/scsi-disk{1..4} \\
  special mirror /dev/disk/by-id/nvme-meta0 /dev/disk/by-id/nvme-meta1`}
        />
      </section>

      {/* Datasets & Native Encryption */}
      <section id="datasets" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-emerald-400" /> Native AES-256-GCM Dataset Encryption &amp; Block Volumes (Zvols)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Create granular filesystems and ZVOL block volumes tailored to each workload, with per-dataset{' '}
          <strong>Native OpenZFS Encryption</strong> (<code className="text-emerald-400 font-mono">aes-256-gcm</code> or{' '}
          <code className="text-emerald-400 font-mono">aes-256-ccm</code> via PBKDF2 passphrase or raw 32-byte key) and
          zero-downtime key load/unload via Web Console, <code className="text-slate-200 font-mono">axonwallctl nas unlock|lock</code>,
          or MCP:
        </p>

        <ul className="text-xs text-slate-300 list-disc list-inside space-y-1.5 ml-2">
          <li>
            <strong>Encrypted Vault &amp; Compliance Datasets:</strong> Enable{' '}
            <code className="text-emerald-400 font-mono">encryption: aes-256-gcm</code> with raw{' '}
            <code className="text-slate-200 font-mono">zfs send -w</code> replication so standby HA peers store ciphertext without needing plaintext keys.
          </li>
          <li>
            <strong>PostgreSQL / MySQL Datasets:</strong> Set <code className="text-emerald-400 font-mono">recordSize: 16K</code>{' '}
            with NVMe SLOG and <code className="text-emerald-400 font-mono">specialSmallBlocks: 32K</code>.
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
          <FolderKanban className="w-6 h-6 text-emerald-400" /> Samba SMB3, Time Machine mDNS, WSDD2, NFSv4 &amp; iSCSI
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="font-bold text-white text-base">SMB3 VSS, Apple Time Machine mDNS &amp; WSDD2</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Axonwall configures Samba with native <code className="text-slate-200">vfs_shadow_copy2</code> hooked
              directly into periodic ZFS snapshots so Windows clients browse historical versions in File Explorer, plus{' '}
              <code className="text-slate-200">wsdd2</code> for instant Windows 11 Network Neighborhood discovery.
            </p>
            <p className="text-xs text-slate-400 leading-relaxed">
              Enabling <code className="text-emerald-400 font-mono">timeMachine: true</code> activates{' '}
              <code className="text-slate-200">vfs_fruit</code> (<code className="text-slate-200">fruit:time machine = yes</code>,
              optional <code className="text-slate-200">timeMachineMaxSizeGb</code>) and automatically publishes{' '}
              <code className="text-slate-200">_smb._tcp</code> + <code className="text-slate-200">_adisk._tcp</code>{' '}
              Avahi mDNS records for zero-click macOS Finder discovery.
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

      {/* Snapshot Retention, Rollback, SMART & rclone Cloud Sync */}
      <section id="snapshots" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Camera className="w-6 h-6 text-emerald-400" /> Snapshots, Rollback, S.M.A.R.T. &amp; Encrypted Cloud Sync
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Configure automated hourly/daily/weekly ZFS snapshots, instant rollback (<code className="text-slate-200 font-mono">zfs rollback -r</code>,
          with Root-on-ZFS <code className="text-rose-400 font-mono">zroot/rpool</code> protection), scheduled{' '}
          <code className="text-slate-200 font-mono">smartd</code> short/long self-tests &amp; pool scrubs, HA{' '}
          <code className="text-slate-200 font-mono">zfs send -w -I</code> mTLS streaming, and encrypted{' '}
          <code className="text-sky-400 font-mono">rclone</code> offsite Cloud Sync tasks (Backblaze B2, AWS S3, Wasabi,
          Cloudflare R2, SFTP) in <code className="text-emerald-400 font-mono">/etc/axonwall/storage.yaml</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-emerald-400 flex items-center gap-1.5">
              <Layers className="w-4 h-4" /> S.M.A.R.T. Self-Tests &amp; Scrub Schedules
            </div>
            <p className="text-slate-400 leading-relaxed">
              Declarative <code className="text-slate-200 font-mono">scrubSchedules</code> and{' '}
              <code className="text-slate-200 font-mono">smartSchedule</code> generate systemd timers and{' '}
              <code className="text-slate-200 font-mono">/etc/smartd.conf</code> thermal/wear alerts across SATA, SAS, and NVMe drives.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-sky-400 flex items-center gap-1.5">
              <Cloud className="w-4 h-4" /> Offsite Cloud Sync (rclone + crypt)
            </div>
            <p className="text-slate-400 leading-relaxed">
              <code className="text-slate-200 font-mono">cloudSyncTasks</code> synchronize ZFS datasets to S3, B2, R2, Wasabi, or SFTP targets with bandwidth caps and client-side encryption.
            </p>
          </div>
        </div>

        <CodeBlock
          title="/etc/axonwall/storage.yaml — Complete NasConfigSchema (nas:)"
          language="yaml"
          code={`nas:
  enabled: true
  workgroup: WORKGROUP
  serverString: Axonwall Enterprise ZFS NAS
  wsddEnabled: true
  avahiTimeMachineEnabled: true
  pools:
    - name: tank
      topology: raidz2
      dataDisks:
        - /dev/disk/by-id/scsi-disk1
        - /dev/disk/by-id/scsi-disk2
        - /dev/disk/by-id/scsi-disk3
        - /dev/disk/by-id/scsi-disk4
      specialDisks:
        - /dev/disk/by-id/nvme-meta0
        - /dev/disk/by-id/nvme-meta1
      logDisks:
        - /dev/disk/by-id/nvme-slog0
      cacheDisks:
        - /dev/disk/by-id/nvme-l2arc0
      spareDisks:
        - /dev/disk/by-id/scsi-spare0
      compression: zstd
      ashift: 12
      autotrim: true
  datasets:
    - name: shares
      pool: tank
      type: filesystem
      compression: zstd
      quotaGb: 4096
      recordSize: 128K
      specialSmallBlocks: 32K
      encryption: aes-256-gcm
      keyFormat: passphrase
      replicateToHaPeer: true
    - name: vm-block01
      pool: tank
      type: zvol
      sizeGb: 256
      recordSize: 64K
      replicateToHaPeer: true
  snapshotPolicies:
    - dataset: tank/shares
      interval: hourly
      keepCount: 24
      replicateToHaPeer: true
      enabled: true
  scrubSchedules:
    - pool: tank
      scheduleCron: "0 2 * * 0"
      enabled: true
  cloudSyncTasks:
    - name: nightly-b2-vault
      dataset: tank/shares
      provider: b2
      bucketOrPath: axonwall-offsite-dr
      scheduleCron: "30 3 * * *"
      clientSideCrypt: true
      bandwidthLimitMbps: 250
      enabled: true
  smbShares:
    - name: Engineering
      dataset: tank/shares
      readOnly: false
      vssShadowCopy: true
      timeMachine: true
      timeMachineMaxSizeGb: 1024
  nfsExports:
    - dataset: tank/shares
      allowedCidrs:
        - 10.0.10.0/24
      readOnly: false
      noRootSquash: false
  iscsiTargets:
    - iqn: iqn.2026-11.com.axonwall:tank-vm-block01
      zvol: tank/vm-block01
      portalPort: 3260
  s3:
    enabled: true
    port: 8333
    objectLockCompliance: true`}
        />
      </section>

      {/* Axonwall Vault Edition */}
      <section id="axonwall-vault" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-emerald-400" /> Axonwall Vault Edition (Immutable S3 Object-Lock Backup Appliance)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Selectable directly inside the unified <code className="text-emerald-400 font-mono">axonwall-debian13-amd64.iso</code> installer (<code className="text-slate-200 font-mono">edition: vault</code>) or provisioned on any ZFS-enabled Axonwall host, <strong>Axonwall Vault Edition</strong> transforms the appliance into a ransomware-proof, air-gap-ready S3 backup target powered by <strong>SeaweedFS S3 Gateway</strong> over TLS on port <code className="text-emerald-400 font-mono">8333</code>.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-emerald-400 text-sm">S3 Object-Lock WORM COMPLIANCE Mode</h3>
            <p className="text-slate-400 leading-relaxed">
              Compatible out-of-the-box with Veeam Backup &amp; Replication, Restic, Kopia, Velero (K3s), and CloudNativePG WAL archiving. Enforces RFC-compliant S3 Object-Lock in strict <code className="text-slate-200 font-mono">COMPLIANCE</code> retention mode backed by immutable OpenZFS snapshots and the internal PKI CA.
            </p>
          </div>
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-sky-400 text-sm">Host-Mode Perimeter Hardening</h3>
            <p className="text-slate-400 leading-relaxed">
              Vault Edition automatically disables WAN packet forwarding and locks ingress strictly to TLS S3 (<code className="text-slate-200 font-mono">tcp/8333</code>), Web Console (<code className="text-slate-200 font-mono">tcp/2966</code>), and administrative SSH, isolating backup repositories from lateral compromise.
            </p>
          </div>
        </div>

        <CodeBlock
          title="Axonwall Vault Provisioning & Verification CLI"
          language="bash"
          code={`# Provision SeaweedFS S3 Vault on ZFS pool 'tank' with Object-Lock COMPLIANCE mode (port 8333)
sudo axonwall-vault-provision --pool tank --port 8333 --object-lock COMPLIANCE

# Inspect SeaweedFS S3 health, TLS certificate trust, ZFS dataset immutability, and bucket retention
sudo axonwall-vault-status`}
        />
      </section>

      {/* Deep OpenZFS ARC / L2ARC / ZIL Kstats & MCP Storage Operations */}
      <section id="arc-zil-telemetry" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white">
          OpenZFS ARC/L2ARC/ZIL Kernel Kstat Telemetry &amp; MCP Storage Governance
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          <code className="text-emerald-400 font-mono">axonwalld</code> continuously parses in-kernel OpenZFS SPL kstats
          from <code className="text-slate-200 font-mono">/proc/spl/kstat/zfs/arcstats</code>,{' '}
          <code className="text-slate-200 font-mono">/proc/spl/kstat/zfs/zil</code>, and per-pool{' '}
          <code className="text-slate-200 font-mono">/proc/spl/kstat/zfs/&lt;pool&gt;/io</code>—correlating them with
          eBPF <code className="text-sky-400 font-mono">fexit/vfs_fsync</code> latency histograms:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">1. ARC &amp; L2ARC Hit Ratios</span>
            <p className="text-slate-400 leading-relaxed">
              Tracks <code className="text-slate-200 font-mono">size</code> vs.{' '}
              <code className="text-slate-200 font-mono">c_max</code>, demand-data hits/misses, NVMe{' '}
              <code className="text-slate-200 font-mono">l2_hits</code> /{' '}
              <code className="text-slate-200 font-mono">l2_size</code>, and{' '}
              <code className="text-slate-200 font-mono">memory_throttle_count</code> under K3s/KVM memory pressure.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">2. ZIL &amp; SLOG Synchronous Commits</span>
            <p className="text-slate-400 leading-relaxed">
              Measures <code className="text-slate-200 font-mono">zil_commit_count</code>,{' '}
              <code className="text-slate-200 font-mono">zil_commit_writer_count</code>, and intent-log transaction
              allocation modes (<code className="text-slate-200 font-mono">itx_indirect_bytes</code> vs.{' '}
              <code className="text-slate-200 font-mono">itx_copied_bytes</code>) for database WAL &amp; NFS sync writes.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">3. MCP Storage Telemetry &amp; Snapshots</span>
            <p className="text-slate-400 leading-relaxed">
              Exposed via <code className="text-sky-300 font-mono">axonwall://nas/storage-telemetry</code>,{' '}
              <code className="text-sky-300 font-mono">mcp_inspect_nas_storage</code> (<code className="font-mono">mcp:nas:read</code>),
              and non-destructive <code className="text-emerald-300 font-mono">mcp_nas_snapshot_or_scrub</code> (<code className="font-mono">mcp:nas:manage</code>).
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
