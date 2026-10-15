import React from 'react';
import Link from 'next/link';
import { HardDrive, Layers, RefreshCw, CheckCircle2, ShieldAlert, Cpu, Terminal } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Multi-Disk RAID & ZFS Partitioning Installer | Axonwall Documentation',
  description:
    'Documentation for the Axonwall ISO and Alpine installers: mdadm RAID-1 system disk mirroring across Slot A, Slot B, Swap, and Data, plus dedicated ZFS storage partition allocation and RAID-Z topologies.',
};

export default function InstallerRaidZfsDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Bare-Metal Installer & Disk Partitioning
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Installer Multi-Disk RAID & ZFS Partitioning
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Deploy unbrickable enterprise bare-metal appliances. The Axonwall installer natively supports multi-disk Linux software RAID-1 (<code className="text-emerald-400 font-mono">mdadm</code>) mirroring for the entire A/B dual-root system disk, and allows reserving dedicated partition slices for OpenZFS pools directly during OS installation.
        </p>
      </div>

      {/* Overview */}
      <section className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <HardDrive className="w-6 h-6 text-emerald-400" /> System Disk Mirroring vs. Dedicated ZFS Storage
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          When installing Axonwall on servers with two or more disks, administrators can mirror the core operating system across disks using hardware or kernel RAID-1, while partitioning the remaining disk capacity for OpenZFS:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 font-bold text-white text-base">
              <Layers className="w-5 h-5 text-emerald-400" />
              <span>Multi-Disk System RAID-1</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Mirrors the entire Axonwall OS layout across 2+ member disks. Each disk contains cloned UEFI ESP partitions, Slot A (<code className="text-slate-200">axon_root_a</code> on <code className="text-slate-200">/dev/md0</code>), Slot B (<code className="text-slate-200">axon_root_b</code> on <code className="text-slate-200">/dev/md1</code>), Swap (<code className="text-slate-200">/dev/md2</code>), and Persistent Data (<code className="text-slate-200">/dev/md3</code>).
            </p>
            <ul className="text-xs text-slate-300 list-disc list-inside space-y-1">
              <li>GRUB bootloader installed on every mirror member</li>
              <li>Survives complete drive loss without loss of firmware watchdog</li>
              <li>Automatic array sync with write-intent bitmaps</li>
            </ul>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 font-bold text-white text-base">
              <HardDrive className="w-5 h-5 text-emerald-400" />
              <span>Dedicated ZFS Storage Allocation</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Instead of consuming the whole disk for the root filesystem, the installer lets you carve out a dedicated ZFS storage slice labeled <code className="text-emerald-400 font-mono">axon_zfs_1</code> (or across all member disks in RAID setups).
            </p>
            <ul className="text-xs text-slate-300 list-disc list-inside space-y-1">
              <li>Specify fixed gigabytes (e.g. 500 GB) or -1 for all remaining disk space</li>
              <li>Select ZFS RAID topology: Stripe, Mirror, RAID-Z1, RAID-Z2, RAID-Z3, or dRAID</li>
              <li>Bootstrap spec saved to <code className="text-slate-200">/var/lib/axonwall/install-zfs.json</code></li>
            </ul>
          </div>
        </div>
      </section>

      {/* Installer Flow */}
      <section className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> Step-by-Step Installer Walkthrough
        </h2>

        <div className="space-y-4">
          <h3 className="text-base font-semibold text-white">1. System Disk Selection & Mirror Mode</h3>
          <p className="text-xs text-slate-400">
            The installer scans the SCSI/NVMe bus and displays all discovered physical drives. If multiple drives are present, you are prompted:
          </p>

          <CodeBlock
            title="Debian & Alpine Installer Terminal Prompt"
            language="text"
            code={`Found physical storage disks:
  [1] /dev/sda (Samsung SSD 990 PRO 2TB - 2000 GB)
  [2] /dev/sdb (Samsung SSD 990 PRO 2TB - 2000 GB)

Select system installation target:
  (1) Single Disk: Install Axonwall on /dev/sda
  (2) Multi-Disk Mirror: Configure mdadm RAID-1 across /dev/sda and /dev/sdb

Enter choice [1-2] (default: 1): 2`}
          />

          <h3 className="text-base font-semibold text-white pt-2">2. A/B Dual-Root Partition Sizing</h3>
          <p className="text-xs text-slate-400">
            Choose the firmware slot size for the A/B root filesystems (Standard: 16 GB, Compact: 8 GB, Expanded: 32 GB, or Custom).
          </p>

          <h3 className="text-base font-semibold text-white pt-2">3. Dedicated ZFS Storage Partition Allocation</h3>
          <p className="text-xs text-slate-400">
            Specify how much space on the system drive(s) to allocate for OpenZFS NAS pools:
          </p>

          <CodeBlock
            title="ZFS Storage Partition Prompt"
            language="text"
            code={`Configure dedicated ZFS storage partition on system disk(s)?
  - Enter '0' to skip dedicated ZFS partition on system disk
  - Enter size in GB (e.g. '500') to reserve a fixed slice
  - Enter '-1' to allocate all remaining disk space for ZFS storage

ZFS Partition Size (GB, 0 to skip, -1 for all remaining) [default: 0]: -1

Select ZFS Storage Pool Topology:
  (1) stripe  - Single VDEV / maximum capacity, no parity
  (2) mirror  - 2-way mirror (RAID-1) across disk partitions
  (3) raidz1  - RAID-Z1 (Single parity, requires 3+ disks)
  (4) raidz2  - RAID-Z2 (Dual parity, requires 4+ disks)
  (5) raidz3  - RAID-Z3 (Triple parity, requires 5+ disks)
  (6) draid1  - Distributed Spare RAID-1
  (7) draid2  - Distributed Spare RAID-2

Enter ZFS topology [1-7] (default: 2): 2
Enter ZFS pool name [default: tank]: tank`}
          />

          <Callout type="tip" title="Automatic First-Boot Provisioning">
            When installation completes, the installer writes <code className="text-emerald-300 font-mono">/var/lib/axonwall/install-zfs.json</code>. On first boot, the privileged Go daemon (<code className="text-emerald-300 font-mono">axonwalld</code>) automatically executes <code className="text-emerald-300 font-mono">zpool create</code> with optimal ashift=12, LZ4 compression, POSIX ACLs, and mounts <code className="text-emerald-300 font-mono">/mnt/tank</code> with zero manual CLI intervention.
          </Callout>
        </div>
      </section>

      {/* Disk Partition Table Layout */}
      <section className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> GPT Partition Structure (Single vs. Mirrored)
        </h2>

        <CodeBlock
          title="Physical Disk Partition Layout (GPT)"
          language="text"
          code={`Drive /dev/sda (and /dev/sdb if RAID-1):
+-------------------------------------------------------------------------------+
| Part | Label         | Size    | Filesystem     | Purpose                     |
+-------------------------------------------------------------------------------+
| p1   | EFI System    | 512 MB  | FAT32 (vfat)   | Cloned UEFI ESP + GRUB      |
| p2   | axon_root_a   | 16 GB   | ext4 (or md0)  | Firmware Slot A (Active)    |
| p3   | axon_root_b   | 16 GB   | ext4 (or md1)  | Firmware Slot B (Standby)   |
| p4   | axon_swap     | 4 GB    | swap (or md2)  | Linux Kernel Swap           |
| p5   | axon_data     | 32 GB   | ext4 (or md3)  | Persistent /var/lib/axonwall|
| p6   | axon_zfs_1    | Rest    | ZFS Member     | OpenZFS Storage Pool (tank) |
+-------------------------------------------------------------------------------+`}
        />
      </section>
    </div>
  );
}
