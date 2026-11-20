import React from 'react';
import Link from 'next/link';
import { HardDrive, Layers, RefreshCw, CheckCircle2, ShieldAlert, Cpu, Terminal, Palette, Lock } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Next-Gen Installer, Multi-Disk RAID, LUKS2+TPM2 & ZFSBootMenu | Axonwall Documentation',
  description:
    'Documentation for Axonwall v0.11.68 bare-metal installation: axonwall-console --install Express/Custom TUI, --unattended automation, unified Vault edition, Smart Disk Tiering, LUKS2 + TPM 2.0 PCR 0+2+7 auto-unlock, and ZFSBootMenu v3.1.0 Boot Environments.',
};

export default function InstallerRaidZfsDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Bare-Metal Installer &amp; Boot Engines • v0.11.68
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Next-Gen Installer, Multi-Disk RAID &amp; ZFSBootMenu
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Deploy unbrickable bare-metal appliances via the interactive <code className="text-emerald-400 font-mono">axonwall-console --install</code> TUI or zero-touch <code className="text-emerald-400 font-mono">--unattended</code> manifests. Choose between unified <code className="text-slate-200 font-mono">axonwall</code> (NGFW), <code className="text-slate-200 font-mono">vault</code> (Immutable S3 Backup), and <code className="text-cyan-300 font-mono">k3s-storage</code> (Barebones K3s + OpenZFS/OpenEBS) editions, Smart NVMe/SSD/HDD disk tiering, LUKS2 encryption with TPM 2.0 auto-unlock, <code className="text-emerald-400 font-mono">mdadm</code> RAID-1 A/B slots, or native ZFSBootMenu v3.1.0 Root-on-ZFS Boot Environments.
        </p>
      </div>

      {/* Next-Gen TUI Installer & Unattended Mode */}
      <section id="next-gen-installer" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-emerald-400" /> Next-Gen Installer TUI, Unified Editions &amp; Smart Tiering
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Booting the unified <code className="text-emerald-400 font-mono">axonwall-debian13-amd64.iso</code> launches{' '}
          <code className="text-emerald-400 font-mono">axonwall-console --install</code> directly on VGA and serial (<code className="text-slate-200 font-mono">ttyS0</code>) consoles:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-emerald-400 text-sm">Express 1-Click vs. 5-Step Custom Wizard</div>
            <p className="text-slate-400 leading-relaxed">
              <strong>Express Mode</strong> inspects hardware topology and provisions optimal defaults in a single confirmation.{' '}
              <strong>5-Step Custom Wizard</strong> walks operators through (1) Edition (<code className="text-slate-200 font-mono">axonwall</code> NGFW/Converged, <code className="text-slate-200 font-mono">vault</code> S3 Immutable Backup, or <code className="text-cyan-300 font-mono">k3s-storage</code> Barebones K3s + OpenZFS/OpenEBS Host), (2) Boot Mode (<code className="text-slate-200 font-mono">ab-dual-root</code>, <code className="text-slate-200 font-mono">zbm</code>, or <code className="text-slate-200 font-mono">rolling</code>), (3) Smart Disk Tiering, (4) LUKS2 + TPM 2.0 Encryption, and (5) Initial Management NIC &amp; Credentials.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-sky-400 text-sm">Smart Disk Tiering (NVMe / SSD / HDD)</div>
            <p className="text-slate-400 leading-relaxed">
              Automatically classifies block devices by rotational media, NVMe namespace speed, and capacity—assigning fast NVMe devices to OS boot mirrors, dedicated ZFS SLOG (<code className="text-slate-200 font-mono">logDisks</code>), and L2ARC (<code className="text-slate-200 font-mono">cacheDisks</code>), while grouping bulk SAS/SATA drives into RAID-Z/dRAID <code className="text-slate-200 font-mono">dataDisks</code> and <code className="text-slate-200 font-mono">spareDisks</code>.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-amber-400 text-sm flex items-center gap-1.5">
              <Lock className="w-4 h-4" /> LUKS2 + TPM 2.0 Auto-Unlock (PCRs 0+2+7)
            </div>
            <p className="text-slate-400 leading-relaxed">
              Optional full-disk/pool at-rest encryption formats backing partitions with AES-256-XTS LUKS2 and seals a hardware recovery key into the onboard TPM 2.0 via <code className="text-slate-200 font-mono">systemd-cryptenroll</code> bound to <strong>PCRs 0 + 2 + 7</strong> (UEFI firmware, Option ROMs, and Secure Boot state), enabling unattended reboots that fail closed if hardware or boot chain is tampered with.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-purple-400 text-sm">Unattended YAML &amp; Cloud-Init ISO Export</div>
            <p className="text-slate-400 leading-relaxed">
              Automate mass fleet rollouts via <code className="text-slate-200 font-mono">axonwall-console --install --unattended &lt;config.yaml|https://...&gt;</code>, or generate a bootable NoCloud seed image with <code className="text-slate-200 font-mono">axonwallctl cloudinit export --iso -o cidata.iso</code>.
            </p>
          </div>
        </div>

        <CodeBlock
          title="Interactive, Unattended & Cloud-Init Provisioning Commands"
          language="bash"
          code={`# Launch interactive TUI installer (Express 1-Click or 5-Step Custom Wizard)
sudo axonwall-console --install

# Automated zero-touch installation from local YAML or HTTPS provisioning endpoint
sudo axonwall-console --install --unattended https://provision.corp.internal/fw-branch-04.yaml

# Export a NoCloud seed ISO (cidata.iso) from an existing or staged configuration
axonwallctl cloudinit export --iso -o cidata.iso`}
        />
      </section>

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
          <Layers className="w-6 h-6 text-emerald-400" /> GPT Partition Structure (Single vs. Mirrored A/B)
        </h2>

        <CodeBlock
          title="Physical Disk Partition Layout (GPT) - A/B Dual-Root Mode"
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

      {/* ZFSBootMenu (Root-on-ZFS) Mode */}
      <section id="zbm-boot-environments" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <RefreshCw className="w-6 h-6 text-emerald-400" /> ZFSBootMenu Root-on-ZFS Mode (v3.1.0)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          As an alternative to traditional ext4 A/B dual-root slots, Axonwall provides native{' '}
          <strong className="text-white">ZFSBootMenu v3.1.0 (ZBM)</strong> support (<code className="text-emerald-400 font-mono">installMode: "zbm"</code>). 
          Under ZBM, the entire operating system boots directly from an OpenZFS root pool (<code className="text-slate-200 font-mono">zroot</code>) with native support for any zpool topology (<code className="text-slate-200">stripe</code>, <code className="text-slate-200">mirror</code>, <code className="text-slate-200">raidz1/2/3</code>, <code className="text-slate-200">draid1/2/3</code>).
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 font-bold text-white text-base">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span>Native Boot Environments (BEs)</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              System root datasets reside in <code className="text-slate-200 font-mono">zroot/ROOT/&lt;be_name&gt;</code>. OTA firmware updates snapshot the active BE (e.g. <code className="text-slate-200 font-mono">zroot/ROOT/axonwall-0.11.67@pre-update-v0.11.68</code>) and clone it instantaneously with zero wasted disk space into a new target BE (<code className="text-slate-200 font-mono">zroot/ROOT/axonwall-0.11.68</code>).
            </p>
            <ul className="text-xs text-slate-300 list-disc list-inside space-y-1">
              <li>Instantaneous atomic updates and rollbacks via <code className="font-mono text-emerald-300">axonwallctl zbm</code></li>
              <li>Multiple historical Boot Environments retained simultaneously</li>
              <li>Non-root data isolated in <code className="text-slate-200 font-mono">zroot/data</code></li>
            </ul>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 font-bold text-white text-base">
              <ShieldAlert className="w-5 h-5 text-emerald-400" />
              <span>Autonomous Pre-Boot Watchdog</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              ZFSBootMenu hooks execute before the Linux kernel is loaded. Hook <code className="text-slate-200 font-mono">20-axonwall-watchdog.sh</code> inspects <code className="text-slate-200 font-mono">org.axonwall:bootcount</code> and <code className="text-slate-200 font-mono">org.axonwall:bootlimit=3</code>.
            </p>
            <ul className="text-xs text-slate-300 list-disc list-inside space-y-1">
              <li>Reverts <code className="text-slate-200 font-mono">bootfs</code> to <code className="text-slate-200 font-mono">org.axonwall:fallback_be</code> on 3 failures</li>
              <li>Autonomous promotion (<code className="text-slate-200 font-mono">zfs promote</code>) upon verified daemon quorum</li>
              <li>Full Web Console UI under <strong>System &gt; Updates</strong> and TUI tab <code className="font-mono text-emerald-300">[u] ZBM/Boot</code></li>
            </ul>
          </div>
        </div>

        <CodeBlock
          title="Physical Disk Partition Layout (GPT) - ZFSBootMenu Mode"
          language="text"
          code={`Physical Disks (Single, Mirror, RAID-Z, or dRAID pool):
+-------------------------------------------------------------------------------+
| Part | Label         | Size    | Filesystem     | Purpose                     |
+-------------------------------------------------------------------------------+
| p1   | EFI System    | 1024 MB | FAT32 (vfat)   | UEFI ESP: EFI/ZBM/VMLINUZ.EFI|
| p2   | axon_swap     | 4 GB    | swap           | Linux Kernel Swap (Optional)|
| p3   | axon_zbm_root | Rest    | OpenZFS VDEV   | zroot (Root Pool VDEV member)|
+-------------------------------------------------------------------------------+

Dataset Hierarchy:
zroot
├── ROOT
│   ├── axonwall-0.11.67          (mountpoint=/, org.zfsbootmenu:commandline="...")
│   │   └── @pre-update-v0.11.68  (Point-in-time snapshot)
│   └── axonwall-0.11.68          (mountpoint=/, clone/promoted next-boot BE)
└── data
    └── axonwall                  (mountpoint=/var/lib/axonwall, persistent config & logs)`}
        />

        <CodeBlock
          title="ZFSBootMenu & Cryptographically Signed OTA Update CLI Reference"
          language="bash"
          code={`# List all ZFSBootMenu Boot Environments, active bootfs, and snapshots
axonwallctl zbm list

# Create a point-in-time snapshot, clone into a new BE, and activate for next boot
sudo axonwallctl zbm snapshot axonwall-0.11.68 pre-change
sudo axonwallctl zbm clone axonwall-0.11.68@pre-change axonwall-canary
sudo axonwallctl zbm activate axonwall-canary

# Prune obsolete Boot Environments or snapshots
sudo axonwallctl zbm delete axonwall-0.11.62
sudo axonwallctl zbm delete-snapshot axonwall-0.11.68@pre-change

# Stage cryptographically verified OTA firmware update (SHA-256 + OpenSSL .sig
# verified against /etc/axonwall/release-signing.pub before writing standby slot/BE)
sudo axonwallctl update --version 0.11.68
sudo axonwallctl update --version 0.11.68 --slot B
sudo axonwallctl update --apt   # Rolling single-root APT upgrade mode`}
        />

        {/* ZFSBootMenu Visual Theming & Styling */}
        <div className="space-y-4 pt-6 border-t border-slate-800/60">
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            <Palette className="w-5 h-5 text-emerald-400" /> ZFSBootMenu Visual Theming &amp; Mirrored ESP Sync
          </h3>
          <p className="text-sm text-slate-300 leading-relaxed">
            Axonwall provides full visual theming for ZFSBootMenu v3.1.0 across the UEFI GOP graphics splash screen, console typography, and 5 tactical ANSI color palettes—automatically synchronizing the updated UKI across all mirrored EFI System Partitions (<code className="text-slate-200 font-mono">/boot/efi</code>, <code className="text-slate-200 font-mono">/boot/efi2</code>, etc.).
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">1. Boot Splash Screen</span>
              <p className="text-xs text-slate-400">
                A 24-bit uncompressed Windows BMP (<code className="text-slate-200">640x480</code>) is embedded directly into the Unified Kernel Image (UKI) <code className="text-slate-200">.splash</code> section via <code className="text-slate-200">systemd-stub</code>, rendering seamlessly before kernel initialization.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">2. High-DPI Fonts</span>
              <p className="text-xs text-slate-400">
                On 4K and Retina consoles, small text is enlarged using <code className="text-slate-200">rd.vconsole.font=ter-132b</code> (32px bold Terminus) with automatic fallback (<code className="text-slate-200">zbm.autosize=1</code>).
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <span className="text-xs font-semibold text-sky-400 uppercase tracking-wider">3. 5 Tactical ANSI Palettes</span>
              <p className="text-xs text-slate-400">
                Early pre-boot hooks (<code className="text-slate-200">15-axonwall-theme.sh</code>) program hardware VGA registers with five built-in palettes: <code className="text-emerald-300">cyber-cyan</code>, <code className="text-emerald-300">emerald-ops</code>, <code className="text-emerald-300">amber-tactical</code>, <code className="text-emerald-300">crimson-soc</code>, and <code className="text-emerald-300">mono-stealth</code>.
              </p>
            </div>
          </div>

          <CodeBlock
            title="Managing ZFSBootMenu Theme & Mirrored ESP Sync with axonwall-zbm-theme"
            language="bash"
            code={`# Check current theme, embedded UKI splash section, mirrored ESPs, and active font
axonwall-zbm-theme status

# Set font for 4K / High-DPI displays (ter-132b, ter-v32b, ter-v28b, ter-v24b, or default)
sudo axonwall-zbm-theme set-font ter-132b

# Switch 16-color ANSI console palette (cyber-cyan, emerald-ops, amber-tactical, crimson-soc, mono-stealth)
sudo axonwall-zbm-theme set-palette emerald-ops

# Install custom splash graphic (automatically converts PNG/JPG to uncompressed BMP)
sudo axonwall-zbm-theme set-splash /root/custom-brand.png

# Re-embed UKI .splash section and sync EFI/ZBM/VMLINUZ.EFI across all mirrored ESP partitions
sudo axonwall-zbm-theme apply`}
          />
        </div>
      </section>

      {/* Barebones K3s + Storage Edition */}
      <section id="k3s-storage-edition" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-cyan-400" /> Barebones K3s + OpenZFS/OpenEBS Storage Host (<code className="font-mono text-cyan-300">k3s-storage</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Dedicated compute and storage nodes do not need NGFW, Suricata IDS, or Samba/NFS appliances enabled. Both the Debian 13 and Alpine Linux ISOs expose the{' '}
          <code className="text-cyan-300 font-mono">k3s-storage</code> profile directly in UEFI GRUB / BIOS ISOLINUX boot menus as well as Step 1 of <code className="text-emerald-400 font-mono">axonwall-console --install</code>.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-cyan-500/30 space-y-2">
            <div className="font-bold text-cyan-300 text-sm">What Gets Provisioned</div>
            <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
              <li><code className="font-mono text-slate-200">core-k3s</code> &amp; <code className="font-mono text-slate-200">core-nas</code> enabled cleanly in host mode (<code className="font-mono">core-firewall=false</code>)</li>
              <li>Pre-staged OpenZFS ZFS-LocalPV CSI operator (<code className="font-mono">/var/lib/rancher/k3s/server/manifests/zfs-operator.yaml</code>) backed by your selected RAID pool</li>
              <li>First-boot reconcilers (<code className="font-mono">axonwall-k3s-firstboot</code>, <code className="font-mono">axonwall-k3s-verify</code>, <code className="font-mono">axonwall-k3s-status</code>) plus hardened minimal host <code className="font-mono">nftables.conf</code> &amp; sysctl tuning</li>
              <li>Alpine Linux OpenRC parity via <code className="font-mono">axonwall-firstboot-alpine</code> + <code className="font-mono">k3s</code> / <code className="font-mono">k3s-agent</code> init scripts</li>
            </ul>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-emerald-400 text-sm">Server Control-Plane or Worker Agent Join</div>
            <p className="text-slate-400 leading-relaxed">
              During installation (or via unattended <code className="font-mono text-slate-200">k3sStorage.role</code> in YAML / Cloud-Init), designate the host as either an initial control-plane <code className="font-mono text-slate-200">server</code> node or a <code className="font-mono text-slate-200">agent</code> storage worker joining an existing cluster URL with a pre-shared join token. Pair with{' '}
              <Link href="/docs/custom-kernel" className="text-indigo-400 underline">Custom Hardened Kernels</Link> to lock down ZFS + K3s host kernels further.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
