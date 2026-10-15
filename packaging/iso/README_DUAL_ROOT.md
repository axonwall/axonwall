# Axonwall A/B Dual-Root Architecture & System Watchdog

## 1. Overview
Axonwall implements an enterprise-grade **A/B Dual-Root System Partitioning** scheme combined with an autonomous **Health Quorum Watchdog**. This guarantees zero-downtime, unbrickable operating system upgrades across physical hardware appliances, virtual machine deployments, and remote edge satellites.

During installation, the installer guides the administrator through target disk selection, explains the dual-root mechanism, and allows customizing the partition sizing per slot based on available hardware storage.

---

## 2. Why Two Identical System Partitions?

### The Problem with Single-Partition Firewalls
In traditional operating systems and firewalls (such as pfSense® or OPNsense®), updates are applied directly to the running root partition (`/`). If a firmware update fails midway, encounters a kernel panic, or breaks network driver compatibility, the appliance is left in an unbootable state ("bricked"), requiring physical serial console or on-site manual recovery.

### The Axonwall A/B Solution
Axonwall maintains two identical, independent system partitions:
1. **Slot A (Primary Active):** Formatted as ext4 with filesystem label `axon_root_a`.
2. **Slot B (Alternate Standby):** Formatted as ext4 with filesystem label `axon_root_b`.
3. **Persistent Data (`/var/lib/axonwall`):** Formatted as ext4 with filesystem label `axon_data`.

When updates are deployed:
- The system writes all kernel, daemon, and UI updates directly into the **inactive standby slot** in the background while network routing and filtering continue uninterrupted.
- Upon scheduled reboot, GRUB boots into the newly staged slot under watchdog supervision.
- If the new image passes interface carrier, nftables, and control-plane health checks within 180 seconds, it is marked active and healthy.
- If boot fails 3 consecutive times, GRUB automatically falls back to the previous healthy slot.

Because both system slots are identical, the root partition size configured during installation is **allocated twice**.

---

## 3. Interactive Partition Sizing Options

During installation, the administrator is presented with partition configuration options tailored to the detected storage capacity:

| Option | Size per Slot | Total System Allocated | Best Suited For |
|---|---|---|---|
| **Compact** | 8 GB per slot | 16 GB total | Embedded devices, eMMC, CFast cards (16 GB - 32 GB disks) |
| **Standard (Recommended)** | 16 GB per slot | 32 GB total | Default appliance profile, ample room for packages & Suricata DPI |
| **Expanded** | 32 GB per slot | 64 GB total | Enterprise appliances with 128 GB+ NVMe SSDs & container engines |
| **Custom** | User-defined (min 6 GB) | 2 × Custom GB | Specialized deployments with specific storage requirements |

### Swap Allocation Options
- **2 GB Swap (Standard):** Balanced profile for general router workloads.
- **No Swap Partition:** Recommended for high-end NVMe drives and systems with ZRAM.
- **4 GB / 8 GB Swap:** Extended swap for intensive Suricata deep packet inspection and large memory dumps.

### Persistent Volume & Dedicated ZFS Storage Allocation
Remaining disk capacity after the A/B system slots and swap can be partitioned flexibly during installation:
1. **Reserve Remaining Space for ZFS Pool (`axon_zfs`):** Allocates 16 GB (or 8 GB on compact drives) to `/var/lib/axonwall` (`LABEL=axon_data`) and assigns all remaining capacity on the system disk(s) to a dedicated OpenZFS partition (`PARTLABEL=axon_zfs_1`, GPT type `bf01`) for NAS shares and K3s OpenEBS volumes.
2. **Split Remaining Space (50/50):** Splits remaining capacity equally between `axon_data` (`ext4`) and `axon_zfs` (OpenZFS).
3. **Custom ZFS Partition Size (GB):** Carves out an exact user-specified GB size for `axon_zfs`.
4. **No ZFS Partition on System Disk:** Assigns 100% of remaining space on the system disk to `axon_data` (`ext4`).

### Multi-Disk System RAID-1 Mirroring & ZFS RAID-Z Topologies
- **System Disk Mirroring (`mdadm` RAID-1):** When 2 or more system disks are selected during installation, Axonwall clones the GPT partition table, EFI System Partition (`AXON_EFI`), and BIOS/UEFI GRUB bootloaders across all selected drives and mirrors `axon_root_a`, `axon_root_b`, and `axon_data` so the appliance survives a complete primary drive failure.
- **OpenZFS Pool Topologies (`tank`):** Any `axon_zfs_*` partitions carved out of the system disk(s) and/or any additional dedicated secondary disks selected during installation are passed directly as raw VDEVs to OpenZFS (`stripe`, `mirror`, `raidz1`, `raidz2`, `raidz3`, `draid1`, `draid2`).

---

## 4. Partition Layout Diagram

```text
+-----------------------------------------------------------------------------------------+
| Partition 1: BIOS Boot (1 MB) / EFI ESP (512 MB) | /boot/efi       | FAT32 | 512 MB     |
| (Cloned across all member disks in RAID-1 mode)  |                 |       | [AXON_EFI] |
+-----------------------------------------------------------------------------------------+
| Partition 2: rootfsA (Active System Slot)        | /               | ext4  | 8-32 GB    |
| (Single or mdadm RAID-1 across system disks)     |                 |       | [axon_root_a]|
+-----------------------------------------------------------------------------------------+
| Partition 3: rootfsB (Standby Fallback Slot)     | /mnt/standby    | ext4  | 8-32 GB    |
| (Single or mdadm RAID-1 across system disks)     | (for staging)   |       | [axon_root_b]|
+-----------------------------------------------------------------------------------------+
| Partition 4: Swap (Optional)                     | [SWAP]          | swap  | 0-8 GB     |
+-----------------------------------------------------------------------------------------+
| Partition 5: Persistent Data & Logs              | /var/lib/axonwall| ext4  | 8-64 GB    |
| (Single or mdadm RAID-1 across system disks)     |                 |       | [axon_data]|
+-----------------------------------------------------------------------------------------+
| Partition 6: Dedicated OpenZFS Storage VDEV      | /mnt/tank       | zfs   | Remainder  |
| (Combined with peer partitions/extra disks into  | (NAS & OpenEBS) | bf01  | or Custom  |
|  Stripe / Mirror / RAIDZ1 / RAIDZ2 / RAIDZ3)     |                 |       | [axon_zfs] |
+-----------------------------------------------------------------------------------------+
```

---

## 5. GRUB Boot-Counting Lifecycle

1. **Next-Boot Staging:**
   When an update is flashed to the inactive slot (e.g., Slot B), `axonwalld` sets:
   ```bash
   grub-editenv /boot/grub/grubenv set active_slot=B
   grub-editenv /boot/grub/grubenv set bootcount=0
   grub-editenv /boot/grub/grubenv set bootlimit=3
   ```
2. **GRUB Boot Attempt:**
   Upon boot, `/etc/grub.d/40_axonwall_ab` reads `bootcount`.
   - If `bootcount < bootlimit`, GRUB increments `bootcount = bootcount + 1` and boots the active slot.
   - If `bootcount >= bootlimit` (e.g. 3 consecutive boot failures or kernel panics), GRUB automatically reverts `active_slot` to the alternate healthy slot and resets `bootcount = 0`.

---

## 6. Watchdog Health Quorum Verification (`axonwalld`)

Immediately after boot, the privileged daemon `axonwalld` initiates an autonomous 3-step verification sequence:

1. **Network Interface Health:**
   - Validates that the Linux loopback interface (`lo`) is operational.
   - Verifies enumeration and link carrier status for physical/virtual network adapters.
2. **Atomic nftables Kernel Baseline:**
   - Executes syntax validation (`nft -c -f ...`) and verifies kernel netfilter subsystem readiness.
3. **Control Plane Quorum:**
   - Confirms IPC socket readiness (`/run/axonwall/agent.sock`) and management control plane quorum.

### Commitment
If all three checks pass within the 180-second health window:
```bash
grub-editenv /boot/grub/grubenv set bootcount=0
```
The active slot is marked **permanently healthy and committed**.
