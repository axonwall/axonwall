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

### Persistent Volume Allocation
All remaining unallocated disk capacity is automatically formatted as ext4 (`LABEL=axon_data`) and mounted to `/var/lib/axonwall`. This volume preserves cryptographic certificates, Headscale WireGuard mesh databases, VictoriaMetrics time-series flows, Suricata logs, and user identities across all OS updates.

---

## 4. Partition Layout Diagram

```text
+-----------------------------------------------------------------------------------------+
| Partition 1: BIOS Boot (1 MB) / EFI ESP (512 MB) | /boot/efi       | FAT32 | 512 MB     |
+-----------------------------------------------------------------------------------------+
| Partition 2: rootfsA (Active System Slot)        | /               | ext4  | 8-32 GB    |
|                                                  |                 |       | [axon_root_a]|
+-----------------------------------------------------------------------------------------+
| Partition 3: rootfsB (Standby Fallback Slot)     | /mnt/standby    | ext4  | 8-32 GB    |
|                                                  | (for staging)   |       | [axon_root_b]|
+-----------------------------------------------------------------------------------------+
| Partition 4: Swap (Optional)                     | [SWAP]          | swap  | 0-8 GB     |
+-----------------------------------------------------------------------------------------+
| Partition 5: Persistent Data & Logs              | /var/lib/axonwall| ext4  | Remainder  |
|                                                  |                 |       | [axon_data]|
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
