# Axonwall A/B Dual-Root Architecture & System Watchdog

## 1. Overview
Axonwall implements an enterprise-grade **A/B Dual-Root System Partitioning** scheme combined with an autonomous **Health Quorum Watchdog**. This guarantees zero-downtime, unbrickable operating system upgrades across physical hardware appliances, virtual machine deployments, and remote edge satellites.

---

## 2. Partition Layout

```text
+-----------------------------------------------------------------------------------------+
| Partition 1: EFI System Partition (ESP)  | /boot/efi       | FAT32 | 512 MB             |
+-----------------------------------------------------------------------------------------+
| Partition 2: rootfsA (Active / Standby)   | /               | ext4  | 16 GB [LABEL: axon_root_a] |
+-----------------------------------------------------------------------------------------+
| Partition 3: rootfsB (Active / Standby)   | /               | ext4  | 16 GB [LABEL: axon_root_b] |
+-----------------------------------------------------------------------------------------+
| Partition 4: Persistent Data & Logs      | /var/lib/axonwall| ext4  | Rest of Disk       |
+-----------------------------------------------------------------------------------------+
```

* **rootfsA & rootfsB:** Contain identical Debian/Axonwall OS environments. One slot is active (read-only or state-isolated), while the other receives system image updates.
* **Persistent Partition (`/var/lib/axonwall`):** Houses cryptographic certificates, Headscale SQLite databases, configuration bundles (`bundles/last-known-good.nft`), and user identities. This partition is mounted consistently regardless of which rootfs slot is booted.

---

## 3. GRUB Boot-Counting Lifecycle

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

## 4. Watchdog Health Quorum Verification (`axonwalld`)

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
