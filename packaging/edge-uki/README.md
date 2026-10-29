# Axonwall Super-Slim Edge NGFW (`axonwall-edge` Single-File EFI UKI)

## 1. Overview
`packaging/edge-uki` builds a **Zero-Surface, Stateless Edge NGFW** designed to sit on the untrusted WAN perimeter while managed by a **Full Axonwall Host** running behind the firewall on the internal LAN.

Instead of shipping a traditional Linux distribution (Debian, Alpine, or OpenWrt) with shells, package managers, and thousands of loadable kernel modules, the Super-Slim Edge NGFW consists of:
1. **A Hardware-Specific Monolithic Linux Kernel (`CONFIG_MODULES=n`)**: Compiled specifically for the target hardware SKU with only the exact NIC, crypto, and netfilter drivers built-in.
2. **Our Static Go Binary as PID 1 (`/init`)**: Compiled with `CGO_ENABLED=0` and CPU microarchitecture optimizations (`GOAMD64=v3`), embedded directly inside the kernel via `CONFIG_INITRAMFS_SOURCE`.
3. **Single-File UEFI Unified Kernel Image (`BOOTX64.EFI`)**: Enabled via `CONFIG_EFI_STUB=y`, allowing the motherboard UEFI firmware to boot the signed `.efi` binary directly into RAM in **< 1.2 seconds** without GRUB or any writable disk filesystem.

---

## 2. Security & Performance Properties

- **Zero Shell / Zero LotL Surface**: No `/bin/sh`, `/bin/bash`, `busybox`, `sshd`, `curl`, `python`, or `libc.so` exists in the image.
- **Total LKM Rootkit Immunity (`CONFIG_MODULES=n`)**: Loadable kernel module support is compiled out of the kernel; `init_module` / `finit_module` syscalls do not exist.
- **Zero Storage Wear**: Runs 100% in RAM (`initramfs`). Conntrack flows (`/proc/net/nf_conntrack`) and `nftables` packet logs (`/dev/kmsg`) are harvested in memory and streamed over mTLS WebSockets (`EDGE_FLOW_BATCH`) to the internal Axonwall Hub.
- **Wire-Speed Fastpath (`CONFIG_NF_FLOW_TABLE_INET=y`)**: Established TCP/UDP connections are offloaded to the kernel/hardware flowtable, bypassing per-packet rule traversal.

---

## 3. Manufacturing Hardware SKU Profiles

| Profile | Target Hardware | Built-in NIC Drivers | Compiler Tuning |
| :--- | :--- | :--- | :--- |
| **`sku-vm-virtio` *(Default)*** | **KVM / QEMU / Proxmox / Cloud Virtual Edge** | **`virtio_net`, `virtio_pci` only (zero physical NIC/storage drivers)** | **`-march=x86-64`, `GOAMD64=v1`** |
| `sku-x86-intel-n100-i226` | Intel Alder Lake-N (N100/N305) Desktop/1U Branch Appliance | `igc` (2.5GbE i225/i226), `igb`, `e1000e` | `-march=x86-64-v3 -mtune=alderlake`, `GOAMD64=v3` |
| `sku-x86-enterprise-10g-25g` | 1U/2U Xeon / EPYC Rack NGFW | `ixgbe` (10G), `i40e` (25/40G), `ice` (100G), `mlx5_core` | `-march=x86-64-v3`, `GOAMD64=v3` |
| `sku-arm64-router` | ARM64 SoC Edge Gateway (MT7988A / Armada) | `mt7530_dsa`, `mtk_eth_soc`, `mvpp2` | `-mcpu=cortex-a73+crypto`, `GOARCH=arm64` |

---

## 4. Building & Booting an Edge NGFW UKI

```bash
# 1. Build the default minimalist Virtualization SKU (sku-vm-virtio) initramfs + kernel config (< 5 seconds):
./packaging/edge-uki/build-edge-uki.sh

# 2. Full UEFI Unified Kernel Image (.efi) compilation with Linux 6.12 LTS:
./packaging/edge-uki/build-edge-uki.sh \
  --sku sku-vm-virtio \
  --mode full-uki \
  --hub wss://10.0.0.2:2966/ws/satellite \
  --cmdline "axonwall.id=edge-vm-01 axonwall.token=ztp_axon_... axonwall.wan=eth0:dhcp axonwall.lan=eth1:10.0.0.1/24"
```

---

## 5. Autonomous Zero-Touch Deployment via Cloud-Init (Zero Python / Zero Shell)

The static Go PID 1 binary (`/init`, see [`cloudinit.go`](../../apps/axonwall-satellite/engine/cloudinit.go)) includes a native, pure-Go Cloud-Init engine so the standard release `axonwall-edge-sku-vm-virtio.efi` image can be deployed autonomously across any cloud or hypervisor without recompiling or modifying kernel command-line parameters:

### Supported Cloud-Init Datasources
1. **NoCloud (`cidata`) & ConfigDrive (`config-2`) Block/CD-ROM Seeds**:
   - Automatically scans `/sys/class/block` (`/dev/vd*`, `/dev/sr*`, `/dev/sd*`), mounts `iso9660` or `vfat` read-only (`MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC`), ingests `user-data`, `meta-data`, and `network-config` (or `/openstack/latest/*`), and unmounts immediately.
2. **QEMU `fw_cfg` Sysfs**:
   - Reads `/sys/firmware/qemu_fw_cfg/by_name/opt/cloud-init/user-data/raw` (or `opt/org.axonwall/user-data/raw`).
3. **Cloud IMDS HTTP Metadata (`http://169.254.169.254`)**:
   - If no static boot interfaces are specified, PID 1 automatically discovers the primary NIC (`eth0`), acquires a DHCPv4 lease via the pure-Go RFC 2131 client, and probes:
     - **OpenStack / Hetzner / DigitalOcean**: `/openstack/latest/user_data`, `meta_data.json`, `network_data.json`
     - **AWS EC2 (IMDSv2 & IMDSv1)**: `/latest/api/token` + `/latest/user-data` & `/latest/meta-data/*`
     - **Google Cloud Platform (GCP)**: `/computeMetadata/v1/instance/attributes/user-data`
     - **Microsoft Azure**: `/metadata/instance/compute/userData`

### Example `#cloud-config` (`user-data`)
```yaml
#cloud-config
hostname: edge-fw-nyc-01
axonwall:
  hub: wss://10.0.0.2:2966/ws/satellite
  id: edge-fw-nyc-01
  token: ztp_axon_9f8e7d6c5b4a...
  sku: sku-vm-virtio
  ca_cert: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  interfaces:
    - name: wan
      device: eth0
      address: dhcp
    - name: lan
      device: eth1
      address: 10.10.0.1/24
  routes:
    - destination: 10.20.0.0/16
      gateway: 10.10.0.254
      device: eth1
```
Standard Cloud-Init `network-config` (both Version 1 `config: - type: physical` used by Proxmox VE / OpenStack and Version 2 Netplan `ethernets:`) and `write_files:` (including `encoding: b64`) are also parsed natively in Go.
