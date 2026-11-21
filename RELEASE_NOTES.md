# Axonwall Release Notes

All notable changes across **Axonwall** appliance editions (`axonwall` Converged NGFW, `minimal` Reduced Attack Surface, `vault` Immutable S3 Backup, and `k3s-storage` Barebones K3s + OpenZFS/OpenEBS), kernel pipelines, Ring-0 eBPF subsystems, and management consoles are documented in this file.

Official build artifacts, SHA-256 checksums, and detached Ed25519 signatures (`.sha256.sig`) are published on [GitHub Releases](https://github.com/axonwall/axonwall/releases) and the [Axonwall Releases Portal](https://axonwall.com/releases).

---

## `v0.13.0` (2026-11-21) — Btrfs + Snapper Root, Minimal Edition, Bundled-Binary Plugins, Expanded eBPF Visuals, Browser K9s & Deep-Dive Hardening

### Highlights
- **Btrfs + Snapper Root Boot Architecture (`installMode: "btrfs"`)**:
  - In-kernel Copy-on-Write alternative to ZFSBootMenu (`zbm`) without external DKMS modules, built across kernel config (`CONFIG_BTRFS_FS=y`, `CONFIG_BTRFS_FS_POSIX_ACL=y` in `packaging/kernel/fragments/03-storage-zfs.config`), Debian 13 & Alpine ISOs (`btrfs-progs`, `snapper`), `axonwall-console --install` TUI, unified `axonwall-install` (`[3] Btrfs + Snapper Root`, shifting `rolling` to `[4]`), Cloud-Init, and `.deb` packaging.
  - Provisions single-disk `compress=zstd:1,noatime,space_cache=v2` or automatic multi-disk native Btrfs RAID-1 (`-d raid1 -m raid1`), flat subvolume isolation (`@`, `@snapshots`, `@var_log`, and `@var_lib_axonwall` or optional `4096 MiB` LUKS2 `axon_data`), plus optional dedicated extra ZFS `tank` disks (`ZFS_EXTRA_DISKS`).
  - Introduces [`axonwall-btrfs-grub`](packaging/iso/config/includes.chroot/usr/local/bin/axonwall-btrfs-grub) (`sync`, `rollback <N>`, `create-snapshot`) to populate the GRUB2 `Axonwall Btrfs Snapshots (Snapper Rollback)` submenu (omitting `grubenv`/`save_env` to prevent sparse-file boot halts) and perform atomic `subvolid=5` flat-subvolume rollbacks.
  - Wired end-to-end across `axonwall-update --btrfs` (fail-closed pre/post Snapper pairs + GRUB sync), `axonwalld` (`/v1/system/btrfs`), Custom Kernel Studio pre-kernel snapshots, `axonwall-tui` (`Btrfs Snapper` tab), `axonwallctl`, and Web Console (`/system/updates`, `/system/power`).
- **Minimal Reduced-Attack-Surface Edition (`minimal`) & On-Demand Role/Plugin Provisioning**:
  - Added `minimal` as the fourth unified edition alongside `axonwall`, `vault`, and `k3s-storage` across GRUB2/ISOLINUX boot menus, TUI & shell installers, Debian d-i (`preseed-minimal.cfg`), Cloud-Init, `axonwall-update`, and dedicated `axonwall-minimal_*.deb` packages.
  - Ships with a stripped boot/management baseline (DHCP, DNS, NAS, and KVM/LXC disabled by default; optional packages purged on target; `/bin/bash` fallback for directory/SSSD when `zsh` is absent) and supports clean on-demand installation of Core Roles & Plugins via `/system/plugins`, `axonwallctl plugin`, and `/v1/system/plugins/action`.
- **Plugin Bundled Binaries & 23-Plugin Catalog (5 Core Roles + 18 Extension Plugins)**:
  - Extension and core plugins now declare SHA-256-verified bundled binary archives extracted fail-closed into isolated per-plugin `bin/` directories with automatic interactive-shell `PATH` snippets (`plugin_shell.go`).
  - Migrated `k3s` & `k9s` into `core-k3s` and `vim` & `neovim` into `cli-workstation`; added `cli-emacs` (bundled Debian Emacs), `cli-emacs-doom`, and `cli-emacs-spacemacs` sharing the Emacs runtime.
- **Expanded Ring-0 eBPF Visualizations & Live Kernel BPF Inventory (`/reporting/ebpf`, `/reporting/flows`, `/security/threat-harvester`)**:
  - Added 6 interactive telemetry visualizers (`EbpfDataplaneCharts`, `EbpfFlowTopologyMap`, `EbpfKernelInventoryPanel`, `EbpfCrossDutyVisualizer`, `EbpfSecurityVisualizer` + `ThreatSketchWaveform`, `FlowsLiveVisualStrip`) powered by `CollectKernelBpfInventory()` inside `/v1/ebpf/overview` (`bpfInventory`).
  - Visualizes live loaded kernel BPF programs (JIT/translated bytes, verified instructions, BTF, run count/time) and BPF maps (key/value/max entries, memlock, frozen flags), real-time XDP verdict rates, per-CPU core load, protocol/dual-stack/VLAN mix, top services, CIDR blocklist impact, per-source SYN rate meter, flow topology, ZFS ARC/ZIL & KVM `vnet`/`tap` cross-duty metrics, and Threat-LLM packet sketch waveforms.
- **Multi-Round Full-Stack Security, Correctness & Platform Modernization (Bug Hunt Rounds 3, 4 & v0.12.4 Deep-Dive + Next.js 16 Stack Rollup)**:
  - **Web Console & API**: DNS/IP/redirect SSRF guard (`ssrf-guard.ts`), CSRF `X-Forwarded-Host` + same-origin proof checks, `/api/auth/gateway` bypass fix, live `.password_changed` enforcement across admin/API routes, OIDC nonce/proxy integration fixes, immediate break-glass MFA reset, 8-field secret redaction, authenticated `GET /api/v1/state`, live ClickHouse Data Lake metrics, and honest daemon-down/unknown states replacing fabricated telemetry.
  - **Go Daemons, Controller, Satellite & Terraform**: NSS shell escalation guards, SSSD `allowed_shells`/`shell_fallback`, fail-closed bundled-binary SHA-256/symlink validation, HelmChart/Samba/LIO/MinIO/QEMU/LXC validators, MCP audit secret redaction & cross-process rate-limit locking, pure-Go Netlink `over`/wildcard `ifname`/chunked sets/delete in `axonwall-satellite`, HA edge reconnect & VIP preservation, and Terraform TLS/timeout/`jobId` propagation.
  - **Packaging, CI & Dependencies**: Next.js 16 (`--webpack`), TypeScript 7, Turbo, Go & Docker dependency rollups; safe POSIX `awk` symlink validation in `axonwall-update`; `core-k3s` preservation over `axon_data` mounts; pinned Alpine `3.21.8` SHA-256 base ISO; `nodejs (>= 20.0.0)` Trixie dependency fix; CI duplicate-script parity and artifact size limits.

---

## `v0.12.4` (2026-11-20) — Serial Console Parity, `nftables` 1.1+ Floor & Installer Parity

### Highlights
- Enabled 9600-baud serial console output with dual `gfxterm`/`serial` terminal input/output across GRUB configurations.
- Raised the `nftables (>= 1.1.0)` dependency floor for `vault` and `k3s-storage` editions and synchronized installer hardening across Debian and Alpine copies of `axonwall-install`.
- Completed Round-4 fail-closed updater/watchdog, controller `dist`, and daemon test hardening.

---

## `v0.12.3` (2026-11-19) — Browser K9s Live Explorer, Cluster Pulse/Topology & Node Roles/Taints Modal

### Highlights
- **Browser K9s Live Explorer (`/k3s/explorer`, `/v1/k3s/*` APIs & `/api/k3s/logs/stream`)**: Full browser-native K9s workbench (`K9sExplorerWorkbench`, `K3sInspectorDrawer`, `K3sPulseCharts`, `K3sTopologyMap`) with `:po`/`:svc`/`:ing`/`:pulse`/`:topo` command navigation, live SSE pod logs, interactive container `exec`, server dry-run YAML editing, admin Secret decoding, and default CLI `k9s` (`v0.51.0`).
- **Node Roles & Taints Modal (`/k3s/cluster` & `/v1/k3s/nodes/scheduling`)**: Merge-patch scheduling controls with one-click edge node tainting and role presets.
- **Identity & HA Hardening**: Authenticated SSSD read bind account (`cn=svc-sssd`), OpenLDAP DIT glue verification, and local node identity preservation during HA SQLite replica promotion to prevent split-brain.

---

## `v0.12.2` (2026-11-18) — Keepalived Sync-Group & ZFS Installer Topology Fixes

### Highlights
- Moved Keepalived `notify_master`, `notify_backup`, and `notify_fault` hooks into `vrrp_sync_group VG1` so multi-instance VRRP transitions fire synchronously without demoting active MASTER directory/NAS services.
- Hoisted `resolve_zfs_topology()` definition before its call site in Debian and Alpine `axonwall-install`.

---

## `v0.12.1` (2026-11-18) — Full-Stack Security & Correctness Audit

### Highlights
- Completed comprehensive `v0.12.0` full-stack hardening across `@axonwall/lib`, `axonwalld`, `axonwall-satellite`, `axonwall-controller`, `axonwall-console`, Web Console, and packaging/CI pipelines.

---

## `v0.12.0` (2026-11-17) — Axonwall Blackbox Threat-LLM Harvester, Custom Hardened Linux 6.12 LTS Kernels & Unified Rebrand

### Highlights
- **Unified Brand Refresh & Plymouth Boot Splash**: Applied the brick-wall, shield, and crossed-axes rebrand across Web Console, GRUB, ZFSBootMenu, and Plymouth splash screens; added Vigilante base domain URL configuration and HelmChart validation support.
- **Axonwall Blackbox: Extreme eBPF Threat-LLM Harvester (`ebpf-threat-harvester`)**:
  - **Multi-Plane CO-RE eBPF Capture**: `tc_harvester_ingress` and `tc_harvester_egress` (attached via Linux 6.6+ TCX) capture first-16 signed packet size/microsecond IAT flow sketches, TCP `JA4T` options, TLS SNI, DNS label Shannon entropy, and triggered Tier-1 L7 slices (`4096 B` default), joined in-kernel by `socket_cookie` / `cgroup_id` / `pid` with `tp_harvester_exec` (`sched_process_exec`), `tp_harvester_memfd` (`sys_enter_memfd_create`), and guarded `uprobe_harvester_ssl_write` (`uprobe/SSL_write`).
  - **Two-Tier Adaptive Flight Recorder & Firehose Modes**: Configurable `adaptive`, `firehose`, and `honeypot_only` modes with canary dark-ports (`23, 2323, 3389, 4444, 5900, 6379, 9200, 27017`), `memfd`/DNS-entropy escalation, stratified benign negative sampling, and a ring-buffer backpressure circuit breaker.
  - **Strict Opt-In & Pre-Disk Privacy Guardrails**: Disabled by default (`defaultEnabled: false`), enforces mandatory pre-disk `ScrubThreatPayload` structural secret/token redaction before writing to `/var/lib/axonwall/threat-corpus`, applies prefix-preserving AES-128 Crypto-PAn IPv4/IPv6 + HMAC-SHA256 hostname anonymization on export/ship, and hardcodes control-plane TLS uprobe exclusions (`axonwalld`, `sshd`, `eluvix`, `slapd`, `vault`, `minio`, `k3s`, `containerd`, `systemd`, `postgres`, plus `*` wildcard rejection).
  - **45s Multi-Oracle Correlator, Teacher-LLM Distiller & Dual-Track Dataset Lake**: Joins Gold oracles (dark-port hits, MCP `dnat_honeypot` leases, `lsm_guard` `-EPERM`) and Silver oracles (Suricata `eve.json`, XDP/Vigilante blocks, `memfd_create`, DNS entropy) with an OpenAI-compatible Teacher-LLM annotator, OpenZFS `zstd` + `refquota` spooling (preserving `Pinned` Gold episodes), `.tar.zst` exports (`manifest.json`, ChatML SFT/RLVR `train.jsonl` / `val.jsonl`, Apache Parquet 1.0 `features.parquet`), stdlib AWS SigV4 S3/Vault shipping, `/security/threat-harvester` 4-tab console UI, and `axonwallctl harvester <status|episodes|simulate|export|ship>`.
- **Universal & Hardware-Stripped Hardened Linux 6.12 LTS Kernel Pipeline (`packaging/kernel/`)**:
  - Seven composable Kconfig fragments (`00-universal-hardware-base.config` through `06-strip-desktop-bloat.config`, now including `CONFIG_NET_CLS_ACT`, `CONFIG_NET_SCH_INGRESS`, `CONFIG_UPROBE_EVENTS`, and `CONFIG_FTRACE_SYSCALLS` for TCX/Uprobe harvesting) plus `95-axonwall-kernel-hardening.sysctl.conf` delivering Debian-13-equivalent server/cloud hardware compatibility layered with KSPP memory/slab/stack hardening, `integrity`-mode Lockdown LSM, `BPF_LSM`, `MODULE_SIG` (`sha512`), rootless Kubernetes `USER_NS` + cgroups v2, `# CONFIG_TRIM_UNUSED_KSYMS is not set` + `KALLSYMS=y` (preserving OpenZFS DKMS symbols), `nftables` flowtables + WireGuard, and eBPF CO-RE BTF + `BPF_UNPRIV_DEFAULT_OFF`.
  - Strips desktop bloat (`SOUND`, `DRM`, `WIRELESS`, `WLAN`, `BT`, `MEDIA_SUPPORT`, `INFINIBAND`) and legacy attack surfaces (`KEXEC`, `HIBERNATION`, `DCCP`, `RDS`, `TIPC`) without desktop `linux-hardened` regressions.
  - Reproducible `./packaging/kernel/build-kernel.sh` supporting `--mode universal`, `--mode stripped` (`localmodconfig` + `--march` ISA tuning), and `--mode config-only`; stages offline kernel tooling into `/usr/share/axonwall/kernel-builder/` on unified ISO builds.
- **Interactive Hardware Detection, 25-Check Audit & Custom Kernel Studio**:
  - **Shared Engine (`@axonwall/lib/kernel`)**: Synthesizes deterministic fragments & sysctl drops, infers optimal `-march` (`x86-64-v2`/`v3`/`v4`/`native`), and scores live `/boot/config-*` / `/proc/config.gz` + runtime LSM/sysctl posture against **25 hardened checks** (including `ebpf-tcx-uprobe-harvester`).
  - **Daemon (`axonwalld`)**: `KernelStudioManager` (`/v1/system/kernel/studio`, `/v1/system/kernel/build`, `/v1/system/kernel/install`) inventories live CPU flags, IOMMU, UEFI Secure Boot, TPM 2.0, hardware watchdogs, PCIe/NIC/NVMe hardware, and `lsmod`, compiles `.deb` packages asynchronously, and stages installs safely via cloned **ZFSBootMenu Boot Environments** (`zbm` mode) or side-by-side `dpkg -i` + `update-grub` (`ab` / `rolling`).
  - **Web Console & CLI**: **System → Custom Kernel Studio** (`/system/kernel`), documentation guide (`/docs/custom-kernel`), and `axonwallctl kernel <detect|audit|config>` commands.

---

## `v0.11.71` (2026-11-15) — Arch Linux Parity & Zero-Config Rootless Dev Sandbox

### Highlights
- **Zero-Config Rootless Dev Sandbox (`.axonwall-dev/`)**: Workspace-local runtime state, daemon sockets, and tokens allow running and developing `axonwalld`, `axonwall`, and `axonwallctl` locally without root privileges or host `/etc/axonwall` contamination.
- **Arch & Omarchy Linux Parity**: Added Arch distro detection, service unit aliases, `pacman` package upgrade support, `/proc/config.gz` live kernel configuration fallback in Kernel Studio, Debian-specific network writer guards on non-Debian runtimes, Cloud-Init symlink traversal protections, and CSRF/dev auth cookie hardening.

---

## `v0.11.70` (2026-11-13) — Installer OS/Disk Detection & Reinstall Safety Guards

### Highlights
- **Booted-System & Disk Reinstall Guards**: Automatically hides installer menu entries on already-installed booted systems, detects existing OS installations and OpenZFS pools across candidate target disks, and requires explicit operator confirmation before wiping existing appliance drives.

---

## `v0.11.69` (2026-11-13) — First-Boot Password Recovery & Cross-Edition Credential Guarantees

### Highlights
- **Unprovisioned Password Setter Fix**: Resolved console login glitch loops when booting without a preconfigured admin password and guaranteed deterministic default credential initialization across `axonwall`, `vault`, and `k3s-storage` first-boot workflows.

---

## `v0.11.68` (2026-11-13) — Triple-Edition Live/Install Bootloader Menus

### Highlights
- **Unified 3-Edition Bootloader Menus Across Debian 13 & Alpine ISOs**:
  - Updated Debian 13 (`axonwall-debian13-amd64.iso`) UEFI GRUB, BIOS ISOLINUX, and Alpine (`build-alpine-iso.sh`) UEFI GRUB / BIOS Syslinux menus so operators can boot directly into **Axonwall NGFW (`axonwall`)**, **Axonwall Vault S3 (`vault`)**, or **Barebones K3s + Storage (`k3s-storage`)** from the initial boot screen as well as inside `axonwall-console --install`.
- **CI Preseed & Branding Verification**:
  - Enforced preseed package/service parity checks across both Vault and K3s-Storage Debian installer configs in `.github/workflows/build-iso.yml`.

### Official `v0.11.68` Artifacts & SHA-256 Checksums
| Artifact | Size | SHA-256 |
| :--- | :--- | :--- |
| `axonwall-debian13-amd64.iso` | `1.27 GiB (1,299.2 MB)` | `dda4648fc20ba148b530cc87f55ecfff16329681a1ffb8265304ccfcfb8aa83b` |
| `axonwall-edge-sku-vm-virtio.efi` | `7.1 MB` | `81795473dfafad59db093b5c8d2a20bc1bf8e327e7edb3c6b1bf3ef7205298c9` |
| `axonwall-edge-sku-vm-virtio-initramfs.cpio.gz` | `3.6 MB` | `cfe81c1cd175a41ecf2dbb4c156c702aa95508cf8d9121c39d69ce780c35d7ba` |
| `axonwall-debian13-amd64-cloud.qcow2` | `1.17 GiB (1,194.9 MB)` | `10c4ec26051bfe130afe13be4a4a2c644f364c3167e5e2643f14bf596b359415` |
| `axonwall_0.11.68_amd64.deb` | `142.3 MB` | `17c8040dabf10dd716447c09a0ecbc61b5d2b6b0a0339a8a73bd940a0e19cfe9` |

---

## `v0.11.66 – v0.11.67` (2026-11-11 – 2026-11-12) — Barebones K3s + Storage Profile (`k3s-storage`)

### Highlights
- **Dedicated Barebones K3s + OpenZFS/OpenEBS Host Profile (`packaging/k3s-storage/`)**:
  - New `k3s-storage` edition enables `core-k3s` and `core-nas` in headless host mode (`core-firewall=false`), strips NGFW/Suricata/Samba/NFS overhead, pre-stages OpenEBS ZFS-LocalPV (`zfs-operator.yaml`), and reconciles `k3s`/`k3s-agent` roles cleanly via `axonwall-k3s-firstboot`, `axonwall-k3s-verify`, and `axonwall-k3s-status`.
  - Integrated into the 5-step `axonwall-console --install` TUI wizard, Debian `preseed-k3s-storage*.cfg` manifests, Alpine OpenRC firstboot (`axonwall-firstboot-alpine`), Cloud-Init seed synthesis, and `@axonwall/lib` K3s/VOW compilers.

---

## `v0.11.64 – v0.11.65` (2026-11-10 – 2026-11-11) — `BPF_TOKEN_CREATE`, Dual-Stack XDP, 25-Tool MCP & 9-Vendor Migration

### Highlights
- **Linux 6.9+ `BPF_TOKEN_CREATE` Unprivileged UserNS Delegation & 5-Hook CO-RE BPF-LSM Mediator**: Added `lsm/bpf_token_create` and `lsm/bpf_token_cmd` hooks plus `/run/axonwall/bpffs-tokens/<profile>` mounts so rootless K3s (`hostUsers: false`) and unprivileged LXC containers can load verified XDP/TC/Socket eBPF while blocking `kprobe`/`tracepoint`/`lsm` kernel memory reads.
- **Dual-Stack IPv4/IPv6 + 802.1Q/802.1ad QinQ VLAN, LPM CIDR & TCP SYN-Flood XDP Engine**: Ring-0 `XDP_DROP` blocklists, per-source SYN-flood PPS rate limiting, and full `axonwallctl ebpf` CLI telemetry.
- **25-Tool MCP Security Server & 9-Vendor Unified Migration Studio**: Expanded `axonwall-mcp` to 16 capability scopes, 16 read-only resources, and 25 guardrailed tools; added Proxmox VE 8.x and TrueNAS SCALE non-destructive migration importers alongside pfSense, OPNsense, Cisco IOS/ASA/FTD, VyOS, MikroTik, `iptables`, and `firewalld`.
- **Coroot-Grade eBPF APM & Cross-Duty Telemetry (`coroot-ebpf-apm`)**: Zero-instrumentation L7 service maps, TLS uprobes, 99 Hz FlameGraphs, OpenZFS SPL kstat ARC/L2ARC/ZIL telemetry, KVM `vnet`/`tap` counters, and Etckeeper `/system/etckeeper` Git diff inspection.

---

## `v0.11.62` (2026-11-08) — CO-RE BPF-LSM Exploit Guard & Restricted Operator Shell

- Ring-0 `lsm/socket_bind` block against **Copy Fail (CVE-2026-31431)** `AF_ALG` crypto socket heap overflows, paired with `lsm/bpf` and `lsm/uring_sqpoll` inode-keyed enforcement.
- Introduced `axonwall-opshell` restricted operator shell and custom Operator-CA certificate preservation across upgrades and HA sync.

---

## `v0.11.58` (2026-11-05) — Cloud QCOW2 Slot-B Sync, K3s Workstation & OpenLDAP Federation

- First-boot background Slot-B sync on `axonwall-debian13-amd64-cloud.qcow2` for full A/B Dual-Root rollback parity in KVM/Proxmox/cloud VMs.
- Zero-touch OpenLDAP RBAC federation across K3s, Vigilant Octo Waffle (VOW), Vigilante SOC, Eluvix AI Router, and FreeRADIUS; bundled `kubectl` & `helm` v3 and `axonwallctl cloudinit export --iso`.

---

## `v0.11.52` (2026-10-31) — Pure ZFSBootMenu v3.1.0 UEFI & Boot Palettes

- Replaced GRUB-on-ZFS chains with direct UEFI **ZFSBootMenu (`v3.1.0`)** EFISTUB booting, mirrored ESP sync, `axonwallctl zbm` snapshot/clone/activate CLI, and five pre-boot tactical ANSI themes (`axonwall-zbm-theme`).

---

## `v0.11.42` (2026-10-25) — Unified Installer, LUKS2 + TPM 2.0 & MCP Tactical Leases

- Unified Standard NGFW & Vault S3 editions inside `axonwall-debian13-amd64.iso` with Smart NVMe/SSD/HDD tiering and **LUKS2 + TPM 2.0 (`PCR 0+2+7`)** auto-unlock.
- Guardrailed `axonwall-mcp` engine behind a disabled-by-default kill switch, blast-radius validators, and auto-expiring TTL leases in isolated `table inet axonwall_mcp`.

---

## `v0.11.32` (2026-10-20) — Super-Slim Edge UKI & Canonical Repository

- **7.1 MB Zero-Shell Edge NGFW (`.efi` UEFI UKI)**: Static Go PID 1 (`axonwall-satellite`) on Linux 6.12 LTS (`CONFIG_MODULES=n`), pure-Go Cloud-Init, Dual-Stack IPv6 (`IA_NA`/`IA_PD` + `RA`), and Active-Standby hardware watchdog HA.
- Unified repository, Go module paths, and OTA updater endpoints under `github.com/axonwall/axonwall`.
