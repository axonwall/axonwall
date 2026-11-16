# Axonwall Release Notes

All notable changes across **Axonwall** appliance editions (`axonwall` Converged NGFW, `vault` Immutable S3 Backup, and `k3s-storage` Barebones K3s + OpenZFS/OpenEBS), kernel pipelines, Ring-0 eBPF subsystems, and management consoles are documented in this file.

Official build artifacts, SHA-256 checksums, and detached Ed25519 signatures (`.sha256.sig`) are published on [GitHub Releases](https://github.com/axonwall/axonwall/releases) and the [Axonwall Releases Portal](https://axonwall.com/releases).

---

## Unreleased (`main`) — Axonwall Blackbox Threat-LLM Harvester & Custom Hardened Linux 6.12 LTS Kernels

### Highlights
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
