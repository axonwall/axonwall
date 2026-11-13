<div align="center">

# 🛡️ Axonwall (`v0.11.68`)

### The Sovereign Linux Next-Generation Firewall, OpenZFS NAS, Hypervisor & Autonomous AI SecOps Platform

*Reimagining perimeter & infrastructure security: from legacy FreeBSD `pf` & PHP to **Linux 6.12+ LTS `nftables`**, **Hardened KSPP Universal & Hardware-Locked Kernels**, **Zero-Shell UEFI UKIs**, **Post-Quantum Dual-KEM**, **CO-RE BPF-LSM**, **OpenZFS**, **K3s**, **KVM/LXC**, and **Guardrailed MCP AI**.*

[![Release](https://img.shields.io/badge/Release-v0.11.68-10b981.svg)](https://github.com/axonwall/axonwall/releases/tag/v0.11.68)
[![License](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/Kernel-Linux_6.12+_LTS-orange.svg)](https://www.kernel.org/)
[![Engine](https://img.shields.io/badge/Firewall-nftables_1.1+%20%26%20eBPF%2FXDP-red.svg)](https://netfilter.org/projects/nftables/)
[![Frontend](https://img.shields.io/badge/Console-Next.js_16_React_19-black.svg)](https://nextjs.org/)
[![Control Plane](https://img.shields.io/badge/Daemon-Go_1.26+%20%26%20TypeScript-00ADD8.svg)](https://golang.org/)
[![Appliance](https://img.shields.io/badge/Appliance-Debian_13_Trixie_%7C_ZFSBootMenu_v3.1-A80030.svg)](https://www.debian.org/)

[Website](https://axonwall.com) • [Documentation (25 Guides)](https://axonwall.com/docs) • [Releases & Checksums](https://axonwall.com/releases) • [Release Notes](RELEASE_NOTES.md) • [2-Host HA Setup Guide](docs/HIGH_AVAILABILITY_SETUP.md) • [Terraform Provider](apps/terraform-provider-axonwall/README.md) • [Business Plan](business-plan.md)

</div>

---

## ⚡ Why Axonwall?

For more than two decades, open-source firewalls relied on FreeBSD (`m0n0wall`, `pfSense®`, `OPNsense®`) and server-rendered PHP scripts. In modern 10G/25G/100G, cloud-native, and AI-assisted environments, that legacy stack creates severe bottlenecks: single-core `pf` state-table contention, multi-year NIC/Wi-Fi 7 driver lag, instant-lockout applies, and zero native container or hypervisor coexistence.

**Axonwall** replaces that legacy stack from the kernel up—unifying **5 modular Core Roles** and **14 first-party Extension Plugins** over a strictly validated, declarative **12-file YAML control plane** (`/etc/axonwall/*.yaml`) with Junos-style **Commit-Confirm** automatic rollback.

```
                   ┌──────────────────────────────────────────────────────────────────┐
                   │   Web Console (:2966) • Neovim TUI • Ink TUI • Terraform • MCP   │
                   └────────────────────────────────┬─────────────────────────────────┘
                                                    │ Declarative /etc/axonwall/*.yaml (Zod + Linter)
                                                    ▼
                   ┌──────────────────────────────────────────────────────────────────┐
                   │         axonwall-controller (TS) + axonwalld (Go Ring-0)         │
                   │   Commit-Confirm Rollback • Etckeeper Git • OpenLDAP + OIDC SSO  │
                   └──────────┬─────────────────────┼─────────────────────┬───────────┘
                              ▼                     ▼                     ▼
               ┌────────────────────────┐ ┌────────────────────┐ ┌────────────────────────┐
               │ Networking & Ring-0    │ │ Converged Compute  │ │ Sovereign AI & SecOps  │
               │ • Atomic nftables      │ │ • OpenZFS NAS/Vault│ │ • Eluvix AI Router/DLP │
               │ • XDP Flow & DDoS Drop │ │ • K3s + OpenEBS HA │ │ • Guardrailed MCP AI   │
               │ • CO-RE BPF-LSM Guard  │ │ • KVM/QEMU + LXC   │ │ • Vigilante 12-Mod SOC │
               │ • Rosenpass PQ-KEM VPN │ │ • Edge UEFI UKI    │ │ • Coroot eBPF APM      │
               └────────────────────────┘ └────────────────────┘ └────────────────────────┘
```

---

## 🧩 Five Modular Core Roles & 19 Built-In Plugins

Run Axonwall as a dedicated zero-bloat perimeter NGFW, disable `core-firewall` to run a pure Host-Mode ZFS Storage Vault or K3s/KVM hypervisor node, or converge all five roles onto a 2-node High Availability bare-metal cluster:

| Core Role ID | Default | Capabilities |
| :--- | :--- | :--- |
| **`core-firewall`** | **Enabled** | Stateful `table inet axonwall` firewall, Dual-Stack IPv4/IPv6 + `802.1Q`/`802.1ad` QinQ VLAN, LPM CIDR & TCP SYN-Flood eBPF XDP fast-drop, SNAT/DNAT/Hairpin/1:1 BINAT/NPTv6, Multi-WAN SD-WAN health prober, FRR (BGP/OSPF/BFD), CAKE/FQ-CoDel QoS, Kea DHCPv4/v6 IA_PD + `radvd` SLAAC, Unbound DNS/RPZ sinkhole, mDNS reflector, UPnP/NAT-PMP, Suricata 7+ IDS/IPS, CrowdSec, WireGuard, strongSwan IKEv2, OpenVPN `ovpn-dco`, Keepalived + `conntrackd` HA |
| **`core-nas`** | Opt-in | OpenZFS Stripe/Mirror/RAIDZ1-3/dRAID pools with Special NVMe VDEVs, SLOG/L2ARC/hot-spares, Checkpoints & NVMe TRIM, `/proc/spl/kstat/zfs` ARC/L2ARC/ZIL SPL kstat telemetry, Native AES-256-GCM encrypted datasets & ZVOLs, Samba SMB3 + VSS shadow copies + Time Machine mDNS + WSDD2, NFSv4, iSCSI targets, S.M.A.R.T. tests, `rclone` Cloud Sync, SeaweedFS S3 WORM Vault, and incremental HA `zfs send/recv` |
| **`core-k3s`** | Opt-in | Embedded single-node or 2-node HA K3s Kubernetes with selectable **Cilium eBPF CNI (`kubeProxyReplacement` + Hubble)** or WireGuard Flannel mesh, Embedded Etcd local & S3 snapshots/restore, Linux 6.9+ `UserNamespacesSupport` (`hostUsers: false`) + `BPF_TOKEN` Pod/DaemonSet profiles, OpenEBS ZFS-LocalPV & replicated Mayastor NVMe-oF storage, bundled `kubectl` & `helm` v3, and non-root `axonwall-kubeconfig --vip` sync |
| **`core-virt`** | Opt-in | Type-1 KVM/QEMU hypervisor (OVMF UEFI, Secure Boot, `swtpm` TPM 2.0, VirtioFS ZFS directory shares, CPU pinning/NUMA/Hugepages, ZFS zero-copy linked clones, QMP + ZFS live migration, canonical Libvirt Domain XML compiler, per-VM `nftables` security groups, HTML5 `noVNC` console), unprivileged LXC containers with Linux 6.9+ `BPF_TOKEN` delegation, PCIe VFIO & SR-IOV passthrough, VXLAN SDN, Hosted Virtual Edge UKI, and ZFS/S3/PBS backups |
| **`core-vigilante`** | Opt-in | Autonomous Cyber Defense & SOAR (`vigilante-soc` on K3s): 12 modular security stacks (VigilSOC, OpenSearch, Wazuh, Falco, Zeek, BloodHound, OpenVAS, kCTF, etc.), priority `-10` kernel nftables SOAR auto-containment, ransomware entropy freeze, honeytoken deception mesh, Merkle-chained ZFS forensic vault, and 106-tool Vigilante MCP |

### Built-In Extension Plugins (14)
- **Default Enabled (3):** `cli-workstation` (Zsh, Neovim `axonwall-config`, Starship, Tmux, `kubectl`, `helm`), `host-malware-rootkit` (8-engine host malware/rootkit hunter + 5-hook CO-RE BPF-LSM & `BPF_TOKEN` Ring-0 mediator), `coroot-ebpf-apm` (zero-instrumentation eBPF L7 service map, TLS uprobes, 99 Hz FlameGraphs & automated RCA).
- **Opt-In Extensions (11):** `rosenpass` (Hybrid Classic McEliece 460896 + ML-KEM-512 post-quantum WireGuard PSK rotation), `eluvix` (Sovereign AI Model Router, Tokenomics, PromptGuard & reversible PII DLP), `vigilant-octo-waffle` (ArgoCD/Flux K3s GitOps PaaS), `headscale`, `tailscale`, `haproxy`, `freeradius`, `snmp`, `nut-ups`, `ntopng`, `cli-diagnostics-nastymap`.

---

## 🔒 Signature Security & Engineering Highlights

- **Universal & Hardware-Stripped Hardened Linux 6.12 LTS Kernels (`/system/kernel` & `axonwallctl kernel`):** Reproducible 7-fragment KSPP kernel pipeline (`packaging/kernel/`) tuned specifically for `k3s` rootless `USER_NS` + cgroups v2, OpenZFS DKMS symbol preservation (`CONFIG_TRIM_UNUSED_KSYMS=n`), `nftables` flowtable fastpath, and eBPF CO-RE BTF with `integrity` Lockdown LSM—plus an interactive **Custom Kernel Studio** (`/system/kernel`) that audits live host hardware against 24 checks, compiles minimal `localmodconfig` kernels, and stages installs safely via ZFS Boot Environments or side-by-side GRUB entries.
- **Triple-Edition Unified Bare-Metal ISO (`axonwall`, `vault`, & `k3s-storage`):** Select **Standard NGFW**, **Immutable S3 Vault**, or **Barebones K3s + OpenZFS/OpenEBS Storage Host** directly from the Debian 13 & Alpine UEFI/BIOS bootloader menus or the 5-step `axonwall-console --install` wizard.
- **Super-Slim Zero-Shell Edge NGFW (`.efi` UEFI UKI):** 7.1 MB single-file Unified Kernel Image running static `axonwall-satellite` directly as **PID 1 (`/init`)** on Linux 6.12 LTS with **zero `/bin/sh`, zero coreutils, zero SSHD**, and `CONFIG_MODULES=n`.
- **5-Hook CO-RE BPF-LSM Guard & Linux 6.9+ `BPF_TOKEN_CREATE` Mediator:** Five kernel LSM hooks (`lsm/socket_bind`, `lsm/bpf`, `lsm/uring_sqpoll`, `lsm/bpf_token_create`, `lsm/bpf_token_cmd`) keyed by unspoofable `(s_dev, i_ino)` kernel inodes block **Copy Fail (CVE-2026-31431)** `AF_ALG` heap overflows, unauthorized `BPF_PROG_LOAD`, and `io_uring` `SQPOLL` syscall-less implants ("Ghost in the Ring"), while delegating verified networking eBPF (`XDP`, `SCHED_CLS`, `CGROUP_SKB`) to unprivileged UserNS containers and blocking Ring-0 `bpf_probe_read_kernel()` tracing types (`kprobe`, `tracepoint`, `lsm`).
- **Guardrailed 25-Tool MCP Security AI Server (`axonwall-mcp`):** **Disabled by default** behind a master kill-switch; enforces SHA-256 `axw_mcp_*` bearer keys, mTLS cert pinning, **16 granular capability scopes, 16 read-only MCP resources, and 25 guardrailed MCP tools** across Firewall, Ring-0 eBPF & `BPF_TOKEN_CREATE`, KVM/Libvirt/LXC, K3s Etcd, OpenZFS NAS, and 9-Vendor Migration—backed by dual TS+Go blast-radius & anti-lockout guards, isolated TTL-bounded tactical leases (`table inet axonwall_mcp`), mandatory Commit-Confirm on DesiredState proposals, and a SHA-256 hash-chained audit trail (`mcp-audit.jsonl`).
- **Unbrickable Boot Architectures:** Choose at install time between **ZFSBootMenu (`v3.1.0`) Root-on-ZFS** (`axonwallctl zbm` snapshot/clone/activate + 5 boot palettes), **Dual-Root A/B Slots** (`axon_root_a` / `axon_root_b` with hardware watchdog fallback), or **Rolling Single-Root**, with optional **LUKS2 + TPM 2.0 (`PCR 0+2+7`)** auto-unlock.
- **6-Plane 2-Host High Availability:** Synchronizes Keepalived VRRP VIPs, `conntrackd` FTFW state, mTLS ECDSA P-256 DesiredState & Kea DHCP leases, OpenLDAP multi-provider `syncrepl` (`ldaps:636`) + hot SQLite snapshots, incremental ZFS `send/recv`, and 2-node K3s + OpenEBS replicated volumes.
- **Unified Identity & Audit:** Zero-touch embedded OpenLDAP (`slapd` + `sssd`) with automatic plugin service-account provisioning, hardened `axonwall-opshell` for operators, Enterprise OIDC/Entra/Okta/Google SSO, GitOps bundle revisions, and **Etckeeper** `/etc` Git history & unified diffs.
- **9-Vendor Unified Appliance Migration Studio:** Deterministic import, rule-shadowing mathematical analysis, subnet collision detection, and non-destructive multi-appliance merge from **pfSense XML**, **OPNsense XML**, **Proxmox VE 8.x**, **TrueNAS SCALE**, **Cisco IOS/ASA/FTD**, **VyOS**, **MikroTik RouterOS**, **`iptables-save`**, and **`firewalld`**.

---

## 🗂️ Declarative Configuration (`/etc/axonwall/*.yaml`)

Every subsystem compiles deterministically from 12 human-readable, Git-friendly YAML files (editable via the Web Console, `axonwall-config` 4-pane Neovim IDE, `axonwall-tui`, or `terraform-provider-axonwall`):

| File | Managed Top-Level Keys |
| :--- | :--- |
| `system.yaml` | `version`, `capabilities`, `system`, `plugins`, `ai`, `eluvix`, `observability`, `snmp`, `ups`, `acme` |
| `interfaces.yaml` | `interfaces`, `vlans`, `bridges`, `bonds`, `virtualIps`, `vrfs` |
| `firewall.yaml` | `aliases`, `rules`, `nat`, `trafficShaper` |
| `routing.yaml` | `gateways`, `gatewayGroups`, `routes`, `frr` |
| `services.yaml` | `dhcp`, `dns`, `captivePortal`, `haproxy`, `freeradius` |
| `vpn.yaml` | `wireguard`, `rosenpass`, `ipsec`, `openvpn`, `headscale` |
| `security.yaml` | `suricata`, `crowdsec`, `geoip`, `zeroTrust`, `sso`, `tlsDecryption`, `hostDefense` |
| `ha.yaml` | `ha`, `fleet` |
| `storage.yaml` | `nas` (pools, datasets, snapshots, SMB, NFS, iSCSI, S3) |
| `k3s.yaml` | `k3s`, `vow` |
| `virt.yaml` | `virt`, `hostedEdge` |
| `vigilante.yaml` | `vigilante` |

---

## 📦 Monorepo Structure

```text
axonwall/
├── apps/
│   ├── axonwall/                     # Next.js 16 + React 19 Web Console & OpenAPI v3.1 gateway (:2966)
│   ├── axonwall-controller/          # TypeScript control plane, axonwallctl, axonwall-tui (Ink), & axonwall-mcp
│   ├── axonwalld/                    # Privileged Go 1.26 daemon, eBPF/XDP/BPF-LSM, HA mTLS, ZFS, K3s, KVM/LXC, OpenLDAP
│   ├── axonwall-console/             # Physical/serial console menu & 5-step BubbleTea bare-metal/Vault installer
│   ├── axonwall-satellite/           # Cross-compiled Go SD-Branch agent & PID-1 Edge NGFW UKI engine
│   └── terraform-provider-axonwall/  # Official Terraform / OpenTofu provider (DesiredState & Cloud-Init)
├── packages/
│   ├── axonwall_lib/                 # Universal TS schemas (Zod), nftables/service compilers, 7x importers, linter
│   ├── nastymap/                     # Interactive Nmap XML topology, GeoIP world map & scan diff engine (v1.0.2)
│   └── vigilante_lib/                # Vigilante Cyber Defense charts, SOAR playbooks, & 106-tool SOC MCP server
├── packaging/
│   ├── iso/                          # Debian 13 Trixie live-build unified NGFW, Vault & K3s-Storage ISO + ZBM pipeline
│   ├── kernel/                       # Universal KSPP + k3s + ZFS + nftables + eBPF kernel pipeline & localmodconfig builder
│   ├── k3s-storage/                  # Barebones K3s + OpenZFS/OpenEBS storage host profile & CSI manifests
│   ├── edge-uki/                     # Linux 6.12 hardened kernel + PID-1 initramfs UEFI UKI (.efi) builder
│   ├── cloud-image/                  # Cloud-Init QCOW2 image builder with Slot-B first-boot sync
│   ├── alpine/                       # Lightweight musl/OpenRC Alpine ISO builder (NGFW, Vault & K3s-Storage)
│   ├── vault/                        # Axonwall Vault Edition immutable SeaweedFS S3 Object-Lock appliance
│   └── debian/                       # Standalone axonwall_<ver>_amd64.deb packager
├── scripts/                          # Operational helpers (release-tagger.sh, update-kubeconfig.sh)
├── docs/                             # Standalone operational guides (HIGH_AVAILABILITY_SETUP.md)
├── RELEASE_NOTES.md                  # Full changelog & SHA-256 build artifact release notes
├── axonwall.com/                     # Public website, releases portal, 25-guide docs & interactive demo
├── LICENSE                           # GNU General Public License v2.0 (GPL-2.0-or-later)
└── TRADEMARKS.md                     # Axonwall trademark & branding guidelines
```

---

## 🛠️ Installation & Quickstart (`v0.11.68`)

### Option 1: Bare-Metal / VM Unified UEFI ISO (`axonwall`, `vault`, or `k3s-storage` Edition)

```bash
wget https://github.com/axonwall/axonwall/releases/download/v0.11.68/axonwall-debian13-amd64.iso
wget https://github.com/axonwall/axonwall/releases/download/v0.11.68/axonwall-debian13-amd64.iso.sha256
sha256sum -c axonwall-debian13-amd64.iso.sha256

# Flash to USB drive:
sudo dd if=axonwall-debian13-amd64.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

1. Boot UEFI media and choose **Axonwall NGFW**, **Axonwall Vault S3**, or **Barebones K3s + Storage**—using **Express 1-Click Install** or the **5-Step Custom Wizard** (`ZFSBootMenu`, `Dual-Root A/B`, or `Rolling`, optional `LUKS2 + TPM 2.0`).
2. Connect to the LAN interface and open the TLS Web Console:
   - **URL:** `https://192.168.1.1:2966`
   - **Default Credentials:** `admin` / `axonwall` (prompted to rotate on first login)
   - **CLI TUIs:** `axonwall-config` (Neovim 4-pane IDE), `axonwall-tui` (11-tab terminal dashboard), `axonwallctl status`, `axonwallctl kernel audit`, `axonwallctl ebpf overview`, `axonwallctl kubeconfig --vip`

### Option 2: Cloud QCOW2 Image, Edge UEFI UKI, or `.deb` Package

- **KVM / Proxmox Cloud Image:** [`axonwall-debian13-amd64-cloud.qcow2`](https://github.com/axonwall/axonwall/releases/download/v0.11.68/axonwall-debian13-amd64-cloud.qcow2)
- **Zero-Shell Edge NGFW UKI (`7.1 MB`):** [`axonwall-edge-sku-vm-virtio.efi`](https://github.com/axonwall/axonwall/releases/download/v0.11.68/axonwall-edge-sku-vm-virtio.efi)
- **Debian 12/13 & Ubuntu 24.04 Package:**
  ```bash
  wget https://github.com/axonwall/axonwall/releases/download/v0.11.68/axonwall_0.11.68_amd64.deb
  sudo apt-get update && sudo apt-get install -y ./axonwall_0.11.68_amd64.deb
  ```

### Option 3: Local Developer Setup

```bash
git clone --recurse-submodules https://github.com/axonwall/axonwall.git
cd axonwall
pnpm install
pnpm test
pnpm dev
```

---

## 📄 License & Trademarks

- **Source Code:** Licensed under the [GNU General Public License v2.0 or later (`GPL-2.0-or-later`)](LICENSE). No Contributor License Agreement (CLA) required.
- **Trademarks:** **Axonwall**, logos, and brand assets are governed by our [Trademark Policy](TRADEMARKS.md).
