<div align="center">

# 🛡️ Axonwall

### The Modern Linux Router & Next-Generation Firewall (NGFW)

*Reimagining open-source perimeter security: from FreeBSD `pf` & legacy PHP to **Linux `nftables`**, **Next.js**, **Go**, and **Autonomous AI**.*

[![License](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/Kernel-Linux_6.12+_LTS-orange.svg)](https://www.kernel.org/)
[![Engine](https://img.shields.io/badge/Firewall-nftables_1.1+-red.svg)](https://netfilter.org/projects/nftables/)
[![Frontend](https://img.shields.io/badge/Console-Next.js_16_React_19-black.svg)](https://nextjs.org/)
[![Controller](https://img.shields.io/badge/Control_Plane-Go_1.24-00ADD8.svg)](https://golang.org/)
[![Appliance](https://img.shields.io/badge/Appliance-Debian_13_Trixie-A80030.svg)](https://www.debian.org/)

[Website](https://axonwall.com) • [Documentation](https://axonwall.com/docs) • [2-Host HA Setup Guide](docs/HIGH_AVAILABILITY_SETUP.md) • [Business Plan](business-plan.md) • [Architecture](https://axonwall.com/architecture) • [Appliance ISOs](#installation--quickstart)

</div>

---

## ⚡ The Problem: The FreeBSD Stagnation

For more than two decades, the open-source firewall ecosystem has relied on FreeBSD foundations (**m0n0wall**, **pfSense®**, and **OPNsense®**). While these platforms pioneered community network security, their historical stack presents compounding architectural liabilities in modern environments:

* **Single-Threaded Locking:** Under heavy connection state loads and NAT traversal, FreeBSD `pf` exhibits severe CPU core contention.
* **Driver & Hardware Lag:** Modern Wi-Fi 6E/7 chipsets, 5G cellular modems, and multi-queue 10G/25G/100G NICs (Intel E810, Mellanox ConnectX) receive day-one support in Linux, but often lag by years or remain completely unsupported in BSD.
* **Legacy PHP Web Tiers:** Traditional firewalls rely on server-side PHP scripts that execute raw system commands, creating state synchronization hazards, sluggish reloads, and administrative lockouts.
* **Administrator Lockout Panic:** Applying an invalid firewall rule or gateway change can immediately cut off your SSH/web session, requiring serial console intervention.
* **Zero Container Coexistence:** FreeBSD cannot run natively inside Docker, Kubernetes, or Linux network namespaces.

---

## 🚀 The Solution: Axonwall

**Axonwall** is a ground-up modernization of the open-source firewall. It pairs the raw line-rate performance and hardware compatibility of the modern Linux networking subsystem with a cloud-native, transaction-safe control plane.

```
                           ┌──────────────────────────────────────────────┐
                           │      Axonwall Modern React/Next.js Console   │
                           │   (OpenLDAP Auth + Supabase Configuration)   │
                           └──────────────────────┬───────────────────────┘
                                                  │ Intent-Driven State (JSON)
                                                  ▼
                           ┌──────────────────────────────────────────────┐
                           │        Privileged Go Control Plane           │
                           │      (Validation, Linting, & Commit-Confirm) │
                           └──────────────────────┬───────────────────────┘
                                                  │
                ┌─────────────────────────────────┼─────────────────────────────────┐
                ▼                                 ▼                                 ▼
   ┌───────────────────────────┐    ┌───────────────────────────┐    ┌───────────────────────────┐
   │     Linux nftables        │    │    Embedded Observability │    │   Distributed Satellites  │
   │ Atomic `table inet axonwall`│   │   VictoriaMetrics & Logs  │    │  OpenWrt & Linux SD-Branch│
   │ WireGuard, Kea, FRR, IDS  │    │   Insight Flow Analytics  │    │  WireGuard Mesh & Edge FW │
   └───────────────────────────┘    └───────────────────────────┘    └───────────────────────────┘
```

### Key Architectural Pillars

* **🔒 Junos-Style Commit-Confirm Rollback:** Apply changes with an automated rollback timer (e.g. 60 seconds). If you do not confirm connectivity, Axonwall atomically reverts to the previous working ruleset. Zero lockout risk.
* **⚡ Pure `nftables` Engine:** Compiles high-level firewall policies directly into atomic `table inet axonwall` rulesets. Never wipes or interferes with Docker (`table ip filter`) or Kubernetes CNI (`table ip nat`) chains.
* **🧠 Built-in AI Security Copilot:** Native multi-provider AI engine supporting **Google Antigravity**, **Ollama**, **Claude Code**, **OpenAI Codex**, and **vLLM**. Drafts complex policies in plain English, analyzes Suricata/VictoriaLogs security events, and executes one-click automated threat containment.
* **📡 SD-Branch Satellite Architecture:** Manage low-cost branch routers, Wi-Fi access points, and remote IoT gateways (**OpenWrt**, Raspberry Pi, Debian) through lightweight cross-compiled Go agents (`axonwall-satellite`) over encrypted WireGuard mesh.
* **📊 Modern Observability (VictoriaMetrics + VictoriaLogs):** High-efficiency time-series metrics and log aggregation built right into the platform, replacing slow legacy RRDtool graphs with real-time insight analytics.

---

## 🎯 Feature Parity Matrix

Axonwall matches OPNsense across all core firewall, networking, and security features while upgrading each to modern Linux standards:

| Capability | Legacy OPNsense / pfSense | Axonwall Modern Linux |
|---|---|---|
| **Packet Filter** | FreeBSD `pf` (single-threaded state lock) | **Linux `nftables`** (wire-speed multi-core scaling) |
| **Configuration Safety** | Instant apply (high lockout risk) | **Junos-style Commit-Confirm & Auto-Rollback** |
| **Web Console** | Legacy PHP 8 server-rendered scripts | **Next.js 16 + React 19 + Tailwind CSS** |
| **Authentication** | Local DB / PHP PAM scripts | **OpenLDAP, RADIUS, & Supabase Row-Level Security** |
| **Dynamic Routing** | FRR package on FreeBSD | **Linux FRR (BGP, OSPF, BFD, ECMP)** |
| **VPN Technologies** | OpenVPN, IPsec (strongSwan), WireGuard (kmod) | **Native Linux WireGuard, strongSwan, OpenVPN (DCO)** |
| **IDS / IPS** | Suricata via FreeBSD Netmap | **Suricata 7+ via AF_PACKET & eBPF/XDP** |
| **DDoS Protection** | Basic pf synproxy | **XDP Line-Rate Drop + CrowdSec IPS Bouncer** |
| **DHCP & DNS** | ISC DHCP (EOL) / Dnsmasq / Unbound | **Kea DHCPv4/v6 + Unbound DNS Sinkhole (RPZ)** |
| **High Availability** | CARP + pfsync (multicast required) | **Keepalived (VRRP) + conntrackd FTFW + mTLS SQLite/ZFS Sync ([2-Host Setup Guide](docs/HIGH_AVAILABILITY_SETUP.md))** |
| **Traffic Shaper / QoS** | FreeBSD ALTQ / dummynet | **Linux CAKE, FQ_CoDel, & HTB Traffic Control (tc)** |
| **Diagnostics** | Packet capture (pcap dump) | **Interactive eBPF Packet Tracer & Live NetFlow** |
| **AI Copilot** | None | **Native Antigravity, Ollama, Claude, Codex, vLLM** |
| **Edge Satellites** | None (centralized box only) | **OpenWrt & Linux SD-Branch agent fleet manager** |

---

## 📦 Monorepo Structure

Axonwall is engineered as an enterprise-grade Turborepo monorepo:

```
axonwall_monorepo/
├── apps/
│   ├── axonwall/             # Next.js 16 reactive web console & API gateway
│   ├── axonwall-controller/  # TypeScript/Node control plane & fleet WebSocket hub
│   ├── axonwalld/            # Privileged Go daemon managing nftables, netlink, & IP routing
│   └── axonwall-satellite/   # Lightweight Go agent cross-compiled for OpenWrt & edge Linux
├── packages/
│   └── axonwall_lib/         # Universal TypeScript engine: schemas, compiler, linter, & AI
├── packaging/
│   ├── debian/               # Debian 13 systemd service units & packaging control
│   └── iso/                  # Live-build automated appliance ISO generator
├── axonwall.com/              # Public documentation & marketing site (Next.js static)
├── business-plan.md          # Commercial go-to-market and appliance sales strategy
├── LICENSE                   # Apache License, Version 2.0
└── TRADEMARKS.md             # Axonwall trademark and branding guidelines
```

---

## 🛠️ Installation & Quickstart

Axonwall can be deployed on bare metal, inside virtual machines (Proxmox, VMware ESXi, KVM), or run as a standalone developer stack.

### Option 1: Turnkey Debian 13 Appliance ISO

Download our hybrid bootable ISO image (supporting both UEFI and BIOS) for automated zero-touch installation:

```bash
# Automated build via GitHub Actions or local live-build:
sudo ./packaging/iso/build-iso.sh
```

1. Flash the generated `axonwall-debian13-amd64.iso` to a USB drive using BalenaEtcher or `dd`:
   ```bash
   sudo dd if=axonwall-debian13-amd64.iso of=/dev/sdX bs=4M status=progress
   ```
2. Boot your appliance. The automated installer partitions the drive, tunes sysctl forwarding parameters, and installs baseline security services.
3. Connect your laptop to the designated LAN port (`eth1`) and access the web console:
   ```
   https://192.168.1.1:3000
   Default credentials: admin / axonwall
   ```

### Option 2: Local Developer Monorepo Setup

To run the development console and control plane on an existing Linux workstation:

```bash
# 1. Clone the repository
git clone https://github.com/axonwall/axonwall_monorepo.git
cd axonwall_monorepo

# 2. Install dependencies via pnpm
pnpm install

# 3. Run the unit test suite
pnpm test

# 4. Start the development server
pnpm dev
```

The Next.js management console will be available at `http://localhost:3000`.

### Option 3: Compile Axonwall Satellite for Edge Routers

To compile the lightweight satellite companion for OpenWrt or edge Linux devices:

```bash
cd apps/axonwall-satellite

# Cross-compiles for amd64, arm64 (Raspberry Pi), and mipsle (OpenWrt routers)
make all

# Deploy binary to remote OpenWrt router:
scp bin/axonwall-satellite-mipsle root@192.168.8.1:/usr/bin/axonwall-satellite
```

Start the satellite with Zero-Touch Provisioning (ZTP):
```bash
axonwall-satellite \
  -core wss://firewall.yourcorp.com:2966/ws/satellite \
  -id sat-branch-01 \
  -token ztp_sec_token_here
```

---

## 🤖 AI Copilot Capabilities

Axonwall includes an integrated AI Copilot with plug-and-play support for five major engines:

1. **Google Antigravity (Gemini 2.5 Pro):** Cloud-scale reasoning with extended thinking budget for deep security audits and compliance verification.
2. **Ollama (Llama 3.3):** 100% offline, privacy-guaranteed local inference running directly on your firewall hardware.
3. **Claude Code (Claude 3.7 Sonnet):** Advanced threat correlation and forensic rule synthesis.
4. **OpenAI Codex / GPT-4o:** Fast natural language policy drafting.
5. **vLLM (Self-Hosted):** High-throughput private inference for MSPs and multi-tenant fleets.

### Example Prompts:
* *"Isolate the IoT VLAN (30) from the Corporate LAN (10) but allow bidirectional streaming to the Apple TV on 10.0.10.50:7000."*
* *"Explain this Suricata CVE-2024-XXXX alert from VictoriaLogs and generate an atomic drop rule with a 2-hour TTL."*
* *"Audit my active port forwarding rules against PCI-DSS 4.0 requirement 1.3."*

---

## 💼 Business & Commercial Model

Axonwall adapts and scales the proven **Deciso / OPNsense** commercial flywheel:

* **100% Open Source Community Core:** Free forever under the GNU General Public License v2 (GPL-2.0-or-later).
* **Turnkey Hardware Appliances:** Pre-burned, factory-certified fanless and 1U rackmount appliances with 45–55% hardware gross margins.
* **Business Edition Subscriptions:** Hardened quarterly release channels, regression test certification, and enterprise SLAs.
* **Commercial Threat Intelligence:** Turnkey integrations with Proofpoint ET Pro, MaxMind GeoIP2, and CrowdSec Enterprise.
* **Fleet Central (SaaS):** Multi-tenant cloud controller for MSPs managing hundreds of customer firewalls from a single pane of glass.

For complete commercial details, financial projections, and go-to-market strategy, read the full [Axonwall Business Plan](business-plan.md).

---

## 🤝 Contributing

We welcome contributions from network engineers, security researchers, and developers!

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/my-new-feature`).
3. Ensure all tests pass (`pnpm test`).
4. Commit your changes (`git commit -m 'feat: add support for BBRv3 congestion control'`).
5. Push to your branch (`git push origin feature/my-new-feature`).
6. Open a Pull Request.

*Axonwall requires no Contributor License Agreement (CLA); all contributions are licensed under the GNU General Public License v2 (GPL-2.0).*

---

## 📄 License & Trademarks

* **Source Code:** Licensed under the [GNU General Public License, Version 2 (GPL-2.0)](LICENSE).
* **Trademarks:** The name **Axonwall**, logo, and brand assets are protected trademarks. Review our [Trademark Policy](TRADEMARKS.md) for guidelines on acceptable usage, forks, and commercial hardware distribution.

---

<div align="center">
<sub>Engineered with precision for the modern Internet. Powered by Linux, nftables, and Open Source.</sub>
</div>
