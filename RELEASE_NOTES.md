# Axonwall Release Notes

All notable changes across **Axonwall** appliance editions (`axonwall` Converged NGFW, `minimal` Reduced Attack Surface, `vault` Immutable S3 Backup, and `k3s-storage` Barebones K3s + OpenZFS/OpenEBS), kernel pipelines, Ring-0 eBPF subsystems, and management consoles are documented in this file.

Official build artifacts, SHA-256 checksums, and detached RSA-4096 SHA-256 signatures (`.sha256.sig`) are published on [GitHub Releases](https://github.com/axonwall/axonwall/releases) and the [Axonwall Releases Portal](https://axonwall.com/releases).

---

## `v0.16.2` (2026-11-25) — Edge-to-Central-Analytics Observability, Hardened WAN Headscale Invites & Port Knocking, Scoped Service Tokens & K3s Analytics Stack

### Highlights
- **Edge-to-Central Telemetry Offload (`packages/axonwall_lib`, `apps/axonwalld`)**:
  - Added unified `observability.offload` in `system.yaml` alongside decoupled `netflow.mode` (`collector` | `exporter` | `both`) and `netflow.nodeId` in `netflow.yaml`, keeping empty/default edge installs zero-overhead.
  - Added `apps/axonwalld` non-blocking **Prometheus Remote-Write** (`snappy` + protobuf `WriteRequest` + optional `/metrics` scrape endpoint), **VictoriaLogs NDJSON/gzip** shipper (native `NETLINK_NETFILTER` NFLOG listener with token-bucket rate limit guard defaulting to `50/s`, `journald`, Suricata EVE, CrowdSec alerts, Kea DHCP lease logging, and strictly opt-in Unbound query logging), and **bounded RAM ring buffer + opt-in zstd disk spool**.
  - Fixed per-target eBPF/conntrack delta accounting (`selfPrevByTarget`), removed the 50-flow exporter cap (`GetAllFlowCounters(16384)`), added `ingress_ifindex` to `flow_tracker.c` eBPF maps, added IPFIX Enterprise PEN `62999` Options Templates `258`/`259` for remote node identity & interface names, added multi-node `node_id`/`node_name` ClickHouse schema & `node:` FQL filtering, and introduced unprivileged `--mode=collector` (`ModeCollector`) for containerized hub deployments.
  - Added SD-WAN ping RTT/jitter/loss extraction and opt-in `remoteEdgeMitigation` with anti-lockout `protectedCidrs` and bounded XDP block TTLs.
- **Hardened WAN Headscale Invite Access, Auto-Closing `nftables` Window & Optional Port Knocking (`packages/axonwall_lib`, `apps/axonwalld`, `apps/axonwall`)**:
  - Added `headscale.wanInvite` in `vpn.yaml` (`packages/axonwall_lib/src/schemas/index.ts`) and hardened HAProxy path allowlisting (`compileHaProxy`) injecting `fe_headscale_wan_invite` with strict TLS SNI + `Host` enforcement, path-traversal guards (`..`, `%2e`, `%2f`), proxy forwarding-header sanitization, optional Headscale control-plane co-hosting, and `http-request silent-drop` keeping `/login`, `/lobby`, `/vpn`, `/admin`, and `/metrics` unreachable from WAN.
  - Added `HeadscaleWanGateManager` (`apps/axonwalld/engine/headscale_wan_gate.go`) to reconcile the dynamic `headscale_wan_window_ports` `nftables` set automatically against pending unexpired invites (`autoWindow: true`) and manual admin arm/close overrides via `/v1/vpn/headscale/wan-window/{status,sync,arm}` (including a 15s expiry ticker and post-`nft -f` apply/rollback reconciliation), ensuring zero open WAN ports at rest.
  - Added optional kernel-native UDP/TCP stateful `nftables` port knocking (`headscale_knock_s*` → `headscale_knock_allow_v4/v6`), optional `allowedCidrs`, optional scrypt-hashed 6-digit out-of-band verification PINs with 5-attempt auto-revocation, single-page post-redeem CLI/QR onboarding directly on `/invite/[token]`, and WAN Invite & Port Knocking controls on `/vpn/mesh`.
- **Central Analytics Control Plane, Satellite Bridge & 29-Tool MCP (`apps/axonwall`, `apps/axonwall-controller`)**:
  - Added HMAC-free scrypt-hashed **Scoped Service Tokens (`axw_svc_*`)** (`/api/v1/system/service-tokens*`) accepted over Bearer auth in `getSession()`.
  - Added VictoriaMetrics PromQL, VictoriaLogs LogsQL, ClickHouse `netflow_flows`, metadata-sync, node directory, status, and opt-in mitigation APIs plus bounded live observability context in AI Copilot.
  - Bridged satellite `TELEMETRY_REPORT` and `EDGE_FLOW_BATCH` streams to VictoriaMetrics, VictoriaLogs, and `axonwalld`, and expanded `axonwall-mcp` to **18 read-only resources** and **29 guardrailed tools** (`axonwall://observability/{offload-status,nodes}`, `mcp_query_metrics`, `mcp_query_logs`, `mcp_query_historical_flows`, `mcp_trigger_edge_mitigation`).
- **Multi-Node WebUI & K3s/Docker Deployment (`apps/axonwall`, `deploy/`, `packaging/k3s-storage/`)**:
  - Added `/reporting/observability` (Offload Control Center + Service Tokens), `/reporting/logs` (LogsQL Explorer), live VictoriaMetrics charts & node selectors on `/reporting/health` & `/reporting/insight`, multi-node FQL selector in NetFlow Studio, and live `axonwall-controller` telemetry/sync/block wiring on `/fleet`.
  - Added unprivileged multi-arch container images (`Dockerfile.axonwalld`, `Dockerfile.controller`), updated Docker Compose, added the `deploy/k8s/helm/axonwall-analytics` Helm chart targeting `axonwall-zfs-local` (`homelab`/`standard`/`enterprise` profiles), opt-in K3s storage firstboot analytics rules (without `flush ruleset`), and `.github/workflows/containers.yml`.

---

## `v0.16.1` (2026-11-25) — Commit-Confirm, Live Kernel Network Rollback & Systemd IPC Hardening

### Highlights
- **Commit-Confirm & Anti-Lockout Hardening**: Removed localhost `/v1/confirm` auto-confirm bypasses and pre-apply `/etc/axonwall/*` disk writes across Web Console interface assignments, DesiredState apply pipelines, and WireGuard peer registration; added live+static overlapping subnet guards and restricted default gateway emission to WAN.
- **Live Kernel Network Rollback (`apps/axonwalld/net_rollback.go`)**: Added live IPv4/route/link snapshot and rollback with ECMP multipath nexthop restoration, virtual/overlay NIC exclusion (`tailscale*`, `wg*`, `veth*`, `tap*`, `cni*`, `flannel*`, `cilium*`, `br-*`), non-releasing `dhcpcd -x` / rebind, `promote_secondaries=1`, and resilient `executeRollback` even when `last-known-good.nft` is empty or `nft -f` fails.
- **Boot, SD-WAN, Topology & Systemd Reliability**: Fixed `--boot-apply` startup ordering for expired/live pending-confirm bundles, `prober.go` cancellation race before `evaluateFailover()`, `topology.go` premature peer auto-confirm, `getDesiredStateInternal()` read-clobber protection, `controlSystemService` critical-unit stop guards, and `RuntimeDirectoryPreserve=yes` on `axonwalld`/`headscale`/`axonwall-ui` systemd units.

---

## `v0.16.0` (2026-11-24) — Lean Router/NGFW Core, 47-Plugin On-Demand Architecture, Curated Starter Packs & Air-Gapped Plugin Cache

### Highlights
- **Lean Router/NGFW Core Default & Zero-Role `minimal` Edition (`packages/axonwall_lib`, `apps/axonwalld`, `apps/axonwall`, `apps/axonwall-controller`, `packaging/`)**:
  - Standard `axonwall` fresh installs now boot as a **Lean Router/NGFW Core** with **only `core-firewall` enabled by default** (`nftables`, Kea DHCPv4/v6, Unbound DNS + RPZ, WireGuard, ACME, QoS, GeoIP, Aliases, Static & Multi-WAN routing, local POSIX users, `/reporting/{health,flows,insight}`, `/diagnostics`, backups, updates, Services, Plugin Store, and Power).
  - **`axonwall-minimal`** boots as a zero-role hardened control-plane host (`core-firewall` disabled by default; local break-glass/POSIX authentication only without OpenLDAP/SSSD).
- **47 Built-In Plugins (`5` Core Roles + `42` Opt-In Extension Plugins) & 4 Curated Starter Packs**:
  - **On-Demand AI Copilot & Offline Docs**: Added `ai-copilot` (`/ai`) and `docs-portal` (`/docs`, ~1.1 MB RSA-4096 detached SHA-256 signature verified offline tarball bundle built via `scripts/build-docs-bundle.sh` and served via CSP-hardened `/api/docs-bundle`, failing over gracefully to `https://axonwall.com/docs` when uninstalled).
  - **18 New Opt-In Extension Plugins (`defaultEnabled: false`)**:
    - *Package-backed (10)*: `suricata-ids`, `crowdsec-bouncer`, `frr-routing`, `openvpn`, `ipsec-strongswan`, `directory-ldap`, `custom-kernel-studio`, `high-availability`, `etckeeper-audit`, `packet-diagnostics`.
    - *Control-plane / software-only (8)*: `captive-portal`, `tls-decryption`, `identity-aware-proxy`, `enterprise-sso`, `firewall-importer`, `mcp-ai-control`, `fleet-controller`, `web-terminal`.
  - **Flipped Opt-In Defaults (3) & Manifest Parity**: `cli-workstation`, `host-malware-rootkit`, and `coroot-ebpf-apm` (including `/reporting/ebpf`) now default to disabled on fresh installs, backed by automated TS↔Go manifest parity verification.
  - **4 Curated Starter Packs (`PLUGIN_STARTER_PACKS`, `getStarterPackPluginIdsWithDeps`, `/system/plugins`, `axonwallctl plugin pack list|install`)**: `enterprise-ngfw`, `remote-access-vpn`, `operator-diagnostics`, and `ai-observability` across Web UI (with category filter pills & impact/dependency confirmation modal), Ink TUI (`[p]` with input locking & fresh state reload), CLI (`--offline-config-only` opt-out; fails closed without `axonwalld`), bare-metal installers (`[P]` / `/etc/axonwall/starter-packs.seed`), and Cloud-Init (`axonwall.starter_packs`).
- **Air-Gapped Offline Plugin Cache (`scripts/build-plugins-bundle.sh`, `apps/axonwalld/engine/plugins.go`, `axonwallctl`)**:
  - Builds self-contained Debian `.deb` and Alpine `.apk` offline repositories using an isolated empty dpkg `status` file and rich `package`/`provides`/`depends` metadata in `manifest.json`, enforced fail-closed in `axonwalld` (SHA-256 + `os.Lstat` regular-file verification, empty-manifest rejection, selective dependency closure) and `axonwallctl plugin cache-status`.
- **Fail-Closed Control Plane, Safe Uninstall & Local POSIX Identity Fallback**:
  - Added fail-closed plugin checks across `axonwalld` HTTP endpoints & diagnostics, `axonwall-controller` (`mcp-ai-control`, `fleet-controller`, and dormant `headscale` ZTP gating), `getOidcConfig`, and `apps/axonwall` (`<PluginDisabledGate>`, `PluginAwareLink` opt-in defaults, `checkPluginApiGuard`, and `assertPluginEnabled` across 32+ Server Actions), plus DesiredState cleanup on uninstall and a non-blocking batched async `systemctl show` supervisor (`/system/services`).
  - Added `protectedCoreOSPackages` + shared-plugin uninstall protection in `UninstallPlugin`, runtime `ResolveDirectoryBootstrapParams()` OpenLDAP bootstrap wiring, validated `/bin/bash` admin shell fallback, and local POSIX `UserManager` support (`/v1/system/users*`, `/v1/system/groups`) when `directory-ldap` is disabled.
- **Packaging Diet & Automatic Upgrade Preservation (`packaging/`, `apps/axonwalld/engine/plugins_upgrade.go`)**:
  - Removed heavy optional plugin daemons, scanners, CLI tools, OpenLDAP/SSSD, and default `headscale` enablement from base `.deb`/ISO/QCOW2 images while isolating `k3s`/`k9s` pre-staging strictly to `k3s-storage`.
  - Added idempotent boot-time upgrade preservation (`RunUpgradePreservation` with `.plugin-migration-v016-done` marker, legacy `DesiredState` inference, and `state.json` sync) so pre-existing `v0.15.x` appliances automatically keep active features enabled on upgrade.

---

## `v0.15.1` (2026-11-23) — Enterprise NetFlow / IPFIX / sFlow Collector & Analytics Studio (Phases 1–5)

### Highlights
- **Multi-Protocol Flow Collector, Transport Hardening & Replication (`netflow-collector`, `/etc/axonwall/netflow.yaml`, `apps/axonwalld/engine/netflow_*.go`)**:
  - Added full decoding and session management for **NetFlow v5**, **NetFlow v9**, **IPFIX (RFC 7011)** over UDP, TCP, and **TLS 1.3 / optional mTLS**, plus **sFlow v5** sample extraction.
  - Enabled Linux `SO_REUSEPORT` multi-worker socket scaling for high-throughput UDP/IPFIX ingest and a UDP fan-out replicator with optional raw-socket source-IP spoofing (`CAP_NET_RAW`) for downstream SIEM/collectors.
- **Dual-Stack eBPF Self-Exporter & Kernel NPM Telemetry (`netflow_decoders.go`, `netflow_sockdiag.go`)**:
  - Built dual-stack IPFIX self-export emitting **Template 256 (IPv4)** and **Template 257 (IPv6)** with NAT/CGNAT Information Elements (`225`–`228`), VLAN/interface indexes, and kernel TCP NPM metrics sampled via Linux `NETLINK_SOCK_DIAG` (TCP RTT and retransmit counters).
- **Zero-CGO Pure-Go Enrichment Pipeline (`netflow_mmdb.go`, `netflow_enrich.go`)**:
  - Implemented a pure-Go MaxMind `.mmdb` v2 reader with scheduled and on-demand HTTPS GeoLite2/DB-IP updaters (`POST /api/v1/netflow/geoip/update`), live FRR BGP RIB longest-prefix-match (AS-Path / Next-Hop), live K3s Pod/Namespace/Service attribution, Linux `conntrack` NAT/CGNAT mapping, reverse DNS resolution, SNMP `ifAlias` tagging, and Suricata/CrowdSec/Threat-Intel correlation.
- **High-Speed Storage, Multi-Tier Rollups, ClickHouse SQL Pushdown & Prometheus (`netflow_store.go`, `netflow_clickhouse_sql.go`, `netflow_metrics.go`)**:
  - Added persisted `1m` / `5m` / `1h` Zstd rollups with multi-tier historical query merging across `[startMs, endMs]`, parameterized FQL-to-ClickHouse SQL pushdown, and native Prometheus text exposition at `/api/v1/netflow/metrics` (`/v1/netflow/metrics`).
- **Session Stitching, 95th-Pct Reports, Adaptive Baselines & Fleet Federation (`netflow_sessions.go`, `netflow_reports.go`, `netflow_baselines.go`, `netflow_federation.go`)**:
  - Added bidirectional biflow session stitching, Source×Dest & Port×Time heatmaps, and geo arc aggregation.
  - Added **95th/99th-percentile capacity & billing reports** exportable in CSV, Markdown, and JSON with scheduled snapshots (`/api/v1/netflow/reports`).
  - Added **168-slot (7d×24h) EWMA/Z-score baselines** and first-seen peer-pair anomaly detection (`/api/v1/netflow/baselines`), plus multi-host **Fleet Federation** queries across `topology.peers`.
- **Interactive Analytics Studio, API Routes & CLI (`/reporting/netflow`, `axonwallctl netflow`)**:
  - Shipped the 5-tab NetFlow Studio with `FqlInputBar` autocomplete, `FlowExplorerTab` interactive time-brush zoom, bidirectional sessions, `FlowHeatmapsPanel`, offline SVG `GeoTrafficMap`, `ReportsPanel`, `LiveTailTab` (SSE `/api/v1/netflow/stream`), `ExportersTemplatesTab`, `AlertsAnomaliesTab`, and `PipelineConfigTab`, plus 1-click pivots to XDP Drop, Packet Capture (`/diagnostics/packet-capture`), Firewall Alias, and Topology Studio (`/topology`).
  - Added 11 secret-redacted `/api/v1/netflow/*` REST endpoints (`status`, `query`, `stream`, `exporters`, `templates`, `alerts`, `reports`, `baselines`, `geoip/update`, `metrics`, `test-inject`) and `axonwallctl netflow status|query|fleet-query|report` + `axonwall-tui` integration.

---

## `v0.15.0` (2026-11-23) — NetBox v4 DCIM/IPAM, LibreNMS Monitoring & Interactive Topology Studio

### Highlights
- **Interactive Fabric Topology Studio (`topology-studio`, `/topology`, `/etc/axonwall/topology.yaml`)**:
  - Added a browser-native `@xyflow/react` multi-host, WAN, K3s, and cable fabric topology editor (`TopologyStudioWorkspace`) with inspector, path tracer, cable cut sheet, staged diff, scenario manager, and Triad sync drawers, strict Green/Yellow/Red health probes (`/api/v1/topology/probe`), WAN-excluded `lldpd`, and phased transactional apply (`/api/v1/topology/apply`).
- **NetBox v4 DCIM/IPAM & LibreNMS Discovery Triad (`netbox`, `librenms`, `/services/netbox`, `/services/librenms`, `services.yaml`)**:
  - Added turnkey K3s-native deployment and idempotent inventory sync for **NetBox v4** and **LibreNMS** (SNMPv2c/v3, LLDP/CDP/FDB discovery, optical DOM, and alert webhooks) with zero-touch OpenLDAP SSO service accounts (`svc-netbox`, `svc-librenms`), Triad cross-sync (`/api/v1/services/{netbox,librenms}/*`), secret redaction suites, and `14` canonical YAML domains + `27` total plugins (`5` Core Roles + `22` Extensions).

---

## `v0.14.1` (2026-11-22) — Full-Suite K3s Telemetry Visualizations & Explorer Stability Hardening

### Highlights
- **Full-Suite Kubernetes (K3s) Live Telemetry Visualizations (`/k3s/explorer`, `/k3s/cluster`, `/k3s/storage`, `/k3s/workloads`, `/k3s/vow`)**:
  - **Cluster Capacity Rings & Signals (`K3sCapacityRings`)**: Five SVG radial gauges (`CPU`, `Memory`, `Pod Slots`, `Workloads`, `Storage`) with scheduler request inner-rings, overcommit/degraded badges, and a clickable `Cluster Signals` attention strip driven live from `/v1/k3s/pulse`.
  - **Expanded K9s Pulse Charts (`K3sPulseCharts`)**: Added a rolling `Live Cluster Telemetry Trend` area chart, centered pod-health donut overlay, namespace `Pods | Objects` toggle, node `Lim` limit-overcommit bar toggle, `Top Pod Resource Consumers` (`CPU × Mem Scatter`, `Top CPU`, `Top Memory`), and a clickable `Event Reasons` histogram filtering live cluster events.
  - **Barycenter 5-Column Topology & Node Bin-Packing Heatmap (`K3sTopologyMap`, `K3sNodeBinPackingMap`)**: Barycenter-ordered `Ingress → Service → Workload → Pod → Node / PVC` SVG flow map with directional arrowheads, `Issues Only` / `Hide Isolated` / `Fit` controls, click-to-lock trace banner with upstream/downstream hop counts, and per-node chassis pod-heatmap tiles.
  - **Dedicated K3s Page Visualizers**: Added `K3sClusterArchitectureMap` (HA Control Plane & Etcd Quorum SVG, Allocatable/Requested/Usage/Limits chart, Kubelet Conditions & Taints matrix) in `/k3s/cluster`, `K3sStorageVisuals` (`StorageClass` GiB allocation chart, namespace donut, and interactive `PVC → Pod → Node` attachment map) in `/k3s/storage`, `K3sWorkloadsVisuals` (Controller readiness, Namespace footprint, Service/Ingress TLS posture, and `Ingress → Service → Pod` traffic chains) in `/k3s/workloads`, and `K3sVowVisuals` (Cluster RAM headroom bar, Category memory footprint, and resolved app dependency graph) in `/k3s/vow`.
- **K9s Live Explorer Crash Fix & Resilience (`/k3s/explorer`, `apps/axonwalld/engine/k3s_explorer.go`)**:
  - Fixed a client-side `TypeError` crash when Kubernetes API resources without short names serialized `nil` Go slices as JSON `null` in `parseAPIResourcesTable` by initializing `verbs` and `shorts` as empty slices in Go and guarding `Array.isArray(api.shortNames)` in `K9sExplorerWorkbench`.
  - Added a dedicated React error boundary (`apps/axonwall/src/app/(console)/k3s/explorer/error.tsx`) and null-safe telemetry helpers (`apps/axonwall/src/lib/k3s-visuals.ts` with 9 Vitest unit tests in `k3s-visuals.test.ts`).

---

## `v0.14.0` (2026-11-22) — Turnkey Headscale Mesh & Self-Service Portal, Ring-0 eBPF Visualizations, and Appliance Packaging Hardening

### Highlights
- **Turnkey Headscale Mesh Onboarding, Magic Invite Links & User Self-Service Portal (`/vpn/mesh`, `/portal/vpn`, `/invite/[token]`)**:
  - **Magic Invite Links & Turnkey Onboarding**: Administrators can invite users with configurable expiration, device registration quotas, pre-assigned tags, and auto-registration flags. Generates single-use invite tokens with instant QR codes and direct links.
  - **Self-Service VPN Portal (`/portal/vpn`)**: Dedicated end-user interface (`MeshSelfServicePortal`) for non-root users to view active mesh nodes, generate authentication keys (reusable, ephemeral, pre-authenticated), register devices via interactive auth-key commands or machine registration keys, inspect WireGuard configs, and manage their credentials.
  - **Headscale Management Engine (`apps/axonwalld` & `apps/axonwall-controller`)**:
    - Native `headscale` configuration reconciliation engine (`headscale_config.go`), automated SQLite/Postgres DB initialization, and secure server key management.
    - Endpoints for user lifecycle management (`/v1/vpn/mesh/people`, `/v1/vpn/mesh/invites/preview`, `/v1/vpn/mesh/invites/redeem`, `/v1/vpn/mesh/self/*`), machine tagging, routing advertisements, and session expiration tracking.
    - Full RBAC integration across OpenLDAP directory users, local accounts, and session revocation tracking.
- **Advanced Ring-0 eBPF Visualizations, Runtime Profiling & Dependency Topologies (`/reporting/ebpf`)**:
  - **Interactive XDP Packet Flow Sankey Diagram (`EbpfXdpPipelineVisualizer`)**: Real-time vector-based visualization of ingress packets traversing Ring-0 DMA RX rings, VLAN decapsulation, IPv4/IPv6 layer parsing, and final XDP verdicts (`PASS`, `DROP`, `TX`, `REDIRECT`), switchable between Cumulative Packets and Live PPS deltas.
  - **Kernel TCP State Machine Funnel & Traffic Heatmap Matrix (`EbpfSocketAndServiceVisualizer`)**: Funnel diagram detailing active TCP connections through kernel states (`LISTEN`, `SYN_SENT`, `ESTABLISHED`, `FIN_WAIT`, `TIME_WAIT`), paired with an interactive Source IP $\\times$ Destination Port traffic matrix supporting 1-click fast-drop defensive rules.
  - **eBPF Execution Profiler & SoftIRQ/NAPI Pressure Heatmap (`EbpfRuntimeProfilerVisualizer`)**: 1-click toggle for `/proc/sys/kernel/bpf_stats_enabled` runtime metric collection, 3-tier execution budget icicle flame-strip, rolling top-program CPU timeline, and per-CPU SoftIRQ/NAPI core pressure heatmap parsing `/proc/net/softnet_stat`.
  - **BPF Kernel Dependency Graph & Verifier Complexity Scatter Plot (`EbpfKernelGraphVisualizer`)**: Force-directed topology connecting BPF links, programs, and maps with type filters, coupled with a Verifier Complexity vs. JIT execution latency scatter plot for instant kernel performance auditing.
  - **Raw Link Enumeration & Socket Telemetry (`apps/axonwalld`)**: Enumerates `bpf_link` objects via raw `BPF_LINK_GET_NEXT_ID` syscalls (`unix.SYS_BPF`), maps program-to-map associations, and collects `/proc/net/{tcp,udp,raw}*` socket exposure telemetry.
- **Appliance ISO, Cloud Image & CI Packaging Hardening**:
  - **Merged-Usr `rsync -aK` Cloud Image Build Fix**: Replaced `cp -r` with `rsync -aK` (`--keep-dirlinks`) in `packaging/cloud-image/build-qcow2.sh` to safely preserve Debian 13 merged-usr `/lib -> usr/lib` symlinks without `cp: cannot overwrite non-directory` errors.
  - **Alpine BusyBox `mktemp` Compatibility**: Adjusted K9s download temporary file pattern in `packaging/alpine/build-alpine-iso.sh` to comply with BusyBox `mktemp` strict requirement that templates end with `XXXXXX`.
  - **Next.js 16 Runtime Standalone Validation**: Aligned Next.js standalone payload checks with Next.js 16 (`dist/shared/lib/errors/code-frame.js`).
  - **Automated CI & Packaging Preflight Suite**: Added `scripts/ci-preflight.sh` and `ci-preflight.test.ts` into monorepo preflight to statically test POSIX/bash syntax, duplicate script parity, BusyBox `mktemp`, merged-usr preservation, and bootloader cache before expensive image builds.

---

## `v0.13.1` (2026-11-22) — Headscale Turnkey Onboarding & Self-Service Portal, Advanced Ring-0 eBPF Visualizations, and Offline ISO Packaging Hardening

### Highlights
- **Turnkey Headscale Mesh Onboarding, Magic Invite Links & User Self-Service Portal (`/vpn/mesh`, `/portal/vpn`, `/invite/[token]`)**:
  - **Magic Invite Links & Turnkey Onboarding**: Administrators can invite users with configurable expiration, device registration quotas, pre-assigned tags, and auto-registration flags. Generates single-use invite tokens with instant QR codes and direct links.
  - **Self-Service VPN Portal (`/portal/vpn`)**: Dedicated end-user interface (`MeshSelfServicePortal`) for non-root users to view active mesh nodes, generate authentication keys (reusable, ephemeral, pre-authenticated), register devices via interactive auth-key commands or machine registration keys, inspect WireGuard configs, and manage their credentials.
  - **Headscale Management Engine (`apps/axonwalld` & `apps/axonwall-controller`)**:
    - Native `headscale` configuration reconciliation engine (`headscale_config.go`), automated SQLite/Postgres DB initialization, and secure server key management.
    - Endpoints for user lifecycle management (`/v1/vpn/mesh/people`, `/v1/vpn/mesh/invites/preview`, `/v1/vpn/mesh/invites/redeem`, `/v1/vpn/mesh/self/*`), machine tagging, routing advertisements, and session expiration tracking.
    - Full RBAC integration across OpenLDAP directory users, local accounts, and session revocation tracking.
- **Advanced Ring-0 eBPF Visualizations, Runtime Profiling & Dependency Topologies (`/reporting/ebpf`)**:
  - **Interactive XDP Packet Flow Sankey Diagram (`EbpfXdpPipelineVisualizer`)**: Real-time vector-based visualization of ingress packets traversing Ring-0 DMA RX rings, VLAN decapsulation, IPv4/IPv6 layer parsing, and final XDP verdicts (`PASS`, `DROP`, `TX`, `REDIRECT`), switchable between Cumulative Packets and Live PPS deltas.
  - **Kernel TCP State Machine Funnel & Traffic Heatmap Matrix (`EbpfSocketAndServiceVisualizer`)**: Funnel diagram detailing active TCP connections through kernel states (`LISTEN`, `SYN_SENT`, `ESTABLISHED`, `FIN_WAIT`, `TIME_WAIT`), paired with an interactive Source IP $\times$ Destination Port traffic matrix supporting 1-click fast-drop defensive rules.
  - **eBPF Execution Profiler & SoftIRQ/NAPI Pressure Heatmap (`EbpfRuntimeProfilerVisualizer`)**: 1-click toggle for `/proc/sys/kernel/bpf_stats_enabled` runtime metric collection, 3-tier execution budget icicle flame-strip, rolling top-program CPU timeline, and per-CPU SoftIRQ/NAPI core pressure heatmap parsing `/proc/net/softnet_stat`.
  - **BPF Kernel Dependency Graph & Verifier Complexity Scatter Plot (`EbpfKernelGraphVisualizer`)**: Force-directed topology connecting BPF links, programs, and maps with type filters, coupled with a Verifier Complexity vs. JIT execution latency scatter plot for instant kernel performance auditing.
  - **Raw Link Enumeration & Socket Telemetry (`apps/axonwalld`)**: Enumerates `bpf_link` objects via raw `BPF_LINK_GET_NEXT_ID` syscalls (`unix.SYS_BPF`), maps program-to-map associations, and collects `/proc/net/{tcp,udp,raw}*` socket exposure telemetry.
- **Appliance ISO Offline Packaging & Bootloader Cache Hardening**:
  - Fixed offline Debian installer chroot cache validation in `packaging/iso/build-iso.sh` by ensuring both `grub-pc` (BIOS) and `grub-efi-amd64` (UEFI) packages are reliably downloaded and cached into `config/includes.chroot/var/cache/apt/archives/`.
  - Resolved `shim-unsigned` and `shim-helpers-amd64-signed` package resolution issues on Ubuntu/Debian runner environments.

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
