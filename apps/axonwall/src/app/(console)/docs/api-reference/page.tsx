import React from 'react';
import Link from 'next/link';
import { Code2, Server, Radio, Terminal, GitBranch, Shield, Key } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'REST API, Fleet/MCP, Agent Sockets & Terraform Reference | Axonwall Documentation',
  description:
    'Complete REST/OpenAPI endpoints, Server-Sent Events (SSE) packet streams, Fleet & MCP security APIs, Go agent Unix socket IPC, and official Terraform / OpenTofu provider for Axonwall v0.15.1.',
};

export default function ApiReferenceDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Developer, IaC &amp; Automation • v0.15.1
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          REST, Fleet/MCP, Agent Socket &amp; Terraform Reference
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Automate Axonwall through standardized OpenAPI REST endpoints, real-time Server-Sent Events (SSE) telemetry streams, Fleet &amp; Model Context Protocol (MCP) APIs, privileged Unix domain sockets, and the official Terraform / OpenTofu provider.
        </p>
      </div>

      {/* Authentication */}
      <section className="space-y-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Key className="w-5 h-5 text-emerald-400" /> Authentication
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          All HTTPS API requests to port <code className="text-emerald-400 font-mono">2966</code> must supply an RBAC-scoped API token generated in <code className="text-slate-200">System &gt; Access &gt; API Keys</code> via the HTTP Authorization header:
        </p>
        <CodeBlock
          title="HTTP Header"
          language="http"
          code={`Authorization: Bearer axw_live_9f82c3e4a1b74d6e9012f`}
        />
      </section>

      {/* Core Console REST Endpoints */}
      <section id="rest-endpoints" className="space-y-6 pt-6 border-t border-slate-800/80">
        {/* Preserve legacy #gitops alias anchor so existing bookmarks never break */}
        <span id="gitops" className="sr-only" aria-hidden="true" />
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Code2 className="w-6 h-6 text-emerald-400" /> 1. Console REST &amp; OpenAPI Endpoints
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The Next.js Console exposes a versioned OpenAPI 3.1 specification at <code className="text-emerald-400 font-mono">/api/v1/openapi.json</code> alongside transactional DesiredState and Commit-Confirm endpoints:
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Method</th>
                <th className="p-3">Endpoint</th>
                <th className="p-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/openapi.json</td>
                <td className="p-3">Machine-readable OpenAPI 3.1 specification for SDK generation and API clients.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/status</td>
                <td className="p-3">Appliance health, version (<code className="font-mono">0.15.1</code>), active boot slot/BE/snapshot, and Commit-Confirm timer state.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / PUT</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/state</td>
                <td className="p-3">Read or stage the merged DesiredState across all 14 <code className="font-mono">/etc/axonwall/*.yaml</code> domains.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-emerald-400 font-bold">POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/apply</td>
                <td className="p-3">Validate (<code className="font-mono">nft -c</code>), apply DesiredState bundle, and arm Commit-Confirm watchdog (60–120s).</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-emerald-400 font-bold">POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/confirm</td>
                <td className="p-3">Confirm active Commit-Confirm transaction, disarm timer, and persist GitOps revision.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-amber-400 font-bold">POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/rollback</td>
                <td className="p-3">Immediately revert to last-known-good state or a specified GitOps revision SHA.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-emerald-400 font-bold">POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/import</td>
                <td className="p-3">Parse &amp; analyze legacy configs (<code className="font-mono">vendor</code>: <code className="font-mono">pfsense</code>, <code className="font-mono">opnsense</code>, <code className="font-mono">proxmox</code>, <code className="font-mono">truenas</code>, <code className="font-mono">cisco-asa</code>, <code className="font-mono">vyos</code>, <code className="font-mono">mikrotik</code>, <code className="font-mono">iptables</code>, <code className="font-mono">firewalld</code>).</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/vpn/mesh/*</td>
                <td className="p-3">Manage sovereign Headscale/Tailscale mesh nodes, pre-auth keys, routes, and Rosenpass PQ peers.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/ebpf/overview</td>
                <td className="p-3">Unified Ring-0 eBPF status: Dual-Stack IPv4/IPv6 + VLAN XDP flow/drop counters, 5-hook CO-RE BPF-LSM state, Linux 6.9+ <code className="font-mono">BPF_TOKEN</code> mounts, cross-duty ARC/ZIL &amp; KVM telemetry, and live kernel BPF program/map inventory (<code className="font-mono">bpfInventory</code>).</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-emerald-400 font-bold">GET / POST / DELETE</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/ebpf/xdp/block</td>
                <td className="p-3">Inspect or mutate monotonic TTL-bounded IPv4/IPv6 <code className="font-mono">XDP_DROP</code> entries (<code className="font-mono">blocklist_map</code> / <code className="font-mono">blocklist6_map</code>) with RFC 1918 / anti-lockout guards.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-emerald-400 font-bold">GET / POST / DELETE</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/ebpf/tokens</td>
                <td className="p-3">List, mount, render K3s <code className="font-mono">hostUsers: false</code> YAML manifests, or unmount isolated Linux 6.9+ <code className="font-mono">/run/axonwall/bpffs-tokens/&lt;profile&gt;</code> superblocks.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/system/etckeeper/*</td>
                <td className="p-3">Inspect <code className="font-mono">/etc</code> Git status, initialize Etckeeper, update <code className="font-mono">.gitignore</code> / <code className="font-mono">autoCommitOnApply</code>, commit snapshots, and fetch unified commit diffs.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/system/kernel</td>
                <td className="p-3">Custom Kernel Studio: detect host hardware &amp; active modules, audit kernel posture (25 checks including <code className="font-mono">/proc/config.gz</code> fallback), synthesize hardened Kconfig fragments, launch async builds, and safely stage/install built <code className="font-mono">.deb</code> kernels via ZBM, Btrfs + Snapper, or GRUB.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/system/update</td>
                <td className="p-3">Release check, OTA updates (<code className="font-mono">update</code> / <code className="font-mono">activate</code> / <code className="font-mono">verify</code>), ZFSBootMenu (<code className="font-mono">zbm-*</code>), and Btrfs + Snapper (<code className="font-mono">btrfs-snapshot</code>, <code className="font-mono">btrfs-delete-snapshot</code>, <code className="font-mono">btrfs-rollback-snapshot</code>, <code className="font-mono">btrfs-sync-grub</code>).</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/k3s &amp; /api/k3s/logs/stream</td>
                <td className="p-3">Query K3s runtime &amp; etcd snapshots, trigger cluster HA join or etcd save/restore, and stream live pod/container SSE logs for Browser K9s Live Explorer.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / POST</td>
                <td className="p-3 font-mono text-cyan-400">/api/v1/security/threat-harvester/*</td>
                <td className="p-3">Axonwall Blackbox Threat-LLM Harvester: inspect TCX/tracepoint/uprobe telemetry (<code className="font-mono">status</code>), filter/review/Teacher-LLM-annotate/simulate episodes (<code className="font-mono">episodes</code>), stream Crypto-PAn anonymized Dual-Track <code className="font-mono">.tar.zst</code> bundles (<code className="font-mono">export</code>), and upload via AWS SigV4 (<code className="font-mono">ship</code>).</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / POST / DEL</td>
                <td className="p-3 font-mono text-sky-400">/api/v1/netflow/*</td>
                <td className="p-3">NetFlow/IPFIX/sFlow Collector Studio: <code className="font-mono">status</code>, <code className="font-mono">query</code> (FQL / ClickHouse / <code className="font-mono">scope: fleet</code>), <code className="font-mono">stream</code> (SSE), <code className="font-mono">exporters</code>, <code className="font-mono">templates</code>, <code className="font-mono">alerts</code>, <code className="font-mono">reports</code> (95th-pct CSV/MD/JSON), <code className="font-mono">baselines</code>, <code className="font-mono">geoip/update</code>, <code className="font-mono">metrics</code> (Prometheus), and <code className="font-mono">test-inject</code>.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/topology/*</td>
                <td className="p-3">Topology Studio multi-host fabric editor: merged <code className="font-mono">fabric</code> graph, strict Green/Yellow/Red <code className="font-mono">probe</code>, phased transactional <code className="font-mono">apply</code>, and NetBox/LibreNMS Triad <code className="font-mono">sync</code>.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-sky-400 font-bold">GET / POST</td>
                <td className="p-3 font-mono text-emerald-400">/api/v1/services/&#123;netbox,librenms&#125;/*</td>
                <td className="p-3">K3s NetBox v4 DCIM/IPAM (<code className="font-mono">status</code>, <code className="font-mono">sync</code>) and LibreNMS discovery hub (<code className="font-mono">status</code>, <code className="font-mono">sync</code>, <code className="font-mono">topology</code>, <code className="font-mono">netbox-sync</code>, <code className="font-mono">webhook</code>).</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Packets SSE Stream */}
      <section id="packets" className="space-y-6 pt-6 border-t border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <span className="px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 font-mono text-xs font-bold uppercase">GET</span>
          <h2 className="text-lg font-mono font-bold text-white">/api/v1/events/packets</h2>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">
          Establishes a persistent Server-Sent Events (SSE) stream delivering real-time parsed packet events directly from the Linux kernel Netfilter / NFLOG &amp; XDP tap.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-slate-800 rounded-xl overflow-hidden">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Query Param</th>
                <th className="p-3">Type</th>
                <th className="p-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="p-3 font-mono text-emerald-400">iface</td>
                <td className="p-3">string</td>
                <td className="p-3">Filter by interface name (e.g., <code className="text-slate-200">wan0</code>, <code className="text-slate-200">lan0</code>).</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-emerald-400">proto</td>
                <td className="p-3">string</td>
                <td className="p-3">Filter by protocol: <code className="text-slate-200">tcp</code>, <code className="text-slate-200">udp</code>, <code className="text-slate-200">icmp</code>.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-emerald-400">port</td>
                <td className="p-3">number</td>
                <td className="p-3">Filter by source or destination port (e.g. 443).</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Controller Fleet & MCP APIs */}
      <section id="fleet-mcp" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" /> 2. Controller Fleet Satellite &amp; MCP Security AI APIs
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Remote Edge UKI satellites and AI SecOps agents integrate via dedicated fleet enrollment and Model Context Protocol (MCP) endpoints:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm font-mono">/api/v1/fleet/enroll &amp; /api/v1/fleet/heartbeat</h3>
            <p className="text-slate-400 leading-relaxed">
              Zero-Touch Provisioning (ZTP) CSR enrollment and periodic mTLS telemetry/policy heartbeat endpoints for distributed <code className="text-slate-200 font-mono">axonwall-satellite</code> Edge UKI appliances declared under <code className="text-emerald-400 font-mono">fleet.nodes</code> in <code className="text-slate-200 font-mono">/etc/axonwall/ha.yaml</code>.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm font-mono">/api/v1/mcp &amp; /api/v1/mcp/sse</h3>
            <p className="text-slate-400 leading-relaxed">
              Streamable HTTP JSON-RPC 2.0 and SSE Model Context Protocol endpoints exposing <strong>16 granular capability scopes</strong>, <strong>16 read-only resources</strong>, and <strong>25 guardrailed tools</strong> across Firewall, Ring-0 eBPF &amp; <code className="text-slate-200 font-mono">BPF_TOKEN_CREATE</code>, KVM/LXC Virtualization, K3s Kubernetes, OpenZFS NAS, and 9-Vendor Migration. See <Link href="/docs/mcp-ai-control" className="text-emerald-400 underline">/docs/mcp-ai-control</Link>.
            </p>
          </div>
        </div>
      </section>

      {/* Privileged Unix Socket IPC */}
      <section id="agent-socket" className="space-y-6 pt-6 border-t border-slate-800/80">
        {/* Preserve legacy #terminal alias anchor so existing links resolve cleanly */}
        <span id="terminal" className="sr-only" aria-hidden="true" />
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Server className="w-6 h-6 text-emerald-400" /> 3. Privileged Agent Socket IPC (<code className="font-mono text-emerald-400">axonwalld</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Internal controllers and CLI tools communicate with <code className="text-emerald-400 font-mono">axonwalld</code>{' '}
          over three specialized Unix domain sockets in <code className="text-slate-200 font-mono">/run/axonwall/</code>,
          authenticated with the 32-byte local token at <code className="text-slate-200 font-mono">/etc/axonwall/agent.token</code>:
        </p>

        <CodeBlock
          title="Agent HTTP API Socket (/run/axonwall/agent-api.sock)"
          language="bash"
          code={`# Query daemon status & Commit-Confirm watchdog timer:
sudo curl -s --unix-socket /run/axonwall/agent-api.sock \\
  -H "X-Axonwall-Agent-Token: $(sudo cat /etc/axonwall/agent.token)" \\
  http://localhost/v1/status | jq .

# Query HA Sync Trust & ECDSA P-256 PKI enrollment state:
sudo curl -s --unix-socket /run/axonwall/agent-api.sock \\
  -H "X-Axonwall-Agent-Token: $(sudo cat /etc/axonwall/agent.token)" \\
  http://localhost/v1/ha/sync-trust | jq .`}
        />

        <CodeBlock
          title="IPC Sockets & Endpoints Summary"
          language="typescript"
          code={`// 1. /run/axonwall/agent-api.sock (0660 root:axonwall-api, HTTP/SSE + X-Axonwall-Agent-Token)
//    GET  /v1/status                     -> Daemon health, active bundle hash, pending Commit-Confirm job
//    POST /v1/apply                      -> Compile & apply nftables + daemon configs with Commit-Confirm
//    POST /v1/confirm                    -> Confirm pending jobId and disarm rollback timer
//    POST /v1/rollback                   -> Immediately revert to last-known-good bundle
//    GET  /v1/ebpf/overview              -> Dual-Stack VLAN XDP stats, 5-hook BPF-LSM, BPF_TOKEN mounts & kernel BPF inventory (bpfInventory)
//    POST /v1/ebpf/xdp/block             -> Monotonic TTL XDP_DROP IPv4/IPv6 blocklist (GET/POST/DELETE)
//    POST /v1/ebpf/tokens                -> Mount/unmount Linux 6.9+ bpffs delegate_* token superblocks
//    GET  /v1/ebpf/tokens/render-k3s     -> Render K3s hostUsers:false Pod/DaemonSet BPF_TOKEN manifest
//    GET  /v1/nas/telemetry              -> OpenZFS /proc/spl/kstat/zfs ARC/L2ARC, ZIL/SLOG & pool ZIO queues
//    GET  /v1/virt/telemetry             -> KVM vnet/tap interface RX/TX/drop stats, IOMMU & LXC BPF_TOKEN state
//    GET  /v1/k3s/telemetry              -> K3s UserNamespacesSupport, CNI/WireGuard interfaces & pod BPF_TOKENs
//    POST /v1/k3s/nodes/scheduling       -> Merge-patch K3s node roles, labels & edge taints (NoSchedule/NoExecute)
//    GET  /v1/k3s/{pulse,api-resources,namespaces,resources,resource/inspect,logs/stream} & POST /v1/k3s/action -> Browser K9s Explorer
//    POST /v1/terminal/exec              -> RBAC-gated Console Command Runner execution
//    GET  /v1/virt/console/ws            -> WebSocket proxy for KVM guest HTML5 noVNC consoles
//    GET  /v1/system/btrfs               -> Btrfs + Snapper list & status; POST list/snapshot/delete-snapshot/rollback-snapshot/sync-grub
//    GET  /v1/system/plugins & POST /v1/system/plugins/action -> On-demand role/plugin install & SHA-256 bundled binary lifecycle
//    GET  /v1/system/etckeeper/*         -> Host /etc Git status, init, config, commit, history & diff
//    GET  /v1/system/kernel/studio       -> Live hardware inventory, lsmod, running kernel config & build jobs
//    POST /v1/system/kernel/build        -> Start async Universal or localmodconfig stripped kernel build
//    POST /v1/system/kernel/install      -> Safe stage/install via ZBM clone, Btrfs pre-snapshot + GRUB sync, or dpkg + update-grub
//    GET  /v1/security/threat-harvester/status   -> Blackbox TCX/tracepoint/uprobe status, redactions & ZFS spool quota
//    POST /v1/security/threat-harvester/config   -> Apply live ThreatHarvesterConfig updates to Ring-0 collector
//    GET  /v1/security/threat-harvester/episodes -> Filter captured Causal Threat Episodes by tier & reviewStatus
//    POST /v1/security/threat-harvester/episodes/{review,annotate,simulate} -> Curate, Teacher-LLM annotate, or synthesize episodes
//    GET  /v1/security/threat-harvester/export   -> Stream Dual-Track SFT/RLVR JSONL + Apache Parquet .tar.zst bundle
//    POST /v1/security/threat-harvester/ship     -> Ship Crypto-PAn anonymized bundle to S3 / Vault via AWS SigV4
//    GET  /v1/ha/sync-trust              -> HA PKI enrollment, effective transport (mtls), SHA-256 fingerprints
//    GET  /v1/system/telemetry/hardware  -> HWMON thermal/fan/voltage sensors & SFP+/QSFP optical DOM
//    GET/POST /v1/netflow/{status,query,stream,exporters,templates,alerts,alerts/ack,reports,reports/generate,baselines,geoip/update,metrics,test-inject}
//    GET/POST /v1/topology/{fabric,probe,apply,sync/netbox,sync/librenms}
//    GET/POST /v1/{netbox,librenms}/*    -> NetBox v4 & LibreNMS Triad sync, credentials, topology & alert webhooks

// 2. /run/axonwall/agent.sock            -> Internal gRPC control-plane socket
// 3. /run/axonwall/ha.sock               -> 0600 root:root SO_PEERCRED Keepalived MASTER/BACKUP/FAULT hook`}
        />
      </section>

      {/* Terraform / OpenTofu Provider */}
      <section id="terraform" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <GitBranch className="w-6 h-6 text-emerald-400" /> 4. Official Terraform &amp; OpenTofu Provider (<code className="font-mono text-emerald-400">terraform-provider-axonwall</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Manage fleets of bare-metal, Proxmox/KVM, and Cloud Edge UKI Axonwall appliances declaratively from Infrastructure-as-Code pipelines using the official Go Plugin Framework provider (<code className="text-emerald-400 font-mono">terraform-provider-axonwall</code>):
        </p>

        <CodeBlock
          title="main.tf — Declarative DesiredState & Zero-Touch Cloud-Init Generation"
          language="hcl"
          code={`terraform {
  required_providers {
    axonwall = {
      source  = "axonwall/axonwall"
      version = "~> 0.15.1"
    }
  }
}

provider "axonwall" {
  endpoint             = "https://10.0.10.1:2966"
  api_token            = var.axonwall_api_token
  insecure_skip_verify = false
}

# Generate a pure-Go Edge UKI / Appliance NoCloud user-data seed
data "axonwall_cloudinit_config" "branch_edge" {
  hostname = "edge-fw-denver-01"
  hub_url  = "wss://10.0.10.1:2966/ws/satellite"
  sku      = "sku-x86-intel-n100-i226"
}

# Reconcile declarative DesiredState with transactional Commit-Confirm auto-confirmation
resource "axonwall_desired_state" "core_cluster" {
  auto_confirm           = true
  confirm_timeout_sec    = 120
  firewall_yaml          = file("\${path.module}/axonwall/firewall.yaml")
  interfaces_yaml        = file("\${path.module}/axonwall/interfaces.yaml")
  vpn_yaml               = file("\${path.module}/axonwall/vpn.yaml")
}`}
        />
      </section>
    </div>
  );
}
