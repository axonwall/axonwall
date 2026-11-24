import { NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { isConsoleUser, isPasswordChangeEnforced } from '@/server/auth-guard';

export async function GET() {
  const session = await getSession();
  const pwdEnforced = isPasswordChangeEnforced(session);
  if (!session || pwdEnforced) {
    return NextResponse.json(
      { error: pwdEnforced ? 'Forbidden: Password change required' : 'Unauthorized' },
      { status: pwdEnforced ? 403 : 401 }
    );
  }
  if (!isConsoleUser(session)) {
    return NextResponse.json(
      { error: 'Forbidden: Console role required' },
      { status: 403 }
    );
  }

  const spec = {
    openapi: '3.1.0',
    info: {
      title: 'Axonwall Firewall REST API',
      version: '0.15.0',
      description: 'Declarative REST API for managing Axonwall Linux nftables firewalls, routing, services, and commit-confirm apply pipeline.',
    },
    servers: [
      {
        url: '/api/v1',
        description: 'Local Appliance API',
      },
    ],
    paths: {
      '/status': {
        get: {
          summary: 'Get operational status',
          description: 'Returns real-time status of the data plane, pending confirm status, uptime, and network interfaces.',
          responses: {
            '200': {
              description: 'Successful status response',
            },
          },
        },
      },
      '/apply': {
        post: {
          summary: 'Apply configuration changes',
          description: 'Atomically compiles and applies candidate ruleset to Linux nftables with commit-confirm protection.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    state: { type: 'object' },
                    confirmTimeoutSeconds: { type: 'integer', default: 120 },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Configuration applied and pending confirmation' },
            '400': { description: 'Validation error' },
          },
        },
      },
      '/confirm': {
        post: {
          summary: 'Confirm active configuration',
          description: 'Promotes candidate ruleset to last-known-good and cancels automatic rollback timer.',
          responses: {
            '200': { description: 'Configuration confirmed' },
          },
        },
      },
      '/rollback': {
        post: {
          summary: 'Rollback to last-known-good',
          description: 'Immediately reverts the active ruleset to the previous last-known-good bundle.',
          responses: {
            '200': { description: 'Rollback successful' },
          },
        },
      },
      '/state': {
        get: {
          summary: 'Read declarative desired state',
          description: 'Returns the active merged DesiredState JSON representation from /etc/axonwall/*.yaml.',
          responses: {
            '200': { description: 'Active DesiredState payload' },
          },
        },
      },
      '/events/packets': {
        get: {
          summary: 'Stream real-time firewall packet events (SSE)',
          description: 'Server-Sent Events (text/event-stream) stream of kernel NFLOG / eBPF packet verdicts and protocol dissections.',
          responses: {
            '200': { description: 'SSE packet stream' },
          },
        },
      },
      '/import': {
        post: {
          summary: 'Import legacy firewall configuration',
          description: 'Translates pfSense XML, OPNsense XML, Cisco IOS/ASA/FTD CLI, VyOS/EdgeOS config.boot, MikroTik RouterOS /export, Linux iptables-save, or firewalld XML/CLI directly into Axonwall DesiredState and Linux nftables.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    config: { type: 'string', description: 'Raw firewall configuration text' },
                    vendor: {
                      type: 'string',
                      enum: ['auto', 'pfsense', 'opnsense', 'proxmox', 'truenas', 'cisco', 'vyos', 'mikrotik', 'iptables', 'firewalld'],
                      default: 'auto',
                    },
                    apply: { type: 'boolean', default: false, description: 'Immediately apply to live firewall with safety rollback' },
                    confirmTimeoutSeconds: { type: 'integer', default: 120 },
                  },
                  required: ['config'],
                },
              },
            },
          },
          responses: {
            '200': { description: 'Configuration parsed and translated successfully' },
            '400': { description: 'Parsing or validation error' },
          },
        },
      },
      '/ebpf/overview': {
        get: {
          summary: 'Get unified Ring-0 eBPF, BPF_TOKEN_CREATE & Cross-Duty telemetry',
          description:
            'Returns dual-stack IPv4/IPv6 + 802.1Q/802.1ad VLAN XDP verdict counters, TTL-bounded XDP_DROP blocklist entries, 5-hook CO-RE BPF-LSM status, Linux 6.9+ bpffs delegation mounts, KVM/LXC vnet/TAP telemetry, K3s UserNS readiness, and OpenZFS ARC/L2ARC/ZIL kstats.',
          responses: {
            '200': { description: 'Unified Ring-0 eBPF and cross-duty telemetry payload' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/ebpf/xdp/block': {
        post: {
          summary: 'Insert IPv4 or IPv6 address into XDP line-rate drop map',
          description:
            'Blocks an attacker IPv4 or IPv6 host at the NIC driver ring (XDP_DROP prior to sk_buff allocation) with automatic monotonic TTL expiration.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    ip: { type: 'string', description: 'IPv4 or IPv6 address to drop at XDP line rate' },
                    ttlSeconds: { type: 'integer', default: 3600, minimum: 10, maximum: 604800 },
                  },
                  required: ['ip'],
                },
              },
            },
          },
          responses: {
            '200': { description: 'XDP_DROP entry programmed into BPF_MAP_TYPE_LRU_HASH' },
          },
        },
        delete: {
          summary: 'Remove IPv4 or IPv6 address from XDP drop map',
          parameters: [
            {
              name: 'ip',
              in: 'query',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': { description: 'XDP_DROP entry removed' },
          },
        },
      },
      '/ebpf/tokens': {
        post: {
          summary: 'Create or mount a Linux 6.9+ delegated bpffs BPF_TOKEN profile',
          description:
            'Mounts a dedicated bpffs instance under /run/axonwall/bpffs-tokens/<name> with safe networking delegation options while BPF-LSM blocks Ring-0 tracing/memory-read program types (kprobe/tracepoint/lsm).',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    name: { type: 'string' },
                    preset: {
                      type: 'string',
                      enum: ['networking-safe', 'cgroup-observability', 'firewall-xdp-tc'],
                      default: 'networking-safe',
                    },
                    workloadTarget: { type: 'string', default: 'k3s-userns' },
                  },
                  required: ['name'],
                },
              },
            },
          },
          responses: {
            '200': { description: 'Delegated bpffs token profile mounted' },
          },
        },
        delete: {
          summary: 'Unmount and remove a delegated bpffs BPF_TOKEN profile',
          parameters: [
            {
              name: 'name',
              in: 'query',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': { description: 'Delegated bpffs token profile unmounted' },
          },
        },
      },
      '/mcp': {
        post: {
          summary: 'Axonwall Model Context Protocol (MCP) JSON-RPC 2.0 Streamable HTTP Endpoint',
          description:
            'Authenticated (Bearer axw_mcp_*) JSON-RPC 2.0 endpoint exposing 16 read-only MCP Resources and 25 guardrailed MCP Tools across Firewall, Ring-0 eBPF & BPF_TOKEN_CREATE, KVM/LXC Virtualization, K3s Kubernetes, OpenZFS NAS, and 9-Vendor Migration.',
          responses: {
            '200': { description: 'MCP JSON-RPC 2.0 response' },
            '401': { description: 'Missing or invalid MCP API key' },
            '403': { description: 'Insufficient MCP scope or subsystem disabled' },
          },
        },
      },
      '/system/kernel': {
        get: {
          summary: 'Inspect Custom Kernel Studio hardware inventory & running kernel posture',
          description:
            'Returns detected CPU flags, IOMMU/TPM2/watchdog/PCIe/NIC/storage hardware, loaded modules, compiled Kconfig fragment, and 25-check kernel hardening audit.',
          responses: {
            '200': { description: 'Kernel Studio payload' },
            '401': { description: 'Unauthorized' },
          },
        },
        post: {
          summary: 'Build or safely stage a custom hardened Linux 6.12 LTS kernel',
          description:
            'Launches an asynchronous Universal or localmodconfig hardware-stripped kernel build via axonwalld, or safely stages built .deb packages via ZFSBootMenu clone / side-by-side GRUB.',
          responses: {
            '200': { description: 'Kernel Studio action accepted' },
            '400': { description: 'Invalid request' },
          },
        },
      },
      '/security/threat-harvester/status': {
        get: {
          summary: 'Inspect Axonwall Blackbox (ebpf-threat-harvester) telemetry, hooks & spool stats',
          description:
            'Returns live CO-RE TCX/tracepoint/uprobe hook status, packet & Tier-0/Tier-1 counts, DLP redactions, hardcoded control-plane TLS uprobe exclusions, and OpenZFS spool quota usage.',
          responses: {
            '200': { description: 'Threat Harvester status snapshot' },
            '401': { description: 'Unauthorized' },
          },
        },
        post: {
          summary: 'Update live Axonwall Blackbox harvester configuration',
          description:
            'Validates ThreatHarvesterConfigSchema and pushes updated captureMode, watchedInterfaces, canaryPorts, enableTlsUprobes, teacherLlm, and fleetShipper settings to axonwalld (admin required).',
          responses: {
            '200': { description: 'Updated Threat Harvester status' },
            '400': { description: 'Invalid configuration' },
            '403': { description: 'Forbidden (admin required)' },
          },
        },
      },
      '/security/threat-harvester/episodes': {
        get: {
          summary: 'List captured Causal Threat Episodes filtered by tier and review status',
          description:
            'Queries recorded multi-oracle threat episodes (gold_malicious, silver_malicious, benign_sampled, unlabeled_anomaly) with 5-tuple, JA4T, first-16 packet sketches, Causal DSL, and DLP-scrubbed L7 slices.',
          responses: {
            '200': { description: 'Filtered ThreatEpisode list & total count' },
            '401': { description: 'Unauthorized' },
          },
        },
        post: {
          summary: 'Review, Teacher-LLM annotate, or synthesize a Threat Harvester episode',
          description:
            'Dispatches op=review (pinned_gold | approved_malicious | marked_benign | delete, operator+), op=annotate (Teacher-LLM distillation, operator+), or op=simulate (safe synthetic episode, admin).',
          responses: {
            '200': { description: 'Updated or synthesized episode' },
            '400': { description: 'Invalid operation or episode ID' },
            '403': { description: 'Forbidden' },
          },
        },
      },
      '/security/threat-harvester/export': {
        get: {
          summary: 'Download Dual-Track .tar.zst corpus (ChatML SFT/RLVR JSONL + Apache Parquet)',
          description:
            'Streams an application/zstd tar archive containing manifest.json, train.jsonl, val.jsonl, and features.parquet with prefix-preserving AES-128 Crypto-PAn IPv4/IPv6 + HMAC hostname anonymization (admin required).',
          responses: {
            '200': { description: 'application/zstd archive download' },
            '403': { description: 'Forbidden (admin required)' },
          },
        },
      },
      '/security/threat-harvester/ship': {
        post: {
          summary: 'Ship anonymized Dual-Track .tar.zst corpus via AWS SigV4 to S3 / Vault',
          description:
            'Triggers an immediate stdlib AWS SigV4 PUT upload of the anonymized training bundle to the configured MinIO / Axonwall Vault / S3 endpoint (admin required).',
          responses: {
            '200': { description: 'Shipped S3 object key confirmation' },
            '400': { description: 'Shipper disabled or S3 upload failed' },
            '403': { description: 'Forbidden (admin required)' },
          },
        },
      },
      '/netflow/status': {
        get: {
          summary: 'Get NetFlow / IPFIX / sFlow collector pipeline & exporter status',
          description:
            'Returns active UDP/TCP/TLS 1.3 mTLS listener health, eBPF self-exporter state, ClickHouse & Zstd rollup status, GeoIP database status, and aggregated flow counters.',
          responses: {
            '200': { description: 'NetFlow collector pipeline status snapshot' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/netflow/query': {
        post: {
          summary: 'Execute Flow Query Language (FQL) search or ClickHouse SQL pushdown',
          description:
            'Queries ingested flows and historical 1m/5m/1h Zstd rollups or ClickHouse using FQL filters, optional bidirectional session stitching (biflow), heatmaps, geo arcs, or multi-host Fleet Federation (scope: fleet).',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    fql: { type: 'string', description: 'Flow Query Language expression' },
                    rangeMinutes: { type: 'integer', default: 60 },
                    startMs: { type: 'integer', description: 'Optional brush-zoom window start epoch ms' },
                    endMs: { type: 'integer', description: 'Optional brush-zoom window end epoch ms' },
                    limit: { type: 'integer', default: 100 },
                    scope: { type: 'string', enum: ['local', 'fleet'], default: 'local' },
                    biflow: { type: 'boolean', default: false },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Matched flow records, aggregates, rollups, sessions, heatmaps, and geo arcs' },
            '400': { description: 'Invalid FQL syntax or parameters' },
          },
        },
      },
      '/netflow/stream': {
        get: {
          summary: 'Stream real-time enriched flow records (SSE)',
          description:
            'Establishes a persistent Server-Sent Events (text/event-stream) feed of enriched NetFlow v5/v9, IPFIX, sFlow v5, and eBPF flows, optionally filtered by ?fql=...',
          parameters: [
            {
              name: 'fql',
              in: 'query',
              required: false,
              schema: { type: 'string' },
            },
          ],
          responses: {
            '200': { description: 'SSE flow telemetry stream' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/netflow/exporters': {
        get: {
          summary: 'List discovered flow exporters and live packet rates',
          description:
            'Returns exporting router/switch/host IPs, protocol versions (NetFlow v5/v9, IPFIX, sFlow v5), TLS/mTLS session state, packet/flow rates, and last-seen timestamps.',
          responses: {
            '200': { description: 'Discovered NetFlow/IPFIX/sFlow exporters' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/netflow/templates': {
        get: {
          summary: 'Inspect decoded NetFlow v9 & IPFIX option/data templates',
          description:
            'Lists active template IDs (including eBPF dual-stack Template 256 IPv4 and Template 257 IPv6), Enterprise Private PEN fields, NAT/CGNAT IEs 225-228, and decoded field definitions.',
          responses: {
            '200': { description: 'Template cache inventory' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/netflow/alerts': {
        get: {
          summary: 'List flow anomaly, threshold & baseline deviation alerts',
          description:
            'Returns active and acknowledged volumetric, DDoS, EWMA Z-score baseline deviation, and first-seen peer-pair alerts.',
          responses: {
            '200': { description: 'NetFlow anomaly and threshold alerts' },
            '401': { description: 'Unauthorized' },
          },
        },
        post: {
          summary: 'Acknowledge a NetFlow alert or all active alerts',
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    id: { type: 'string', default: 'all' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Alert acknowledgement result' },
          },
        },
      },
      '/netflow/reports': {
        get: {
          summary: 'Generate 95th/99th percentile capacity & billing report',
          description:
            'Computes 95th/99th percentile throughput and byte/packet rollups grouped by interface, exporter, ASN, application, VLAN, or subnet in json, csv, or markdown format (pass raw=1 for direct file download).',
          parameters: [
            { name: 'rangeDays', in: 'query', required: false, schema: { type: 'integer', default: 7 } },
            { name: 'groupBy', in: 'query', required: false, schema: { type: 'string', default: 'interface' } },
            { name: 'format', in: 'query', required: false, schema: { type: 'string', enum: ['json', 'csv', 'markdown'], default: 'json' } },
            { name: 'raw', in: 'query', required: false, schema: { type: 'string', enum: ['0', '1'] } },
          ],
          responses: {
            '200': { description: '95th-percentile report payload or attachment' },
          },
        },
        post: {
          summary: 'Persist a scheduled 95th-percentile report snapshot',
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    rangeDays: { type: 'integer', default: 7 },
                    groupBy: { type: 'string', default: 'interface' },
                    format: { type: 'string', enum: ['json', 'csv', 'markdown'], default: 'json' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Generated report snapshot metadata' },
          },
        },
      },
      '/netflow/baselines': {
        get: {
          summary: 'Inspect learned 7d x 24h EWMA anomaly baselines',
          parameters: [
            { name: 'limit', in: 'query', required: false, schema: { type: 'integer', default: 50 } },
          ],
          responses: {
            '200': { description: 'Learned 168-slot baseline entries' },
          },
        },
        delete: {
          summary: 'Reset learned 7d x 24h EWMA baselines',
          responses: {
            '200': { description: 'Baselines cleared' },
          },
        },
      },
      '/netflow/geoip/update': {
        post: {
          summary: 'Trigger on-demand HTTPS MaxMind GeoLite2 / DB-IP MMDB database update',
          responses: {
            '200': { description: 'GeoIP MMDB databases refreshed' },
            '502': { description: 'Upstream MMDB update failed' },
          },
        },
      },
      '/netflow/metrics': {
        get: {
          summary: 'Expose Prometheus text format NetFlow collector & exporter metrics',
          description:
            'Returns OpenMetrics / Prometheus text/plain; version=0.0.4 metrics for collector throughput, drops, templates, exporters, alerts, and baselines.',
          responses: {
            '200': { description: 'Prometheus metrics exposition' },
            '401': { description: 'Unauthorized' },
          },
        },
      },
      '/netflow/test-inject': {
        post: {
          summary: 'Inject a synthetic flow burst for collector & FQL pipeline validation',
          requestBody: {
            required: false,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    protocol: { type: 'string', default: 'ipfix' },
                    count: { type: 'integer', default: 12 },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Synthetic flow burst injected' },
          },
        },
      },
      '/topology/fabric': {
        get: {
          summary: 'Inspect Topology Studio merged multi-host fabric graph & DesiredState projection',
          responses: {
            '200': { description: 'Merged fabric topology graph' },
          },
        },
      },
      '/topology/probe': {
        get: {
          summary: 'Run strict Green/Yellow/Red live link, carrier, LLDP & BGP fabric probes',
          responses: {
            '200': { description: 'Live fabric health probe report' },
          },
        },
      },
      '/topology/apply': {
        post: {
          summary: 'Execute phased transactional Topology Studio fabric apply',
          responses: {
            '200': { description: 'Fabric plan applied' },
          },
        },
      },
      '/topology/sync': {
        post: {
          summary: 'Synchronize Topology Studio graph with NetBox or LibreNMS Triad',
          responses: {
            '200': { description: 'Triad synchronization result' },
          },
        },
      },
      '/services/netbox/status': {
        get: {
          summary: 'Get K3s-native NetBox v4 DCIM/IPAM deployment & OpenLDAP SSO status',
          responses: {
            '200': { description: 'NetBox status snapshot' },
          },
        },
      },
      '/services/netbox/sync': {
        post: {
          summary: 'Run idempotent Axonwall-to-NetBox DCIM/IPAM inventory reconciliation',
          responses: {
            '200': { description: 'NetBox sync report' },
          },
        },
      },
      '/services/librenms/status': {
        get: {
          summary: 'Get LibreNMS SNMPv2c/v3, LLDP/CDP & optical DOM hub status',
          responses: {
            '200': { description: 'LibreNMS status snapshot' },
          },
        },
      },
      '/services/librenms/sync': {
        post: {
          summary: 'Synchronize monitored hosts and SNMP credentials with LibreNMS',
          responses: {
            '200': { description: 'LibreNMS sync report' },
          },
        },
      },
      '/services/librenms/topology': {
        get: {
          summary: 'Fetch LLDP/CDP/FDB L2/L3 neighbor discovery graph from LibreNMS',
          responses: {
            '200': { description: 'LibreNMS discovery topology' },
          },
        },
      },
      '/services/librenms/netbox-sync': {
        post: {
          summary: 'Cross-sync discovered LibreNMS links and cables into NetBox DCIM',
          responses: {
            '200': { description: 'LibreNMS-to-NetBox sync report' },
          },
        },
      },
      '/services/librenms/webhook': {
        get: {
          summary: 'Inspect recent LibreNMS alert webhook deliveries',
          responses: {
            '200': { description: 'Recent LibreNMS alert webhooks' },
          },
        },
        post: {
          summary: 'Receive LibreNMS alert webhook notification',
          responses: {
            '200': { description: 'Webhook ingested' },
          },
        },
      },
    },
  };

  return NextResponse.json(spec);
}
