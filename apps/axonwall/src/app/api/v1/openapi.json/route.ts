import { NextResponse } from 'next/server';
import { getSession } from '@/server/auth';

export async function GET() {
  const session = await getSession();
  if (!session || session.passwordChangeRequired) {
    return NextResponse.json(
      { error: session?.passwordChangeRequired ? 'Forbidden: Password change required' : 'Unauthorized' },
      { status: session?.passwordChangeRequired ? 403 : 401 }
    );
  }

  const spec = {
    openapi: '3.1.0',
    info: {
      title: 'Axonwall Firewall REST API',
      version: '0.12.4',
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
    },
  };

  return NextResponse.json(spec);
}
