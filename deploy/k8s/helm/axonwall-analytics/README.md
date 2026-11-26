# Axonwall Central Analytics Stack (`axonwall-analytics`)

Deploys the central **Axonwall Analytics & Observability** stack on an Axonwall `k3s-storage` node (or any Kubernetes cluster with OpenEBS ZFS storage) so edge routers can offload storage and query workloads while staying focused on packet forwarding.

## Components

- **ClickHouse** — Columnar NetFlow v5/v9, IPFIX (Enterprise PEN `62999`), and sFlow v5 flow store with multi-node `node_id` / `node_name` attribution.
- **VictoriaMetrics** — High-compression time-series backend ingesting Prometheus Remote-Write metrics from edge routers.
- **VictoriaLogs** — Structured LogsQL store receiving NFLOG, `journald`, Suricata EVE, CrowdSec alerts, Kea DHCP leases, and opt-in Unbound query logs.
- **`axonwalld --mode=collector`** — Unprivileged collector daemon receiving IPFIX/NetFlow/sFlow packets and querying ClickHouse.
- **`axonwall-controller`** — Control plane bridging edge telemetry, service-token authentication (`axw_svc_*`), MCP observability tools, and opt-in bounded XDP edge mitigation.

## Resource Profiles (`axonwall-zfs-local`)

Three ready-made sizing overlays are included:

- `values-homelab.yaml` — Compact single-node footprint (`10Gi` ClickHouse, `5Gi` VictoriaMetrics, `5Gi` VictoriaLogs)
- `values-standard.yaml` — Balanced production defaults
- `values-enterprise.yaml` — Extended retention & larger PVC allocations

## Quick Install

```bash
helm upgrade --install axonwall-analytics deploy/k8s/helm/axonwall-analytics \
  --namespace axonwall-analytics \
  --create-namespace \
  -f deploy/k8s/helm/axonwall-analytics/values-standard.yaml
```

For automated first-boot provisioning on Axonwall `k3s-storage` appliances, copy [02-axonwall-analytics-helmchart.yaml.example](../../../packaging/k3s-storage/02-axonwall-analytics-helmchart.yaml.example) to `/var/lib/rancher/k3s/server/manifests/02-axonwall-analytics-helmchart.yaml`.

## Docker Compose Alternative

For non-Kubernetes Linux/ZFS hosts, run `docker compose -f deploy/docker/compose.yaml up -d`.

## Configuring Edge Routers

1. Mint a scoped service token (`axw_svc_*`) in the central Web Console under **Reporting → Observability (`/reporting/observability`)** (or `POST /api/v1/system/service-tokens`).
2. Configure `observability.offload` in `/etc/axonwall/system.yaml` and `netflow.mode: exporter` in `/etc/axonwall/netflow.yaml` on each edge router pointing at the central host's WireGuard or management IP.
3. Optional `remoteEdgeMitigation` allows the central Hub / MCP server to push bounded-TTL `XDP_DROP` blocks to edge nodes while respecting anti-lockout `protectedCidrs`.
