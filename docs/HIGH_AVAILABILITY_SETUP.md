# Axonwall High Availability (HA) — Two-Host Cluster Setup Guide

Axonwall provides enterprise-grade **Active/Passive High Availability (HA)** with sub-second failover and zero TCP/UDP/WireGuard connection drops. Beyond floating VRRP Virtual IPs (`keepalived`) and kernel connection-tracking state replication (`conntrackd` FTFW), Axonwall synchronizes the entire appliance stack over a dedicated point-to-point sync link (`eth3`):

| Subsystem | Protocol / Port | Purpose & Failover Behavior |
| :--- | :--- | :--- |
| **Keepalived VRRPv2/v3** | IP Protocol `112` | Groups all WAN & LAN Floating VIPs into `vrrp_sync_group VG1` and invokes `/usr/local/bin/axonwall-ha-notify` over `/run/axonwall/ha.sock` on role transition |
| **conntrackd FTFW** | UDP `3780` | Sequence-numbered, acknowledged Linux Netfilter state table replication (`conntrackd -c` commits cache on promotion) |
| **Axonwall HA Engine** | TCP `9876` (`mTLS`) | Cryptographically signed desired-state configuration (`/api/v1/sync/state`) and online SQLite backup streaming (`/api/v1/sync/db`) |
| **HA Cluster PKI** | TCP `9876` (`ECDSA P-256`) | Automatic 10-year Root CA & node CSR enrollment (`/api/v1/sync/pki-enroll` -> `/var/lib/axonwall/secrets/ha-pki/`) with SHA-256 fingerprint pinning |
| **Chrony Symmetric NTP** | UDP `123` | Peer-to-peer clock discipline (`peer <peerIp> iburst`) so OpenLDAP CSNs and SQLite timestamps never drift during WAN outages |
| **OpenLDAP `syncrepl`** | TCP `636` (`LDAPS`) | Multi-provider `refreshAndPersist` directory replication (`ServerID 1` on Master, `ServerID 2` on Backup) |
| **Kea DHCPv4 HA** | TCP `8001` | `libdhcp_ha.so` hot-standby DHCP lease synchronization |
| **OpenZFS Storage** | TCP `9876` (`mTLS`) | Incremental `zfs send -w -I` snapshot streaming (`/api/v1/sync/zfs`); Backup keeps pools `readonly=on` until promoted to `MASTER` |
| **2-Node K3s + OpenEBS** | TCP `9876` / `6443` | Automated K3s cluster token exchange (`/api/v1/sync/k3s-token`) over WireGuard Flannel mesh + `axonwall-replicated-ha` OpenEBS volumes |

---

## Topology & Reference IP Plan

In this walkthrough, we configure two Axonwall hosts—**`axonwall-fw01`** (Primary `MASTER`) and **`axonwall-fw02`** (Secondary `BACKUP`):

```text
+---------------------------------------------------------------------------------+
|                              Upstream WAN Switch / ISP                          |
|                         Floating WAN VIP: 198.51.100.1/24 (VRID 51)             |
+---------------------------------------------------------------------------------+
                      |                                       |
                      | eth0: 198.51.100.2/24                 | eth0: 198.51.100.3/24
                      v                                       v
       +------------------------------+        +------------------------------+
       |  Host 1: axonwall-fw01       |        |  Host 2: axonwall-fw02       |
       |  Role: MASTER (Priority 150) |        |  Role: BACKUP (Priority 100) |
       |  ZFS Pool: Read-Write        |        |  ZFS Pool: Read-Only Target  |
       |  Headscale: Active           |        |  Headscale: Standby (Stopped)|
       +------------------------------+        +------------------------------+
                      ^                                       ^
                      |      Dedicated HA Sync Link (eth3)    |
                      |   10.0.99.1/30 <=====> 10.0.99.2/30   |
                      +<=====================================>+
                      | eth1: 10.0.10.2/24                    | eth1: 10.0.10.3/24
                      v                                       v
+---------------------------------------------------------------------------------+
|                                 LAN Core Switch                                 |
|                Floating LAN Gateway VIP: 10.0.10.1/24 (VRID 52)                 |
+---------------------------------------------------------------------------------+
```

| Logical Name / Device | Role | Host 1 (`axonwall-fw01`) | Host 2 (`axonwall-fw02`) | Floating VRRP VIP (Shared) |
| :--- | :--- | :--- | :--- | :--- |
| `wan` / `eth0` | WAN Uplink | `198.51.100.2/24` | `198.51.100.3/24` | `198.51.100.1/24` (`VRID 51`) |
| `lan` / `eth1` | LAN Core | `10.0.10.2/24` | `10.0.10.3/24` | `10.0.10.1/24` (`VRID 52`) |
| `ha-sync` / `eth3` | Dedicated HA Sync | `10.0.99.1/30` | `10.0.99.2/30` | None (Direct Point-to-Point) |

> **Important:** Both hosts must use identical Linux network interface names (`eth0`, `eth1`, `eth3`) so that synchronized nftables rulesets and VRRP definitions bind to the same interfaces on both appliances.
>
> **Hypervisor Note (Proxmox VE / KVM / ESXi):** Enable **MAC Spoofing / Promiscuous Mode / Forged Transmits** on the `eth0` and `eth1` virtual NICs, and ensure the hypervisor firewall allows IP Protocol `112` (VRRP) and multicast `224.0.0.18` / `225.0.0.50`. Connect `eth3` to a dedicated physical port or isolated host-only bridge.

---

## Step-by-Step Two-Host Setup

### Step 1: Configure Physical & Sync Interfaces on Both Hosts

Each host keeps its own physical interface addresses in `/etc/axonwall/interfaces.yaml`. Because `syncSections.interfaces` defaults to `false`, Host 1 will never overwrite Host 2's physical management IPs during state sync.

#### Host 1 (`axonwall-fw01`) — `/etc/axonwall/interfaces.yaml`

```yaml
interfaces:
  - name: wan
    device: eth0
    role: wan
    type: static
    enabled: true
    ipv4Address: 198.51.100.2/24
    ipv4Gateway: 198.51.100.254
    mtu: 1500
    description: Primary WAN Uplink (Host 1)

  - name: lan
    device: eth1
    role: lan
    type: static
    enabled: true
    ipv4Address: 10.0.10.2/24
    mtu: 1500
    description: Core LAN Interface (Host 1)

  - name: ha-sync
    device: eth3
    role: ha-sync
    type: static
    enabled: true
    ipv4Address: 10.0.99.1/30
    mtu: 9000
    description: Dedicated HA Sync Link (to fw02)
```

#### Host 2 (`axonwall-fw02`) — `/etc/axonwall/interfaces.yaml`

```yaml
interfaces:
  - name: wan
    device: eth0
    role: wan
    type: static
    enabled: true
    ipv4Address: 198.51.100.3/24
    ipv4Gateway: 198.51.100.254
    mtu: 1500
    description: Secondary WAN Uplink (Host 2)

  - name: lan
    device: eth1
    role: lan
    type: static
    enabled: true
    ipv4Address: 10.0.10.3/24
    mtu: 1500
    description: Core LAN Interface (Host 2)

  - name: ha-sync
    device: eth3
    role: ha-sync
    type: static
    enabled: true
    ipv4Address: 10.0.99.2/30
    mtu: 9000
    description: Dedicated HA Sync Link (to fw01)
```

Verify point-to-point link connectivity over `eth3` before enabling HA:

```bash
# On Host 1 (axonwall-fw01):
ping -I eth3 -c 3 10.0.99.2

# On Host 2 (axonwall-fw02):
ping -I eth3 -c 3 10.0.99.1
```

---

### Step 2: Configure Host 1 (`axonwall-fw01`) as Primary `MASTER`

Generate a shared secret on Host 1 (`openssl rand -hex 24`) for VRRP authentication and initial HA PKI bootstrap, then create `/etc/axonwall/ha.yaml` under the top-level `ha:` key on **`axonwall-fw01`**:

```yaml
ha:
  enabled: true
  nodeRole: master
  role: master
  syncInterface: eth3
  peerAddress: 10.0.99.2
  peerIp: 10.0.99.2
  peerPort: 2966
  maintenanceMode: false

  vrrpInstances:
    - name: VI_WAN
      vrid: 51
      interface: eth0
      priority: 150
      virtualIps:
        - 198.51.100.1/24
      authPassword: "replace-with-shared-secret"
    - name: VI_LAN
      vrid: 52
      interface: eth1
      priority: 150
      virtualIps:
        - 10.0.10.1/24
      authPassword: "replace-with-shared-secret"

  conntrackSync:
    enabled: true
    interface: eth3
    mode: FTFW
    protocol: multicast
    multicastGroup: 225.0.0.50
    peerAddress: 10.0.99.2
    port: 3780

  sqliteSync:
    enabled: true
    mode: direct_stream
    syncIntervalSeconds: 5
    listenPort: 9876
    peerAddress: 10.0.99.2
    peerPort: 9876
    authToken: "replace-with-shared-secret"
    transport: mtls
    requireSignedPayloads: true
    databases:
      - /var/lib/axonwall/headscale/db.sqlite

  syncSections:
    interfaces: false
    firewall: true
    dhcp: true
    dns: true
    aliases: true
    vpn: true
    sqlite: true
    nas: true
    k3s: true
```

---

### Step 3: Configure Host 2 (`axonwall-fw02`) as Secondary `BACKUP`

Create `/etc/axonwall/ha.yaml` on **`axonwall-fw02`** with `nodeRole: backup`, `priority: 100`, `peerAddress: 10.0.99.1`, and the matching `authPassword` / `authToken`:

```yaml
ha:
  enabled: true
  nodeRole: backup
  role: backup
  syncInterface: eth3
  peerAddress: 10.0.99.1
  peerIp: 10.0.99.1
  peerPort: 2966
  maintenanceMode: false

  vrrpInstances:
    - name: VI_WAN
      vrid: 51
      interface: eth0
      priority: 100
      virtualIps:
        - 198.51.100.1/24
      authPassword: "replace-with-shared-secret"
    - name: VI_LAN
      vrid: 52
      interface: eth1
      priority: 100
      virtualIps:
        - 10.0.10.1/24
      authPassword: "replace-with-shared-secret"

  conntrackSync:
    enabled: true
    interface: eth3
    mode: FTFW
    protocol: multicast
    multicastGroup: 225.0.0.50
    peerAddress: 10.0.99.1
    port: 3780

  sqliteSync:
    enabled: true
    mode: direct_stream
    syncIntervalSeconds: 5
    listenPort: 9876
    peerAddress: 10.0.99.1
    peerPort: 9876
    authToken: "replace-with-shared-secret"
    transport: mtls
    requireSignedPayloads: true
    databases:
      - /var/lib/axonwall/headscale/db.sqlite

  syncSections:
    interfaces: false
    firewall: true
    dhcp: true
    dns: true
    aliases: true
    vpn: true
    sqlite: true
    nas: true
    k3s: true
```

---

### Step 4: Validate & Apply on Both Hosts

You can apply the configuration using the **Web Console** (`/ha`), the **Neovim Super Configurator**, or **`axonwallctl`**:

1. **Web Console (`/ha`)**: Open `/ha` on Host 1 and Host 2, configure the fields (Node Role, VRID, Sync Interface `eth3`, Peer Sync IP, Sync Password, Virtual IP CIDR, VRRP Interface `eth1`, and Distributed SQLite Sync), and click **Save to ha.yaml**.
2. **Neovim Super Configurator**: Run `axonwallctl config ha` (or `axonwall-config ha`) over SSH or serial console and press `Ctrl+s` to validate and apply.
3. **`axonwallctl` CLI**: Run on Host 1 first, then Host 2:

```bash
axonwallctl validate
axonwallctl apply --no-confirm
axonwallctl confirm
```

When applied, `axonwalld` automatically generates and reloads:
- `/etc/keepalived/keepalived.conf` and `/usr/local/bin/axonwall-ha-notify` (reporting transitions over `/run/axonwall/ha.sock`)
- `/etc/conntrackd/conntrackd.conf`
- `/etc/chrony/conf.d/axonwall-ha.conf`
- Dedicated nftables input rules on `eth3` for VRRP (`proto 112`), `conntrackd` (`udp/3780`), HA Sync (`tcp/9876`), Chrony NTP (`udp/123`), and OpenLDAP `syncrepl` (`tcp/636`)

---

### Step 5: Verify PKI Enrollment, VIPs, `conntrackd` & State Sync

Within 5–15 seconds, Host 2 (`backup`) contacts Host 1 (`master`) over `10.0.99.1:9876`, submits a CSR to `/api/v1/sync/pki-enroll` to enroll in the cluster ECDSA P-256 Root CA (`/var/lib/axonwall/secrets/ha-pki/`), and upgrades replication to mutual TLS (`mtls`) with signed payloads.

Run these verification commands on Host 1 and Host 2:

```bash
# 1. Inspect live HA Sync Trust state, effective transport, and SHA-256 PKI certificate fingerprints:
sudo curl -s --unix-socket /run/axonwall/agent-api.sock \
  -H "X-Axonwall-Agent-Token: $(sudo cat /etc/axonwall/agent.token)" \
  http://localhost/v1/ha/sync-trust | jq .

# 2. Verify Floating WAN & LAN VIPs are bound on Host 1 (MASTER):
ip -br addr show dev eth0
ip -br addr show dev eth1

# 3. Check keepalived VRRP and conntrackd FTFW replication statistics:
sudo systemctl status keepalived conntrackd
sudo conntrackd -s

# 4. Verify symmetric Chrony NTP peering across eth3:
chronyc sources -v

# 5. Query the Master HA Sync Server status endpoint directly over mTLS (port 9876):
sudo curl -sk --cacert /var/lib/axonwall/secrets/ha-pki/ca.crt \
  --cert /var/lib/axonwall/secrets/ha-pki/node.crt \
  --key /var/lib/axonwall/secrets/ha-pki/node.key \
  -H "X-Axonwall-Sync-Token: replace-with-shared-secret" \
  https://10.0.99.1:9876/api/v1/sync/status | jq .
```

---

### Step 6: Optional ZFS Snapshot Replication & 2-Node K3s + OpenEBS HA

- **OpenZFS Storage Replication (`/etc/axonwall/storage.yaml`)**: Under `nas:`, set `replicateToHaPeer: true` on `datasets` and `snapshotPolicies` to stream incremental `zfs send -w -I` snapshots over `/api/v1/sync/zfs`. Replicated pools on `BACKUP` remain `readonly=on` until failover promotion.
- **2-Node K3s + OpenEBS HA (`/etc/axonwall/k3s.yaml`)**: Under `k3s:`, set `autoJoinHaPeer: true` and `openEbs.replicatedStorageEnabled: true` so the Backup node automatically retrieves the K3s cluster token from `/api/v1/sync/k3s-token` and joins over the WireGuard Flannel mesh. Optional Linux 6.9+ `enableUserNamespaces: true` (`UserNamespacesSupport=true`) and `bpfTokenProfiles` allow rootless `hostUsers: false` pods to use verified networking eBPF across both cluster nodes.
- **Non-Root HA Kubeconfig Synchronization (`axonwall-kubeconfig`)**: Axonwall configures K3s with `write-kubeconfig-mode: "0640"` and `write-kubeconfig-group: "axonwall-api"` so administrative users can run `kubectl` and `helm` without `sudo`. Export a kubeconfig bound to your floating VRRP LAN VIP (`10.0.10.1`) locally or from a remote workstation:
  ```bash
  # On either appliance as your admin user (binds server URL to Floating LAN VIP):
  axonwall-kubeconfig --vip
  # or via axonwallctl:
  axonwallctl kubeconfig --vip

  # From a remote Linux/macOS workstation over SSH (merges context into local ~/.kube/config):
  ./scripts/update-kubeconfig.sh admin@10.0.10.2 --vip -c axonwall-ha
  kubectl --context axonwall-ha get nodes -o wide
  ```
- **Operator-Managed Appliance CA Preservation**: If you install a corporate/operator-signed `/etc/axonwall/certs/ca.crt` + `hub.crt` (without placing `ca.key` on the box), `axonwall-rotate-hub-cert` automatically detects Operator-CA mode and refuses to overwrite your TLS chain during HA updates.

---

### Step 7: Test Live Failover & Maintenance Mode

1. From a LAN client using `10.0.10.1` as its default gateway, start a continuous ping (`ping -i 0.2 1.1.1.1`) and an active SSH session through the firewall.
2. **Graceful Maintenance Failover**: On Host 1, set `maintenanceMode: true` under `ha:` in `/etc/axonwall/ha.yaml` and run `axonwallctl apply` (or click **Force Failover to Peer** -> **Save to ha.yaml** in `/ha`). Verify that Host 2 immediately claims `198.51.100.1/24` and `10.0.10.1/24` with zero dropped packets.
3. **Simulated Link Failure**: With Host 1 restored as `MASTER`, run `sudo ip link set eth0 down` on Host 1. Host 2 transitions to `MASTER` within 1000ms, commits the `conntrackd` external cache into the kernel Netfilter table, and keeps the active SSH session alive without a TCP reset.
4. Run `sudo ip link set eth0 up` on Host 1 to return it to normal operation.
