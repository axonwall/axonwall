# Axonwall High Availability (HA) — Two-Host Cluster Setup Guide

Axonwall provides enterprise-grade **Active/Passive High Availability (HA)** with sub-second failover and zero TCP/UDP/WireGuard connection drops. Beyond floating VRRP Virtual IPs (`keepalived`) and kernel connection-tracking state replication (`conntrackd` FTFW), Axonwall synchronizes the entire appliance stack over a dedicated point-to-point sync link (`eth3`):

| Subsystem | Protocol / Port | Purpose & Failover Behavior |
| :--- | :--- | :--- |
| **Keepalived VRRPv2/v3** | IP Protocol `112` | Groups all WAN & LAN Floating VIPs into `vrrp_sync_group VG1` and invokes `/usr/local/bin/axonwall-ha-notify` on role transition |
| **conntrackd FTFW** | UDP `3780` | Sequence-numbered, acknowledged Linux Netfilter state table replication (`conntrackd -c` commits cache on promotion) |
| **Axonwall HA Engine** | TCP `9876` (`mTLS`) | Cryptographically signed desired-state configuration (`/api/v1/sync/state`) and atomic SQLite WAL/DB streaming (`/api/v1/sync/db`) |
| **HA Cluster PKI** | TCP `9876` (`ECDSA P-256`) | Automatic 10-year Root CA & node certificate bootstrap (`/var/lib/axonwall/secrets/ha-pki/`) with SHA-256 fingerprint pinning |
| **Chrony Symmetric NTP** | UDP `123` | Peer-to-peer clock discipline (`peer <peerIp> iburst`) so OpenLDAP CSNs and SQLite timestamps never drift during WAN outages |
| **OpenLDAP `syncrepl`** | TCP `636` (`LDAPS`) | Multi-provider `refreshAndPersist` directory replication (`ServerID 1` on Master, `ServerID 2` on Backup) |
| **Kea DHCPv4 HA** | TCP `8001` | `libdhcp_ha.so` hot-standby DHCP lease synchronization |
| **OpenZFS Storage** | TCP `9876` (`mTLS`) | Incremental `zfs send -I \| zfs recv -F -u` snapshot streaming; Backup keeps pools `readonly=on` until promoted to `MASTER` |
| **2-Node K3s + OpenEBS** | TCP `9876` / `6443` | Automated K3s cluster token exchange (`/api/v1/sync/k3s-token`) over WireGuard Flannel mesh + OpenEBS Mayastor NVMe-oF |

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

| Interface | Role | Host 1 (`axonwall-fw01`) | Host 2 (`axonwall-fw02`) | Floating VRRP VIP (Shared) |
| :--- | :--- | :--- | :--- | :--- |
| `eth0` | WAN Uplink | `198.51.100.2/24` | `198.51.100.3/24` | `198.51.100.1/24` (`VRID 51`) |
| `eth1` | LAN Core | `10.0.10.2/24` | `10.0.10.3/24` | `10.0.10.1/24` (`VRID 52`) |
| `eth3` | Dedicated HA Sync | `10.0.99.1/30` | `10.0.99.2/30` | None (Direct Point-to-Point) |

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
  - name: eth0
    role: wan
    enabled: true
    address: 198.51.100.2/24
    gateway: 198.51.100.254
    description: Primary WAN Uplink (Host 1)

  - name: eth1
    role: lan
    enabled: true
    address: 10.0.10.2/24
    description: Core LAN Interface (Host 1)

  - name: eth3
    role: opt
    enabled: true
    address: 10.0.99.1/30
    mtu: 9000
    description: Dedicated HA Sync Link (to fw02)
```

#### Host 2 (`axonwall-fw02`) — `/etc/axonwall/interfaces.yaml`

```yaml
interfaces:
  - name: eth0
    role: wan
    enabled: true
    address: 198.51.100.3/24
    gateway: 198.51.100.254
    description: Secondary WAN Uplink (Host 2)

  - name: eth1
    role: lan
    enabled: true
    address: 10.0.10.3/24
    description: Core LAN Interface (Host 2)

  - name: eth3
    role: opt
    enabled: true
    address: 10.0.99.2/30
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

Generate a shared secret on Host 1 (`openssl rand -hex 24`) for VRRP authentication and initial HA PKI bootstrap, then create `/etc/axonwall/ha.yaml` on **`axonwall-fw01`**:

```yaml
enabled: true
nodeRole: master
syncInterface: eth3
peerAddress: 10.0.99.2
virtualRouterId: 51
priority: 150
preempt: true
advertInterval: 1
authPassword: "replace-with-shared-secret"
maintenanceMode: false

virtualIps:
  - interface: eth0
    address: 198.51.100.1/24
    vrid: 51
    description: Floating WAN VIP
  - interface: eth1
    address: 10.0.10.1/24
    vrid: 52
    description: Floating LAN Default Gateway VIP

conntrackSync:
  enabled: true
  mode: ftfw
  protocol: multicast
  multicastAddress: 225.0.0.50
  port: 3780

sqliteSync:
  enabled: true
  engine: direct_stream
  peerEndpoint: "https://10.0.99.2:9876/api/v1/sync"
  syncIntervalSec: 5
  authToken: "replace-with-shared-secret"
  transport: mtls
  requireSignedPayloads: true
  databases:
    - /var/lib/axonwall/state.db
    - /var/lib/headscale/db.sqlite
    - /var/lib/crowdsec/data/crowdsec.db

syncSections:
  firewall: true
  dhcp: true
  dns: true
  aliases: true
  vpn: true
  interfaces: false
  sqlite: true
  nas: true
  k3s: true
```

---

### Step 3: Configure Host 2 (`axonwall-fw02`) as Secondary `BACKUP`

Create `/etc/axonwall/ha.yaml` on **`axonwall-fw02`** with `nodeRole: backup`, `priority: 100`, `peerAddress: 10.0.99.1`, and the matching `authPassword` / `authToken`:

```yaml
enabled: true
nodeRole: backup
syncInterface: eth3
peerAddress: 10.0.99.1
virtualRouterId: 51
priority: 100
preempt: true
advertInterval: 1
authPassword: "replace-with-shared-secret"
maintenanceMode: false

virtualIps:
  - interface: eth0
    address: 198.51.100.1/24
    vrid: 51
    description: Floating WAN VIP
  - interface: eth1
    address: 10.0.10.1/24
    vrid: 52
    description: Floating LAN Default Gateway VIP

conntrackSync:
  enabled: true
  mode: ftfw
  protocol: multicast
  multicastAddress: 225.0.0.50
  port: 3780

sqliteSync:
  enabled: true
  engine: direct_stream
  peerEndpoint: "https://10.0.99.1:9876/api/v1/sync"
  syncIntervalSec: 5
  authToken: "replace-with-shared-secret"
  transport: mtls
  requireSignedPayloads: true
  databases:
    - /var/lib/axonwall/state.db
    - /var/lib/headscale/db.sqlite
    - /var/lib/crowdsec/data/crowdsec.db

syncSections:
  firewall: true
  dhcp: true
  dns: true
  aliases: true
  vpn: true
  interfaces: false
  sqlite: true
  nas: true
  k3s: true
```

---

### Step 4: Validate & Apply on Both Hosts

You can apply the configuration using the **Web Console** (`/ha`), the **Neovim Super Configurator**, or **`axonwallctl`**:

1. **Web Console (`/ha`)**: Open `/ha` on Host 1 and Host 2, configure the fields, and click **Save to ha.yaml**.
2. **Neovim Super Configurator**: Run `axonwall-config ha` over SSH or serial console and press `Ctrl+s` to validate and apply.
3. **`axonwallctl` CLI**: Run on Host 1 first, then Host 2:

```bash
axonwallctl validate /etc/axonwall
axonwallctl apply /etc/axonwall --confirm-timeout 60
axonwallctl confirm
```

When applied, `axonwalld` automatically generates and reloads:
- `/etc/keepalived/keepalived.conf` and `/usr/local/bin/axonwall-ha-notify`
- `/etc/conntrackd/conntrackd.conf`
- `/etc/chrony/conf.d/axonwall-ha.conf`
- Dedicated nftables input rules on `eth3` for VRRP (`proto 112`), `conntrackd` (`udp/3780`), HA Sync (`tcp/9876`), Chrony NTP (`udp/123`), and OpenLDAP `syncrepl` (`tcp/636`)

---

### Step 5: Verify PKI Enrollment, VIPs, `conntrackd` & State Sync

Within 5–15 seconds, Host 2 (`backup`) contacts Host 1 (`master`) over `10.0.99.1:9876`, enrolls in the cluster ECDSA P-256 Root CA (`/var/lib/axonwall/secrets/ha-pki/`), and upgrades replication to mutual TLS (`mtls`) with signed payloads.

Run these verification commands on Host 1 and Host 2:

```bash
# 1. Inspect HA sync status, peer reachability, and SHA-256 PKI certificate fingerprints:
curl -s --unix-socket /run/axonwalld/agent.sock http://localhost/v1/ha/status | jq .

# 2. Verify Floating WAN & LAN VIPs are bound on Host 1 (MASTER):
ip -br addr show dev eth0
ip -br addr show dev eth1

# 3. Check keepalived VRRP and conntrackd FTFW replication statistics:
systemctl status keepalived conntrackd
conntrackd -s

# 4. Verify symmetric Chrony NTP peering across eth3:
chronyc sources -v

# 5. Trigger an immediate manual state + SQLite sync from Host 1:
curl -s -X POST --unix-socket /run/axonwalld/agent.sock http://localhost/v1/ha/sync | jq .
```

---

### Step 6: Optional ZFS Snapshot Replication & 2-Node K3s + OpenEBS HA

- **OpenZFS Storage Replication (`/etc/axonwall/nas.yaml`)**: Set `replicateToHaPeer: true` on pools/datasets to stream incremental `zfs send -I` snapshots over the HA channel. Replicated pools on `BACKUP` remain `readonly=on` until failover promotion.
- **2-Node K3s + OpenEBS HA (`/etc/axonwall/k3s.yaml`)**: Set `autoJoinHaPeer: true` so the Backup node automatically retrieves the K3s cluster token from `/api/v1/sync/k3s-token` and joins over the WireGuard Flannel mesh.

---

### Step 7: Test Live Failover & Maintenance Mode

1. From a LAN client using `10.0.10.1` as its default gateway, start a continuous ping (`ping -i 0.2 1.1.1.1`) and an active SSH session through the firewall.
2. **Graceful Maintenance Failover**: On Host 1, enable `maintenanceMode: true` (or toggle Maintenance Mode in `/ha`). Verify that Host 2 immediately claims `198.51.100.1/24` and `10.0.10.1/24` with zero dropped packets.
3. **Simulated Link Failure**: With Host 1 restored as `MASTER`, run `sudo ip link set eth0 down` on Host 1. Host 2 transitions to `MASTER` within 1000ms, commits the `conntrackd` external cache into the kernel Netfilter table, and keeps the active SSH session alive without a TCP reset.
4. Run `sudo ip link set eth0 up` on Host 1 to return it to normal operation.
