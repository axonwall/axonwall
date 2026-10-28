import React from 'react';
import Link from 'next/link';
import {
  ArrowRightLeft,
  Shield,
  Zap,
  Server,
  Network,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  Database,
  Lock,
  Layers,
  Clock,
  FileCode2,
} from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'High Availability (HA), 2-Host Setup Guide & conntrackd Sync | Axonwall Documentation',
  description:
    'Complete step-by-step guide to configuring two Axonwall hosts in an enterprise Active/Passive High Availability cluster: Keepalived VRRP, conntrackd FTFW state sync, HA PKI mTLS enrollment, Chrony NTP peering, OpenLDAP syncrepl, SQLite WAL streaming, ZFS Send/Recv, and 2-node K3s HA.',
};

export default function HighAvailabilityDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Clustering, State Replication & Step-by-Step Two-Host Walkthrough
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          High Availability & Two-Host Cluster Setup
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Achieve 99.999% uptime with zero connection drops. Axonwall pairs industry-standard{' '}
          <code className="text-white font-mono">Keepalived</code> VRRPv2/v3 clustering with{' '}
          <code className="text-emerald-400 font-mono">conntrackd</code> FTFW kernel state replication, mutual-TLS
          signed configuration &amp; SQLite WAL replication, Chrony NTP peering, OpenLDAP multi-provider{' '}
          <code className="text-emerald-400 font-mono">syncrepl</code>, incremental OpenZFS snapshot streaming, and
          automated 2-node K3s joining.
        </p>

        {/* Quick Anchor Bar */}
        <div className="flex flex-wrap gap-2 pt-2">
          <a
            href="#two-host-setup"
            className="px-3 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-semibold hover:bg-emerald-500/25 transition"
          >
            Jump to 2-Host Step-by-Step Guide →
          </a>
          <a
            href="#pki-mtls"
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs font-medium hover:border-slate-700 transition"
          >
            HA PKI &amp; mTLS Security
          </a>
          <a
            href="#keepalived"
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs font-medium hover:border-slate-700 transition"
          >
            Keepalived VRRP
          </a>
          <a
            href="#conntrackd"
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs font-medium hover:border-slate-700 transition"
          >
            conntrackd FTFW Sync
          </a>
          <a
            href="#zfs-k3s-sync"
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs font-medium hover:border-slate-700 transition"
          >
            ZFS, SQLite &amp; K3s Sync
          </a>
          <a
            href="#failover"
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs font-medium hover:border-slate-700 transition"
          >
            Failover Verification
          </a>
        </div>
      </div>

      {/* HA Topology Overview */}
      <section className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Network className="w-6 h-6 text-emerald-400" /> Cluster Architecture &amp; Full-Stack Synchronization
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          An Axonwall HA cluster consists of two appliances (<code className="text-white font-mono">master</code> and{' '}
          <code className="text-white font-mono">backup</code>) connected to shared upstream WAN and downstream LAN
          broadcast domains, plus a dedicated point-to-point synchronization link (recommended on{' '}
          <code className="text-emerald-400 font-mono">eth3</code>). Beyond floating VRRP virtual IPs and kernel TCP/UDP
          connection tracking, Axonwall synchronizes the entire appliance stack across the dedicated HA link:
        </p>

        <CodeBlock
          title="High Availability Two-Host Full-Stack Topology"
          language="text"
          code={`+---------------------------------------------------------------------------------+
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
                      |  • VRRP Heartbeats (IP Proto 112)     |
                      |  • conntrackd FTFW State (UDP :3780)  |
                      |  • HA Sync & SQLite WAL (mTLS :9876)  |
                      |  • Chrony Symmetric NTP (UDP :123)    |
                      |  • OpenLDAP syncrepl (LDAPS :636)     |
                      |  • Kea DHCPv4 Hot-Standby (TCP :8001) |
                      v                                       v
       +------------------------------+        +------------------------------+
                      | eth1: 10.0.10.2/24                    | eth1: 10.0.10.3/24
                      v                                       v
+---------------------------------------------------------------------------------+
|                                 LAN Core Switch                                 |
|                Floating LAN Gateway VIP: 10.0.10.1/24 (VRID 52)                 |
+---------------------------------------------------------------------------------+`}
        />

        {/* Sync Channels Summary Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-slate-800 rounded-xl overflow-hidden">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Subsystem</th>
                <th className="p-3">Port / Protocol</th>
                <th className="p-3">Direction &amp; Mechanism</th>
                <th className="p-3">Failover Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Keepalived VRRP</td>
                <td className="p-3 font-mono text-emerald-400">IP Proto 112</td>
                <td className="p-3">VRRP sync group (<code className="font-mono">VG1</code>) tracks WAN + LAN VIPs together</td>
                <td className="p-3">Promotes VIPs in &lt;1s and invokes <code className="font-mono">axonwall-ha-notify</code></td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">conntrackd FTFW</td>
                <td className="p-3 font-mono text-emerald-400">UDP 3780</td>
                <td className="p-3">Sequence-numbered Netfilter connection tracking delta stream</td>
                <td className="p-3"><code className="font-mono">conntrackd -c</code> commits external cache into kernel table</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Axonwall HA Engine</td>
                <td className="p-3 font-mono text-emerald-400">TCP 9876 (mTLS)</td>
                <td className="p-3">Signed desired-state YAML (<code className="font-mono">/sync/state</code>) &amp; SQLite (<code className="font-mono">/sync/db</code>)</td>
                <td className="p-3">Applies firewall/NAT/DNS/VPN configs &amp; promotes SQLite DBs</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Chrony NTP Peer</td>
                <td className="p-3 font-mono text-emerald-400">UDP 123</td>
                <td className="p-3">Symmetric <code className="font-mono">peer &lt;peerIp&gt; iburst</code> time discipline</td>
                <td className="p-3">Prevents OpenLDAP CSN &amp; SQLite timestamp drift during WAN outage</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">OpenLDAP Directory</td>
                <td className="p-3 font-mono text-emerald-400">TCP 636 (LDAPS)</td>
                <td className="p-3"><code className="font-mono">refreshAndPersist</code> multi-provider <code className="font-mono">syncrepl</code> (ServerID 1 &amp; 2)</td>
                <td className="p-3">Seamless local LDAP/802.1X/VPN authentication on both nodes</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Kea DHCPv4 HA</td>
                <td className="p-3 font-mono text-emerald-400">TCP 8001</td>
                <td className="p-3"><code className="font-mono">libdhcp_ha.so</code> hot-standby lease replication</td>
                <td className="p-3">Zero duplicate IP assignments when Primary goes offline</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">OpenZFS Storage</td>
                <td className="p-3 font-mono text-emerald-400">TCP 9876 (mTLS)</td>
                <td className="p-3">Incremental <code className="font-mono">zfs send -I</code> snapshot stream (<code className="font-mono">/sync/zfs</code>)</td>
                <td className="p-3">Flips target pool <code className="font-mono">readonly=off</code> and starts SMB/NFS/iSCSI</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* STEP-BY-STEP 2-HOST SETUP GUIDE */}
      <section id="two-host-setup" className="space-y-8 pt-8 border-t border-slate-800/80">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
            STEP-BY-STEP WALKTHROUGH
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white flex items-center gap-2.5">
            <Server className="w-7 h-7 text-emerald-400" /> Step-by-Step Guide: Setting Up Two Hosts
          </h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            Follow this 8-step guide to deploy two Axonwall appliances—<code className="text-white font-mono">axonwall-fw01</code>{' '}
            (Primary <code className="text-emerald-400 font-mono">MASTER</code>) and{' '}
            <code className="text-white font-mono">axonwall-fw02</code> (Secondary{' '}
            <code className="text-amber-400 font-mono">BACKUP</code>)—into a zero-drop active/passive cluster.
          </p>
        </div>

        {/* Step 1 */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs">
              1
            </span>
            <h3 className="text-lg font-bold text-white">
              Plan Physical Cabling, Interface Names &amp; IP Addressing
            </h3>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            Both hosts must have identical interface mappings (<code className="text-white font-mono">eth0</code> for WAN,{' '}
            <code className="text-white font-mono">eth1</code> for LAN, and <code className="text-white font-mono">eth3</code>{' '}
            for the dedicated HA sync interconnect) so that synchronized nftables rulesets and VRRP definitions reference
            the exact same Linux interface names on both machines.
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border border-slate-800 rounded-xl overflow-hidden">
              <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Interface / Role</th>
                  <th className="p-3">Host 1 (axonwall-fw01)</th>
                  <th className="p-3">Host 2 (axonwall-fw02)</th>
                  <th className="p-3">Floating VRRP VIP (Shared)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300 font-mono">
                <tr>
                  <td className="p-3 font-sans font-semibold text-white">eth0 (WAN Uplink)</td>
                  <td className="p-3">198.51.100.2/24</td>
                  <td className="p-3">198.51.100.3/24</td>
                  <td className="p-3 text-emerald-400">198.51.100.1/24 (VRID 51)</td>
                </tr>
                <tr>
                  <td className="p-3 font-sans font-semibold text-white">eth1 (LAN Core)</td>
                  <td className="p-3">10.0.10.2/24</td>
                  <td className="p-3">10.0.10.3/24</td>
                  <td className="p-3 text-emerald-400">10.0.10.1/24 (VRID 52)</td>
                </tr>
                <tr>
                  <td className="p-3 font-sans font-semibold text-white">eth3 (Dedicated HA Sync)</td>
                  <td className="p-3 text-cyan-400">10.0.99.1/30</td>
                  <td className="p-3 text-cyan-400">10.0.99.2/30</td>
                  <td className="p-3 text-slate-500">None (Point-to-Point Direct)</td>
                </tr>
              </tbody>
            </table>
          </div>

          <Callout type="warning" title="Virtualization Note (Proxmox VE, KVM/libvirt, VMware ESXi)">
            If either host runs inside a hypervisor, enable <strong>MAC Spoofing / Promiscuous Mode / Forged Transmits</strong>{' '}
            on the <code className="font-mono">eth0</code> and <code className="font-mono">eth1</code> vNICs and disable any
            hypervisor firewall rules that drop IP Protocol <code className="font-mono">112</code> (VRRP) or multicast{' '}
            <code className="font-mono">224.0.0.18</code> / <code className="font-mono">225.0.0.50</code>. Connect{' '}
            <code className="font-mono">eth3</code> to an isolated host-only bridge or dedicated physical NIC port.
          </Callout>
        </div>

        {/* Step 2 */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs">
              2
            </span>
            <h3 className="text-lg font-bold text-white">
              Configure Physical &amp; Sync Interfaces on Both Hosts
            </h3>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            Each host retains its own physical interface IP addresses in{' '}
            <code className="text-emerald-400 font-mono">/etc/axonwall/interfaces.yaml</code>. By design,{' '}
            <code className="text-white font-mono">syncSections.interfaces</code> defaults to{' '}
            <code className="text-amber-400 font-mono">false</code> so Host 1 never overwrites Host 2&apos;s unique physical
            management IPs during state synchronization.
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <CodeBlock
              title="Host 1 (axonwall-fw01): /etc/axonwall/interfaces.yaml"
              language="yaml"
              code={`interfaces:
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
    description: Dedicated HA Sync Link (to fw02)`}
            />

            <CodeBlock
              title="Host 2 (axonwall-fw02): /etc/axonwall/interfaces.yaml"
              language="yaml"
              code={`interfaces:
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
    description: Dedicated HA Sync Link (to fw01)`}
            />
          </div>

          <p className="text-xs text-slate-400">
            Verify point-to-point reachability across <code className="text-white font-mono">eth3</code> before enabling
            HA: run <code className="text-emerald-400 font-mono">ping -I eth3 -c 3 10.0.99.2</code> from Host 1 and{' '}
            <code className="text-emerald-400 font-mono">ping -I eth3 -c 3 10.0.99.1</code> from Host 2.
          </p>
        </div>

        {/* Step 3 */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs">
              3
            </span>
            <h3 className="text-lg font-bold text-white">
              Configure Host 1 (<code className="font-mono text-emerald-400">axonwall-fw01</code>) as Primary MASTER
            </h3>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            Generate a shared secret on Host 1 (<code className="text-emerald-400 font-mono">openssl rand -hex 24</code>)
            for the initial PKI bootstrap and VRRP authentication, then populate{' '}
            <code className="text-emerald-400 font-mono">/etc/axonwall/ha.yaml</code> on{' '}
            <code className="text-white font-mono">axonwall-fw01</code> with{' '}
            <code className="text-emerald-400 font-mono">nodeRole: master</code> and priority{' '}
            <code className="text-emerald-400 font-mono">150</code>:
          </p>

          <CodeBlock
            title="Host 1 (axonwall-fw01): /etc/axonwall/ha.yaml"
            language="yaml"
            code={`enabled: true
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
  k3s: true`}
          />
        </div>

        {/* Step 4 */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs">
              4
            </span>
            <h3 className="text-lg font-bold text-white">
              Configure Host 2 (<code className="font-mono text-amber-400">axonwall-fw02</code>) as Secondary BACKUP
            </h3>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            On <code className="text-white font-mono">axonwall-fw02</code>, configure{' '}
            <code className="text-emerald-400 font-mono">/etc/axonwall/ha.yaml</code> with{' '}
            <code className="text-amber-400 font-mono">nodeRole: backup</code>, a lower VRRP priority (
            <code className="text-amber-400 font-mono">100</code>),{' '}
            <code className="text-cyan-400 font-mono">peerAddress: 10.0.99.1</code> pointing back to Host 1, and the exact
            same <code className="text-white font-mono">authPassword</code> / <code className="text-white font-mono">authToken</code>{' '}
            and <code className="text-white font-mono">virtualIps</code>:
          </p>

          <CodeBlock
            title="Host 2 (axonwall-fw02): /etc/axonwall/ha.yaml"
            language="yaml"
            code={`enabled: true
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
  k3s: true`}
          />
        </div>

        {/* Step 5 */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs">
              5
            </span>
            <h3 className="text-lg font-bold text-white">
              Apply Configuration via Web Console, CLI, or Neovim Super Configurator
            </h3>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            You can configure and commit the HA configuration on both hosts using any of Axonwall&apos;s three management
            interfaces—they all read and write the exact same <code className="text-emerald-400 font-mono">/etc/axonwall/ha.yaml</code>{' '}
            state and trigger the privileged <code className="text-white font-mono">axonwalld</code> compiler:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <div className="font-bold text-white text-sm flex items-center gap-1.5">
                <Layers className="w-4 h-4 text-emerald-400" /> 1. Web Console (/ha)
              </div>
              <p className="text-slate-400 leading-relaxed">
                Navigate to <Link href="/ha" className="text-emerald-400 underline hover:text-emerald-300">/ha</Link> on
                Host 1 and Host 2, toggle <strong>Enable High Availability</strong>, configure Node Role, Peer Sync IP,
                Floating VIPs, and click <strong>Save to ha.yaml</strong>.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <div className="font-bold text-white text-sm flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-emerald-400" /> 2. Neovim Super Configurator
              </div>
              <p className="text-slate-400 leading-relaxed">
                Over SSH or serial console, launch the form-driven TUI directly onto the High Availability card:
              </p>
              <code className="block p-2 rounded bg-slate-900 text-emerald-300 font-mono">
                axonwall-config ha
              </code>
              <p className="text-slate-500">
                Press <kbd className="px-1 py-0.5 rounded bg-slate-800 text-slate-300">Ctrl+s</kbd> to validate &amp;
                apply with Commit-Confirm safety.
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <div className="font-bold text-white text-sm flex items-center gap-1.5">
                <FileCode2 className="w-4 h-4 text-emerald-400" /> 3. axonwallctl CLI
              </div>
              <p className="text-slate-400 leading-relaxed">
                Validate and apply <code className="text-slate-200">/etc/axonwall/</code> on Host 1 first, then Host 2:
              </p>
              <code className="block p-2 rounded bg-slate-900 text-emerald-300 font-mono">
                axonwallctl validate /etc/axonwall &amp;&amp; axonwallctl apply /etc/axonwall --confirm-timeout 60 &amp;&amp; axonwallctl confirm
              </code>
            </div>
          </div>

          <Callout type="info" title="What Happens Automatically When You Apply HA">
            When <code className="font-mono">axonwalld</code> applies <code className="font-mono">ha.yaml</code>, it
            automatically compiles and reloads:
            <ul className="list-disc list-inside mt-1 space-y-0.5">
              <li>
                <code className="font-mono">/etc/keepalived/keepalived.conf</code> +{' '}
                <code className="font-mono">/usr/local/bin/axonwall-ha-notify</code> transition script
              </li>
              <li>
                <code className="font-mono">/etc/conntrackd/conntrackd.conf</code> (FTFW state replication over{' '}
                <code className="font-mono">eth3</code>)
              </li>
              <li>
                <code className="font-mono">/etc/chrony/conf.d/axonwall-ha.conf</code> (symmetric NTP peering over{' '}
                <code className="font-mono">eth3</code>)
              </li>
              <li>
                nftables rules permitting VRRP (<code className="font-mono">ip protocol 112</code>), conntrackd (
                <code className="font-mono">udp dport 3780</code>), HA Sync (<code className="font-mono">tcp dport 9876</code>
                ), Chrony NTP (<code className="font-mono">udp dport 123</code>), and OpenLDAP{' '}
                <code className="font-mono">syncrepl</code> (<code className="font-mono">tcp dport 636</code>) strictly
                on <code className="font-mono">iifname &quot;eth3&quot;</code>
              </li>
            </ul>
          </Callout>
        </div>

        {/* Step 6 */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs">
              6
            </span>
            <h3 className="text-lg font-bold text-white">
              Verify Automatic HA PKI Enrollment, VIPs, conntrackd &amp; State Sync
            </h3>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            Within 5–15 seconds of enabling HA on both hosts, Host 2 (<code className="text-white font-mono">backup</code>)
            contacts Host 1 (<code className="text-white font-mono">master</code>) on{' '}
            <code className="text-emerald-400 font-mono">10.0.99.1:9876</code> using the bootstrap{' '}
            <code className="text-white font-mono">authPassword</code>, enrolls in the cluster ECDSA P-256 Root CA (
            <code className="text-emerald-400 font-mono">/var/lib/axonwall/secrets/ha-pki/</code>), and upgrades the
            replication transport to mutual TLS (<code className="text-emerald-400 font-mono">mtls</code>) with signed
            payload enforcement. Run the following checks to confirm healthy cluster convergence:
          </p>

          <CodeBlock
            title="Cluster Verification Checklist (Run on Host 1 & Host 2)"
            language="bash"
            code={`# 1. Verify HA status, peer reachability, and matching SHA-256 PKI fingerprints:
curl -s --unix-socket /run/axonwalld/agent.sock http://localhost/v1/ha/status | jq .

# 2. Confirm Host 1 (MASTER) holds the Floating WAN & LAN VIPs (198.51.100.1 & 10.0.10.1):
ip -br addr show dev eth0
ip -br addr show dev eth1

# 3. Verify Keepalived VRRP sync group (VG1) and conntrackd FTFW state cache:
systemctl status keepalived conntrackd
conntrackd -s

# 4. Verify symmetric Chrony NTP peering across eth3:
chronyc sources -v

# 5. Trigger an immediate manual state + SQLite sync from the Master node:
curl -s -X POST --unix-socket /run/axonwalld/agent.sock http://localhost/v1/ha/sync | jq .`}
          />

          <p className="text-xs text-slate-400">
            In the Web Console under <Link href="/ha" className="text-emerald-400 underline">/ha</Link>, check the{' '}
            <strong>Cluster PKI &amp; Transport Security</strong> card: both the <em>CA Fingerprint</em> and{' '}
            <em>Peer CA Fingerprint</em> badges will turn emerald green (<code className="text-emerald-400 font-mono">Match</code>)
            once PKI enrollment completes.
          </p>
        </div>

        {/* Step 7 */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs">
              7
            </span>
            <h3 className="text-lg font-bold text-white">
              (Optional) Enable ZFS Snapshot Replication &amp; 2-Node K3s + OpenEBS HA
            </h3>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            If your two hosts also run the optional <strong>OpenZFS Storage</strong> or{' '}
            <strong>K3s Kubernetes</strong> workloads, enable their HA peer integration so storage pools and container
            volumes fail over alongside the firewall:
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <CodeBlock
              title="ZFS HA Replication (/etc/axonwall/nas.yaml)"
              language="yaml"
              code={`enabled: true
pools:
  - name: tank
    topology: mirror
    disks: ["/dev/nvme0n1", "/dev/nvme1n1"]
    compression: zstd
    replicateToHaPeer: true
datasets:
  - name: tank/shares
    mountpoint: /srv/tank/shares
    quota: 2T
    replicateToHaPeer: true`}
            />

            <CodeBlock
              title="2-Node K3s + OpenEBS HA (/etc/axonwall/k3s.yaml)"
              language="yaml"
              code={`enabled: true
role: server
clusterCidr: 10.42.0.0/16
serviceCidr: 10.43.0.0/16
flannelBackend: wireguard-native
autoJoinHaPeer: true
openebs:
  enabled: true
  engine: mayastor
  defaultStorageClass: openebs-mayastor
  zfsPoolName: tank`}
            />
          </div>
        </div>

        {/* Step 8 */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center gap-3">
            <span className="flex items-center justify-center w-7 h-7 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs">
              8
            </span>
            <h3 className="text-lg font-bold text-white">
              Test Live Failover &amp; Graceful Maintenance Mode
            </h3>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            Before placing the cluster into production, validate both graceful maintenance demotion and abrupt hardware
            failover while keeping a continuous SSH session and <code className="text-white font-mono">ping</code> running
            from a LAN workstation through the <code className="text-emerald-400 font-mono">10.0.10.1</code> floating
            gateway VIP:
          </p>

          <CodeBlock
            title="Live Failover & Preemption Validation"
            language="bash"
            code={`# From a LAN client routed through VIP 10.0.10.1, start an active SSH & ping test:
ping -i 0.2 1.1.1.1

# TEST A — Graceful Maintenance Mode (on Host 1 / axonwall-fw01):
# Toggle "Maintenance Mode" in /ha (or set maintenanceMode: true in ha.yaml).
# Keepalived lowers effective priority and shifts VIPs + conntrack state to Host 2 with 0 packet loss.

# Verify Host 2 (axonwall-fw02) now owns 198.51.100.1 and 10.0.10.1:
ssh admin@10.0.10.3 "ip -br addr show dev eth0; ip -br addr show dev eth1"

# TEST B — Unplanned Link / Power Loss Simulation (on Host 1 / axonwall-fw01):
# Bring down the WAN link or stop keepalived on Host 1:
sudo ip link set eth0 down
# Host 2 transitions to MASTER within 1000ms, commits conntrackd cache, and active TCP/SSH stays up.

# Restore Host 1 WAN link (with preempt: true, Host 1 smoothly reclaims MASTER):
sudo ip link set eth0 up`}
          />
        </div>
      </section>

      {/* HA PKI & mTLS Transport */}
      <section id="pki-mtls" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-emerald-400" /> Cluster PKI, Mutual TLS &amp; Signed State Payloads
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall never transmits configuration state or SQLite WAL frames in cleartext. The Go daemon (
          <code className="text-emerald-400 font-mono">axonwalld</code>) maintains a dedicated ECDSA P-256 High
          Availability PKI hierarchy stored in{' '}
          <code className="text-emerald-400 font-mono">/var/lib/axonwall/secrets/ha-pki/</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Automated PKI Bootstrap &amp; Rotation</h3>
            <p className="text-slate-400 leading-relaxed">
              The Primary node generates a 10-year ECDSA P-256 Root CA (<code className="text-slate-200">ca.crt</code>)
              and node certificate (<code className="text-slate-200">node.crt</code>) bound to the cluster&apos;s sync IP
              Subject Alternative Names (SANs). When the Backup node joins using the shared{' '}
              <code className="text-slate-200">authPassword</code>, it automatically pulls the cluster CA bundle via{' '}
              <code className="text-emerald-400 font-mono">/api/v1/sync/pki</code>. Operators can rotate certificates at
              any time from the <Link href="/ha" className="text-emerald-400 underline">/ha</Link> console.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Cryptographic Payload Signing</h3>
            <p className="text-slate-400 leading-relaxed">
              With <code className="text-emerald-400 font-mono">requireSignedPayloads: true</code>, every{' '}
              <code className="text-slate-200">/api/v1/sync/state</code> and{' '}
              <code className="text-slate-200">/api/v1/sync/db</code> payload is signed with the sender&apos;s ECDSA
              private key and verified against the pinned HA Root CA before being written to disk or applied to the
              Backup node.
            </p>
          </div>
        </div>
      </section>

      {/* Keepalived VRRP */}
      <section id="keepalived" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ArrowRightLeft className="w-6 h-6 text-emerald-400" /> Keepalived VRRP v2/v3 Clustering
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Keepalived manages virtual IP address failover according to RFC 5798 (VRRPv3). Axonwall groups all floating
          VIPs into a unified <code className="text-emerald-400 font-mono">vrrp_sync_group VG1</code> so that if either
          the WAN uplink (<code className="text-white font-mono">eth0</code>) or LAN trunk (
          <code className="text-white font-mono">eth1</code>) loses carrier, all virtual IPs fail over together—preventing
          asymmetric blackhole routing.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">VRRP Failover Triggers</h3>
            <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
              <li>Loss of physical link carrier on WAN or LAN ports (<code className="font-mono">track_interface</code>)</li>
              <li>Unresponsive <code className="font-mono">axonwalld</code> health probe (<code className="font-mono">chk_axonwalld</code> weight -50)</li>
              <li>Manual maintenance failover initiated from Web Console (<code className="font-mono">maintenanceMode: true</code>)</li>
              <li>Power loss or kernel watchdog reset on the active Master</li>
            </ul>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Transition Orchestration Hook</h3>
            <p className="text-slate-400 leading-relaxed">
              On state change, Keepalived executes <code className="text-slate-200">/usr/local/bin/axonwall-ha-notify</code>{' '}
              to commit the <code className="text-slate-200">conntrackd</code> external cache, flip OpenZFS pool{' '}
              <code className="text-slate-200">readonly</code> flags, and start or stop <code className="text-slate-200">headscale</code>{' '}
              to prevent dual-active split-brain.
            </p>
          </div>
        </div>
      </section>

      {/* conntrackd Stateful Connection Sync */}
      <section id="conntrackd" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Server className="w-6 h-6 text-emerald-400" /> conntrackd Stateful Replication Engine
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Without state synchronization, a VRRP failover forces all active TCP connections to reset, cutting off active
          SSH sessions, dropping VoIP calls, and aborting file downloads. Axonwall integrates{' '}
          <code className="text-emerald-400 font-mono">conntrackd</code> to replicate the kernel Netfilter state table
          seamlessly across <code className="text-white font-mono">eth3</code>.
        </p>

        <div className="space-y-4">
          <h3 className="text-base font-semibold text-white">FTFW Protocol (Fault-Tolerant Framework)</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Unlike BSD <code className="text-slate-200">pfsync</code> which uses simple unacknowledged UDP broadcasts, the
            Netfilter FTFW protocol implements sequence-numbered state transactions, explicit sequence acknowledgment, and
            reliable retransmission of lost state deltas over either multicast (<code className="text-slate-200">225.0.0.50:3780</code>)
            or point-to-point unicast UDP.
          </p>

          <CodeBlock
            title="/etc/conntrackd/conntrackd.conf (Compiled by Axonwall)"
            language="text"
            code={`Sync {
  Mode FTFW {
    ResendQueueSize 131072
    CommitTimeout 180
    PurgeTimeout 60
    ACKWindowSize 300
    DisableExternalCache Off
  }

  # Dedicated synchronization interface (eth3)
  Multicast {
    IPv4_address 225.0.0.50
    Group 3780
    IPv4_interface 10.0.99.1
    Interface eth3
    SndSocketBuffer 12582912
    RcvSocketBuffer 12582912
    Checksum on
  }
}

General {
  Systemd on
  HashSize 32768
  HashLimit 131072
  SocketFile /var/run/conntrackd.ctl
  LockFile /var/lock/conntrack.lock
  LogFile off
  Syslog on

  Filter From Userspace {
    Protocol Accept {
      TCP
      UDP
      ICMP
    }
    Address Ignore {
      IPv4_address 127.0.0.1
      IPv4_address 10.0.99.1
      IPv4_address 10.0.99.2
    }
  }
}`}
          />
        </div>
      </section>

      {/* ZFS, SQLite, NTP, LDAP & K3s Sync */}
      <section id="zfs-k3s-sync" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-emerald-400" /> SQLite WAL, Chrony NTP, OpenLDAP, ZFS &amp; K3s Replication
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall extends High Availability beyond L3/L4 packet filtering so stateful control-plane services survive
          node failure without data loss or split-brain corruption:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm flex items-center gap-1.5">
              <Database className="w-4 h-4 text-emerald-400" /> SQLite Atomic Snapshot &amp; WAL Stream
            </h3>
            <p className="text-slate-400 leading-relaxed">
              The Primary node creates consistent atomic snapshots (<code className="text-slate-200">VACUUM INTO</code> /
              WAL checkpoint) of <code className="text-slate-200">/var/lib/axonwall/state.db</code>,{' '}
              <code className="text-slate-200">/var/lib/headscale/db.sqlite</code>, and{' '}
              <code className="text-slate-200">/var/lib/crowdsec/data/crowdsec.db</code> and streams them over mTLS to
              the Backup node every <code className="text-slate-200">syncIntervalSec</code> seconds (or continuously via
              Litestream).
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm flex items-center gap-1.5">
              <Clock className="w-4 h-4 text-emerald-400" /> Chrony Symmetric NTP &amp; OpenLDAP syncrepl
            </h3>
            <p className="text-slate-400 leading-relaxed">
              OpenLDAP multi-provider <code className="text-slate-200">syncrepl</code> relies on Change Sequence Numbers
              (CSNs) with microsecond timestamps. Axonwall automatically configures Chrony symmetric peering (
              <code className="text-slate-200">peer &lt;peerAddress&gt; iburst</code>) on <code className="text-slate-200">eth3</code>{' '}
              so both nodes maintain sub-millisecond clock alignment even if upstream internet NTP servers are unreachable.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm flex items-center gap-1.5">
              <Server className="w-4 h-4 text-emerald-400" /> Incremental OpenZFS Send/Recv
            </h3>
            <p className="text-slate-400 leading-relaxed">
              Pools and datasets marked with <code className="text-emerald-400 font-mono">replicateToHaPeer: true</code>{' '}
              are snapshotted (<code className="text-slate-200">@axonwall_ha_&lt;epoch&gt;</code>) and streamed via{' '}
              <code className="text-slate-200">zfs send -I | zfs recv -F -u</code> to the Backup node. On the Backup node,
              replicated pools stay <code className="text-slate-200">readonly=on</code> until Keepalived promotes the node
              to <code className="text-emerald-400 font-mono">MASTER</code>.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-emerald-400" /> Automated 2-Node K3s Token Exchange
            </h3>
            <p className="text-slate-400 leading-relaxed">
              When <code className="text-emerald-400 font-mono">autoJoinHaPeer: true</code> is set in{' '}
              <code className="text-slate-200">k3s.yaml</code>, the Backup node securely fetches the K3s node join token
              from <code className="text-slate-200">/api/v1/sync/k3s-token</code> over mTLS and joins the cluster over the
              WireGuard Flannel mesh, pairing with OpenEBS Mayastor NVMe-oF synchronous volume replication.
            </p>
          </div>
        </div>
      </section>

      {/* Zero-Drop Failover Benchmarks */}
      <section id="failover" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Zap className="w-6 h-6 text-emerald-400" /> Failover Latency &amp; Connection Continuity
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          During an abrupt power failure on the Master appliance, the Backup node detects the missed VRRP advertisement
          within 1000ms, transitions to <code className="text-emerald-400 font-semibold">MASTER</code>, and flushes the
          external state cache directly into the Linux Netfilter kernel table:
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-slate-800 rounded-xl overflow-hidden">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Protocol / Session Type</th>
                <th className="p-3">Behavior on Legacy pfSense/OPNsense</th>
                <th className="p-3">Behavior on Axonwall HA</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">Active TCP (SSH, HTTPS, Database)</td>
                <td className="p-3 text-rose-400">Broken on packet drop / retransmission limit</td>
                <td className="p-3 text-emerald-400 font-medium">Zero-drop; seamlessly continues without RST</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">VoIP Calls (SIP Signaling / RTP Audio)</td>
                <td className="p-3 text-rose-400">Audio drops; SIP session terminates</td>
                <td className="p-3 text-emerald-400 font-medium">Sub-second jitter; call remains connected</td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-3 font-semibold text-white">WireGuard Site-to-Site Tunnels</td>
                <td className="p-3 text-rose-400">Requires 30s re-handshake</td>
                <td className="p-3 text-emerald-400 font-medium">Instantaneous handover; zero packet drop</td>
              </tr>
            </tbody>
          </table>
        </div>

        <Callout type="tip" title="Sysctl Performance Tuning">
          Axonwall automatically tunes{' '}
          <code className="font-mono text-emerald-300">net.netfilter.nf_conntrack_tcp_timeout_established = 86400</code>{' '}
          and expands <code className="font-mono text-emerald-300">nf_conntrack_max = 2097152</code> to handle enterprise
          connection tables up to 2 million concurrent flows without memory thrashing.
        </Callout>
      </section>
    </div>
  );
}
