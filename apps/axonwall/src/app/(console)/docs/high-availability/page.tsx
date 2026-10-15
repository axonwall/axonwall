import React from 'react';
import Link from 'next/link';
import { ArrowRightLeft, Shield, Zap, Server, Network, CheckCircle2, AlertTriangle } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'High Availability (HA) & conntrackd Sync | Axonwall Documentation',
  description:
    'Complete guide to enterprise High Availability in Axonwall: Keepalived VRRP clustering, conntrackd stateful connection synchronization via FTFW multicast and unicast, and zero-drop failover.',
};

export default function HighAvailabilityDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Clustering & Resiliency
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          High Availability & State Synchronization
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Achieve 99.999% uptime with zero connection drops. Axonwall pairs industry-standard <code className="text-white font-mono">Keepalived</code> VRRP clustering with <code className="text-emerald-400 font-mono">conntrackd</code> state replication across dedicated FTFW sync links.
        </p>
      </div>

      {/* HA Topology Overview */}
      <section className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Network className="w-6 h-6 text-emerald-400" /> Cluster Architecture & Full-State Synchronization
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Axonwall implements comprehensive 2-node High Availability. Beyond VRRP virtual IPs and conntrackd TCP/UDP state replication, Axonwall replicates all configuration state (<code className="text-emerald-400 font-mono">/api/v1/sync/state</code>), SQLite databases (Headscale, CrowdSec), incremental OpenZFS dataset snapshots (<code className="text-emerald-400 font-mono">/api/v1/sync/zfs</code>), and automated K3s cluster join tokens (<code className="text-emerald-400 font-mono">/api/v1/sync/k3s-token</code>).
        </p>

        <CodeBlock
          title="High Availability Full-Stack Sync Topology"
          language="text"
          code={`+-------------------------------------------------------------------------+
|                              WAN Switch / ISP                           |
+-------------------------------------------------------------------------+
                    |                                 |
                    | (VIP: 198.51.100.1 / VRID 51)   |
                    v                                 v
       +-------------------------+       +-------------------------+
       |   Axonwall Node 1       |       |   Axonwall Node 2       |
       |     [ MASTER ]          |       |     [ BACKUP ]          |
       |  VRRP Priority: 110     |       |  VRRP Priority: 100     |
       |  ZFS: Read-Write        |       |  ZFS: Readonly Target   |
       +-------------------------+       +-------------------------+
                    ^                                 ^
                    |      Dedicated Sync Link (eth3) |
                    +<===============================>+
                    | 1. conntrackd FTFW Kernel Sync  |
                    | 2. SQLite DB Stream (:9876)     |
                    | 3. ZFS Send/Recv Deltas (:8443) |
                    | 4. K3s Token & OpenEBS NVMe-oF  |
                    v                                 v
       +-------------------------+       +-------------------------+
                    |                                 |
                    | (VIP: 10.0.0.1 / VRID 52)       |
                    v                                 v
+-------------------------------------------------------------------------+
|                              LAN Core Switch                            |
+-------------------------------------------------------------------------+`}
        />
      </section>

      {/* Keepalived VRRP */}
      <section id="keepalived" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ArrowRightLeft className="w-6 h-6 text-emerald-400" /> Keepalived VRRP v2/v3 Clustering
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Keepalived manages virtual IP address failover according to RFC 5798 (VRRPv3). Axonwall supports both standard multicast heartbeats and point-to-point unicast peer configurations for cloud environments where multicast packets are dropped.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">VRRP Failover Triggers</h3>
            <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
              <li>Loss of physical link carrier on WAN or LAN ports</li>
              <li>Failure of gateway health-check ping probes</li>
              <li>Manual maintenance failover initiated from Web Console</li>
              <li>Unresponsive daemon or kernel panic watchdog trigger</li>
            </ul>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Virtual MAC (VMAC) Support</h3>
            <p className="text-slate-400 leading-relaxed">
              Axonwall binds each VRRP instance to a virtual MAC address (<code className="text-slate-200">00:00:5E:00:01:XX</code>), eliminating the need for gratuitous ARP updates on client workstations during node failover.
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
          Without state synchronization, a VRRP failover forces all active TCP connections to reset, cutting off active SSH sessions, dropping VoIP calls, and aborting file downloads. Axonwall integrates <code className="text-emerald-400 font-mono">conntrackd</code> to replicate the kernel Netfilter state table seamlessly.
        </p>

        <div className="space-y-4">
          <h3 className="text-base font-semibold text-white">FTFW Protocol (Fault-Tolerant Framework)</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Unlike BSD <code className="text-slate-200">pfsync</code> which uses simple unacknowledged UDP broadcasts, the Netfilter FTFW protocol implements sequence-numbered state transactions, sequence acknowledgment, and reliable retransmission of lost state deltas.
          </p>

          <CodeBlock
            title="/etc/conntrackd/conntrackd.conf"
            language="text"
            code={`Sync {
  Mode FTFW {
    ResendQueueSize 131072
    CommitTimeout 180
    PurgeTimeout 60
  }

  # Dedicated synchronization interface
  Multicast {
    IPv4_address 225.0.0.50
    Group 3780
    IPv4_interface eth3
    Interface eth3
    SndSocketBuffer 12582912
    RcvSocketBuffer 12582912
    Checksum on
  }
}

General {
  Systemd on
  SocketFile /run/conntrackd.ctl
  LockFile /run/conntrackd.lock
  LogFile off
  Syslog on
}`}
          />
        </div>
      </section>

      {/* Zero-Drop Failover Benchmarks */}
      <section id="failover" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Zap className="w-6 h-6 text-emerald-400" /> Failover Latency & Connection Continuity
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          During an abrupt power failure on the Master appliance, the Backup node detects the missed VRRP advertisement within 1000ms, transitions to <code className="text-emerald-400 font-semibold">MASTER</code>, and flushes the external state cache directly into the Linux Netfilter kernel table:
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
          Axonwall automatically tunes <code className="font-mono text-emerald-300">net.netfilter.nf_conntrack_tcp_timeout_established = 86400</code> and expands <code className="font-mono text-emerald-300">nf_conntrack_max = 2097152</code> to handle enterprise connection tables up to 2 million concurrent flows without memory thrashing.
        </Callout>
      </section>
    </div>
  );
}
