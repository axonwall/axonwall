import React from 'react';
import Link from 'next/link';
import { Activity, Binary, Radio, Cpu, CheckCircle2, Zap, Layers } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Live Observability & eBPF Packet Tracing | Axonwall Documentation',
  description:
    'Real-time network observability in Axonwall: Linux NFLOG and eBPF kernel packet streams, deep protocol dissector, Server-Sent Events (SSE) API, and VictoriaMetrics time-series flow analytics.',
};

export default function ObservabilityDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Real-Time Diagnostics
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Live Observability & Packet Tracing
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Diagnose network issues instantly. Replace cumbersome offline PCAP downloads with real-time kernel packet streams powered by Linux <code className="text-emerald-400 font-mono">NFLOG</code>, <code className="text-white font-mono">eBPF</code>, and Server-Sent Events (SSE).
        </p>
      </div>

      {/* Kernel Packet Tap */}
      <section id="kernel-tap" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> Kernel Packet Stream Architecture
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Traditional BSD firewalls require administrators to start a packet capture, wait for an incident to occur, download an unwieldy <code className="text-slate-200 font-mono">.pcap</code> file, and open Wireshark on a workstation. Axonwall taps directly into the Linux netfilter subsystem via <code className="text-emerald-400 font-mono">NFLOG</code> and eBPF:
        </p>

        <CodeBlock
          title="Packet Capture Dataflow"
          language="text"
          code={`[ Network Interface (wan0 / lan0) ]
                 |
                 v
      [ Linux Kernel Netfilter ]
                 |
     NFLOG Group / eBPF Tap
                 |
                 v
   [ axonwalld Packet Streamer ]  <-- Ring-buffered zero-copy memory ring
                 |
                 v
     [ Unix Domain Socket ]
                 |
                 v
 [ Axonwall Web Controller (SSE) ]
  GET /api/v1/events/packets
                 |
                 v
 [ Live Browser Terminal / UI ]   <-- Instant interactive flow stream`}
        />
      </section>

      {/* Protocol Dissectors */}
      <section id="dissectors" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Binary className="w-6 h-6 text-emerald-400" /> Deep Protocol Dissector
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The embedded Go daemon dissector analyzes raw Ethernet frames at wire-speed and parses packet headers without writing files to disk:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">Layer 2 (Ethernet)</span>
            <p className="text-slate-400">Source & Destination MAC addresses, VLAN tags (802.1Q), and EtherType decoding.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">Layer 3 (IP / IPv6)</span>
            <p className="text-slate-400">Source/Destination IPs, TTL/Hop Limit, Type of Service (TOS), and packet length.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">Layer 4 (TCP / UDP / ICMP)</span>
            <p className="text-slate-400">Ports, sequence numbers, TCP flags (SYN, ACK, FIN, RST, PSH), and ICMP type/code.</p>
          </div>
        </div>
      </section>

      {/* SSE Streaming Endpoint */}
      <section id="sse-streaming" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Radio className="w-6 h-6 text-emerald-400" /> Server-Sent Events (SSE) API
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Clients stream live packet telemetry over HTTP/2 using Server-Sent Events. The stream supports server-side filtering by interface, protocol, IP address, and port:
        </p>

        <CodeBlock
          title="Streaming Example"
          language="bash"
          code={`# Stream live TCP packets on interface eth0 with SYN or RST flags
curl -N "https://192.168.1.1:2966/api/v1/events/packets?iface=eth0&proto=tcp"`}
        />

        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Example Event Payload (JSON)</h4>
          <CodeBlock
            title="SSE Packet Event"
            language="json"
            code={`{
  "timestamp": "2026-10-13T07:15:22.408Z",
  "interface": "wan0",
  "direction": "in",
  "ethernet": {
    "src": "00:1a:2b:3c:4d:5e",
    "dst": "52:54:00:12:34:56",
    "type": "IPv4"
  },
  "ip": {
    "version": 4,
    "src": "198.51.100.24",
    "dst": "192.168.1.1",
    "ttl": 54,
    "proto": "TCP",
    "length": 60
  },
  "tcp": {
    "srcPort": 52414,
    "dstPort": 443,
    "seq": 284192041,
    "flags": ["SYN"]
  },
  "action": "pass"
}`}
          />
        </div>
      </section>

      {/* VictoriaMetrics */}
      <section id="victoriametrics" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Activity className="w-6 h-6 text-emerald-400" /> VictoriaMetrics & Insight Flow Analytics
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          In addition to real-time packet tracing, historical flow data is stored in an embedded, resource-efficient <code className="text-slate-200">VictoriaMetrics</code> time-series database. This replaces legacy slow RRDtool graphs with interactive drill-down analytics for bandwidth usage, top talkers, and application protocols.
        </p>

        <Callout type="tip" title="Web Console Dashboards">
          Explore real-time flows in your console under <code className="text-emerald-300 font-mono">Reporting &gt; Live Flow Monitor (/reporting/flows)</code> and <code className="text-emerald-300 font-mono">Diagnostics &gt; Packet Tracer (/diagnostics/packet-tracer)</code>.
        </Callout>
      </section>
    </div>
  );
}
