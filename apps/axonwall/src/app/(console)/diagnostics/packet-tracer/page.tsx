'use client';

import { useState } from 'react';
import { Play, CheckCircle2, XCircle, ArrowRight, Shield, Layers, HelpCircle } from 'lucide-react';
import { simulatePacket, type SimulationResult } from '@axonwall/lib/sim';
import type { DesiredState, PacketTracerQuery } from '@axonwall/lib/schemas';

const SAMPLE_SIM_STATE: DesiredState = {
  version: 1,
  system: {
    hostname: 'axonwall-core',
    domain: 'axonwall.local',
    dnsServers: ['1.1.1.1'],
    timezone: 'UTC',
    flowtableOffload: true,
    antiLockout: {
      enabled: true,
      interface: 'lan',
      ports: [22, 80, 443, 3000],
    },
  },
  interfaces: [
    { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, mtu: 1500, description: 'WAN Fiber' },
    { name: 'lan', device: 'eth1', type: 'static', enabled: true, ipv4Address: '192.168.100.1/24', mtu: 1500, description: 'Corporate LAN' },
  ],
  vlans: [],
  bridges: [],
  bonds: [],
  virtualIps: [],
  vrfs: [],
  aliases: [
    {
      name: 'malicious_hosts',
      type: 'host',
      entries: ['198.51.100.99', '203.0.113.88'],
      description: 'Threat Intelligence Blocklist',
      enabled: true,
    },
  ],
  rules: [
    {
      id: 'r-block-threats',
      action: 'block',
      direction: 'in',
      interface: 'lan',
      quick: true,
      protocol: 'any',
      source: 'any',
      sourcePort: '',
      destination: '$malicious_hosts',
      destinationPort: '',
      log: true,
      enabled: true,
      description: 'Block Traffic to Threat Intelligence IPs',
      sortOrder: 10,
    },
    {
      id: 'r-allow-https',
      action: 'pass',
      direction: 'in',
      interface: 'lan',
      quick: true,
      protocol: 'tcp',
      source: '192.168.100.0/24',
      sourcePort: '',
      destination: 'any',
      destinationPort: '443',
      gatewayGroup: 'WAN_Failover_Tier1_Tier2',
      log: false,
      enabled: true,
      description: 'Allow LAN to HTTPS with Multi-WAN Failover',
      sortOrder: 20,
    },
    {
      id: 'r-allow-dns',
      action: 'pass',
      direction: 'in',
      interface: 'lan',
      quick: true,
      protocol: 'udp',
      source: '192.168.100.0/24',
      sourcePort: '',
      destination: 'any',
      destinationPort: '53',
      log: false,
      enabled: true,
      description: 'Allow LAN DNS Queries to Unbound',
      sortOrder: 30,
    },
  ],
  nat: [
    {
      id: 'dnat-http',
      type: 'dnat',
      interface: 'wan',
      protocol: 'tcp',
      source: 'any',
      sourcePort: '',
      destination: 'wan_ip',
      destinationPort: '8443',
      targetIp: '192.168.100.50',
      targetPort: '443',
      log: false,
      enabled: true,
      description: 'Port Forward WAN 8443 to Internal Web App 443',
      sortOrder: 10,
    },
    {
      id: 'snat-wan',
      type: 'masquerade',
      interface: 'wan',
      protocol: 'any',
      source: 'any',
      sourcePort: '',
      destination: 'any',
      destinationPort: '',
      log: false,
      enabled: true,
      description: 'Default Outbound Masquerade',
      sortOrder: 100,
    },
  ],
  gateways: [],
  gatewayGroups: [
    {
      name: 'WAN_Failover_Tier1_Tier2',
      trigger: 'loss',
      members: [{ gatewayName: 'WAN1_Fiber_GW', tier: 1, weight: 1 }],
      description: 'Failover Group',
    },
  ],
  dhcp: { enabled: true, subnets: [] },
  dns: { enabled: true, listenPort: 53, dnssec: true, dotEnabled: true, dotUpstreams: [], hostOverrides: [] },
  routes: [],
};

export default function PacketTracerPage() {
  const [inInterface, setInInterface] = useState('lan');
  const [srcIp, setSrcIp] = useState('192.168.100.45');
  const [srcPort, setSrcPort] = useState(54321);
  const [dstIp, setDstIp] = useState('1.1.1.1');
  const [dstPort, setDstPort] = useState(443);
  const [protocol, setProtocol] = useState<'tcp' | 'udp' | 'icmp'>('tcp');

  const [result, setResult] = useState<SimulationResult | null>(null);

  const handleSimulate = (e: React.FormEvent) => {
    e.preventDefault();
    const query: PacketTracerQuery = {
      inInterface,
      srcIp,
      dstIp,
      protocol,
      srcPort,
      dstPort,
    };
    const res = simulatePacket(query, SAMPLE_SIM_STATE);
    setResult(res);
  };

  const handleLoadSample = (type: 'allow' | 'block' | 'lockout' | 'dnat') => {
    if (type === 'allow') {
      setInInterface('lan');
      setSrcIp('192.168.100.45');
      setDstIp('1.1.1.1');
      setProtocol('tcp');
      setSrcPort(54321);
      setDstPort(443);
    } else if (type === 'block') {
      setInInterface('lan');
      setSrcIp('192.168.100.45');
      setDstIp('198.51.100.99');
      setProtocol('tcp');
      setSrcPort(54321);
      setDstPort(80);
    } else if (type === 'lockout') {
      setInInterface('lan');
      setSrcIp('192.168.100.45');
      setDstIp('192.168.100.1');
      setProtocol('tcp');
      setSrcPort(54321);
      setDstPort(3000);
    } else if (type === 'dnat') {
      setInInterface('wan');
      setSrcIp('203.0.113.10');
      setDstIp('198.51.100.1');
      setProtocol('tcp');
      setSrcPort(41234);
      setDstPort(8443);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" />
          Packet Tracer & Policy Simulator (E5)
        </h1>
        <p className="text-sm text-slate-400">
          Simulate arbitrary 5-tuples through aliases, DNAT, firewall filter chains, and multi-WAN routing tables without injecting live traffic.
        </p>
      </div>

      {/* Preset Test Buttons */}
      <div className="flex gap-2 flex-wrap text-xs">
        <span className="text-slate-400 py-1 font-medium">Quick Scenarios:</span>
        <button
          type="button"
          onClick={() => handleLoadSample('allow')}
          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
        >
          LAN Outbound HTTPS (Pass + Multi-WAN)
        </button>
        <button
          type="button"
          onClick={() => handleLoadSample('block')}
          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
        >
          Blocklisted IP (Drop via Alias)
        </button>
        <button
          type="button"
          onClick={() => handleLoadSample('lockout')}
          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
        >
          Anti-Lockout Console (TCP 3000)
        </button>
        <button
          type="button"
          onClick={() => handleLoadSample('dnat')}
          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
        >
          Inbound Port Forward (WAN 8443 DNAT)
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Form: 5-Tuple Definition */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <h3 className="font-semibold text-white text-sm flex items-center gap-2 border-b border-slate-800 pb-3">
            <Shield className="w-4 h-4 text-emerald-400" />
            Simulated 5-Tuple Packet
          </h3>

          <form onSubmit={handleSimulate} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Ingress Interface</label>
              <select
                value={inInterface}
                onChange={(e) => setInInterface(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
              >
                <option value="lan">lan (eth1 - 192.168.100.1/24)</option>
                <option value="wan">wan (eth0 - Uplink)</option>
              </select>
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="block text-xs font-medium text-slate-400 mb-1">Source IP</label>
                <input
                  type="text"
                  value={srcIp}
                  onChange={(e) => setSrcIp(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Src Port</label>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={srcPort}
                  onChange={(e) => setSrcPort(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Protocol</label>
              <div className="grid grid-cols-3 gap-2">
                {(['tcp', 'udp', 'icmp'] as const).map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setProtocol(p)}
                    className={`py-1.5 px-3 rounded-lg text-xs font-mono font-semibold uppercase transition border ${
                      protocol === p
                        ? 'border-emerald-500 bg-emerald-500/10 text-emerald-400'
                        : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <label className="block text-xs font-medium text-slate-400 mb-1">Destination IP</label>
                <input
                  type="text"
                  value={dstIp}
                  onChange={(e) => setDstIp(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Dst Port</label>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={dstPort}
                  onChange={(e) => setDstPort(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2.5 px-4 rounded-lg text-sm transition flex items-center justify-center gap-2 shadow-sm mt-4"
            >
              <Play className="w-4 h-4 fill-white" />
              Trace Packet Through Pipeline
            </button>
          </form>
        </div>

        {/* Right Output: Pipeline Simulation Trace */}
        <div className="lg:col-span-7 space-y-4">
          {result ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-5">
              {/* Verdict Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Simulation Verdict</span>
                  <div className="flex items-center gap-2 mt-1">
                    {result.verdict === 'ALLOW' ? (
                      <span className="inline-flex items-center gap-2 text-2xl font-bold font-mono text-emerald-400">
                        <CheckCircle2 className="w-7 h-7" /> ALLOWED
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-2 text-2xl font-bold font-mono text-red-400">
                        <XCircle className="w-7 h-7" /> {result.verdict}ED
                      </span>
                    )}
                  </div>
                </div>

                {result.matchedRule && (
                  <div className="text-right">
                    <span className="text-xs text-slate-500 font-mono block">Matched Rule</span>
                    <span className="text-xs font-semibold text-white font-mono bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                      {result.matchedRule.description}
                    </span>
                  </div>
                )}
              </div>

              {/* Policy Routing / NAT Badges */}
              {(result.policyRouting || result.nat) && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {result.nat && (
                    <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono">
                      <span className="text-slate-500 uppercase block text-[10px]">DNAT Translated Endpoint</span>
                      <span className="text-emerald-400 font-bold">
                        {result.nat.translatedIp}:{result.nat.translatedPort}
                      </span>
                    </div>
                  )}
                  {result.policyRouting?.gatewayGroup && (
                    <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono">
                      <span className="text-slate-500 uppercase block text-[10px]">Policy Routing Gateway</span>
                      <span className="text-blue-400 font-bold">{result.policyRouting.gatewayGroup}</span>
                    </div>
                  )}
                </div>
              )}

              {/* Step-by-Step Pipeline Trail */}
              <div className="space-y-3">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
                  Pipeline Evaluation Trail
                </span>
                <div className="space-y-2">
                  {result.steps.map((step, idx) => (
                    <div
                      key={idx}
                      className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex items-start gap-3 text-xs"
                    >
                      <div className="mt-0.5">
                        <ArrowRight className="w-4 h-4 text-emerald-400 shrink-0" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-emerald-400 uppercase font-semibold text-[11px]">
                            Stage: {step.stage}
                          </span>
                          {step.action && (
                            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 font-mono text-[10px] text-slate-300 font-bold">
                              {step.action}
                            </span>
                          )}
                        </div>
                        <p className="text-slate-300 mt-1 font-mono">{step.description}</p>
                        {step.detail && <p className="text-slate-500 mt-0.5 text-[11px]">{step.detail}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
              <HelpCircle className="w-10 h-10 text-slate-600" />
              <div>
                <p className="font-semibold text-slate-400">No Simulation Run Yet</p>
                <p className="text-xs mt-1">Specify a 5-tuple packet on the left or select a quick scenario to trace.</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
