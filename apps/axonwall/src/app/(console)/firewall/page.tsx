'use client';

import { useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Plus,
  Play,
  FileCode,
  Shield,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { applyDesiredState, confirmActiveRuleset, rollbackActiveRuleset } from '../../../server/agent';
import type { DesiredState, FirewallRule } from '@axonwall/lib/schemas';

const INITIAL_STATE: DesiredState = {
  version: 1,
  system: {
    hostname: 'axonwall',
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
    { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, description: 'WAN', mtu: 1500 },
    { name: 'lan', device: 'eth1', type: 'static', enabled: true, description: 'LAN', ipv4Address: '192.168.1.1/24', mtu: 1500 },
  ],
  aliases: [
    { name: 'web_servers', type: 'host', entries: ['192.168.1.10', '192.168.1.20'], description: 'Internal Web Servers', enabled: true },
  ],
  rules: [
    {
      id: 'rule-1',
      action: 'pass',
      direction: 'in',
      interface: 'lan',
      quick: true,
      protocol: 'tcp',
      source: 'any',
      sourcePort: '',
      destination: 'any',
      destinationPort: '22, 80, 443, 3000',
      log: false,
      enabled: true,
      description: 'Anti-Lockout Rule: Web GUI & SSH',
      sortOrder: 10,
    },
    {
      id: 'rule-2',
      action: 'pass',
      direction: 'in',
      interface: 'lan',
      quick: true,
      protocol: 'tcp',
      source: 'any',
      sourcePort: '',
      destination: '$web_servers',
      destinationPort: '80, 443',
      log: true,
      enabled: true,
      description: 'Allow LAN to Internal Web Servers',
      sortOrder: 20,
    },
    {
      id: 'rule-3',
      action: 'pass',
      direction: 'in',
      interface: 'lan',
      quick: true,
      protocol: 'any',
      source: 'any',
      sourcePort: '',
      destination: 'any',
      destinationPort: '',
      log: false,
      enabled: true,
      description: 'Default Allow LAN to Internet',
      sortOrder: 100,
    },
  ],
  nat: [
    {
      type: 'masquerade',
      interface: 'wan',
      protocol: 'any',
      source: 'any',
      sourcePort: '',
      destination: 'any',
      destinationPort: '',
      enabled: true,
      description: 'Default Outbound NAT',
      sortOrder: 100,
      log: false,
    },
  ],
  gateways: [],
  gatewayGroups: [],
  vlans: [],
  bridges: [],
  bonds: [],
  virtualIps: [],
  vrfs: [],
  dhcp: { enabled: true, subnets: [] },
  dns: { enabled: true, listenPort: 53, dnssec: true, dotEnabled: true, dotUpstreams: [], hostOverrides: [] },
  routes: [],
};

export default function FirewallPage() {
  const [state, setState] = useState<DesiredState>(INITIAL_STATE);
  const [selectedInterface, setSelectedInterface] = useState<'lan' | 'wan' | 'all'>('lan');
  const [compiledScript, setCompiledScript] = useState<string | null>(null);
  const [applyResult, setApplyResult] = useState<{ message: string; warnings: string[] } | null>(null);
  const [isApplying, setIsApplying] = useState(false);

  const filteredRules = state.rules.filter(
    (r) => selectedInterface === 'all' || r.interface === selectedInterface
  );

  async function handleApply() {
    setIsApplying(true);
    try {
      const res = await applyDesiredState(state, 120);
      setCompiledScript(res.nftScript);
      setApplyResult({
        message: res.message,
        warnings: res.warnings,
      });
    } finally {
      setIsApplying(false);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Firewall Rules</h1>
          <p className="text-sm text-slate-400 mt-1">
            Declarative packet filtering powered by Linux nftables with atomic transaction support.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleApply}
            disabled={isApplying}
            className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition cursor-pointer shadow-lg shadow-emerald-950 disabled:opacity-50"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>{isApplying ? 'Compiling & Applying...' : 'Apply Changes'}</span>
          </button>
        </div>
      </div>

      {applyResult && (
        <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl space-y-2">
          <div className="flex items-center gap-2 text-emerald-400 font-medium text-sm">
            <CheckCircle2 className="w-4 h-4" />
            <span>{applyResult.message}</span>
          </div>
          {applyResult.warnings.length > 0 && (
            <div className="mt-2 space-y-1">
              <span className="text-xs font-semibold text-amber-400 block uppercase">
                Linter Warnings:
              </span>
              {applyResult.warnings.map((w, idx) => (
                <div key={idx} className="flex items-center gap-2 text-xs text-amber-300">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>{w}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Interface Tabs */}
      <div className="flex border-b border-slate-800">
        {(['lan', 'wan', 'all'] as const).map((iface) => (
          <button
            key={iface}
            type="button"
            onClick={() => setSelectedInterface(iface)}
            className={`px-4 py-2.5 font-medium text-sm transition border-b-2 cursor-pointer uppercase tracking-wider ${
              selectedInterface === iface
                ? 'border-emerald-500 text-emerald-400 bg-emerald-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {iface}
          </button>
        ))}
      </div>

      {/* Rules Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Proto</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Port</th>
                <th className="px-4 py-3">Destination</th>
                <th className="px-4 py-3">Port</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {filteredRules.map((rule) => (
                <tr key={rule.id} className="hover:bg-slate-800/40 transition">
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold uppercase ${
                        rule.action === 'pass'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-red-500/10 text-red-400 border border-red-500/20'
                      }`}
                    >
                      {rule.action === 'pass' ? (
                        <CheckCircle2 className="w-3 h-3" />
                      ) : (
                        <XCircle className="w-3 h-3" />
                      )}
                      {rule.action}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-300 uppercase">{rule.protocol}</td>
                  <td className="px-4 py-3 text-slate-300">{rule.source}</td>
                  <td className="px-4 py-3 text-slate-400">{rule.sourcePort || '*'}</td>
                  <td className="px-4 py-3 text-emerald-400">{rule.destination}</td>
                  <td className="px-4 py-3 text-slate-400">{rule.destinationPort || '*'}</td>
                  <td className="px-4 py-3 font-sans text-slate-300">{rule.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Compiled nftables Output Preview */}
      {compiledScript && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <FileCode className="w-4 h-4 text-emerald-400" />
              <span>Compiled nftables Atomic Script (`table inet axonwall`)</span>
            </div>
            <span className="text-xs text-slate-400 font-mono">Kernel-validated</span>
          </div>

          <pre className="bg-slate-950 border border-slate-800/80 rounded-lg p-4 font-mono text-xs text-slate-300 overflow-x-auto max-h-96 leading-relaxed">
            {compiledScript}
          </pre>
        </div>
      )}
    </div>
  );
}
