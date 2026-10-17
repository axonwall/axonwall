'use client';

import { useState, useEffect } from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Plus,
  Play,
  FileCode,
  Shield,
  Trash2,
  Edit2,
  X,
  Sliders,
} from 'lucide-react';
import { getCurrentDesiredState, applyDesiredState } from '../../../server/agent';
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
      ports: [22, 80, 443, 2966, 3000],
    },
  },
  interfaces: [
    { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, description: 'WAN', mtu: 1500 },
    { name: 'lan', device: 'eth1', type: 'static', enabled: true, description: 'LAN', ipv4Address: '192.168.1.1/24', mtu: 1500 },
    { name: 'opt1', device: 'eth2', type: 'dhcp', enabled: false, description: 'OPT1 (Attached)', mtu: 1500 },
    { name: 'opt2', device: 'eth3', type: 'dhcp', enabled: false, description: 'OPT2 (Attached)', mtu: 1500 },
  ],
  aliases: [
    { name: 'web_servers', type: 'host', entries: ['192.168.1.10', '192.168.1.20'], description: 'Internal Web Servers', enabled: true },
  ],
  rules: [
    {
      id: '00000000-0000-4000-8000-000000000001',
      action: 'pass',
      direction: 'in',
      interface: 'lan',
      quick: true,
      protocol: 'tcp',
      source: 'any',
      sourcePort: '',
      destination: 'any',
      destinationPort: '22, 80, 443, 2966, 3000',
      log: false,
      enabled: true,
      description: 'Anti-Lockout Rule: Web GUI & SSH',
      sortOrder: 10,
    },
    {
      id: '00000000-0000-4000-8000-000000000002',
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
      id: '00000000-0000-4000-8000-000000000003',
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

const DEFAULT_RULE: FirewallRule = {
  action: 'pass',
  direction: 'in',
  interface: 'lan',
  quick: true,
  protocol: 'tcp',
  source: 'any',
  sourcePort: '',
  destination: 'any',
  destinationPort: '',
  log: false,
  enabled: true,
  description: '',
  sortOrder: 100,
};

export default function FirewallPage() {
  const [state, setState] = useState<DesiredState>(INITIAL_STATE);
  const [selectedInterface, setSelectedInterface] = useState<string>('lan');
  const [compiledScript, setCompiledScript] = useState<string | null>(null);
  const [applyResult, setApplyResult] = useState<{ message: string; warnings: string[] } | null>(null);
  const [isApplying, setIsApplying] = useState(false);
  const [hasUnappliedChanges, setHasUnappliedChanges] = useState(false);

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [ruleForm, setRuleForm] = useState<FirewallRule>(DEFAULT_RULE);

  useEffect(() => {
    getCurrentDesiredState()
      .then((s) => {
        if (s) setState(s);
      })
      .catch(() => {});
  }, []);

  const availableInterfaces = [
    ...state.interfaces.map((i) => i.name),
    'any',
  ];

  const filteredRules = state.rules.filter(
    (r) => selectedInterface === 'all' || r.interface === selectedInterface
  );

  const handleOpenAddModal = () => {
    setEditingRuleId(null);
    setRuleForm({
      ...DEFAULT_RULE,
      interface: selectedInterface === 'all' ? 'lan' : selectedInterface,
      sortOrder: (state.rules.length + 1) * 10,
    });
    setIsModalOpen(true);
  };

  const handleOpenEditModal = (rule: FirewallRule) => {
    setEditingRuleId(rule.id || null);
    setRuleForm({ ...rule });
    setIsModalOpen(true);
  };

  const handleSaveRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingRuleId) {
      // Edit existing rule
      setState((prev) => ({
        ...prev,
        rules: prev.rules.map((r) => (r.id === editingRuleId ? { ...ruleForm, id: editingRuleId } : r)),
      }));
    } else {
      // Create new rule
      const newRule: FirewallRule = {
        ...ruleForm,
        id: crypto.randomUUID(),
      };
      setState((prev) => ({
        ...prev,
        rules: [...prev.rules, newRule],
      }));
    }
    setHasUnappliedChanges(true);
    setIsModalOpen(false);
  };

  const handleDeleteRule = (id?: string) => {
    if (!id) return;
    if (confirm('Are you sure you want to delete this firewall rule?')) {
      setState((prev) => ({
        ...prev,
        rules: prev.rules.filter((r) => r.id !== id),
      }));
      setHasUnappliedChanges(true);
    }
  };

  const handleToggleRule = (id?: string) => {
    if (!id) return;
    setState((prev) => ({
      ...prev,
      rules: prev.rules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
    }));
    setHasUnappliedChanges(true);
  };

  async function handleApply() {
    setIsApplying(true);
    try {
      const res = await applyDesiredState(state, 120);
      setCompiledScript(res.nftScript);
      setApplyResult({
        message: res.message,
        warnings: res.warnings,
      });
      setHasUnappliedChanges(false);
    } catch (err: any) {
      setApplyResult({
        message: `Apply Failed: ${err?.message || 'Configuration validation error'}`,
        warnings: ['State could not be applied to kernel nftables.'],
      });
    } finally {
      setIsApplying(false);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-emerald-400" />
            <span>Firewall Rules</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Declarative packet filtering powered by Linux nftables with atomic transaction safety. Rules are saved to <code className="text-emerald-400 font-mono">/etc/axonwall/firewall.yaml</code>.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleOpenAddModal}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition cursor-pointer"
          >
            <Plus className="w-4 h-4 text-emerald-400" />
            <span>Add Rule</span>
          </button>

          <button
            type="button"
            onClick={handleApply}
            disabled={isApplying}
            className={`px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition cursor-pointer shadow-lg disabled:opacity-50 ${
              hasUnappliedChanges
                ? 'bg-amber-600 hover:bg-amber-500 text-white animate-pulse shadow-amber-950'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-950'
            }`}
          >
            <Play className="w-4 h-4 fill-current" />
            <span>{isApplying ? 'Compiling & Applying...' : hasUnappliedChanges ? 'Apply Changes *' : 'Apply Changes'}</span>
          </button>
        </div>
      </div>

      {hasUnappliedChanges && (
        <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl flex items-center justify-between text-xs text-amber-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>You have unapplied rule changes pending. Click <strong>Apply Changes</strong> to compile and commit to kernel nftables.</span>
          </div>
        </div>
      )}

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
        {(['lan', 'wan', 'opt1', 'opt2', 'all'] as const).map((iface) => (
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

      {/* Interface Security Context Callouts */}
      {selectedInterface === 'wan' && (
        <div className="p-4 bg-sky-950/40 border border-sky-500/30 rounded-xl flex items-start gap-3">
          <Shield className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="text-sm font-semibold text-sky-300">
              Default Deny WAN Policy & Management Isolation
            </h4>
            <p className="text-xs text-sky-200/80 leading-relaxed">
              By default, all unsolicited inbound connections from the WAN to the Axonwall host and Web Management Console (ports 2966, 3000, 80, 443) and SSH (port 22) are strictly blocked. Inbound management is restricted to LAN and internal networks to protect the appliance from internet scanning and unauthorized access.
            </p>
          </div>
        </div>
      )}

      {selectedInterface === 'lan' && (
        <div className="p-3 bg-emerald-950/30 border border-emerald-500/20 rounded-xl flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-emerald-300">
            <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>
              <strong>System Anti-Lockout Protected:</strong> Web Console (ports 2966, 443, 80) and SSH (port 22) are permitted from LAN to prevent administrator lockout.
            </span>
          </div>
          <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded font-mono text-[10px] uppercase font-semibold">
            LAN Anti-Lockout Active
          </span>
        </div>
      )}

      {/* Rules Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">State</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Iface</th>
                <th className="px-4 py-3">Proto</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Port</th>
                <th className="px-4 py-3">Destination</th>
                <th className="px-4 py-3">Port</th>
                <th className="px-4 py-3">Description</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={10} className="px-4 py-8 text-center text-slate-500 font-sans">
                    No rules configured on this interface. Click <strong>Add Rule</strong> above to create one.
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => (
                  <tr
                    key={rule.id}
                    className={`hover:bg-slate-800/40 transition ${
                      !rule.enabled ? 'opacity-50 bg-slate-950/40' : ''
                    }`}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={rule.enabled ?? true}
                        onChange={() => handleToggleRule(rule.id)}
                        title={rule.enabled ? 'Click to disable' : 'Click to enable'}
                        className="w-4 h-4 rounded accent-emerald-500 cursor-pointer"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold uppercase ${
                          rule.action === 'pass'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : rule.action === 'reject'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
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
                    <td className="px-4 py-3 text-slate-300 uppercase font-sans font-medium">{rule.interface}</td>
                    <td className="px-4 py-3 text-slate-300 uppercase">{rule.protocol}</td>
                    <td className="px-4 py-3 text-slate-300">{rule.source}</td>
                    <td className="px-4 py-3 text-slate-400">{rule.sourcePort || '*'}</td>
                    <td className="px-4 py-3 text-emerald-400">{rule.destination}</td>
                    <td className="px-4 py-3 text-slate-400">{rule.destinationPort || '*'}</td>
                    <td className="px-4 py-3 font-sans text-slate-300">{rule.description || '-'}</td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={() => handleOpenEditModal(rule)}
                          className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition"
                          title="Edit Rule"
                        >
                          <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDeleteRule(rule.id)}
                          className="p-1 rounded text-slate-400 hover:text-red-400 hover:bg-slate-800 transition"
                          title="Delete Rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add / Edit Rule Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-5 shadow-2xl my-8">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Sliders className="w-5 h-5 text-emerald-400" />
                  <span>{editingRuleId ? 'Edit Firewall Rule' : 'Add Firewall Rule'}</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Configure stateful packet filtering parameters for this interface.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveRule} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {/* Action */}
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Action</label>
                  <select
                    value={ruleForm.action}
                    onChange={(e) => setRuleForm({ ...ruleForm, action: e.target.value as any })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 uppercase font-medium"
                  >
                    <option value="pass">PASS (Allow)</option>
                    <option value="block">BLOCK (Drop)</option>
                    <option value="reject">REJECT (TCP Reset / ICMP)</option>
                  </select>
                </div>

                {/* Interface */}
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Interface</label>
                  <select
                    value={ruleForm.interface}
                    onChange={(e) => setRuleForm({ ...ruleForm, interface: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 uppercase font-medium"
                  >
                    {availableInterfaces.map((iface) => (
                      <option key={iface} value={iface}>
                        {iface}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Protocol */}
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Protocol</label>
                  <select
                    value={ruleForm.protocol}
                    onChange={(e) => setRuleForm({ ...ruleForm, protocol: e.target.value as any })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 uppercase font-medium"
                  >
                    <option value="any">ANY</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="tcp_udp">TCP/UDP</option>
                    <option value="icmp">ICMP</option>
                    <option value="esp">ESP</option>
                    <option value="gre">GRE</option>
                  </select>
                </div>
              </div>

              {/* Source & Source Port */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Source IP / CIDR / Alias</label>
                  <input
                    type="text"
                    required
                    value={ruleForm.source}
                    onChange={(e) => setRuleForm({ ...ruleForm, source: e.target.value })}
                    placeholder="any, 192.168.1.0/24, or $alias"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Source Port (optional)</label>
                  <input
                    type="text"
                    value={ruleForm.sourcePort || ''}
                    onChange={(e) => setRuleForm({ ...ruleForm, sourcePort: e.target.value })}
                    placeholder="any or port range"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              {/* Destination & Destination Port */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Destination IP / CIDR / Alias</label>
                  <input
                    type="text"
                    required
                    value={ruleForm.destination}
                    onChange={(e) => setRuleForm({ ...ruleForm, destination: e.target.value })}
                    placeholder="any, 10.0.0.1, or $web_servers"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Destination Port(s)</label>
                  <input
                    type="text"
                    value={ruleForm.destinationPort || ''}
                    onChange={(e) => setRuleForm({ ...ruleForm, destinationPort: e.target.value })}
                    placeholder="e.g. 80, 443, 2966, or $port_alias"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              {/* Description */}
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1">Description</label>
                <input
                  type="text"
                  value={ruleForm.description}
                  onChange={(e) => setRuleForm({ ...ruleForm, description: e.target.value })}
                  placeholder="e.g. Allow Web Console access from management subnet"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
                />
              </div>

              {/* Toggles */}
              <div className="flex flex-wrap items-center gap-6 pt-2 border-t border-slate-800">
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ruleForm.enabled ?? true}
                    onChange={(e) => setRuleForm({ ...ruleForm, enabled: e.target.checked })}
                    className="w-4 h-4 rounded accent-emerald-500"
                  />
                  <span>Enable Rule</span>
                </label>

                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ruleForm.quick ?? true}
                    onChange={(e) => setRuleForm({ ...ruleForm, quick: e.target.checked })}
                    className="w-4 h-4 rounded accent-emerald-500"
                  />
                  <span>Quick Match (First match terminates)</span>
                </label>

                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ruleForm.log ?? false}
                    onChange={(e) => setRuleForm({ ...ruleForm, log: e.target.checked })}
                    className="w-4 h-4 rounded accent-emerald-500"
                  />
                  <span>Log Packet Matches</span>
                </label>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-lg text-sm font-medium text-slate-400 hover:text-white hover:bg-slate-800 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-2 rounded-lg text-sm font-medium transition cursor-pointer shadow-lg shadow-emerald-950"
                >
                  {editingRuleId ? 'Update Rule' : 'Add Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

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
