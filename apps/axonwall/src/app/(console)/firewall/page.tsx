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
import { getCurrentDesiredState } from '../../../server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import { inferInterfaceRole, type DesiredState, type FirewallRule, type NatRule } from '@axonwall/lib/schemas';

const DEFAULT_NAT_RULE: NatRule = {
  type: 'dnat',
  interface: 'wan',
  protocol: 'tcp',
  source: 'any',
  sourcePort: '',
  destination: 'wan_ip',
  destinationPort: '443',
  targetIp: '192.168.1.50',
  targetPort: '443',
  natReflection: true,
  log: false,
  enabled: true,
  description: '',
  sortOrder: 100,
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
  const { applyState } = useDesiredStateApply();
  // C1: never render a placeholder ruleset. State starts null and the page
  // shows a loading/error screen until the real config loads, so Apply can
  // never persist demo rules over the live configuration.
  const [state, setState] = useState<DesiredState | null>(null);
  const [isLoadingState, setIsLoadingState] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedInterface, setSelectedInterface] = useState<string>('lan');
  const [policyTab, setPolicyTab] = useState<'filter' | 'nat'>('filter');
  const [compiledScript, setCompiledScript] = useState<string | null>(null);
  const [applyResult, setApplyResult] = useState<{ ok: boolean; message: string; warnings: string[] } | null>(null);
  const [isApplying, setIsApplying] = useState(false);
  const [hasUnappliedChanges, setHasUnappliedChanges] = useState(false);

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [ruleForm, setRuleForm] = useState<FirewallRule>(DEFAULT_RULE);
  const [isNatModalOpen, setIsNatModalOpen] = useState(false);
  const [editingNatId, setEditingNatId] = useState<string | null>(null);
  const [natForm, setNatForm] = useState<NatRule>(DEFAULT_NAT_RULE);
  // C19: toggle/delete/edit of an id-less rule used to silently no-op
  // (and edit-then-save duplicated the rule). Such rules now surface
  // an error instead of pretending to work.
  const [ruleActionError, setRuleActionError] = useState<string | null>(null);

  const loadState = () => {
    setIsLoadingState(true);
    setLoadError(null);
    getCurrentDesiredState()
      .then((s) => {
        if (s) {
          setState({
            ...s,
            rules: (s.rules || []).map((r, idx) => (r.id ? r : { ...r, id: crypto.randomUUID() || `rule-${idx + 1}` })),
            nat: (s.nat || []).map((n) => (n.id ? n : { ...n, id: crypto.randomUUID() })),
          });
        } else {
          setLoadError('No firewall configuration was returned by the server.');
        }
      })
      .catch((err: any) => {
        setLoadError(err?.message || 'Failed to load the current firewall configuration.');
      })
      .finally(() => {
        setIsLoadingState(false);
      });
  };

  useEffect(() => {
    loadState();
  }, []);

  const availableInterfaces = [
    ...(state?.interfaces ?? []).map((i) => i.name),
    'floating',
    'any',
  ];

  const handleOpenAddNatModal = () => {
    if (!state) return;
    setEditingNatId(null);
    setNatForm({
      ...DEFAULT_NAT_RULE,
      sortOrder: ((state.nat?.length ?? 0) + 1) * 10,
    });
    setIsNatModalOpen(true);
  };

  const handleOpenEditNatModal = (natRule: NatRule) => {
    if (!natRule.id) return;
    setEditingNatId(natRule.id);
    setNatForm({ ...natRule });
    setIsNatModalOpen(true);
  };

  const handleSaveNat = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingNatId) {
      setState((prev) =>
        prev
          ? {
              ...prev,
              nat: (prev.nat || []).map((n) => (n.id === editingNatId ? { ...natForm, id: editingNatId } : n)),
            }
          : prev
      );
    } else {
      const nextNat: NatRule = { ...natForm, id: crypto.randomUUID() };
      setState((prev) => (prev ? { ...prev, nat: [...(prev.nat || []), nextNat] } : prev));
    }
    setHasUnappliedChanges(true);
    setIsNatModalOpen(false);
  };

  const handleDeleteNat = (id?: string) => {
    if (!id) return;
    if (confirm('Delete this NAT translation rule?')) {
      setState((prev) => (prev ? { ...prev, nat: (prev.nat || []).filter((n) => n.id !== id) } : prev));
      setHasUnappliedChanges(true);
    }
  };

  const handleToggleNat = (id?: string) => {
    if (!id) return;
    setState((prev) =>
      prev
        ? {
            ...prev,
            nat: (prev.nat || []).map((n) => (n.id === id ? { ...n, enabled: !n.enabled } : n)),
          }
        : prev
    );
    setHasUnappliedChanges(true);
  };

  const filteredRules = (state?.rules ?? []).filter(
    (r) => selectedInterface === 'all' || r.interface === selectedInterface
  );

  const handleOpenAddModal = () => {
    if (!state) return;
    setEditingRuleId(null);
    setRuleForm({
      ...DEFAULT_RULE,
      interface: selectedInterface === 'all' ? 'lan' : selectedInterface,
      sortOrder: (state.rules.length + 1) * 10,
    });
    setIsModalOpen(true);
  };

  const handleOpenEditModal = (rule: FirewallRule) => {
    // C19: editing an id-less rule used to fall into the create branch
    // on save, appending a duplicate while the original remained.
    // Refuse with an error instead of opening a modal that duplicates.
    if (!rule.id) {
      setRuleActionError(
        'This rule has no id (it was staged before ids were assigned at staging) and cannot be edited from here. Delete is also unavailable for id-less rules; remove it by editing the stored ruleset directly.'
      );
      return;
    }
    setRuleActionError(null);
    setEditingRuleId(rule.id);
    setRuleForm({ ...rule });
    setIsModalOpen(true);
  };

  const handleSaveRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingRuleId) {
      // Edit existing rule; if the id matches nothing (stale edit),
      // say so instead of silently closing the modal as if saved.
      if (!state?.rules.some((r) => r.id === editingRuleId)) {
        setRuleActionError(`No rule with id ${editingRuleId} exists anymore; nothing was saved.`);
        setIsModalOpen(false);
        return;
      }
      setState((prev) =>
        prev
          ? {
              ...prev,
              rules: prev.rules.map((r) => (r.id === editingRuleId ? { ...ruleForm, id: editingRuleId } : r)),
            }
          : prev
      );
    } else {
      // Create new rule
      const newRule: FirewallRule = {
        ...ruleForm,
        id: crypto.randomUUID(),
      };
      setState((prev) => (prev ? { ...prev, rules: [...prev.rules, newRule] } : prev));
    }
    setHasUnappliedChanges(true);
    setIsModalOpen(false);
  };

  const handleDeleteRule = (id?: string) => {
    // C19: was a silent no-op for id-less rules.
    if (!id) {
      setRuleActionError('This rule has no id and cannot be deleted from here. Rules staged before ids were assigned at staging must be removed by editing the stored ruleset directly.');
      return;
    }
    if (confirm('Are you sure you want to delete this firewall rule?')) {
      setState((prev) => (prev ? { ...prev, rules: prev.rules.filter((r) => r.id !== id) } : prev));
      setHasUnappliedChanges(true);
    }
  };

  const handleToggleRule = (id?: string) => {
    // C19: was a silent no-op for id-less rules.
    if (!id) {
      setRuleActionError('This rule has no id and cannot be toggled from here.');
      return;
    }
    setState((prev) =>
      prev
        ? {
            ...prev,
            rules: prev.rules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
          }
        : prev
    );
    setHasUnappliedChanges(true);
  };

  async function handleApply() {
    if (!state) return;
    setIsApplying(true);
    try {
      const res = await applyState(state, 120);
      setCompiledScript(res.nftScript);
      setApplyResult({
        ok: true,
        message: res.message,
        warnings: res.warnings,
      });
      setHasUnappliedChanges(false);
    } catch (err: any) {
      setApplyResult({
        ok: false,
        message: `Apply Failed: ${err?.message || 'Configuration validation error'}`,
        warnings: ['State could not be applied to kernel nftables.'],
      });
    } finally {
      setIsApplying(false);
    }
  }

  // C1: nothing editable renders until the real configuration has loaded.
  // A load failure shows an error (never the demo ruleset) with a retry.
  if (isLoadingState) {
    return (
      <div className="space-y-6 max-w-7xl mx-auto">
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl text-sm text-slate-300">
          Loading firewall configuration…
        </div>
      </div>
    );
  }

  if (loadError || !state) {
    return (
      <div className="space-y-6 max-w-7xl mx-auto">
        <div className="p-6 bg-red-500/10 border border-red-500/30 rounded-xl space-y-3">
          <div className="flex items-center gap-2 text-red-400 font-medium text-sm">
            <XCircle className="w-4 h-4" />
            <span>{loadError || 'Firewall configuration could not be loaded.'}</span>
          </div>
          <p className="text-xs text-slate-400">
            The current ruleset is unknown, so editing and applying are disabled until it loads successfully.
          </p>
          <button
            type="button"
            onClick={loadState}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-2 rounded-lg font-medium text-sm cursor-pointer"
          >
            Retry loading configuration
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-emerald-400" />
            <span>Firewall &amp; NAT Policy Engine</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Declarative packet filtering, Floating rules, PBR, Hairpin DNAT, 1:1 BINAT, and Stateless NPTv6 compiled into atomic Linux nftables (<code className="text-emerald-400 font-mono">/etc/axonwall/firewall.yaml</code>).
          </p>
        </div>

        <div className="flex items-center gap-3">
          {policyTab === 'filter' ? (
            <button
              type="button"
              onClick={handleOpenAddModal}
              className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition cursor-pointer"
            >
              <Plus className="w-4 h-4 text-emerald-400" />
              <span>Add Filter Rule</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={handleOpenAddNatModal}
              className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition cursor-pointer"
            >
              <Plus className="w-4 h-4 text-cyan-400" />
              <span>Add NAT Rule</span>
            </button>
          )}

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

      {ruleActionError && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center justify-between text-sm text-red-300">
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{ruleActionError}</span>
          </div>
          <button
            type="button"
            onClick={() => setRuleActionError(null)}
            className="text-slate-400 hover:text-white text-xs cursor-pointer shrink-0 ml-4"
          >
            ✕
          </button>
        </div>
      )}

      {applyResult && (
        <div
          className={`p-4 rounded-xl space-y-2 ${
            applyResult.ok
              ? 'bg-emerald-500/10 border border-emerald-500/30'
              : 'bg-red-500/10 border border-red-500/30'
          }`}
        >
          <div
            className={`flex items-center gap-2 font-medium text-sm ${
              applyResult.ok ? 'text-emerald-400' : 'text-red-400'
            }`}
          >
            {applyResult.ok ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
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

      {/* Policy Mode Switcher */}
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => setPolicyTab('filter')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer border ${
            policyTab === 'filter'
              ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          Packet Filter &amp; Floating Rules ({state.rules.length})
        </button>
        <button
          type="button"
          onClick={() => setPolicyTab('nat')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer border ${
            policyTab === 'nat'
              ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          NAT Suite: DNAT / Hairpin / SNAT / 1:1 BINAT / NPTv6 ({state.nat?.length ?? 0})
        </button>
      </div>

      {policyTab === 'nat' ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">State</th>
                  <th className="px-4 py-3">NAT Mode</th>
                  <th className="px-4 py-3">Iface</th>
                  <th className="px-4 py-3">Proto</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Destination : Port</th>
                  <th className="px-4 py-3">Translated Target</th>
                  <th className="px-4 py-3">Hairpin</th>
                  <th className="px-4 py-3">Description</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                {(state.nat || []).length === 0 ? (
                  <tr>
                    <td colSpan={10} className="px-4 py-8 text-center text-slate-500 font-sans">
                      No NAT rules configured. Click <strong>Add NAT Rule</strong> to configure Port Forwards (DNAT), Outbound SNAT/Masquerade, 1:1 BINAT, or Stateless NPTv6.
                    </td>
                  </tr>
                ) : (
                  (state.nat || []).map((nr) => (
                    <tr key={nr.id} className={`hover:bg-slate-800/40 transition ${!nr.enabled ? 'opacity-50' : ''}`}>
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={nr.enabled ?? true}
                          onChange={() => handleToggleNat(nr.id)}
                          className="w-4 h-4 rounded accent-cyan-500 cursor-pointer"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 uppercase text-[11px] font-semibold">
                          {nr.type}
                        </span>
                      </td>
                      <td className="px-4 py-3 uppercase text-slate-300">{nr.interface}</td>
                      <td className="px-4 py-3 uppercase text-slate-300">{nr.protocol}</td>
                      <td className="px-4 py-3 text-slate-300">{nr.source}</td>
                      <td className="px-4 py-3 text-slate-300">
                        {nr.destination}{nr.destinationPort ? `:${nr.destinationPort}` : ''}
                      </td>
                      <td className="px-4 py-3 text-emerald-400">
                        {nr.type === 'masquerade'
                          ? 'MASQUERADE'
                          : `${nr.targetIp || '-'}${nr.targetPort ? `:${nr.targetPort}` : ''}`}
                      </td>
                      <td className="px-4 py-3">
                        {nr.type === 'dnat' && nr.natReflection !== false ? (
                          <span className="text-emerald-400 text-[11px]">Enabled</span>
                        ) : (
                          <span className="text-slate-500 text-[11px]">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-sans text-slate-300">{nr.description || '-'}</td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            type="button"
                            onClick={() => handleOpenEditNatModal(nr)}
                            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition"
                          >
                            <Edit2 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteNat(nr.id)}
                            className="p-1 rounded text-slate-400 hover:text-red-400 hover:bg-slate-800 transition"
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
      ) : (
      <>
      {/* Interface Tabs */}
      <div className="flex flex-wrap border-b border-slate-800">
        {Array.from(
          new Set([
            ...state.interfaces
              .filter((i) => i.enabled || i.name === 'lan' || i.name === 'wan')
              .map((i) => i.name),
            ...state.rules.map((r) => r.interface).filter((n) => n && n !== 'any'),
            'all',
          ])
        ).map((iface) => (
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
      {(() => {
        const selectedObj = state.interfaces.find((i) => i.name === selectedInterface);
        const role = selectedObj
          ? inferInterfaceRole(selectedObj)
          : selectedInterface.startsWith('wan')
            ? 'wan'
            : selectedInterface === 'all'
              ? null
              : 'lan';
        if (role === 'wan') {
          return (
            <div className="p-4 bg-sky-950/40 border border-sky-500/30 rounded-xl flex items-start gap-3">
              <Shield className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <h4 className="text-sm font-semibold text-sky-300">
                  Default Deny WAN Policy &amp; Management Isolation ({selectedInterface.toUpperCase()})
                </h4>
                <p className="text-xs text-sky-200/80 leading-relaxed">
                  The configured default-deny policy blocks unsolicited inbound connections from WAN uplinks to the Axonwall host and Web Management Console (ports 2966, 3000, 80, 443) and SSH (port 22). Inbound management is configured to be reachable only from LAN and internal networks, to protect the appliance from internet scanning and unauthorized access.
                </p>
              </div>
            </div>
          );
        }
        if (role === 'lan') {
          // A13: the badge used to render from interface-role inference
          // alone, claiming anti-lockout protection even when the
          // setting is disabled. Gate it on the loaded config
          // (schema default is enabled, so an absent value still
          // counts as enabled).
          const antiLockoutEnabled = state.system?.antiLockout?.enabled !== false;
          if (!antiLockoutEnabled) {
            return (
              <div className="p-3 bg-amber-950/30 border border-amber-500/20 rounded-xl flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 text-amber-300">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                  <span>
                    <strong>Anti-Lockout Disabled ({selectedInterface.toUpperCase()}):</strong> the anti-lockout setting is off, so Web Console and SSH are not guaranteed to stay reachable on LAN interfaces. Re-enable it in System settings to prevent administrator lockout.
                  </span>
                </div>
                <span className="px-2 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded font-mono text-[10px] uppercase font-semibold">
                  LAN Anti-Lockout Off
                </span>
              </div>
            );
          }
          return (
            <div className="p-3 bg-emerald-950/30 border border-emerald-500/20 rounded-xl flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 text-emerald-300">
                <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>
                  <strong>System Anti-Lockout Protected ({selectedInterface.toUpperCase()}):</strong> Web Console (ports 2966, 443, 80) and SSH (port 22) are permitted on LAN interfaces to prevent administrator lockout.
                </span>
              </div>
              <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded font-mono text-[10px] uppercase font-semibold">
                LAN Anti-Lockout Active
              </span>
            </div>
          );
        }
        return null;
      })()}

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
      </>
      )}

      {/* Add / Edit NAT Modal */}
      {isNatModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl my-8">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-white">{editingNatId ? 'Edit NAT Rule' : 'Add NAT Policy Rule'}</h3>
                <p className="text-xs text-slate-400">Configure DNAT Port Forwarding, Hairpin NAT Reflection, Outbound SNAT/Masquerade, 1:1 BINAT, or Stateless NPTv6.</p>
              </div>
              <button type="button" onClick={() => setIsNatModalOpen(false)} className="text-slate-400 hover:text-white p-1">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleSaveNat} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">NAT Mode</label>
                  <select
                    value={natForm.type}
                    onChange={(e) => setNatForm({ ...natForm, type: e.target.value as NatRule['type'] })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white uppercase font-semibold"
                  >
                    <option value="dnat">DNAT (Port Forward)</option>
                    <option value="snat">SNAT (Static Outbound)</option>
                    <option value="masquerade">Masquerade (Dynamic WAN)</option>
                    <option value="binat">1:1 BINAT (Bidirectional)</option>
                    <option value="nptv6">NPTv6 (Stateless IPv6 Prefix)</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Interface</label>
                  <select
                    value={natForm.interface}
                    onChange={(e) => setNatForm({ ...natForm, interface: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white uppercase"
                  >
                    {availableInterfaces.filter((x) => x !== 'floating').map((iface) => (
                      <option key={iface} value={iface}>{iface}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Protocol</label>
                  <select
                    value={natForm.protocol}
                    onChange={(e) => setNatForm({ ...natForm, protocol: e.target.value as NatRule['protocol'] })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white uppercase"
                  >
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="tcp_udp">TCP/UDP</option>
                    <option value="any">ANY</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">
                    {natForm.type === 'nptv6' ? 'Internal ULA Prefix (Source)' : 'Source Endpoint'}
                  </label>
                  <input
                    type="text"
                    value={natForm.source}
                    onChange={(e) => setNatForm({ ...natForm, source: e.target.value })}
                    placeholder={natForm.type === 'nptv6' ? 'fd00:10::/48' : 'any or 192.168.1.0/24'}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Destination / External VIP</label>
                  <input
                    type="text"
                    value={natForm.destination}
                    onChange={(e) => setNatForm({ ...natForm, destination: e.target.value })}
                    placeholder="wan_ip or 203.0.113.10"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">External Port</label>
                  <input
                    type="text"
                    value={natForm.destinationPort || ''}
                    onChange={(e) => setNatForm({ ...natForm, destinationPort: e.target.value })}
                    placeholder="443 or 8000:8010"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">
                    {natForm.type === 'nptv6' ? 'External GUA Prefix' : 'Translated Target IP'}
                  </label>
                  <input
                    type="text"
                    value={natForm.targetIp || ''}
                    onChange={(e) => setNatForm({ ...natForm, targetIp: e.target.value })}
                    placeholder={natForm.type === 'nptv6' ? '2001:db8:10::/48' : '192.168.1.50'}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Target Internal Port</label>
                  <input
                    type="text"
                    value={natForm.targetPort || ''}
                    onChange={(e) => setNatForm({ ...natForm, targetPort: e.target.value })}
                    placeholder="8443"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1">Description</label>
                <input
                  type="text"
                  value={natForm.description}
                  onChange={(e) => setNatForm({ ...natForm, description: e.target.value })}
                  placeholder="e.g. Reverse Proxy HTTPS Port Forward"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
                />
              </div>

              <div className="flex flex-wrap items-center gap-5 pt-2 border-t border-slate-800">
                {natForm.type === 'dnat' && (
                  <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={natForm.natReflection !== false}
                      onChange={(e) => setNatForm({ ...natForm, natReflection: e.target.checked })}
                      className="w-4 h-4 rounded accent-cyan-500"
                    />
                    <span>Hairpin NAT Reflection (LAN clients can reach WAN VIP)</span>
                  </label>
                )}
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={natForm.log ?? false}
                    onChange={(e) => setNatForm({ ...natForm, log: e.target.checked })}
                    className="w-4 h-4 rounded accent-cyan-500"
                  />
                  <span>Log Translations</span>
                </label>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-800">
                <button type="button" onClick={() => setIsNatModalOpen(false)} className="px-4 py-2 text-xs text-slate-400 hover:text-white">
                  Cancel
                </button>
                <button type="submit" className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white">
                  {editingNatId ? 'Update NAT Rule' : 'Add NAT Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

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

              {/* Advanced OPNsense Parity: Direction, Negated Match, DSCP, Rate Limit & PBR Gateway Group */}
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-2 border-t border-slate-800">
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Direction</label>
                  <select
                    value={ruleForm.direction || 'in'}
                    onChange={(e) => setRuleForm({ ...ruleForm, direction: e.target.value as 'in' | 'out' })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white uppercase"
                  >
                    <option value="in">IN (Ingress)</option>
                    <option value="out">OUT (Egress)</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">DSCP Class</label>
                  <input
                    type="text"
                    value={ruleForm.dscp ?? ''}
                    onChange={(e) =>
                      setRuleForm({
                        ...ruleForm,
                        dscp: e.target.value.trim() ? e.target.value.trim() : undefined,
                      })
                    }
                    placeholder="ef, cs6, af41"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">Max PPS Limit</label>
                  <input
                    type="number"
                    min={0}
                    value={ruleForm.rateLimitPps ?? ''}
                    onChange={(e) =>
                      setRuleForm({
                        ...ruleForm,
                        rateLimitPps: e.target.value ? Number(e.target.value) : undefined,
                      })
                    }
                    placeholder="0 (Unlimited)"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-300 block mb-1">PBR Gateway Group</label>
                  <input
                    type="text"
                    value={ruleForm.gatewayGroup || ''}
                    onChange={(e) =>
                      setRuleForm({
                        ...ruleForm,
                        gatewayGroup: e.target.value.trim() || undefined,
                      })
                    }
                    placeholder="default routing"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono"
                  />
                </div>
              </div>

              {/* Toggles */}
              <div className="flex flex-wrap items-center gap-5 pt-2 border-t border-slate-800">
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={Boolean(ruleForm.invertSource)}
                    onChange={(e) => setRuleForm({ ...ruleForm, invertSource: e.target.checked })}
                    className="w-4 h-4 rounded accent-amber-500"
                  />
                  <span>! Invert Source</span>
                </label>

                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={Boolean(ruleForm.invertDestination)}
                    onChange={(e) => setRuleForm({ ...ruleForm, invertDestination: e.target.checked })}
                    className="w-4 h-4 rounded accent-amber-500"
                  />
                  <span>! Invert Dest</span>
                </label>
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
