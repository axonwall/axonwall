'use client';

import { useState, useEffect } from 'react';
import { Layers, Network, GitFork, ShieldAlert, Cpu, Plus, Trash2, CheckCircle2, Save, XCircle } from 'lucide-react';
import { getCurrentDesiredState } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import type { DesiredState, Vlan, Bridge, Bond, VirtualIp, Vrf } from '@axonwall/lib/schemas';

export default function AdvancedInterfacesPage() {
  const { applyState } = useDesiredStateApply();
  const [activeTab, setActiveTab] = useState<'vlan' | 'bridge' | 'bond' | 'vip' | 'vrf'>('vlan');
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  // A11: save failures need a red banner, not the emerald one.
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [vlans, setVlans] = useState<Vlan[]>([]);
  const [bridges, setBridges] = useState<Bridge[]>([]);
  const [bonds, setBonds] = useState<Bond[]>([]);
  const [vips, setVips] = useState<VirtualIp[]>([]);
  const [vrfs, setVrfs] = useState<Vrf[]>([]);

  // C-A1: nothing editable renders until the real topology loads. A
  // save before (or after a failed) load used to persist the empty
  // defaults above, wiping the whole topology from disk.
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const loadState = async () => {
    setIsLoading(true);
    setLoadError(null);
    try {
      const state = await getCurrentDesiredState();
      setFullState(state);
      setVlans(state.vlans || []);
      setBridges(state.bridges || []);
      setBonds(state.bonds || []);
      setVips(state.virtualIps || []);
      setVrfs(state.vrfs || []);
      // A17: the default VLAN parent is 'eth1', which may not
      // exist on a box with renamed NICs. Point it at the first
      // real device/bond when 'eth1' is not among them.
      const candidates = [
        ...(state.interfaces || [])
          .map((i) => i.device)
          .filter((d) => d && d !== 'none'),
        ...(state.bonds || []).map((b) => b.name),
      ];
      if (candidates.length > 0 && !candidates.includes('eth1')) {
        setNewVlanParent(candidates[0]!);
      }
    } catch (err: any) {
      setLoadError(err?.message || 'Failed to load interface topology.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadState();
  }, []);

  const persistTopology = async (
    nextVlans = vlans,
    nextBridges = bridges,
    nextBonds = bonds,
    nextVips = vips,
    nextVrfs = vrfs
  ) => {
    const prevFullState = fullState;
    const prevVlans = vlans;
    const prevBridges = bridges;
    const prevBonds = bonds;
    const prevVips = vips;
    const prevVrfs = vrfs;
    setVlans(nextVlans);
    setBridges(nextBridges);
    setBonds(nextBonds);
    setVips(nextVips);
    setVrfs(nextVrfs);
    setSaving(true);
    setStatusMsg(null);
    setErrorMsg(null);
    try {
      const current = await getCurrentDesiredState();
      const nextState: DesiredState = {
        ...current,
        vlans: nextVlans,
        bridges: nextBridges,
        bonds: nextBonds,
        virtualIps: nextVips,
        vrfs: nextVrfs,
      };
      setFullState(nextState);
      const res = await applyState(nextState);
      setStatusMsg(res.message || 'Saved topology to /etc/axonwall/interfaces.yaml');
    } catch (err: any) {
      setVlans(prevVlans);
      setBridges(prevBridges);
      setBonds(prevBonds);
      setVips(prevVips);
      setVrfs(prevVrfs);
      setFullState(prevFullState);
      setErrorMsg(`Failed to save interfaces.yaml: ${err?.message || 'Unknown error'}`);
    } finally {
      setSaving(false);
    }
  };

  // Form states for quick add
  const [newVlanTag, setNewVlanTag] = useState('');
  const [newVlanParent, setNewVlanParent] = useState('eth1');
  const [newVlanDesc, setNewVlanDesc] = useState('');

  // A17: the parent select used to hardcode eth0/eth1/bond0, so
  // boxes with renamed NICs could not pick the real parent at all.
  // Derive the options from the loaded interfaces (plus configured
  // bonds); fall back to the hardcoded three only when nothing has
  // loaded yet.
  const vlanParentOptions: { value: string; label: string }[] = (() => {
    const fromInterfaces = (fullState?.interfaces || [])
      .filter((i) => i.device && i.device !== 'none')
      .map((i) => ({ value: i.device, label: `${i.device} (${i.name})` }));
    const fromBonds = (bonds || []).map((b) => ({ value: b.name, label: `${b.name} (LACP)` }));
    const seen = new Set<string>();
    const merged = [...fromInterfaces, ...fromBonds].filter((o) => {
      if (seen.has(o.value)) return false;
      seen.add(o.value);
      return true;
    });
    if (merged.length > 0) return merged;
    return [
      { value: 'eth0', label: 'eth0 (WAN)' },
      { value: 'eth1', label: 'eth1 (LAN)' },
      { value: 'bond0', label: 'bond0 (LACP)' },
    ];
  })();

  const handleAddVlan = async (e: React.FormEvent) => {
    e.preventDefault();
    const tag = Number.parseInt(newVlanTag, 10);
    if (!tag || tag < 1 || tag > 4094) return;
    // C-A9: a duplicate (parent, tag) used to be accepted, creating two
    // `eth1.100` sub-interfaces — and deleting one row then removed
    // every VLAN sharing the tag. Reject the add with an error.
    if (vlans.some((v) => v.parentInterface === newVlanParent && v.tag === tag)) {
      setStatusMsg(`Error: VLAN ${newVlanParent}.${tag} already exists. Delete the existing VLAN first if you want to replace it.`);
      return;
    }
    const nextVlans: Vlan[] = [
      ...vlans,
      {
        tag,
        parentInterface: newVlanParent,
        vlanInterface: `${newVlanParent}.${tag}`,
        priority: 0,
        description: newVlanDesc,
      },
    ];
    setNewVlanTag('');
    setNewVlanDesc('');
    await persistTopology(nextVlans, bridges, bonds, vips, vrfs);
  };

  // C-A1: loading/error screens until the real topology loads, so Save
  // can never persist empty defaults over the live configuration.
  if (isLoading) {
    return (
      <div className="space-y-6 max-w-7xl mx-auto">
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl text-sm text-slate-300">
          Loading interface topology…
        </div>
      </div>
    );
  }

  if (loadError || !fullState) {
    return (
      <div className="space-y-6 max-w-7xl mx-auto">
        <div className="p-6 bg-red-500/10 border border-red-500/30 rounded-xl space-y-3">
          <div className="flex items-center gap-2 text-red-400 font-medium text-sm">
            <XCircle className="w-4 h-4" />
            <span>{loadError || 'Interface topology could not be loaded.'}</span>
          </div>
          <p className="text-xs text-slate-400">
            The current topology is unknown, so editing and saving are disabled until it loads successfully.
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
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Layers className="w-6 h-6 text-emerald-400" />
            Advanced Interfaces & Virtual Topologies
          </h1>
          <p className="text-sm text-slate-400">
            Configure 802.1Q VLANs, Linux bridges, LACP bonds, VIPs, and VRFs synced with{' '}
            <code className="text-emerald-400 font-mono">/etc/axonwall/interfaces.yaml</code>.
          </p>
        </div>
        <button
          type="button"
          onClick={() => persistTopology()}
          disabled={saving}
          className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
        >
          <Save className="w-3.5 h-3.5" />
          <span>{saving ? 'Saving YAML...' : 'Save to interfaces.yaml'}</span>
        </button>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {statusMsg && (
        <div
          className={`p-3 rounded-lg text-xs flex items-center gap-2 ${
            statusMsg.startsWith('Error:')
              ? 'bg-red-500/10 border border-red-500/30 text-red-300'
              : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
          }`}
        >
          {statusMsg.startsWith('Error:') ? (
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          )}
          <span>{statusMsg}</span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1">
        <button
          onClick={() => setActiveTab('vlan')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'vlan'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          VLANs (802.1Q) ({vlans.length})
        </button>
        <button
          onClick={() => setActiveTab('bridge')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'bridge'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Network className="w-4 h-4" />
          Bridges ({bridges.length})
        </button>
        <button
          onClick={() => setActiveTab('bond')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'bond'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitFork className="w-4 h-4" />
          Bonds / LAGG ({bonds.length})
        </button>
        <button
          onClick={() => setActiveTab('vip')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'vip'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          Virtual IPs ({vips.length})
        </button>
        <button
          onClick={() => setActiveTab('vrf')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'vrf'
              ? 'border-emerald-400 text-emerald-400 bg-slate-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Cpu className="w-4 h-4" />
          VRF Routing Tables ({vrfs.length})
        </button>
      </div>

      {/* Tab: VLANs */}
      {activeTab === 'vlan' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <div>
                <h3 className="font-semibold text-white">802.1Q Tagged VLAN Interfaces</h3>
                <p className="text-xs text-slate-400">Created as kernel sub-interfaces (e.g. eth1.100)</p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">VLAN Tag</th>
                    <th className="px-4 py-3">Device Interface</th>
                    <th className="px-4 py-3">Parent Link</th>
                    <th className="px-4 py-3">802.1p Priority</th>
                    <th className="px-4 py-3">Description</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {vlans.map((vlan, vlanIdx) => (
                    <tr key={vlan.id || vlan.vlanInterface} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 font-mono text-emerald-400 font-semibold">
                        Tag {vlan.tag}
                      </td>
                      <td className="px-4 py-3 font-mono font-medium text-white">{vlan.vlanInterface}</td>
                      <td className="px-4 py-3 font-mono text-slate-400">{vlan.parentInterface}</td>
                      <td className="px-4 py-3 font-mono">{vlan.priority}</td>
                      <td className="px-4 py-3 text-slate-400">{vlan.description}</td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() =>
                            // C-A9: delete exactly the clicked row. The
                            // old predicate matched on tag alone, so
                            // deleting one tag-100 row removed every
                            // VLAN sharing that tag.
                            persistTopology(
                              vlans.filter((_, i) => i !== vlanIdx),
                              bridges,
                              bonds,
                              vips,
                              vrfs
                            )
                          }
                          className="text-slate-500 hover:text-red-400 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Add VLAN Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h4 className="font-semibold text-white mb-3 text-sm flex items-center gap-2">
              <Plus className="w-4 h-4 text-emerald-400" />
              Add 802.1Q VLAN
            </h4>
            <form onSubmit={handleAddVlan} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">VLAN Tag (1-4094)</label>
                <input
                  type="number"
                  min="1"
                  max="4094"
                  value={newVlanTag}
                  onChange={(e) => setNewVlanTag(e.target.value)}
                  placeholder="100"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Parent Physical Link</label>
                <select
                  value={newVlanParent}
                  onChange={(e) => setNewVlanParent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
                >
                  {vlanParentOptions.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Description</label>
                <input
                  type="text"
                  value={newVlanDesc}
                  onChange={(e) => setNewVlanDesc(e.target.value)}
                  placeholder="e.g. DMZ Isolated"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <button
                  type="submit"
                  className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 px-4 rounded-lg text-sm transition flex items-center justify-center gap-2"
                >
                  <Plus className="w-4 h-4" />
                  Create VLAN
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Tab: Bridges */}
      {activeTab === 'bridge' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <div>
              <h3 className="font-semibold text-white">Linux VLAN-Aware Bridges</h3>
              <p className="text-xs text-slate-400">High-performance L2 switching in kernel space</p>
            </div>
          </div>
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Bridge Name</th>
                <th className="px-4 py-3">Member Interfaces</th>
                <th className="px-4 py-3">VLAN Filtering</th>
                <th className="px-4 py-3">STP (Spanning Tree)</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {bridges.map((br) => (
                <tr key={br.id || br.name} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono font-semibold text-white">{br.name}</td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1.5 flex-wrap">
                      {br.members.map((m) => (
                        <span key={m.interface} className="px-2 py-0.5 rounded bg-slate-800 font-mono text-xs text-emerald-400 border border-slate-700">
                          {m.interface}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {br.vlanFiltering ? (
                      <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Enabled (vlan_filtering 1)
                      </span>
                    ) : (
                      <span className="text-xs text-slate-500">Disabled</span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{br.stp ? 'Enabled' : 'Disabled'}</td>
                  <td className="px-4 py-3 text-slate-400">{br.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab: Bonds */}
      {activeTab === 'bond' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <div>
              <h3 className="font-semibold text-white">Link Aggregation Groups (LAGG / Bonds)</h3>
              <p className="text-xs text-slate-400">802.3ad LACP, active-backup, and round-robin bonding</p>
            </div>
          </div>
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Bond Name</th>
                <th className="px-4 py-3">Mode</th>
                <th className="px-4 py-3">Slaves / Members</th>
                <th className="px-4 py-3">LACP Rate</th>
                <th className="px-4 py-3">Transmit Hash</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {bonds.map((b) => (
                <tr key={b.id || b.name} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono font-semibold text-white">{b.name}</td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-mono border border-emerald-500/20 font-semibold">
                      {b.mode}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">
                    {b.members.join(', ')}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{b.lacpRate}</td>
                  <td className="px-4 py-3 font-mono text-xs">{b.xmitHashPolicy}</td>
                  <td className="px-4 py-3 text-slate-400">{b.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab: Virtual IPs */}
      {activeTab === 'vip' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <div>
              <h3 className="font-semibold text-white">Virtual IP Addresses (VIP)</h3>
              <p className="text-xs text-slate-400">IP Aliases for multi-IP WANs and CARP/VRRP high availability</p>
            </div>
          </div>
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Virtual IP / Subnet</th>
                <th className="px-4 py-3">Interface</th>
                <th className="px-4 py-3">VHID / Group</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {vips.map((vip) => (
                <tr key={vip.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-mono uppercase font-semibold ${
                        vip.type === 'carp'
                          ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                          : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                      }`}
                    >
                      {vip.type}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono font-medium text-white">
                    {vip.ip}/{vip.subnetBits}
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-400">{vip.interface}</td>
                  <td className="px-4 py-3 font-mono text-xs">{vip.vhid ? `vhid ${vip.vhid}` : '-'}</td>
                  <td className="px-4 py-3 text-slate-400">{vip.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab: VRF */}
      {activeTab === 'vrf' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <div>
              <h3 className="font-semibold text-white">VRF (Virtual Routing and Forwarding)</h3>
              <p className="text-xs text-slate-400">Strict kernel routing domain and interface isolation (E11)</p>
            </div>
          </div>
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">VRF Name</th>
                <th className="px-4 py-3">Routing Table ID</th>
                <th className="px-4 py-3">Bound Interfaces</th>
                <th className="px-4 py-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {vrfs.map((vrf) => (
                <tr key={vrf.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono font-semibold text-emerald-400">{vrf.name}</td>
                  <td className="px-4 py-3 font-mono text-white">table {vrf.tableId}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">{vrf.interfaces.join(', ')}</td>
                  <td className="px-4 py-3 text-slate-400">{vrf.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
