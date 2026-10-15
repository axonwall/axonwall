'use client';

import { useState, useEffect } from 'react';
import { FolderKanban, Plus, Trash2 } from 'lucide-react';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';
import type { DesiredState } from '@axonwall/lib/schemas';

export default function NasSharesPage() {
  const [state, setState] = useState<DesiredState | null>(null);
  const [smbName, setSmbName] = useState('corp-share');
  const [smbPath, setSmbPath] = useState('/mnt/tank/shares/general');
  const [shadowCopies, setShadowCopies] = useState(true);
  const [timeMachine, setTimeMachine] = useState(false);

  const [nfsPath, setNfsPath] = useState('/mnt/tank/shares/general');
  const [nfsNet, setNfsNet] = useState('192.168.1.0/24');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getCurrentDesiredState().then(setState).catch(() => {});
  }, []);

  const addSmbShare = async () => {
    if (!state || !smbName.trim()) return;
    setSaving(true);
    try {
      const next = structuredClone(state);
      next.nas = next.nas || {
        enabled: true,
        workgroup: 'WORKGROUP',
        serverString: 'Axonwall Enterprise ZFS NAS',
        pools: [],
        datasets: [],
        snapshotPolicies: [],
        smbShares: [],
        nfsExports: [],
        iscsiTargets: [],
      };
      next.nas.smbShares = [
        ...next.nas.smbShares.filter((s) => s.name !== smbName.trim()),
        {
          name: smbName.trim(),
          path: smbPath.trim(),
          comment: 'Managed by Axonwall ZFS NAS',
          browseable: true,
          readOnly: false,
          guestOk: false,
          shadowCopies,
          timeMachine,
          validUsers: [],
          hostsAllow: [],
          enabled: true,
        },
      ];
      await applyDesiredState(next);
      setState(next);
    } finally {
      setSaving(false);
    }
  };

  const addNfsExport = async () => {
    if (!state || !nfsPath.trim()) return;
    setSaving(true);
    try {
      const next = structuredClone(state);
      next.nas = next.nas || {
        enabled: true,
        workgroup: 'WORKGROUP',
        serverString: 'Axonwall Enterprise ZFS NAS',
        pools: [],
        datasets: [],
        snapshotPolicies: [],
        smbShares: [],
        nfsExports: [],
        iscsiTargets: [],
      };
      next.nas.nfsExports = [
        ...next.nas.nfsExports.filter((e) => e.path !== nfsPath.trim()),
        {
          path: nfsPath.trim(),
          allowedNetworks: [nfsNet.trim()],
          readOnly: false,
          mapRootUser: 'root',
          async: false,
          description: 'NFSv4 Export',
          enabled: true,
        },
      ];
      await applyDesiredState(next);
      setState(next);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex items-center gap-3 border-b border-slate-800 pb-6">
        <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
          <FolderKanban className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">NAS File & Block Shares (SMB / NFSv4 / iSCSI)</h1>
          <p className="text-sm text-slate-400">
            Configure Samba SMB3 shares with ZFS VSS Shadow Copies, Apple Time Machine, and NFSv4 exports bound to HA VIPs.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SMB Share Builder */}
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Plus className="w-4 h-4 text-emerald-400" /> Add Samba (SMB3) Share
          </h2>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Share Name</label>
              <input
                type="text"
                value={smbName}
                onChange={(e) => setSmbName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">ZFS Dataset Mount Path</label>
              <input
                type="text"
                value={smbPath}
                onChange={(e) => setSmbPath(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          </div>
          <div className="flex items-center gap-6 text-xs text-slate-300">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={shadowCopies} onChange={(e) => setShadowCopies(e.target.checked)} />
              Windows Previous Versions (shadow_copy2)
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={timeMachine} onChange={(e) => setTimeMachine(e.target.checked)} />
              macOS Time Machine (vfs_fruit)
            </label>
          </div>
          <button
            disabled={saving}
            onClick={addSmbShare}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
          >
            Save SMB3 Share
          </button>

          <div className="pt-4 border-t border-slate-800 space-y-2">
            {(state?.nas?.smbShares ?? []).map((s) => (
              <div key={s.name} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                <div>
                  <span className="font-bold text-white font-mono">\\axonwall\{s.name}</span>
                  <span className="text-slate-400 ml-2 font-mono">→ {s.path}</span>
                </div>
                <span className="text-emerald-400 text-[11px] font-mono">
                  {s.shadowCopies ? 'VSS ' : ''}{s.timeMachine ? 'TimeMachine' : ''}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* NFSv4 Export Builder */}
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Plus className="w-4 h-4 text-emerald-400" /> Add NFSv4 Export
          </h2>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Export Path</label>
              <input
                type="text"
                value={nfsPath}
                onChange={(e) => setNfsPath(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Allowed Subnet CIDR</label>
              <input
                type="text"
                value={nfsNet}
                onChange={(e) => setNfsNet(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          </div>
          <button
            disabled={saving}
            onClick={addNfsExport}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
          >
            Save NFSv4 Export
          </button>

          <div className="pt-4 border-t border-slate-800 space-y-2">
            {(state?.nas?.nfsExports ?? []).map((e) => (
              <div key={e.path} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                <span className="font-mono text-white">{e.path}</span>
                <span className="font-mono text-slate-400">{e.allowedNetworks.join(', ')}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
