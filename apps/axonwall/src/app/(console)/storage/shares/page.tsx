'use client';

import { useState, useEffect } from 'react';
import { FolderKanban, Plus, Trash2, CheckCircle2, AlertCircle, HardDrive, CloudUpload, RefreshCw } from 'lucide-react';
import { getCurrentDesiredState, runNasCloudSyncAction } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import type { DesiredState, NfsExport, CloudSyncTask } from '@axonwall/lib/schemas';

export default function NasSharesPage() {
  const { applyState } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [smbName, setSmbName] = useState('corp-share');
  const [smbPath, setSmbPath] = useState('/mnt/tank/shares/general');
  const [shadowCopies, setShadowCopies] = useState(true);
  const [timeMachine, setTimeMachine] = useState(false);
  const [recycleBin, setRecycleBin] = useState(true);
  const [auditLog, setAuditLog] = useState(false);

  const [nfsPath, setNfsPath] = useState('/mnt/tank/shares/general');
  const [nfsNet, setNfsNet] = useState('192.168.1.0/24');
  const [nfsSecFlavor, setNfsSecFlavor] = useState<NonNullable<NfsExport['secFlavor']>>('sys');

  // iSCSI SAN Target state
  const [iscsiIqn, setIscsiIqn] = useState('iqn.2026-10.io.axonwall:storage.target0');
  const [iscsiPortalIp, setIscsiPortalIp] = useState('0.0.0.0');
  const [iscsiZvol, setIscsiZvol] = useState('/dev/zvol/tank/vm-lun0');
  const [iscsiInitiator, setIscsiInitiator] = useState('');

  // Cloud Sync (rclone) state
  const [syncName, setSyncName] = useState('nightly-offsite');
  const [syncProvider, setSyncProvider] = useState<CloudSyncTask['provider']>('s3');
  const [syncDirection, setSyncDirection] = useState<CloudSyncTask['direction']>('push');
  const [syncLocalPath, setSyncLocalPath] = useState('/mnt/tank/shares');
  const [syncRemoteBucket, setSyncRemoteBucket] = useState('axonwall-dr-vault/shares');
  const [syncCron, setSyncCron] = useState('0 3 * * *');
  const [syncEncrypt, setSyncEncrypt] = useState(true);

  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    getCurrentDesiredState().then(setState).catch(() => {});
  }, []);

  const ensureNas = (next: DesiredState) => {
    next.nas = next.nas || {
      enabled: true,
      workgroup: 'WORKGROUP',
      serverString: 'Axonwall Enterprise ZFS NAS',
      smbMultichannel: true,
      wsddEnabled: true,
      pools: [],
      datasets: [],
      snapshotPolicies: [],
      smbShares: [],
      nfsExports: [],
      iscsiTargets: [],
      cloudSyncTasks: [],
    };
    return next.nas;
  };

  const toggleNasGlobalSetting = async (field: 'smbMultichannel' | 'wsddEnabled', value: boolean) => {
    if (!state) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      const nas = ensureNas(next);
      nas[field] = value;
      await applyState(next);
      setState(next);
      setStatusMsg(`Updated NAS global setting ${field}=${value}.`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to update NAS setting'}`);
    } finally {
      setSaving(false);
    }
  };

  const removeSmbShare = async (shareName: string) => {
    if (!state?.nas) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      if (next.nas) {
        next.nas.smbShares = next.nas.smbShares.filter((s) => s.name !== shareName);
      }
      await applyState(next);
      setState(next);
      setStatusMsg(`Removed SMB share ${shareName}.`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to remove SMB share'}`);
    } finally {
      setSaving(false);
    }
  };

  const removeNfsExport = async (exportPath: string) => {
    if (!state?.nas) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      if (next.nas) {
        next.nas.nfsExports = next.nas.nfsExports.filter((e) => e.path !== exportPath);
      }
      await applyState(next);
      setState(next);
      setStatusMsg(`Removed NFS export ${exportPath}.`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to remove NFS export'}`);
    } finally {
      setSaving(false);
    }
  };

  const addSmbShare = async () => {
    if (!state || !smbName.trim()) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      const nas = ensureNas(next);
      nas.smbShares = [
        ...nas.smbShares.filter((s) => s.name !== smbName.trim()),
        {
          name: smbName.trim(),
          path: smbPath.trim(),
          comment: 'Managed by Axonwall ZFS NAS',
          browseable: true,
          readOnly: false,
          guestOk: false,
          shadowCopies,
          timeMachine,
          recycleBin,
          auditLog,
          validUsers: [],
          hostsAllow: [],
          enabled: true,
        },
      ];
      await applyState(next);
      setState(next);
      setStatusMsg(`Saved SMB share ${smbName.trim()}.`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save SMB share'}`);
    } finally {
      setSaving(false);
    }
  };

  const addNfsExport = async () => {
    if (!state || !nfsPath.trim()) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      const nas = ensureNas(next);
      nas.nfsExports = [
        ...nas.nfsExports.filter((e) => e.path !== nfsPath.trim()),
        {
          path: nfsPath.trim(),
          allowedNetworks: [nfsNet.trim()],
          readOnly: false,
          mapRootUser: 'root',
          secFlavor: nfsSecFlavor,
          async: false,
          description: 'NFSv4 Export',
          enabled: true,
        },
      ];
      await applyState(next);
      setState(next);
      setStatusMsg(`Saved NFSv4 export ${nfsPath.trim()} (sec=${nfsSecFlavor}).`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save NFSv4 export'}`);
    } finally {
      setSaving(false);
    }
  };

  const addIscsiTarget = async () => {
    if (!state || !iscsiIqn.trim() || !iscsiZvol.trim()) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      const nas = ensureNas(next);
      nas.iscsiTargets = [
        ...nas.iscsiTargets.filter((t) => t.iqn !== iscsiIqn.trim()),
        {
          iqn: iscsiIqn.trim(),
          portalIp: iscsiPortalIp.trim() || '0.0.0.0',
          portalPort: 3260,
          allowedInitiators: iscsiInitiator.trim() ? [iscsiInitiator.trim()] : [],
          chapUser: '',
          chapSecret: '',
          luns: [
            {
              lunId: 0,
              zvolPath: iscsiZvol.trim(),
              blockSize: '4096',
              readOnly: false,
            },
          ],
          enabled: true,
          description: 'ZFS ZVOL Block SAN Target',
        },
      ];
      await applyState(next);
      setState(next);
      setStatusMsg(`Saved iSCSI SAN target ${iscsiIqn.trim()}.`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save iSCSI target'}`);
    } finally {
      setSaving(false);
    }
  };

  const removeIscsiTarget = async (iqn: string) => {
    if (!state?.nas) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      if (next.nas) {
        next.nas.iscsiTargets = next.nas.iscsiTargets.filter((t) => t.iqn !== iqn);
      }
      await applyState(next);
      setState(next);
      setStatusMsg(`Removed iSCSI target ${iqn}.`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to remove iSCSI target'}`);
    } finally {
      setSaving(false);
    }
  };

  const addCloudSyncTask = async () => {
    if (!state || !syncName.trim() || !syncLocalPath.trim() || !syncRemoteBucket.trim()) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      const nas = ensureNas(next);
      const existing = nas.cloudSyncTasks ?? [];
      nas.cloudSyncTasks = [
        ...existing.filter((t) => t.name !== syncName.trim()),
        {
          name: syncName.trim(),
          provider: syncProvider,
          direction: syncDirection,
          transferMode: 'sync',
          localPath: syncLocalPath.trim(),
          remoteBucket: syncRemoteBucket.trim(),
          scheduleCron: syncCron.trim() || '0 3 * * *',
          bandwidthLimitMbps: 0,
          clientSideEncrypt: syncEncrypt,
          enabled: true,
          description: `${syncProvider.toUpperCase()} ${syncDirection} backup`,
        },
      ];
      await applyState(next);
      setState(next);
      setStatusMsg(`Saved Cloud Sync task '${syncName.trim()}'.`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to save Cloud Sync task'}`);
    } finally {
      setSaving(false);
    }
  };

  const removeCloudSyncTask = async (taskName: string) => {
    if (!state?.nas) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const next = structuredClone(state);
      if (next.nas) {
        next.nas.cloudSyncTasks = (next.nas.cloudSyncTasks ?? []).filter((t) => t.name !== taskName);
      }
      await applyState(next);
      setState(next);
      setStatusMsg(`Removed Cloud Sync task '${taskName}'.`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to remove Cloud Sync task'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleRunCloudSyncNow = async (taskName: string) => {
    setStatusMsg(null);
    try {
      const res = await runNasCloudSyncAction(taskName);
      setStatusMsg(res.success ? res.message : `Error: ${res.message}`);
    } catch (err: any) {
      setStatusMsg(`Error: ${err?.message || 'Failed to trigger Cloud Sync'}`);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <FolderKanban className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">NAS File, Block SAN &amp; Offsite Cloud Sync</h1>
            <p className="text-sm text-slate-400">
              Configure Samba SMB3 Multichannel shares, Kerberos NFSv4 exports, ZVOL iSCSI SAN targets, and encrypted rclone Cloud Sync.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 cursor-pointer">
            <input
              type="checkbox"
              checked={state?.nas?.smbMultichannel !== false}
              onChange={(e) => toggleNasGlobalSetting('smbMultichannel', e.target.checked)}
              className="accent-emerald-500"
            />
            SMB3 Multichannel
          </label>
          <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 cursor-pointer">
            <input
              type="checkbox"
              checked={state?.nas?.wsddEnabled !== false}
              onChange={(e) => toggleNasGlobalSetting('wsddEnabled', e.target.checked)}
              className="accent-emerald-500"
            />
            WSDD Discovery
          </label>
        </div>
      </div>

      {/* C-B12: statusMsg rendered for all handlers */}
      {statusMsg && (
        <div
          className={`p-3 rounded-lg text-xs flex items-center gap-2 ${
            statusMsg.startsWith('Error:')
              ? 'bg-red-500/10 border border-red-500/30 text-red-300'
              : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
          }`}
        >
          {statusMsg.startsWith('Error:') ? (
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          )}
          <span className="flex-1">{statusMsg}</span>
          <button onClick={() => setStatusMsg(null)}>✕</button>
        </div>
      )}

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
          <div className="grid grid-cols-2 gap-2.5 text-xs text-slate-300">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={shadowCopies} onChange={(e) => setShadowCopies(e.target.checked)} />
              VSS Shadow Copies (shadow_copy2)
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={timeMachine} onChange={(e) => setTimeMachine(e.target.checked)} />
              macOS Time Machine (vfs_fruit)
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={recycleBin} onChange={(e) => setRecycleBin(e.target.checked)} />
              Recycle Bin (.recycle / vfs_recycle)
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={auditLog} onChange={(e) => setAuditLog(e.target.checked)} />
              SMB Access Audit (vfs_full_audit)
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
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 text-[11px] font-mono">
                    {s.shadowCopies ? 'VSS ' : ''}
                    {s.timeMachine ? 'TM ' : ''}
                    {s.recycleBin ? 'Recycle ' : ''}
                    {s.auditLog ? 'Audit' : ''}
                  </span>
                  <button
                    type="button"
                    onClick={() => removeSmbShare(s.name)}
                    disabled={saving}
                    className="p-1 text-slate-400 hover:text-rose-400 transition-colors"
                    title="Delete SMB Share"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* NFSv4 Export Builder */}
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Plus className="w-4 h-4 text-emerald-400" /> Add NFSv4 Export
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
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
            <div>
              <label className="block text-xs text-slate-400 mb-1">RPCSEC_GSS Flavor</label>
              <select
                value={nfsSecFlavor}
                onChange={(e) => setNfsSecFlavor(e.target.value as NonNullable<NfsExport['secFlavor']>)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              >
                <option value="sys">sys (AUTH_SYS UID/GID)</option>
                <option value="krb5">krb5 (Kerberos Auth)</option>
                <option value="krb5i">krb5i (Kerberos + Integrity)</option>
                <option value="krb5p">krb5p (Kerberos + Encrypted)</option>
              </select>
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
                <div className="flex items-center gap-2">
                  <span className="px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 font-mono text-[10px]">
                    sec={e.secFlavor || 'sys'}
                  </span>
                  <span className="font-mono text-slate-400">{e.allowedNetworks.join(', ')}</span>
                  <button
                    type="button"
                    onClick={() => removeNfsExport(e.path)}
                    disabled={saving}
                    className="p-1 text-slate-400 hover:text-rose-400 transition-colors"
                    title="Delete NFS Export"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* iSCSI SAN Target Builder & Encrypted Cloud Sync (rclone) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* iSCSI SAN Target Builder */}
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-cyan-400" /> Add iSCSI Block SAN Target (LIO / targetcli)
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Target IQN</label>
              <input
                type="text"
                value={iscsiIqn}
                onChange={(e) => setIscsiIqn(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Backing ZVOL Device</label>
              <input
                type="text"
                value={iscsiZvol}
                onChange={(e) => setIscsiZvol(e.target.value)}
                placeholder="/dev/zvol/tank/vm-lun0"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Portal Bind IP</label>
              <input
                type="text"
                value={iscsiPortalIp}
                onChange={(e) => setIscsiPortalIp(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Allowed Initiator IQN (optional)</label>
              <input
                type="text"
                value={iscsiInitiator}
                onChange={(e) => setIscsiInitiator(e.target.value)}
                placeholder="iqn.1993-08.org.debian:01:node1"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          </div>
          <button
            disabled={saving}
            onClick={addIscsiTarget}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white"
          >
            Save iSCSI SAN Target
          </button>

          <div className="pt-4 border-t border-slate-800 space-y-2">
            {(state?.nas?.iscsiTargets ?? []).map((t) => (
              <div key={t.iqn} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                <div className="min-w-0">
                  <div className="font-mono font-bold text-cyan-300 truncate">{t.iqn}</div>
                  <div className="text-slate-400 font-mono text-[11px]">
                    {t.portalIp}:{t.portalPort} • LUN0: {t.luns?.[0]?.zvolPath || 'none'}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => removeIscsiTarget(t.iqn)}
                  disabled={saving}
                  className="p-1 text-slate-400 hover:text-rose-400 transition-colors"
                  title="Delete iSCSI Target"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Cloud Sync (rclone) Tasks */}
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <CloudUpload className="w-4 h-4 text-emerald-400" /> Offsite Cloud Sync Tasks (rclone S3 / B2 / GCS / SFTP)
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Task Name</label>
              <input
                type="text"
                value={syncName}
                onChange={(e) => setSyncName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Cloud Provider</label>
              <select
                value={syncProvider}
                onChange={(e) => setSyncProvider(e.target.value as CloudSyncTask['provider'])}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              >
                <option value="s3">AWS S3 / Wasabi / MinIO</option>
                <option value="b2">Backblaze B2</option>
                <option value="gcs">Google Cloud Storage</option>
                <option value="sftp">SFTP / SSH Vault</option>
                <option value="webdav">WebDAV</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Direction</label>
              <select
                value={syncDirection}
                onChange={(e) => setSyncDirection(e.target.value as CloudSyncTask['direction'])}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              >
                <option value="push">PUSH (ZFS → Cloud)</option>
                <option value="pull">PULL (Cloud → ZFS)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Local ZFS Dataset Path</label>
              <input
                type="text"
                value={syncLocalPath}
                onChange={(e) => setSyncLocalPath(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Remote Bucket / Prefix</label>
              <input
                type="text"
                value={syncRemoteBucket}
                onChange={(e) => setSyncRemoteBucket(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Schedule (Cron)</label>
              <input
                type="text"
                value={syncCron}
                onChange={(e) => setSyncCron(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
              />
            </div>
          </div>
          <div className="flex items-center justify-between">
            <label className="flex items-center gap-2 text-xs text-slate-300">
              <input type="checkbox" checked={syncEncrypt} onChange={(e) => setSyncEncrypt(e.target.checked)} />
              Client-Side Rclone Crypt Envelope (Zero-Knowledge Offsite Encryption)
            </label>
            <button
              disabled={saving}
              onClick={addCloudSyncTask}
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
            >
              Save Cloud Sync Task
            </button>
          </div>

          <div className="pt-4 border-t border-slate-800 space-y-2">
            {(state?.nas?.cloudSyncTasks ?? []).map((t) => (
              <div key={t.name} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs gap-2">
                <div className="min-w-0">
                  <div className="font-mono font-bold text-white truncate">
                    {t.name}{' '}
                    <span className="text-emerald-400 uppercase text-[10px]">
                      [{t.provider} • {t.direction}]
                    </span>
                  </div>
                  <div className="text-slate-400 font-mono text-[11px] truncate">
                    {t.localPath} ↔ {t.remoteBucket} ({t.scheduleCron})
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => handleRunCloudSyncNow(t.name)}
                    className="px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 font-semibold flex items-center gap-1"
                  >
                    <RefreshCw className="w-3 h-3" /> Sync Now
                  </button>
                  <button
                    type="button"
                    onClick={() => removeCloudSyncTask(t.name)}
                    disabled={saving}
                    className="p-1 text-slate-400 hover:text-rose-400 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
