import {
  DesiredStateSchema,
  type ZfsPool,
  type ZfsDataset,
  type SmbShare,
  type NfsExport,
  type IscsiTarget,
  type ZfsSnapshotPolicy,
  type CloudSyncTask,
} from '../../schemas/index.js';
import type { ImportReport } from '../types.js';

function normalizeCompression(raw: unknown): 'lz4' | 'zstd' | 'gzip' | 'off' {
  const s = String(raw || 'lz4').toLowerCase();
  if (s === 'off' || s === 'none') return 'off';
  if (s.startsWith('zstd')) return 'zstd';
  if (s.startsWith('gzip')) return 'gzip';
  return 'lz4';
}

function normalizeRecordSize(raw: unknown): '4K' | '16K' | '64K' | '128K' | '512K' | '1M' {
  const s = String(raw || '128K').toUpperCase();
  if (s === '4K' || s === '16K' || s === '64K' || s === '128K' || s === '512K' || s === '1M') {
    return s;
  }
  return '128K';
}

export function importTruenasConfig(content: string): ImportReport {
  const warnings: string[] = [];
  const trimmed = content.trim();

  const pools: ZfsPool[] = [];
  const datasets: ZfsDataset[] = [];
  const smbShares: SmbShare[] = [];
  const nfsExports: NfsExport[] = [];
  const iscsiTargets: IscsiTarget[] = [];
  const snapshotPolicies: ZfsSnapshotPolicy[] = [];
  const cloudSyncTasks: CloudSyncTask[] = [];
  let workgroup = 'WORKGROUP';
  let serverString = 'Axonwall Enterprise ZFS NAS (Migrated from TrueNAS)';
  let smbMultichannel = true;

  if (trimmed.startsWith('{')) {
    let data: Record<string, unknown> = {};
    try {
      data = JSON.parse(trimmed) as Record<string, unknown>;
    } catch (err) {
      warnings.push(`Failed to parse TrueNAS JSON config: ${err instanceof Error ? err.message : String(err)}`);
    }

    if (data.smb && typeof data.smb === 'object') {
      const smbGlobal = data.smb as Record<string, unknown>;
      if (typeof smbGlobal.workgroup === 'string' && smbGlobal.workgroup) workgroup = smbGlobal.workgroup;
      if (typeof smbGlobal.description === 'string' && smbGlobal.description) serverString = smbGlobal.description;
      if (typeof smbGlobal.enable_smb2_3_multichannel === 'boolean') smbMultichannel = smbGlobal.enable_smb2_3_multichannel;
    }

    const rawPools = (Array.isArray(data.pools) ? data.pools : Array.isArray(data['storage.pool']) ? data['storage.pool'] : []) as Array<Record<string, unknown>>;
    for (const p of rawPools) {
      const name = String(p.name || 'tank').replace(/[^a-zA-Z0-9_.-]/g, '');
      if (!name) continue;
      const topoObj = (p.topology && typeof p.topology === 'object' ? p.topology : {}) as Record<string, unknown>;
      const dataVdevs = Array.isArray(topoObj.data) ? (topoObj.data as Array<Record<string, unknown>>) : [];
      const firstVdevType = String(dataVdevs[0]?.type || p.type || 'mirror').toLowerCase();
      let topology: 'stripe' | 'mirror' | 'raidz1' | 'raidz2' | 'raidz3' = 'mirror';
      if (firstVdevType.includes('raidz3')) topology = 'raidz3';
      else if (firstVdevType.includes('raidz2')) topology = 'raidz2';
      else if (firstVdevType.includes('raidz')) topology = 'raidz1';
      else if (firstVdevType.includes('stripe') || firstVdevType === 'disk') topology = 'stripe';

      const extractDisks = (arr: unknown): string[] => {
        if (!Array.isArray(arr)) return [];
        const out: string[] = [];
        for (const item of arr) {
          if (typeof item === 'string') {
            out.push(item.startsWith('/dev/') ? item : `/dev/${item}`);
          } else if (item && typeof item === 'object') {
            const obj = item as Record<string, unknown>;
            if (typeof obj.path === 'string') out.push(obj.path);
            else if (typeof obj.disk === 'string') out.push(`/dev/${obj.disk}`);
            if (Array.isArray(obj.children)) out.push(...extractDisks(obj.children));
            if (Array.isArray(obj.disks)) out.push(...extractDisks(obj.disks));
          }
        }
        return out;
      };

      const dataDisks = extractDisks(topoObj.data ?? p.disks);
      const specialDisks = extractDisks(topoObj.special ?? p.specialDisks);
      const logDisks = extractDisks(topoObj.log ?? p.logDisks);
      const cacheDisks = extractDisks(topoObj.cache ?? p.cacheDisks);
      const spareDisks = extractDisks(topoObj.spares ?? p.spareDisks);

      pools.push({
        name,
        topology,
        dataDisks: dataDisks.length > 0 ? dataDisks : ['/dev/sda', '/dev/sdb'],
        ...(specialDisks.length > 0 ? { specialDisks } : {}),
        logDisks,
        cacheDisks,
        spareDisks,
        ashift: 12,
        autotrim: p.autotrim !== false && p.autotrim !== 'OFF',
        compression: normalizeCompression(p.compression || 'zstd'),
        scrubScheduleCron: '0 2 * * 0',
        description: String(p.comment || p.description || `Imported TrueNAS pool ${name}`).slice(0, 255),
      });
    }

    const rawDatasets = (Array.isArray(data.datasets) ? data.datasets : Array.isArray(data['pool.dataset']) ? data['pool.dataset'] : []) as Array<Record<string, unknown>>;
    for (const ds of rawDatasets) {
      const fullId = String(ds.id || ds.name || '');
      if (!fullId || !fullId.includes('/')) continue;
      const slash = fullId.indexOf('/');
      const pool = fullId.slice(0, slash);
      const relName = fullId.slice(slash + 1);
      const isZvol = String(ds.type || '').toUpperCase() === 'VOLUME' || ds.type === 'zvol';
      const encrypted = Boolean(ds.encrypted) || (typeof ds.encryption === 'string' && ds.encryption !== 'off');
      const quotaBytes = Number(ds.quota || 0);
      const quotaGb = quotaBytes > 1024 * 1024 ? Math.round(quotaBytes / (1024 ** 3)) : Number(ds.quotaGb || 0);
      const volBytes = Number(ds.volsize || 0);
      const volSizeGb = volBytes > 1024 * 1024 ? Math.max(1, Math.round(volBytes / (1024 ** 3))) : Number(ds.volSizeGb || 10);

      datasets.push({
        name: relName,
        pool,
        type: isZvol ? 'zvol' : 'filesystem',
        compression: normalizeCompression(ds.compression),
        dedup: String(ds.deduplication || ds.dedup || 'off').toLowerCase() === 'on' ? 'on' : 'off',
        quotaGb: Math.max(0, quotaGb),
        recordSize: normalizeRecordSize(ds.recordsize || ds.recordSize),
        volSizeGb,
        encryption: encrypted ? 'aes-256-gcm' : 'off',
        ...(encrypted
          ? {
              keyFormat: 'hex' as const,
              keyLocation: `file:///etc/axonwall/zfs-keys/${pool}-${relName.replace(/[^a-zA-Z0-9._-]/g, '_')}.key`,
            }
          : {}),
        aclMode: String(ds.aclmode || 'passthrough').toLowerCase() === 'restricted' ? 'restricted' : 'passthrough',
        replicateToHaPeer: true,
        description: String(ds.comments || ds.description || `Imported TrueNAS dataset ${fullId}`).slice(0, 255),
      });
    }

    const rawSmb = (
      Array.isArray(data.smb_shares)
        ? data.smb_shares
        : Array.isArray(data.sharing_smb)
          ? data.sharing_smb
          : Array.isArray(data['sharing.smb'])
            ? data['sharing.smb']
            : []
    ) as Array<Record<string, unknown>>;
    for (const sh of rawSmb) {
      const name = String(sh.name || '').trim();
      const path = String(sh.path || '').trim();
      if (!name || !path) continue;
      smbShares.push({
        name,
        path,
        comment: String(sh.comment || '').slice(0, 255),
        readOnly: Boolean(sh.ro || sh.readOnly),
        guestOk: Boolean(sh.guestok || sh.guestOk),
        browseable: sh.browsable !== false,
        timeMachine: Boolean(sh.timemachine || sh.purpose === 'TIMEMACHINE'),
        shadowCopies: sh.shadowcopy !== false,
        recycleBin: Boolean(sh.recyclebin || sh.recycleBin),
        auditLog: Boolean(sh.audit && (sh.audit as Record<string, unknown>).enable),
        validUsers: Array.isArray(sh.validUsers) ? (sh.validUsers as string[]) : [],
        hostsAllow: Array.isArray(sh.hostsallow) ? (sh.hostsallow as string[]) : [],
        enabled: sh.enabled !== false,
      });
    }

    const rawNfs = (Array.isArray(data.nfs_shares) ? data.nfs_shares : Array.isArray(data['sharing.nfs']) ? data['sharing.nfs'] : []) as Array<Record<string, unknown>>;
    for (const ex of rawNfs) {
      const rawPath = String(ex.path || (Array.isArray(ex.paths) ? ex.paths[0] : '') || '').trim();
      if (!rawPath) continue;
      const nets = Array.isArray(ex.networks) && ex.networks.length > 0 ? (ex.networks as string[]) : ['192.168.1.0/24'];
      const secArr = Array.isArray(ex.security) ? (ex.security as string[]) : [];
      const firstSec = (secArr[0] || 'sys').toLowerCase();
      const secFlavor: 'sys' | 'krb5' | 'krb5i' | 'krb5p' =
        firstSec === 'krb5p' || firstSec === 'krb5i' || firstSec === 'krb5' ? firstSec : 'sys';
      nfsExports.push({
        path: rawPath,
        allowedNetworks: nets,
        readOnly: Boolean(ex.ro || ex.readOnly),
        mapRootUser: ex.maproot_user === 'nobody' ? 'nobody' : 'root',
        secFlavor,
        async: false,
        enabled: ex.enabled !== false,
        description: String(ex.comment || 'Imported TrueNAS NFSv4 export').slice(0, 255),
      });
    }

    const rawIscsi = (Array.isArray(data.iscsi_targets) ? data.iscsi_targets : Array.isArray(data['iscsi.target']) ? data['iscsi.target'] : []) as Array<Record<string, unknown>>;
    for (const tgt of rawIscsi) {
      const baseName = String(tgt.name || 'target0').replace(/[^a-zA-Z0-9.:-]/g, '-');
      const iqn = baseName.startsWith('iqn.') ? baseName : `iqn.2026-10.io.axonwall:${baseName}`;
      const rawZvol = String(tgt.zvol || tgt.disk || `/dev/zvol/${pools[0]?.name || 'tank'}/${baseName}`);
      iscsiTargets.push({
        iqn,
        portalIp: '0.0.0.0',
        portalPort: 3260,
        allowedInitiators: [],
        chapUser: '',
        chapSecret: '',
        luns: [
          {
            lunId: 0,
            zvolPath: rawZvol.startsWith('/dev/') ? rawZvol : `/dev/zvol/${rawZvol}`,
            blockSize: '4096',
            readOnly: false,
          },
        ],
        enabled: true,
        description: String(tgt.alias || `Imported TrueNAS iSCSI target ${baseName}`).slice(0, 255),
      });
    }

    const rawSnaps = (Array.isArray(data.snapshot_tasks) ? data.snapshot_tasks : Array.isArray(data['pool.snapshottask']) ? data['pool.snapshottask'] : []) as Array<Record<string, unknown>>;
    for (const sp of rawSnaps) {
      const dsName = String(sp.dataset || '').trim();
      if (!dsName) continue;
      const unit = String(sp.lifetime_unit || 'DAY').toUpperCase();
      const val = Number(sp.lifetime_value || 24);
      snapshotPolicies.push({
        dataset: dsName,
        interval: unit.startsWith('HOUR') ? 'hourly' : unit.startsWith('WEEK') ? 'weekly' : 'daily',
        keepCount: Math.max(1, Math.min(1000, val)),
        replicateToHaPeer: true,
        enabled: sp.enabled !== false,
      });
    }

    const rawCloudSync = (Array.isArray(data.cloudsync_tasks) ? data.cloudsync_tasks : Array.isArray(data['cloudsync.task']) ? data['cloudsync.task'] : []) as Array<Record<string, unknown>>;
    for (const cs of rawCloudSync) {
      const rawName = String(cs.description || cs.name || `cloudsync_${cloudSyncTasks.length + 1}`)
        .replace(/[^a-zA-Z0-9_-]/g, '_');
      const rawLocal = String(cs.path || '/mnt/tank/backups').trim();
      const localPath = rawLocal.startsWith('/mnt/') ? rawLocal : `/mnt/tank/${rawLocal.replace(/^\/+/, '')}`;
      const attrs = (cs.attributes && typeof cs.attributes === 'object' ? cs.attributes : {}) as Record<string, unknown>;
      const bucket = String(attrs.bucket || cs.remoteBucket || 'truenas-backup').replace(/[^a-zA-Z0-9._:/-]/g, '');
      cloudSyncTasks.push({
        name: rawName,
        provider: 's3',
        direction: String(cs.direction || 'PUSH').toLowerCase() === 'pull' ? 'pull' : 'push',
        transferMode: String(cs.transfer_mode || 'SYNC').toLowerCase() === 'copy' ? 'copy' : 'sync',
        localPath,
        remoteBucket: bucket || 'truenas-backup',
        scheduleCron: '0 3 * * *',
        bandwidthLimitMbps: 0,
        clientSideEncrypt: Boolean(cs.encryption ?? true),
        enabled: cs.enabled !== false,
        description: `Imported TrueNAS Cloud Sync (${rawName})`.slice(0, 255),
      });
    }
  } else {
    // Parse Samba smb.conf / /etc/exports text configuration
    let currentSection = '';
    let curShare: Partial<SmbShare> | null = null;
    const flushShare = () => {
      if (curShare && curShare.name && curShare.path) {
        smbShares.push({
          name: curShare.name,
          path: curShare.path.startsWith('/mnt/') ? curShare.path : `/mnt/tank/${curShare.name}`,
          comment: curShare.comment || '',
          readOnly: Boolean(curShare.readOnly),
          guestOk: Boolean(curShare.guestOk),
          browseable: curShare.browseable !== false,
          timeMachine: Boolean(curShare.timeMachine),
          shadowCopies: curShare.shadowCopies !== false,
          recycleBin: Boolean(curShare.recycleBin),
          auditLog: Boolean(curShare.auditLog),
          validUsers: curShare.validUsers || [],
          hostsAllow: [],
          enabled: true,
        });
      }
      curShare = null;
    };

    for (const rawLine of content.replace(/\r\n/g, '\n').split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith(';')) continue;
      const secMatch = line.match(/^\[([^\]]+)\]$/);
      if (secMatch) {
        flushShare();
        currentSection = secMatch[1]!.trim();
        if (currentSection.toLowerCase() !== 'global' && currentSection.toLowerCase() !== 'printers') {
          curShare = { name: currentSection };
        }
        continue;
      }

      if (line.startsWith('/mnt/') && line.includes('(')) {
        // /etc/exports line
        const parts = line.split(/\s+/);
        const expPath = parts[0]!;
        const nets: string[] = [];
        for (const spec of parts.slice(1)) {
          const paren = spec.indexOf('(');
          const host = paren === -1 ? spec : spec.slice(0, paren);
          if (host && host !== '*') nets.push(host);
        }
        nfsExports.push({
          path: expPath,
          allowedNetworks: nets.length > 0 ? nets : ['192.168.1.0/24'],
          readOnly: line.includes('(ro') || line.includes(',ro,') || line.includes(',ro)'),
          mapRootUser: line.includes('all_squash') ? 'nobody' : 'root',
          secFlavor: line.includes('sec=krb5p') ? 'krb5p' : line.includes('sec=krb5i') ? 'krb5i' : line.includes('sec=krb5') ? 'krb5' : 'sys',
          async: line.includes('async'),
          enabled: true,
          description: 'Imported NFS export',
        });
        continue;
      }

      const eq = line.indexOf('=');
      if (eq !== -1) {
        const k = line.slice(0, eq).trim().toLowerCase();
        const v = line.slice(eq + 1).trim();
        if (currentSection.toLowerCase() === 'global') {
          if (k === 'workgroup') workgroup = v;
          if (k === 'server string') serverString = v;
          if (k === 'server multi channel support') smbMultichannel = v.toLowerCase() !== 'no';
        } else if (curShare) {
          if (k === 'path') curShare.path = v;
          else if (k === 'comment') curShare.comment = v;
          else if (k === 'read only') curShare.readOnly = v.toLowerCase() === 'yes';
          else if (k === 'guest ok') curShare.guestOk = v.toLowerCase() === 'yes';
          else if (k === 'browseable' || k === 'browsable') curShare.browseable = v.toLowerCase() !== 'no';
          else if (k === 'vfs objects') {
            if (v.includes('fruit')) curShare.timeMachine = true;
            if (v.includes('recycle')) curShare.recycleBin = true;
            if (v.includes('full_audit')) curShare.auditLog = true;
          }
        }
      }
    }
    flushShare();
  }

  if (pools.length === 0) {
    pools.push({
      name: 'tank',
      topology: 'raidz2',
      dataDisks: ['/dev/sda', '/dev/sdb', '/dev/sdc', '/dev/sdd'],
      cacheDisks: [],
      logDisks: [],
      spareDisks: [],
      ashift: 12,
      autotrim: true,
      compression: 'zstd',
      scrubScheduleCron: '0 2 * * 0',
      description: 'Synthesized default ZFS pool for imported TrueNAS shares',
    });
  }

  const baseState = DesiredStateSchema.parse({
    plugins: [
      { id: 'core-firewall', enabled: true },
      { id: 'core-nas', enabled: true },
    ],
    nas: {
      enabled: true,
      workgroup,
      serverString,
      smbMultichannel,
      wsddEnabled: true,
      pools,
      datasets,
      snapshotPolicies,
      smbShares,
      nfsExports,
      iscsiTargets,
      cloudSyncTasks,
    },
  });

  const totalShares = smbShares.length + nfsExports.length + iscsiTargets.length;

  return {
    success: true,
    vendor: 'truenas',
    version: 'TrueNAS SCALE 24.10+',
    sourceFormat: trimmed.startsWith('{') ? 'TrueNAS SCALE JSON Export' : 'Samba smb.conf / NFS exports',
    interfacesCount: baseState.interfaces.length,
    vlansCount: 0,
    aliasesCount: 0,
    rulesCount: 0,
    natRulesCount: 0,
    dhcpSubnetsCount: 0,
    dnsOverridesCount: 0,
    routesCount: 0,
    zfsPoolsCount: pools.length,
    datasetsCount: datasets.length,
    sharesCount: totalShares,
    warnings,
    state: baseState,
  };
}
