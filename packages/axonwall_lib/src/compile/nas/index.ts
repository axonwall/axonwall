import type { NasConfig, ZfsPool, ZfsDataset } from '../../schemas/index.js';

export interface CompiledNas {
  smbConf: string;
  nfsExports: string;
  iscsiConf: string;
  lioSaveconfigJson: string;
  s3EnvConf: string;
  cloudSyncCommands: string[];
  zfsCommands: string[];
}

export function compileZfsPoolCommand(pool: ZfsPool): string {
  const args: string[] = [
    'zpool create -f',
    `-o ashift=${pool.ashift ?? 12}`,
    `-o autotrim=${pool.autotrim !== false ? 'on' : 'off'}`,
    `-O compression=${pool.compression ?? 'lz4'}`,
    '-O acltype=posixacl',
    '-O xattr=sa',
    '-O dnodesize=auto',
    '-O normalization=formD',
  ];
  if (pool.specialSmallBlocks && pool.specialSmallBlocks !== '0') {
    args.push(`-O special_small_blocks=${pool.specialSmallBlocks}`);
  }
  args.push(`-O mountpoint=/mnt/${pool.name}`, pool.name);

  if (pool.topology && pool.topology !== 'stripe') {
    args.push(pool.topology);
  }
  args.push(...pool.dataDisks);

  if (pool.specialDisks && pool.specialDisks.length > 0) {
    args.push('special');
    if (pool.specialDisks.length >= 2) {
      args.push('mirror');
    }
    args.push(...pool.specialDisks);
  }

  if (pool.dedupDisks && pool.dedupDisks.length > 0) {
    args.push('dedup');
    if (pool.dedupDisks.length >= 2) {
      args.push('mirror');
    }
    args.push(...pool.dedupDisks);
  }

  if (pool.logDisks && pool.logDisks.length > 0) {
    args.push('log');
    if (pool.logDisks.length >= 2) {
      args.push('mirror');
    }
    args.push(...pool.logDisks);
  }

  if (pool.cacheDisks && pool.cacheDisks.length > 0) {
    args.push('cache', ...pool.cacheDisks);
  }

  if (pool.spareDisks && pool.spareDisks.length > 0) {
    args.push('spare', ...pool.spareDisks);
  }

  return args.join(' ');
}

export function compileZfsDatasetCommands(dataset: ZfsDataset): string[] {
  const fullName = dataset.name.startsWith(`${dataset.pool}/`)
    ? dataset.name
    : `${dataset.pool}/${dataset.name}`;

  const encOpts: string[] = [];
  if (dataset.encryption && dataset.encryption !== 'off') {
    encOpts.push(`-o encryption=${dataset.encryption}`);
    encOpts.push(`-o keyformat=${dataset.keyFormat || 'hex'}`);
    encOpts.push(`-o keylocation=${dataset.keyLocation || 'prompt'}`);
  }

  if (dataset.type === 'zvol') {
    const volSize = dataset.volSizeGb && dataset.volSizeGb > 0 ? `${dataset.volSizeGb}G` : '10G';
    const zvolParts = [
      `zfs create -p -V ${volSize}`,
      `-o compression=${dataset.compression ?? 'lz4'}`,
      '-o volblocksize=16K',
      ...encOpts,
      fullName,
    ];
    return [zvolParts.join(' ')];
  }

  const createParts: string[] = [
    'zfs create -p',
    `-o compression=${dataset.compression ?? 'lz4'}`,
    `-o recordsize=${dataset.recordSize ?? '128K'}`,
    `-o dedup=${dataset.dedup ?? 'off'}`,
    `-o aclmode=${dataset.aclMode ?? 'passthrough'}`,
  ];
  if (dataset.atime) {
    createParts.push(`-o atime=${dataset.atime}`);
  }
  if (dataset.sync) {
    createParts.push(`-o sync=${dataset.sync}`);
  }
  if (dataset.specialSmallBlocks && dataset.specialSmallBlocks !== '0') {
    createParts.push(`-o special_small_blocks=${dataset.specialSmallBlocks}`);
  }
  createParts.push(...encOpts, fullName);

  const cmds: string[] = [createParts.join(' ')];
  if (dataset.quotaGb && dataset.quotaGb > 0) {
    cmds.push(`zfs set quota=${dataset.quotaGb}G ${fullName}`);
  }
  if (dataset.refQuotaGb && dataset.refQuotaGb > 0) {
    cmds.push(`zfs set refquota=${dataset.refQuotaGb}G ${fullName}`);
  }
  if (dataset.refReservationGb && dataset.refReservationGb > 0) {
    cmds.push(`zfs set refreservation=${dataset.refReservationGb}G ${fullName}`);
  }
  return cmds;
}

function sanitizeIniVal(v?: string): string {
  if (!v) return '';
  return v.replace(/[\r\n]/g, '').trim();
}

function sanitizeIniSection(v?: string): string {
  if (!v) return '';
  return v.replace(/[\r\n[\]]/g, '_').trim();
}

export function compileSmbConf(nas?: NasConfig): string {
  const lines: string[] = [
    '# Axonwall Auto-Generated Samba (SMB3) Configuration',
    '[global]',
    `  workgroup = ${sanitizeIniVal(nas?.workgroup) || 'WORKGROUP'}`,
    `  server string = ${sanitizeIniVal(nas?.serverString) || 'Axonwall Enterprise ZFS NAS'}`,
    '  security = user',
    '  map to guest = Bad User',
    '  server min protocol = SMB2_10',
    `  server multi channel support = ${nas?.smbMultichannel !== false ? 'yes' : 'no'}`,
    '  ea support = yes',
    '  vfs objects = acl_xattr',
    '  map acl inherit = yes',
    '  store dos attributes = yes',
    '  load printers = no',
    '  printing = bsd',
    '  printcap name = /dev/null',
    '  disable spoolss = yes',
    '',
  ];

  for (const share of nas?.smbShares ?? []) {
    if (!share.enabled) continue;
    lines.push(`[${sanitizeIniSection(share.name)}]`);
    lines.push(`  path = ${sanitizeIniVal(share.path)}`);
    if (share.comment) {
      lines.push(`  comment = ${sanitizeIniVal(share.comment)}`);
    }
    lines.push(`  browseable = ${share.browseable !== false ? 'yes' : 'no'}`);
    lines.push(`  read only = ${share.readOnly ? 'yes' : 'no'}`);
    lines.push(`  guest ok = ${share.guestOk ? 'yes' : 'no'}`);

    const vfsObjects: string[] = ['acl_xattr'];
    if (share.shadowCopies) {
      vfsObjects.push('shadow_copy2');
    }
    if (share.timeMachine) {
      vfsObjects.push('catia', 'fruit', 'streams_xattr');
    }
    if (share.recycleBin) {
      vfsObjects.push('recycle');
    }
    if (share.auditLog) {
      vfsObjects.push('full_audit');
    }
    lines.push(`  vfs objects = ${vfsObjects.join(' ')}`);

    if (share.shadowCopies) {
      lines.push('  shadow:snapdir = .zfs/snapshot');
      lines.push('  shadow:sort = desc');
      lines.push('  shadow:format = @auto-%Y%m%d-%H%M');
      lines.push('  shadow:localtime = yes');
    }

    if (share.timeMachine) {
      lines.push('  fruit:aapl = yes');
      lines.push('  fruit:time machine = yes');
    }

    if (share.recycleBin) {
      lines.push('  recycle:repository = .recycle/%U');
      lines.push('  recycle:keeptree = yes');
      lines.push('  recycle:versions = yes');
      lines.push('  recycle:touch = yes');
    }

    if (share.auditLog) {
      lines.push('  full_audit:prefix = %u|%I|%S');
      lines.push('  full_audit:success = open write unlink rename mkdir rmdir');
      lines.push('  full_audit:failure = connect');
    }

    if (share.validUsers && share.validUsers.length > 0) {
      lines.push(`  valid users = ${share.validUsers.map(sanitizeIniVal).join(' ')}`);
    }
    if (share.hostsAllow && share.hostsAllow.length > 0) {
      lines.push(`  hosts allow = ${share.hostsAllow.map(sanitizeIniVal).join(' ')}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function compileNfsExports(nas?: NasConfig): string {
  const lines: string[] = [
    '# Axonwall Auto-Generated NFSv4 Exports',
  ];

  for (const exp of nas?.nfsExports ?? []) {
    if (!exp.enabled) continue;
    const mode = exp.readOnly ? 'ro' : 'rw';
    const syncMode = exp.async ? 'async' : 'sync';
    const squash = exp.mapRootUser === 'root' ? 'no_root_squash' : 'root_squash';
    const secOpt = exp.secFlavor && exp.secFlavor !== 'sys' ? `,sec=${exp.secFlavor}` : '';
    const rawNets = exp.allowedNetworks && exp.allowedNetworks.length > 0
      ? exp.allowedNetworks
      : ['*'];
    const nets = rawNets.map((n) => sanitizeIniVal(n).replace(/[\s()]/g, '')).filter(Boolean);
    const clientSpecs = nets.map((net) => `${net}(${mode},${syncMode},no_subtree_check,${squash}${secOpt})`).join(' ');
    lines.push(`${sanitizeIniVal(exp.path).replace(/[\s()]/g, '')} ${clientSpecs}`);
  }

  lines.push('');
  return lines.join('\n');
}

export function compileLioTargetSaveconfig(nas?: NasConfig): string {
  const targets = (nas?.iscsiTargets ?? []).filter((t) => t.enabled);
  const storageObjects: Array<Record<string, unknown>> = [];
  const targetEntries: Array<Record<string, unknown>> = [];

  for (const t of targets) {
    const tpgLuns: Array<Record<string, unknown>> = [];
    for (const l of t.luns) {
      const zvolDev = l.zvolPath.startsWith('/dev/')
        ? l.zvolPath
        : `/dev/zvol/${l.zvolPath.replace(/^\/+/, '')}`;
      const soName = `${t.iqn.replace(/[^a-zA-Z0-9_-]/g, '_')}_lun${l.lunId}`;
      storageObjects.push({
        alua_tpgs: [{ alua_access_type: 3, name: 'default_tg_pt_gp', tg_pt_gp_id: 0 }],
        attributes: { block_size: Number(l.blockSize || '4096'), emulate_tpu: 1 },
        dev: zvolDev,
        name: soName,
        plugin: 'block',
        readonly: Boolean(l.readOnly),
      });
      tpgLuns.push({
        index: l.lunId,
        storage_object: `/backstores/block/${soName}`,
      });
    }

    targetEntries.push({
      fabric: 'iscsi',
      wwn: t.iqn,
      tpgs: [
        {
          enable: true,
          tag: 1,
          attributes: {
            authentication: t.chapUser && t.chapSecret ? 1 : 0,
            generate_node_acls: t.allowedInitiators.length === 0 ? 1 : 0,
            cache_dynamic_acls: t.allowedInitiators.length === 0 ? 1 : 0,
          },
          luns: tpgLuns,
          portals: [{ ip_address: t.portalIp || '0.0.0.0', port: t.portalPort || 3260 }],
          node_acls: t.allowedInitiators.map((initWwn) => ({
            node_wwn: initWwn,
            ...(t.chapUser && t.chapSecret
              ? { chap_userid: t.chapUser, chap_password: t.chapSecret }
              : {}),
            mapped_luns: tpgLuns.map((tl) => ({
              index: tl.index,
              tpg_lun: tl.index,
              write_protect: false,
            })),
          })),
        },
      ],
    });
  }

  return JSON.stringify(
    {
      fabric_modules: [],
      storage_objects: storageObjects,
      targets: targetEntries,
    },
    null,
    2,
  );
}

export function compileS3MinioEnv(nas?: NasConfig): string {
  const s3 = nas?.s3;
  if (!s3?.enabled) return '';
  const rootDir = sanitizeIniVal(s3.rootDataset || '/mnt/tank/s3');
  const accessKey = sanitizeIniVal(s3.accessKey || 'axonwall-admin');
  const secretKey = sanitizeIniVal(s3.secretKey || '');
  return [
    '# Axonwall Auto-Generated S3 Object Storage (MinIO) Configuration',
    `MINIO_VOLUMES="${rootDir}"`,
    `MINIO_OPTS="--address :${s3.listenPort || 9000} --console-address :${s3.consolePort || 9001}"`,
    `MINIO_ROOT_USER="${accessKey}"`,
    ...(secretKey ? [`MINIO_ROOT_PASSWORD="${secretKey}"`] : []),
    '',
  ].join('\n');
}

export function compileCloudSyncCommands(nas?: NasConfig): string[] {
  const cmds: string[] = [];
  for (const task of nas?.cloudSyncTasks ?? []) {
    if (!task.enabled) continue;
    const verb = task.transferMode === 'copy' ? 'copy' : 'sync';
    const bw = task.bandwidthLimitMbps > 0 ? ` --bwlimit ${task.bandwidthLimitMbps}M` : '';
    const remoteSpec = `${task.provider}:${task.remoteBucket}`;
    if (task.direction === 'pull') {
      cmds.push(`rclone ${verb} "${remoteSpec}" "${task.localPath}"${bw}`);
    } else {
      cmds.push(`rclone ${verb} "${task.localPath}" "${remoteSpec}"${bw}`);
    }
  }
  return cmds;
}

export function compileIscsiConfig(nas?: NasConfig): string {
  const targets = (nas?.iscsiTargets ?? []).filter((t) => t.enabled);
  return JSON.stringify(
    {
      generatedBy: 'axonwall-nas-compiler',
      targets: targets.map((t) => ({
        iqn: t.iqn,
        portal: `${t.portalIp}:${t.portalPort}`,
        allowedInitiators: t.allowedInitiators,
        chapEnabled: Boolean(t.chapUser && t.chapSecret),
        chapUser: t.chapUser || undefined,
        chapSecret: t.chapSecret || undefined,
        luns: t.luns.map((l) => ({
          lunId: l.lunId,
          zvolDevice: l.zvolPath.startsWith('/dev/') ? l.zvolPath : `/dev/zvol/${l.zvolPath.replace(/^\/+/, '')}`,
          blockSize: Number(l.blockSize),
          readOnly: l.readOnly,
        })),
      })),
    },
    null,
    2,
  );
}

export function compileNas(nas?: NasConfig): CompiledNas {
  const zfsCommands: string[] = [];
  for (const pool of nas?.pools ?? []) {
    zfsCommands.push(compileZfsPoolCommand(pool));
  }
  for (const ds of nas?.datasets ?? []) {
    zfsCommands.push(...compileZfsDatasetCommands(ds));
  }

  return {
    smbConf: compileSmbConf(nas),
    nfsExports: compileNfsExports(nas),
    iscsiConf: compileIscsiConfig(nas),
    lioSaveconfigJson: compileLioTargetSaveconfig(nas),
    s3EnvConf: compileS3MinioEnv(nas),
    cloudSyncCommands: compileCloudSyncCommands(nas),
    zfsCommands,
  };
}
