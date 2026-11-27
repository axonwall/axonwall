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

const SAFE_ZFS_POOL_REGEX = /^[a-zA-Z][a-zA-Z0-9_.:-]*$/;
const SAFE_ZFS_DATASET_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9_.:/-]*$/;
const SAFE_ZFS_DISK_REGEX = /^\/dev\/[a-zA-Z0-9_.:/-]+$/;
const SAFE_ZFS_TOKEN_REGEX = /^[a-zA-Z0-9_.-]+$/;
const SAFE_RCLONE_PROVIDER_REGEX = /^[a-zA-Z0-9_-]+$/;
const RESERVED_SMB_SECTIONS = new Set(['global', 'homes', 'printers', 'ipc$']);

function shellSingleQuote(v: string): string {
  if (/[\0\r\n]/.test(v)) {
    throw new Error('Control characters are forbidden in shell arguments');
  }
  return `'${v.replace(/'/g, "'\\''")}'`;
}

function shellSafeZfsArg(v: string): string {
  if (/[\0\r\n]/.test(v)) {
    throw new Error('Control characters are forbidden in ZFS arguments');
  }
  if (/^[a-zA-Z0-9_./:=+-]+$/.test(v)) {
    return v;
  }
  return shellSingleQuote(v);
}

function assertSafeZfsDisks(disks: string[] | undefined, kind: string): string[] {
  return (disks ?? []).map((disk) => {
    if (!disk || !SAFE_ZFS_DISK_REGEX.test(disk) || disk.includes('..')) {
      throw new Error(`Invalid ZFS ${kind} disk path: ${disk}`);
    }
    return shellSafeZfsArg(disk);
  });
}

function assertSafeZfsToken(val: string, label: string): string {
  if (!val || !SAFE_ZFS_TOKEN_REGEX.test(val) || val.includes('..')) {
    throw new Error(`Invalid ZFS ${label}: ${val}`);
  }
  return shellSafeZfsArg(val);
}

export function compileZfsPoolCommand(pool: ZfsPool): string {
  if (!pool.name || !SAFE_ZFS_POOL_REGEX.test(pool.name) || pool.name.includes('..')) {
    throw new Error(`Invalid ZFS pool name: ${pool.name}`);
  }
  const safePoolName = shellSafeZfsArg(pool.name);
  const ashift = Number.isInteger(pool.ashift) ? Number(pool.ashift) : 12;
  const compression = assertSafeZfsToken(pool.compression ?? 'lz4', 'compression');
  const topology = pool.topology ? assertSafeZfsToken(pool.topology, 'topology') : undefined;

  const args: string[] = [
    'zpool create -f',
    `-o ashift=${ashift}`,
    `-o autotrim=${pool.autotrim !== false ? 'on' : 'off'}`,
    `-O compression=${compression}`,
    '-O acltype=posixacl',
    '-O xattr=sa',
    '-O dnodesize=auto',
    '-O normalization=formD',
  ];
  if (pool.specialSmallBlocks && pool.specialSmallBlocks !== '0') {
    args.push(`-O special_small_blocks=${assertSafeZfsToken(pool.specialSmallBlocks, 'specialSmallBlocks')}`);
  }
  args.push(`-O mountpoint=/mnt/${safePoolName}`, safePoolName);

  if (topology && topology !== 'stripe') {
    args.push(topology);
  }
  args.push(...assertSafeZfsDisks(pool.dataDisks, 'data'));

  const specialDisks = assertSafeZfsDisks(pool.specialDisks, 'special');
  if (specialDisks.length > 0) {
    args.push('special');
    if (specialDisks.length >= 2) {
      args.push('mirror');
    }
    args.push(...specialDisks);
  }

  const dedupDisks = assertSafeZfsDisks(pool.dedupDisks, 'dedup');
  if (dedupDisks.length > 0) {
    args.push('dedup');
    if (dedupDisks.length >= 2) {
      args.push('mirror');
    }
    args.push(...dedupDisks);
  }

  const logDisks = assertSafeZfsDisks(pool.logDisks, 'log');
  if (logDisks.length > 0) {
    args.push('log');
    if (logDisks.length >= 2) {
      args.push('mirror');
    }
    args.push(...logDisks);
  }

  const cacheDisks = assertSafeZfsDisks(pool.cacheDisks, 'cache');
  if (cacheDisks.length > 0) {
    args.push('cache', ...cacheDisks);
  }

  const spareDisks = assertSafeZfsDisks(pool.spareDisks, 'spare');
  if (spareDisks.length > 0) {
    args.push('spare', ...spareDisks);
  }

  return args.join(' ');
}

export function compileZfsDatasetCommands(dataset: ZfsDataset): string[] {
  if (!dataset.pool || !SAFE_ZFS_POOL_REGEX.test(dataset.pool) || dataset.pool.includes('..')) {
    throw new Error(`Invalid ZFS pool name: ${dataset.pool}`);
  }
  if (!dataset.name || !SAFE_ZFS_DATASET_REGEX.test(dataset.name) || dataset.name.includes('..') || dataset.name.endsWith('/')) {
    throw new Error(`Invalid ZFS dataset name: ${dataset.name}`);
  }
  const fullName = dataset.name.startsWith(`${dataset.pool}/`)
    ? dataset.name
    : `${dataset.pool}/${dataset.name}`;
  if (!SAFE_ZFS_DATASET_REGEX.test(fullName) || fullName.includes('..') || fullName.endsWith('/')) {
    throw new Error(`Invalid full ZFS dataset name: ${fullName}`);
  }
  const safeFullName = shellSafeZfsArg(fullName);

  const encOpts: string[] = [];
  if (dataset.encryption && dataset.encryption !== 'off') {
    const keyLoc = dataset.keyLocation || 'prompt';
    if (keyLoc !== 'prompt' && (!/^file:\/\/\/[a-zA-Z0-9_./-]+$/.test(keyLoc) || keyLoc.includes('..'))) {
      throw new Error(`Invalid ZFS keyLocation: ${keyLoc}`);
    }
    encOpts.push(`-o encryption=${assertSafeZfsToken(dataset.encryption, 'encryption')}`);
    encOpts.push(`-o keyformat=${assertSafeZfsToken(dataset.keyFormat || 'hex', 'keyFormat')}`);
    encOpts.push(`-o keylocation=${shellSafeZfsArg(keyLoc)}`);
  }

  if (dataset.type === 'zvol') {
    const volSize = dataset.volSizeGb && Number.isFinite(dataset.volSizeGb) && dataset.volSizeGb > 0
      ? `${Math.trunc(dataset.volSizeGb)}G`
      : '10G';
    const zvolParts = [
      `zfs create -p -V ${volSize}`,
      `-o compression=${assertSafeZfsToken(dataset.compression ?? 'lz4', 'compression')}`,
      '-o volblocksize=16K',
      ...encOpts,
      safeFullName,
    ];
    return [zvolParts.join(' ')];
  }

  const createParts: string[] = [
    'zfs create -p',
    `-o compression=${assertSafeZfsToken(dataset.compression ?? 'lz4', 'compression')}`,
    `-o recordsize=${assertSafeZfsToken(dataset.recordSize ?? '128K', 'recordSize')}`,
    `-o dedup=${assertSafeZfsToken(dataset.dedup ?? 'off', 'dedup')}`,
    `-o aclmode=${assertSafeZfsToken(dataset.aclMode ?? 'passthrough', 'aclMode')}`,
  ];
  if (dataset.atime) {
    createParts.push(`-o atime=${assertSafeZfsToken(dataset.atime, 'atime')}`);
  }
  if (dataset.sync) {
    createParts.push(`-o sync=${assertSafeZfsToken(dataset.sync, 'sync')}`);
  }
  if (dataset.specialSmallBlocks && dataset.specialSmallBlocks !== '0') {
    createParts.push(`-o special_small_blocks=${assertSafeZfsToken(dataset.specialSmallBlocks, 'specialSmallBlocks')}`);
  }
  createParts.push(...encOpts, safeFullName);

  const cmds: string[] = [createParts.join(' ')];
  if (dataset.quotaGb && Number.isFinite(dataset.quotaGb) && dataset.quotaGb > 0) {
    cmds.push(`zfs set quota=${Math.trunc(dataset.quotaGb)}G ${safeFullName}`);
  }
  if (dataset.refQuotaGb && Number.isFinite(dataset.refQuotaGb) && dataset.refQuotaGb > 0) {
    cmds.push(`zfs set refquota=${Math.trunc(dataset.refQuotaGb)}G ${safeFullName}`);
  }
  if (dataset.refReservationGb && Number.isFinite(dataset.refReservationGb) && dataset.refReservationGb > 0) {
    cmds.push(`zfs set refreservation=${Math.trunc(dataset.refReservationGb)}G ${safeFullName}`);
  }
  return cmds;
}

function sanitizeIniVal(v?: string): string {
  if (!v) return '';
  return v.replace(/[\r\n\0]/g, '').trim().replace(/\\+$/g, '').trim();
}

function sanitizeIniSection(v?: string): string {
  if (!v) return '';
  const sanitized = v.replace(/[\r\n\0[\]]/g, '_').trim();
  if (!sanitized || RESERVED_SMB_SECTIONS.has(sanitized.toLowerCase())) {
    throw new Error(`Invalid or reserved SMB share section name: ${v}`);
  }
  return sanitized;
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
    const rawNets = Array.isArray(exp.allowedNetworks) ? exp.allowedNetworks : [];
    const nets = rawNets
      .map((n) => sanitizeIniVal(n).replace(/[\s()]/g, ''))
      .filter((n) => n && n !== '*');
    if (nets.length === 0) {
      lines.push(`# Disabled NFS export ${sanitizeIniVal(exp.path)}: allowedNetworks must not be empty or '*'`);
      continue;
    }
    const clientSpecs = nets.map((net) => `${net}(${mode},${syncMode},no_subtree_check,${squash}${secOpt})`).join(' ');
    lines.push(`${sanitizeIniVal(exp.path).replace(/[\s()]/g, '')} ${clientSpecs}`);
  }

  lines.push('');
  return lines.join('\n');
}

function validateIscsiZvolPath(rawPath: string): string {
  const trimmed = String(rawPath ?? '').trim();
  if (
    !trimmed ||
    trimmed.includes('..') ||
    /[\r\n\0]/.test(trimmed) ||
    !/^\/dev\/zvol\/[a-zA-Z0-9._-]+\/[a-zA-Z0-9._/-]+$/.test(trimmed)
  ) {
    throw new Error(`Invalid iSCSI LUN zvolPath (must start with /dev/zvol/<pool>/... without ..): ${rawPath}`);
  }
  return trimmed;
}

export function compileLioTargetSaveconfig(nas?: NasConfig): string {
  const targets = (nas?.iscsiTargets ?? []).filter((t) => t.enabled);
  const storageObjects: Array<Record<string, unknown>> = [];
  const targetEntries: Array<Record<string, unknown>> = [];

  for (const t of targets) {
    const tpgLuns: Array<Record<string, unknown>> = [];
    for (const l of t.luns) {
      const zvolDev = validateIscsiZvolPath(l.zvolPath);
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
            generate_node_acls: 0,
            cache_dynamic_acls: 0,
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

function escapeEnvDoubleQuoted(v?: string): string {
  return sanitizeIniVal(v)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\$/g, '\\$')
    .replace(/`/g, '\\`');
}

export function compileS3MinioEnv(nas?: NasConfig): string {
  const s3 = nas?.s3;
  if (!s3?.enabled) return '';
  const rootDir = escapeEnvDoubleQuoted(s3.rootDataset || '/mnt/tank/s3');
  const accessKey = escapeEnvDoubleQuoted(s3.accessKey || 'axonwall-admin');
  const secretKey = escapeEnvDoubleQuoted(s3.secretKey || '');
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
    if (!task.provider || !SAFE_RCLONE_PROVIDER_REGEX.test(task.provider)) {
      throw new Error(`Invalid cloud sync provider: ${task.provider}`);
    }
    if (!task.remoteBucket || /[\0\r\n]/.test(task.remoteBucket) || task.remoteBucket.includes('..')) {
      throw new Error(`Invalid cloud sync remote bucket: ${task.remoteBucket}`);
    }
    if (!task.localPath || /[\0\r\n]/.test(task.localPath) || task.localPath.includes('..') || !task.localPath.startsWith('/')) {
      throw new Error(`Invalid cloud sync local path: ${task.localPath}`);
    }
    const verb = task.transferMode === 'copy' ? 'copy' : 'sync';
    const bw =
      Number.isFinite(task.bandwidthLimitMbps) && task.bandwidthLimitMbps > 0
        ? ` --bwlimit ${Math.trunc(task.bandwidthLimitMbps)}M`
        : '';
    const remoteSpec = `${task.provider}:${task.remoteBucket}`;
    if (task.direction === 'pull') {
      cmds.push(`rclone ${verb} ${shellSingleQuote(remoteSpec)} ${shellSingleQuote(task.localPath)}${bw}`);
    } else {
      cmds.push(`rclone ${verb} ${shellSingleQuote(task.localPath)} ${shellSingleQuote(remoteSpec)}${bw}`);
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
          zvolDevice: validateIscsiZvolPath(l.zvolPath),
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
