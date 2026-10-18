import type { NasConfig, ZfsPool, ZfsDataset } from '../../schemas/index.js';

export interface CompiledNas {
  smbConf: string;
  nfsExports: string;
  iscsiConf: string;
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
    `-O mountpoint=/mnt/${pool.name}`,
    pool.name,
  ];

  if (pool.topology && pool.topology !== 'stripe') {
    args.push(pool.topology);
  }
  args.push(...pool.dataDisks);

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

  if (dataset.type === 'zvol') {
    const volSize = dataset.volSizeGb && dataset.volSizeGb > 0 ? `${dataset.volSizeGb}G` : '10G';
    return [
      `zfs create -p -V ${volSize} -o compression=${dataset.compression ?? 'lz4'} -o volblocksize=16K ${fullName}`,
    ];
  }

  const cmds: string[] = [
    `zfs create -p -o compression=${dataset.compression ?? 'lz4'} -o recordsize=${dataset.recordSize ?? '128K'} -o dedup=${dataset.dedup ?? 'off'} -o aclmode=${dataset.aclMode ?? 'passthrough'} ${fullName}`,
  ];
  if (dataset.quotaGb && dataset.quotaGb > 0) {
    cmds.push(`zfs set quota=${dataset.quotaGb}G ${fullName}`);
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
    const rawNets = exp.allowedNetworks && exp.allowedNetworks.length > 0
      ? exp.allowedNetworks
      : ['*'];
    const nets = rawNets.map(sanitizeIniVal).filter(Boolean);
    const clientSpecs = nets.map((net) => `${net}(${mode},${syncMode},no_subtree_check,${squash})`).join(' ');
    lines.push(`${sanitizeIniVal(exp.path)} ${clientSpecs}`);
  }

  lines.push('');
  return lines.join('\n');
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
    zfsCommands,
  };
}
