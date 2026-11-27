import { describe, it, expect } from 'vitest';
import { importTruenasConfig } from './index.js';
import { DesiredStateSchema } from '../../schemas/index.js';

describe('TrueNAS SCALE / CORE Importer', () => {
  it('defaults NFS mapRootUser to nobody unless explicitly root in JSON and /etc/exports [SEC-H20]', () => {
    const jsonCfg = JSON.stringify({
      'sharing.nfs': [
        { path: '/mnt/tank/data', networks: ['10.10.0.0/24'] },
        { path: '/mnt/tank/nobody', networks: ['10.10.0.0/24'], maproot_user: 'nobody' },
        { path: '/mnt/tank/rootok', networks: ['10.10.0.0/24'], maproot_user: 'root' },
      ],
    });

    const jsonReport = importTruenasConfig(jsonCfg);
    expect(jsonReport.state.nas?.nfsExports).toHaveLength(3);
    expect(jsonReport.state.nas?.nfsExports[0]!.mapRootUser).toBe('nobody');
    expect(jsonReport.state.nas?.nfsExports[1]!.mapRootUser).toBe('nobody');
    expect(jsonReport.state.nas?.nfsExports[2]!.mapRootUser).toBe('root');
    expect(() => DesiredStateSchema.parse(jsonReport.state)).not.toThrow();

    const textCfg = `
/mnt/tank/default 10.10.0.0/24(rw,sync,no_subtree_check)
/mnt/tank/squashed 10.10.0.0/24(rw,root_squash)
/mnt/tank/explicit_root 10.10.0.0/24(rw,no_root_squash,sync)
`;
    const textReport = importTruenasConfig(textCfg);
    expect(textReport.state.nas?.nfsExports).toHaveLength(3);
    expect(textReport.state.nas?.nfsExports[0]!.mapRootUser).toBe('nobody');
    expect(textReport.state.nas?.nfsExports[1]!.mapRootUser).toBe('nobody');
    expect(textReport.state.nas?.nfsExports[2]!.mapRootUser).toBe('root');
    expect(() => DesiredStateSchema.parse(textReport.state)).not.toThrow();
  });

  it('imports iSCSI targets with enabled: false when allowedInitiators and CHAP are empty [SEC-H20]', () => {
    const jsonCfg = JSON.stringify({
      'iscsi.target': [
        { name: 'open_target', zvol: 'tank/iscsi0' },
        { name: 'partial_chap', zvol: 'tank/iscsi1', chapUser: 'admin' },
        { name: 'acl_target', zvol: 'tank/iscsi2', allowedInitiators: ['iqn.2026-01.com.example:host1'] },
        { name: 'chap_target', zvol: 'tank/iscsi3', chapUser: 'iscsi', chapSecret: 'supersecret1234' },
      ],
    });

    const report = importTruenasConfig(jsonCfg);
    const targets = report.state.nas?.iscsiTargets ?? [];
    expect(targets).toHaveLength(4);

    expect(targets[0]!.enabled).toBe(false);
    expect(targets[1]!.enabled).toBe(false);
    expect(targets[2]!.enabled).toBe(true);
    expect(targets[2]!.allowedInitiators).toEqual(['iqn.2026-01.com.example:host1']);
    expect(targets[3]!.enabled).toBe(true);
    expect(targets[3]!.chapUser).toBe('iscsi');
    expect(report.warnings.length).toBeGreaterThanOrEqual(2);
    expect(() => DesiredStateSchema.parse(report.state)).not.toThrow();

    const unsafeIscsi = importTruenasConfig(
      JSON.stringify({
        'iscsi.target': [
          { name: 'bad_dev', disk: '/dev/sda', allowedInitiators: ['iqn.2026-01.com.example:host1'] },
          { name: 'bad_trav', zvol: '/dev/zvol/tank/../sda', allowedInitiators: ['iqn.2026-01.com.example:host1'] },
        ],
      }),
    );
    expect(unsafeIscsi.state.nas?.iscsiTargets ?? []).toHaveLength(0);
    expect(unsafeIscsi.warnings.length).toBe(2);
  });

  it('restricts imported SMB paths to normalized /mnt/... without .. traversal [SEC-H20]', () => {
    const jsonCfg = JSON.stringify({
      'sharing.smb': [
        { name: 'ValidShare', path: '/mnt/tank//media/./' },
        { name: 'RootEtc', path: '/etc/shadow' },
        { name: 'Traversal1', path: '/mnt/tank/../../etc' },
        { name: 'Traversal2', path: '/mnt/tank/sub/../share' },
        { name: 'BareMnt', path: '/mnt/' },
        { name: 'Backslash', path: '/mnt/tank\\..\\etc' },
      ],
    });

    const jsonReport = importTruenasConfig(jsonCfg);
    expect(jsonReport.state.nas?.smbShares).toHaveLength(1);
    expect(jsonReport.state.nas?.smbShares[0]!.name).toBe('ValidShare');
    expect(jsonReport.state.nas?.smbShares[0]!.path).toBe('/mnt/tank/media');
    expect(jsonReport.warnings.length).toBe(5);
    expect(() => DesiredStateSchema.parse(jsonReport.state)).not.toThrow();

    const smbConf = `
[global]
  workgroup = WORKGROUP
  vfs objects = acl_xattr

[SafeShare]
  path = /mnt/dozer//projects/
  read only = no

[EtcEscape]
  path = /etc

[DotDotEscape]
  path = /mnt/dozer/../../../etc/passwd
`;
    const confReport = importTruenasConfig(smbConf);
    expect(confReport.state.nas?.smbShares).toHaveLength(1);
    expect(confReport.state.nas?.smbShares[0]!.name).toBe('SafeShare');
    expect(confReport.state.nas?.smbShares[0]!.path).toBe('/mnt/dozer/projects');
    expect(confReport.warnings.length).toBe(2);
    expect(() => DesiredStateSchema.parse(confReport.state)).not.toThrow();
  });
});
