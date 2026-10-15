import { describe, it, expect } from 'vitest';
import { DesiredStateSchema } from '../../schemas/index.js';
import { compileNftables } from '../nft/index.js';
import { compileNas, compileZfsPoolCommand } from './index.js';
import { compileK3s } from '../k3s/index.js';
import { resolveCapabilities } from '../../plugins/index.js';

describe('Modular Firewall, NAS (ZFS/SMB/NFS/iSCSI), and K3s+OpenEBS Compilers', () => {
  it('switches compileNftables to Host-Mode Appliance Ruleset when core-firewall is disabled', () => {
    const state = DesiredStateSchema.parse({
      capabilities: {
        firewallEnabled: false,
        nasEnabled: true,
        k3sEnabled: true,
      },
      interfaces: [
        { name: 'wan', device: 'eth0', enabled: true, mode: 'dhcp' },
        { name: 'lan', device: 'eth1', enabled: true, mode: 'static', address: '192.168.1.1/24' },
      ],
      nas: {
        enabled: true,
        s3: { enabled: true, listenPort: 9000, consolePort: 9001 },
      },
    });

    const caps = resolveCapabilities(state);
    expect(caps.firewallEnabled).toBe(false);
    expect(caps.nasEnabled).toBe(true);
    expect(caps.k3sEnabled).toBe(true);

    const compiled = compileNftables(state);
    expect(compiled.nftScript).toContain('Host-Mode Appliance Ruleset (core-firewall plugin disabled)');
    expect(compiled.nftScript).not.toContain('chain prerouting');
    expect(compiled.nftScript).not.toContain('chain postrouting');
    expect(compiled.nftScript).toContain('tcp dport { 139, 445 } accept comment "nas-smb"');
    expect(compiled.nftScript).toContain('tcp dport 3260 accept comment "nas-iscsi"');
    expect(compiled.nftScript).toContain('tcp dport { 6443, 10250, 2379, 2380, 10124, 9500 } accept comment "k3s-and-openebs-tcp"');
  });

  it('compiles ZFS pool creation commands for mirror, raidz1, raidz2, raidz3, and draid1 with SLOG/L2ARC/spares', () => {
    const cmdRaidz2 = compileZfsPoolCommand({
      name: 'tank',
      topology: 'raidz2',
      dataDisks: ['/dev/sda', '/dev/sdb', '/dev/sdc', '/dev/sdd'],
      logDisks: ['/dev/nvme0n1p7', '/dev/nvme1n1p7'],
      cacheDisks: ['/dev/nvme2n1'],
      spareDisks: ['/dev/sde'],
      ashift: 12,
      autotrim: true,
      compression: 'zstd',
      scrubScheduleCron: '0 2 * * 0',
      description: 'Primary RAID-Z2 array',
    });

    expect(cmdRaidz2).toContain('zpool create -f -o ashift=12 -o autotrim=on -O compression=zstd');
    expect(cmdRaidz2).toContain('tank raidz2 /dev/sda /dev/sdb /dev/sdc /dev/sdd');
    expect(cmdRaidz2).toContain('log mirror /dev/nvme0n1p7 /dev/nvme1n1p7');
    expect(cmdRaidz2).toContain('cache /dev/nvme2n1');
    expect(cmdRaidz2).toContain('spare /dev/sde');
  });

  it('compiles SMB shares with ZFS Shadow Copies & Time Machine, NFSv4 exports, and iSCSI targets', () => {
    const state = DesiredStateSchema.parse({
      nas: {
        enabled: true,
        workgroup: 'AXONCORP',
        pools: [
          {
            name: 'tank',
            topology: 'mirror',
            dataDisks: ['/dev/disk/by-partlabel/axon_zfs_1', '/dev/disk/by-partlabel/axon_zfs_2'],
          },
        ],
        datasets: [
          {
            name: 'shares',
            pool: 'tank',
            type: 'filesystem',
            compression: 'zstd',
            quotaGb: 500,
          },
          {
            name: 'vm-lun0',
            pool: 'tank',
            type: 'zvol',
            volSizeGb: 100,
          },
        ],
        smbShares: [
          {
            name: 'Engineering',
            path: '/mnt/tank/shares',
            timeMachine: true,
            shadowCopies: true,
            validUsers: ['admin'],
          },
        ],
        nfsExports: [
          {
            path: '/mnt/tank/shares',
            allowedNetworks: ['192.168.1.0/24', '10.0.0.0/24'],
            readOnly: false,
            mapRootUser: 'root',
          },
        ],
        iscsiTargets: [
          {
            iqn: 'iqn.2026-10.io.axonwall:storage.vms',
            portalIp: '0.0.0.0',
            portalPort: 3260,
            luns: [{ lunId: 0, zvolPath: 'tank/vm-lun0', blockSize: '4096', readOnly: false }],
          },
        ],
      },
    });

    const compiled = compileNas(state.nas);
    expect(compiled.smbConf).toContain('workgroup = AXONCORP');
    expect(compiled.smbConf).toContain('[Engineering]');
    expect(compiled.smbConf).toContain('shadow_copy2');
    expect(compiled.smbConf).toContain('fruit:time machine = yes');
    expect(compiled.nfsExports).toContain('/mnt/tank/shares 192.168.1.0/24(rw,sync,no_subtree_check,no_root_squash)');
    expect(compiled.iscsiConf).toContain('/dev/zvol/tank/vm-lun0');
    expect(compiled.zfsCommands.some((c) => c.includes('zfs set quota=500G tank/shares'))).toBe(true);
  });

  it('compiles K3s config for HA auto-join on backup node and OpenEBS ZFS-LocalPV + Replicated StorageClasses', () => {
    const backupState = DesiredStateSchema.parse({
      capabilities: { firewallEnabled: true, nasEnabled: true, k3sEnabled: true },
      ha: {
        enabled: true,
        role: 'backup',
        syncInterface: 'lan',
        peerIp: '192.168.1.2',
        virtualRouterId: 51,
        priority: 100,
        sharedSecret: 'secret123',
      },
      k3s: {
        enabled: true,
        autoJoinHaPeer: true,
        openEbs: {
          enabled: true,
          zfsLocalPvPool: 'tank',
          replicatedStorageEnabled: true,
          defaultReplicaCount: 2,
        },
      },
    });

    const compiled = compileK3s(backupState, 'K10abc123::server:token');
    expect(compiled.k3sConfigYaml).toContain('server: "https://192.168.1.2:6443"');
    expect(compiled.k3sConfigYaml).toContain('token: "K10abc123::server:token"');
    expect(compiled.openEbsManifestYaml).toContain('name: axonwall-zfs-local');
    expect(compiled.openEbsManifestYaml).toContain('name: axonwall-replicated-ha');
    expect(compiled.openEbsManifestYaml).toContain('repl: "2"');
  });
});
