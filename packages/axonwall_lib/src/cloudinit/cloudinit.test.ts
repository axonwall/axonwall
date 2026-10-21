import { describe, it, expect } from 'vitest';
import {
  parseCloudInitYaml,
  serializeCloudInitYaml,
  cloudInitStorageToInstallerChoices,
  formatInstallerChoicesEnv,
  type FullCloudInit,
} from './index.js';

describe('Axonwall Cloud-Init & Custom Partitioning Engine', () => {
  it('parses valid #cloud-config with custom partitions and LUKS2 encryption', () => {
    const yaml = `
#cloud-config
hostname: edge-sec-01
timezone: America/New_York
users:
  - name: axonwall
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdminKey admin@corp

axonwall:
  storage:
    layout_mode: custom
    target_disks:
      - /dev/nvme0n1
      - /dev/nvme1n1
    system_raid:
      enabled: true
      level: raid1
    encryption:
      enabled: true
      tpm2_auto_unlock: true
      passphrase: "super-secure-vault-passphrase"
    partitions:
      efi_size_mb: 1024
      slot_a:
        size_gb: 24
        filesystem: ext4
      slot_b:
        size_gb: 24
        filesystem: ext4
      swap:
        size_gb: 4
        zram_enabled: true
      data:
        size_gb: 80
        filesystem: xfs
      logs:
        enabled: true
        size_gb: 50
        filesystem: xfs
        mountpoint: /var/log
      custom_mounts:
        - name: axon_pcap
          size_gb: 120
          filesystem: xfs
          mountpoint: /var/lib/axonwall/pcap
    zfs:
      enabled: true
      pool_name: storage_pool
      allocate_system_disk_remainder: true
      extra_disks:
        - /dev/sda
        - /dev/sdb
      topology: mirror
      datasets:
        - name: storage_pool/nas
          mountpoint: /mnt/nas
          compression: zstd
  auth:
    admin_username: admin
    admin_password_hash: "scrypt$12345$abcdef"
    ztp:
      enabled: true
      controller_url: "https://hub.example.com:2966"
      enrollment_token: "enrollment-secret-token"
  desired_state:
    system:
      hostname: edge-sec-01
      domain: corp.internal
`;

    const parsed = parseCloudInitYaml(yaml);
    expect(parsed.hostname).toBe('edge-sec-01');
    expect(parsed.users?.[0].name).toBe('axonwall');
    expect(parsed.axonwall?.storage?.layout_mode).toBe('custom');
    expect(parsed.axonwall?.storage?.encryption.enabled).toBe(true);
    expect(parsed.axonwall?.storage?.encryption.tpm2_auto_unlock).toBe(true);
    expect(parsed.axonwall?.storage?.system_raid.enabled).toBe(true);
    expect(parsed.axonwall?.storage?.partitions.slot_a.size_gb).toBe(24);
    expect(parsed.axonwall?.storage?.partitions.logs.enabled).toBe(true);
    expect(parsed.axonwall?.storage?.partitions.logs.size_gb).toBe(50);
    expect(parsed.axonwall?.storage?.partitions.custom_mounts[0].mountpoint).toBe('/var/lib/axonwall/pcap');
    expect(parsed.axonwall?.storage?.zfs.pool_name).toBe('storage_pool');
    expect(parsed.axonwall?.storage?.zfs.extra_disks).toEqual(['/dev/sda', '/dev/sdb']);
    expect(parsed.axonwall?.auth?.ztp.controller_url).toBe('https://hub.example.com:2966');
  });

  it('converts CloudInitStorage into installer choice variables with LUKS2 & RAID-1', () => {
    const parsed: FullCloudInit = {
      axonwall: {
        storage: {
          layout_mode: 'custom',
          target_disks: ['/dev/nvme0n1', '/dev/nvme1n1'],
          system_raid: { enabled: true, level: 'raid1' },
          encryption: {
            enabled: true,
            tpm2_auto_unlock: true,
            passphrase: 'vault-passphrase',
            cipher: 'aes-xts-plain64',
            key_size: 512,
          },
          partitions: {
            efi_size_mb: 1024,
            slot_a: { size_gb: 25, filesystem: 'ext4' },
            slot_b: { size_gb: 25, filesystem: 'ext4' },
            swap: { size_gb: 8, zram_enabled: true },
            data: { size_gb: 60, allocate_remaining: false, filesystem: 'xfs' },
            logs: { enabled: true, size_gb: 40, filesystem: 'xfs', mountpoint: '/var/log' },
            custom_mounts: [
              { name: 'axon_telemetry', size_gb: 100, filesystem: 'ext4', mountpoint: '/var/lib/axonwall/telemetry' },
            ],
          },
          zfs: {
            enabled: true,
            pool_name: 'tank',
            allocate_system_disk_remainder: true,
            system_disk_size_gb: 0,
            extra_disks: ['/dev/sdb'],
            topology: 'mirror',
            datasets: [],
          },
        },
      },
    };

    const choices = cloudInitStorageToInstallerChoices(parsed.axonwall!.storage!);
    expect(choices.TARGET_DISK).toBe('/dev/nvme0n1');
    expect(choices.SYSTEM_RAID_MODE).toBe('mirror');
    expect(choices.SYSTEM_RAID_DISKS).toBe('/dev/nvme0n1 /dev/nvme1n1');
    expect(choices.EFI_MB).toBe(1024);
    expect(choices.ROOT_GB).toBe(25);
    expect(choices.ROOT_MB).toBe(25600);
    expect(choices.ROOT_FSTYPE).toBe('ext4');
    expect(choices.SWAP_GB).toBe(8);
    expect(choices.ZRAM_ENABLED).toBe(true);
    expect(choices.DATA_GB).toBe(60);
    expect(choices.DATA_FSTYPE).toBe('xfs');
    expect(choices.LOGS_ENABLED).toBe(true);
    expect(choices.LOGS_GB).toBe(40);
    expect(choices.LOGS_FSTYPE).toBe('xfs');
    expect(choices.LUKS_ENABLED).toBe(true);
    expect(choices.LUKS_TPM2).toBe(true);
    expect(choices.LUKS_PASSPHRASE).toBe('vault-passphrase');
    expect(choices.ZFS_ALLOC_MODE).toBe('remainder');
    expect(choices.ZFS_EXTRA_DISKS).toBe('/dev/sdb');

    const envText = formatInstallerChoicesEnv(choices);
    expect(envText).toContain("TARGET_DISK='/dev/nvme0n1'");
    expect(envText).toContain("SYSTEM_RAID_MODE='mirror'");
    expect(envText).toContain('LUKS_ENABLED=true');
    expect(envText).toContain('LUKS_TPM2=true');
    expect(envText).toContain('LOGS_ENABLED=true');
    expect(envText).toContain('ROOT_MB=25600');
  });

  it('serializes and roundtrips cloud-config YAML cleanly', () => {
    const input: FullCloudInit = {
      hostname: 'axonwall-cloud',
      timezone: 'UTC',
      axonwall: {
        auth: {
          admin_username: 'admin',
          admin_password_hash: 'scrypt$dummy$hash',
          ztp: { enabled: false },
        },
      },
    };

    const serialized = serializeCloudInitYaml(input);
    expect(serialized.startsWith('#cloud-config')).toBe(true);
    const roundtripped = parseCloudInitYaml(serialized);
    expect(roundtripped.hostname).toBe('axonwall-cloud');
    expect(roundtripped.axonwall?.auth?.admin_password_hash).toBe('scrypt$dummy$hash');
  });
});
