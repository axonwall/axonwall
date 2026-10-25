import { describe, it, expect } from 'vitest';
import { DesiredStateSchema } from '../schemas/index.js';
import {
  parseStorageFromLsblk,
  buildCloudInitFromSystem,
  exportCloudInitYaml,
  parseCloudInitYaml,
  parseCloudInitNetworkConfig,
  generateCloudInitMetaData,
  buildNoCloudIso,
  cloudInitStorageToInstallerChoices,
  REDACTED_KEY32_PLACEHOLDER,
  REDACTED_SECRET_PLACEHOLDER,
} from './index.js';

describe('Cloud-Init Exporter & System Replicator', () => {
  const sampleLsblk = {
    blockdevices: [
      {
        name: 'sda',
        size: 68719476736, // 64 GB
        type: 'disk',
        fstype: null,
        label: null,
        mountpoint: null,
        children: [
          {
            name: 'sda1',
            size: 536870912, // 512 MB
            type: 'part',
            fstype: 'vfat',
            label: 'EFI',
            mountpoint: '/boot/efi',
          },
          {
            name: 'sda2',
            size: 17179869184, // 16 GB
            type: 'part',
            fstype: 'ext4',
            label: 'axon_root_a',
            mountpoint: null,
          },
          {
            name: 'sda3',
            size: 17179869184, // 16 GB
            type: 'part',
            fstype: 'ext4',
            label: 'axon_root_b',
            mountpoint: '/',
          },
          {
            name: 'sda4',
            size: 2147483648, // 2 GB
            type: 'part',
            fstype: 'swap',
            label: null,
            mountpoint: '[SWAP]',
          },
          {
            name: 'sda5',
            size: 31675383808, // ~29.5 GB
            type: 'part',
            fstype: 'ext4',
            label: 'axon_data',
            mountpoint: '/var/lib/axonwall',
          },
        ],
      },
      {
        name: 'zram0',
        size: 1073741824,
        type: 'disk',
        fstype: 'swap',
        label: null,
        mountpoint: '[SWAP]',
      },
    ],
  };

  it('introspects A/B dual-root partition layout from lsblk JSON', () => {
    const storage = parseStorageFromLsblk(sampleLsblk);
    expect(storage.layout_mode).toBe('standard_ab');
    expect(storage.target_disks).toEqual(['/dev/sda']);
    expect(storage.partitions.efi_size_mb).toBe(512);
    expect(storage.partitions.slot_a).toEqual({ size_gb: 16, filesystem: 'ext4' });
    expect(storage.partitions.slot_b).toEqual({ size_gb: 16, filesystem: 'ext4' });
    expect(storage.partitions.swap).toEqual({ size_gb: 2, zram_enabled: true });
    expect(storage.partitions.data.allocate_remaining).toBe(true);

    const choices = cloudInitStorageToInstallerChoices(storage);
    expect(choices.STANDBY_ENABLED).toBe(true);
    expect(choices.ROOT_GB).toBe(16);
    expect(choices.ZRAM_ENABLED).toBe(true);
  });

  it('builds a valid #cloud-config YAML with redacted secrets and round-trips through parseCloudInitYaml', () => {
    const desiredState = DesiredStateSchema.parse({
      system: {
        hostname: 'edge-fw-01',
        domain: 'corp.axonwall.io',
        timezone: 'America/Chicago',
      },
      interfaces: [
        {
          name: 'wan',
          device: 'eth0',
          type: 'static',
          ipv4Address: '203.0.113.10/24',
          ipv4Gateway: '203.0.113.1',
        },
        {
          name: 'lan',
          device: 'eth1',
          type: 'static',
          ipv4Address: '10.80.0.1/24',
        },
      ],
      frr: {
        enabled: true,
        bgp: {
          enabled: true,
          asNumber: 65001,
          routerId: '10.80.0.1',
          neighbors: [
            {
              peerIp: '203.0.113.1',
              remoteAs: 65000,
              password: 'super-secret-bgp-md5-password',
            },
          ],
        },
      },
      wireguard: {
        enabled: true,
        listenPort: 51820,
        privateKey: 'LIVE_WG_PRIVATE_KEY_SECRET_32_CHARS_LONG_1234',
        address: '10.99.0.1/24',
      },
    });

    const storage = parseStorageFromLsblk(sampleLsblk);
    const yamlText = exportCloudInitYaml(
      {
        desiredState,
        hostname: 'edge-fw-01',
        timezone: 'America/Chicago',
        storage,
        adminUsername: 'admin',
        adminPassword: 'real-admin-password',
        ztp: {
          enabled: true,
          controllerUrl: 'https://ctrl.corp.axonwall.io:2966',
          enrollmentToken: 'real-ztp-token',
        },
        osUsers: [
          {
            name: 'thoth',
            gecos: 'Thoth Admin',
            sudo: 'ALL=(ALL) NOPASSWD:ALL',
            shell: '/usr/bin/zsh',
            sshAuthorizedKeys: [
              'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl thoth@workstation',
              '# comment line that should be filtered out',
            ],
          },
        ],
      },
      {
        redactSecrets: true,
        templateMode: false,
      }
    );

    expect(yamlText.startsWith('#cloud-config\n')).toBe(true);
    expect(yamlText).not.toContain('super-secret-bgp-md5-password');
    expect(yamlText).not.toContain('LIVE_WG_PRIVATE_KEY_SECRET_32_CHARS_LONG_1234');
    expect(yamlText).not.toContain('real-admin-password');
    expect(yamlText).not.toContain('real-ztp-token');

    const parsed = parseCloudInitYaml(yamlText);
    expect(parsed.hostname).toBe('edge-fw-01');
    expect(parsed.packages).toContain('frr');
    expect(parsed.packages).toContain('wireguard-tools');
    expect(parsed.users?.length).toBe(1);
    expect(parsed.users?.[0]?.name).toBe('thoth');
    expect(parsed.users?.[0]?.ssh_authorized_keys.length).toBe(1);
    expect(parsed.axonwall?.auth?.admin_password).toBe(REDACTED_SECRET_PLACEHOLDER);
    expect(parsed.axonwall?.desired_state?.wireguard?.privateKey).toBe(REDACTED_KEY32_PLACEHOLDER);
    expect(parsed.axonwall?.desired_state?.frr?.bgp?.neighbors?.[0]?.password).toBe(
      REDACTED_SECRET_PLACEHOLDER
    );
  });

  it('supports templateMode by appending -clone and converting static WAN interfaces to DHCP', () => {
    const desiredState = DesiredStateSchema.parse({
      system: {
        hostname: 'hq-fw-01',
        domain: 'axonwall.local',
      },
      interfaces: [
        {
          name: 'wan',
          device: 'eth0',
          type: 'static',
          ipv4Address: '198.51.100.42/24',
          ipv4Gateway: '198.51.100.1',
          macAddress: '52:54:00:12:34:56',
        },
        {
          name: 'lan',
          device: 'eth1',
          type: 'static',
          ipv4Address: '192.168.1.1/24',
        },
      ],
    });

    const config = buildCloudInitFromSystem(
      { desiredState, hostname: 'hq-fw-01' },
      { redactSecrets: true, templateMode: true }
    );

    expect(config.hostname).toBe('hq-fw-01-clone');
    expect(config.axonwall?.desired_state?.system?.hostname).toBe('hq-fw-01-clone');
    const wan = config.axonwall?.desired_state?.interfaces?.find((i) => i.name === 'wan');
    const lan = config.axonwall?.desired_state?.interfaces?.find((i) => i.name === 'lan');
    expect(wan?.type).toBe('dhcp');
    expect(wan?.ipv4Address).toBeUndefined();
    expect(wan?.macAddress).toBeUndefined();
    expect(lan?.ipv4Address).toBe('192.168.1.1/24');
  });

  it('generates a valid ISO9660 + Rock Ridge NoCloud cidata.iso image', () => {
    const userData = '#cloud-config\nhostname: axonwall-clone\n';
    const metaData = generateCloudInitMetaData('i-axonwall-01', 'axonwall-clone');
    const isoBytes = buildNoCloudIso(userData, metaData);

    expect(isoBytes.byteLength).toBeGreaterThanOrEqual(180 * 2048);
    // Check Primary Volume Descriptor at sector 16 (offset 32768)
    const pvdOffset = 16 * 2048;
    expect(isoBytes[pvdOffset]).toBe(0x01);
    const cd001 = new TextDecoder().decode(isoBytes.subarray(pvdOffset + 1, pvdOffset + 6));
    expect(cd001).toBe('CD001');
    const volId = new TextDecoder()
      .decode(isoBytes.subarray(pvdOffset + 40, pvdOffset + 72))
      .trim();
    expect(volId).toBe('cidata');

    // Verify embedded payload and Rock Ridge RRIP_1991A ER extension record exist
    const fullText = new TextDecoder().decode(isoBytes);
    expect(fullText).toContain('RRIP_1991A');
    expect(fullText).toContain('#cloud-config\nhostname: axonwall-clone');
    expect(fullText).toContain('instance-id: i-axonwall-01');
  });

  it('parses Proxmox VE and KVM Cloud-Init user-data formats cleanly', () => {
    const proxmoxUserData = `#cloud-config
hostname: pve-axonwall
manage_etc_hosts: true
fqdn: pve-axonwall.local
user: admin
password: $6$rounds=4096$saltsalt$hashedpassword
chpasswd:
  expire: false
users:
  - default
ssh_authorized_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@pve
package_upgrade: true
`;
    const parsed = parseCloudInitYaml(proxmoxUserData);
    expect(parsed.hostname).toBe('pve-axonwall');
    expect(parsed.user).toBe('admin');
    expect(parsed.password).toContain('$6$');
    expect(parsed.ssh_authorized_keys?.length).toBe(1);
    expect(parsed.users).toEqual([]);
  });

  it('parses Cloud-Init network-config v1 (Proxmox) and v2 (Netplan)', () => {
    const v1Yaml = `version: 1
config:
  - type: physical
    name: eth0
    subnets:
      - type: static
        address: '10.10.20.5'
        netmask: '255.255.255.0'
        gateway: '10.10.20.1'
  - type: physical
    name: eth1
    subnets:
      - type: dhcp4
  - type: nameserver
    address:
      - '1.1.1.1'
      - '9.9.9.9'
    search:
      - 'lab.internal'
`;
    const net1 = parseCloudInitNetworkConfig(v1Yaml, ['ens18', 'ens19']);
    expect(net1).not.toBeNull();
    expect(net1?.interfaces).toHaveLength(2);
    expect(net1?.interfaces[0]).toMatchObject({
      name: 'wan',
      role: 'wan',
      device: 'ens18',
      type: 'static',
      ipv4Address: '10.10.20.5/24',
      ipv4Gateway: '10.10.20.1',
    });
    expect(net1?.interfaces[1]).toMatchObject({
      name: 'lan',
      role: 'lan',
      device: 'ens19',
      type: 'dhcp',
    });
    expect(net1?.dnsServers).toEqual(['1.1.1.1', '9.9.9.9']);
    expect(net1?.searchDomain).toBe('lab.internal');

    const v2Yaml = `version: 2
ethernets:
  eth0:
    dhcp4: false
    addresses: [192.168.50.10/24]
    gateway4: 192.168.50.1
    nameservers:
      addresses: [8.8.8.8]
      search: [axonwall.lan]
`;
    const net2 = parseCloudInitNetworkConfig(v2Yaml, ['enp1s0']);
    expect(net2).not.toBeNull();
    expect(net2?.interfaces[0]).toMatchObject({
      name: 'wan',
      device: 'enp1s0',
      type: 'static',
      ipv4Address: '192.168.50.10/24',
      ipv4Gateway: '192.168.50.1',
    });
    expect(net2?.dnsServers).toEqual(['8.8.8.8']);
    expect(net2?.searchDomain).toBe('axonwall.lan');
  });
});
