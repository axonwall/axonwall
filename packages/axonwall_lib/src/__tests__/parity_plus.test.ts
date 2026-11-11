import { describe, it, expect } from 'vitest';
import {
  DesiredStateSchema,
  compileNftables,
  compileNas,
  compileK3s,
  compileVirtBundle,
  detectFirewallType,
  importFirewallConfig,
  mergeFirewallConfigs,
} from '../index.js';

describe('Axonwall Parity-Plus Architecture Suite (@axonwall/lib)', () => {
  it('compiles NPTv6, 1:1 BINAT, Hairpin NAT Reflection, Dual-Stack Aliases, Negation, DSCP, Rate-Limiting & Outbound Chains', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'static', enabled: true, ipv4Address: '203.0.113.10/24' },
        { name: 'lan', device: 'eth1', type: 'static', enabled: true, ipv4Address: '192.168.50.1/24' },
      ],
      aliases: [
        {
          name: 'hybrid_cdn',
          type: 'network',
          entries: ['198.51.100.0/24', '2001:db8:c0de::/48'],
          enabled: true,
        },
      ],
      rules: [
        {
          action: 'pass',
          direction: 'in',
          interface: 'lan',
          protocol: 'tcp',
          source: 'any',
          destination: '$hybrid_cdn',
          destinationPort: '443',
          dscp: 'ef',
          enabled: true,
          sortOrder: 10,
        },
        {
          action: 'block',
          direction: 'in',
          interface: 'wan',
          protocol: 'tcp',
          source: '198.51.100.5',
          invertSource: true,
          destination: 'any',
          destinationPort: '2222',
          rateLimitPps: 50,
          enabled: true,
          sortOrder: 20,
        },
        {
          action: 'block',
          direction: 'out',
          interface: 'wan',
          protocol: 'tcp',
          source: 'any',
          destination: 'any',
          destinationPort: '25',
          enabled: true,
          sortOrder: 30,
        },
      ],
      nat: [
        {
          type: 'dnat',
          interface: 'wan',
          protocol: 'tcp',
          source: 'any',
          destination: 'wan_ip',
          destinationPort: '8443',
          targetIp: '192.168.50.20',
          targetPort: '443',
          natReflection: true,
          enabled: true,
          sortOrder: 10,
        },
        {
          type: 'binat',
          interface: 'wan',
          protocol: 'any',
          source: 'any',
          destination: '203.0.113.11',
          targetIp: '192.168.50.21',
          enabled: true,
          sortOrder: 20,
        },
        {
          type: 'nptv6',
          interface: 'wan',
          protocol: 'any',
          source: 'fd00:50::/64',
          destination: 'any',
          targetIp: '2001:db8:50::/64',
          enabled: true,
          sortOrder: 30,
        },
      ],
      upnp: {
        enabled: true,
        externalInterface: 'wan',
        internalInterfaces: ['lan'],
        acls: [{ action: 'allow', externalPorts: '1024-65535', internalCidr: '192.168.50.0/24', internalPorts: '1024-65535' }],
      },
    });

    const res = compileNftables(state);
    // Dual-stack alias expansion
    expect(res.nftScript).toContain('set set_hybrid_cdn {');
    expect(res.nftScript).toContain('set set_hybrid_cdn_v6 {');
    expect(res.nftScript).toContain('ip daddr @set_hybrid_cdn ip dscp ef tcp dport 443 accept');
    expect(res.nftScript).toContain('ip6 daddr @set_hybrid_cdn_v6 ip6 dscp ef tcp dport 443 accept');
    // Negated source + rate limit PPS
    expect(res.nftScript).toContain('ip saddr != 198.51.100.5 tcp dport 2222 limit rate over 50/second drop');
    // Outbound interface chains
    expect(res.nftScript).toContain('oifname "eth0" jump forward_out_wan');
    expect(res.nftScript).toContain('chain forward_out_wan {');
    expect(res.nftScript).toContain('chain output_wan {');
    // Hairpin NAT Reflection
    expect(res.nftScript).toContain('iifname "eth1" ip daddr 203.0.113.10 tcp dport 8443 dnat ip to 192.168.50.20:443 comment "nat-reflection-dnat"');
    expect(res.nftScript).toContain('oifname "eth1" ip saddr 192.168.50.0/24 ip daddr 192.168.50.20 masquerade comment "nat-reflection-snat"');
    // 1:1 BINAT
    expect(res.nftScript).toContain('iifname "eth0" ip daddr 203.0.113.11 dnat ip to 192.168.50.21 comment "binat-inbound"');
    expect(res.nftScript).toContain('oifname "eth0" ip saddr 192.168.50.21 snat ip to 203.0.113.11 comment "binat-outbound"');
    // Stateless NPTv6
    expect(res.nftScript).toContain('iifname "eth0" ip6 daddr 2001:db8:50::/64 dnat ip6 prefix to fd00:50::/64 comment "nptv6-inbound"');
    expect(res.nftScript).toContain('oifname "eth0" ip6 saddr fd00:50::/64 snat ip6 prefix to 2001:db8:50::/64 comment "nptv6-outbound"');
    // UPnP isolated anchor chains & file
    expect(res.nftScript).toContain('chain upnp_prerouting {}');
    expect(res.files.some((f) => f.path === '/etc/miniupnpd/miniupnpd.conf')).toBe(true);
  });

  it('compiles Kea DHCPv6 IA_NA + IA_PD prefix delegation and radvd Router Advertisements', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true },
        { name: 'lan', device: 'eth1', type: 'static', enabled: true, ipv4Address: '192.168.1.1/24', ipv6Address: '2001:db8:1::1/64' },
      ],
      dhcp: {
        enabled: true,
        dhcp6Enabled: true,
        subnets: [],
        subnets6: [
          {
            interface: 'lan',
            subnet: '2001:db8:1::/64',
            poolStart: '2001:db8:1::100',
            poolEnd: '2001:db8:1::200',
            delegatedPrefix: '2001:db8:100::/56',
            delegatedLen: 60,
            raMode: 'assisted',
            dnsServers: ['2001:db8:1::1'],
            domainSearchList: ['axonwall.local'],
          },
        ],
      },
    });

    const res = compileNftables(state);
    const kea6 = res.files.find((f) => f.path === '/etc/kea/kea-dhcp6.conf');
    const radvd = res.files.find((f) => f.path === '/etc/radvd.conf');
    expect(kea6).toBeDefined();
    expect(radvd).toBeDefined();
    expect(kea6!.content).toContain('"pd-pools"');
    expect(kea6!.content).toContain('"delegated-len": 60');
    expect(radvd!.content).toContain('AdvManagedFlag on;');
    expect(radvd!.content).toContain('RDNSS 2001:db8:1::1');
    expect(res.nftScript).toContain('udp dport 547 accept comment "kea-dhcp6-server"');
  });

  it('compiles TrueNAS-grade OpenZFS Special VDEVs, AES-256-GCM encryption, SMB Multichannel/Recycle/Audit, LIO iSCSI & CloudSync', () => {
    const state = DesiredStateSchema.parse({
      plugins: [{ id: 'core-nas', enabled: true }],
      nas: {
        enabled: true,
        smbMultichannel: true,
        wsddEnabled: true,
        pools: [
          {
            name: 'tank',
            topology: 'raidz2',
            dataDisks: ['/dev/sda', '/dev/sdb', '/dev/sdc', '/dev/sdd'],
            specialDisks: ['/dev/nvme0n1', '/dev/nvme1n1'],
            specialSmallBlocks: '32K',
            compression: 'zstd',
          },
        ],
        datasets: [
          {
            name: 'vault',
            pool: 'tank',
            type: 'filesystem',
            encryption: 'aes-256-gcm',
            keyFormat: 'hex',
            keyLocation: 'file:///etc/axonwall/zfs-keys/vault.key',
            refQuotaGb: 500,
            atime: 'off',
          },
        ],
        smbShares: [
          {
            name: 'VaultShare',
            path: '/mnt/tank/vault',
            timeMachine: true,
            shadowCopies: true,
            recycleBin: true,
            auditLog: true,
          },
        ],
        nfsExports: [
          {
            path: '/mnt/tank/vault',
            allowedNetworks: ['10.0.0.0/24'],
            secFlavor: 'krb5p',
          },
        ],
        iscsiTargets: [
          {
            iqn: 'iqn.2026-10.io.axonwall:san0',
            luns: [{ lunId: 0, zvolPath: '/dev/zvol/tank/san0', blockSize: '4096' }],
          },
        ],
        s3: {
          enabled: true,
          rootDataset: '/mnt/tank/s3',
          accessKey: 'axonadmin',
          secretKey: 'supersecretminio',
        },
        cloudSyncTasks: [
          {
            name: 'nightly_b2',
            provider: 'b2',
            direction: 'push',
            transferMode: 'sync',
            localPath: '/mnt/tank/vault',
            remoteBucket: 'b2-crypt:axonwall-vault',
          },
        ],
      },
    });

    const nas = compileNas(state.nas);
    expect(nas.zfsCommands.join('\n')).toContain('special mirror /dev/nvme0n1 /dev/nvme1n1');
    expect(nas.zfsCommands.join('\n')).toContain('-O special_small_blocks=32K');
    expect(nas.zfsCommands.join('\n')).toContain('-o encryption=aes-256-gcm');
    expect(nas.smbConf).toContain('server multi channel support = yes');
    expect(nas.smbConf).toContain('recycle');
    expect(nas.smbConf).toContain('full_audit');
    expect(nas.nfsExports).toContain('sec=krb5p');
    expect(JSON.parse(nas.lioSaveconfigJson).targets[0].wwn).toBe('iqn.2026-10.io.axonwall:san0');
    expect(nas.s3EnvConf).toContain('MINIO_ROOT_USER=');
    expect(nas.cloudSyncCommands[0]).toContain('rclone sync');
  });

  it('compiles Proxmox-grade KVM SecureBoot, USB, VirtioFS, Disk IOPS, Libvirt XML, Per-VNIC Security Groups & Converged Auto-DNS', () => {
    const state = DesiredStateSchema.parse({
      plugins: [
        { id: 'core-firewall', enabled: true },
        { id: 'core-virt', enabled: true },
        { id: 'core-k3s', enabled: true },
      ],
      system: { hostname: 'axonwall', domain: 'corp.internal' },
      interfaces: [
        { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true },
        { name: 'lan', device: 'eth1', type: 'static', enabled: true, ipv4Address: '10.10.0.1/24' },
      ],
      dns: {
        enabled: true,
        autoRegisterVirtHosts: true,
        autoRegisterK3sIngresses: true,
      },
      virt: {
        enabled: true,
        exportLibvirtXml: true,
        securityGroups: [
          {
            name: 'dmz_web',
            rules: [
              { direction: 'in', action: 'accept', protocol: 'tcp', cidr: 'any', port: '443', description: 'HTTPS in' },
            ],
          },
        ],
        vms: [
          {
            vmid: 205,
            name: 'win11-vdi',
            osType: 'windows',
            bios: 'ovmf',
            secureBoot: true,
            tpm2: true,
            cores: 8,
            memoryMb: 16384,
            hugepages: '2M',
            disks: [{ name: 'scsi0', pool: 'tank', sizeGb: 120, bus: 'scsi', iopsReadLimit: 5000, iopsWriteLimit: 2500 }],
            virtioFsShares: [{ tag: 'shared_nas', hostPath: '/mnt/tank/shared' }],
            usbPassthrough: ['1050:0407'],
            nics: [{ bridge: 'vmbr0', model: 'virtio', securityGroups: ['dmz_web'] }],
            cloudInit: { user: 'admin', ipConfig: '10.10.0.55/24' },
          },
        ],
      },
      frr: {
        enabled: true,
        bgp: {
          enabled: true,
          asNumber: 65010,
          routerId: '10.10.0.1',
          networks: ['10.10.0.0/24'],
          neighbors: [],
        },
      },
      k3s: {
        enabled: true,
        cniPlugin: 'cilium-ebpf',
        haTopology: 'single-server-ha-agent',
        etcdSnapshots: { enabled: true, retention: 21 },
        serviceLbPools: [{ name: 'lan-vip-pool', cidr: '10.10.0.240/29', mode: 'both' }],
        workloads: [
          {
            name: 'grafana',
            image: 'grafana/grafana:latest',
            port: 3000,
            serviceType: 'LoadBalancer',
            ingressHostname: 'grafana.corp.internal',
            exposeViaHaproxy: true,
          },
        ],
      },
    });

    const virt = compileVirtBundle(state);
    expect(virt.vms).toHaveLength(1);
    const vmArgs = virt.vms[0]!.args.join(' ');
    expect(vmArgs).toContain('q35,accel=kvm,smm=on');
    expect(vmArgs).toContain('OVMF_CODE_4M.secboot.fd');
    expect(vmArgs).toContain('iops_rd=5000,iops_wr=2500');
    expect(vmArgs).toContain('vhost-user-fs-pci');
    expect(vmArgs).toContain('vendorid=0x1050,productid=0x0407');
    expect(virt.libvirtDomainsXml[205]).toContain("<domain type='kvm'>");

    const k3s = compileK3s(state);
    expect(k3s.k3sConfigYaml).toContain('flannel-backend: "none"');
    expect(k3s.k3sConfigYaml).toContain('disable-kube-proxy: true');
    expect(k3s.ciliumManifestYaml).toContain('kind: HelmChart');
    expect(k3s.serviceLbManifestYaml).toContain('kind: CiliumLoadBalancerIPPool');
    expect(k3s.serviceLbManifestYaml).toContain('kind: CiliumBGPPeeringPolicy');
    expect(k3s.workloadsManifestYaml).toContain('kind: Ingress');

    const bundle = compileNftables(state);
    expect(bundle.nftScript).toContain('oifname "tap205i0" jump virt_sg_dmz_web_in');
    expect(bundle.nftScript).toContain('chain virt_sg_dmz_web_in {');
    const unboundFile = bundle.files.find((f) => f.path === '/etc/unbound/unbound.conf.d/axonwall.conf');
    expect(unboundFile?.content).toContain('win11-vdi.corp.internal.');
    expect(unboundFile?.content).toContain('10.10.0.55');
    expect(unboundFile?.content).toContain('grafana.corp.internal.');
    expect(unboundFile?.content).toContain('10.10.0.1');
    const haproxyFile = bundle.files.find((f) => f.path === '/etc/haproxy/haproxy.cfg');
    expect(haproxyFile?.content).toContain('backend k3s_grafana');
    expect(haproxyFile?.content).toContain('frontend fe_converged_tls');
    expect(haproxyFile?.content).toContain('acl host_grafana_corp_internal hdr_dom(host) -i grafana.corp.internal');
    expect(haproxyFile?.content).toContain('use_backend k3s_grafana if host_grafana_corp_internal');
    const frrFile = bundle.files.find((f) => f.path === '/etc/frr/frr.conf');
    expect(frrFile?.content).toContain('network 10.10.0.240/29');
    expect(frrFile?.content).toContain('neighbor 127.0.0.1 remote-as 65010');
    expect(frrFile?.content).toContain('Axonwall K3s Cilium BGP Speaker');
  });

  it('auto-detects, imports, and merges Proxmox VE 8.x and TrueNAS SCALE configurations', () => {
    const proxmoxDump = `
# === /etc/pve/storage.cfg ===
zfspool: nvme-zfs
  pool nvme_tank

# === /etc/pve/qemu-server/104.conf ===
name: db-prod
cores: 4
sockets: 2
memory: 8192
bios: ovmf
efidisk0: nvme-zfs:vm-104-disk-0,efitype=4m,pre-enrolled-keys=1
tpmstate0: nvme-zfs:vm-104-disk-1,version=v2.0
scsi0: nvme-zfs:vm-104-disk-2,size=250G,iops_rd=10000
net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=30
ipconfig0: ip=10.30.0.40/24,gw=10.30.0.1

# === /etc/pve/lxc/201.conf ===
hostname: redis-cache
cores: 2
memory: 2048
unprivileged: 1
rootfs: nvme-zfs:subvol-201-disk-0,size=16G
net0: name=eth0,bridge=vmbr0,ip=10.30.0.41/24,hwaddr=BC:24:11:AA:BB:DD
`;
    expect(detectFirewallType(proxmoxDump)).toBe('proxmox');
    const pveReport = importFirewallConfig(proxmoxDump);
    expect(pveReport.vendor).toBe('proxmox');
    expect(pveReport.vmsCount).toBe(1);
    expect(pveReport.containersCount).toBe(1);
    expect(pveReport.state.virt?.vms[0]?.secureBoot).toBe(true);
    expect(pveReport.state.virt?.vms[0]?.tpm2).toBe(true);
    expect(pveReport.state.virt?.vms[0]?.disks[0]?.sizeGb).toBe(250);

    const truenasJson = JSON.stringify({
      'storage.pool': [
        {
          name: 'dozer',
          topology: {
            data: [{ type: 'RAIDZ2', children: ['/dev/sda', '/dev/sdb', '/dev/sdc', '/dev/sdd'] }],
            special: ['/dev/nvme0n1', '/dev/nvme1n1'],
          },
        },
      ],
      'pool.dataset': [
        { id: 'dozer/media', type: 'FILESYSTEM', compression: 'ZSTD', recordsize: '1M', encrypted: true },
      ],
      'sharing.smb': [
        { name: 'Media', path: '/mnt/dozer/media', timemachine: true, recyclebin: true },
      ],
    });
    expect(detectFirewallType(truenasJson)).toBe('truenas');
    const tnReport = importFirewallConfig(truenasJson);
    expect(tnReport.vendor).toBe('truenas');
    expect(tnReport.zfsPoolsCount).toBe(1);
    expect(tnReport.datasetsCount).toBe(1);
    expect(tnReport.sharesCount).toBe(1);

    const base = DesiredStateSchema.parse({});
    const mergedBoth = mergeFirewallConfigs(mergeFirewallConfigs(base, pveReport.state), tnReport.state);
    expect(mergedBoth.virt?.vms).toHaveLength(1);
    expect(mergedBoth.virt?.containers).toHaveLength(1);
    expect(mergedBoth.nas?.pools.map((p) => p.name)).toContain('dozer');
    expect(mergedBoth.nas?.smbShares[0]?.name).toBe('Media');
  });
});
