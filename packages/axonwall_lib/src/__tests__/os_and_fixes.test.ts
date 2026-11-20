import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  DesiredStateSchema,
  BUILTIN_PLUGINS,
  isPluginEnabled,
  parseOsRelease,
  classifyOsFamily,
  detectHostOs,
  resolveOvmfFirmware,
  resolveKeaHaHookPath,
  compileSuricata,
  compileK3s,
  compileKeepalived,
  compileKeaHaHook,
  compileVfio,
  compileVirtBundle,
  compileTrafficShaper,
  compileFrr,
  compileHostDefenseBundle,
  compileVowBundle,
  compileVigilanteUnboundOverrides,
  compileEluvixBundle,
  compileS3MinioEnv,
  compileCaptivePortal,
  compileNftables,
  importProxmoxConfig,
  simulatePacket,
} from '../index.js';

describe('OS Detection & Multi-Distro Adapters (Arch / Omarchy / Debian / Alpine)', () => {
  it('detects Omarchy (ID=omarchy, ID_LIKE=arch) and Arch Linux as arch family', () => {
    const omarchyParsed = parseOsRelease(
      'NAME="Omarchy"\nID=omarchy\nID_LIKE=arch\nVERSION_ID="4.5.0"\nPRETTY_NAME="Omarchy 4.5.0"\n',
    );
    expect(omarchyParsed.id).toBe('omarchy');
    expect(omarchyParsed.idLike).toContain('arch');
    expect(classifyOsFamily(omarchyParsed)).toBe('arch');

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'axon-os-'));
    try {
      fs.mkdirSync(path.join(tmpRoot, 'etc'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpRoot, 'etc', 'os-release'),
        'NAME="Omarchy"\nID=omarchy\nID_LIKE="arch"\nVERSION_ID="4.5.0"\n',
      );
      const info = detectHostOs(tmpRoot);
      expect(info.family).toBe('arch');
      expect(info.isDerivative).toBe(true);
      expect(info.id).toBe('omarchy');
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('classifies Debian and Alpine accurately and resolves OVMF / Kea HA paths', () => {
    expect(classifyOsFamily(parseOsRelease('ID=debian\nPRETTY_NAME="Debian 13"\n'))).toBe('debian');
    expect(classifyOsFamily(parseOsRelease('ID=ubuntu\nID_LIKE=debian\n'))).toBe('debian');
    expect(classifyOsFamily(parseOsRelease('ID=alpine\nVERSION_ID=3.20\n'))).toBe('alpine');
    expect(classifyOsFamily(parseOsRelease('ID=linux\n'), { hasArchRelease: true })).toBe('arch');

    expect(resolveOvmfFirmware({ osFamily: 'arch' }).code).toBe('/usr/share/edk2/x64/OVMF_CODE.4m.fd');
    expect(resolveOvmfFirmware({ osFamily: 'arch', secureBoot: true }).code).toBe(
      '/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd',
    );
    expect(resolveOvmfFirmware({ osFamily: 'debian' }).code).toBe('/usr/share/OVMF/OVMF_CODE.fd');
    expect(resolveKeaHaHookPath({ osFamily: 'arch' })).toBe('/usr/lib/kea/hooks/libdhcp_ha.so');
    expect(resolveKeaHaHookPath({ osFamily: 'debian', arch: 'arm64' })).toBe(
      '/usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp_ha.so',
    );
  });

  it('includes Arch packages and valid console routes in BUILTIN_PLUGINS', () => {
    for (const p of BUILTIN_PLUGINS) {
      if (p.packages) {
        expect(Array.isArray(p.packages.arch)).toBe(true);
        expect(p.packages.arch.length).toBeGreaterThan(0);
      }
      if (p.menuEntry) {
        expect(
          ['/services/haproxy', '/services/freeradius', '/services/snmp', '/vpn/tailscale', '/reporting/ntopng', '/firewall/rules'].includes(
            p.menuEntry.path,
          ),
        ).toBe(false);
      }
    }
    const coreVirt = BUILTIN_PLUGINS.find((p) => p.id === 'core-virt');
    expect(coreVirt?.systemdUnits).not.toContain('qemu-kvm.service');
  });
});

describe('Compiler, Importer & Simulator Bug Fixes', () => {
  it('adds IDS repeat mark guard to Suricata NFQUEUE rules so IDS mode avoids infinite loop', () => {
    const ids = compileSuricata({
      enabled: true,
      mode: 'ids',
      interfaces: ['wan'],
      nfqueueBypass: true,
      nfqueueFailOpen: true,
      homeNet: ['192.168.1.0/24'],
      rulesets: ['et-open'],
      customRules: '',
    });
    expect(ids.nftRules[0]).toContain('meta mark & 0x1 == 0');
    expect(ids.nftRules[0]).toContain('suricata-ids-inbound');

    const ips = compileSuricata({
      enabled: true,
      mode: 'ips',
      interfaces: ['wan'],
      nfqueueBypass: true,
      nfqueueFailOpen: true,
      homeNet: ['192.168.1.0/24'],
      rulesets: ['et-open'],
      customRules: '',
    });
    expect(ips.nftRules[0]).not.toContain('meta mark & 0x1 == 0');
  });

  it('emits valid YAML when K3s workload has both storageClass and bpfTokenProfileId', () => {
    const state = DesiredStateSchema.parse({
      k3s: {
        enabled: true,
        workloads: [
          {
            name: 'ebpf-sensor',
            image: 'ghcr.io/example/sensor:latest',
            port: 9090,
            storageClass: 'axonwall-zfs-local',
            storageSizeGb: 5,
            mountPath: '/var/lib/sensor',
            bpfTokenProfileId: 'net-dp',
            enabled: true,
          },
        ],
      },
    });
    const compiled = compileK3s(state);
    expect(compiled.workloadsManifestYaml).toContain('- name: data');
    expect(compiled.workloadsManifestYaml).toContain('- name: bpf-token-bpffs');
    expect(compiled.workloadsManifestYaml).toContain('LIBBPF_BPF_TOKEN_PATH');
    expect(compiled.workloadsManifestYaml.indexOf('          env:')).toBeLessThan(
      compiled.workloadsManifestYaml.indexOf('      volumes:'),
    );
  });

  it('supports Arch OVMF/LXC/rkhunter/Kea paths when osFamily is arch', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [{ name: 'lan', device: 'enp5s0', enabled: true, ipv4Mode: 'static', ipv4Address: '10.0.0.1/24' }],
      virt: {
        enabled: true,
        vms: [
          {
            vmid: 301,
            name: 'arch-vm',
            bios: 'ovmf',
            secureBoot: true,
            enabled: true,
            disks: [],
            nics: [],
          },
        ],
        containers: [
          {
            ctid: 302,
            hostname: 'arch-ct',
            features: ['nesting'],
            enabled: true,
            nics: [],
            mountPoints: [],
          },
        ],
        vxlanZones: [{ name: 'vx1', vni: 100, underlayInterface: 'lan', enabled: true }],
      },
    });
    const bundle = compileVirtBundle(state, { osFamily: 'arch' });
    expect(bundle.vms[0].args.join(' ')).toContain('/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd');
    expect(bundle.containers[0].lxcConfig).toContain('/usr/share/lxc/config/nesting.conf');
    expect(bundle.vxlanCommands[0]).toContain('dev enp5s0');

    const rootkit = compileHostDefenseBundle(state, { osFamily: 'arch' });
    expect(rootkit.files['/etc/rkhunter.conf.local']).toContain('PKGMGR=PACMAN');
    expect(rootkit.files['/usr/local/bin/axonwall-hunt-rootkits']).toContain('pacman -Qkk');

    const haConf = compileKeepalived({ enabled: true, nodeRole: 'master', vrrpInstances: [{ name: 'VI_1', interface: 'lan', vrid: 10, priority: 100, virtualIps: ['10.0.0.1/24'] }] } as any);
    expect(haConf).not.toContain(';');
    const keaHook = compileKeaHaHook({ enabled: true, nodeRole: 'master', peerAddress: '10.0.0.2' } as any, '10.0.0.1', { osFamily: 'arch' });
    expect(keaHook?.library).toBe('/usr/lib/kea/hooks/libdhcp_ha.so');
  });

  it('prevents IFB name overflow/collisions in compileTrafficShaper and resolves logical interfaces', () => {
    const tc = compileTrafficShaper(
      {
        enabled: true,
        interfaces: [
          { interface: 'longwaniface_alpha', uploadBandwidthMbps: 100, downloadBandwidthMbps: 200, scheduler: 'cake', enabled: true },
          { interface: 'longwaniface_bravo', uploadBandwidthMbps: 100, downloadBandwidthMbps: 200, scheduler: 'cake', enabled: true },
          { interface: 'lan', uploadBandwidthMbps: 100, downloadBandwidthMbps: 50, scheduler: 'cake', enabled: true },
        ],
      } as any,
      [{ name: 'lan', device: 'enp2s0', enabled: true } as any],
    );
    const ifbAdds = tc.commands.filter((c) => c.startsWith('ip link add name '));
    expect(ifbAdds).toHaveLength(3);
    const ifbNames = ifbAdds.map((c) => c.split(' ')[4]);
    expect(ifbNames[0].length).toBeLessThanOrEqual(15);
    expect(ifbNames[1].length).toBeLessThanOrEqual(15);
    expect(ifbNames[0]).not.toBe(ifbNames[1]);
    expect(ifbNames[2]).toBe('ifb-enp2s0');

    const frr = compileFrr(
      {
        enabled: true,
        ospf: {
          enabled: true,
          routerId: '1.1.1.1',
          areas: [{ areaId: '0.0.0.0', interfaces: ['lan'], networks: ['10.0.0.0/24'] }],
        },
      } as any,
      [{ name: 'lan', device: 'enp2s0', enabled: true } as any],
    );
    expect(frr.frrConf).toContain('interface enp2s0');
  });

  it('respects state.vow.enabled=false over stale plugins entry and emits stateful virt SG rules', () => {
    const state = DesiredStateSchema.parse({
      capabilities: { firewallEnabled: true, k3sEnabled: true, virtEnabled: true },
      vow: { enabled: false },
      plugins: [{ id: 'vigilant-octo-waffle', enabled: true }],
      virt: {
        enabled: true,
        securityGroups: [{ name: 'web_sg', rules: [{ direction: 'in', protocol: 'tcp', port: '443', action: 'accept' }] }],
      },
    });
    expect(isPluginEnabled('vigilant-octo-waffle', state)).toBe(false);
    expect(compileVowBundle(state).enabled).toBe(false);

    const nft = compileNftables(state);
    expect(nft.nftScript).toContain('chain virt_sg_web_sg_in {\n    ct state established,related accept');
  });

  it('sanitizes MINIO env vars, captive portal rules, VFIO IDs, and Proxmox vnet fields', () => {
    const minioEnv = compileS3MinioEnv({
      s3: { enabled: true, accessKey: 'admin', secretKey: 'p@ss"$(whoami)`1' },
    } as any);
    expect(minioEnv).toContain('\\"\\$(whoami)\\`1');

    expect(() =>
      compileVfio([{ bdf: '0000:01:00.0', driver: 'vfio-pci', vendorId: '8086;id', deviceId: '1000', iommuGroup: 1, sriovNumVfs: 0, description: '' }]),
    ).toThrow();

    expect(() =>
      compileCaptivePortal({
        enabled: true,
        zones: [{ name: 'guest', interface: 'eth1" bad', listenPort: 8999, authServers: ['ldap_internal'], sessionTimeoutMinutes: 60, idleTimeoutMinutes: 10, passThroughMacs: [], passThroughIps: [], enableBandwidthQuotas: false, downloadLimitKbps: 1000, uploadLimitKbps: 1000, enabled: true }],
      }),
    ).toThrow();

    const pve = importProxmoxConfig(
      'hostname: ct1\nrootfs: local-zfs:subvol-105-disk-0,size=8G\nnet0: name=eth0,bridge=vmbr0,ip=10.10.0.5/24\n',
    );
    expect(pve.state.virt?.containers[0].nics[0].vnet).toBe('eth0');

    expect(() =>
      compileEluvixBundle({
        interfaces: [],
        eluvix: { domain: 'ai.local\necho pwned' } as any,
      } as any),
    ).toThrow();

    const vigDns = compileVigilanteUnboundOverrides({
      interfaces: [],
      vigilante: { enabled: true, domain: 'soc.local" drop', modules: [{ id: 'wazuh', enabled: true }] } as any,
    } as any);
    expect(vigDns).not.toContain('" drop');
  });

  it('supports invertSource/invertDestination, comma ports, and case-insensitive port aliases in packet simulator', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [
        { name: 'lan', device: 'eth1', role: 'lan', ipv4Address: '192.168.1.1/24', enabled: true },
        { name: 'wan', device: 'eth0', role: 'wan', ipv4Address: '203.0.113.2/24', enabled: true },
      ],
      aliases: [{ name: 'WebPorts', type: 'port', entries: ['80,443'], enabled: true }],
      rules: [
        {
          interface: 'lan',
          direction: 'in',
          action: 'pass',
          protocol: 'tcp',
          source: '192.168.1.99',
          invertSource: true,
          destination: 'any',
          destinationPort: '$webports',
          enabled: true,
          sortOrder: 1,
        },
      ],
    });

    const allowed = simulatePacket(
      {
        inInterface: 'lan',
        protocol: 'tcp',
        srcIp: '192.168.1.50',
        srcPort: 55000,
        dstIp: '1.1.1.1',
        dstPort: 443,
      },
      state,
    );
    expect(allowed.verdict).toBe('ALLOW');

    const invertedDrop = simulatePacket(
      {
        inInterface: 'lan',
        protocol: 'tcp',
        srcIp: '192.168.1.99',
        srcPort: 55000,
        dstIp: '1.1.1.1',
        dstPort: 443,
      },
      state,
    );
    expect(invertedDrop.verdict).toBe('DROP');
  });
});
