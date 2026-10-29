import { describe, it, expect } from 'vitest';
import {
  compileVmProcess,
  compileCloudInit,
  compileLxcContainer,
  compileVfio,
  compileVxlan,
  compileVirtBundle,
  compileHostedEdge,
  generateDeterministicMac,
} from './index.js';
import {
  serializeDesiredStateToYamlFiles,
  parseDesiredStateFromYamlFiles,
  validateYamlConfigFiles,
} from '../../yaml/index.js';
import type { VirtualMachine, LxcContainer } from '../../schemas/index.js';
import { DesiredStateSchema } from '../../schemas/index.js';

describe('Virt / Hypervisor Compilers', () => {
  const sampleVm: VirtualMachine = {
    vmid: 101,
    name: 'test-vm',
    description: 'Debian 12 production VM',
    osType: 'linux',
    bios: 'ovmf',
    secureBoot: false,
    tpm2: true,
    sockets: 1,
    cores: 4,
    cpuType: 'host',
    memoryMb: 4096,
    balloonMinMb: 1024,
    agent: true,
    autostart: true,
    haManaged: false,
    enabled: true,
    disks: [
      {
        name: 'disk0',
        pool: 'tank',
        sizeGb: 50,
        bus: 'virtio',
        cache: 'none',
        discard: true,
        readOnly: false,
        backup: true,
        iopsReadLimit: 0,
        iopsWriteLimit: 0,
      },
    ],
    nics: [
      {
        mac: 'bc:24:11:00:65:00',
        bridge: 'br0',
        vlanTag: 10,
        model: 'virtio',
        firewall: true,
        rateLimitMbps: 0,
      },
    ],
    cloudInit: {
      user: 'debian',
      password: 'password123',
      sshAuthorizedKeys: ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@host'],
      ipConfig: '192.168.10.50/24',
      gateway: '192.168.10.1',
      nameservers: ['1.1.1.1', '8.8.8.8'],
    },
    pciPassthrough: ['0000:03:00.0'],
    usbPassthrough: [],
  };

  const sampleContainer: LxcContainer = {
    ctid: 201,
    hostname: 'web-ct',
    description: 'Nginx container',
    template: 'debian-12-standard',
    unprivileged: true,
    cores: 2,
    memoryMb: 1024,
    swapMb: 512,
    rootfsPool: 'tank',
    rootfsSizeGb: 10,
    features: ['nesting'],
    autostart: true,
    haManaged: false,
    enabled: true,
    nics: [
      {
        mac: 'bc:24:11:00:c9:00',
        bridge: 'br0',
        model: 'virtio',
        firewall: true,
        rateLimitMbps: 0,
      },
    ],
    mountPoints: [
      {
        hostPath: '/mnt/tank/data',
        mountPath: '/data',
        readOnly: false,
      },
    ],
    dnsServers: ['1.1.1.1'],
  };

  it('generates deterministic MAC addresses', () => {
    const mac1 = generateDeterministicMac(100, 0);
    const mac2 = generateDeterministicMac(100, 1);
    const mac3 = generateDeterministicMac(200, 0);
    expect(mac1).toBe('bc:24:11:00:64:00');
    expect(mac2).toBe('bc:24:11:00:64:01');
    expect(mac3).toBe('bc:24:11:00:c8:00');
  });

  it('compiles QEMU command arguments for VirtualMachine', () => {
    const compiled = compileVmProcess(sampleVm);
    expect(compiled.vmid).toBe(101);
    expect(compiled.name).toBe('test-vm');
    expect(compiled.qemuBinary).toBe('qemu-system-x86_64');
    expect(compiled.qmpSocket).toBe('/run/axonwall/qmp/vm-101.sock');
    expect(compiled.vncSocket).toBe('/run/axonwall/vnc/vm-101.sock');
    expect(compiled.serialSocket).toBe('/run/axonwall/serial/vm-101.sock');

    const argStr = compiled.args.join(' ');
    expect(argStr).toContain('-enable-kvm');
    expect(argStr).toContain('-machine q35,accel=kvm');
    expect(argStr).toContain('-smp cpus=4,cores=4,threads=1,sockets=1');
    expect(argStr).toContain('-m 4096');
    expect(argStr).toContain('/run/axonwall/qmp/vm-101.sock');
    expect(argStr).toContain('/usr/share/OVMF/OVMF_CODE.fd');
    expect(argStr).toContain('/run/axonwall/swtpm/vm-101.sock');
    expect(argStr).toContain('file=/dev/zvol/tank/vms/vm-101-disk-0');
    expect(argStr).toContain('-device virtio-blk-pci,drive=drive-disk0');
    expect(argStr).toContain('-device virtio-net-pci,netdev=net0,mac=bc:24:11:00:65:00');
    expect(argStr).toContain('-device vfio-pci,host=0000:03:00.0');
    expect(argStr).toContain('vm-101-cidata.iso');
  });

  it('compiles Cloud-Init metadata, user-data, and network-config', () => {
    const ci = compileCloudInit(sampleVm);
    expect(ci).not.toBeNull();
    if (!ci) return;

    expect(ci.metaDataYaml).toContain('instance-id: vm-101');
    expect(ci.metaDataYaml).toContain('local-hostname: test-vm');

    expect(ci.userDataYaml).toContain('#cloud-config');
    expect(ci.userDataYaml).toContain('name: debian');
    expect(ci.userDataYaml).toContain('ssh-ed25519');
    expect(ci.userDataYaml).toContain('plain_text_passwd: password123');

    expect(ci.networkConfigYaml).toContain('version: 2');
    expect(ci.networkConfigYaml).toContain('192.168.10.50/24');
    expect(ci.networkConfigYaml).toContain('gateway4: 192.168.10.1');
    expect(ci.networkConfigYaml).toContain('1.1.1.1, 8.8.8.8');
  });

  it('compiles LXC container configuration', () => {
    const ct = compileLxcContainer(sampleContainer);
    expect(ct.ctid).toBe(201);
    expect(ct.name).toBe('web-ct');
    expect(ct.lxcConfig).toContain('lxc.uts.name = web-ct');
    expect(ct.lxcConfig).toContain('lxc.rootfs.path = dir:/mnt/tank/lxc/subvol-201-disk-0');
    expect(ct.lxcConfig).toContain('lxc.cgroup2.memory.max = 1024M');
    expect(ct.lxcConfig).toContain('lxc.cgroup2.cpuset.cpus = 0-1');
    expect(ct.lxcConfig).toContain('lxc.idmap = u 0 100000 65536');
    expect(ct.lxcConfig).toContain('lxc.net.0.type = veth');
    expect(ct.lxcConfig).toContain('lxc.net.0.link = br0');
    expect(ct.lxcConfig).toContain('lxc.mount.entry = /mnt/tank/data data none rw,bind,create=dir 0 0');
  });

  it('compiles VFIO and SR-IOV configurations', () => {
    const vfio = compileVfio([
      {
        bdf: '0000:03:00.0',
        vendorId: '8086',
        deviceId: '1539',
        iommuGroup: 12,
        driver: 'vfio-pci',
        sriovNumVfs: 4,
        description: 'Intel I211 Gigabit NIC',
      },
    ]);

    expect(vfio.modprobeConf).toContain('options vfio-pci ids=8086:1539');
    expect(vfio.udevRules).toContain('SUBSYSTEM=="vfio", OWNER="root", GROUP="kvm"');
    expect(vfio.sriovInitScript).toContain('echo 4 > /sys/bus/pci/devices/0000:03:00.0/sriov_numvfs');
  });

  it('compiles VXLAN zone commands', () => {
    const vxlan = compileVxlan([
      {
        name: 'vxlan100',
        vni: 100,
        peers: ['192.168.1.10', '192.168.1.20'],
        underlayInterface: 'lan',
        port: 4789,
        bridge: 'vmbr0',
        mtu: 1450,
        enabled: true,
        description: 'Cluster overlay',
      },
    ]);

    expect(vxlan.ipCommands).toHaveLength(4);
    expect(vxlan.ipCommands[0]).toContain('ip link add vxlan100 type vxlan id 100 dstport 4789 dev lan');
    expect(vxlan.ipCommands[1]).toContain('ip link set vxlan100 mtu 1450');
    expect(vxlan.ipCommands[2]).toContain('ip link set vxlan100 up');
    expect(vxlan.ipCommands[3]).toContain('ip link set vxlan100 master vmbr0');
  });

  it('compiles whole VirtBundle from DesiredState', () => {
    const state = DesiredStateSchema.parse({
      virt: {
        enabled: true,
        defaultPool: 'tank',
        isoPool: 'tank',
        vms: [sampleVm],
        containers: [sampleContainer],
        isos: [],
        pciDevices: [],
        backupJobs: [],
        vxlanZones: [],
      },
    });

    const bundle = compileVirtBundle(state);
    expect(bundle.vms).toHaveLength(1);
    expect(bundle.cloudInits).toHaveLength(1);
    expect(bundle.containers).toHaveLength(1);
  });

  it('serializes and deserializes virt.yaml correctly with GitOps YAML engine', () => {
    const state = DesiredStateSchema.parse({
      capabilities: {
        firewallEnabled: true,
        nasEnabled: false,
        k3sEnabled: false,
        virtEnabled: true,
      },
      virt: {
        enabled: true,
        defaultPool: 'tank',
        isoPool: 'tank',
        vms: [sampleVm],
        containers: [sampleContainer],
        isos: [],
        pciDevices: [],
        backupJobs: [],
        vxlanZones: [],
      },
    });

    const files = serializeDesiredStateToYamlFiles(state);
    expect(files['virt.yaml']).toBeDefined();
    expect(files['virt.yaml']).toContain('Axonwall Hypervisor');
    expect(files['virt.yaml']).toContain('test-vm');
    expect(files['virt.yaml']).toContain('web-ct');

    const validation = validateYamlConfigFiles(files);
    expect(validation.valid).toBe(true);
    expect(validation.errors).toHaveLength(0);

    const parsed = parseDesiredStateFromYamlFiles(files);
    expect(parsed.virt).toBeDefined();
    expect(parsed.virt?.vms).toHaveLength(1);
    expect(parsed.virt?.vms[0].name).toBe('test-vm');
    expect(parsed.virt?.containers).toHaveLength(1);
    expect(parsed.virt?.containers[0].hostname).toBe('web-ct');
  });

  it('compiles Hosted Edge NGFW UKI with direct -kernel, -fw_cfg, i6300esb watchdog, br-wan/br-lan NICs, and baseline /etc/nftables.conf', () => {
    const state = DesiredStateSchema.parse({
      system: {
        hostname: 'router-box-a',
      },
      interfaces: [
        { name: 'wan', device: 'eth0', role: 'wan-delegated', type: 'dhcp', enabled: true, ipv6Mode: 'disabled' },
        { name: 'lan1', device: 'eth1', role: 'lan', type: 'static', enabled: true },
        { name: 'lan2', device: 'eth2', role: 'lan', type: 'static', enabled: true },
      ],
      hostedEdge: {
        enabled: true,
        ukiSlot: 'A',
        skuProfile: 'sku-vm-virtio',
        vcpus: 2,
        memoryMiB: 256,
        wan: {
          hostDevice: 'eth0',
          bridgeName: 'br-wan',
          attachMode: 'bridge',
          ipv4Mode: 'dhcp',
          ipv6Mode: 'auto',
          ipv6RequestPrefix: 56,
        },
        lan: {
          bridgeName: 'br-lan',
          edgeAddress: '10.0.0.1/24',
          hostAddress: '10.0.0.2/24',
          ipv6Mode: 'delegated',
        },
        portForwards: [
          { proto: 'tcp', wanPort: 443, targetIp: '10.0.0.2', targetPort: 443, comment: 'k3s-ingress' },
        ],
      },
    });

    const compiled = compileHostedEdge(state, {
      ztpToken: 'ztp_secret_123',
      caCertPem: '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----',
    });

    expect(compiled.vmSpec.id).toBe('edge');
    expect(compiled.vmSpec.name).toBe('axonwall-edge-ngfw');
    const argsStr = compiled.vmSpec.args.join(' ');
    expect(argsStr).toContain('-kernel /usr/lib/axonwall/edge/slot-A/axonwall-edge-sku-vm-virtio.efi');
    expect(argsStr).toContain('-fw_cfg name=opt/org.axonwall/user-data,file=/run/axonwall/edge/user-data');
    expect(argsStr).toContain('-fw_cfg name=opt/org.axonwall/meta-data,file=/run/axonwall/edge/meta-data');
    expect(argsStr).toContain('-device i6300esb -watchdog-action reset');
    expect(argsStr).toContain('ifname=tap-edge-wan,script=no,downscript=no,vhost=on');
    expect(argsStr).toContain('addr=0x3');
    expect(argsStr).toContain('ifname=tap-edge-lan,script=no,downscript=no,vhost=on,queues=2');
    expect(argsStr).toContain('mq=on,vectors=6,addr=0x4');
    expect(argsStr).not.toContain('/dev/zvol/');

    expect(compiled.wanBridge.name).toBe('br-wan');
    expect(compiled.wanBridge.members.map((m) => m.interface)).toEqual(['eth0']);
    expect(compiled.lanBridge.name).toBe('br-lan');
    expect(compiled.lanBridge.members.map((m) => m.interface)).toEqual(['eth1', 'eth2']);

    expect(compiled.userData).toContain('#cloud-config');
    expect(compiled.userData).toContain('hostname: edge-router-box-a');
    expect(compiled.userData).toContain('hub: wss://10.0.0.2:2966/ws/satellite');
    expect(compiled.userData).toContain('token: ztp_secret_123');
    expect(compiled.userData).toContain('path: /etc/nftables.conf');

    expect(compiled.baselineNftScript).toContain('iifname "eth1" oifname "eth0" accept comment "allow-lan-to-wan"');
    expect(compiled.baselineNftScript).toContain('oifname "eth0" masquerade comment "edge-ngfw-wan-masquerade"');
    expect(compiled.baselineNftScript).toContain('iifname "eth0" tcp dport 443 dnat ip to 10.0.0.2:443 comment "k3s-ingress"');
  });
});
