import { describe, it, expect } from 'vitest';
import {
  AXONWALL_YAML_FILENAMES,
  serializeDesiredStateToYamlFiles,
  serializeDesiredStateToSingleYaml,
  parseDesiredStateFromYamlFiles,
  validateYamlConfigFiles,
} from './index.js';
import { DesiredStateSchema } from '../schemas/index.js';

describe('Axonwall YAML Configuration Engine (/etc/axonwall/*.yaml)', () => {
  it('round-trips a full DesiredState across all 10 domain YAML files losslessly', () => {
    const initial = DesiredStateSchema.parse({
      version: 1,
      capabilities: {
        firewallEnabled: true,
        nasEnabled: true,
        k3sEnabled: true,
      },
      system: {
        hostname: 'axonwall-edge-01',
        domain: 'corp.axonwall.io',
        dnsServers: ['1.1.1.1', '9.9.9.9'],
        timezone: 'America/Chicago',
        flowtableOffload: true,
        sshEnabled: true,
        sshPort: 2222,
        webGuiPort: 8443,
      },
      interfaces: [
        {
          name: 'wan',
          device: 'eth0',
          type: 'dhcp',
          enabled: true,
          description: 'Primary Fiber WAN',
          mtu: 1500,
        },
        {
          name: 'lan',
          device: 'eth1',
          type: 'static',
          enabled: true,
          ipv4Address: '10.10.1.1/24',
          description: 'Core Trusted LAN',
          mtu: 1500,
        },
      ],
      vlans: [
        {
          tag: 20,
          parentInterface: 'eth1',
          vlanInterface: 'eth1.20',
          priority: 0,
          description: 'IoT VLAN 20',
        },
      ],
      aliases: [
        {
          name: 'rfc1918_nets',
          type: 'network',
          entries: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
          description: 'Private IPv4 ranges',
          enabled: true,
        },
      ],
      rules: [
        {
          action: 'pass',
          direction: 'in',
          interface: 'lan',
          protocol: 'any',
          source: '10.10.1.0/24',
          destination: 'any',
          description: 'Allow LAN to anywhere',
          sortOrder: 10,
        },
      ],
      wireguard: {
        enabled: true,
        listenPort: 51820,
        address: '10.99.0.1/24',
        peers: [
          {
            name: 'roadwarrior-laptop',
            publicKey: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2=',
            allowedIps: ['10.99.0.2/32'],
            persistentKeepalive: 25,
            enabled: true,
          },
        ],
      },
      suricata: {
        enabled: true,
        mode: 'ips',
        interfaces: ['wan'],
        nfqueueFailOpen: true,
        nfqueueBypass: true,
        homeNet: ['10.10.1.0/24'],
      },
      nas: {
        enabled: true,
        workgroup: 'CORP',
        serverString: 'Axonwall ZFS NAS',
        pools: [
          {
            name: 'tank',
            topology: 'mirror',
            dataDisks: ['/dev/nvme0n1', '/dev/nvme1n1'],
            compression: 'zstd',
          },
        ],
      },
      k3s: {
        enabled: true,
        clusterCidr: '10.42.0.0/16',
        serviceCidr: '10.43.0.0/16',
        nodeIpInterface: 'lan',
        flannelBackend: 'wireguard-native',
      },
    });

    const yamlFiles = serializeDesiredStateToYamlFiles(initial);
    expect(Object.keys(yamlFiles)).toEqual(AXONWALL_YAML_FILENAMES);

    for (const filename of AXONWALL_YAML_FILENAMES) {
      expect(yamlFiles[filename]).toContain(`# File: /etc/axonwall/${filename}`);
      expect(yamlFiles[filename]).toContain('axonwallctl apply');
    }

    const parsed = parseDesiredStateFromYamlFiles(yamlFiles);
    expect(parsed).toEqual(initial);

    const singleYaml = serializeDesiredStateToSingleYaml(initial);
    const parsedFromSingle = parseDesiredStateFromYamlFiles({ 'axonwall.yaml': singleYaml });
    expect(parsedFromSingle).toEqual(initial);
  });

  it('reports file and path details when a YAML file has invalid schema values', () => {
    const res = validateYamlConfigFiles({
      'interfaces.yaml': `
interfaces:
  - name: wan
    device: eth0
    type: static
    ipv4Address: "999.999.999.999"
`,
    });

    expect(res.valid).toBe(false);
    expect(res.errors.length).toBeGreaterThan(0);
    expect(res.errors[0].file).toBe('interfaces.yaml');
    expect(res.errors[0].path).toContain('interfaces.0.ipv4Address');
  });
});
