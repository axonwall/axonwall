import { describe, expect, it } from 'vitest';
import {
  BUILTIN_PLUGINS,
  DesiredStateSchema,
  arePluginDependenciesMet,
  disablePluginWithDependents,
  enablePluginWithDependencies,
  isPluginEnabled,
  serializeDesiredStateToYamlFiles,
  validateYamlConfigFiles,
} from '../../index.js';
import { buildNetBoxSyncPlan, compileNetBoxBundle } from './index.js';
import { compileNftables } from '../nft/index.js';

describe('NetBox DCIM & IPAM Plugin Compiler & Schema', () => {
  it('registers netbox in BUILTIN_PLUGINS with core-k3s dependency and OpenLDAP integration', () => {
    const plugin = BUILTIN_PLUGINS.find((p) => p.id === 'netbox');
    expect(plugin).toBeDefined();
    expect(plugin?.dependencies).toContain('core-k3s');
    expect(plugin?.menuEntry?.path).toBe('/services/netbox');
    expect(plugin?.ldapIntegration?.serviceAccountCn).toBe('svc-netbox');
    expect(plugin?.ldapIntegration?.groups.map((g) => g.cn)).toEqual([
      'netbox-admin',
      'netbox-operator',
      'netbox-readonly',
    ]);
  });

  it('auto-enables core-k3s when enabling netbox and disables netbox when core-k3s is disabled', () => {
    const baseline = DesiredStateSchema.parse({});
    expect(arePluginDependenciesMet('netbox', baseline)).toEqual({
      met: false,
      missing: ['core-k3s'],
    });

    const enabledRes = enablePluginWithDependencies('netbox', baseline);
    expect(enabledRes.autoEnabledDependencies).toContain('core-k3s');
    expect(isPluginEnabled('core-k3s', enabledRes.state)).toBe(true);
    expect(isPluginEnabled('netbox', enabledRes.state)).toBe(true);
    expect(enabledRes.state.netbox?.enabled).toBe(true);

    const disabledRes = disablePluginWithDependents('core-k3s', enabledRes.state);
    expect(disabledRes.autoDisabledDependents).toContain('netbox');
    expect(isPluginEnabled('netbox', disabledRes.state)).toBe(false);
  });

  it('synthesizes NetBoxSyncPlan from interfaces, VLANs, VRFs, DHCP, VIPs, K3s, and KVM/LXC', () => {
    const state = DesiredStateSchema.parse({
      system: { hostname: 'edge-gw-01', domain: 'corp.example.com' },
      interfaces: [
        {
          name: 'lan',
          device: 'eth1',
          type: 'static',
          role: 'lan',
          enabled: true,
          ipv4Address: '10.80.0.1/24',
          mtu: 1500,
        },
        {
          name: 'wan',
          device: 'eth0',
          type: 'dhcp',
          role: 'wan',
          enabled: true,
        },
      ],
      vlans: [
        { tag: 20, vlanInterface: 'eth1.20', parentInterface: 'eth1', description: 'Management VLAN' },
      ],
      vrfs: [
        { name: 'red-vrf', tableId: 100, interfaces: ['eth1.20'], description: 'Isolated VRF' },
      ],
      virtualIps: [
        { interface: 'lan', ip: '10.80.0.200', type: 'carp', vhid: 10, description: 'Cluster VIP' },
      ],
      dhcp: {
        enabled: true,
        subnets: [
          {
            interface: 'lan',
            subnet: '10.80.0.0/24',
            poolStart: '10.80.0.100',
            poolEnd: '10.80.0.199',
            dnsServers: ['10.80.0.1'],
            staticMappings: [
              { mac: 'aa:bb:cc:dd:ee:ff', ip: '10.80.0.50', hostname: 'nas-01' },
            ],
          },
        ],
      },
      k3s: { enabled: true },
      virt: {
        enabled: true,
        vms: [
          {
            vmid: 101,
            name: 'scanner-vm',
            cores: 4,
            memoryMb: 4096,
            disks: [{ name: 'disk0', sizeGb: 40 }],
            osType: 'linux',
          },
        ],
      },
      netbox: { enabled: true, siteName: 'HQ Rack', siteSlug: 'hq-rack' },
    });

    const plan = buildNetBoxSyncPlan(state);
    expect(plan.site).toEqual({ name: 'HQ Rack', slug: 'hq-rack' });
    expect(plan.device.hostname).toBe('edge-gw-01');
    expect(plan.device.primaryIp).toBe('10.80.0.1');
    expect(plan.vrfs).toHaveLength(1);
    expect(plan.vlans).toHaveLength(1);
    expect(plan.interfaces.map((i) => i.name)).toContain('eth1.20');
    expect(plan.prefixes.map((p) => p.prefix)).toEqual(
      expect.arrayContaining(['10.80.0.0/24', '10.42.0.0/16', '10.43.0.0/16']),
    );
    expect(plan.ipAddresses.map((ip) => ip.address)).toEqual(
      expect.arrayContaining(['10.80.0.1/24', '10.80.0.200/24', '10.80.0.50/32']),
    );
    expect(plan.virtualMachines).toHaveLength(1);
    expect(plan.virtualMachines[0]?.name).toBe('scanner-vm');
  });

  it('compiles safe K3s manifests with loopback LDAP rewritten and Unbound override', () => {
    const state = DesiredStateSchema.parse({
      capabilities: { k3sEnabled: true, firewallEnabled: true },
      k3s: { enabled: true },
      dns: { enabled: true, hostOverrides: [] },
      interfaces: [
        { name: 'lan', device: 'eth1', type: 'static', role: 'lan', enabled: true, ipv4Address: '10.80.0.1/24' },
      ],
      netbox: {
        enabled: true,
        domain: 'netbox.axonwall.local',
      },
    });

    const compiled = compileNetBoxBundle(state);
    expect(compiled.enabled).toBe(true);
    expect(compiled.k3sDependencyMet).toBe(true);
    expect(compiled.podLdapUrl).toBe('ldap://10.80.0.1:389');
    expect(compiled.unboundOverrides).toContain('local-data: "netbox.axonwall.local. IN A 10.80.0.1"');
    expect(compiled.k3sManifestsYaml).toContain('kind: StatefulSet');
    expect(compiled.k3sManifestsYaml).toContain('netboxcommunity/netbox:v4.2');
    expect(compiled.k3sManifestsYaml).toContain('__AXONWALL_NETBOX_DB_PASSWORD__');
    expect(compiled.k3sManifestsYaml).toContain('subPath: ldap_config.py');
    // Security invariant: never emit HelmChart or hostPath or ClusterRole in K3s bundle
    expect(compiled.k3sManifestsYaml).not.toContain('kind: HelmChart');
    expect(compiled.k3sManifestsYaml).not.toContain('hostPath:');
    expect(compiled.k3sManifestsYaml).not.toContain('kind: ClusterRole');

    const nftBundle = compileNftables(state);
    expect(nftBundle.files.some((f) => f.path === '/etc/axonwall/managed/netbox_config.json')).toBe(true);
    expect(nftBundle.files.some((f) => f.path === '/etc/unbound/unbound.conf.d/netbox.conf')).toBe(true);
  });

  it('round-trips netbox inside services.yaml domain serialization', () => {
    const state = DesiredStateSchema.parse({
      netbox: {
        enabled: true,
        domain: 'ipam.axonwall.local',
        postgresStorageGb: 50,
      },
    });
    const yamlFiles = serializeDesiredStateToYamlFiles(state);
    expect(yamlFiles['services.yaml']).toContain('ipam.axonwall.local');
    const validation = validateYamlConfigFiles(yamlFiles); expect(validation.valid).toBe(true); const parsedBack = validation.state!;
    expect(parsedBack.netbox?.domain).toBe('ipam.axonwall.local');
    expect(parsedBack.netbox?.postgresStorageGb).toBe(50);
  });
});
