import { describe, expect, it } from 'vitest';
import {
  DesiredStateSchema,
  compileLibreNmsBundle,
  buildLibreNmsEnrollmentPlan,
  enablePluginWithDependencies,
  disablePluginWithDependents,
  isPluginEnabled,
  compileNftables,
} from '../../index.js';
import { serializeDesiredStateToYamlFiles, validateYamlConfigFiles } from '../../yaml/index.js';

describe('LibreNMS K3s Monitoring Plugin & Compiler', () => {
  it('auto-enables core-k3s dependency when enabling librenms and cascades disable from core-k3s', () => {
    const base = DesiredStateSchema.parse({
      capabilities: { firewallEnabled: true, k3sEnabled: false },
    });
    const enabledRes = enablePluginWithDependencies('librenms', base);
    expect(isPluginEnabled('librenms', enabledRes.state)).toBe(true);
    expect(isPluginEnabled('core-k3s', enabledRes.state)).toBe(true);
    expect(enabledRes.autoEnabledDependencies).toContain('core-k3s');

    const disabledRes = disablePluginWithDependents('core-k3s', enabledRes.state);
    expect(isPluginEnabled('core-k3s', disabledRes.state)).toBe(false);
    expect(isPluginEnabled('librenms', disabledRes.state)).toBe(false);
    expect(disabledRes.autoDisabledDependents).toContain('librenms');
  });

  it('compiles safe K3s manifests, OpenLDAP PHP config, discovery PHP config, and Unbound override', () => {
    const state = DesiredStateSchema.parse({
      system: { hostname: 'edge-fw', domain: 'lab.internal', timezone: 'America/Chicago' },
      interfaces: [{ name: 'lan', device: 'eth1', role: 'lan', enabled: true, ipv4Address: '10.20.0.1/24' }],
      dns: { enabled: true, hostOverrides: [] },
      snmp: { enabled: true, community: 'axonwall-ro', listenPort: 161 },
      ha: { enabled: true, role: 'master', peerIp: '10.20.0.2', interface: 'eth2' },
      fleet: {
        nodes: [
          {
            id: 'sat-1',
            name: 'branch-ap',
            role: 'satellite',
            ip: '10.20.50.10',
            status: 'online',
            wireguard: { tunnelIp: '10.99.0.10', connected: true },
          },
        ],
      },
      librenms: {
        enabled: true,
        mode: 'k3s',
        domain: 'nms.lab.internal',
        syslogEnabled: true,
        snmpTrapEnabled: true,
        discoverySubnets: [{ cidr: '10.20.10.0/24', label: 'Mgmt VLAN 10', enabled: true }],
      },
      plugins: [
        { id: 'core-k3s', enabled: true },
        { id: 'librenms', enabled: true },
      ],
    });

    const compiled = compileLibreNmsBundle(state);
    expect(compiled.enabled).toBe(true);
    expect(compiled.k3sDependencyMet).toBe(true);
    expect(compiled.endpointUrl).toBe('https://nms.lab.internal');
    expect(compiled.podLdapUrl).toBe('ldap://10.20.0.1:389');
    expect(compiled.ldapConfigPhp).toContain("cn=svc-librenms,ou=services,dc=lab,dc=internal");
    expect(compiled.ldapConfigPhp).toContain("'librenms-admin' => ['level' => 10]");
    expect(compiled.discoveryConfigPhp).toContain("10.20.10.0/24");
    expect(compiled.discoveryConfigPhp).toContain("axonwall-ro");
    expect(compiled.unboundOverrides).toContain('local-data: "nms.lab.internal. IN A 10.20.0.1"');

    // Bundle safety checks aligned with bundle_validate.go
    expect(compiled.k3sManifestsYaml).not.toContain('kind: HelmChart');
    expect(compiled.k3sManifestsYaml).not.toContain('kind: PersistentVolume\n');
    expect(compiled.k3sManifestsYaml).not.toContain('kind: ClusterRole');
    expect(compiled.k3sManifestsYaml).not.toContain('kind: Role');
    expect(compiled.k3sManifestsYaml).not.toContain('hostPath:');
    expect(compiled.k3sManifestsYaml).not.toContain('hostNetwork:');
    expect(compiled.k3sManifestsYaml).not.toContain('privileged: true');
    expect(compiled.k3sManifestsYaml).not.toContain('capabilities:');

    expect(compiled.k3sManifestsYaml).toContain('__AXONWALL_LIBRENMS_DB_PASSWORD__');
    expect(compiled.k3sManifestsYaml).toContain('__AXONWALL_LIBRENMS_API_TOKEN__');
    expect(compiled.k3sManifestsYaml).toContain('librenms-mariadb');
    expect(compiled.k3sManifestsYaml).toContain('librenms-valkey');
    expect(compiled.k3sManifestsYaml).toContain('librenms-rrdcached');
    expect(compiled.k3sManifestsYaml).toContain('librenms-dispatcher');
    expect(compiled.k3sManifestsYaml).toContain('librenms-syslogng');
    expect(compiled.k3sManifestsYaml).toContain('librenms-snmptrapd');

    const plan = buildLibreNmsEnrollmentPlan(state);
    expect(plan.snmpEnabledOnLocal).toBe(true);
    expect(plan.targets.map((t) => t.source)).toEqual(['local', 'ha-peer', 'fleet']);
    expect(plan.discoverySubnets).toEqual([{ cidr: '10.20.10.0/24', label: 'Mgmt VLAN 10' }]);
  });

  it('skips K3s manifests and Unbound overrides in external mode while keeping enrollment plan', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [{ name: 'lan', device: 'eth1', role: 'lan', enabled: true, ipv4Address: '10.1.0.1/24' }],
      librenms: {
        enabled: true,
        mode: 'external',
        externalUrl: 'https://nms.corp.example:8443/',
        apiToken: 'tok-ext-123',
      },
      plugins: [{ id: 'librenms', enabled: true }],
    });

    const compiled = compileLibreNmsBundle(state);
    expect(compiled.enabled).toBe(true);
    expect(compiled.mode).toBe('external');
    expect(compiled.endpointUrl).toBe('https://nms.corp.example:8443');
    expect(compiled.k3sManifestsYaml).toBe('');
    expect(compiled.unboundOverrides).toBe('');
  });

  it('emits managed config and round-trips inside services.yaml', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [{ name: 'lan', device: 'eth1', role: 'lan', enabled: true, ipv4Address: '192.168.10.1/24' }],
      dns: { enabled: true, hostOverrides: [] },
      librenms: {
        enabled: true,
        mode: 'k3s',
        domain: 'monitor.axonwall.local',
        webhookSecret: 'hook-secret',
      },
      plugins: [
        { id: 'core-k3s', enabled: true },
        { id: 'librenms', enabled: true },
      ],
    });

    const compiled = compileNftables(state);
    const managed = compiled.files.find((f) => f.path === '/etc/axonwall/managed/librenms_config.json');
    const unbound = compiled.files.find((f) => f.path === '/etc/unbound/unbound.conf.d/librenms.conf');
    expect(managed).toBeDefined();
    expect(managed?.fileMode).toBe(0o600);
    expect(unbound).toBeDefined();
    expect(unbound?.content).toContain('monitor.axonwall.local');

    const yamlFiles = serializeDesiredStateToYamlFiles(state);
    expect(yamlFiles['services.yaml']).toContain('monitor.axonwall.local');
    const validation = validateYamlConfigFiles(yamlFiles);
    expect(validation.valid).toBe(true);
    expect(validation.state?.librenms?.domain).toBe('monitor.axonwall.local');
  });
});
