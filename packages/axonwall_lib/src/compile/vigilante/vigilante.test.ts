import { describe, it, expect } from 'vitest';
import {
  compileVigilanteNftables,
  compileVigilanteUnboundOverrides,
  compileVigilanteK3sManifests,
  compileVigilanteConfigYaml,
  compileVigilanteLdapEnv,
  compileVigilanteBundle,
} from './index.js';
import { DesiredStateSchema, type DesiredState } from '../../schemas/index.js';
import { serializeDesiredStateToYamlFiles, parseDesiredStateFromYamlFiles } from '../../yaml/index.js';
import {
  BUILTIN_PLUGINS,
  findPluginById,
  getPluginDependencies,
  getDependentPlugins,
  enablePluginWithDependencies,
  disablePluginWithDependents,
  isPluginEnabled,
} from '../../plugins/index.js';

describe('Vigilante Subsystem Compilers', () => {
  const baseState: DesiredState = DesiredStateSchema.parse({
    version: 1,
    interfaces: [
      {
        name: 'lan',
        device: 'eth0',
        enabled: true,
        type: 'static',
        description: 'Primary LAN',
        mtu: 1500,
        ipv4Address: '192.168.1.1/24',
      },
    ],
    vigilante: {
      enabled: true,
      domain: 'soc.axonwall.local',
      modules: [
        {
          id: 'opensearch',
          enabled: true,
          namespace: 'vigilante-soc',
          storageClass: 'axonwall-zfs-local',
          storageSizeGb: 50,
          customValuesYaml: 'clusterName: opensearch-soc',
        },
        {
          id: 'falco',
          enabled: true,
          namespace: 'vigilante-soc',
          storageClass: 'axonwall-zfs-local',
          storageSizeGb: 5,
        },
      ],
      soar: {
        autoBlockC2Ips: true,
        autoIsolateCompromisedPods: true,
        autoFreezeRansomwarePods: true,
        ransomwareEntropyDeltaThreshold: 2.0,
        warRoomQuorumThreshold: 0.75,
        blocklistTimeoutSeconds: 86400,
      },
      deception: {
        enabled: true,
        canaryServiceAccounts: ['cluster-admin-backup', 'vault-sync-sa'],
        honeytokens: ['aws-sts', 'kubeconfig'],
        decoyServices: ['smb'],
        ransomwareCanaryDirs: ['/mnt/tank/shares'],
      },
      evidenceVault: {
        zfsPool: 'tank',
        datasetName: 'vigilante-evidence',
        dataLakeBackend: 'sqlite',
        gpgEnabled: false,
        gpgKeyId: '',
        merkleLedgerEnabled: true,
      },
      federation: {
        enabled: false,
        nodeName: 'axonwall-soc-primary',
        peers: [],
        autoIngestPeerBlocks: true,
      },
    },
  });

  it('compiles nftables dynamic set and drop rules for SOAR', () => {
    const nft = compileVigilanteNftables(baseState);
    expect(nft).toContain('table inet axonwall');
    expect(nft).toContain('set vigilante_soar_blocklist_v4');
    expect(nft).toContain('set vigilante_soar_blocklist_v6');
    expect(nft).toContain('ip saddr @vigilante_soar_blocklist_v4 counter drop');
    expect(nft).toContain('ip6 saddr @vigilante_soar_blocklist_v6 counter drop');
  });

  it('returns disabled comment when Vigilante is not enabled', () => {
    const disabledState = DesiredStateSchema.parse({
      ...baseState,
      vigilante: { ...baseState.vigilante!, enabled: false },
    });
    expect(compileVigilanteNftables(disabledState)).toContain('disabled');
    expect(compileVigilanteUnboundOverrides(disabledState)).toContain('disabled');
    expect(compileVigilanteK3sManifests(disabledState)).toContain('disabled');
  });

  it('compiles Unbound DNS local-zone and local-data overrides', () => {
    const unbound = compileVigilanteUnboundOverrides(baseState);
    expect(unbound).toContain('local-zone: "soc.axonwall.local." transparent');
    expect(unbound).toContain('local-data: "siem.soc.axonwall.local. IN A 192.168.1.1"');
  });

  it('compiles K3s manifests with namespace, canary ServiceAccounts, PVC and HelmChart CRDs', () => {
    const manifests = compileVigilanteK3sManifests(baseState);
    expect(manifests).toContain('kind: Namespace');
    expect(manifests).toContain('name: vigilante-soc');
    expect(manifests).toContain('name: cluster-admin-backup');
    expect(manifests).toContain('name: opensearch-data-pvc');
    expect(manifests).toContain('storageClassName: axonwall-zfs-local');
    expect(manifests).toContain('kind: HelmChart');
    expect(manifests).toContain('name: vigilante-opensearch');
    expect(manifests).toContain('name: vigilante-falco');
  });

  it('compiles Vigilante runtime config.yaml', () => {
    const yaml = compileVigilanteConfigYaml(baseState);
    expect(yaml).toContain('domain: soc.axonwall.local');
    expect(yaml).toContain('clusterName: axonwall-k3s');
    expect(yaml).toContain('clusterProvider: k3s');
    expect(yaml).toContain('kubeconfig: /etc/rancher/k3s/k3s.yaml');
    expect(yaml).toContain('storageClass: axonwall-zfs-local');
    expect(yaml).toContain('backend: sqlite');
    expect(yaml).toContain('autoBlockC2Ips: true');
    expect(yaml).toContain('cluster-admin-backup');
  });

  it('enforces core-k3s dependency for core-vigilante and auto-enables/disables with K3s', () => {
    const manifest = findPluginById('core-vigilante');
    expect(manifest?.dependencies).toEqual(['core-k3s']);
    expect(getPluginDependencies('core-vigilante')).toEqual(['core-k3s']);
    expect(getDependentPlugins('core-k3s').map((p) => p.id)).toContain('core-vigilante');

    const initial = DesiredStateSchema.parse({});
    expect(isPluginEnabled('core-k3s', initial)).toBe(false);
    expect(isPluginEnabled('core-vigilante', initial)).toBe(false);

    const { state: enabledState, autoEnabledDependencies } = enablePluginWithDependencies(
      'core-vigilante',
      initial
    );
    expect(autoEnabledDependencies).toEqual(['core-k3s']);
    expect(isPluginEnabled('core-k3s', enabledState)).toBe(true);
    expect(isPluginEnabled('core-vigilante', enabledState)).toBe(true);
    expect(enabledState.k3s?.enabled).toBe(true);
    expect(enabledState.vigilante?.enabled).toBe(true);

    const { state: disabledK3sState, autoDisabledDependents } = disablePluginWithDependents(
      'core-k3s',
      enabledState
    );
    expect(autoDisabledDependents).toContain('core-vigilante');
    expect(isPluginEnabled('core-k3s', disabledK3sState)).toBe(false);
    expect(isPluginEnabled('core-vigilante', disabledK3sState)).toBe(false);
    expect(disabledK3sState.vigilante?.enabled).toBe(false);
  });

  it('compiles full Vigilante bundle', () => {
    const bundle = compileVigilanteBundle(baseState);
    expect(bundle.nftablesRuleset).toBeTruthy();
    expect(bundle.unboundOverrides).toBeTruthy();
    expect(bundle.k3sManifests).toBeTruthy();
    expect(bundle.configYaml).toBeTruthy();
  });

  it('performs bidirectional round-trip GitOps serialization via vigilante.yaml', () => {
    const yamlFiles = serializeDesiredStateToYamlFiles(baseState);
    expect(yamlFiles['vigilante.yaml']).toBeDefined();
    expect(yamlFiles['vigilante.yaml']).toContain('soc.axonwall.local');

    const merged = parseDesiredStateFromYamlFiles(yamlFiles);
    expect(merged.vigilante?.enabled).toBe(true);
    expect(merged.vigilante?.domain).toBe('soc.axonwall.local');
    expect(merged.vigilante?.modules.length).toBe(2);
  });

  it('registers core-vigilante plugin LDAP integration metadata', () => {
    const plugin = BUILTIN_PLUGINS.find((p) => p.id === 'core-vigilante');
    expect(plugin).toBeDefined();
    expect(plugin?.ldapIntegration).toBeDefined();
    expect(plugin?.ldapIntegration?.serviceAccountCn).toBe('svc-vigilante');
    expect(plugin?.ldapIntegration?.envPrefix).toBe('VIGILANTE_LDAP_');
    expect(plugin?.ldapIntegration?.inheritApplianceRoleGroups).toBe(true);
    expect(plugin?.ldapIntegration?.groups).toEqual([
      {
        cn: 'vigilante-admin',
        gidNumber: 10230,
        description: 'Vigilante SOC & SOAR Administrators',
        role: 'admin',
      },
      {
        cn: 'vigilante-operator',
        gidNumber: 10231,
        description: 'Vigilante SOC Analysts, Threat Hunters & Incident Responders',
        role: 'operator',
      },
      {
        cn: 'vigilante-readonly',
        gidNumber: 10232,
        description: 'Vigilante SOC Read-Only Auditors & Observers',
        role: 'readonly',
      },
    ]);
  });

  it('compiles K3s vigilante-ldap-sso ConfigMap, config.yaml ldap section, and ldapEnv', () => {
    const manifests = compileVigilanteK3sManifests(baseState);
    expect(manifests).toContain('name: vigilante-ldap-sso');
    expect(manifests).toContain('VIGILANTE_LDAP_URI: ldap://127.0.0.1:389');
    expect(manifests).toContain('VIGILANTE_LDAP_CONFIG_PATH: /etc/axonwall/vigilante/ldap.json');
    expect(manifests).toContain('VIGILANTE_LDAP_OPERATOR_GROUPS: axonwall-operator,vigilante-operator');

    const configYaml = compileVigilanteConfigYaml(baseState);
    expect(configYaml).toContain('ldap:');
    expect(configYaml).toContain('uri: ldap://127.0.0.1:389');
    expect(configYaml).toContain('configPath: /etc/axonwall/vigilante/ldap.json');
    expect(configYaml).toContain('defaultRole: viewer');

    const ldapEnv = compileVigilanteLdapEnv(baseState);
    expect(ldapEnv).toContain('VIGILANTE_LDAP_ENABLED=true');
    expect(ldapEnv).toContain('VIGILANTE_LDAP_CONFIG_PATH=/etc/axonwall/vigilante/ldap.json');
    expect(ldapEnv).toContain('VIGILANTE_LDAP_PLUGIN_CONFIG_PATH=/etc/axonwall/ldap-plugins/vigilante.json');

    const bundle = compileVigilanteBundle(baseState);
    expect(bundle.ldapEnv).toContain('VIGILANTE_LDAP_ENABLED=true');
  });
});
