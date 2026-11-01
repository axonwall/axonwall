import { inferInterfaceRole, type DesiredState, type VigilanteConfig } from '../../schemas/index.js';
import { isPluginEnabled } from '../../plugins/index.js';
import { stringify as stringifyYaml } from 'yaml';

export interface CompiledVigilanteBundle {
  k3sDependencyMet: boolean;
  nftablesRuleset: string;
  unboundOverrides: string;
  k3sManifests: string;
  configYaml: string;
  ldapEnv: string;
}

/**
 * Compile nftables dynamic sets and early drop rules for SOAR Active Containment.
 * Offending IPs added to @vigilante_soar_blocklist are blocked at the wire.
 */
export function compileVigilanteNftables(state: DesiredState): string {
  const vigilante = state.vigilante;
  if (!vigilante?.enabled) {
    return '# Vigilante SOAR nftables integration is disabled\n';
  }

  const lines: string[] = [
    '# =============================================================================',
    '# Axonwall / Vigilante SOAR Active Containment nftables Integration',
    '# =============================================================================',
    'table inet axonwall {',
    '  set vigilante_soar_blocklist_v4 {',
    '    type ipv4_addr',
    '    flags interval, timeout',
    '    comment "Vigilante SOAR dynamic C2 / honeytoken attacker blocklist"',
    '  }',
    '',
    '  set vigilante_soar_blocklist_v6 {',
    '    type ipv6_addr',
    '    flags interval, timeout',
    '    comment "Vigilante SOAR dynamic C2 / honeytoken IPv6 attacker blocklist"',
    '  }',
    '',
    '  chain vigilante_soar_filter {',
    '    type filter hook prerouting priority -15; policy accept;',
    '    ip saddr @vigilante_soar_blocklist_v4 counter drop',
    '    ip daddr @vigilante_soar_blocklist_v4 counter drop',
    '    ip6 saddr @vigilante_soar_blocklist_v6 counter drop',
    '    ip6 daddr @vigilante_soar_blocklist_v6 counter drop',
    '  }',
    '}',
    '',
  ];

  return lines.join('\n');
}

/**
 * Compile Unbound DNS local-zone and local-data overrides for Vigilante module endpoints.
 */
export function compileVigilanteUnboundOverrides(state: DesiredState): string {
  const vigilante = state.vigilante;
  if (!vigilante?.enabled) {
    return '# Vigilante DNS integration disabled\n';
  }

  const domain = vigilante.domain || 'vigilante.local';
  const lanIface =
    state.interfaces.find((i) => i.enabled && i.name.toLowerCase() === 'lan' && i.ipv4Address) ||
    state.interfaces.find((i) => i.enabled && inferInterfaceRole(i) === 'lan' && i.ipv4Address) ||
    state.interfaces.find((i) => i.name.toLowerCase() === 'lan');
  const lanIp = lanIface?.ipv4Address?.split('/')[0] || '192.168.1.1';

  const defaultSubdomains: Record<string, string> = {
    'vigil-soc': 'vigil',
    'vigil-local': 'local',
    opensearch: 'siem',
    wazuh: 'wazuh',
    bloodhound: 'bloodhound',
    zap: 'zap',
    flamingo: 'flamingo',
    kctf: 'ctf',
    openvas: 'openvas',
  };

  const lines: string[] = [
    `# Vigilante Local DNS Ingress Zone (${domain})`,
    `server:`,
    `  local-zone: "${domain}." transparent`,
  ];

  for (const mod of vigilante.modules ?? []) {
    if (!mod.enabled) continue;
    const sub = defaultSubdomains[mod.id] || mod.id;
    const host = mod.ingressHostname || `${sub}.${domain}`;
    lines.push(`  local-data: "${host}. IN A ${lanIp}"`);
  }

  lines.push('');
  return lines.join('\n');
}

/**
 * Compile Kubernetes manifests for Vigilante modules onto Axonwall K3s.
 */
export function compileVigilanteK3sManifests(state: DesiredState): string {
  const vigilante = state.vigilante;
  if (!vigilante?.enabled) {
    return '# Vigilante K3s integration disabled\n';
  }

  const docs: string[] = [];

  // 1. Core Namespace
  docs.push(
    stringifyYaml({
      apiVersion: 'v1',
      kind: 'Namespace',
      metadata: {
        name: 'vigilante-soc',
        labels: {
          'app.kubernetes.io/name': 'vigilante-soc',
          'app.kubernetes.io/managed-by': 'axonwall',
          'pod-security.kubernetes.io/enforce': 'privileged',
        },
      },
    }).trim()
  );

  // 2. Canary ServiceAccounts (Deception Mesh)
  if (vigilante.deception?.enabled) {
    for (const sa of vigilante.deception.canaryServiceAccounts ?? []) {
      docs.push(
        stringifyYaml({
          apiVersion: 'v1',
          kind: 'ServiceAccount',
          metadata: {
            name: sa,
            namespace: 'vigilante-soc',
            labels: {
              'vigilante.deception/canary': 'true',
              'app.kubernetes.io/managed-by': 'vigilante-deception',
            },
            annotations: {
              'vigilante.io/canary-trap': 'true',
              'vigilante.io/trip-action': 'isolate-pod',
            },
          },
        }).trim()
      );
    }
  }

  // 2.5. Local OpenLDAP SSO ConfigMap for K3s SOC Modules (Vigil-SOC, OpenSearch, Wazuh)
  const ldapEnabled = vigilante.ldapAuth?.enabled ?? true;
  const syncModuleSso = vigilante.ldapAuth?.syncModuleSso ?? true;
  if (ldapEnabled && syncModuleSso) {
    docs.push(
      stringifyYaml({
        apiVersion: 'v1',
        kind: 'ConfigMap',
        metadata: {
          name: 'vigilante-ldap-sso',
          namespace: 'vigilante-soc',
          labels: {
            'app.kubernetes.io/name': 'vigilante-ldap-sso',
            'app.kubernetes.io/part-of': 'vigilante',
            'app.kubernetes.io/managed-by': 'axonwall',
          },
        },
        data: {
          VIGILANTE_LDAP_ENABLED: 'true',
          VIGILANTE_LDAP_URI: 'ldap://127.0.0.1:389',
          VIGILANTE_LDAP_CONFIG_PATH: '/etc/axonwall/vigilante/ldap.json',
          VIGILANTE_LDAP_DEFAULT_ROLE: vigilante.ldapAuth?.defaultRole || 'viewer',
          VIGILANTE_LDAP_OWNER_GROUPS: 'axonwall-admin',
          VIGILANTE_LDAP_ADMIN_GROUPS: 'vigilante-admin',
          VIGILANTE_LDAP_OPERATOR_GROUPS: 'axonwall-operator,vigilante-operator',
          VIGILANTE_LDAP_VIEWER_GROUPS: 'axonwall-readonly,vigilante-readonly',
          VIGILANTE_CLUSTER_PROVIDER: 'k3s',
          VIGILANTE_CLUSTER_NAME: 'axonwall-k3s',
          KUBECONFIG: '/etc/rancher/k3s/k3s.yaml',
        },
      }).trim()
    );
  }

  // 3. Module Storage and HelmChart CRDs (K3s native helm controller)
  for (const mod of vigilante.modules ?? []) {
    if (!mod.enabled) continue;
    const ns = mod.namespace || 'vigilante-soc';
    const sc = mod.storageClass || 'axonwall-zfs-local';

    // PVC for stateful modules
    if (['opensearch', 'wazuh', 'bloodhound', 'vigil-soc', 'openvas'].includes(mod.id)) {
      docs.push(
        stringifyYaml({
          apiVersion: 'v1',
          kind: 'PersistentVolumeClaim',
          metadata: {
            name: `${mod.id}-data-pvc`,
            namespace: ns,
            labels: {
              'app.kubernetes.io/name': mod.id,
              'app.kubernetes.io/part-of': 'vigilante',
            },
          },
          spec: {
            accessModes: ['ReadWriteOnce'],
            storageClassName: sc,
            resources: {
              requests: {
                storage: `${mod.storageSizeGb || 10}Gi`,
              },
            },
          },
        }).trim()
      );
    }

    // K3s HelmChart CRD
    docs.push(
      stringifyYaml({
        apiVersion: 'helm.cattle.io/v1',
        kind: 'HelmChart',
        metadata: {
          name: `vigilante-${mod.id}`,
          namespace: 'kube-system',
        },
        spec: {
          chart: mod.id,
          repo: 'https://charts.vigilante.local',
          targetNamespace: ns,
          valuesContent: mod.customValuesYaml || '',
        },
      }).trim()
    );
  }

  return docs.join('\n---\n') + '\n';
}

/**
 * Compile Vigilante environment variables for OpenLDAP Directory SSO (/etc/axonwall/vigilante/ldap.env).
 */
export function compileVigilanteLdapEnv(state: DesiredState): string {
  const vigilante = state.vigilante;
  const ldapAuth = vigilante?.ldapAuth;
  const enabled = ldapAuth?.enabled ?? true;
  const autoProvision = ldapAuth?.autoProvisionPrincipals ?? true;
  const allowBreakGlass = ldapAuth?.allowLocalBreakGlass ?? true;
  const defaultRole = ldapAuth?.defaultRole || 'viewer';
  const syncModuleSso = ldapAuth?.syncModuleSso ?? true;

  return [
    '# Managed by Axonwall Vigilante OpenLDAP Compiler',
    `VIGILANTE_LDAP_ENABLED=${enabled ? 'true' : 'false'}`,
    'VIGILANTE_LDAP_CONFIG_PATH=/etc/axonwall/vigilante/ldap.json',
    'VIGILANTE_LDAP_PLUGIN_CONFIG_PATH=/etc/axonwall/ldap-plugins/vigilante.json',
    `VIGILANTE_LDAP_AUTO_PROVISION=${autoProvision ? 'true' : 'false'}`,
    `VIGILANTE_LDAP_ALLOW_BREAK_GLASS=${allowBreakGlass ? 'true' : 'false'}`,
    `VIGILANTE_LDAP_DEFAULT_ROLE=${defaultRole}`,
    `VIGILANTE_LDAP_SYNC_MODULE_SSO=${syncModuleSso ? 'true' : 'false'}`,
    'VIGILANTE_LDAP_OWNER_GROUPS=axonwall-admin',
    'VIGILANTE_LDAP_ADMIN_GROUPS=vigilante-admin',
    'VIGILANTE_LDAP_OPERATOR_GROUPS=axonwall-operator,vigilante-operator',
    'VIGILANTE_LDAP_VIEWER_GROUPS=axonwall-readonly,vigilante-readonly',
    'KUBECONFIG=/etc/rancher/k3s/k3s.yaml',
    'VIGILANTE_CLUSTER_PROVIDER=k3s',
    'VIGILANTE_CLUSTER_NAME=axonwall-k3s',
    'VIGILANTE_STORAGE_CLASS=axonwall-zfs-local',
    '',
  ].join('\n');
}

/**
 * Compile Vigilante configuration file for the engine runtime (/var/lib/axonwall/vigilante/config.yaml).
 */
export function compileVigilanteConfigYaml(state: DesiredState): string {
  const vigilante = state.vigilante;
  const defaultStorageClass = state.k3s?.openEbs?.replicatedStorageEnabled
    ? 'axonwall-replicated-ha'
    : 'axonwall-zfs-local';
  const config = {
    theme: {
      name: 'cyberpunk',
    },
    defaults: {
      domain: vigilante?.domain || 'vigilante.local',
      clusterName: 'axonwall-k3s',
      clusterProvider: 'k3s',
      kubeconfig: '/etc/rancher/k3s/k3s.yaml',
      storageClass: defaultStorageClass,
      ip: '127.0.0.1',
      valuesDir: '/var/lib/axonwall/vigilante/values',
    },
    hostr: {
      enabled: false, // In Axonwall, Unbound DNS is compiled natively
    },
    gpg: {
      enabled: Boolean(vigilante?.evidenceVault?.gpgEnabled),
      keyId: vigilante?.evidenceVault?.gpgKeyId || '',
      autoSign: true,
      detached: true,
    },
    datalake: {
      backend: vigilante?.evidenceVault?.dataLakeBackend || 'sqlite',
    },
    soar: vigilante?.soar || {
      autoBlockC2Ips: true,
      autoIsolateCompromisedPods: true,
      autoFreezeRansomwarePods: true,
      ransomwareEntropyDeltaThreshold: 2.0,
      warRoomQuorumThreshold: 0.75,
      blocklistTimeoutSeconds: 86400,
    },
    deception: vigilante?.deception || {
      enabled: true,
      canaryServiceAccounts: ['cluster-admin-backup', 'vault-sync-sa'],
      honeytokens: ['aws-sts', 'kubeconfig'],
      decoyServices: [],
      ransomwareCanaryDirs: ['/mnt/tank/shares'],
    },
    federation: vigilante?.federation || {
      enabled: false,
      nodeName: 'axonwall-soc-primary',
      peers: [],
      autoIngestPeerBlocks: true,
    },
    ldap: {
      enabled: vigilante?.ldapAuth?.enabled ?? true,
      configPath: '/etc/axonwall/vigilante/ldap.json',
      pluginConfigPath: '/etc/axonwall/ldap-plugins/vigilante.json',
      uri: 'ldap://127.0.0.1:389',
      autoProvisionPrincipals: vigilante?.ldapAuth?.autoProvisionPrincipals ?? true,
      allowLocalBreakGlass: vigilante?.ldapAuth?.allowLocalBreakGlass ?? true,
      defaultRole: vigilante?.ldapAuth?.defaultRole || 'viewer',
      syncModuleSso: vigilante?.ldapAuth?.syncModuleSso ?? true,
      roleMapping: {
        ownerGroups: ['axonwall-admin'],
        adminGroups: ['vigilante-admin'],
        operatorGroups: ['axonwall-operator', 'vigilante-operator'],
        viewerGroups: ['axonwall-readonly', 'vigilante-readonly'],
      },
    },
  };

  return stringifyYaml(config);
}

/**
 * Compile full Vigilante bundle.
 */
export function compileVigilanteBundle(state: DesiredState): CompiledVigilanteBundle {
  return {
    k3sDependencyMet: isPluginEnabled('core-k3s', state),
    nftablesRuleset: compileVigilanteNftables(state),
    unboundOverrides: compileVigilanteUnboundOverrides(state),
    k3sManifests: compileVigilanteK3sManifests(state),
    configYaml: compileVigilanteConfigYaml(state),
    ldapEnv: compileVigilanteLdapEnv(state),
  };
}
