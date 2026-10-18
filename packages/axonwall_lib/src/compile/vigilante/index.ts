import type { DesiredState, VigilanteConfig } from '../../schemas/index.js';
import { stringify as stringifyYaml } from 'yaml';

export interface CompiledVigilanteBundle {
  nftablesRuleset: string;
  unboundOverrides: string;
  k3sManifests: string;
  configYaml: string;
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
  const lanIface = state.interfaces.find((i) => i.name.toLowerCase() === 'lan');
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
 * Compile Vigilante configuration file for the engine runtime (/var/lib/axonwall/vigilante/config.yaml).
 */
export function compileVigilanteConfigYaml(state: DesiredState): string {
  const vigilante = state.vigilante;
  const config = {
    theme: {
      name: 'cyberpunk',
    },
    defaults: {
      domain: vigilante?.domain || 'vigilante.local',
      clusterName: 'axonwall-k3s',
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
  };

  return stringifyYaml(config);
}

/**
 * Compile full Vigilante bundle.
 */
export function compileVigilanteBundle(state: DesiredState): CompiledVigilanteBundle {
  return {
    nftablesRuleset: compileVigilanteNftables(state),
    unboundOverrides: compileVigilanteUnboundOverrides(state),
    k3sManifests: compileVigilanteK3sManifests(state),
    configYaml: compileVigilanteConfigYaml(state),
  };
}
