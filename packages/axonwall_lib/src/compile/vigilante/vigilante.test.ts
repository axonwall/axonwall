import { describe, it, expect } from 'vitest';
import {
  compileVigilanteNftables,
  compileVigilanteUnboundOverrides,
  compileVigilanteK3sManifests,
  compileVigilanteConfigYaml,
  compileVigilanteBundle,
} from './index.js';
import { DesiredStateSchema, type DesiredState } from '../../schemas/index.js';
import { serializeDesiredStateToYamlFiles, parseDesiredStateFromYamlFiles } from '../../yaml/index.js';

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
    expect(yaml).toContain('backend: sqlite');
    expect(yaml).toContain('autoBlockC2Ips: true');
    expect(yaml).toContain('cluster-admin-backup');
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
});
