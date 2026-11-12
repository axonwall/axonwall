import { describe, it, expect } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { DesiredStateSchema } from '../../schemas/index.js';
import { compileK3s } from './index.js';

describe('compileK3s (standard & barebones-storage profiles, server & agent roles)', () => {
  it('maintains full backward compatibility for standard server profile', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [
        { name: 'lan', device: 'eth1', enabled: true, ipv4Address: '10.0.10.1/24' },
      ],
      k3s: {
        enabled: true,
      },
    });

    expect(state.k3s?.profile).toBe('standard');
    expect(state.k3s?.role).toBe('server');
    expect(state.k3s?.zfsArcMaxMb).toBe(0);
    expect(state.k3s?.disableServiceLb).toBe(false);
    expect(state.k3s?.disableLocalStorage).toBe(false);
    expect(state.k3s?.disableMetricsServer).toBe(false);

    const compiled = compileK3s(state);
    expect(compiled.k3sConfigYaml).toContain('write-kubeconfig-mode: "0640"');
    expect(compiled.k3sConfigYaml).toContain('cluster-cidr: "10.42.0.0/16"');
    expect(compiled.k3sConfigYaml).toContain('service-cidr: "10.43.0.0/16"');
    expect(compiled.k3sConfigYaml).toContain('flannel-backend: "wireguard-native"');
    expect(compiled.k3sConfigYaml).toContain('flannel-iface: "eth1"');
    expect(compiled.k3sConfigYaml).toContain('node-ip: "10.0.10.1"');
    expect(compiled.k3sConfigYaml).toContain('cluster-init: true');
    expect(compiled.k3sConfigYaml).not.toContain('disable:');
    expect(compiled.k3sConfigYaml).toContain('feature-gates=UserNamespacesSupport=true');
    expect(compiled.k3sConfigYaml).not.toContain('eviction-hard=');

    expect(compiled.openEbsManifestYaml).toContain('name: axonwall-zfs-local');
    expect(compiled.openEbsManifestYaml).toContain('poolname: "tank"');
    expect(compiled.openEbsManifestYaml).toContain('name: axonwall-replicated-ha');
    expect(compiled.openEbsManifestYaml).toContain('provisioner: io.openebs.csi-mayastor');

    const docs = compiled.openEbsManifestYaml
      .split(/^---$/m)
      .map((d) => parseYaml(d))
      .filter(Boolean);
    const zfsSc = docs.find((d: any) => d.metadata?.name === 'axonwall-zfs-local');
    const repSc = docs.find((d: any) => d.metadata?.name === 'axonwall-replicated-ha');
    expect(zfsSc.metadata.annotations['storageclass.kubernetes.io/is-default-class']).toBe('false');
    expect(repSc.metadata.annotations['storageclass.kubernetes.io/is-default-class']).toBe('true');
  });

  it('compiles barebones-storage standalone server profile (SQLite, disabled heavy addons, eviction-hard, ZFS-LocalPV default SC)', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [
        { name: 'lan', device: 'enp1s0', enabled: true, ipv4Address: '192.168.50.10/24' },
      ],
      k3s: {
        enabled: true,
        profile: 'barebones-storage',
        zfsArcMaxMb: 4096,
      },
    });

    expect(state.k3s?.profile).toBe('barebones-storage');
    expect(state.k3s?.role).toBe('server');
    expect(state.k3s?.zfsArcMaxMb).toBe(4096);
    expect(state.k3s?.disableServiceLb).toBe(false);
    expect(state.k3s?.disableLocalStorage).toBe(false);
    expect(state.k3s?.disableMetricsServer).toBe(false);

    const compiled = compileK3s(state);
    const cfg = parseYaml(compiled.k3sConfigYaml) as Record<string, any>;

    // Standalone barebones-storage uses embedded SQLite — must NOT emit cluster-init
    expect(compiled.k3sConfigYaml).not.toContain('cluster-init');
    expect(cfg['cluster-init']).toBeUndefined();

    // Disables all 4 heavy bundled addons in deterministic order
    expect(cfg.disable).toEqual(['traefik', 'servicelb', 'local-storage', 'metrics-server']);

    // Emits barebones kubelet eviction thresholds alongside userns support
    expect(cfg['kubelet-arg']).toContain('eviction-hard=memory.available<200Mi,nodefs.available<5%');
    expect(cfg['kubelet-arg']).toContain('feature-gates=UserNamespacesSupport=true');

    // OpenEBS StorageClasses: axonwall-zfs-local is default with pool tank/k8s, Mayastor omitted
    expect(compiled.openEbsManifestYaml).toContain('name: axonwall-zfs-local');
    expect(compiled.openEbsManifestYaml).toContain('poolname: "tank/k8s"');
    expect(compiled.openEbsManifestYaml).not.toContain('axonwall-replicated-ha');
    expect(compiled.openEbsManifestYaml).not.toContain('io.openebs.csi-mayastor');

    const docs = compiled.openEbsManifestYaml
      .split(/^---$/m)
      .map((d) => parseYaml(d))
      .filter(Boolean);
    const zfsSc = docs.find((d: any) => d.metadata?.name === 'axonwall-zfs-local');
    expect(zfsSc.metadata.annotations['storageclass.kubernetes.io/is-default-class']).toBe('true');
  });

  it('allows explicit datastore: etcd and custom zfsLocalPvPool / kubeletEvictionHard on barebones-storage server', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [
        { name: 'lan', device: 'eth0', enabled: true, ipv4Address: '10.20.30.40/24' },
      ],
      k3s: {
        enabled: true,
        profile: 'barebones-storage',
        datastore: 'etcd',
        kubeletEvictionHard: 'memory.available<512Mi,nodefs.available<10%',
        openEbs: {
          enabled: true,
          zfsLocalPvEnabled: true,
          zfsLocalPvPool: 'fastpool/k3s',
          replicatedStorageEnabled: false,
        },
      },
    });

    const compiled = compileK3s(state);
    const cfg = parseYaml(compiled.k3sConfigYaml) as Record<string, any>;

    expect(cfg['cluster-init']).toBe(true);
    expect(cfg['kubelet-arg']).toContain('eviction-hard=memory.available<512Mi,nodefs.available<10%');
    expect(compiled.openEbsManifestYaml).toContain('poolname: "fastpool/k3s"');
    expect(compiled.openEbsManifestYaml).not.toContain('axonwall-replicated-ha');
  });

  it('compiles barebones-storage agent role without server-only flags or auto-deploy manifests', () => {
    const state = DesiredStateSchema.parse({
      interfaces: [
        { name: 'lan', device: 'eth0', enabled: true, ipv4Address: '192.168.50.11/24' },
      ],
      k3s: {
        enabled: true,
        profile: 'barebones-storage',
        role: 'agent',
        serverUrl: 'https://192.168.50.10:6443',
      },
    });

    const compiledWithFile = compileK3s(state);
    const cfgFile = parseYaml(compiledWithFile.k3sConfigYaml) as Record<string, any>;

    expect(cfgFile.server).toBe('https://192.168.50.10:6443');
    expect(cfgFile['token-file']).toBe('/var/lib/axonwall/k3s-join.token');
    expect(cfgFile['flannel-iface']).toBe('eth0');
    expect(cfgFile['node-ip']).toBe('192.168.50.11');
    expect(cfgFile['kubelet-arg']).toContain('eviction-hard=memory.available<200Mi,nodefs.available<5%');

    // Must NOT contain server-only keys
    for (const forbidden of [
      'cluster-init',
      'cluster-cidr',
      'service-cidr',
      'flannel-backend',
      'disable',
      'tls-san',
      'write-kubeconfig-mode',
      'write-kubeconfig-group',
    ]) {
      expect(cfgFile[forbidden]).toBeUndefined();
      expect(compiledWithFile.k3sConfigYaml).not.toContain(`${forbidden}:`);
    }

    // Agents do not run server auto-deploy manifests
    expect(compiledWithFile.openEbsManifestYaml).toBe('');
    expect(compiledWithFile.workloadsManifestYaml).toBe('');

    // Explicit joinToken overrides token-file
    const compiledWithToken = compileK3s(state, 'K10agentsecret::server:12345');
    const cfgToken = parseYaml(compiledWithToken.k3sConfigYaml) as Record<string, any>;
    expect(cfgToken.token).toBe('K10agentsecret::server:12345');
    expect(cfgToken['token-file']).toBeUndefined();
  });
});
