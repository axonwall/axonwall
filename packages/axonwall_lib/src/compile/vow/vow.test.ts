import { describe, it, expect } from 'vitest';
import { DesiredStateSchema } from '../../schemas/index.js';
import {
  findPluginById,
  getPluginDependencies,
  getDependentPlugins,
  arePluginDependenciesMet,
  isPluginEnabled,
  enablePluginWithDependencies,
  disablePluginWithDependents,
} from '../../plugins/index.js';
import {
  VOW_APP_CATALOG,
  VOW_DEPLOYMENT_PRESETS,
  VOW_WAFFLE_BLUEPRINTS,
  VOW_PERMISSIONS,
  resolveVowAppDependencies,
  synthesizeFluxFromArgo,
  compileVowBundle,
  compileVowUnboundOverrides,
} from './index.js';

describe('Vigilant Octo Waffle (vigilant-octo-waffle) Plugin & K3s Dependency', () => {
  it('registers vigilant-octo-waffle in BUILTIN_PLUGINS with core-k3s dependency', () => {
    const manifest = findPluginById('vigilant-octo-waffle');
    expect(manifest).toBeDefined();
    expect(manifest?.name).toContain('Vigilant Octo Waffle');
    expect(manifest?.dependencies).toEqual(['core-k3s']);
    expect(getPluginDependencies('vigilant-octo-waffle')).toEqual(['core-k3s']);
    expect(getDependentPlugins('core-k3s').map((p) => p.id)).toContain('vigilant-octo-waffle');
  });

  it('requires core-k3s to be enabled before vigilant-octo-waffle is considered enabled', () => {
    const stateWithoutK3s = DesiredStateSchema.parse({
      capabilities: {
        firewallEnabled: true,
        nasEnabled: false,
        k3sEnabled: false,
        virtEnabled: false,
        vigilanteEnabled: false,
      },
      vow: {
        enabled: true,
      },
      plugins: [{ id: 'vigilant-octo-waffle', enabled: true }],
    });

    expect(arePluginDependenciesMet('vigilant-octo-waffle', stateWithoutK3s)).toEqual({
      met: false,
      missing: ['core-k3s'],
    });
    expect(isPluginEnabled('vigilant-octo-waffle', stateWithoutK3s)).toBe(false);

    const stateWithK3s = DesiredStateSchema.parse({
      capabilities: {
        firewallEnabled: true,
        nasEnabled: false,
        k3sEnabled: true,
        virtEnabled: false,
        vigilanteEnabled: false,
      },
      k3s: {
        enabled: true,
      },
      vow: {
        enabled: true,
      },
    });

    expect(arePluginDependenciesMet('vigilant-octo-waffle', stateWithK3s)).toEqual({
      met: true,
      missing: [],
    });
    expect(isPluginEnabled('vigilant-octo-waffle', stateWithK3s)).toBe(true);
  });

  it('automatically enables core-k3s when enabling vigilant-octo-waffle and disables VOW when core-k3s is disabled', () => {
    const initial = DesiredStateSchema.parse({});
    expect(isPluginEnabled('core-k3s', initial)).toBe(false);
    expect(isPluginEnabled('vigilant-octo-waffle', initial)).toBe(false);

    const { state: enabledState, autoEnabledDependencies } = enablePluginWithDependencies(
      'vigilant-octo-waffle',
      initial
    );
    expect(autoEnabledDependencies).toEqual(['core-k3s']);
    expect(isPluginEnabled('core-k3s', enabledState)).toBe(true);
    expect(isPluginEnabled('vigilant-octo-waffle', enabledState)).toBe(true);
    expect(enabledState.k3s?.enabled).toBe(true);
    expect(enabledState.vow?.enabled).toBe(true);

    const { state: disabledK3sState, autoDisabledDependents } = disablePluginWithDependents(
      'core-k3s',
      enabledState
    );
    expect(autoDisabledDependents).toEqual(['vigilant-octo-waffle']);
    expect(isPluginEnabled('core-k3s', disabledK3sState)).toBe(false);
    expect(isPluginEnabled('vigilant-octo-waffle', disabledK3sState)).toBe(false);
    expect(disabledK3sState.vow?.enabled).toBe(false);
  });

  it('resolves intra-catalog app dependencies automatically', () => {
    const res = resolveVowAppDependencies(['argocd', 'goharbor', 'nextcloud']);
    expect(res.autoAddedDependencies).toContain('kubegres');
    expect(res.autoAddedDependencies).toContain('openebs');
    expect(res.resolvedApps).toContain('kubegres');
    expect(res.resolvedApps).toContain('openebs');
    expect(res.resolvedApps).toContain('goharbor');
    expect(res.resolvedApps).toContain('nextcloud');
  });

  it('synthesizes FluxCD GitRepository + HelmRelease from ArgoCD Application YAML', () => {
    const argoSample = `
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: goharbor
  namespace: argocd
spec:
  source:
    repoURL: https://github.com/DeployCoop/vigilant-octo-waffle.git
    path: argo/goharbor
    helm:
      valuesObject:
        expose:
          tls:
            enabled: true
  destination:
    namespace: harbor
`;
    const fluxYaml = synthesizeFluxFromArgo(argoSample, 'goharbor', 'flux-system', {
      interval: '5m',
      branch: 'main',
    });
    expect(fluxYaml).toContain('kind: GitRepository');
    expect(fluxYaml).toContain('name: goharbor-repo');
    expect(fluxYaml).toContain('kind: HelmRelease');
    expect(fluxYaml).toContain('targetNamespace: harbor');
    expect(fluxYaml).toContain('chart: argo/goharbor');
  });

  it('compiles full VOW bundle when core-k3s is enabled and blocks when core-k3s is disabled', () => {
    const stateNoK3s = DesiredStateSchema.parse({
      vow: {
        enabled: true,
        cdRunner: 'both',
        domain: 'vow.axonwall.local',
        enabledApps: ['argocd', 'goharbor'],
      },
    });

    const blockedBundle = compileVowBundle(stateNoK3s);
    expect(blockedBundle.enabled).toBe(false);
    expect(blockedBundle.k3sDependencyMet).toBe(false);
    expect(blockedBundle.combinedK3sManifestsYaml).toContain('requires the Kubernetes (core-k3s) plugin');

    const { state: activeState } = enablePluginWithDependencies('vigilant-octo-waffle', stateNoK3s);
    activeState.interfaces = [
      {
        name: 'lan',
        device: 'eth1',
        role: 'lan',
        type: 'static',
        enabled: true,
        description: 'LAN',
        ipv4Address: '10.80.0.1/24',
        mtu: 1500,
      },
    ];

    const bundle = compileVowBundle(activeState);
    expect(bundle.enabled).toBe(true);
    expect(bundle.k3sDependencyMet).toBe(true);
    expect(bundle.autoAddedDependencies).toEqual(['kubegres']);
    expect(bundle.argoManifestsYaml).toContain('kind: Application');
    expect(bundle.fluxManifestsYaml).toContain('kind: GitRepository');
    expect(bundle.unboundOverrides).toContain('local-zone: "vow.axonwall.local." transparent');
    expect(bundle.unboundOverrides).toContain('harbor.vow.axonwall.local. IN A 10.80.0.1');
    expect(bundle.enablerEnv).toContain('export GOHARBOR_ENABLED=true');
    expect(bundle.enablerEnv).toContain('export KUBEGRES_ENABLED=true');
    expect(bundle.authzYaml).toContain('axonwall-admin');
    expect(VOW_APP_CATALOG.length).toBeGreaterThanOrEqual(35);
    expect(VOW_DEPLOYMENT_PRESETS.length).toBe(6);
    expect(VOW_WAFFLE_BLUEPRINTS.length).toBe(6);
    expect(VOW_PERMISSIONS.length).toBe(34);
    expect(compileVowUnboundOverrides(activeState)).toContain('argocd.vow.axonwall.local. IN A 10.80.0.1');
  });
});
