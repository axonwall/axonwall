'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Boxes,
  Download,
  Trash2,
  CheckCircle2,
  Shield,
  Flame,
  Database,
  Cpu,
  Search,
  Power,
  Loader2,
  RefreshCw,
  Terminal,
  Settings,
  AlertTriangle,
  FileText,
  X,
} from 'lucide-react';
import {
  BUILTIN_PLUGINS,
  PLUGIN_STARTER_PACKS,
  findPluginById,
  getDependentPlugins,
  getStarterPackPluginIdsWithDeps,
  isPluginEnabled,
  enablePluginWithDependencies,
  disablePluginWithDependents,
  enableStarterPack,
  arePluginDependenciesMet,
  type PluginManifest,
} from '@axonwall/lib/plugins';
import { getCurrentDesiredState } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import { getExtensionPlugins, executePluginAction, type ExtensionPluginLiveStatus } from '@/server/plugins';
import {
  type DesiredState,
  VigilanteConfigSchema,
} from '@axonwall/lib/schemas';

type PluginFilterGroup =
  | 'all'
  | 'active'
  | 'installed'
  | 'security'
  | 'routing'
  | 'identity'
  | 'observability'
  | 'cli'
  | 'k3s';

const PLUGIN_FILTER_PILLS: Array<{ id: PluginFilterGroup; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'active', label: 'Active' },
  { id: 'installed', label: 'Installed' },
  { id: 'security', label: 'Security & IDS' },
  { id: 'routing', label: 'Routing & VPN' },
  { id: 'identity', label: 'Identity & HA' },
  { id: 'observability', label: 'AI & Observability' },
  { id: 'cli', label: 'CLI & Docs' },
  { id: 'k3s', label: 'K3s & Fabric' },
];

const PLUGIN_GROUP_MAP: Record<string, Exclude<PluginFilterGroup, 'all' | 'active' | 'installed'>> = {
  'suricata-ids': 'security',
  'crowdsec-bouncer': 'security',
  'tls-decryption': 'security',
  'captive-portal': 'security',
  'identity-aware-proxy': 'security',
  'host-malware-rootkit': 'security',
  'ebpf-threat-harvester': 'security',
  'firewall-importer': 'security',
  'etckeeper-audit': 'security',
  'frr-routing': 'routing',
  openvpn: 'routing',
  'ipsec-strongswan': 'routing',
  headscale: 'routing',
  tailscale: 'routing',
  rosenpass: 'routing',
  haproxy: 'routing',
  'directory-ldap': 'identity',
  'enterprise-sso': 'identity',
  freeradius: 'identity',
  'high-availability': 'identity',
  'fleet-controller': 'identity',
  'nut-ups': 'identity',
  'ai-copilot': 'observability',
  'mcp-ai-control': 'observability',
  'coroot-ebpf-apm': 'observability',
  'netflow-collector': 'observability',
  ntopng: 'observability',
  snmp: 'observability',
  netbox: 'observability',
  librenms: 'observability',
  'topology-studio': 'observability',
  'packet-diagnostics': 'observability',
  'cli-workstation': 'cli',
  'cli-emacs': 'cli',
  'cli-emacs-doom': 'cli',
  'cli-emacs-spacemacs': 'cli',
  'cli-diagnostics-nastymap': 'cli',
  'web-terminal': 'cli',
  'docs-portal': 'cli',
  'custom-kernel-studio': 'cli',
  'vigilant-octo-waffle': 'k3s',
  eluvix: 'k3s',
};

function getPluginGroup(plugin: PluginManifest): Exclude<PluginFilterGroup, 'all' | 'active' | 'installed'> {
  if (PLUGIN_GROUP_MAP[plugin.id]) return PLUGIN_GROUP_MAP[plugin.id];
  if (plugin.dependencies?.includes('core-k3s')) return 'k3s';
  return 'observability';
}

interface PendingConfirmAction {
  kind: 'pack' | 'disable-role' | 'disable-extension' | 'uninstall';
  targetId: string;
  title: string;
  description: string;
  affectedPlugins: string[];
  osPackages: string[];
}

export default function PluginManagerPage() {
  const { applyState, refreshFingerprint } = useDesiredStateApply();
  const [state, setState] = useState<DesiredState | null>(null);
  const [savingRole, setSavingRole] = useState<string | null>(null);
  const [packLoading, setPackLoading] = useState<string | null>(null);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; text: string; output?: string } | null>(null);
  const [activeOutputModal, setActiveOutputModal] = useState<{ title: string; output: string } | null>(null);

  const [livePlugins, setLivePlugins] = useState<Record<string, ExtensionPluginLiveStatus>>({});
  const [osFamily, setOsFamily] = useState<'alpine' | 'debian' | 'arch'>('debian');
  const [pluginActionLoading, setPluginActionLoading] = useState<string | null>(null);

  const [selectedPlugin, setSelectedPlugin] = useState<PluginManifest | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedGroup, setSelectedGroup] = useState<PluginFilterGroup>('all');
  const [pendingConfirm, setPendingConfirm] = useState<PendingConfirmAction | null>(null);

  const [livePluginsError, setLivePluginsError] = useState<string | null>(null);

  const refreshLivePlugins = () => {
    getExtensionPlugins()
      .then((res) => {
        if (res && res.plugins) {
          const map: Record<string, ExtensionPluginLiveStatus> = {};
          for (const p of res.plugins) {
            map[p.id] = p;
          }
          setLivePlugins(map);
          setOsFamily(res.osFamily);
          setLivePluginsError(null);
        }
      })
      .catch((err: any) => {
        // C25: the server now throws a distinct daemon-unavailable
        // error instead of returning an empty list. Keep the previous
        // live list and banner the unknown state.
        setLivePluginsError(err?.message || 'Live plugin status unavailable.');
      });
  };

  useEffect(() => {
    getCurrentDesiredState()
      .then((s) => setState(s))
      .catch(() => {});
    refreshLivePlugins();
  }, []);

  const coreRolePlugins = BUILTIN_PLUGINS.filter((p) => p.category === 'core_role');
  const extensionPlugins = BUILTIN_PLUGINS.filter((p) => p.category !== 'core_role');

  const isCoreRoleEnabled = (id: string): boolean => {
    if (!state) return id === 'core-firewall';
    if (id === 'core-firewall') return state.capabilities?.firewallEnabled !== false;
    if (id === 'core-nas') return Boolean(state.capabilities?.nasEnabled ?? state.nas?.enabled);
    if (id === 'core-k3s') return Boolean(state.capabilities?.k3sEnabled ?? state.k3s?.enabled);
    if (id === 'core-virt') return Boolean(state.capabilities?.virtEnabled ?? state.virt?.enabled);
    if (id === 'core-vigilante') return Boolean(state.capabilities?.vigilanteEnabled ?? state.vigilante?.enabled);
    return false;
  };

  const upsertPluginEntry = (target: DesiredState, pluginId: string, enabled: boolean) => {
    const plugins = target.plugins ? [...target.plugins] : [];
    const idx = plugins.findIndex((p) => p.id === pluginId);
    if (idx >= 0) {
      plugins[idx] = { ...plugins[idx], id: pluginId, enabled };
    } else {
      plugins.push({ id: pluginId, enabled });
    }
    target.plugins = plugins;
  };

  const toggleCoreRole = async (id: string) => {
    if (!state) return;
    setSavingRole(id);
    setStatusBanner(null);

    try {
      const next = structuredClone(state);
      const currentFw = next.capabilities?.firewallEnabled !== false;
      const currentNas = Boolean(next.capabilities?.nasEnabled ?? next.nas?.enabled);
      const currentK3s = Boolean(next.capabilities?.k3sEnabled ?? next.k3s?.enabled);
      const currentVirt = Boolean(next.capabilities?.virtEnabled ?? next.virt?.enabled);
      const currentVigilante = Boolean(next.capabilities?.vigilanteEnabled ?? next.vigilante?.enabled);

      const nextCaps = {
        firewallEnabled: id === 'core-firewall' ? !currentFw : currentFw,
        nasEnabled: id === 'core-nas' ? !currentNas : currentNas,
        k3sEnabled: id === 'core-k3s' ? !currentK3s : currentK3s,
        virtEnabled: id === 'core-virt' ? !currentVirt : currentVirt,
        vigilanteEnabled: id === 'core-vigilante' ? !currentVigilante : currentVigilante,
      };
      next.capabilities = nextCaps;

      if (id === 'core-nas') {
        next.nas = next.nas || {
          enabled: nextCaps.nasEnabled,
          workgroup: 'WORKGROUP',
          serverString: 'Axonwall Enterprise ZFS NAS',
          pools: [],
          datasets: [],
          snapshotPolicies: [],
          smbShares: [],
          nfsExports: [],
          iscsiTargets: [],
        };
        next.nas.enabled = nextCaps.nasEnabled;
      }

      let autoDisabledNote = '';
      if (id === 'core-k3s') {
        next.k3s = next.k3s || {
          enabled: nextCaps.k3sEnabled,
          clusterCidr: '10.42.0.0/16',
          serviceCidr: '10.43.0.0/16',
          nodeIpInterface: 'lan',
          flannelBackend: 'wireguard-native',
          disableTraefik: false,
          autoJoinHaPeer: true,
          openEbs: {
            enabled: true,
            zfsLocalPvEnabled: true,
            zfsLocalPvPool: 'tank',
            replicatedStorageEnabled: true,
            defaultReplicaCount: 2,
            replicatedBackingPool: 'tank/openebs-replicated',
          },
          enableUserNamespaces: false,
          bpfTokenProfiles: [],
          workloads: [],
        };
        next.k3s.enabled = nextCaps.k3sEnabled;
        if (!nextCaps.k3sEnabled) {
          const depRes = disablePluginWithDependents('core-k3s', next);
          Object.assign(next, depRes.state);
          if (depRes.autoDisabledDependents.length > 0) {
            autoDisabledNote = ` • Auto-disabled dependent plugins: ${depRes.autoDisabledDependents.join(', ')}`;
          }
        }
      }

      if (id === 'core-virt') {
        next.virt = next.virt || {
          enabled: nextCaps.virtEnabled,
          defaultPool: 'tank',
          isoPool: 'tank',
          vms: [],
          containers: [],
          isos: [],
          pciDevices: [],
          backupJobs: [],
          vxlanZones: [],
        };
        next.virt.enabled = nextCaps.virtEnabled;
      }

      if (id === 'core-vigilante') {
        if (nextCaps.vigilanteEnabled) {
          const depRes = enablePluginWithDependencies('core-vigilante', next);
          Object.assign(next, depRes.state);
          if (depRes.autoEnabledDependencies.length > 0) {
            autoDisabledNote = ` • Auto-enabled required dependency: ${depRes.autoEnabledDependencies.join(', ')}`;
          }
        } else {
          const depRes = disablePluginWithDependents('core-vigilante', next);
          Object.assign(next, depRes.state);
        }
      }

      const roleEnabledAfter =
        id === 'core-firewall'
          ? nextCaps.firewallEnabled
          : id === 'core-nas'
            ? nextCaps.nasEnabled
            : id === 'core-k3s'
              ? nextCaps.k3sEnabled
              : id === 'core-virt'
                ? nextCaps.virtEnabled
                : nextCaps.vigilanteEnabled;
      upsertPluginEntry(next, id, roleEnabledAfter);

      const isEnablingRole =
        (id === 'core-firewall' && !currentFw && nextCaps.firewallEnabled) ||
        (id === 'core-nas' && !currentNas && nextCaps.nasEnabled) ||
        (id === 'core-k3s' && !currentK3s && nextCaps.k3sEnabled) ||
        (id === 'core-virt' && !currentVirt && nextCaps.virtEnabled) ||
        (id === 'core-vigilante' && !currentVigilante && nextCaps.vigilanteEnabled);

      let hostMutated = false;
      if (isEnablingRole) {
        if (id === 'core-vigilante' && !currentK3s) {
          upsertPluginEntry(next, 'core-k3s', true);
          const k3sInstallRes = await executePluginAction('core-k3s', 'install');
          if (!k3sInstallRes.success) {
            setStatusBanner({
              type: 'error',
              text: `Failed to install required core-k3s dependency: ${k3sInstallRes.message}`,
              output: k3sInstallRes.output,
            });
            return;
          }
          hostMutated = true;
        }
        const installRes = await executePluginAction(id, 'install');
        if (!installRes.success) {
          setStatusBanner({
            type: 'error',
            text: `Failed to install/enable ${id}: ${installRes.message}`,
            output: installRes.output,
          });
          return;
        }
        hostMutated = true;
      } else {
        const disableRes = await executePluginAction(id, 'disable');
        if (!disableRes.success) {
          setStatusBanner({
            type: 'error',
            text: `Failed to disable ${id}: ${disableRes.message}`,
            output: disableRes.output,
          });
          return;
        }
        hostMutated = true;
      }

      let res: { message: string };
      try {
        res = await applyState(next);
      } catch (applyErr: any) {
        refreshLivePlugins();
        throw new Error(
          hostMutated
            ? `Host plugin action ran for ${id}, but DesiredState apply failed (refresh status to inspect host state): ${applyErr?.message || applyErr}`
            : applyErr?.message || 'Failed to update appliance role'
        );
      }
      setState(next);
      refreshLivePlugins();
      window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      setStatusBanner({
        type: 'success',
        text: `${id} toggled (${res.message})${autoDisabledNote}`,
      });
    } catch (err: any) {
      if (err?.message?.includes('Failed to find Server Action')) {
        window.location.reload();
        return;
      }
      setStatusBanner({
        type: 'error',
        text: err?.message || 'Failed to update appliance role',
      });
    } finally {
      setSavingRole(null);
    }
  };

  const handlePluginAction = async (id: string, action: 'install' | 'uninstall' | 'reconfigure') => {
    setPluginActionLoading(id);
    setStatusBanner(null);
    try {
      const res = await executePluginAction(id, action);
      if (res.success) {
        setStatusBanner({
          type: 'success',
          text: res.message,
          output: res.output,
        });
        if (state && ((id === 'docs-portal' && action === 'install') || action === 'uninstall')) {
          await refreshFingerprint();
          const latestState = await getCurrentDesiredState();
          if (action === 'install' || isPluginEnabled(id, latestState)) {
            const nextRes =
              action === 'install'
                ? enablePluginWithDependencies(id, latestState)
                : disablePluginWithDependents(id, latestState);
            try {
              await applyState(nextRes.state);
              setState(nextRes.state);
            } catch (syncErr: unknown) {
              setStatusBanner({
                type: 'error',
                text: `${res.message} (failed to sync DesiredState: ${syncErr instanceof Error ? syncErr.message : String(syncErr)})`,
                output: res.output,
              });
            }
          }
        }
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new Event('axonwall-capabilities-updated'));
        }
      } else {
        setStatusBanner({
          type: 'error',
          text: res.message || `Action ${action} failed`,
          output: res.output,
        });
      }
      refreshLivePlugins();
    } catch (err: any) {
      if (err?.message?.includes('Failed to find Server Action')) {
        window.location.reload();
        return;
      }
      setStatusBanner({
        type: 'error',
        text: err?.message || `Failed to execute ${action} for plugin ${id}`,
      });
    } finally {
      setPluginActionLoading(null);
    }
  };

  const toggleExtensionPlugin = async (id: string) => {
    if (!state) return;
    setSavingRole(id);
    setStatusBanner(null);

    try {
      const isCurrentlyEnabled = isPluginEnabled(id, state);
      let depNotice = '';

      const needsK3sInstall =
        (id === 'vigilant-octo-waffle' || id === 'netbox' || id === 'librenms') &&
        !isCurrentlyEnabled &&
        !isPluginEnabled('core-k3s', state) &&
        !(id === 'librenms' && state.librenms?.mode === 'external');

      let next: DesiredState;
      if (!isCurrentlyEnabled) {
        const depRes = enablePluginWithDependencies(id, state);
        next = depRes.state;
        if (depRes.autoEnabledDependencies.length > 0) {
          depNotice = ` [Auto-enabled required dependency: ${depRes.autoEnabledDependencies.join(', ')}]`;
        }
        if (needsK3sInstall) {
          upsertPluginEntry(next, 'core-k3s', true);
        }
      } else {
        const depRes = disablePluginWithDependents(id, state);
        next = depRes.state;
        if (depRes.autoDisabledDependents.length > 0) {
          depNotice = ` [Also disabled dependent plugin(s): ${depRes.autoDisabledDependents.join(', ')}]`;
        }
      }

      if (needsK3sInstall) {
        const k3sInstallRes = await executePluginAction('core-k3s', 'install');
        if (!k3sInstallRes.success) {
          setStatusBanner({
            type: 'error',
            text: `Failed to install required core-k3s dependency: ${k3sInstallRes.message}`,
            output: k3sInstallRes.output,
          });
          return;
        }
        await refreshFingerprint();
      }

      const actionRes = await executePluginAction(id, !isCurrentlyEnabled ? 'enable' : 'disable');
      if (!actionRes.success) {
        setStatusBanner({
          type: 'error',
          text: `Plugin action failed for ${id}: ${actionRes.message}. The toggle was not applied.`,
        });
        return;
      }

      await refreshFingerprint();
      let res: { message: string };
      try {
        res = await applyState(next);
      } catch (applyErr: any) {
        refreshLivePlugins();
        throw new Error(
          `Host plugin action succeeded for ${id}, but DesiredState apply failed (refresh status to inspect host state): ${applyErr?.message || applyErr}`
        );
      }
      setState(next);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
      setStatusBanner({
        type: 'success',
        text: `${id} is now ${!isCurrentlyEnabled ? 'enabled' : 'disabled'}${depNotice} (${res.message})`,
      });
    } catch (err: any) {
      if (err?.message?.includes('Failed to find Server Action')) {
        window.location.reload();
        return;
      }
      setStatusBanner({
        type: 'error',
        text: err?.message || `Failed to toggle plugin ${id}`,
      });
    } finally {
      setSavingRole(null);
    }
  };

  const pluginRequiresPackageInstall = (plugin: PluginManifest, live?: ExtensionPluginLiveStatus): boolean => {
    if (plugin.id === 'docs-portal' || plugin.id === 'headscale') return true;
    const hasManifestPkgs = Boolean(
      plugin.packages &&
        ((plugin.packages.debian && plugin.packages.debian.length > 0) ||
          (plugin.packages.alpine && plugin.packages.alpine.length > 0) ||
          (plugin.packages.arch && plugin.packages.arch.length > 0))
    );
    return hasManifestPkgs || Boolean(live?.packages && live.packages.length > 0);
  };

  const installAndEnablePack = async (packId: string) => {
    const pack = PLUGIN_STARTER_PACKS.find((p) => p.id === packId);
    if (!pack || !state) return;
    setPackLoading(packId);
    setStatusBanner(null);

    try {
      const installedNow: string[] = [];
      for (const pid of getStarterPackPluginIdsWithDeps(pack.id)) {
        const manifest = BUILTIN_PLUGINS.find((p) => p.id === pid);
        const live = livePlugins[pid];
        if (manifest && pluginRequiresPackageInstall(manifest, live) && !live?.installed && !live?.bundled) {
          const installRes = await executePluginAction(pid, 'install');
          if (!installRes.success) {
            setStatusBanner({
              type: 'error',
              text: `Starter pack '${pack.name}' stopped while installing '${pid}': ${installRes.message}`,
              output: installRes.output,
            });
            refreshLivePlugins();
            return;
          }
          installedNow.push(pid);
        }
      }

      await refreshFingerprint();
      const latestState = await getCurrentDesiredState();
      const packRes = enableStarterPack(packId, latestState);
      const applyRes = await applyState(packRes.state);
      setState(packRes.state);
      refreshLivePlugins();
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
      const installSummary =
        installedNow.length > 0 ? `Installed OS packages for ${installedNow.join(', ')}. ` : '';
      setStatusBanner({
        type: 'success',
        text: `${installSummary}Enabled ${pack.name} (${packRes.enabledPlugins.length} plugins). (${applyRes.message})`,
      });
    } catch (err: any) {
      if (err?.message?.includes('Failed to find Server Action')) {
        window.location.reload();
        return;
      }
      setStatusBanner({
        type: 'error',
        text: err?.message || `Failed to install starter pack ${packId}`,
      });
    } finally {
      setPackLoading(null);
    }
  };

  const matchesFilterGroup = (plugin: PluginManifest, group: PluginFilterGroup): boolean => {
    if (group === 'all') return true;
    const live = livePlugins[plugin.id];
    const isInstalledOrBundled = Boolean(live?.installed || live?.bundled || !pluginRequiresPackageInstall(plugin, live));
    if (group === 'active') return isPluginEnabled(plugin.id, state);
    if (group === 'installed') return isInstalledOrBundled;
    return getPluginGroup(plugin) === group;
  };

  const groupCounts = PLUGIN_FILTER_PILLS.reduce<Record<PluginFilterGroup, number>>(
    (acc, pill) => {
      acc[pill.id] = extensionPlugins.filter((p) => matchesFilterGroup(p, pill.id)).length;
      return acc;
    },
    {
      all: 0,
      active: 0,
      installed: 0,
      security: 0,
      routing: 0,
      identity: 0,
      observability: 0,
      cli: 0,
      k3s: 0,
    }
  );

  const filteredExtensions = extensionPlugins.filter((p) => {
    if (!matchesFilterGroup(p, selectedGroup)) return false;
    const q = searchQuery.trim().toLowerCase();
    if (!q) return true;
    const osPkgs = p.packages?.[osFamily] ?? [];
    return (
      p.id.toLowerCase().includes(q) ||
      p.name.toLowerCase().includes(q) ||
      p.description.toLowerCase().includes(q) ||
      osPkgs.some((pkg) => pkg.toLowerCase().includes(q))
    );
  });

  const requestInstallPack = (packId: string) => {
    const pack = PLUGIN_STARTER_PACKS.find((p) => p.id === packId);
    if (!pack || !state) return;
    const pendingPkgs = new Set<string>();
    for (const pid of pack.pluginIds) {
      const manifest = findPluginById(pid);
      const live = livePlugins[pid];
      if (manifest && pluginRequiresPackageInstall(manifest, live) && !live?.installed && !live?.bundled) {
        for (const pkg of manifest.packages?.[osFamily] ?? []) {
          pendingPkgs.add(pkg);
        }
      }
    }
    const inactivePlugins = pack.pluginIds.filter((pid) => !isPluginEnabled(pid, state));
    setPendingConfirm({
      kind: 'pack',
      targetId: pack.id,
      title: `Install & Enable Starter Pack: ${pack.name}`,
      description: `${pack.tagline} Enabling this pack activates ${inactivePlugins.length} plugin(s) and reconciles DesiredState.`,
      affectedPlugins: pack.pluginIds,
      osPackages: Array.from(pendingPkgs),
    });
  };

  const requestToggleCoreRole = (id: string) => {
    if (!state) return;
    if (!isCoreRoleEnabled(id)) {
      void toggleCoreRole(id);
      return;
    }
    const enabledDeps = getDependentPlugins(id)
      .map((d) => d.id)
      .filter((depId) => isPluginEnabled(depId, state));
    setPendingConfirm({
      kind: 'disable-role',
      targetId: id,
      title: `Disable Core Role: ${id}`,
      description:
        enabledDeps.length > 0
          ? `Disabling '${id}' will also cascade-disable ${enabledDeps.length} dependent plugin(s) and stop associated core services.`
          : `Disabling Core Role '${id}' removes its firewall/storage/orchestration capabilities from the active appliance profile.`,
      affectedPlugins: enabledDeps,
      osPackages: findPluginById(id)?.packages?.[osFamily] ?? [],
    });
  };

  const requestToggleExtensionPlugin = (id: string) => {
    if (!state) return;
    if (!isPluginEnabled(id, state)) {
      void toggleExtensionPlugin(id);
      return;
    }
    const enabledDeps = getDependentPlugins(id)
      .map((d) => d.id)
      .filter((depId) => isPluginEnabled(depId, state));
    if (enabledDeps.length === 0) {
      void toggleExtensionPlugin(id);
      return;
    }
    setPendingConfirm({
      kind: 'disable-extension',
      targetId: id,
      title: `Disable Extension Plugin: ${id}`,
      description: `Other enabled plugins depend on '${id}'. Disabling it will cascade-disable those dependents as well.`,
      affectedPlugins: enabledDeps,
      osPackages: [],
    });
  };

  const requestUninstallPlugin = (id: string) => {
    const manifest = findPluginById(id);
    const enabledDeps = state
      ? getDependentPlugins(id)
          .map((d) => d.id)
          .filter((depId) => isPluginEnabled(depId, state))
      : [];
    const selfEnabled = state ? isPluginEnabled(id, state) : false;
    const osPkgs = manifest?.packages?.[osFamily] ?? [];
    setPendingConfirm({
      kind: 'uninstall',
      targetId: id,
      title: `Uninstall Extension Plugin: ${manifest?.name || id}`,
      description:
        selfEnabled || enabledDeps.length > 0
          ? `This will uninstall '${id}' OS packages from the host.${selfEnabled ? ' The plugin is currently enabled.' : ''}`
          : `Remove '${id}' OS packages (${osFamily}) from the host.`,
      affectedPlugins: enabledDeps,
      osPackages: osPkgs,
    });
  };

  const executeConfirmedAction = async () => {
    if (!pendingConfirm) return;
    const current = pendingConfirm;
    setPendingConfirm(null);
    if (current.kind === 'pack') {
      await installAndEnablePack(current.targetId);
    } else if (current.kind === 'disable-role') {
      await toggleCoreRole(current.targetId);
    } else if (current.kind === 'disable-extension') {
      await toggleExtensionPlugin(current.targetId);
    } else if (current.kind === 'uninstall') {
      await handlePluginAction(current.targetId, 'uninstall');
    }
  };

  const getRoleIcon = (id: string) => {
    if (id === 'core-firewall') return Flame;
    if (id === 'core-nas') return Database;
    if (id === 'core-vigilante') return Shield;
    return Cpu;
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Boxes className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Appliance Roles & Plugin Store</h1>
            <p className="text-sm text-slate-400">
              Toggle Core Appliance Roles (Firewall, enterprise grade NAS, K3s + OpenEBS) or install sandboxed extensions ({osFamily.toUpperCase()} Host).
            </p>
          </div>
        </div>

        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search plugins & extensions..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-64"
          />
        </div>
      </div>

      {livePluginsError && (
        <div className="p-4 rounded-xl border text-xs font-medium flex items-center justify-between bg-amber-500/10 border-amber-500/30 text-amber-300">
          <span>
            {livePluginsError} Live plugin status is unknown; the list below shows the last known
            state, if any.
          </span>
          <button onClick={refreshLivePlugins} className="text-slate-300 hover:text-white shrink-0 ml-4 cursor-pointer">
            Retry
          </button>
        </div>
      )}

      {statusBanner && (
        <div
          className={`p-4 rounded-xl border text-xs font-medium flex items-center justify-between ${
            statusBanner.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          <div className="flex items-center gap-3">
            <span>{statusBanner.text}</span>
            {statusBanner.output && (
              <button
                onClick={() =>
                  setActiveOutputModal({
                    title: `Execution Log (${statusBanner.type === 'success' ? 'Success' : 'Error'})`,
                    output: statusBanner.output || '',
                  })
                }
                className="underline text-[11px] font-mono text-slate-300 hover:text-white"
              >
                View Log Output
              </button>
            )}
          </div>
          <button onClick={() => setStatusBanner(null)} className="text-slate-400 hover:text-white">
            ✕
          </button>
        </div>
      )}

      {/* Core Appliance Role Plugins */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-white tracking-tight">Core Appliance Roles</h2>
            <p className="text-xs text-slate-400">
              Run Axonwall as a dedicated NGFW, a pure ZFS NAS appliance, or a hyper-converged Firewall + ZFS NAS + K3s HA node.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {coreRolePlugins.map((plugin) => {
            const enabled = isCoreRoleEnabled(plugin.id);
            const RoleIcon = getRoleIcon(plugin.id);
            const isSaving = savingRole === plugin.id;

            return (
              <div
                key={plugin.id}
                className={`p-6 rounded-2xl border transition flex flex-col justify-between space-y-5 ${
                  enabled
                    ? 'bg-slate-900/95 border-emerald-500/40 shadow-lg shadow-emerald-950/20'
                    : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-10 h-10 rounded-xl flex items-center justify-center border ${
                          enabled
                            ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400'
                            : 'bg-slate-800 border-slate-700 text-slate-400'
                        }`}
                      >
                        <RoleIcon className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-white">{plugin.name}</h3>
                        <span className="text-[11px] font-mono text-slate-400">{plugin.id}</span>
                      </div>
                    </div>
                    <span
                      className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider border ${
                        enabled
                          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {enabled ? 'Active Role' : 'Disabled'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{plugin.description}</p>

                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {plugin.dependencies && plugin.dependencies.map((depId) => {
                      const depMet = isPluginEnabled(depId, state);
                      return (
                        <span
                          key={depId}
                          title={depMet ? `Required dependency ${depId} is active` : `Requires ${depId} (will be auto-enabled when enabling ${plugin.id})`}
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border flex items-center gap-1 ${
                            depMet
                              ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                              : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                          }`}
                        >
                          <Cpu className="w-2.5 h-2.5" /> Requires: {depId}
                        </span>
                      );
                    })}
                    {plugin.systemdUnits.map((u) => (
                      <span
                        key={u}
                        className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-400"
                      >
                        {u}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-4 border-t border-slate-800/80">
                  <button
                    onClick={() => setSelectedPlugin(plugin)}
                    className="text-xs text-slate-400 hover:text-emerald-400 font-medium flex items-center gap-1 transition"
                  >
                    <Shield className="w-3.5 h-3.5" /> Role Spec
                  </button>

                  <button
                    disabled={isSaving}
                    onClick={() => requestToggleCoreRole(plugin.id)}
                    className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-1.5 ${
                      enabled
                        ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20'
                        : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/40'
                    }`}
                  >
                    {isSaving ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" /> Applying...
                      </>
                    ) : (
                      <>
                        <Power className="w-3.5 h-3.5" />
                        {enabled ? 'Disable Role' : 'Enable Role'}
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Curated Starter Packs */}
      <div className="space-y-4 pt-2">
        <div>
          <h2 className="text-base font-bold text-white tracking-tight">Curated Starter Packs</h2>
          <p className="text-xs text-slate-400">
            Install and enable multi-plugin bundles in one click on top of the Lean Router/NGFW Core.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {PLUGIN_STARTER_PACKS.map((pack) => {
            const allEnabled = Boolean(state && pack.pluginIds.every((pid) => isPluginEnabled(pid, state)));
            const isPackWorking = packLoading === pack.id;
            return (
              <div
                key={pack.id}
                className="p-5 rounded-2xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-3"
              >
                <div className="space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h3 className="text-sm font-semibold text-white">{pack.name}</h3>
                      <p className="text-[11px] text-emerald-400 font-medium">{pack.tagline}</p>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                        allEnabled
                          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {allEnabled ? 'All Active' : `${pack.pluginIds.length} Plugins`}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{pack.description}</p>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {pack.pluginIds.map((pid) => {
                      const active = isPluginEnabled(pid, state);
                      return (
                        <span
                          key={pid}
                          className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                            active
                              ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                              : 'bg-slate-950 text-slate-400 border-slate-800'
                          }`}
                        >
                          {pid}
                        </span>
                      );
                    })}
                  </div>
                </div>
                <div className="flex justify-end pt-2 border-t border-slate-800/80">
                  <button
                    type="button"
                    disabled={isPackWorking || !state || allEnabled}
                    onClick={() => requestInstallPack(pack.id)}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white transition flex items-center gap-1.5"
                  >
                    {isPackWorking ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" /> Installing Pack...
                      </>
                    ) : allEnabled ? (
                      <>
                        <CheckCircle2 className="w-3.5 h-3.5" /> Enabled
                      </>
                    ) : (
                      <>
                        <Download className="w-3.5 h-3.5" /> Install & Enable Pack
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Add-on Extensions Grid */}
      <div className="space-y-4 pt-2">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h2 className="text-base font-bold text-white tracking-tight">Sandboxed Extension Plugins</h2>
            <p className="text-xs text-slate-400">
              Modular services, network telemetry, and operator CLI packages ({osFamily === 'alpine' ? 'Alpine apk' : osFamily === 'arch' ? 'Arch pacman' : 'Debian apt'}).
            </p>
          </div>
          <button
            onClick={refreshLivePlugins}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white rounded-lg text-xs font-medium flex items-center gap-1.5 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh Status
          </button>
        </div>

        {/* Category Filter Pills */}
        <div className="flex flex-wrap items-center gap-2">
          {PLUGIN_FILTER_PILLS.map((pill) => {
            const activePill = selectedGroup === pill.id;
            return (
              <button
                key={pill.id}
                type="button"
                onClick={() => setSelectedGroup(pill.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition flex items-center gap-1.5 cursor-pointer ${
                  activePill
                    ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                }`}
              >
                <span>{pill.label}</span>
                <span
                  className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                    activePill ? 'bg-emerald-500/20 text-emerald-200' : 'bg-slate-800 text-slate-500'
                  }`}
                >
                  {groupCounts[pill.id]}
                </span>
              </button>
            );
          })}
        </div>

        {filteredExtensions.length === 0 ? (
          <div className="p-8 rounded-2xl bg-slate-900/60 border border-slate-800 text-center space-y-2">
            <p className="text-sm font-medium text-slate-300">No extension plugins match the current filter.</p>
            <button
              type="button"
              onClick={() => {
                setSelectedGroup('all');
                setSearchQuery('');
              }}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition"
            >
              Reset filters
            </button>
          </div>
        ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredExtensions.map((plugin) => {
            const live = livePlugins[plugin.id];
            const isInstalled = live ? live.installed : false;
            const isBundled = live ? live.bundled : false;
            const isLoading = pluginActionLoading === plugin.id;
            const isEnabled = isPluginEnabled(plugin.id, state);
            const isSaving = savingRole === plugin.id;
            const needsPackage = pluginRequiresPackageInstall(plugin, live);

            return (
              <div
                key={plugin.id}
                className="p-6 rounded-2xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-4"
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h3 className="text-base font-semibold text-white tracking-tight">{plugin.name}</h3>
                      <span className="text-xs text-slate-500 font-mono">v{plugin.version} • {plugin.author}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`px-2.5 py-1 rounded-md text-[11px] font-semibold border ${
                          isBundled
                            ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                            : !needsPackage
                              ? 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20'
                              : isInstalled
                                ? 'bg-sky-500/10 text-sky-400 border-sky-500/20'
                                : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                      >
                        {isBundled
                          ? 'Bundled (OS)'
                          : !needsPackage
                            ? 'Built-in Module'
                            : isInstalled
                              ? 'Installed'
                              : 'Available'}
                      </span>
                      {(isInstalled || isBundled || !needsPackage) && (
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                            isEnabled
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                              : 'bg-slate-800/80 text-slate-400 border-slate-700'
                          }`}
                        >
                          {isEnabled ? 'Active' : 'Disabled'}
                        </span>
                      )}
                      {live && live.missingBinaries && live.missingBinaries.length > 0 && (
                        <span
                          title={`Missing required binaries: ${live.missingBinaries.join(', ')}`}
                          className="px-2 py-0.5 rounded text-[10px] font-semibold border bg-amber-500/15 text-amber-300 border-amber-500/30"
                        >
                          Missing: {live.missingBinaries.join(', ')}
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed line-clamp-3">
                    {plugin.description}
                  </p>

                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {plugin.dependencies && plugin.dependencies.map((depId) => {
                      const depMet = isPluginEnabled(depId, state);
                      return (
                        <span
                          key={depId}
                          title={depMet ? `Required dependency ${depId} is active` : `Requires ${depId} (will be auto-enabled when enabling ${plugin.id})`}
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border flex items-center gap-1 ${
                            depMet
                              ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                              : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                          }`}
                        >
                          <Cpu className="w-2.5 h-2.5" /> Requires: {depId}
                        </span>
                      );
                    })}
                    {plugin.systemdUnits.map((u) => (
                      <span key={u} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-400">
                        {u}
                      </span>
                    ))}
                    {plugin.cliBinaries && plugin.cliBinaries.map((b) => (
                      <span key={b} className="px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-900/60 text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                        <Terminal className="w-2.5 h-2.5" /> {b}
                      </span>
                    ))}
                    {live?.bundledBinaries && live.bundledBinaries.map((b) => (
                      <span
                        key={`bundled-${b}`}
                        title="Verified bundled binary inside plugin sandbox"
                        className="px-2 py-0.5 rounded bg-sky-950/50 border border-sky-800/60 text-[10px] font-mono text-sky-300 flex items-center gap-1"
                      >
                        bundled: {b}
                      </span>
                    ))}
                    {(() => {
                      const osPkgs = plugin.packages?.[osFamily] ?? [];
                      if (osPkgs.length === 0 && !needsPackage) {
                        return (
                          <span className="px-2 py-0.5 rounded bg-indigo-950/40 border border-indigo-800/50 text-[10px] font-mono text-indigo-300">
                            Config / UI only
                          </span>
                        );
                      }
                      const visiblePkgs = osPkgs.slice(0, 5);
                      const remaining = osPkgs.length - visiblePkgs.length;
                      return (
                        <>
                          {visiblePkgs.map((pkg) => (
                            <span
                              key={`pkg-${pkg}`}
                              title={`${osFamily} OS package: ${pkg}`}
                              className="px-2 py-0.5 rounded bg-violet-950/40 border border-violet-800/60 text-[10px] font-mono text-violet-300"
                            >
                              pkg: {pkg}
                            </span>
                          ))}
                          {remaining > 0 && (
                            <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] font-mono text-slate-400">
                              +{remaining} pkg{remaining === 1 ? '' : 's'}
                            </span>
                          )}
                        </>
                      );
                    })()}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-4 border-t border-slate-800/80 gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setSelectedPlugin(plugin)}
                      className="text-xs text-slate-400 hover:text-emerald-400 font-medium flex items-center gap-1 transition"
                    >
                      <Shield className="w-3.5 h-3.5" /> Manifest
                    </button>
                    {plugin.menuEntry && (
                      <Link
                        href={plugin.menuEntry.path}
                        className="text-xs text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1 transition"
                      >
                        <Settings className="w-3.5 h-3.5" /> Configure
                      </Link>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {(isInstalled || isBundled || !needsPackage) && (
                      <button
                        disabled={isSaving}
                        onClick={() => requestToggleExtensionPlugin(plugin.id)}
                        className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-1.5 ${
                          isEnabled
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20'
                            : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/40'
                        }`}
                      >
                        {isSaving ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Power className="w-3.5 h-3.5" />
                        )}
                        {isEnabled ? 'Disable' : 'Enable'}
                      </button>
                    )}

                    {plugin.id === 'cli-workstation' && isInstalled && (
                      <button
                        disabled={isLoading}
                        onClick={() => handlePluginAction(plugin.id, 'reconfigure')}
                        title="Re-apply starship, zsh, vim, and tmux configuration files"
                        className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition flex items-center gap-1"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} /> Re-sync
                      </button>
                    )}

                    {(needsPackage || isInstalled || isBundled) &&
                      (isInstalled ? (
                        <button
                          disabled={isLoading || isBundled}
                          onClick={() => requestUninstallPlugin(plugin.id)}
                          title={isBundled ? 'Cannot uninstall packages bundled into the rootfs image' : 'Uninstall extension package'}
                          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-1.5 ${
                            isBundled
                              ? 'bg-slate-800/50 text-slate-500 border border-slate-800 cursor-not-allowed'
                              : 'bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20'
                          }`}
                        >
                          {isLoading ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <Trash2 className="w-3.5 h-3.5" />
                          )}
                          {isBundled ? 'Bundled' : 'Uninstall'}
                        </button>
                      ) : (
                        <button
                          disabled={isLoading}
                          onClick={() => handlePluginAction(plugin.id, 'install')}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/40 transition flex items-center gap-1.5"
                        >
                          {isLoading ? (
                            <>
                              <Loader2 className="w-3.5 h-3.5 animate-spin" /> Installing...
                            </>
                          ) : (
                            <>
                              <Download className="w-3.5 h-3.5" /> Install Plugin
                            </>
                          )}
                        </button>
                      ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        )}
      </div>

      {/* Manifest Modal */}
      {selectedPlugin && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-emerald-400" />
                Plugin Manifest: {selectedPlugin.id}
              </h2>
              <button
                onClick={() => setSelectedPlugin(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-500 block">ID & VERSION</span>
                <span className="text-white font-mono">{selectedPlugin.id} @ {selectedPlugin.version}</span>
              </div>
              {selectedPlugin.dependencies && selectedPlugin.dependencies.length > 0 && (
                <div>
                  <span className="text-slate-500 block">REQUIRED PLUGIN DEPENDENCIES</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedPlugin.dependencies.map((depId) => {
                      const depMet = isPluginEnabled(depId, state);
                      return (
                        <span
                          key={depId}
                          className={`px-2 py-0.5 rounded font-mono border ${
                            depMet
                              ? 'bg-sky-500/15 text-sky-300 border-sky-500/30'
                              : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                          }`}
                        >
                          {depId} ({depMet ? 'Active' : 'Will Auto-Enable'})
                        </span>
                      );
                    })}
                  </div>
                </div>
              )}
              <div>
                <span className="text-slate-500 block">REQUIRED PRIVILEGES</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedPlugin.privileges.map((p) => (
                    <span key={p} className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
              {selectedPlugin.systemdUnits && selectedPlugin.systemdUnits.length > 0 && (
                <div>
                  <span className="text-slate-500 block">SYSTEMD SANDBOX UNITS</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedPlugin.systemdUnits.map((u) => (
                      <span key={u} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">
                        {u}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {selectedPlugin.packages && (
                <div>
                  <span className="text-slate-500 block">OS PACKAGES ({osFamily.toUpperCase()})</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {((osFamily === 'alpine'
                      ? selectedPlugin.packages.alpine
                      : osFamily === 'arch'
                        ? selectedPlugin.packages.arch
                        : selectedPlugin.packages.debian) || []).map((pkg) => (
                      <span key={pkg} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-sky-400 font-mono">
                        {pkg}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {livePlugins[selectedPlugin.id]?.bundledBinaries &&
                livePlugins[selectedPlugin.id]!.bundledBinaries!.length > 0 && (
                  <div>
                    <span className="text-slate-500 block">VERIFIED BUNDLED BINARIES</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {livePlugins[selectedPlugin.id]!.bundledBinaries!.map((bin) => (
                        <span key={bin} className="px-2 py-0.5 rounded bg-slate-950 border border-sky-800/60 text-sky-300 font-mono">
                          {bin}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              {selectedPlugin.cliBinaries && selectedPlugin.cliBinaries.length > 0 && (
                <div>
                  <span className="text-slate-500 block">CLI BINARIES</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedPlugin.cliBinaries.map((bin) => (
                      <span key={bin} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-emerald-400 font-mono">
                        {bin}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {selectedPlugin.nftHooks && (
                <div>
                  <span className="text-slate-500 block">NFTABLES HOOK POINTS</span>
                  <div className="mt-1 space-y-1">
                    {selectedPlugin.nftHooks.map((h, i) => (
                      <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-sky-400">
                        {h.table} → chain {h.chain} (priority {h.priority})
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedPlugin(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Floating Status Notification Toast */}
      {statusBanner && (
        <div
          className={`fixed bottom-6 right-6 z-40 max-w-md w-full p-4 rounded-xl border shadow-2xl backdrop-blur-md flex flex-col gap-2 transition-all ${
            statusBanner.type === 'success'
              ? 'bg-slate-900/95 border-emerald-500/40 text-emerald-300'
              : 'bg-slate-900/95 border-rose-500/40 text-rose-300'
          }`}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2 font-semibold text-xs">
              {statusBanner.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              )}
              <span>{statusBanner.text}</span>
            </div>
            <button
              onClick={() => setStatusBanner(null)}
              className="text-slate-400 hover:text-white shrink-0 p-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          {statusBanner.output && (
            <div className="pt-2 border-t border-slate-800 flex justify-end">
              <button
                onClick={() =>
                  setActiveOutputModal({
                    title: `Execution Log (${statusBanner.type === 'success' ? 'Success' : 'Error'})`,
                    output: statusBanner.output || '',
                  })
                }
                className="text-[11px] font-mono text-slate-300 hover:text-white flex items-center gap-1.5 underline decoration-slate-600 hover:decoration-white"
              >
                <FileText className="w-3 h-3" /> View Execution Log Output
              </button>
            </div>
          )}
        </div>
      )}

      {/* Impact / Dependency Confirmation Modal */}
      {pendingConfirm && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <AlertTriangle
                  className={`w-4 h-4 ${pendingConfirm.kind === 'pack' ? 'text-emerald-400' : 'text-amber-400'}`}
                />
                {pendingConfirm.title}
              </h2>
              <button
                type="button"
                onClick={() => setPendingConfirm(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">{pendingConfirm.description}</p>

            {pendingConfirm.affectedPlugins.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  {pendingConfirm.kind === 'pack'
                    ? 'Plugins Included in Pack'
                    : 'Dependent Plugins Affected'}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {pendingConfirm.affectedPlugins.map((pid) => (
                    <span
                      key={pid}
                      className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                        pendingConfirm.kind === 'pack'
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                          : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                      }`}
                    >
                      {pid}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-1.5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                {pendingConfirm.kind === 'pack'
                  ? `OS Packages to Install (${osFamily})`
                  : pendingConfirm.kind === 'uninstall'
                    ? `OS Packages to Remove (${osFamily})`
                    : `Associated OS Packages (${osFamily})`}
              </div>
              {pendingConfirm.osPackages.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {pendingConfirm.osPackages.map((pkg) => (
                    <span
                      key={pkg}
                      className="px-2 py-0.5 rounded bg-violet-950/40 border border-violet-800/60 text-[11px] font-mono text-violet-300"
                    >
                      {pkg}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-slate-400 font-mono">
                  {pendingConfirm.kind === 'pack'
                    ? '0 new OS packages required (plugins already installed or config/UI only).'
                    : 'No external OS packages targeted.'}
                </p>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setPendingConfirm(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void executeConfirmedAction()}
                className={`px-4 py-2 rounded-lg text-xs font-semibold text-white transition ${
                  pendingConfirm.kind === 'pack'
                    ? 'bg-emerald-600 hover:bg-emerald-500'
                    : 'bg-rose-600 hover:bg-rose-500'
                }`}
              >
                {pendingConfirm.kind === 'pack'
                  ? 'Confirm Install & Enable'
                  : pendingConfirm.kind === 'uninstall'
                    ? 'Confirm Uninstall'
                    : 'Confirm Disable'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Execution Output Modal */}
      {activeOutputModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                {activeOutputModal.title}
              </h2>
              <button
                onClick={() => setActiveOutputModal(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <pre className="bg-black/60 border border-slate-800/80 rounded-xl p-4 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-96 whitespace-pre-wrap leading-relaxed">
              {activeOutputModal.output}
            </pre>
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setActiveOutputModal(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
