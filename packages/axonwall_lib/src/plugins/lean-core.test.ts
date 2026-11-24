import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DesiredStateSchema } from '../schemas/index.js';
import {
  BUILTIN_PLUGINS,
  CORE_ROLE_PLUGIN_IDS,
  PLUGIN_STARTER_PACKS,
  disablePluginWithDependents,
  enablePluginWithDependencies,
  enableStarterPack,
  findPluginById,
  findStarterPackById,
  getStarterPackPluginIdsWithDeps,
  isPluginEnabled,
} from './index.js';

const NEW_OPT_IN_PLUGIN_IDS = [
  'suricata-ids',
  'crowdsec-bouncer',
  'frr-routing',
  'openvpn',
  'ipsec-strongswan',
  'captive-portal',
  'tls-decryption',
  'identity-aware-proxy',
  'directory-ldap',
  'enterprise-sso',
  'firewall-importer',
  'mcp-ai-control',
  'custom-kernel-studio',
  'high-availability',
  'fleet-controller',
  'etckeeper-audit',
  'web-terminal',
  'packet-diagnostics',
] as const;

const FLIPPED_DEFAULT_OFF_IDS = [
  'cli-workstation',
  'host-malware-rootkit',
  'coroot-ebpf-apm',
] as const;

describe('Lean Router/NGFW Core & Plugin Migration', () => {
  it('enables only core-firewall on null or fresh DesiredState and keeps all 18 new + 3 flipped plugins opt-in', () => {
    const fresh = DesiredStateSchema.parse({});
    expect(isPluginEnabled('core-firewall', null)).toBe(true);
    expect(isPluginEnabled('core-firewall', fresh)).toBe(true);

    for (const id of [...NEW_OPT_IN_PLUGIN_IDS, ...FLIPPED_DEFAULT_OFF_IDS, 'ai-copilot', 'docs-portal']) {
      const manifest = findPluginById(id);
      expect(manifest, `missing manifest for ${id}`).toBeDefined();
      expect(manifest?.defaultEnabled, `${id} must have defaultEnabled: false`).toBe(false);
      expect(isPluginEnabled(id, null), `${id} should default disabled on null state`).toBe(false);
      expect(isPluginEnabled(id, fresh), `${id} should default disabled on fresh state`).toBe(false);
    }
  });

  it('auto-preserves legacy DesiredState enabled configurations on upgrade unless explicitly disabled', () => {
    const legacyState = DesiredStateSchema.parse({
      suricata: { enabled: true },
      crowdsec: { enabled: true },
      frr: { enabled: true },
      openvpn: { enabled: true },
      ipsec: { enabled: true },
      captivePortal: { enabled: true },
      tlsDecryption: { enabled: true },
      zeroTrust: { enabled: true },
      identity: { ldapEnabled: true },
      sso: { enabled: true },
      ha: { enabled: true },
      fleet: { enabled: true },
      mcp: { enabled: true },
      hostDefense: { enabled: true },
      observability: {
        ebpfApm: { enabled: true },
      },
    });

    for (const id of [
      'suricata-ids',
      'crowdsec-bouncer',
      'frr-routing',
      'openvpn',
      'ipsec-strongswan',
      'captive-portal',
      'tls-decryption',
      'identity-aware-proxy',
      'directory-ldap',
      'enterprise-sso',
      'high-availability',
      'fleet-controller',
      'mcp-ai-control',
      'host-malware-rootkit',
      'coroot-ebpf-apm',
    ]) {
      expect(isPluginEnabled(id, legacyState), `${id} should auto-preserve on upgrade`).toBe(true);
      const disabled = disablePluginWithDependents(id, legacyState);
      expect(isPluginEnabled(id, disabled.state), `${id} should disable cleanly`).toBe(false);
    }
  });

  it('toggles all 18 new plugins via enablePluginWithDependencies / disablePluginWithDependents', () => {
    let state = DesiredStateSchema.parse({});
    for (const id of NEW_OPT_IN_PLUGIN_IDS) {
      const en = enablePluginWithDependencies(id, state);
      expect(isPluginEnabled(id, en.state), `${id} enable failed`).toBe(true);
      const dis = disablePluginWithDependents(id, en.state);
      expect(isPluginEnabled(id, dis.state), `${id} disable failed`).toBe(false);
      state = dis.state;
    }
  });

  it('validates all 4 Starter Packs and enables every pack member cleanly', () => {
    expect(PLUGIN_STARTER_PACKS).toHaveLength(4);
    for (const pack of PLUGIN_STARTER_PACKS) {
      expect(findStarterPackById(pack.id)?.id).toBe(pack.id);
      for (const pid of pack.pluginIds) {
        expect(BUILTIN_PLUGINS.some((p) => p.id === pid), `pack ${pack.id} references unknown plugin ${pid}`).toBe(true);
      }
      const res = enableStarterPack(pack.id, DesiredStateSchema.parse({}));
      for (const pid of pack.pluginIds) {
        expect(isPluginEnabled(pid, res.state), `pack ${pack.id} failed to enable ${pid}`).toBe(true);
      }
      const withDeps = getStarterPackPluginIdsWithDeps(pack.id);
      for (const pid of pack.pluginIds) {
        expect(withDeps).toContain(pid);
      }
    }
  });

  it('maintains 100% manifest parity between TypeScript BUILTIN_PLUGINS and Go apps/axonwalld/engine/plugins.go', () => {
    const pluginsGoPath = path.resolve(import.meta.dirname, '../../../../apps/axonwalld/engine/plugins.go');
    const goSrc = fs.readFileSync(pluginsGoPath, 'utf8');

    const goMap = new Map<
      string,
      {
        defaultEnabled: boolean;
        dependencies: string[];
        systemdUnits: string[];
        debian: string[];
        alpine: string[];
        arch: string[];
      }
    >();

    const parts = goSrc.split(/\n\t\t\{\n\t\t\tID:\s*"/);
    for (let i = 1; i < parts.length; i++) {
      const chunk = parts[i]!;
      const id = chunk.slice(0, chunk.indexOf('"'));
      const blockEnd = chunk.indexOf('\n\t\t},');
      const body = blockEnd >= 0 ? chunk.slice(0, blockEnd) : chunk.slice(0, 3000);
      const extractSlice = (field: string): string[] => {
        const m = body.match(new RegExp(`${field}:\\s*\\[\\]string\\{([^}]*)\\}`));
        if (!m) return [];
        return [...m[1]!.matchAll(/"([^"]+)"/g)].map((x) => x[1]!);
      };
      goMap.set(id, {
        defaultEnabled: /DefaultEnabled:\s*true/.test(body),
        dependencies: extractSlice('Dependencies'),
        systemdUnits: extractSlice('SystemdUnits'),
        debian: extractSlice('DebianPackages'),
        alpine: extractSlice('AlpinePackages'),
        arch: extractSlice('ArchPackages'),
      });
    }

    const sorted = (arr?: string[]) => [...(arr || [])].sort();
    for (const plugin of BUILTIN_PLUGINS) {
      if (CORE_ROLE_PLUGIN_IDS.has(plugin.id) || plugin.id.startsWith('cli-emacs')) continue;
      const g = goMap.get(plugin.id);
      expect(g, `Go extension definition missing for ${plugin.id}`).toBeDefined();
      expect(Boolean(plugin.defaultEnabled), `defaultEnabled mismatch on ${plugin.id}`).toBe(g!.defaultEnabled);
      expect(sorted(plugin.dependencies), `dependencies mismatch on ${plugin.id}`).toEqual(sorted(g!.dependencies));
      expect(sorted(plugin.systemdUnits), `systemdUnits mismatch on ${plugin.id}`).toEqual(sorted(g!.systemdUnits));
      expect(sorted(plugin.packages?.debian), `debian packages mismatch on ${plugin.id}`).toEqual(sorted(g!.debian));
      expect(sorted(plugin.packages?.alpine), `alpine packages mismatch on ${plugin.id}`).toEqual(sorted(g!.alpine));
      expect(sorted(plugin.packages?.arch), `arch packages mismatch on ${plugin.id}`).toEqual(sorted(g!.arch));
    }
  });
});
