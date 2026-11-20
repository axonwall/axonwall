import { describe, expect, it } from 'vitest';
import {
  BUILTIN_PLUGINS,
  CustomKernelBuildSpecSchema,
  DesiredStateSchema,
  ThreatHarvesterConfigSchema,
  compileCustomKernelArtifacts,
  compileNftables,
  disablePluginWithDependents,
  enablePluginWithDependencies,
  isPluginEnabled,
  serializeDesiredStateToYamlFiles,
  validateYamlConfigFiles,
} from '../index.js';

describe('Axonwall Blackbox (ebpf-threat-harvester) Schema, Plugin, Nft & Kernel Integration', () => {
  it('registers ebpf-threat-harvester in BUILTIN_PLUGINS as strictly opt-in', () => {
    const manifest = BUILTIN_PLUGINS.find((p) => p.id === 'ebpf-threat-harvester');
    expect(manifest).toBeDefined();
    expect(manifest?.category).toBe('extension');
    expect(manifest?.defaultEnabled).toBe(false);
    expect(manifest?.menuEntry?.path).toBe('/security/threat-harvester');

    expect(isPluginEnabled('ebpf-threat-harvester', undefined)).toBe(false);
    expect(isPluginEnabled('ebpf-threat-harvester', {})).toBe(false);

    const base = DesiredStateSchema.parse({});
    expect(isPluginEnabled('ebpf-threat-harvester', base)).toBe(false);

    const enabled = enablePluginWithDependencies('ebpf-threat-harvester', base);
    expect(isPluginEnabled('ebpf-threat-harvester', enabled.state)).toBe(true);
    expect(enabled.state.threatHarvester?.enabled).toBe(true);

    const disabled = disablePluginWithDependents('ebpf-threat-harvester', enabled.state);
    expect(isPluginEnabled('ebpf-threat-harvester', disabled.state)).toBe(false);
    expect(disabled.state.threatHarvester?.enabled).toBe(false);
  });

  it('enforces safe ThreatHarvesterConfigSchema defaults', () => {
    const cfg = ThreatHarvesterConfigSchema.parse({});
    expect(cfg.enabled).toBe(false);
    expect(cfg.captureMode).toBe('adaptive');
    expect(cfg.maxPayloadBytes).toBe(4096);
    expect(cfg.correlationWindowSec).toBe(45);
    expect(cfg.canaryPorts).toEqual([23, 2323, 3389, 4444, 5900, 6379, 9200, 27017]);
    expect(cfg.enableTlsUprobes).toBe(false);
    expect(cfg.autoHoneypotTlsUprobes).toBe(true);
    expect(cfg.anonymizeOnExport).toBe(true);
    expect(cfg.spoolDir).toBe('/var/lib/axonwall/threat-corpus');
    expect(cfg.teacherLlm.maxCallsPerHour).toBe(30);
    expect(cfg.fleetShipper.usePathStyle).toBe(true);
  });

  it('emits /etc/axonwall/managed/threat_harvester_config.json (0600) only when opted-in', () => {
    const baseState = DesiredStateSchema.parse({});
    const baseCompiled = compileNftables(baseState);
    expect(baseCompiled.files.some((f) => f.path === '/etc/axonwall/managed/threat_harvester_config.json')).toBe(false);

    const enabled = enablePluginWithDependencies('ebpf-threat-harvester', baseState).state;
    enabled.threatHarvester = ThreatHarvesterConfigSchema.parse({
      enabled: true,
      captureMode: 'firehose',
      watchedInterfaces: ['wan0', 'lan0'],
      canaryPorts: [23, 4444],
      enableTlsUprobes: true,
      tlsUprobeAllowlist: ['curl'],
    });

    const compiled = compileNftables(enabled);
    const cfgFile = compiled.files.find((f) => f.path === '/etc/axonwall/managed/threat_harvester_config.json');
    expect(cfgFile).toBeDefined();
    expect(cfgFile?.fileMode).toBe(0o600);
    const parsed = JSON.parse(cfgFile!.content);
    expect(parsed.enabled).toBe(true);
    expect(parsed.captureMode).toBe('firehose');
    expect(parsed.watchedInterfaces).toEqual(['wan0', 'lan0']);
    expect(parsed.tlsUprobeAllowlist).toEqual(['curl']);
  });

  it('round-trips threatHarvester in security.yaml', () => {
    const state = DesiredStateSchema.parse({
      threatHarvester: {
        enabled: true,
        captureMode: 'honeypot_only',
        canaryPorts: [23, 6379],
        maxPayloadBytes: 8192,
        enableTlsUprobes: false,
        anonymizeOnExport: true,
      },
    });
    const files = serializeDesiredStateToYamlFiles(state);
    expect(files['security.yaml']).toContain('threatHarvester:');
    expect(files['security.yaml']).toContain('captureMode: honeypot_only');

    const validated = validateYamlConfigFiles(files);
    expect(validated.valid).toBe(true);
    expect(validated.state?.threatHarvester?.captureMode).toBe('honeypot_only');
    expect(validated.state?.threatHarvester?.maxPayloadBytes).toBe(8192);
  });

  it('includes TCX & Uprobe Kconfig symbols in ebpf kernel capability pack', () => {
    const spec = CustomKernelBuildSpecSchema.parse({
      mode: 'universal',
      capabilities: ['k3s', 'zfs', 'nftables', 'ebpf'],
      lockdownTier: 'integrity',
    });
    const bundle = compileCustomKernelArtifacts(spec);
    expect(bundle.kconfigFragment).toContain('CONFIG_NET_CLS_ACT=y');
    expect(bundle.kconfigFragment).toContain('CONFIG_NET_SCH_INGRESS=y');
    expect(bundle.kconfigFragment).toContain('CONFIG_UPROBE_EVENTS=y');
    expect(bundle.kconfigFragment).toContain('CONFIG_TRACEPOINTS=y');
    expect(bundle.kconfigFragment).toContain('CONFIG_FTRACE_SYSCALLS=y');
    expect(bundle.simulatedAudit.checks.find((c) => c.id === 'ebpf-tcx-uprobe-harvester')?.status).toBe('PASS');
  });
});
