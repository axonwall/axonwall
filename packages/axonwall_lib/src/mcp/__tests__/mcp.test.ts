import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect } from 'vitest';
import {
  McpPolicyLimitsSchema,
  validateMcpTarget,
  validateRedirectTargetAllowlist,
  isIpInCidr,
  type McpGuardContext,
} from '../index.js';
import { compileNftables } from '../../compile/nft/index.js';
import { DesiredStateSchema } from '../../schemas/index.js';

describe('Axonwall MCP Safety Guard & Blast-Radius Validator', () => {
  const baseLimits = McpPolicyLimitsSchema.parse({
    maxIpv4PrefixLen: 24,
    maxIpv6PrefixLen: 64,
    allowedRedirectTargets: ['10.99.0.10', '10.99.0.10:2222', '10.99.1.0/24'],
  });

  const guardCtx: McpGuardContext = {
    applianceHostIps: ['192.168.1.1/24', '203.0.113.2/29'],
    gatewayAndHaIps: ['203.0.113.1', '192.168.1.2'],
    callerIp: '192.168.1.50',
    antiLockoutPorts: [2966, 22, 9876],
    policyLimits: baseLimits,
  };

  it('rejects loopback, link-local, multicast, and default route /0', () => {
    expect(validateMcpTarget('127.0.0.1', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('::1', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('169.254.10.20', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('224.0.0.18', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('0.0.0.0/0', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('::/0', guardCtx).valid).toBe(false);
  });

  it('rejects local appliance interface IPs, upstream gateways, and HA peers', () => {
    const appCheck = validateMcpTarget('192.168.1.1', guardCtx);
    expect(appCheck.valid).toBe(false);
    expect(appCheck.reason).toContain('appliance');

    const subnetOverlappingAppliance = validateMcpTarget('192.168.1.0/24', guardCtx);
    expect(subnetOverlappingAppliance.valid).toBe(false);

    const gwCheck = validateMcpTarget('203.0.113.1', guardCtx);
    expect(gwCheck.valid).toBe(false);
    expect(gwCheck.reason).toContain('gateway');

    const haCheck = validateMcpTarget('192.168.1.2', guardCtx);
    expect(haCheck.valid).toBe(false);
  });

  it('rejects the MCP client caller IP to prevent self-lockout', () => {
    const selfCheck = validateMcpTarget('192.168.1.50', guardCtx);
    expect(selfCheck.valid).toBe(false);
    expect(selfCheck.reason).toContain('self-lockout');
  });

  it('rejects anti-lockout management ports (2966, 22, 9876)', () => {
    const portCheck = validateMcpTarget('198.51.100.77', guardCtx, { port: 2966 });
    expect(portCheck.valid).toBe(false);
    expect(portCheck.reason).toContain('anti-lockout');

    const sshCheck = validateMcpTarget('198.51.100.77', guardCtx, { port: 22 });
    expect(sshCheck.valid).toBe(false);
  });

  it('enforces CIDR prefix blast-radius limits (/24 IPv4, /64 IPv6)', () => {
    expect(validateMcpTarget('198.51.0.0/16', guardCtx).valid).toBe(false);
    expect(validateMcpTarget('2001:db8::/48', guardCtx).valid).toBe(false);

    const validV4Subnet = validateMcpTarget('198.51.100.0/24', guardCtx);
    expect(validV4Subnet.valid).toBe(true);
    expect(validV4Subnet.normalizedTarget).toBe('198.51.100.0/24');

    const validV4Host = validateMcpTarget('198.51.100.42/32', guardCtx);
    expect(validV4Host.valid).toBe(true);
    expect(validV4Host.normalizedTarget).toBe('198.51.100.42');

    const validV6Subnet = validateMcpTarget('2001:db8:abcd:1234::/64', guardCtx);
    expect(validV6Subnet.valid).toBe(true);
  });

  it('enforces honeypot / redirection target allowlists', () => {
    expect(
      validateRedirectTargetAllowlist('10.99.0.10:2222', baseLimits.allowedRedirectTargets).valid
    ).toBe(true);
    expect(
      validateRedirectTargetAllowlist('10.99.1.55:8080', baseLimits.allowedRedirectTargets).valid
    ).toBe(true);
    expect(
      validateRedirectTargetAllowlist('198.51.100.99:4444', baseLimits.allowedRedirectTargets).valid
    ).toBe(false);
  });

  it('matches IPv4 and IPv6 addresses against CIDRs accurately', () => {
    expect(isIpInCidr('10.42.5.19', '10.42.0.0/16')).toBe(true);
    expect(isIpInCidr('10.43.5.19', '10.42.0.0/16')).toBe(false);
    expect(isIpInCidr('2001:db8:1::42', '2001:db8:1::/48')).toBe(true);
  });

  it('places loopback and anti-lockout rules before @blocked_ips in compiled nftables', () => {
    const state = DesiredStateSchema.parse({
      version: 1,
      system: {
        hostname: 'axonwall',
        domain: 'local',
        timezone: 'UTC',
        dnsServers: ['1.1.1.1'],
        flowtableOffload: false,
        antiLockout: {
          enabled: true,
          interfaces: ['lan'],
          ports: [2966, 22],
        },
      },
      interfaces: [
        { name: 'wan', device: 'eth0', role: 'wan', enabled: true, dhcp: true },
        { name: 'lan', device: 'eth1', role: 'lan', enabled: true, dhcp: false, ipv4Address: '192.168.1.1/24' },
      ],
      rules: [],
      nat: [],
      aliases: [],
      routes: [],
    });

    const compiled = compileNftables(state);
    const loIdx = compiled.nftScript.indexOf('iif "lo" accept');
    const antiLockoutIdx = compiled.nftScript.indexOf('comment "anti-lockout"');
    const blockedIpsIdx = compiled.nftScript.indexOf('ip saddr @blocked_ips drop');

    expect(loIdx).toBeGreaterThan(0);
    expect(antiLockoutIdx).toBeGreaterThan(loIdx);
    expect(blockedIpsIdx).toBeGreaterThan(antiLockoutIdx);
  });

  it('correctly reports master switch status via env vars and settings file (disabled by default)', async () => {
    const { isMcpServerEnabled, getMcpServerStatus } = await import('../index.js');
    
    // Default disabled
    expect(isMcpServerEnabled('/nonexistent/mcp-settings.json')).toBe(false);
    const defaultStatus = getMcpServerStatus('/nonexistent/mcp-settings.json');
    expect(defaultStatus.enabled).toBe(false);
    expect(defaultStatus.source).toBe('default');
    expect(defaultStatus.disabledReason).toMatch(/disabled by default/i);

    // Explicitly enabled via AXONWALL_MCP_ENABLED=true
    process.env.AXONWALL_MCP_ENABLED = 'true';
    expect(isMcpServerEnabled('/nonexistent/mcp-settings.json')).toBe(true);
    expect(getMcpServerStatus('/nonexistent/mcp-settings.json').source).toBe('env');
    delete process.env.AXONWALL_MCP_ENABLED;

    // Disabled via AXONWALL_MCP_ENABLED=false
    process.env.AXONWALL_MCP_ENABLED = 'false';
    expect(isMcpServerEnabled('/nonexistent/mcp-settings.json')).toBe(false);
    expect(getMcpServerStatus('/nonexistent/mcp-settings.json').source).toBe('env');
    delete process.env.AXONWALL_MCP_ENABLED;

    // Disabled via AXONWALL_DISABLE_MCP=1
    process.env.AXONWALL_DISABLE_MCP = '1';
    expect(isMcpServerEnabled('/nonexistent/mcp-settings.json')).toBe(false);
    delete process.env.AXONWALL_DISABLE_MCP;

    // Test persistent settings file
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-lib-mcp-test-'));
    const settingsPath = path.join(tmpDir, 'mcp-settings.json');

    // Explicitly enabled via settings file
    fs.writeFileSync(settingsPath, JSON.stringify({ enabled: true }));
    expect(isMcpServerEnabled(settingsPath)).toBe(true);
    expect(getMcpServerStatus(settingsPath).source).toBe('settings_file');

    // Explicitly disabled via settings file
    fs.writeFileSync(settingsPath, JSON.stringify({ enabled: false, disabledReason: 'Emergency maintenance' }));
    expect(isMcpServerEnabled(settingsPath)).toBe(false);
    const fileStatus = getMcpServerStatus(settingsPath);
    expect(fileStatus.source).toBe('settings_file');
    expect(fileStatus.disabledReason).toBe('Emergency maintenance');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('persists master-switch settings through the canonical path and verifies them (R4-B-M1)', async () => {
    const { getMcpServerStatus, saveMcpSettings, resolveMcpSettingsPath } = await import('../index.js');
    // No env override in this test: file-based status decides.
    const prevEnabled = process.env.AXONWALL_MCP_ENABLED;
    const prevDisabled = process.env.AXONWALL_DISABLE_MCP;
    const prevSettingsPath = process.env.AXONWALL_MCP_SETTINGS_PATH;
    const prevStateDir = process.env.AXONWALL_STATE_DIR;
    const prevPersistDir = process.env.AXONWALL_PERSIST_YAML_DIR;
    const prevEtcDir = process.env.AXONWALL_CONFIG_DIR;
    delete process.env.AXONWALL_MCP_ENABLED;
    delete process.env.AXONWALL_DISABLE_MCP;
    delete process.env.AXONWALL_MCP_SETTINGS_PATH;
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'axonwall-lib-mcp-settings-test-'));
    const stateDir = path.join(tmpDir, 'var');
    const persistDir = path.join(tmpDir, 'persist');
    const etcDir = path.join(tmpDir, 'etc');
    for (const d of [stateDir, persistDir, etcDir]) fs.mkdirSync(d, { recursive: true });
    process.env.AXONWALL_STATE_DIR = stateDir;
    process.env.AXONWALL_PERSIST_YAML_DIR = persistDir;
    process.env.AXONWALL_CONFIG_DIR = etcDir;
    try {
      // Canonical path is <stateDir>/mcp-settings.json.
      expect(resolveMcpSettingsPath()).toBe(path.join(stateDir, 'mcp-settings.json'));

      const disabled = saveMcpSettings({
        enabled: false,
        disabledReason: 'Disabled in test',
        disabledAt: new Date().toISOString(),
        disabledBy: 'test',
      });
      expect(disabled.ok).toBe(true);
      expect(getMcpServerStatus().enabled).toBe(false);

      // A stale enabled:true mirror must not defeat the disable.
      fs.writeFileSync(path.join(etcDir, 'mcp-settings.json'), JSON.stringify({ enabled: true }));
      fs.writeFileSync(path.join(persistDir, 'mcp-settings.json'), JSON.stringify({ enabled: true }));
      expect(getMcpServerStatus().enabled).toBe(false);
      expect(getMcpServerStatus().source).toBe('settings_file');

      // Re-enable round-trips and is visible on re-read.
      expect(saveMcpSettings({ enabled: true }).ok).toBe(true);
      expect(getMcpServerStatus().enabled).toBe(true);

      // A canonical write that cannot land reports ok:false.
      const blocker = path.join(tmpDir, 'blocker');
      fs.writeFileSync(blocker, 'not a directory');
      process.env.AXONWALL_MCP_SETTINGS_PATH = path.join(blocker, 'mcp-settings.json');
      const failed = saveMcpSettings({ enabled: false });
      expect(failed.ok).toBe(false);
      expect(failed.error || '').toMatch(/Failed to persist mcp-settings\.json to canonical path/);
    } finally {
      if (prevEnabled !== undefined) process.env.AXONWALL_MCP_ENABLED = prevEnabled;
      else delete process.env.AXONWALL_MCP_ENABLED;
      if (prevDisabled !== undefined) process.env.AXONWALL_DISABLE_MCP = prevDisabled;
      else delete process.env.AXONWALL_DISABLE_MCP;
      if (prevSettingsPath !== undefined) process.env.AXONWALL_MCP_SETTINGS_PATH = prevSettingsPath;
      else delete process.env.AXONWALL_MCP_SETTINGS_PATH;
      if (prevStateDir !== undefined) process.env.AXONWALL_STATE_DIR = prevStateDir;
      else delete process.env.AXONWALL_STATE_DIR;
      if (prevPersistDir !== undefined) process.env.AXONWALL_PERSIST_YAML_DIR = prevPersistDir;
      else delete process.env.AXONWALL_PERSIST_YAML_DIR;
      if (prevEtcDir !== undefined) process.env.AXONWALL_CONFIG_DIR = prevEtcDir;
      else delete process.env.AXONWALL_CONFIG_DIR;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('validates Linux 6.9+ BPF_TOKEN_CREATE delegation masks and rejects Ring-0 tracing programs', async () => {
    const {
      validateBpfTokenDelegationInput,
      validateVirtWorkloadSafety,
      validateZfsResourcePath,
      MCP_SCOPES,
    } = await import('../index.js');

    expect(MCP_SCOPES).toContain('mcp:ebpf:read');
    expect(MCP_SCOPES).toContain('mcp:ebpf:manage');
    expect(MCP_SCOPES).toContain('mcp:virt:manage');
    expect(MCP_SCOPES).toContain('mcp:k3s:manage');
    expect(MCP_SCOPES).toContain('mcp:nas:manage');

    expect(
      validateBpfTokenDelegationInput({
        preset: 'network-dataplane',
        delegateProgs: 'xdp:sched_cls:cgroup_skb',
      }).valid,
    ).toBe(true);

    for (const forbidden of ['kprobe', 'tracepoint', 'raw_tracepoint', 'perf_event', 'tracing', 'lsm', 'struct_ops']) {
      const res = validateBpfTokenDelegationInput({
        preset: 'custom',
        delegateCmds: 'prog_load:map_create',
        delegateProgs: `xdp:${forbidden}`,
        delegateMaps: 'hash:array',
        delegateAttachs: 'xdp',
      });
      expect(res.valid).toBe(false);
      expect(res.reason).toContain('bpf_probe_read_kernel');
    }

    expect(
      validateBpfTokenDelegationInput({
        preset: 'network-dataplane',
        delegateProgs: 'any',
      }).valid,
    ).toBe(false);

    // Hosted Edge VM anti-lockout safety
    expect(validateVirtWorkloadSafety('axonwall-edge-ngfw', 'stop', true).valid).toBe(false);
    expect(validateVirtWorkloadSafety('edge-primary', 'pause', false).valid).toBe(false);
    expect(validateVirtWorkloadSafety('app-worker-01', 'stop', true).valid).toBe(true);

    // B-M5: fail closed when the workload name cannot be resolved —
    // a destructive action on an unknown target must not proceed blind.
    expect(validateVirtWorkloadSafety(undefined, 'stop', true).valid).toBe(false);
    expect(validateVirtWorkloadSafety('', 'pause', false).valid).toBe(false);
    expect(validateVirtWorkloadSafety(undefined, 'stop', false).valid).toBe(false);
    // ... but non-destructive actions on an unknown target stay allowed.
    expect(validateVirtWorkloadSafety(undefined, 'start', true).valid).toBe(true);
    expect(validateVirtWorkloadSafety(undefined, 'snapshot', true).valid).toBe(true);
    // B-M5: identity-based guard — a hosted-edge VM renamed to a plain
    // name is still recognised by its compiled vmid/id when hosted
    // edge is enabled, and not when it is disabled.
    expect(validateVirtWorkloadSafety('fw-01', 'stop', true, 100).valid).toBe(false);
    expect(validateVirtWorkloadSafety('fw-01', 'stop', true, 'edge').valid).toBe(false);
    expect(validateVirtWorkloadSafety('fw-01', 'stop', false, 100).valid).toBe(true);
    expect(validateVirtWorkloadSafety('fw-01', 'stop', true, 101).valid).toBe(true);

    // ZFS resource sanitization
    expect(validateZfsResourcePath('tank/vms', true).valid).toBe(true);
    expect(validateZfsResourcePath('tank/vms', false).valid).toBe(false);
    expect(validateZfsResourcePath('-o mountpoint=/root', true).valid).toBe(false);
    expect(validateZfsResourcePath('tank@snap', true).valid).toBe(false);
  });
});
