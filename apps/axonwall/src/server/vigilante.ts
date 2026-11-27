'use server';

import net from 'node:net';
import {
  type VigilanteConfig,
  type VigilanteModuleConfig,
  VigilanteConfigSchema,
  VigilanteModuleConfigSchema,
} from '@axonwall/lib/schemas';
import { enablePluginWithDependencies } from '@axonwall/lib/plugins';
import { getCurrentDesiredState, applyDesiredState } from './agent';
import { callAgentApi, callAgentApiResponse } from './agent-client';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { getDesiredStateInternal } from './desired-state-internal';
import { assertPluginEnabled } from './plugin-guard';
import { queryDataLakeMetrics, type DataLakeMetricsSnapshot } from './clickhouse';

function validateIpOrCidr(raw: string): string {
  const trimmed = (raw || '').trim();
  if (!trimmed) {
    throw new Error('Invalid IP or CIDR address');
  }
  const parts = trimmed.split('/');
  if (parts.length > 2) {
    throw new Error('Invalid IP or CIDR address');
  }
  const ipPart = parts[0] || '';
  const family = net.isIP(ipPart);
  if (family === 0) {
    throw new Error('Invalid IP or CIDR address');
  }
  if (parts.length === 2) {
    const prefixStr = parts[1] || '';
    if (!/^\d+$/.test(prefixStr)) {
      throw new Error('Invalid CIDR prefix length');
    }
    const prefix = Number(prefixStr);
    const maxPrefix = family === 4 ? 32 : 128;
    if (prefix < 0 || prefix > maxPrefix) {
      throw new Error('Invalid CIDR prefix length');
    }
  }
  return trimmed;
}

export interface SoarBlockedIP {
  ip: string;
  family: string;
  blockedAt: string;
  expiresAt?: string;
}

export interface SecurityModuleStatus {
  id: string;
  name: string;
  category: 'threat_detection' | 'deception' | 'ad_identity' | 'vulnerability' | 'siem_edr' | 'purple_team';
  description: string;
  enabled: boolean;
  health: 'healthy' | 'warning' | 'offline' | 'unconfigured' | 'unknown';
  port: number;
  subdomain: string;
  telemetryEps: number;
  lastEventAt?: string;
}

export interface AttackNode {
  id: string;
  label: string;
  type: 'User' | 'Group' | 'Computer' | 'Domain' | 'GPO' | 'OU';
  compromised: boolean;
  highValue: boolean;
}

export interface AttackEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  riskWeight: number;
}

export interface PurpleTeamTechnique {
  id: string;
  tactic: string;
  name: string;
  testedAt?: string;
  status: 'passed' | 'detected' | 'blocked' | 'untested';
  detectionRule?: string;
}

export interface DeceptionCanary {
  id: string;
  name: string;
  type: 'fake_ssh' | 'smb_decoy' | 'kctf_web' | 'kerberoast_spn' | 'dns_canary';
  ipAddress: string;
  trippedCount: number;
  lastTrippedAt?: string;
  status: 'active' | 'triggered' | 'standby';
}

const DEFAULT_MODULE_SPECS: Array<Omit<SecurityModuleStatus, 'enabled' | 'health' | 'telemetryEps' | 'lastEventAt'>> = [
  { id: 'vigil-soc', name: 'Vigil SOC BattleStation', category: 'siem_edr', description: 'Centralized SecOps cockpit and alert triage console', port: 3000, subdomain: 'vigil' },
  { id: 'vigil-local', name: 'Vigil Local Agent', category: 'threat_detection', description: 'Local autonomous threat response sensor', port: 9100, subdomain: 'local-soc' },
  { id: 'kctf', name: 'kCTF HoneyMesh & Flags', category: 'deception', description: 'Isolated sandbox honeynets and dynamic canary services', port: 8080, subdomain: 'kctf' },
  { id: 'openvas', name: 'OpenVAS / Greenbone Scanner', category: 'vulnerability', description: 'Comprehensive network vulnerability and CVE assessment', port: 9392, subdomain: 'openvas' },
  { id: 'wazuh', name: 'Wazuh SIEM & EDR Core', category: 'siem_edr', description: 'Host-level intrusion detection, integrity monitoring and compliance', port: 55000, subdomain: 'wazuh' },
  { id: 'flamingo', name: 'Flamingo Identity Analyzer', category: 'ad_identity', description: 'Active Directory privilege escalation and Kerberos auditor', port: 8088, subdomain: 'flamingo' },
  { id: 'falco', name: 'Falco Kernel Sensor', category: 'threat_detection', description: 'Cloud-native runtime threat detection via Linux eBPF', port: 8765, subdomain: 'falco' },
  { id: 'suricata', name: 'Suricata NIDS Engine', category: 'threat_detection', description: 'High-performance multi-threaded network threat inspection', port: 8000, subdomain: 'suricata' },
  { id: 'zeek', name: 'Zeek Protocol Metadata Engine', category: 'threat_detection', description: 'Behavioral protocol analysis and transaction logging', port: 47761, subdomain: 'zeek' },
  { id: 'zap', name: 'OWASP ZAP DAST Scanner', category: 'vulnerability', description: 'Automated dynamic web application security scanning', port: 8081, subdomain: 'zap' },
  { id: 'bloodhound', name: 'BloodHound Attack Paths', category: 'ad_identity', description: 'Active Directory graph visualization and attack path discovery', port: 7474, subdomain: 'bloodhound' },
  { id: 'purpleteam', name: 'Purple Team Adversary Emulator', category: 'purple_team', description: 'Automated MITRE ATT&CK adversary emulation & coverage testing', port: 8888, subdomain: 'purpleteam' },
];

export async function getVigilanteConfigAction(): Promise<VigilanteConfig> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-vigilante');

  const state = await getCurrentDesiredState();
  return state.vigilante ?? VigilanteConfigSchema.parse({ enabled: false });
}

export async function saveVigilanteConfigAction(
  patch: Partial<VigilanteConfig>,
  // C2: fingerprint captured by the calling page at load time; the apply
  // is refused instead of silently overwriting newer on-disk state.
  options?: { expectedFingerprint?: string }
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('core-vigilante');

  let state = await getCurrentDesiredState();
  const current = state.vigilante ?? VigilanteConfigSchema.parse({ enabled: true });

  const updated: VigilanteConfig = {
    ...current,
    ...patch,
  };

  state.vigilante = updated;
  if (updated.enabled) {
    const depRes = enablePluginWithDependencies('core-vigilante', state);
    state = depRes.state;
    state.vigilante = updated;
  } else if (!state.capabilities) {
    state.capabilities = {
      firewallEnabled: true,
      nasEnabled: false,
      k3sEnabled: false,
      virtEnabled: false,
      vigilanteEnabled: false,
    };
  } else {
    state.capabilities.vigilanteEnabled = false;
  }

  // C2: a fingerprint mismatch is an expected conflict, not a crash —
  // return it as a failure result so the page can tell the operator to
  // reload instead of surfacing an unhandled rejection.
  try {
    const result = await applyDesiredState(
      state,
      120,
      options?.expectedFingerprint ? { expectedFingerprint: options.expectedFingerprint } : undefined
    );
    return {
      success: result.success,
      message: result.message,
    };
  } catch (err: any) {
    // C-B2 residual: a daemon-down apply throws 'axonwalld is
    // unreachable' — same as a fingerprint conflict, return it as a
    // failure result so the page can tell the operator nothing was
    // applied instead of surfacing an unhandled rejection.
    if (
      err?.message?.includes('Configuration changed since it was loaded') ||
      err?.message?.includes('axonwalld is unreachable')
    ) {
      return { success: false, message: err.message };
    }
    throw err;
  }
}

export async function soarBlockIPAction(
  ip: string,
  timeoutSec = 86400
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');
  await assertPluginEnabled('core-vigilante');
  const validIp = validateIpOrCidr(ip);

  const res = await callAgentApiResponse<{ success: boolean; message: string }>(
    '/v1/vigilante/soar/block-ip',
    'POST',
    { ip: validIp, timeoutSec }
  );

  return res ?? { success: false, message: 'Failed to contact agent daemon' };
}

export async function soarUnblockIPAction(
  ip: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');
  await assertPluginEnabled('core-vigilante');
  const validIp = validateIpOrCidr(ip);

  const res = await callAgentApiResponse<{ success: boolean; message: string }>(
    '/v1/vigilante/soar/unblock-ip',
    'POST',
    { ip: validIp }
  );

  return res ?? { success: false, message: 'Failed to contact agent daemon' };
}

export async function getSoarBlockedIPsAction(): Promise<SoarBlockedIP[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-vigilante');

  const res = await callAgentApi<{ blockedIPs: SoarBlockedIP[] }>(
    '/v1/vigilante/soar/blocked-ips',
    'GET'
  );

  // C25: a daemon outage used to collapse to "0 blocked IPs / nothing under
  // SOAR quarantine" mid-incident. Throw so the page shows an unknown state
  // and keeps its previous list instead of an empty one.
  if (!res?.blockedIPs) {
    throw new Error('Daemon unavailable: could not load SOAR blocked IPs from axonwalld');
  }
  return res.blockedIPs;
}

export async function provisionEvidenceVaultAction(
  pool = 'tank',
  dataset = 'vigilante-evidence'
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('core-vigilante');

  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(pool) || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(dataset)) {
    return { success: false, message: 'Invalid ZFS pool or dataset name' };
  }

  const res = await callAgentApiResponse<{ success: boolean; message: string }>(
    '/v1/vigilante/vault/provision',
    'POST',
    { pool, dataset }
  );

  return res ?? { success: false, message: 'Failed to provision evidence vault' };
}

export async function createIncidentSnapshotAction(
  pool: string,
  dataset: string,
  incidentId: string
): Promise<{ success: boolean; snapshot?: string; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');
  await assertPluginEnabled('core-vigilante');

  if (
    !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(pool) ||
    !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(dataset) ||
    !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(incidentId)
  ) {
    return { success: false, error: 'Invalid pool, dataset, or incident ID format' };
  }

  const res = await callAgentApiResponse<{ success: boolean; snapshot?: string; error?: string }>(
    '/v1/vigilante/vault/snapshot',
    'POST',
    { pool, dataset, incidentId }
  );

  return res ?? { success: false, error: 'Failed to create snapshot' };
}

export async function listSecurityModulesAction(): Promise<SecurityModuleStatus[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-vigilante');

  const state = await getCurrentDesiredState();
  const configuredModules = state.vigilante?.modules ?? [];

  return DEFAULT_MODULE_SPECS.map((spec) => {
    const configured = configuredModules.find((m) => m.id === spec.id);
    const enabled = configured ? configured.enabled : (state.vigilante?.enabled ?? false);
    // D15: no module is ever probed (no port check, process check, or
    // daemon query), so an enabled module's health is unknown — never
    // "healthy" just because it is enabled — and its throughput is
    // unmeasured (0 EPS, no last-event time). A disabled module is
    // genuinely offline. Do not invent a random 5–49 EPS.
    const health = enabled ? 'unknown' : 'offline';
    const eps = 0;

    return {
      ...spec,
      enabled,
      health,
      telemetryEps: eps,
      lastEventAt: undefined,
    };
  });
}

export async function updateVigilanteDomainAction(
  domain: string,
  options?: { expectedFingerprint?: string }
): Promise<{ success: boolean; message: string; domain?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('core-vigilante');

  const trimmed = (domain || '').trim().toLowerCase();
  if (!trimmed || trimmed.length > 253 || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(trimmed)) {
    return { success: false, message: 'Invalid domain name (e.g. vigilante.local or soc.example.com)' };
  }

  let state = await getCurrentDesiredState();
  if (!state.vigilante) {
    state.vigilante = VigilanteConfigSchema.parse({ enabled: true, domain: trimmed });
  } else {
    state.vigilante.domain = trimmed;
  }

  try {
    const result = await applyDesiredState(
      state,
      120,
      options?.expectedFingerprint ? { expectedFingerprint: options.expectedFingerprint } : undefined
    );
    return {
      success: result.success,
      message: result.message,
      domain: trimmed,
    };
  } catch (err: any) {
    if (
      err?.message?.includes('Configuration changed since it was loaded') ||
      err?.message?.includes('axonwalld is unreachable')
    ) {
      return { success: false, message: err.message };
    }
    return { success: false, message: err?.message || 'Failed to update Vigilante domain' };
  }
}

export async function toggleSecurityModuleAction(
  moduleId: string,
  enabled: boolean,
  // C2: fingerprint captured by the calling page at load time; see
  // saveVigilanteConfigAction above.
  options?: { expectedFingerprint?: string }
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('core-vigilante');

  let state = await getCurrentDesiredState();
  if (!state.vigilante) {
    state.vigilante = VigilanteConfigSchema.parse({ enabled: true });
  }
  if (enabled || state.vigilante.enabled) {
    const depRes = enablePluginWithDependencies('core-vigilante', state);
    state = depRes.state;
  }

  const existingIndex = state.vigilante!.modules.findIndex((m) => m.id === moduleId);
  if (existingIndex >= 0) {
    state.vigilante!.modules[existingIndex].enabled = enabled;
  } else {
    state.vigilante!.modules.push(
      VigilanteModuleConfigSchema.parse({
        id: moduleId as any,
        enabled,
      })
    );
  }

  // C2: a fingerprint mismatch is an expected conflict, not a crash —
  // return it as a failure result so the page can tell the operator to
  // reload instead of surfacing an unhandled rejection.
  try {
    const result = await applyDesiredState(
      state,
      120,
      options?.expectedFingerprint ? { expectedFingerprint: options.expectedFingerprint } : undefined
    );
    return {
      success: result.success,
      message: result.message,
    };
  } catch (err: any) {
    // C-B2 residual: a daemon-down apply throws 'axonwalld is
    // unreachable' — same as a fingerprint conflict, return it as a
    // failure result so the page can tell the operator nothing was
    // applied instead of surfacing an unhandled rejection.
    if (
      err?.message?.includes('Configuration changed since it was loaded') ||
      err?.message?.includes('axonwalld is unreachable')
    ) {
      return { success: false, message: err.message };
    }
    throw err;
  }
}

export async function getAttackGraphDataAction(): Promise<{
  nodes: AttackNode[];
  edges: AttackEdge[];
  criticalPathsCount: number;
}> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-vigilante');

  return {
    nodes: [],
    edges: [],
    criticalPathsCount: 0,
  };
}

export async function getDeceptionMeshStatusAction(): Promise<{
  canaries: DeceptionCanary[];
  activeHoneynetsCount: number;
  isolatedAttackersCount: number;
}> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-vigilante');

  return {
    canaries: [],
    activeHoneynetsCount: 0,
    isolatedAttackersCount: 0,
  };
}

export async function getPurpleTeamMatrixAction(): Promise<{
  techniques: PurpleTeamTechnique[];
  coveragePercent: number;
  totalSimulations: number;
}> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-vigilante');

  return {
    techniques: [],
    coveragePercent: 0,
    totalSimulations: 0,
  };
}

export async function getDataLakeMetricsAction(): Promise<DataLakeMetricsSnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-vigilante');

  const state = await getDesiredStateInternal().catch(() => null);
  return queryDataLakeMetrics(state?.observability?.clickhouse);
}
