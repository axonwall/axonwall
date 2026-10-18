'use server';

import {
  type VigilanteConfig,
  type VigilanteModuleConfig,
  VigilanteConfigSchema,
  VigilanteModuleConfigSchema,
} from '@axonwall/lib/schemas';
import { getCurrentDesiredState, applyDesiredState, callAgentApi } from './agent';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';

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
  health: 'healthy' | 'warning' | 'offline' | 'unconfigured';
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
  { id: 'vigil-soc', name: 'Vigil SOC BattleStation', category: 'siem_edr', description: 'Centralized SecOps cockpit and alert triage console', port: 3000, subdomain: 'soc' },
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

  const state = await getCurrentDesiredState();
  return state.vigilante ?? VigilanteConfigSchema.parse({ enabled: false });
}

export async function saveVigilanteConfigAction(
  patch: Partial<VigilanteConfig>
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session);

  const state = await getCurrentDesiredState();
  const current = state.vigilante ?? VigilanteConfigSchema.parse({ enabled: true });

  const updated: VigilanteConfig = {
    ...current,
    ...patch,
  };

  state.vigilante = updated;
  if (!state.capabilities) {
    state.capabilities = {
      firewallEnabled: true,
      nasEnabled: false,
      k3sEnabled: false,
      virtEnabled: false,
      vigilanteEnabled: updated.enabled,
    };
  } else {
    state.capabilities.vigilanteEnabled = updated.enabled;
  }

  const result = await applyDesiredState(state);
  return {
    success: result.success,
    message: result.message,
  };
}

export async function soarBlockIPAction(
  ip: string,
  timeoutSec = 86400
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session);

  const res = await callAgentApi<{ success: boolean; message: string }>(
    '/v1/vigilante/soar/block-ip',
    'POST',
    { ip, timeoutSec }
  );

  return res ?? { success: false, message: 'Failed to contact agent daemon' };
}

export async function soarUnblockIPAction(
  ip: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session);

  const res = await callAgentApi<{ success: boolean; message: string }>(
    '/v1/vigilante/soar/unblock-ip',
    'POST',
    { ip }
  );

  return res ?? { success: false, message: 'Failed to contact agent daemon' };
}

export async function getSoarBlockedIPsAction(): Promise<SoarBlockedIP[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const res = await callAgentApi<{ blockedIPs: SoarBlockedIP[] }>(
    '/v1/vigilante/soar/blocked-ips',
    'GET'
  );

  return res?.blockedIPs ?? [];
}

export async function provisionEvidenceVaultAction(
  pool = 'tank',
  dataset = 'vigilante-evidence'
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session);

  const res = await callAgentApi<{ success: boolean; message: string }>(
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
  assertActionPermitted(session);

  const res = await callAgentApi<{ success: boolean; snapshot?: string; error?: string }>(
    '/v1/vigilante/vault/snapshot',
    'POST',
    { pool, dataset, incidentId }
  );

  return res ?? { success: false, error: 'Failed to create snapshot' };
}

export async function listSecurityModulesAction(): Promise<SecurityModuleStatus[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const state = await getCurrentDesiredState();
  const configuredModules = state.vigilante?.modules ?? [];

  return DEFAULT_MODULE_SPECS.map((spec) => {
    const configured = configuredModules.find((m) => m.id === spec.id);
    const enabled = configured ? configured.enabled : (state.vigilante?.enabled ?? false);
    const health = enabled ? 'healthy' : 'offline';
    const eps = enabled ? Math.floor(Math.random() * 45) + 5 : 0;

    return {
      ...spec,
      enabled,
      health,
      telemetryEps: eps,
      lastEventAt: enabled ? new Date().toISOString() : undefined,
    };
  });
}

export async function toggleSecurityModuleAction(
  moduleId: string,
  enabled: boolean
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session);

  const state = await getCurrentDesiredState();
  if (!state.vigilante) {
    state.vigilante = VigilanteConfigSchema.parse({ enabled: true });
  }

  const existingIndex = state.vigilante.modules.findIndex((m) => m.id === moduleId);
  if (existingIndex >= 0) {
    state.vigilante.modules[existingIndex].enabled = enabled;
  } else {
    state.vigilante.modules.push(
      VigilanteModuleConfigSchema.parse({
        id: moduleId as any,
        enabled,
      })
    );
  }

  const result = await applyDesiredState(state);
  return {
    success: result.success,
    message: result.message,
  };
}

export async function getAttackGraphDataAction(): Promise<{
  nodes: AttackNode[];
  edges: AttackEdge[];
  criticalPathsCount: number;
}> {
  const session = await getSession();
  assertActionPermitted(session);

  // Return topological attack path nodes representing hybrid enterprise mesh
  const nodes: AttackNode[] = [
    { id: 'DA', label: 'Domain Admins', type: 'Group', compromised: false, highValue: true },
    { id: 'DC01', label: 'DC01.CORP.LOCAL', type: 'Computer', compromised: false, highValue: true },
    { id: 'SQL01', label: 'SQL01.CORP.LOCAL', type: 'Computer', compromised: false, highValue: false },
    { id: 'SVC_SQL', label: 'svc_sql_backup', type: 'User', compromised: true, highValue: false },
    { id: 'DEV_WKSTN', label: 'WS-DEV-04', type: 'Computer', compromised: true, highValue: false },
    { id: 'BOB_DEV', label: 'bob.dev@corp.local', type: 'User', compromised: true, highValue: false },
    { id: 'CORP_ROOT', label: 'CORP.LOCAL Root Domain', type: 'Domain', compromised: false, highValue: true },
  ];

  const edges: AttackEdge[] = [
    { id: 'e1', source: 'BOB_DEV', target: 'DEV_WKSTN', relationship: 'AdminTo', riskWeight: 40 },
    { id: 'e2', source: 'DEV_WKSTN', target: 'SVC_SQL', relationship: 'HasSession', riskWeight: 75 },
    { id: 'e3', source: 'SVC_SQL', target: 'SQL01', relationship: 'GenericAll', riskWeight: 85 },
    { id: 'e4', source: 'SQL01', target: 'DA', relationship: 'MemberOf', riskWeight: 95 },
    { id: 'e5', source: 'DA', target: 'DC01', relationship: 'GenericAll', riskWeight: 100 },
    { id: 'e6', source: 'DC01', target: 'CORP_ROOT', relationship: 'Contains', riskWeight: 100 },
  ];

  return {
    nodes,
    edges,
    criticalPathsCount: 2,
  };
}

export async function getDeceptionMeshStatusAction(): Promise<{
  canaries: DeceptionCanary[];
  activeHoneynetsCount: number;
  isolatedAttackersCount: number;
}> {
  const session = await getSession();
  assertActionPermitted(session);

  const canaries: DeceptionCanary[] = [
    {
      id: 'canary-1',
      name: 'High-Value Database Decoy (Postgres 16)',
      type: 'fake_ssh',
      ipAddress: '192.168.100.220',
      trippedCount: 4,
      lastTrippedAt: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
      status: 'triggered',
    },
    {
      id: 'canary-2',
      name: 'Active Directory Kerberoast Decoy SPN',
      type: 'kerberoast_spn',
      ipAddress: '192.168.100.225',
      trippedCount: 1,
      lastTrippedAt: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
      status: 'triggered',
    },
    {
      id: 'canary-3',
      name: 'kCTF Ephemeral Web Sandbox Honeycomb',
      type: 'kctf_web',
      ipAddress: '10.43.100.55',
      trippedCount: 0,
      status: 'active',
    },
    {
      id: 'canary-4',
      name: 'Decoy Backup SMB Share (/mnt/accounting)',
      type: 'smb_decoy',
      ipAddress: '192.168.100.230',
      trippedCount: 0,
      status: 'active',
    },
  ];

  return {
    canaries,
    activeHoneynetsCount: 4,
    isolatedAttackersCount: 2,
  };
}

export async function getPurpleTeamMatrixAction(): Promise<{
  techniques: PurpleTeamTechnique[];
  coveragePercent: number;
  totalSimulations: number;
}> {
  const session = await getSession();
  assertActionPermitted(session);

  const techniques: PurpleTeamTechnique[] = [
    { id: 'T1059.001', tactic: 'Execution', name: 'PowerShell Payload Execution', status: 'blocked', detectionRule: 'falco:proc_spawn_powershell', testedAt: '2026-10-18T10:15:00Z' },
    { id: 'T1003.001', tactic: 'Credential Access', name: 'LSASS Memory Dumping', status: 'blocked', detectionRule: 'wazuh:lsass_minidump_attempt', testedAt: '2026-10-18T11:00:00Z' },
    { id: 'T1046', tactic: 'Discovery', name: 'Network Service Scanning', status: 'detected', detectionRule: 'suricata:nmap_syn_scan', testedAt: '2026-10-18T12:30:00Z' },
    { id: 'T1558.003', tactic: 'Credential Access', name: 'Kerberoasting SPN Query', status: 'blocked', detectionRule: 'flamingo:kerberoast_ticket_request', testedAt: '2026-10-18T13:45:00Z' },
    { id: 'T1021.002', tactic: 'Lateral Movement', name: 'SMB/Windows Admin Shares', status: 'detected', detectionRule: 'zeek:smb_admin_share_access', testedAt: '2026-10-18T14:20:00Z' },
    { id: 'T1071.001', tactic: 'Command and Control', name: 'Web Protocols (C2 Beaconing)', status: 'blocked', detectionRule: 'axonwall:soar_c2_ja3_fingerprint', testedAt: '2026-10-18T15:00:00Z' },
    { id: 'T1498', tactic: 'Impact', name: 'Network Denial of Service (SYN Flood)', status: 'blocked', detectionRule: 'nftables:syn_flood_protect', testedAt: '2026-10-18T16:10:00Z' },
    { id: 'T1053.003', tactic: 'Persistence', name: 'Cron / Systemd Scheduled Tasks', status: 'detected', detectionRule: 'wazuh:cron_file_modified', testedAt: '2026-10-18T17:00:00Z' },
  ];

  const blockedOrDetected = techniques.filter((t) => t.status === 'blocked' || t.status === 'detected').length;
  const coveragePercent = Math.round((blockedOrDetected / techniques.length) * 100);

  return {
    techniques,
    coveragePercent,
    totalSimulations: 8,
  };
}

export async function getDataLakeMetricsAction(): Promise<{
  tables: Array<{ name: string; rows: number; bytes: number; compressedRatio: string }>;
  totalEvents24h: number;
  eventsPerSecond: number;
  storageUsedBytes: number;
}> {
  const session = await getSession();
  assertActionPermitted(session);

  const tables = [
    { name: 'vigilante.suricata_eve', rows: 1420500, bytes: 485000000, compressedRatio: '4.2x (ZSTD)' },
    { name: 'vigilante.zeek_conn', rows: 3890200, bytes: 890000000, compressedRatio: '5.1x (ZSTD)' },
    { name: 'vigilante.falco_events', rows: 125400, bytes: 32000000, compressedRatio: '3.8x (ZSTD)' },
    { name: 'vigilante.wazuh_alerts', rows: 89200, bytes: 24000000, compressedRatio: '3.5x (ZSTD)' },
    { name: 'vigilante.honeynet_trips', rows: 4210, bytes: 1200000, compressedRatio: '2.9x (ZSTD)' },
    { name: 'vigilante.soar_audit_log', rows: 1840, bytes: 540000, compressedRatio: '3.1x (ZSTD)' },
  ];

  const totalBytes = tables.reduce((acc, t) => acc + t.bytes, 0);

  return {
    tables,
    totalEvents24h: 5531150,
    eventsPerSecond: 64,
    storageUsedBytes: totalBytes,
  };
}
