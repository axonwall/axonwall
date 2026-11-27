'use server';

import { compileNftables } from '@axonwall/lib/compile/nft';
import { buildNetBoxSyncPlan, resolveNetBoxConfig } from '@axonwall/lib/compile/netbox';
import { buildLibreNmsEnrollmentPlan, resolveLibreNmsConfig } from '@axonwall/lib/compile/librenms';
import { lintRuleset } from '@axonwall/lib/lint';
import {
  DesiredStateSchema,
  InterfaceSchema,
  ThreatHarvesterConfigSchema,
  inferInterfaceRole,
  isInterfaceAuthoritativeDhcp,
  type DesiredState,
  type InterfaceRole,
  type ThreatHarvesterConfig,
} from '@axonwall/lib/schemas';
import { isValidDevice } from '@axonwall/lib/util';
import {
  AXONWALL_YAML_FILENAMES,
  serializeDesiredStateToYamlFiles,
  serializeDesiredStateToSingleYaml,
  validateYamlConfigFiles,
} from '@axonwall/lib/yaml';
import {
  parseStorageFromLsblk,
  buildCloudInitFromSystem,
  exportCloudInitYaml,
  generateCloudInitMetaData,
  type CloudInitExportOptions,
  type HostIntrospectionData,
} from '@axonwall/lib/cloudinit';
import {
  McpApiKeySchema,
  McpPolicyLimitsSchema,
  McpSettingsSchema,
  isMcpServerEnabled,
  getMcpServerStatus,
  resolveMcpSettingsPath,
  type McpApiKey,
  type McpApiKeyPublic,
  type McpAuditLogEntry,
  type McpPolicyLimits,
  type McpScope,
  type McpTacticalLease,
  type McpServerStatus,
} from '@axonwall/lib/mcp';
import { isPluginEnabled } from '@axonwall/lib/plugins';
import http from 'node:http';
import os from 'node:os';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import dns from 'node:dns';
import { execSync, execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { getSession } from './auth';
import { assertActionPermitted, assertInteractiveSession, isPasswordChangeEnforced } from './auth-guard';
import { assertPluginEnabled } from './plugin-guard';
import {
  assertSafeOutboundUrl,
  createPinnedLookup,
  isDisallowedSsrfIp,
  isLoopbackSsrfIp,
  ssrfSafeFetch,
} from './ssrf-guard';
import type { UserSession } from '@axonwall/lib/rbac';
import { headers } from 'next/headers';
import {
  normalizeEbpfOverviewResponse,
  createEmptyKernelBpfInventory,
  createEmptyKernelRca,
  createEmptySoftnetTelemetry,
  createEmptyKernelSocketTelemetry,
  FORBIDDEN_RING0_PROG_TYPES,
  type BpfTokenProfileStatus,
  type BpfTokenCapabilityReport,
  type XdpVerdictStats,
  type XdpPerCpuStat,
  type XdpFlowEntry,
  type XdpProtocolSummary,
  type XdpPortSummary,
  type XdpVlanSummary,
  type XdpSynMeterEntry,
  type XdpBlockedEntry,
  type BpfLsmAllowlistEntry,
  type BpfLsmEventEntry,
  type BpfProgramInventoryItem,
  type BpfMapInventoryItem,
  type BpfTypeAggregate,
  type KernelBpfInventory,
  type KernelRcaTelemetry,
  type NetdevTrafficStat,
  type VirtWorkloadSummary,
  type NasPoolIoStat,
  type ThreatHarvesterOverviewSummary,
  type ZfsDeepTelemetry,
  type VirtDutyTelemetry,
  type K3sDutyTelemetry,
  type EbpfOverviewTelemetry,
} from '@/lib/ebpf-telemetry';

const execFileAsync = promisify(execFile);

import { callAgentApi, callAgentApiDetailed, callAgentApiResponse } from './agent-client';
import type {
  K3sClusterPulse,
  K3sAPIResource,
  K3sNamespaceSummary,
  K3sResourceListResponse,
  K3sResourceInspectResponse,
  K3sLogsResponse,
  K3sActionRequest,
  K3sActionResponse,
} from '@/components/k3s/types';
import {
  BASELINE_STATE,
  ETC_CONFIG_DIR,
  PERSIST_CONFIG_DIR,
  YAML_CONFIG_DIRS,
  computeSubnetAndDefaultPool,
  findOverlappingSubnet,
  getDesiredStateInternal,
  invalidateDesiredStateCacheInternal,
  ipToUint32,
  persistDesiredStateToDisk,
  prepareDesiredStateBundle,
  readAllYamlConfigFiles,
  readLiveKernelIpv4Addrs,
  writeConfigFileSafe,
} from './desired-state-internal';
import {
  getStateDir,
  isApplianceRuntime,
  isDevRuntime,
  isVirtualOrLoopbackInterface,
  readHostOSRelease,
} from './dev-paths';
import {
  buildDaemonBundleFiles,
  clearMockPendingConfirm,
  getLastPendingJobId,
  getMockApplyState,
  isDevModeRuntimeInternal,
  runDesiredStateApplyPipeline,
  setLastPendingJobId,
} from './apply-state-internal';

function isDevModeRuntime(): boolean {
  return isDevModeRuntimeInternal();
}

export interface AgentStatus {
  nodeId: string;
  version: string;
  uptimeSeconds: number;
  activeBundleHash: string;
  pendingConfirm: boolean;
  confirmDeadlineUnix: number;
  // R4-C-H1: true when axonwalld did not answer /v1/status, so every
  // daemon-sourced field below is UNKNOWN (not a live measurement).
  // Consumers must render an explicit "daemon unavailable" state
  // instead of treating the placeholders as live data.
  daemonDown: boolean;
  osName?: string;
  osId?: string;
  osFamily?: string;
  kernelVersion?: string;
  runtimeMode?: string;
  interfaces: Array<{
    name: string;
    device: string;
    isUp: boolean;
    ipAddresses: string[];
  }>;
}

const actionRateLimit = new Map<string, { count: number, resetAt: number }>();

async function enforceRateLimit(maxRequests = 20, windowMs = 60000, keySuffix = '') {
  let clientIp = '127.0.0.1';
  try {
    const reqHeaders = await headers();
    const rawXff = reqHeaders.get('x-forwarded-for');
    if (rawXff) {
      const parts = rawXff.split(',').map((p) => p.trim()).filter(Boolean);
      clientIp = parts[parts.length - 1] || '127.0.0.1';
    } else {
      clientIp = reqHeaders.get('x-real-ip') || '127.0.0.1';
    }
  } catch {}

  // Authenticated callers are limited per user, independent of any
  // client-supplied forwarding header (which is spoofable when the UI
  // port is reached directly). Only anonymous callers fall back to IP.
  let limiterKey = `ip:${clientIp}`;
  try {
    const session = await getSession();
    if (session?.username) {
      limiterKey = `user:${session.username}`;
    }
  } catch {}

  if (keySuffix) {
    limiterKey += `:${keySuffix}`;
  }

  const now = Date.now();
  const record = actionRateLimit.get(limiterKey);

  // Clean up old entries occasionally or when size reaches 10,000 to prevent memory leaks
  if (Math.random() < 0.05 || actionRateLimit.size >= 10000) {
    for (const [key, val] of actionRateLimit.entries()) {
      if (now > val.resetAt) actionRateLimit.delete(key);
    }
    if (actionRateLimit.size >= 10000) {
      const oldestKey = actionRateLimit.keys().next().value;
      if (oldestKey !== undefined) actionRateLimit.delete(oldestKey);
    }
  }

  if (record) {
    if (now > record.resetAt) {
      actionRateLimit.set(limiterKey, { count: 1, resetAt: now + windowMs });
    } else {
      if (record.count >= maxRequests) {
        throw new Error('Too Many Requests');
      }
      record.count += 1;
    }
  } else {
    actionRateLimit.set(limiterKey, { count: 1, resetAt: now + windowMs });
  }
}

export async function getAgentStatus(): Promise<AgentStatus> {
  const session = await getSession();
  assertActionPermitted(session);

  const hostOs = readHostOSRelease();
  const fallbackMode = isApplianceRuntime() ? 'appliance' : isDevRuntime() ? 'dev' : 'host';

  // Try live communication with root daemon over Unix socket first
  const daemonStatus = await callAgentApi<any>('/v1/status');
  if (daemonStatus) {
    return {
      nodeId: daemonStatus.node_id || daemonStatus.nodeId || `axonwall-${os.hostname()}`,
      // R4-C-H1: a daemon that answers without a version / bundle hash /
      // uptime is UNKNOWN on those fields — never stamp the UI's own
      // version, a placeholder hash, or the UI host's uptime onto it.
      // (Main's only change here was bumping the stale literal
      // '0.12.3' → '0.12.4'; the literal itself is the bug this fix
      // removes, so the branch version stands.)
      version: daemonStatus.version || 'UNKNOWN',
      uptimeSeconds: Number(daemonStatus.uptime_seconds ?? daemonStatus.uptimeSeconds ?? 0),
      activeBundleHash: daemonStatus.active_bundle_hash || daemonStatus.activeBundleHash || 'UNKNOWN',
      pendingConfirm: Boolean(daemonStatus.pending_confirm ?? daemonStatus.pendingConfirm),
      confirmDeadlineUnix: Number(daemonStatus.confirm_deadline_unix || daemonStatus.confirmDeadlineUnix || 0),
      osName: daemonStatus.os_name || hostOs.prettyName,
      osId: daemonStatus.os_id || hostOs.id,
      osFamily: daemonStatus.os_family || hostOs.family,
      kernelVersion: daemonStatus.kernel_version || hostOs.kernelVersion,
      runtimeMode: daemonStatus.runtime_mode || fallbackMode,
      interfaces: (daemonStatus.interfaces || []).map((iface: any) => ({
        name: iface.name || iface.device,
        device: iface.device || iface.name,
        isUp: Boolean(iface.is_up ?? iface.isUp),
        ipAddresses: iface.ip_addresses || iface.ipAddresses || [],
      })),
      daemonDown: false,
    };
  }

  // R4-C-H1: the daemon did not answer. In production, surface
  // daemon-down explicitly with UNKNOWN placeholders — never build a
  // healthy-looking node out of local OS data (os.networkInterfaces()
  // lists interfaces regardless of link state, os.uptime() is the UI
  // host's uptime, and the version / bundle hash literals are not
  // daemon measurements). The lobby and layout render an explicit
  // "daemon unavailable — status unknown" state from daemonDown.
  if (!isDevModeRuntime()) {
    return {
      nodeId: `axonwall-${os.hostname()}`,
      version: 'UNKNOWN',
      uptimeSeconds: 0,
      activeBundleHash: 'UNKNOWN',
      pendingConfirm: false,
      confirmDeadlineUnix: 0,
      osName: hostOs.prettyName,
      osId: hostOs.id,
      osFamily: hostOs.family,
      kernelVersion: hostOs.kernelVersion,
      runtimeMode: fallbackMode,
      interfaces: [],
      daemonDown: true,
    };
  }

  // Dev mode only (fc576368 gate): demo fallback from local OS data,
  // standing in for a daemon that does not exist in a dev checkout.
  // Fallback: Gather real OS interfaces and system uptime directly
  const ifaces = os.networkInterfaces();
  const interfaceList: Array<{
    name: string;
    device: string;
    isUp: boolean;
    ipAddresses: string[];
  }> = [];

  for (const [name, addrs] of Object.entries(ifaces)) {
    if (!addrs) continue;
    if (!isApplianceRuntime() && name === 'lo') continue;
    const ipAddresses = addrs.map((a) => a.cidr || `${a.address}/${a.family === 'IPv4' ? '24' : '64'}`);
    interfaceList.push({
      name,
      device: name,
      isUp: true,
      ipAddresses,
    });
  }

  const mockState = getMockApplyState();
  return {
    nodeId: `axonwall-${os.hostname()}`,
    version: '0.16.4',
    uptimeSeconds: Math.floor(os.uptime()),
    activeBundleHash: mockState.activeBundleHash,
    pendingConfirm: mockState.pendingConfirm,
    confirmDeadlineUnix: mockState.confirmDeadlineUnix,
    osName: hostOs.prettyName,
    osId: hostOs.id,
    osFamily: hostOs.family,
    kernelVersion: hostOs.kernelVersion,
    runtimeMode: fallbackMode,
    interfaces: interfaceList,
    // Dev-mode demo data stands in for the daemon by design (see the
    // fc576368 gate above); it is not a daemon-down signal.
    daemonDown: false,
  };
}

const REDACT_MASK = '********';
const RECURSIVE_SECRET_KEY_PATTERN =
  /(?:password|passphrase|secret|token|salt|apiKey|accessKey|accessKeyId|presharedKey|psk|privateKey|encryptionKey|hmacKey|secretKey|mtlsKey|serverKey|caKey|tlsAuthKey|authKey|authPass|privPass|cryptoPass|webhookUrl|customUpdateUrl|externalDatastoreEndpoint)(?:Base64|Pem)?$/i;
const SENSITIVE_URI_PARAM_PATTERN =
  /^(?:token|secret|password|pass|apikey|api_key|access_key|secret_key|key|sig|signature|auth)$/i;
const NON_REDACT_KEY_NAMES = new Set([
  'keyPreview',
  'publicKey',
  'sshPublicKey',
  'peerPublicKey',
  'passwordPolicy',
  'tokenType',
  'saltLength',
  'keyType',
  'keySize',
]);

function redactCredentialUri(value: string): string {
  if (!value.includes('://')) {
    return value;
  }
  try {
    const parsed = new URL(value);
    if (parsed.username || parsed.password) {
      return REDACT_MASK;
    }
    let changed = false;
    for (const [k] of parsed.searchParams.entries()) {
      if (SENSITIVE_URI_PARAM_PATTERN.test(k)) {
        parsed.searchParams.set(k, REDACT_MASK);
        changed = true;
      }
    }
    return changed ? parsed.toString() : value;
  } catch {
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/@\s]+@/.test(value)) {
      return REDACT_MASK;
    }
    return value;
  }
}

function redactSecretsRecursively(node: unknown, visited = new Set<object>()): void {
  if (!node || typeof node !== 'object') {
    return;
  }
  if (visited.has(node)) {
    return;
  }
  visited.add(node);

  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const item = node[i];
      if (typeof item === 'string' && item !== REDACT_MASK) {
        node[i] = redactCredentialUri(item);
      } else if (item && typeof item === 'object') {
        redactSecretsRecursively(item, visited);
      }
    }
    return;
  }

  const record = node as Record<string, unknown>;
  for (const [key, val] of Object.entries(record)) {
    if (typeof val === 'string') {
      if (val.length === 0 || val === REDACT_MASK) {
        continue;
      }
      if (!NON_REDACT_KEY_NAMES.has(key) && RECURSIVE_SECRET_KEY_PATTERN.test(key)) {
        record[key] = REDACT_MASK;
      } else {
        record[key] = redactCredentialUri(val);
      }
    } else if (val && typeof val === 'object') {
      redactSecretsRecursively(val, visited);
    }
  }
}

function redactDesiredStateForSession(state: DesiredState, session: UserSession): DesiredState {
  if (isAdminSession(session)) {
    return state;
  }
  const redacted: any = structuredClone(state);
  const MASK = REDACT_MASK;

  if (redacted.vpn?.wireguard) {
    if (redacted.vpn.wireguard.privateKey) {
      redacted.vpn.wireguard.privateKey = MASK;
    }
    if (Array.isArray(redacted.vpn.wireguard.peers)) {
      for (const peer of redacted.vpn.wireguard.peers) {
        if (peer?.presharedKey) {
          peer.presharedKey = MASK;
        }
      }
    }
  }

  if (redacted.headscale?.wanInvite?.portKnocking?.sequence) {
    redacted.headscale.wanInvite.portKnocking.sequence = [];
  }

  if (Array.isArray(redacted.vpn?.ipsec?.connections)) {
    for (const conn of redacted.vpn.ipsec.connections) {
      if (conn?.psk) {
        conn.psk = MASK;
      }
    }
  }

  if (Array.isArray(redacted.certificates?.cas)) {
    for (const ca of redacted.certificates.cas) {
      if (ca?.privateKeyPem) {
        ca.privateKeyPem = MASK;
      }
    }
  }

  if (Array.isArray(redacted.certificates?.certs)) {
    for (const cert of redacted.certificates.certs) {
      if (cert?.privateKeyPem) {
        cert.privateKeyPem = MASK;
      }
    }
  }

  if (redacted.ha) {
    if (redacted.ha.authPassword) {
      redacted.ha.authPassword = MASK;
    }
    if (redacted.ha.sqliteSync?.authToken) {
      redacted.ha.sqliteSync.authToken = MASK;
    }
    if (redacted.ha.stateSync?.litestreamAccessKeyId) {
      redacted.ha.stateSync.litestreamAccessKeyId = MASK;
    }
    if (redacted.ha.stateSync?.litestreamSecretAccessKey) {
      redacted.ha.stateSync.litestreamSecretAccessKey = MASK;
    }
  }

  if (redacted.ai?.providers && typeof redacted.ai.providers === 'object') {
    for (const provider of Object.values(redacted.ai.providers) as any[]) {
      if (provider && typeof provider === 'object' && provider.apiKey) {
        provider.apiKey = MASK;
      }
    }
  }

  if (Array.isArray(redacted.dynamicRouting?.bgp?.neighbors)) {
    for (const neighbor of redacted.dynamicRouting.bgp.neighbors) {
      if (neighbor?.password) {
        neighbor.password = MASK;
      }
    }
  }

  if (Array.isArray(redacted.dynamicRouting?.ospf?.areas)) {
    for (const area of redacted.dynamicRouting.ospf.areas) {
      if (area?.authKey) {
        area.authKey = MASK;
      }
    }
  }

  if (redacted.captivePortal?.radiusSecret) {
    redacted.captivePortal.radiusSecret = MASK;
  }

  if (redacted.observability?.clickhouse?.password) {
    redacted.observability.clickhouse.password = MASK;
  }

  if (redacted.observability?.s3?.secretAccessKey) {
    redacted.observability.s3.secretAccessKey = MASK;
  }

  if (redacted.snmp) {
    if (redacted.snmp.community) {
      redacted.snmp.community = MASK;
    }
    if (Array.isArray(redacted.snmp.v3Users)) {
      for (const u of redacted.snmp.v3Users) {
        if (u?.authPassword) u.authPassword = MASK;
        if (u?.privPassword) u.privPassword = MASK;
      }
    }
  }

  if (Array.isArray(redacted.virt?.vms)) {
    for (const vm of redacted.virt.vms) {
      if (vm?.cloudInit?.password) {
        vm.cloudInit.password = MASK;
      }
    }
  }

  if (Array.isArray(redacted.virt?.backupJobs)) {
    for (const job of redacted.virt.backupJobs) {
      if (job?.encryptionKey) {
        job.encryptionKey = MASK;
      }
    }
  }

  // Redact canonical DesiredStateSchema top-level secret fields
  if (redacted.wireguard) {
    if (redacted.wireguard.privateKey) redacted.wireguard.privateKey = MASK;
    if (Array.isArray(redacted.wireguard.peers)) {
      for (const peer of redacted.wireguard.peers) {
        if (peer?.presharedKey) peer.presharedKey = MASK;
      }
    }
  }
  if (Array.isArray(redacted.ipsec?.tunnels)) {
    for (const t of redacted.ipsec.tunnels) {
      if (t?.presharedKey) t.presharedKey = MASK;
    }
  }
  if (Array.isArray(redacted.openvpn?.servers)) {
    for (const s of redacted.openvpn.servers) {
      if (s?.caKey) s.caKey = MASK;
      if (s?.serverKey) s.serverKey = MASK;
      if (s?.tlsAuthKey) s.tlsAuthKey = MASK;
    }
  }
  if (redacted.acme) {
    if (Array.isArray(redacted.acme.accounts)) {
      for (const a of redacted.acme.accounts) {
        if (a?.eabHmacKey) a.eabHmacKey = MASK;
      }
    }
    if (Array.isArray(redacted.acme.internalCAs)) {
      for (const ca of redacted.acme.internalCAs) {
        if (ca?.privateKeyBase64) ca.privateKeyBase64 = MASK;
      }
    }
  }
  if (redacted.ha) {
    if (Array.isArray(redacted.ha.vrrpInstances)) {
      for (const v of redacted.ha.vrrpInstances) {
        if (v?.authPassword) v.authPassword = MASK;
      }
    }
    if (redacted.ha.sqliteSync?.litestreamAccessKeyId) {
      redacted.ha.sqliteSync.litestreamAccessKeyId = MASK;
    }
    if (redacted.ha.sqliteSync?.litestreamSecretAccessKey) {
      redacted.ha.sqliteSync.litestreamSecretAccessKey = MASK;
    }
  }
  if (Array.isArray(redacted.frr?.bgp?.neighbors)) {
    for (const n of redacted.frr.bgp.neighbors) {
      if (n?.password) n.password = MASK;
    }
  }
  if (redacted.nas) {
    if (redacted.nas.s3?.accessKey) redacted.nas.s3.accessKey = MASK;
    if (redacted.nas.s3?.secretKey) redacted.nas.s3.secretKey = MASK;
    if (Array.isArray(redacted.nas.iscsiTargets)) {
      for (const t of redacted.nas.iscsiTargets) {
        if (t?.chapSecret) t.chapSecret = MASK;
      }
    }
  }
  if (redacted.k3s) {
    if (redacted.k3s.externalDatastoreEndpoint) redacted.k3s.externalDatastoreEndpoint = MASK;
    if (redacted.k3s.token) redacted.k3s.token = MASK;
  }
  if (redacted.sso?.clientSecret) {
    redacted.sso.clientSecret = MASK;
  }
  if (Array.isArray(redacted.virtualIps)) {
    for (const vip of redacted.virtualIps) {
      if (vip?.password) vip.password = MASK;
    }
  }
  if (redacted.radius) {
    if (redacted.radius.ldapBindPassword) redacted.radius.ldapBindPassword = MASK;
    if (Array.isArray(redacted.radius.clients)) {
      for (const c of redacted.radius.clients) {
        if (c?.secret) c.secret = MASK;
      }
    }
    if (Array.isArray(redacted.radius.users)) {
      for (const u of redacted.radius.users) {
        if (u?.password) u.password = MASK;
      }
    }
  }
  if (redacted.freeradius && Array.isArray(redacted.freeradius.clients)) {
    for (const c of redacted.freeradius.clients) {
      if (c?.secret) c.secret = MASK;
    }
  }
  if (redacted.vow) {
    if (redacted.vow.gitCredentials?.token) redacted.vow.gitCredentials.token = MASK;
    if (redacted.vow.gitCredentials?.sshPrivateKey) redacted.vow.gitCredentials.sshPrivateKey = MASK;
    if (redacted.vow.webhookSecret) redacted.vow.webhookSecret = MASK;
    if (redacted.vow.adminPassword) redacted.vow.adminPassword = MASK;
  }
  if (redacted.eluvix) {
    if (Array.isArray(redacted.eluvix.providers)) {
      for (const p of redacted.eluvix.providers) {
        if (p?.apiKey) p.apiKey = MASK;
      }
    }
    if (redacted.eluvix.semanticCache?.redisPassword) {
      redacted.eluvix.semanticCache.redisPassword = MASK;
    }
  }
  if (redacted.zeroTrust) {
    if (redacted.zeroTrust.sharedSecret) redacted.zeroTrust.sharedSecret = MASK;
    if (Array.isArray(redacted.zeroTrust.apps)) {
      for (const app of redacted.zeroTrust.apps) {
        if (app?.oidcClientSecret) app.oidcClientSecret = MASK;
      }
    }
  }
  if (redacted.ddns && Array.isArray(redacted.ddns.entries)) {
    for (const entry of redacted.ddns.entries) {
      if (entry?.apiToken) entry.apiToken = MASK;
      if (entry?.customUpdateUrl) entry.customUpdateUrl = MASK;
    }
  }
  if (redacted.captivePortal) {
    if (redacted.captivePortal.radiusSecret) redacted.captivePortal.radiusSecret = MASK;
    if (Array.isArray(redacted.captivePortal.zones)) {
      for (const zone of redacted.captivePortal.zones) {
        if (zone?.radiusSecret) zone.radiusSecret = MASK;
      }
    }
  }
  if (redacted.crowdsec?.apiKey) {
    redacted.crowdsec.apiKey = MASK;
  }
  if (redacted.ha?.mtlsKey) {
    redacted.ha.mtlsKey = MASK;
  }
  if (redacted.observability) {
    if (redacted.observability.alerting?.webhookUrl) {
      redacted.observability.alerting.webhookUrl = MASK;
    }
    if (redacted.observability.victoriaMetrics?.bearerToken) {
      redacted.observability.victoriaMetrics.bearerToken = MASK;
    }
    if (redacted.observability.victoriaLogs?.bearerToken) {
      redacted.observability.victoriaLogs.bearerToken = MASK;
    }
    if (redacted.observability.offload) {
      if (redacted.observability.offload.ingestToken) {
        redacted.observability.offload.ingestToken = MASK;
      }
      if (redacted.observability.offload.metrics?.scrapeToken) {
        redacted.observability.offload.metrics.scrapeToken = MASK;
      }
    }
  }
  if (redacted.fleet && Array.isArray(redacted.fleet.nodes)) {
    for (const node of redacted.fleet.nodes) {
      if (node?.ztpToken) node.ztpToken = MASK;
    }
  }
  if (redacted.threatHarvester) {
    if (redacted.threatHarvester.anonymizationSalt) {
      redacted.threatHarvester.anonymizationSalt = MASK;
    }
    if (redacted.threatHarvester.teacherLlm?.apiKey) {
      redacted.threatHarvester.teacherLlm.apiKey = MASK;
    }
    if (redacted.threatHarvester.fleetShipper?.accessKey) {
      redacted.threatHarvester.fleetShipper.accessKey = MASK;
    }
    if (redacted.threatHarvester.fleetShipper?.secretKey) {
      redacted.threatHarvester.fleetShipper.secretKey = MASK;
    }
  }
  if (redacted.netbox) {
    if (redacted.netbox.apiToken) redacted.netbox.apiToken = MASK;
    if (redacted.netbox.superuserPassword) redacted.netbox.superuserPassword = MASK;
  }
  if (redacted.librenms) {
    if (redacted.librenms.apiToken) redacted.librenms.apiToken = MASK;
    if (redacted.librenms.webhookSecret) redacted.librenms.webhookSecret = MASK;
    if (redacted.librenms.adminPassword) redacted.librenms.adminPassword = MASK;
    if (redacted.librenms.snmpDefaults) {
      if (redacted.librenms.snmpDefaults.community) redacted.librenms.snmpDefaults.community = MASK;
      if (redacted.librenms.snmpDefaults.v3AuthPass) redacted.librenms.snmpDefaults.v3AuthPass = MASK;
      if (redacted.librenms.snmpDefaults.v3CryptoPass) redacted.librenms.snmpDefaults.v3CryptoPass = MASK;
    }
  }
  if (redacted.topology && Array.isArray(redacted.topology.peers)) {
    for (const peer of redacted.topology.peers) {
      if (peer?.apiToken) peer.apiToken = MASK;
    }
  }
  if (redacted.netflow) {
    if (redacted.netflow.storage?.clickhouse?.password) {
      redacted.netflow.storage.clickhouse.password = MASK;
    }
    if (redacted.netflow.reporting?.webhookUrl) {
      redacted.netflow.reporting.webhookUrl = MASK;
    }
    if (redacted.netflow.enrichment?.geoipCityDownloadUrl) {
      redacted.netflow.enrichment.geoipCityDownloadUrl = MASK;
    }
    if (redacted.netflow.enrichment?.geoipAsnDownloadUrl) {
      redacted.netflow.enrichment.geoipAsnDownloadUrl = MASK;
    }
    if (redacted.netflow.selfExport?.metadataSync?.apiToken) {
      redacted.netflow.selfExport.metadataSync.apiToken = MASK;
    }
    if (Array.isArray(redacted.netflow.alerting?.rules)) {
      for (const rule of redacted.netflow.alerting.rules) {
        if (rule?.webhookUrl) rule.webhookUrl = MASK;
      }
    }
  }

  redactSecretsRecursively(redacted);
  return redacted as DesiredState;
}

export async function getCurrentDesiredState(): Promise<DesiredState> {
  const session = await getSession();
  assertActionPermitted(session);
  const state = await getDesiredStateInternal();
  return redactDesiredStateForSession(state, session);
}

// State-version token for the slice-edit pages (C2): the SHA-256 of the
// on-disk YAML config files. A page can pass the fingerprint it loaded with
// as applyDesiredState's expectedFingerprint; the apply is then refused
// instead of silently overwriting newer on-disk state.
export async function getDesiredStateFingerprint(): Promise<{ fingerprint: string }> {
  const session = await getSession();
  assertActionPermitted(session);
  return { fingerprint: readAllYamlConfigFiles().fingerprint };
}

export async function getYamlConfigFilesSnapshot(): Promise<{
  directory: string;
  files: Record<string, string>;
}> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const state = await getCurrentDesiredState();
  const generated = serializeDesiredStateToYamlFiles(state);
  const { files: onDisk } = readAllYamlConfigFiles();

  return {
    directory: ETC_CONFIG_DIR,
    files: { ...generated, ...onDisk },
  };
}

export async function saveYamlDomainFile(
  filename: string,
  yamlContent: string,
  applyImmediately = true,
  options?: { expectedFingerprint?: string }
): Promise<{ success: boolean; message: string; warnings: string[] }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  if (!(AXONWALL_YAML_FILENAMES as readonly string[]).includes(filename)) {
    throw new Error(`Invalid YAML domain filename: ${filename}`);
  }

  const currentSnapshot = await getYamlConfigFilesSnapshot();
  const updatedFiles: Record<string, string> = {
    ...currentSnapshot.files,
    [filename]: yamlContent,
  };

  const validation = validateYamlConfigFiles(updatedFiles);
  if (!validation.valid || !validation.state) {
    const details = validation.errors
      .map((e) => `${e.file}${e.path ? ` (${e.path})` : ''}: ${e.message}`)
      .join('; ');
    throw new Error(`YAML validation failed: ${details}`);
  }

  if (applyImmediately) {
    // C-B2 residual: a daemon-down apply throws ('axonwalld is
    // unreachable') — return it as a structured failure instead of
    // propagating, so the caller can show the operator that nothing
    // was applied. Same for a fingerprint conflict, if one is ever
    // threaded through this path.
    try {
      // C-M8: thread the caller's fingerprint through so a concurrent
      // save in another tab cannot be silently reverted by this apply.
      const res = await applyDesiredState(
        validation.state,
        120,
        options?.expectedFingerprint ? { expectedFingerprint: options.expectedFingerprint } : undefined
      );
      return {
        success: res.success,
        message: `Saved /etc/axonwall/${filename} and applied configuration.`,
        warnings: res.warnings,
      };
    } catch (err: any) {
      if (
        err?.message?.includes('axonwalld is unreachable') ||
        err?.message?.includes('Configuration changed since it was loaded')
      ) {
        return { success: false, message: err.message, warnings: [] };
      }
      throw err;
    }
  }

  persistDesiredStateToDisk(validation.state);
  return {
    success: true,
    message: `Saved /etc/axonwall/${filename} to disk.`,
    warnings: [],
  };
}

export async function exportUnifiedYamlConfig(): Promise<string> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  const state = await getCurrentDesiredState();
  return serializeDesiredStateToSingleYaml(state);
}

export interface CloudInitExportSnapshot {
  yaml: string;
  metaData: string;
  hostname: string;
  fqdn: string;
  storageSummary: {
    layoutMode: string;
    targetDisks: string[];
    slotAGb: number;
    slotBGb: number;
    swapGb: number;
    zramEnabled: boolean;
    raidEnabled: boolean;
    luksEnabled: boolean;
    zfsEnabled: boolean;
  };
  usersCount: number;
  sshKeysCount: number;
  packagesCount: number;
}

async function collectHostIntrospectionData(): Promise<HostIntrospectionData> {
  const desiredState = await getDesiredStateInternal();
  const hostname = os.hostname() || desiredState.system?.hostname || 'axonwall-fw';
  let timezone = desiredState.system?.timezone || 'UTC';
  try {
    if (fs.existsSync('/etc/timezone')) {
      const tz = fs.readFileSync('/etc/timezone', 'utf8').trim();
      if (tz) timezone = tz;
    }
  } catch {}

  // 1. Storage introspection via lsblk + zpool
  let lsblkRaw = '{}';
  try {
    lsblkRaw = execFileSync(
      'lsblk',
      ['-J', '-b', '-o', 'NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT,PKNAME'],
      { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
  } catch {}

  const zfsPools: Array<{
    name: string;
    datasets?: Array<{ name: string; mountpoint?: string; compression?: string }>;
  }> = [];
  try {
    const zpoolOut = execFileSync('zpool', ['list', '-H', '-o', 'name'], {
      encoding: 'utf8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (zpoolOut) {
      for (const poolName of zpoolOut.split('\n').map((s) => s.trim()).filter(Boolean)) {
        const datasets: Array<{ name: string; mountpoint?: string; compression?: string }> = [];
        try {
          const zfsOut = execFileSync('zfs', ['list', '-H', '-r', '-o', 'name,mountpoint,compression', poolName], {
            encoding: 'utf8',
            timeout: 2000,
            stdio: ['ignore', 'pipe', 'ignore'],
          }).trim();
          for (const line of zfsOut.split('\n')) {
            const [dsName, mp, comp] = line.split('\t').map((s) => s.trim());
            if (dsName && dsName !== poolName) {
              datasets.push({
                name: dsName.replace(new RegExp(`^${poolName}/`), ''),
                mountpoint: mp && mp !== 'none' && mp !== '-' ? mp : undefined,
                compression: comp || 'lz4',
              });
            }
          }
        } catch {}
        zfsPools.push({ name: poolName, datasets });
      }
    }
  } catch {}

  const storage = parseStorageFromLsblk(lsblkRaw, { zfsPools });

  // 2. Admin credentials & ZTP metadata
  let adminUsername = 'admin';
  let adminPassword: string | undefined;
  for (const envPath of Array.from(
    new Set([
      path.join(ETC_CONFIG_DIR, 'admin.env'),
      path.join(PERSIST_CONFIG_DIR, 'admin.env'),
      '/etc/axonwall/admin.env',
      '/var/lib/axonwall/etc-axonwall/admin.env',
    ]),
  )) {
    try {
      if (fs.existsSync(envPath)) {
        const raw = fs.readFileSync(envPath, 'utf8');
        for (const line of raw.split('\n')) {
          const [k, ...vParts] = line.trim().split('=');
          const v = vParts.join('=').trim();
          if (k === 'LOCAL_ADMIN_USER' && v) adminUsername = v;
          if (k === 'LOCAL_ADMIN_PASSWORD' && v) adminPassword = v;
        }
        break;
      }
    } catch {}
  }

  let ztpEnabled = false;
  let controllerUrl: string | undefined;
  let enrollmentToken: string | undefined;
  try {
    const controllerEnvPath = Array.from(
      new Set([
        path.join(ETC_CONFIG_DIR, 'controller.env'),
        path.join(PERSIST_CONFIG_DIR, 'controller.env'),
        '/etc/axonwall/controller.env',
      ]),
    ).find((p) => fs.existsSync(p));
    if (controllerEnvPath) {
      const raw = fs.readFileSync(controllerEnvPath, 'utf8');
      for (const line of raw.split('\n')) {
        const [k, ...vParts] = line.trim().split('=');
        const v = vParts.join('=').trim();
        if (k === 'AXONWALL_CONTROLLER_URL' && v) controllerUrl = v;
        if (k === 'AXONWALL_ZTP_TOKEN' && v) enrollmentToken = v;
      }
      if (
        controllerUrl &&
        !controllerUrl.includes('127.0.0.1') &&
        !controllerUrl.includes('localhost')
      ) {
        ztpEnabled = true;
      }
    }
  } catch {}

  // 3. OS Users & SSH Authorized Keys
  const osUsersMap = new Map<
    string,
    {
      name: string;
      gecos?: string;
      sudo?: string;
      shell?: string;
      lockPasswd?: boolean;
      sshAuthorizedKeys: string[];
    }
  >();

  const defaultAdminShell = fs.existsSync('/usr/bin/zsh') ? '/usr/bin/zsh' : '/bin/bash';
  try {
    const daemonUsers = await callAgentApi<{ users: any[] }>('/v1/system/users', 'GET');
    if (daemonUsers && Array.isArray(daemonUsers.users)) {
      for (const u of daemonUsers.users) {
        if (u.isSystem) continue;
        const isPriv =
          u.applianceRole === 'admin' ||
          (Array.isArray(u.groups) && (u.groups.includes('sudo') || u.groups.includes('wheel')));
        osUsersMap.set(u.username, {
          name: u.username,
          gecos: u.comment || `${u.username} (${u.applianceRole || 'operator'})`,
          sudo: isPriv ? 'ALL=(ALL) NOPASSWD:ALL' : undefined,
          shell: u.shell || defaultAdminShell,
          lockPasswd: Boolean(u.passwordLocked),
          sshAuthorizedKeys: Array.isArray(u.sshKeys) ? u.sshKeys : [],
        });
      }
    }
  } catch {}

  // Fallback / supplement from /home/*/.ssh/authorized_keys and /root/.ssh/authorized_keys
  try {
    if (fs.existsSync('/home')) {
      for (const dirName of fs.readdirSync('/home')) {
        const akPath = path.join('/home', dirName, '.ssh', 'authorized_keys');
        let keys: string[] = [];
        try {
          if (fs.existsSync(akPath)) {
            keys = fs
              .readFileSync(akPath, 'utf8')
              .split('\n')
              .map((l) => l.trim())
              .filter((l) => l && !l.startsWith('#'));
          }
        } catch {}
        const existing = osUsersMap.get(dirName);
        if (existing) {
          existing.sshAuthorizedKeys = Array.from(new Set([...existing.sshAuthorizedKeys, ...keys]));
        } else if (/^[a-z_][a-z0-9_-]{0,31}$/.test(dirName)) {
          osUsersMap.set(dirName, {
            name: dirName,
            gecos: `${dirName} Administrator`,
            sudo: 'ALL=(ALL) NOPASSWD:ALL',
            shell: defaultAdminShell,
            sshAuthorizedKeys: keys,
          });
        }
      }
    }
  } catch {}

  return {
    desiredState,
    hostname,
    timezone,
    storage,
    adminUsername,
    adminPassword,
    ztp: ztpEnabled ? { enabled: true, controllerUrl, enrollmentToken } : { enabled: false },
    osUsers: Array.from(osUsersMap.values()),
  };
}

export async function exportCloudInitConfigAction(
  options: CloudInitExportOptions = {}
): Promise<CloudInitExportSnapshot> {
  const session = await getSession();
  assertInteractiveSession(session);
  assertActionPermitted(session, 'admin');

  const data = await collectHostIntrospectionData();
  const safeOptions: CloudInitExportOptions = {
    redactSecrets: options.redactSecrets !== false,
    templateMode: Boolean(options.templateMode),
    includeStorage: options.includeStorage !== false,
    includeUsers: options.includeUsers !== false,
    includePackages: options.includePackages !== false,
    hostnameOverride: options.hostnameOverride?.trim() || undefined,
  };

  const fullConfig = buildCloudInitFromSystem(data, safeOptions);
  const yaml = exportCloudInitYaml(data, safeOptions);
  const metaData = generateCloudInitMetaData(undefined, fullConfig.hostname);
  const st = data.storage;
  const users = fullConfig.users || [];
  const sshKeysCount = users.reduce((acc, u) => acc + (u.ssh_authorized_keys?.length || 0), 0);

  return {
    yaml,
    metaData,
    hostname: fullConfig.hostname || data.hostname || 'axonwall-fw',
    fqdn: fullConfig.fqdn || `${fullConfig.hostname || 'axonwall-fw'}.axonwall.local`,
    storageSummary: {
      layoutMode: st?.layout_mode || 'standard_ab',
      targetDisks: st?.target_disks || ['/dev/sda'],
      slotAGb: st?.partitions?.slot_a?.size_gb ?? 16,
      slotBGb: st?.partitions?.slot_b?.size_gb ?? 16,
      swapGb: st?.partitions?.swap?.size_gb ?? 2,
      zramEnabled: Boolean(st?.partitions?.swap?.zram_enabled),
      raidEnabled: Boolean(st?.system_raid?.enabled),
      luksEnabled: Boolean(st?.encryption?.enabled),
      zfsEnabled: Boolean(st?.zfs?.enabled),
    },
    usersCount: users.length,
    sshKeysCount,
    packagesCount: (fullConfig.packages || []).length,
  };
}

export async function applyDesiredState(
  state: DesiredState,
  confirmTimeoutSeconds = 120,
  options?: { expectedFingerprint?: string }
): Promise<{ success: boolean; message: string; nftScript: string; warnings: string[]; jobId?: string }> {
  const session = await getSession();
  await enforceRateLimit(10, 60000); // Max 10 applies per minute per IP
  assertActionPermitted(session, 'admin');

  // Preserve redacted headscale port-knocking sequence before Zod .min(2) validation runs.
  let candidateState: any = state;
  if (
    candidateState &&
    typeof candidateState === 'object' &&
    Array.isArray(candidateState?.headscale?.wanInvite?.portKnocking?.sequence) &&
    candidateState.headscale.wanInvite.portKnocking.sequence.length === 0
  ) {
    const existingForKnock = await getDesiredStateInternal().catch(() => null);
    candidateState = structuredClone(candidateState);
    if (existingForKnock?.headscale?.wanInvite?.portKnocking?.sequence?.length) {
      candidateState.headscale.wanInvite.portKnocking.sequence =
        existingForKnock.headscale.wanInvite.portKnocking.sequence;
    } else {
      delete candidateState.headscale.wanInvite.portKnocking.sequence;
    }
  }

  const normalizedState = DesiredStateSchema.parse(candidateState);
  const needsExistingForMask =
    (normalizedState.netbox &&
      (normalizedState.netbox.apiToken === '********' ||
        normalizedState.netbox.superuserPassword === '********')) ||
    (normalizedState.librenms &&
      (normalizedState.librenms.apiToken === '********' ||
        normalizedState.librenms.webhookSecret === '********' ||
        normalizedState.librenms.adminPassword === '********' ||
        normalizedState.librenms.snmpDefaults?.community === '********' ||
        normalizedState.librenms.snmpDefaults?.v3AuthPass === '********' ||
        normalizedState.librenms.snmpDefaults?.v3CryptoPass === '********')) ||
    Boolean(normalizedState.topology?.peers?.some((p) => p.apiToken === '********')) ||
    Boolean(
      normalizedState.ddns?.entries?.some(
        (e) => e.apiToken === '********' || e.customUpdateUrl === '********'
      )
    ) ||
    normalizedState.threatHarvester?.anonymizationSalt === '********' ||
    normalizedState.threatHarvester?.teacherLlm?.apiKey === '********' ||
    normalizedState.threatHarvester?.fleetShipper?.accessKey === '********' ||
    normalizedState.threatHarvester?.fleetShipper?.secretKey === '********' ||
    normalizedState.k3s?.externalDatastoreEndpoint === '********' ||
    normalizedState.ha?.sqliteSync?.litestreamAccessKeyId === '********' ||
    normalizedState.ha?.sqliteSync?.litestreamSecretAccessKey === '********' ||
    normalizedState.nas?.s3?.accessKey === '********' ||
    normalizedState.nas?.s3?.secretKey === '********' ||
    normalizedState.netflow?.storage?.clickhouse?.password === '********' ||
    normalizedState.netflow?.reporting?.webhookUrl === '********' ||
    normalizedState.netflow?.enrichment?.geoipCityDownloadUrl === '********' ||
    normalizedState.netflow?.enrichment?.geoipAsnDownloadUrl === '********' ||
    normalizedState.netflow?.selfExport?.metadataSync?.apiToken === '********' ||
    Boolean(normalizedState.netflow?.alerting?.rules?.some((r) => r.webhookUrl === '********')) ||
    normalizedState.observability?.clickhouse?.password === '********' ||
    normalizedState.observability?.alerting?.webhookUrl === '********' ||
    normalizedState.observability?.victoriaMetrics?.bearerToken === '********' ||
    normalizedState.observability?.victoriaLogs?.bearerToken === '********' ||
    normalizedState.observability?.offload?.ingestToken === '********' ||
    normalizedState.observability?.offload?.metrics?.scrapeToken === '********' ||
    normalizedState.snmp?.community === '********' ||
    Boolean(
      normalizedState.snmp?.v3Users?.some(
        (u) => u.authPassword === '********' || u.privPassword === '********'
      )
    );
  if (needsExistingForMask) {
    const existing = await getDesiredStateInternal().catch(() => null);
    if (normalizedState.observability && existing?.observability) {
      if (normalizedState.observability.clickhouse?.password === '********') {
        normalizedState.observability.clickhouse.password = existing.observability.clickhouse?.password;
      }
      if (normalizedState.observability.alerting?.webhookUrl === '********') {
        normalizedState.observability.alerting.webhookUrl = existing.observability.alerting?.webhookUrl;
      }
      if (normalizedState.observability.victoriaMetrics?.bearerToken === '********') {
        normalizedState.observability.victoriaMetrics.bearerToken =
          existing.observability.victoriaMetrics?.bearerToken;
      }
      if (normalizedState.observability.victoriaLogs?.bearerToken === '********') {
        normalizedState.observability.victoriaLogs.bearerToken =
          existing.observability.victoriaLogs?.bearerToken;
      }
      if (normalizedState.observability.offload) {
        if (normalizedState.observability.offload.ingestToken === '********') {
          normalizedState.observability.offload.ingestToken =
            existing.observability.offload?.ingestToken;
        }
        if (normalizedState.observability.offload.metrics?.scrapeToken === '********') {
          normalizedState.observability.offload.metrics.scrapeToken =
            existing.observability.offload?.metrics?.scrapeToken;
        }
      }
    }
    if (normalizedState.snmp && existing?.snmp) {
      if (normalizedState.snmp.community === '********' && existing.snmp.community) {
        normalizedState.snmp.community = existing.snmp.community;
      }
      if (normalizedState.snmp.v3Users?.length) {
        const existingUsers = new Map((existing.snmp.v3Users ?? []).map((u) => [u.username, u]));
        normalizedState.snmp.v3Users = normalizedState.snmp.v3Users.map((u) => ({
          ...u,
          authPassword:
            u.authPassword === '********'
              ? existingUsers.get(u.username)?.authPassword || u.authPassword
              : u.authPassword,
          privPassword:
            u.privPassword === '********'
              ? existingUsers.get(u.username)?.privPassword || u.privPassword
              : u.privPassword,
        }));
      }
    }
    if (normalizedState.netbox) {
      if (normalizedState.netbox.apiToken === '********') {
        normalizedState.netbox.apiToken = existing?.netbox?.apiToken;
      }
      if (normalizedState.netbox.superuserPassword === '********') {
        normalizedState.netbox.superuserPassword = existing?.netbox?.superuserPassword;
      }
    }
    if (normalizedState.librenms) {
      if (normalizedState.librenms.apiToken === '********') {
        normalizedState.librenms.apiToken = existing?.librenms?.apiToken;
      }
      if (normalizedState.librenms.webhookSecret === '********') {
        normalizedState.librenms.webhookSecret = existing?.librenms?.webhookSecret;
      }
      if (normalizedState.librenms.adminPassword === '********') {
        normalizedState.librenms.adminPassword = existing?.librenms?.adminPassword;
      }
      if (normalizedState.librenms.snmpDefaults) {
        if (normalizedState.librenms.snmpDefaults.community === '********' && existing?.librenms?.snmpDefaults?.community) {
          normalizedState.librenms.snmpDefaults.community = existing.librenms.snmpDefaults.community;
        }
        if (normalizedState.librenms.snmpDefaults.v3AuthPass === '********') {
          normalizedState.librenms.snmpDefaults.v3AuthPass = existing?.librenms?.snmpDefaults?.v3AuthPass;
        }
        if (normalizedState.librenms.snmpDefaults.v3CryptoPass === '********') {
          normalizedState.librenms.snmpDefaults.v3CryptoPass = existing?.librenms?.snmpDefaults?.v3CryptoPass;
        }
      }
    }
    if (normalizedState.topology?.peers?.length) {
      const existingPeers = new Map((existing?.topology?.peers ?? []).map((p) => [p.id, p]));
      normalizedState.topology.peers = normalizedState.topology.peers.map((p) =>
        p.apiToken === '********' ? { ...p, apiToken: existingPeers.get(p.id)?.apiToken } : p,
      );
    }
    if (normalizedState.ddns?.entries?.length && existing?.ddns?.entries?.length) {
      const existingById = new Map(existing.ddns.entries.map((e) => [e.id, e]));
      const existingByHost = new Map(existing.ddns.entries.map((e) => [e.hostname, e]));
      normalizedState.ddns.entries = normalizedState.ddns.entries.map((e) => {
        const prev = existingById.get(e.id) || existingByHost.get(e.hostname);
        if (!prev) return e;
        return {
          ...e,
          apiToken: e.apiToken === '********' ? prev.apiToken : e.apiToken,
          customUpdateUrl:
            e.customUpdateUrl === '********' ? prev.customUpdateUrl : e.customUpdateUrl,
        };
      });
    }
    if (normalizedState.threatHarvester) {
      if (normalizedState.threatHarvester.anonymizationSalt === '********') {
        normalizedState.threatHarvester.anonymizationSalt =
          existing?.threatHarvester?.anonymizationSalt;
      }
      if (
        normalizedState.threatHarvester.teacherLlm &&
        normalizedState.threatHarvester.teacherLlm.apiKey === '********'
      ) {
        normalizedState.threatHarvester.teacherLlm.apiKey =
          existing?.threatHarvester?.teacherLlm?.apiKey;
      }
      if (normalizedState.threatHarvester.fleetShipper) {
        if (normalizedState.threatHarvester.fleetShipper.accessKey === '********') {
          normalizedState.threatHarvester.fleetShipper.accessKey =
            existing?.threatHarvester?.fleetShipper?.accessKey;
        }
        if (normalizedState.threatHarvester.fleetShipper.secretKey === '********') {
          normalizedState.threatHarvester.fleetShipper.secretKey =
            existing?.threatHarvester?.fleetShipper?.secretKey;
        }
      }
    }
    if (
      normalizedState.k3s &&
      normalizedState.k3s.externalDatastoreEndpoint === '********'
    ) {
      normalizedState.k3s.externalDatastoreEndpoint = existing?.k3s?.externalDatastoreEndpoint;
    }
    if (normalizedState.ha?.sqliteSync) {
      if (normalizedState.ha.sqliteSync.litestreamAccessKeyId === '********') {
        normalizedState.ha.sqliteSync.litestreamAccessKeyId =
          existing?.ha?.sqliteSync?.litestreamAccessKeyId;
      }
      if (normalizedState.ha.sqliteSync.litestreamSecretAccessKey === '********') {
        normalizedState.ha.sqliteSync.litestreamSecretAccessKey =
          existing?.ha?.sqliteSync?.litestreamSecretAccessKey;
      }
    }
    if (normalizedState.nas?.s3) {
      if (normalizedState.nas.s3.accessKey === '********' && existing?.nas?.s3?.accessKey !== undefined) {
        normalizedState.nas.s3.accessKey = existing.nas.s3.accessKey;
      }
      if (normalizedState.nas.s3.secretKey === '********' && existing?.nas?.s3?.secretKey !== undefined) {
        normalizedState.nas.s3.secretKey = existing.nas.s3.secretKey;
      }
    }
    if (normalizedState.netflow) {
      if (normalizedState.netflow.storage?.clickhouse?.password === '********') {
        normalizedState.netflow.storage.clickhouse.password = existing?.netflow?.storage?.clickhouse?.password;
      }
      if (normalizedState.netflow.reporting?.webhookUrl === '********') {
        normalizedState.netflow.reporting.webhookUrl = existing?.netflow?.reporting?.webhookUrl ?? '';
      }
      if (normalizedState.netflow.enrichment?.geoipCityDownloadUrl === '********') {
        normalizedState.netflow.enrichment.geoipCityDownloadUrl =
          existing?.netflow?.enrichment?.geoipCityDownloadUrl ?? '';
      }
      if (normalizedState.netflow.enrichment?.geoipAsnDownloadUrl === '********') {
        normalizedState.netflow.enrichment.geoipAsnDownloadUrl =
          existing?.netflow?.enrichment?.geoipAsnDownloadUrl ?? '';
      }
      if (normalizedState.netflow.selfExport?.metadataSync?.apiToken === '********') {
        normalizedState.netflow.selfExport.metadataSync.apiToken =
          existing?.netflow?.selfExport?.metadataSync?.apiToken ?? '';
      }
      if (normalizedState.netflow.alerting?.rules?.length) {
        const existingRules = new Map((existing?.netflow?.alerting?.rules ?? []).map((r) => [r.id, r]));
        normalizedState.netflow.alerting.rules = normalizedState.netflow.alerting.rules.map((r) =>
          r.webhookUrl === '********' ? { ...r, webhookUrl: existingRules.get(r.id)?.webhookUrl } : r,
        );
      }
    }
  }
  const { devMode: _devMode, ...result } = await runDesiredStateApplyPipeline(
    normalizedState,
    confirmTimeoutSeconds,
    {
      expectedFingerprint: options?.expectedFingerprint,
      actorUsername: session?.username || 'admin',
    }
  );
  return result;
}

export async function applyDesiredStateAction(
  state: DesiredState,
  confirmTimeoutSeconds = 120,
  options?: { expectedFingerprint?: string }
): Promise<
  | { ok: true; result: { success: boolean; message: string; nftScript: string; warnings: string[] } }
  | { ok: false; error: string }
> {
  try {
    const result = await applyDesiredState(state, confirmTimeoutSeconds, options);
    return { ok: true, result };
  } catch (err: any) {
    return {
      ok: false,
      error: err?.message || 'Failed to apply configuration',
    };
  }
}

export async function confirmActiveRuleset(explicitJobId?: string): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  let targetJobId: string | null = explicitJobId?.trim() || getLastPendingJobId() || null;
  try {
    const daemonStatus = await callAgentApi<any>('/v1/status', 'GET', undefined, 5000);
    if (daemonStatus?.pending_job_id || daemonStatus?.pendingJobId) {
      targetJobId = daemonStatus.pending_job_id || daemonStatus.pendingJobId;
    }
  } catch {}
  if (!targetJobId) {
    return {
      success: false,
      message: 'No pending ruleset to confirm: no pending job id is known.',
    };
  }

  const confirmRes = await callAgentApiDetailed<any>(
    '/v1/confirm',
    'POST',
    {
      job_id: targetJobId,
      jobId: targetJobId,
    },
    60_000
  );
  if (confirmRes.kind === 'ok') {
    const daemonResp = confirmRes.data;
    if (daemonResp.success) {
      clearMockPendingConfirm();
      setLastPendingJobId('');
    }
    return {
      success: daemonResp.success,
      message: daemonResp.message,
    };
  }
  if (confirmRes.kind === 'http_error') {
    return {
      success: false,
      message: confirmRes.message || 'Daemon rejected ruleset confirmation.',
    };
  }
  if (confirmRes.kind === 'timeout') {
    return {
      success: false,
      message: 'Daemon confirm timed out — pending commit-confirm state preserved; retry confirm or check status.',
    };
  }

  return {
    success: false,
    message: 'Daemon unavailable — confirm not acknowledged; pending state preserved. Retry once axonwalld is reachable.',
  };
}

export async function rollbackActiveRuleset(): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const rollbackRes = await callAgentApiDetailed<any>(
    '/v1/rollback',
    'POST',
    { reason: 'operator rollback' },
    60_000
  );
  if (rollbackRes.kind === 'ok') {
    const daemonResp = rollbackRes.data;
    if (daemonResp.success) {
      clearMockPendingConfirm();
      setLastPendingJobId('');
      invalidateDesiredStateCacheInternal();
    }
    return {
      success: daemonResp.success,
      message: daemonResp.message,
    };
  }
  if (rollbackRes.kind === 'http_error') {
    return {
      success: false,
      message: rollbackRes.message || 'Daemon rejected ruleset rollback.',
    };
  }
  if (rollbackRes.kind === 'timeout') {
    return {
      success: false,
      message: 'Daemon rollback timed out — check pending commit-confirm status before retrying.',
    };
  }

  return {
    success: false,
    message: 'Daemon unavailable — rollback not acknowledged; pending state preserved. Retry once axonwalld is reachable.',
  };
}

export async function runDiagnostic(
  type: 'ping' | 'port_probe',
  target: string,
  port = 80
): Promise<{ success: boolean; output: string }> {
  const session = await getSession();
  await enforceRateLimit(5, 60000); // Max 5 diagnostics per minute per IP
  assertActionPermitted(session, 'admin');

  const cleanTarget = target.trim();
  if (!cleanTarget) {
    return { success: false, output: 'Target cannot be empty' };
  }

  // Basic sanitation against command injection in case this ever shells out
  if (/^[a-zA-Z0-9.-]+$/.test(cleanTarget) === false) {
    return { success: false, output: 'Invalid target format' };
  }

  if (type === 'port_probe') {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { success: false, output: 'Invalid port number' };
    }
    const lowerTarget = cleanTarget.toLowerCase();
    if (
      lowerTarget === 'localhost' ||
      lowerTarget.endsWith('.localhost') ||
      lowerTarget === 'metadata.google.internal' ||
      lowerTarget === 'metadata.goog' ||
      lowerTarget === 'metadata' ||
      lowerTarget === 'instance-data'
    ) {
      return {
        success: false,
        output: `Port probe blocked for ${cleanTarget}: loopback and cloud metadata hosts are disallowed`,
      };
    }

    let resolvedAddrs: Array<{ address: string; family: number }>;
    const ipFamily = net.isIP(cleanTarget);
    if (ipFamily !== 0) {
      resolvedAddrs = [{ address: cleanTarget, family: ipFamily }];
    } else {
      try {
        const lookedUp = await dns.promises.lookup(cleanTarget, { all: true, verbatim: true });
        resolvedAddrs = Array.isArray(lookedUp) ? lookedUp : [lookedUp];
      } catch (err: any) {
        return {
          success: false,
          output: `Port probe DNS lookup failed for ${cleanTarget}: ${err?.message || 'lookup failed'}`,
        };
      }
    }
    if (!resolvedAddrs.length) {
      return { success: false, output: `Port probe DNS lookup returned no addresses for ${cleanTarget}` };
    }
    for (const addr of resolvedAddrs) {
      if (isDisallowedSsrfIp(addr.address, { allowPrivate: true }) || isLoopbackSsrfIp(addr.address)) {
        return {
          success: false,
          output: `Port probe blocked for ${cleanTarget}: target resolves to disallowed loopback, link-local, or metadata address`,
        };
      }
    }

    const pinnedLookup = createPinnedLookup(resolvedAddrs);
    return new Promise((resolve) => {
      const start = Date.now();
      const socket = net.createConnection(
        { host: cleanTarget, port, timeout: 3000, lookup: pinnedLookup as any },
        () => {
        const latency = Date.now() - start;
        socket.destroy();
        resolve({
          success: true,
          output: `Port ${port} on ${cleanTarget} is OPEN (connected in ${latency}ms)`,
        });
      });

      socket.on('error', (err) => {
        resolve({
          success: false,
          output: `Port probe failed for ${cleanTarget}:${port} - ${err.message}`,
        });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({
          success: false,
          output: `Port probe timed out after 3000ms for ${cleanTarget}:${port}`,
        });
      });
    });
  }

  // Delegate ping diagnostic to privileged axonwalld first
  try {
    const pingRes = await callAgentApi<{ success: boolean; output: string }>('/v1/diagnostic', 'POST', {
      type: 1, // DIAGNOSTIC_TYPE_PING
      target: cleanTarget,
      count: 3,
    });
    if (pingRes && typeof pingRes.output === 'string' && pingRes.output.trim().length > 0) {
      return {
        success: Boolean(pingRes.success),
        output: pingRes.output,
      };
    }
  } catch {}

  // N1: the daemon did not answer (or returned no output). Never fabricate
  // a perfect ping result — report the probe as not run.
  return {
    success: false,
    output: `Ping unavailable: axonwalld unreachable — no ping of ${cleanTarget} was run.`,
  };
}

import { runLivePacketCapture as executeCapture, type CaptureResult, type CapturedPacket } from './pcap';
export type { CaptureResult, CapturedPacket };

export async function startPacketCapture(
  iface: string,
  filter: string,
  count = 50
): Promise<CaptureResult> {
  const session = await getSession();
  await enforceRateLimit(10, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('packet-diagnostics');

  return executeCapture({ iface, filter, count });
}

export interface SystemHealthMetrics {
  cpuCount: number;
  arch: string;
  loadAvg: number[];
  totalMemGB: number;
  usedMemGB: number;
  freeMemGB: number;
  memPercent: number;
  uptimeSeconds: number;
}

export async function getSystemHealthTelemetry(): Promise<SystemHealthMetrics> {
  const session = await getSession();
  assertActionPermitted(session);

  const cpus = os.cpus();
  const arch = process.arch === 'x64' ? 'amd64' : process.arch;
  const loadAvg = os.loadavg();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = Math.max(0, totalMem - freeMem);

  return {
    cpuCount: cpus.length || 1,
    arch,
    loadAvg: [Number(loadAvg[0]?.toFixed(2) || '0.00'), Number(loadAvg[1]?.toFixed(2) || '0.00'), Number(loadAvg[2]?.toFixed(2) || '0.00')],
    totalMemGB: Number((totalMem / (1024 ** 3)).toFixed(2)),
    usedMemGB: Number((usedMem / (1024 ** 3)).toFixed(2)),
    freeMemGB: Number((freeMem / (1024 ** 3)).toFixed(2)),
    memPercent: Number(((usedMem / (totalMem || 1)) * 100).toFixed(1)),
    uptimeSeconds: Math.floor(os.uptime()),
  };
}

// C12: hub-cert status is a discriminated union, not nullable. "No cert
// on this box", "cert unreadable/unparseable", and "cert OK" used to
// collapse to the same null, so the expiry card silently vanished in
// exactly the case it exists to warn about.
export type HubCertStatus =
  | { state: 'ok'; expiresAt: string; daysRemaining: number; subject: string }
  | { state: 'missing' }
  | { state: 'error'; message: string };

// Hub TLS certificate expiry (audit B-14). The packaged hub certificate
// is a 10-year self-signed cert with no renewal machinery; surface its
// expiry so it never arrives as a surprise outage. The cert is public
// material (mode 0644) and this runs server-side, so reading it directly
// is safe. Returns 'missing' when no packaged cert exists (dev machines)
// and 'error' when the cert exists but cannot be read or parsed, so the
// page can alert instead of rendering nothing.
export async function getHubCertStatus(): Promise<HubCertStatus> {
  const session = await getSession();
  assertActionPermitted(session);

  let pem: string;
  try {
    pem = fs.readFileSync('/etc/axonwall/certs/hub.crt', 'utf8');
  } catch (err: any) {
    if (err?.code === 'ENOENT') return { state: 'missing' };
    return {
      state: 'error',
      message: `Hub certificate unreadable: ${err?.message || 'read failed'}`,
    };
  }

  try {
    const cert = new crypto.X509Certificate(pem);
    const expires = new Date(cert.validTo);
    if (Number.isNaN(expires.getTime())) {
      return { state: 'error', message: 'Hub certificate has no parseable expiry date.' };
    }
    return {
      state: 'ok',
      expiresAt: expires.toISOString(),
      daysRemaining: Math.floor((expires.getTime() - Date.now()) / 86_400_000),
      subject: cert.subject.replace(/\n/g, ', '),
    };
  } catch (err: any) {
    return {
      state: 'error',
      message: `Hub certificate unparseable: ${err?.message || 'parse failed'}`,
    };
  }
}

export interface HASyncTrustStatus {
  nodeRole: string;
  transportConfigured: string;
  transportEffective: string;
  requireSignedPayloads: boolean;
  pkiEnrolled: boolean;
  nodeCertFingerprint?: string;
  caCertFingerprint?: string;
  nodeCertSubject?: string;
  nodeCertExpiresAt?: string;
}

// HA sync trust state (audit D-04 Phase 3): PKI enrollment, the transport
// configured vs the one actually in effect, the payload-signing policy,
// and the pair's certificate fingerprints. The daemon owns the PKI files
// (they are not readable by the UI user), so this comes from its agent
// API; null when the daemon is unreachable.
export async function getHASyncTrustStatus(): Promise<HASyncTrustStatus | null> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('high-availability');

  const resp = await callAgentApi<HASyncTrustStatus>('/v1/ha/sync-trust');
  return resp ?? null;
}

export interface UpsStatus {
  connected: boolean;
  status: string; // 'OL' | 'OB' | 'LB' | 'DISCONNECTED'
  chargePct: number | null;
  runtimeSeconds: number | null;
  loadPct: number | null;
  inputVoltage: number | null;
  model: string | null;
  isVirtual: boolean;
  message: string;
}

export async function getUpsStatus(): Promise<UpsStatus> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('nut-ups');

  let isVirtual = false;
  try {
    const virt = execSync('systemd-detect-virt 2>/dev/null', { encoding: 'utf8', timeout: 500 }).trim();
    if (virt && virt !== 'none') isVirtual = true;
  } catch {
    try {
      const vendor = fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').toLowerCase();
      if (vendor.includes('qemu') || vendor.includes('kvm') || vendor.includes('vmware') || vendor.includes('virtualbox')) {
        isVirtual = true;
      }
    } catch {}
  }

  // 1. Try upsc query if NUT is running
  try {
    const upscList = execFileSync('upsc', ['-l'], { encoding: 'utf8', timeout: 1000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    const rawUpsName = upscList.split('\n')[0]?.trim();
    if (rawUpsName && !rawUpsName.startsWith('-') && /^[a-zA-Z0-9_.-]+$/.test(rawUpsName)) {
      const rawData = execFileSync('upsc', [rawUpsName], { encoding: 'utf8', timeout: 1500, stdio: ['ignore', 'pipe', 'ignore'] });
      const kv: Record<string, string> = {};
      for (const line of rawData.split('\n')) {
        const [k, v] = line.split(':').map((s) => s.trim());
        if (k && v) kv[k] = v;
      }
      return {
        connected: true,
        status: kv['ups.status'] || 'OL',
        chargePct: kv['battery.charge'] ? Number(kv['battery.charge']) : null,
        runtimeSeconds: kv['battery.runtime'] ? Number(kv['battery.runtime']) : null,
        loadPct: kv['ups.load'] ? Number(kv['ups.load']) : null,
        inputVoltage: kv['input.voltage'] ? Number(kv['input.voltage']) : null,
        model: kv['ups.model'] || rawUpsName,
        isVirtual,
        message: 'Active NUT daemon connected',
      };
    }
  } catch {}

  // 2. Check physical battery subsystem (/sys/class/power_supply/)
  // Only consider batteries if NOT running inside a VM (virtual power supplies are often dummy)
  if (!isVirtual) {
    try {
      if (fs.existsSync('/sys/class/power_supply')) {
        const supplies = fs.readdirSync('/sys/class/power_supply');
        const bat = supplies.find((s) => s.startsWith('BAT'));
        if (bat) {
          const capacityPath = `/sys/class/power_supply/${bat}/capacity`;
          const statusPath = `/sys/class/power_supply/${bat}/status`;
          const modelPath = `/sys/class/power_supply/${bat}/model_name`;
          const charge = fs.existsSync(capacityPath) ? parseInt(fs.readFileSync(capacityPath, 'utf8').trim(), 10) : null;
          const status = fs.existsSync(statusPath) ? fs.readFileSync(statusPath, 'utf8').trim() : 'Unknown';
          const model = fs.existsSync(modelPath) ? fs.readFileSync(modelPath, 'utf8').trim() : bat;
          return {
            connected: true,
            status: status === 'Charging' || status === 'Full' ? 'OL' : 'OB',
            chargePct: charge,
            runtimeSeconds: null,
            loadPct: null,
            inputVoltage: null,
            model,
            isVirtual,
            message: 'Host ACPI battery subsystem detected',
          };
        }
      }
    } catch {}
  }

  return {
    connected: false,
    status: 'DISCONNECTED',
    chargePct: null,
    runtimeSeconds: null,
    loadPct: null,
    inputVoltage: null,
    model: null,
    isVirtual,
    message: isVirtual
      ? 'Virtual machine environment detected: No physical UPS hardware or NUT service connected.'
      : 'No NUT daemon or battery hardware detected.',
  };
}

export interface SystemServiceInfo {
  name: string;
  unit: string;
  description: string;
  pluginId?: string;
  pluginEnabled?: boolean;
  // C-B15: 'unknown' means the state could not be read (systemctl
  // failed); it is distinct from 'not-installed' (no unit file) and
  // from 'inactive' (installed but stopped).
  status: 'active' | 'inactive' | 'failed' | 'not-installed' | 'unknown';
  pid: number | null;
  memory: string | null;
  uptime: string | null;
}

export type LiveServiceInfo = SystemServiceInfo;

interface SystemdUnitProbe {
  unit: string;
  loadState?: string;
  status: 'active' | 'inactive' | 'failed' | 'not-installed' | 'unknown';
  pid: number | null;
  memory: string | null;
  uptime: string | null;
}

const SERVICE_UNIT_ALIASES: Record<string, string[]> = {
  'kea-dhcp4-server.service': ['kea-dhcp4-server.service', 'kea-dhcp4.service'],
  'kea-dhcp6-server.service': ['kea-dhcp6-server.service', 'kea-dhcp6.service'],
  'nut-server.service': ['nut-server.service', 'upsd.service'],
  'chrony.service': ['chrony.service', 'chronyd.service'],
  'smbd.service': ['smbd.service', 'smb.service'],
  'ssh.service': ['ssh.service', 'sshd.service'],
  'freeradius.service': ['freeradius.service', 'radiusd.service'],
  'rtslib-fb-targetctl.service': ['rtslib-fb-targetctl.service', 'target.service'],
  'openvpn-server@axonwall.service': ['openvpn-server@axonwall.service', 'openvpn-server@server.service'],
  'strongswan-starter.service': ['strongswan-starter.service', 'strongswan.service', 'charon.service'],
};

/**
 * Queries multiple systemd units in a single batched async invocation so the
 * Next.js event loop is never blocked by sequential `execFileSync` calls.
 */
async function querySystemdUnitsBatch(units: string[]): Promise<Map<string, SystemdUnitProbe>> {
  const uniqueUnits = Array.from(new Set(units.filter(Boolean)));
  const resultMap = new Map<string, SystemdUnitProbe>();
  if (uniqueUnits.length === 0) return resultMap;

  try {
    const { stdout } = await execFileAsync(
      'systemctl',
      [
        '--no-ask-password',
        'show',
        '--property=Id,LoadState,ActiveState,SubState,MainPID,MemoryCurrent',
        ...uniqueUnits,
      ],
      { encoding: 'utf8', timeout: 2500, maxBuffer: 4 * 1024 * 1024 }
    );
    const blocks = stdout.trim() ? stdout.trim().split(/\r?\n\r?\n+/) : [];
    for (let i = 0; i < blocks.length; i++) {
      const props: Record<string, string> = {};
      for (const line of blocks[i]!.split(/\r?\n/)) {
        const idx = line.indexOf('=');
        if (idx > 0) {
          props[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
        }
      }
      const unitId = props['Id'] || (blocks.length === uniqueUnits.length ? uniqueUnits[i]! : '');
      if (!unitId) continue;

      const activeState = props['ActiveState'];
      let status: SystemdUnitProbe['status'] = 'inactive';
      if (props['LoadState'] === 'not-found') status = 'not-installed';
      else if (activeState === 'active') status = 'active';
      else if (activeState === 'failed') status = 'failed';
      else status = 'inactive';

      let pid: number | null = null;
      const parsedPid = parseInt(props['MainPID'] || '0', 10);
      if (parsedPid > 0) pid = parsedPid;

      let memory: string | null = null;
      const memBytes = parseInt(props['MemoryCurrent'] || '0', 10);
      if (memBytes > 0 && memBytes < 1e15) {
        memory = `${(memBytes / (1024 * 1024)).toFixed(1)} MB`;
      }

      const requestedUnit = blocks.length === uniqueUnits.length ? uniqueUnits[i]! : unitId;
      const probe: SystemdUnitProbe = {
        unit: requestedUnit,
        loadState: props['LoadState'],
        status,
        pid,
        memory,
        uptime: status === 'active' && pid ? 'Active' : null,
      };
      resultMap.set(requestedUnit, probe);
      if (!resultMap.has(unitId)) resultMap.set(unitId, probe);
    }
    return resultMap;
  } catch {
    // Fallback when dbus/manager is unavailable: list unit files from disk in one async call.
    // Preserves the C-B15 invariant: inconclusive probes report 'unknown', never 'not-installed'.
    let presentUnits: Set<string> | null = null;
    try {
      const { stdout } = await execFileAsync(
        'systemctl',
        ['--no-ask-password', 'list-unit-files', '--no-legend', '--no-pager', ...uniqueUnits],
        { encoding: 'utf8', timeout: 1500, maxBuffer: 2 * 1024 * 1024 }
      );
      presentUnits = new Set(
        stdout
          .split(/\r?\n/)
          .map((l) => l.trim().split(/\s+/)[0] || '')
          .filter(Boolean)
      );
    } catch (err: any) {
      if (err?.code === 1 || err?.status === 1) {
        presentUnits = new Set<string>();
      }
    }
    for (const unit of uniqueUnits) {
      const status: SystemdUnitProbe['status'] =
        presentUnits === null ? 'unknown' : presentUnits.has(unit) ? 'unknown' : 'not-installed';
      resultMap.set(unit, { unit, status, pid: null, memory: null, uptime: null });
    }
    return resultMap;
  }
}

export async function getSystemServicesStatus(): Promise<SystemServiceInfo[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const desiredState = await getDesiredStateInternal().catch(() => null);

  const units: Array<{ name: string; unit: string; description: string; pluginId?: string }> = [
    { name: 'Axonwall Privileged Daemon', unit: 'axonwalld.service', description: 'Go privileged nftables & netlink transaction supervisor' },
    { name: 'Axonwall Web Console', unit: 'axonwall-ui.service', description: 'Next.js web management application' },
    { name: 'Axonwall Controller', unit: 'axonwall-controller.service', description: 'State synchronization and orchestration engine' },
    { name: 'Keepalived VRRP Daemon', unit: 'keepalived.service', description: 'High availability virtual router failover daemon', pluginId: 'high-availability' },
    { name: 'Conntrack State Sync', unit: 'conntrackd.service', description: 'Connection tracking state table sync over FTFW', pluginId: 'high-availability' },
    { name: 'Suricata IDS/IPS', unit: 'suricata.service', description: 'Next-gen intrusion detection and prevention (NFQUEUE)', pluginId: 'suricata-ids' },
    { name: 'Unbound DNS Resolver', unit: 'unbound.service', description: 'Recursive DNSSEC validating caching resolver with RPZ blocklists', pluginId: 'core-firewall' },
    { name: 'ISC Kea DHCPv4 Server', unit: 'kea-dhcp4-server.service', description: 'High-performance DHCPv4 server', pluginId: 'core-firewall' },
    { name: 'FRRouting Dynamic Engine', unit: 'frr.service', description: 'BGP, OSPF, and BFD routing protocol daemon', pluginId: 'frr-routing' },
    { name: 'CrowdSec Security Engine', unit: 'crowdsec.service', description: 'Collaborative IPS agent and nftables set bouncer', pluginId: 'crowdsec-bouncer' },
    { name: 'Headscale Mesh VPN', unit: 'headscale.service', description: 'Private WireGuard mesh coordination server', pluginId: 'headscale' },
    { name: 'Tailscale Mesh Client', unit: 'tailscaled.service', description: 'Zero-config WireGuard mesh VPN daemon', pluginId: 'tailscale' },
    { name: 'OpenVPN Server', unit: 'openvpn-server@axonwall.service', description: 'SSL/TLS routed and bridged VPN tunnel server', pluginId: 'openvpn' },
    { name: 'strongSwan IPsec', unit: 'strongswan-starter.service', description: 'IKEv2 site-to-site and roadwarrior IPsec VPN', pluginId: 'ipsec-strongswan' },
    { name: 'OpenLDAP Directory Server', unit: 'slapd.service', description: 'Enterprise LDAP directory authentication backend', pluginId: 'directory-ldap' },
    { name: 'SSSD Identity Cache', unit: 'sssd.service', description: 'System Security Services Daemon for LDAP/AD auth', pluginId: 'directory-ldap' },
    { name: 'HAProxy Load Balancer', unit: 'haproxy.service', description: 'L4/L7 reverse proxy and TLS termination daemon', pluginId: 'haproxy' },
    { name: 'FreeRADIUS Server', unit: 'freeradius.service', description: 'RADIUS authentication, authorization, and accounting server', pluginId: 'freeradius' },
    { name: 'SNMP Telemetry Agent', unit: 'snmpd.service', description: 'SNMPv3 telemetry and MIB exporter daemon', pluginId: 'snmp' },
    { name: 'Network UPS Tools (NUT)', unit: 'nut-server.service', description: 'UPS hardware monitoring and shutdown supervisor', pluginId: 'nut-ups' },
    { name: 'Coroot eBPF Node Agent', unit: 'coroot-node-agent.service', description: 'Kernel eBPF APM and service-map collector', pluginId: 'coroot-ebpf-apm' },
    { name: 'ntopng Flow Monitor', unit: 'ntopng.service', description: 'High-speed deep packet inspection and flow monitor', pluginId: 'ntopng' },
    { name: 'Samba File Server', unit: 'smbd.service', description: 'SMB/CIFS enterprise file sharing service', pluginId: 'core-nas' },
    { name: 'K3s Kubernetes Cluster', unit: 'k3s.service', description: 'Lightweight embedded Kubernetes cluster runtime', pluginId: 'core-k3s' },
  ];

  const allCandidates = units.flatMap((u) => SERVICE_UNIT_ALIASES[u.unit] || [u.unit]);
  const probeMap = await querySystemdUnitsBatch(allCandidates);

  const results: SystemServiceInfo[] = [];

  for (const u of units) {
    const candidates = SERVICE_UNIT_ALIASES[u.unit] || [u.unit];
    let probe: SystemdUnitProbe =
      probeMap.get(candidates[0]!) ?? { unit: candidates[0]!, status: 'unknown', pid: null, memory: null, uptime: null };
    if (probe.status === 'not-installed' && candidates.length > 1) {
      for (const altUnit of candidates.slice(1)) {
        const altProbe = probeMap.get(altUnit);
        if (altProbe && altProbe.status !== 'not-installed') {
          probe = altProbe;
          break;
        }
      }
    }

    const pluginEnabled = u.pluginId ? isPluginEnabled(u.pluginId, desiredState ?? undefined) : true;

    results.push({
      ...u,
      pluginEnabled,
      unit: probe.unit,
      status: probe.status,
      pid: probe.pid,
      memory: probe.memory || (probe.status === 'active' ? 'Running' : '-'),
      uptime: probe.uptime || (probe.status === 'active' ? 'Active' : '-'),
    });
  }

  return results;
}

// C3: real service control for the Service Supervisor page. The buttons
// used to be a setTimeout that reported success without executing
// anything. This runs the actual systemctl action against an allowlist
// of the units the page lists — never an arbitrary unit name — and
// reports the real outcome, so a failed restart is a visible failure,
// not a success banner. There is no daemon service-control RPC; the UI
// server already runs privileged systemctl/journalctl reads, so the
// control action lives here beside them. The console's own unit is
// excluded by the page: restarting it from this page would kill the
// request itself.
const CONTROLLABLE_SERVICE_UNITS = [
  'axonwalld.service',
  'axonwall-ui.service',
  'axonwall-controller.service',
  'keepalived.service',
  'conntrackd.service',
  'suricata.service',
  'unbound.service',
  'kea-dhcp4-server.service',
  'kea-dhcp4.service',
  'kea-dhcp6-server.service',
  'kea-dhcp6.service',
  'frr.service',
  'crowdsec.service',
  'headscale.service',
  'tailscaled.service',
  'openvpn-server@axonwall.service',
  'openvpn-server@server.service',
  'strongswan-starter.service',
  'strongswan.service',
  'charon.service',
  'slapd.service',
  'sssd.service',
  'haproxy.service',
  'snmpd.service',
  'coroot-node-agent.service',
  'ntopng.service',
  'k3s.service',
  'nut-server.service',
  'upsd.service',
  'chrony.service',
  'chronyd.service',
  'smbd.service',
  'smb.service',
  'ssh.service',
  'sshd.service',
  'freeradius.service',
  'radiusd.service',
  'rtslib-fb-targetctl.service',
  'target.service',
];

const ALLOWED_SERVICE_JOURNAL_UNITS = new Set<string>([
  ...CONTROLLABLE_SERVICE_UNITS,
  ...Object.values(SERVICE_UNIT_ALIASES).flat(),
]);

export async function getServiceJournalLogs(unit: string): Promise<string> {
  const session = await getSession();
  assertActionPermitted(session);

  const trimmed = unit.trim();
  if (!trimmed || trimmed.startsWith('-') || !/^[a-zA-Z0-9_@.-]+$/.test(trimmed)) {
    throw new Error('Invalid service unit name');
  }
  const normalizedUnit = trimmed.endsWith('.service') ? trimmed : `${trimmed}.service`;
  if (!ALLOWED_SERVICE_JOURNAL_UNITS.has(trimmed) && !ALLOWED_SERVICE_JOURNAL_UNITS.has(normalizedUnit)) {
    throw new Error(`Forbidden: Service unit '${trimmed}' is not in the managed appliance allowlist`);
  }
  const safeUnit = ALLOWED_SERVICE_JOURNAL_UNITS.has(trimmed) ? trimmed : normalizedUnit;
  try {
    const logs = execFileSync('journalctl', ['-u', safeUnit, '-n', '50', '--no-pager'], {
      encoding: 'utf8',
      timeout: 1500,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    if (logs.trim()) return logs.trim();
  } catch {}

  const svcBase = safeUnit.replace(/\.service$/, '');
  for (const logPath of [`/var/log/axonwall/${svcBase}.log`, `/var/log/${svcBase}.log`, '/var/log/messages']) {
    try {
      if (fs.existsSync(logPath)) {
        const raw = execFileSync('tail', ['-n', '50', logPath], { encoding: 'utf8', timeout: 1000 });
        if (raw.trim()) {
          // C-B15: fallback log sources used to be returned bare, so
          // the last 50 lines of the global /var/log/messages were
          // presented as the unit's own "Journal Logs". Every fallback
          // is now labelled with its source; the global log is
          // explicitly flagged as NOT this unit's logs.
          if (logPath === '/var/log/messages') {
            return `-- Source: /var/log/messages (system-wide log — no logs found for ${safeUnit}; entries below are NOT this unit's logs) --\n${raw.trim()}`;
          }
          return `-- Source: ${logPath} (service log file, not the journal) --\n${raw.trim()}`;
        }
      }
    } catch {}
  }

  return `-- No service logs found for ${safeUnit} --`;
}

const CRITICAL_NO_STOP_UNITS = new Set([
  'axonwalld.service',
  'axonwall-ui.service',
  'axonwall-controller.service',
  'ssh.service',
  'sshd.service',
]);

export async function controlSystemService(
  unit: string,
  action: 'start' | 'stop' | 'restart'
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const cleanUnit = (unit || '').trim();
  if (!CONTROLLABLE_SERVICE_UNITS.includes(cleanUnit)) {
    return { success: false, message: `Service control is not available for '${unit}'.` };
  }
  if (action !== 'start' && action !== 'stop' && action !== 'restart') {
    return { success: false, message: `Invalid service action '${action}'.` };
  }
  if (action === 'stop' && CRITICAL_NO_STOP_UNITS.has(cleanUnit)) {
    return {
      success: false,
      message: `Refusing to stop critical control-plane unit '${cleanUnit}': stopping it would sever appliance management or rollback safety.`,
    };
  }
  if (action === 'restart' && cleanUnit === 'axonwall-ui.service') {
    return {
      success: false,
      message: `Refusing to restart '${cleanUnit}' from within the Web Console request handler.`,
    };
  }

  let resolvedUnit = cleanUnit;
  const aliases = SERVICE_UNIT_ALIASES[cleanUnit];
  if (aliases && aliases.length > 1) {
    const probeMap = await querySystemdUnitsBatch(aliases);
    const primary = probeMap.get(aliases[0]!);
    if (!primary || primary.status === 'not-installed') {
      for (const alt of aliases.slice(1)) {
        const altProbe = probeMap.get(alt);
        if (altProbe && altProbe.status !== 'not-installed') {
          resolvedUnit = alt;
          break;
        }
      }
    }
  }

  try {
    execFileSync('systemctl', ['--no-ask-password', action, resolvedUnit], {
      encoding: 'utf8',
      timeout: 30000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { success: true, message: `systemctl ${action} ${resolvedUnit} completed.` };
  } catch (err: any) {
    const detail = (err?.stderr || err?.stdout || err?.message || 'command failed').toString().trim();
    return {
      success: false,
      message: `systemctl ${action} ${resolvedUnit} failed: ${detail.slice(0, 300)}`,
    };
  }
}

// C4 (SSO): a real, live OIDC discovery check for the SSO page's
// "Test IdP Discovery" button, which used to be a timer that always
// reported success. This deliberately does NOT reuse the login flow's
// cached discovery helper: a test button must reflect the IdP's live
// state, not a 10-minute-old cached document, so it fetches with its
// own short timeout and validates all three endpoints.
export async function testOidcDiscoveryAction(
  issuerUrl: string
): Promise<{ ok: boolean; message: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('enterprise-sso');

  const issuer = (issuerUrl || '').trim().replace(/\/+$/, '');
  if (!issuer) {
    return { ok: false, message: 'Enter an OIDC issuer URL first.' };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    let res: Awaited<ReturnType<typeof ssrfSafeFetch>>;
    try {
      res = await ssrfSafeFetch(
        `${issuer}/.well-known/openid-configuration`,
        {
          headers: { accept: 'application/json' },
          signal: controller.signal,
          timeoutMs: 10000,
        },
        { allowHttp: true, allowPrivate: false }
      );
    } finally {
      clearTimeout(timeoutId);
    }
    if (!res.ok) {
      return { ok: false, message: `OIDC discovery failed: ${issuer} returned HTTP ${res.status}.` };
    }
    const doc: any = await res.json();
    const missing = ['authorization_endpoint', 'token_endpoint', 'jwks_uri'].filter(
      (k) => typeof doc?.[k] !== 'string' || !doc[k]
    );
    if (missing.length > 0) {
      return {
        ok: false,
        message: `OIDC discovery document from ${issuer} is incomplete (missing ${missing.join(', ')}).`,
      };
    }
    return {
      ok: true,
      message: `OIDC discovery verified at ${issuer}: authorization, token, and JWKS endpoints all present.`,
    };
  } catch (err: any) {
    const reason = err?.name === 'AbortError' ? 'timed out after 10s' : err?.message || 'fetch failed';
    return { ok: false, message: `OIDC discovery failed for ${issuer}: ${reason}.` };
  }
}

export interface LiveInterfaceInfo {
  name: string;
  device: string;
  type: string;
  ipv4: string;
  gateway: string;
  mtu: number;
  mac: string;
  status: 'Up' | 'Down' | 'Unknown';
}

function getLogicalInterfaceMappings(): Record<string, string> {
  const mapping: Record<string, string> = {};
  try {
    const confPath = path.join(ETC_CONFIG_DIR, 'interfaces.conf');
    if (fs.existsSync(confPath)) {
      const content = fs.readFileSync(confPath, 'utf8');
      const rawKv: Record<string, string> = {};
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
        const eqIdx = trimmed.indexOf('=');
        const k = trimmed.slice(0, eqIdx).trim();
        const v = trimmed.slice(eqIdx + 1).trim();
        rawKv[k] = v;
      }

      if ('AXONWALL_INTERFACES' in rawKv) {
        const activeNames = rawKv.AXONWALL_INTERFACES.split(',')
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean);
        for (const name of activeNames) {
          const keyPrefix = `IFACE_${name.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}`;
          const dev = rawKv[`${keyPrefix}_DEVICE`];
          if (isValidDevice(dev)) {
            mapping[name] = dev;
          }
        }
      } else {
        if (isValidDevice(rawKv.WAN_INTERFACE)) mapping.wan = rawKv.WAN_INTERFACE;
        if (isValidDevice(rawKv.LAN_INTERFACE)) mapping.lan = rawKv.LAN_INTERFACE;
        if (isValidDevice(rawKv.OPT1_INTERFACE)) mapping.opt1 = rawKv.OPT1_INTERFACE;
        if (isValidDevice(rawKv.OPT2_INTERFACE)) mapping.opt2 = rawKv.OPT2_INTERFACE;
        for (const [k, v] of Object.entries(rawKv)) {
          if (k.startsWith('IFACE_') && k.endsWith('_DEVICE') && isValidDevice(v)) {
            const keyCore = k.slice('IFACE_'.length, -'_DEVICE'.length);
            const explicitName = (rawKv[`IFACE_${keyCore}_NAME`] || keyCore).trim().toLowerCase();
            if (explicitName) mapping[explicitName] = v;
          }
        }
      }
    }
  } catch {}
  return mapping;
}

function isPoolValidForSubnet(
  subnetInfo: NonNullable<ReturnType<typeof computeSubnetAndDefaultPool>>,
  poolStartStr?: string,
  poolEndStr?: string,
): boolean {
  if (!poolStartStr || !poolEndStr) return false;
  const startInt = ipToUint32(poolStartStr);
  const endInt = ipToUint32(poolEndStr);
  if (startInt === null || endInt === null) return false;
  return (
    startInt >= subnetInfo.firstUsableInt &&
    endInt <= subnetInfo.lastUsableInt &&
    startInt <= endInt
  );
}

export async function getSystemInterfaces(): Promise<LiveInterfaceInfo[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const confMap = getLogicalInterfaceMappings();
  let state: DesiredState | null = null;
  try {
    state = await getDesiredStateInternal();
  } catch {}

  const devToIface = new Map<string, DesiredState['interfaces'][number]>();
  for (const [logicName, dev] of Object.entries(confMap)) {
    if (isValidDevice(dev)) {
      const stIface = state?.interfaces?.find((i) => i.name === logicName);
      if (stIface) devToIface.set(dev, stIface);
    }
  }
  for (const stIface of state?.interfaces || []) {
    if (stIface.enabled && isValidDevice(stIface.device)) {
      devToIface.set(stIface.device, stIface);
    }
  }

  const ifConfEntries = Object.values(confMap).filter(Boolean);

  try {
    const rawJson = execSync('ip -json address show 2>/dev/null', { encoding: 'utf8', timeout: 1000 });
    const ipData = JSON.parse(rawJson);

    // Get default routes to know gateways (including multi-WAN default routes)
    const defaultGwByDev = new Map<string, string>();
    let primaryDefaultDev = '';
    try {
      const routesJson = execSync('ip -json route show 2>/dev/null', { encoding: 'utf8', timeout: 500 });
      const routes = JSON.parse(routesJson);
      for (const r of routes) {
        if (r.dst === 'default' && r.dev) {
          if (!primaryDefaultDev) primaryDefaultDev = r.dev;
          if (!defaultGwByDev.has(r.dev)) {
            defaultGwByDev.set(r.dev, r.gateway || 'Connected');
          }
        }
      }
    } catch {}

    const results: LiveInterfaceInfo[] = [];

    for (const item of ipData) {
      if (item.ifname === 'lo') continue; // Skip loopback

      const isUp = item.flags?.includes('UP') && !item.flags?.includes('NO-CARRIER');
      const inetAddr = item.addr_info?.find((a: any) => a.family === 'inet');
      const ipv4 = inetAddr ? `${inetAddr.local}/${inetAddr.prefixlen}` : 'Unassigned';

      const mappedIface = devToIface.get(item.ifname);
      let logicalName = mappedIface?.name || item.ifname;
      if (!mappedIface) {
        for (const [k, v] of Object.entries(confMap)) {
          if (v === item.ifname) {
            logicalName = k;
            break;
          }
        }
        if (
          logicalName === item.ifname &&
          ifConfEntries.length === 0 &&
          (item.ifname === primaryDefaultDev || item.ifname.includes('wan') || item.ifname.includes('wlp'))
        ) {
          logicalName = 'wan';
        }
      }

      const role = mappedIface ? inferInterfaceRole(mappedIface) : logicalName.startsWith('wan') ? 'wan' : 'lan';
      const isAuthDhcp = mappedIface
        ? isInterfaceAuthoritativeDhcp(mappedIface, state?.dhcp)
        : logicalName === 'lan';

      let typeLabel = inetAddr?.dynamic ? 'DHCP Client' : inetAddr ? 'Static IPv4' : 'Unconfigured';
      if (role === 'wan') {
        typeLabel = inetAddr?.dynamic ? 'WAN — DHCP Client' : inetAddr ? 'WAN — Static IPv4' : 'WAN — Unconfigured';
      } else if (mappedIface || logicalName !== item.ifname) {
        if (isAuthDhcp) {
          typeLabel = 'LAN — Authoritative DHCP Server';
        } else {
          typeLabel = inetAddr?.dynamic
            ? 'LAN — Joined Network (DHCP Client)'
            : inetAddr
              ? 'LAN — Joined Network (Static IPv4)'
              : 'LAN — Joined Network (Unconfigured)';
        }
      }

      results.push({
        name: logicalName,
        device: item.ifname,
        type: typeLabel,
        ipv4,
        gateway: defaultGwByDev.get(item.ifname) || mappedIface?.ipv4Gateway || 'None',
        mtu: item.mtu || 1500,
        mac: item.address || '00:00:00:00:00:00',
        status: isUp ? 'Up' : 'Down',
      });
    }

    if (results.length > 0) return results;
  } catch {}

  // Fallback to os.networkInterfaces()
  const ifaces = os.networkInterfaces();
  const fallbackList: LiveInterfaceInfo[] = [];

  for (const [name, addrs] of Object.entries(ifaces)) {
    if (name === 'lo' || !addrs) continue;
    const ipv4Info = addrs.find((a) => a.family === 'IPv4');

    const mappedIface = devToIface.get(name);
    let logicalName = mappedIface?.name || name;
    if (!mappedIface) {
      for (const [k, v] of Object.entries(confMap)) {
        if (v === name) {
          logicalName = k;
          break;
        }
      }
    }

    const role = mappedIface ? inferInterfaceRole(mappedIface) : logicalName.startsWith('wan') ? 'wan' : 'lan';
    const isAuthDhcp = mappedIface
      ? isInterfaceAuthoritativeDhcp(mappedIface, state?.dhcp)
      : logicalName === 'lan';
    const typeLabel =
      role === 'wan'
        ? 'WAN Uplink'
        : isAuthDhcp
          ? 'LAN — Authoritative DHCP Server'
          : 'LAN — Joined Network (Non-authoritative)';

    fallbackList.push({
      name: logicalName,
      device: name,
      type: typeLabel,
      ipv4: ipv4Info ? ipv4Info.cidr || `${ipv4Info.address}/24` : 'Unassigned',
      gateway: mappedIface?.ipv4Gateway || 'None',
      mtu: 1500,
      mac: ipv4Info?.mac || '00:00:00:00:00:00',
      status: 'Up',
    });
  }

  return fallbackList;
}

export interface LogicalInterfaceView {
  name: string;
  label: string;
  role: InterfaceRole;
  device: string;
  enabled: boolean;
  type: 'dhcp' | 'static';
  ipv4Address?: string;
  ipv4Gateway?: string;
  description: string;
  mtu: number;
  dhcpServer: boolean;
  dhcpPoolStart?: string;
  dhcpPoolEnd?: string;
  isAuthoritativeDhcp: boolean;
  isOpt: boolean;
  liveStatus: {
    isUp: boolean;
    carrier: string;
    currentIp: string;
    currentGateway: string;
    mac: string;
  };
}

export async function getLogicalInterfacesView(): Promise<LogicalInterfaceView[]> {
  const session = await getSession();
  assertActionPermitted(session);

  const state = await getCurrentDesiredState();
  const liveIfaces = await getSystemInterfaces();
  const confMap = getLogicalInterfaceMappings();

  const mergedList: DesiredState['interfaces'] = [...(state.interfaces || [])];

  // Only seed from legacy interfaces.conf or defaults if DesiredState has no interfaces at all
  if (mergedList.length === 0) {
    for (const [confName, confDev] of Object.entries(confMap)) {
      if (!isValidDevice(confDev)) continue;
      const inferredRole: InterfaceRole = confName.startsWith('wan') ? 'wan' : 'lan';
      mergedList.push({
        name: confName,
        role: inferredRole,
        device: confDev,
        enabled: true,
        type: confName === 'lan' ? 'static' : 'dhcp',
        dhcpServer: confName === 'lan',
        ipv4Address: confName === 'lan' ? '192.168.1.1/24' : undefined,
        mtu: 1500,
        description:
          inferredRole === 'wan'
            ? `${confName.toUpperCase()} Uplink`
            : `${confName.toUpperCase()} Network`,
      });
    }
    if (!mergedList.some((i) => inferInterfaceRole(i) === 'wan')) {
      mergedList.unshift({
        name: 'wan',
        role: 'wan',
        device: confMap.wan || 'eth0',
        enabled: Boolean(confMap.wan),
        type: 'dhcp',
        dhcpServer: false,
        mtu: 1500,
        description: 'Primary WAN Uplink',
      });
    }
    if (!mergedList.some((i) => inferInterfaceRole(i) === 'lan')) {
      mergedList.push({
        name: 'lan',
        role: 'lan',
        device: confMap.lan || 'eth1',
        enabled: Boolean(confMap.lan),
        type: 'static',
        dhcpServer: true,
        ipv4Address: '192.168.1.1/24',
        mtu: 1500,
        description: 'Primary LAN Network',
      });
    }
  }

  // Filter out legacy disabled opt1/opt2 placeholders that have no assigned physical device in interfaces.conf
  const visibleInterfaces = mergedList.filter((iface) => {
    if ((iface.name === 'opt1' || iface.name === 'opt2') && !iface.enabled && !confMap[iface.name]) {
      return false;
    }
    return true;
  });

  return visibleInterfaces.map((existing) => {
    const role = inferInterfaceRole(existing);
    const confDev = confMap[existing.name];
    const existingValidDev = existing.device && isValidDevice(existing.device) ? existing.device : undefined;
    const assignedDev = existingValidDev || confDev || 'none';
    const isEnabled = Boolean(assignedDev && isValidDevice(assignedDev)) && (existing.enabled ?? true);
    const live =
      liveIfaces.find((l) => l.device === assignedDev) ||
      liveIfaces.find((l) => l.name === existing.name);

    const isAuthDhcp = isInterfaceAuthoritativeDhcp(existing, state.dhcp);
    const dhcpSubnet = state.dhcp?.subnets?.find((s) => s.interface === existing.name);
    const defaultPool = computeSubnetAndDefaultPool(
      existing.ipv4Address || (existing.name === 'lan' ? '192.168.1.1/24' : undefined)
    );

    const roleLabel =
      role === 'wan'
        ? `${existing.name.toUpperCase()} (WAN Uplink)`
        : isAuthDhcp
          ? `${existing.name.toUpperCase()} (LAN — Authoritative DHCP)`
          : `${existing.name.toUpperCase()} (LAN — Joined Network)`;

    const defaultDesc =
      role === 'wan'
        ? 'External WAN Uplink'
        : isAuthDhcp
          ? 'Local Network (Authoritative DHCP Server)'
          : 'Joined Existing Network (Non-authoritative)';

    return {
      name: existing.name,
      label: roleLabel,
      role,
      device: assignedDev,
      enabled: isEnabled,
      type: (existing.type === 'static' ? 'static' : 'dhcp') as 'dhcp' | 'static',
      ipv4Address: existing.ipv4Address || (existing.name === 'lan' && existing.type === 'static' ? '192.168.1.1/24' : ''),
      ipv4Gateway: existing.ipv4Gateway || '',
      description: existing.description || defaultDesc,
      mtu: existing.mtu || 1500,
      dhcpServer: isAuthDhcp,
      dhcpPoolStart: dhcpSubnet?.poolStart || defaultPool?.poolStart || '',
      dhcpPoolEnd: dhcpSubnet?.poolEnd || defaultPool?.poolEnd || '',
      isAuthoritativeDhcp: isAuthDhcp,
      isOpt: role === 'lan' && !isAuthDhcp,
      liveStatus: {
        isUp: live?.status === 'Up',
        carrier: live?.status || 'Unknown',
        currentIp: live?.ipv4 || 'Unassigned',
        currentGateway: live?.gateway || 'None',
        mtu: live?.mtu || existing.mtu || 1500,
        mac: live?.mac || '00:00:00:00:00:00',
      } as any,
    };
  });
}

export async function getPhysicalNetworkDevices(): Promise<string[]> {
  const session = await getSession();
  assertActionPermitted(session);

  try {
    const raw = execSync("ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -vx 'lo' 2>/dev/null", { encoding: 'utf8', timeout: 1000 });
    const devs = raw.split('\n').map((s) => s.trim()).filter(Boolean);
    if (devs.length > 0) return Array.from(new Set(devs));
  } catch {}

  const ifaces = os.networkInterfaces();
  const list = Object.keys(ifaces).filter((k) => k !== 'lo');
  return list.length > 0 ? list : ['eth0', 'eth1', 'eth2', 'eth3'];
}

type InterfaceApplyOutcome =
  | { status: 'applied'; preparedState: DesiredState; jobId: string }
  | { status: 'failed'; message: string }
  | { status: 'dev_unreachable'; preparedState: DesiredState; reason: string };

async function submitInterfaceMutationBundle(params: {
  state: DesiredState;
  jobPrefix: string;
  label: string;
  actionNoun: string;
  verbPast: string;
}): Promise<InterfaceApplyOutcome> {
  const { normalizedState: preparedState, yamlDaemonFiles, confContent, ifacesContent } =
    prepareDesiredStateBundle(params.state);

  const jobId = `${params.jobPrefix}-${Date.now()}`;
  let daemonError: string | null = null;
  let daemonTimedOut: string | null = null;
  let daemonUnreachable: string | null = null;

  try {
    const { nftScript, files, reloadServices } = compileNftables(preparedState);
    const bundleHash = crypto.createHash('sha256').update(nftScript).digest('hex');
    const allFiles = buildDaemonBundleFiles({
      preparedState,
      compiledFiles: files,
      yamlDaemonFiles,
      confContent,
      ifacesContent,
    });

    setLastPendingJobId(jobId);
    const applyRes = await callAgentApiDetailed<any>(
      '/v1/apply',
      'POST',
      {
        job_id: jobId,
        bundle_hash: bundleHash,
        nft_script: nftScript,
        files: allFiles,
        reload_services: reloadServices,
        confirm_timeout_seconds: 120,
      },
      120_000
    );

    if (applyRes.kind === 'ok' && applyRes.data?.success) {
      // Do NOT auto-confirm over localhost: operator must verify reachability
      // and confirm via header/API within 120s or axonwalld reverts.
      invalidateDesiredStateCacheInternal();
      return { status: 'applied', preparedState, jobId };
    }
    if (applyRes.kind === 'timeout') {
      try {
        const st = await callAgentApi<any>('/v1/status', 'GET', undefined, 5000);
        const livePending = st?.pending_job_id || st?.pendingJobId;
        if (livePending) setLastPendingJobId(livePending);
      } catch {}
      daemonTimedOut = `apply request timed out after 120s — ${params.actionNoun} may still be committing on axonwalld.`;
    } else if (applyRes.kind === 'http_error' || applyRes.kind === 'ok') {
      daemonError =
        applyRes.kind === 'http_error'
          ? applyRes.message
          : applyRes.data?.message || applyRes.data?.error || `Daemon rejected ${params.actionNoun}`;
    } else {
      daemonUnreachable = 'apply call failed';
    }
  } catch (err: any) {
    daemonUnreachable = err?.message || 'daemon call threw';
  }

  if (daemonError) {
    invalidateDesiredStateCacheInternal();
    setLastPendingJobId('');
    return { status: 'failed', message: `${params.label} was not ${params.verbPast}: ${daemonError}` };
  }

  if (daemonTimedOut) {
    return { status: 'failed', message: `${params.label} ${daemonTimedOut}` };
  }

  const reason = daemonUnreachable || 'daemon unreachable';
  if (!isDevModeRuntime()) {
    invalidateDesiredStateCacheInternal();
    setLastPendingJobId('');
    return {
      status: 'failed',
      message: `${params.label} was NOT ${params.verbPast}: axonwalld is unreachable (${reason}). On-disk configuration was left unchanged.`,
    };
  }

  persistDesiredStateToDisk(preparedState);
  return { status: 'dev_unreachable', preparedState, reason };
}

export async function saveInterfaceAssignment(data: {
  name: string;
  originalName?: string;
  role?: InterfaceRole;
  device: string;
  enabled: boolean;
  type: 'dhcp' | 'static';
  ipv4Address?: string;
  ipv4Gateway?: string;
  description?: string;
  mtu?: number;
  dhcpServer?: boolean;
  dhcpPoolStart?: string;
  dhcpPoolEnd?: string;
}): Promise<{ success: boolean; message: string; pendingConfirm?: boolean; jobId?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const cleanName = (data.name || '')
    .trim()
    .toLowerCase()
    .replace(/-/g, '_')
    .replace(/[^a-z0-9_]/g, '');
  if (!cleanName) {
    throw new Error('Interface name is required (e.g. wan, wan2, lan, lan2, mgmt)');
  }

  const rawDev = (data.device || '').trim();
  const validDev = isValidDevice(rawDev);
  const normalizedDevice = validDev ? rawDev : 'none';
  const normalizedEnabled = Boolean(data.enabled && validDev);

  if (normalizedDevice !== 'none' && !/^[a-zA-Z0-9_.:-]+$/.test(normalizedDevice)) {
    throw new Error('Invalid device name');
  }

  const role: InterfaceRole = data.role || (cleanName.startsWith('wan') ? 'wan' : 'lan');
  const dhcpServer =
    role === 'lan' && data.type === 'static'
      ? (data.dhcpServer ?? (cleanName === 'lan' || cleanName.startsWith('lan')))
      : false;

  const state = await getCurrentDesiredState();
  const lookupName = (data.originalName || cleanName).trim().toLowerCase();
  // C18: a create (no originalName) must not silently overwrite an
  // existing interface. The Interfaces page sends no originalName for
  // "Add", so a stale or failed load that emptied its list used to
  // turn an add into an overwrite of the live LAN assignment. Renames
  // (originalName present) keep the replace path.
  if (!data.originalName?.trim()) {
    if (state.interfaces.some((i) => i.name === cleanName)) {
      throw new Error(
        `Interface '${cleanName}' already exists. Edit the existing interface instead of creating a duplicate.`
      );
    }
  }
  // C-A10: mirror the name-collision check for devices. The UI used to
  // both suggest and permit a device already bound to another logical
  // interface (including a disabled one), and the server accepted it,
  // so two logical interfaces could share one NIC. Renames
  // (originalName present) may keep their own device.
  if (normalizedDevice !== 'none') {
    const holder = state.interfaces.find(
      (i) => i.device === normalizedDevice && i.name.toLowerCase() !== lookupName
    );
    if (holder) {
      throw new Error(
        `Device '${normalizedDevice}' is already assigned to interface '${holder.name}'. Remove or reassign that interface first.`
      );
    }
  }
  const idx = state.interfaces.findIndex((i) => i.name === lookupName);

  const defaultDesc =
    role === 'wan'
      ? `${cleanName.toUpperCase()} WAN Uplink`
      : dhcpServer
        ? `${cleanName.toUpperCase()} LAN (Authoritative DHCP)`
        : `${cleanName.toUpperCase()} LAN (Joined Network)`;

  const updatedIface = InterfaceSchema.parse({
    name: cleanName,
    role,
    device: normalizedDevice,
    enabled: normalizedEnabled,
    type: data.type,
    dhcpServer,
    ipv4Address: data.type === 'static' ? data.ipv4Address : undefined,
    ipv4Gateway:
      (role === 'wan' || role === 'wan-delegated') && data.type === 'static' && data.ipv4Gateway
        ? data.ipv4Gateway
        : undefined,
    description: data.description || defaultDesc,
    mtu: data.mtu || 1500,
  });

  // Reject any static IPv4 subnet that overlaps either another static interface
  // (LAN or WAN) OR a live kernel IPv4 address (e.g. a DHCP lease on OPT1).
  if (data.type === 'static' && data.ipv4Address && normalizedEnabled) {
    const existingIface = idx >= 0 ? state.interfaces[idx] : undefined;
    const excludeDevices = [
      normalizedDevice !== 'none' ? normalizedDevice : '',
      existingIface?.device && existingIface.device !== 'none' ? existingIface.device : '',
    ].filter(Boolean);
    const overlap = findOverlappingSubnet(
      data.ipv4Address,
      state.interfaces,
      readLiveKernelIpv4Addrs(),
      { excludeNames: [lookupName, cleanName], excludeDevices }
    );
    if (overlap) {
      const candidateSub = computeSubnetAndDefaultPool(data.ipv4Address);
      throw new Error(
        `Subnet ${candidateSub?.subnetCidr || data.ipv4Address} overlaps ${overlap.source} (${overlap.cidr}). Assigning an overlapping static subnet on '${normalizedDevice}' creates a competing kernel route that can sever connectivity. Choose a different subnet for '${cleanName}'.`
      );
    }
  }

  if (idx >= 0) {
    state.interfaces[idx] = updatedIface;
  } else {
    state.interfaces.push(updatedIface);
  }

  // If the interface was renamed, update references across firewall rules, NAT, gateways, routes, VIPs, etc.
  if (lookupName && lookupName !== cleanName) {
    for (const r of state.rules || []) {
      if (r.interface === lookupName) r.interface = cleanName;
    }
    for (const n of state.nat || []) {
      if (n.interface === lookupName) n.interface = cleanName;
    }
    for (const g of state.gateways || []) {
      if (g.interface === lookupName) g.interface = cleanName;
    }
    for (const rt of state.routes || []) {
      if (rt.interface === lookupName) rt.interface = cleanName;
    }
    for (const vip of state.virtualIps || []) {
      if (vip.interface === lookupName) vip.interface = cleanName;
    }
    for (const z of state.captivePortal?.zones || []) {
      if (z.interface === lookupName) z.interface = cleanName;
    }
    if (state.suricata?.interfaces) {
      state.suricata.interfaces = state.suricata.interfaces.map((i) => (i === lookupName ? cleanName : i));
    }
    if (state.ha?.syncInterface === lookupName) {
      state.ha.syncInterface = cleanName;
    }
  }

  // Reconcile Kea DHCPv4 subnet for this interface
  if (!state.dhcp) {
    state.dhcp = { enabled: true, subnets: [] };
  }

  if (role === 'lan' && data.type === 'static' && dhcpServer && data.ipv4Address) {
    const subnetInfo = computeSubnetAndDefaultPool(data.ipv4Address);
    if (subnetInfo) {
      const candidateStart = (data.dhcpPoolStart || '').trim();
      const candidateEnd = (data.dhcpPoolEnd || '').trim();
      const validCustomPool = isPoolValidForSubnet(subnetInfo, candidateStart, candidateEnd);
      const poolStart = validCustomPool ? candidateStart : subnetInfo.poolStart;
      const poolEnd = validCustomPool ? candidateEnd : subnetInfo.poolEnd;

      const existingSubIdx = state.dhcp.subnets.findIndex(
        (s) => s.interface === cleanName || s.interface === lookupName,
      );
      if (existingSubIdx >= 0) {
        const prev = state.dhcp.subnets[existingSubIdx];
        const prevSubnetChanged = prev.subnet !== subnetInfo.subnetCidr;
        state.dhcp.subnets[existingSubIdx] = {
          ...prev,
          interface: cleanName,
          subnet: subnetInfo.subnetCidr,
          poolStart,
          poolEnd,
          routers: [subnetInfo.routerIp],
          dnsServers:
            !prevSubnetChanged && prev.dnsServers?.length ? prev.dnsServers : [subnetInfo.routerIp],
        };
        if (lookupName !== cleanName) {
          state.dhcp.subnets = state.dhcp.subnets.filter(
            (s, i) => i === existingSubIdx || s.interface !== lookupName,
          );
        }
      } else {
        state.dhcp.subnets.push({
          id: crypto.randomUUID(),
          interface: cleanName,
          subnet: subnetInfo.subnetCidr,
          poolStart,
          poolEnd,
          routers: [subnetInfo.routerIp],
          dnsServers: [subnetInfo.routerIp],
          staticMappings: [],
          enabled: true,
        });
      }
      state.dhcp.enabled = true;
    }
  } else {
    // Non-authoritative (Joined Network) or WAN: strictly remove from Kea DHCP subnets
    state.dhcp.subnets = (state.dhcp.subnets || []).filter(
      (s) => s.interface !== cleanName && s.interface !== lookupName,
    );
  }

  // Reconcile gateway IP if WAN static gateway was updated
  if (role === 'wan' && data.type === 'static' && data.ipv4Gateway) {
    for (const g of state.gateways || []) {
      if (g.interface === cleanName || g.interface === lookupName) {
        g.gatewayIp = data.ipv4Gateway;
      }
    }
  }

  // Reconcile anti-lockout interfaces across all LAN ports
  const lanNames = state.interfaces
    .filter((i) => inferInterfaceRole(i) === 'lan' && i.enabled && isValidDevice(i.device))
    .map((i) => i.name);
  if (lanNames.length === 0) lanNames.push('lan');
  if (state.system?.antiLockout) {
    state.system.antiLockout.interfaces = Array.from(new Set(lanNames));
    state.system.antiLockout.interface = lanNames[0] || 'lan';
  }

  const outcome = await submitInterfaceMutationBundle({
    state,
    jobPrefix: 'iface',
    label: `Interface ${cleanName.toUpperCase()}`,
    actionNoun: 'the interface change',
    verbPast: 'applied',
  });

  if (outcome.status === 'failed') {
    return {
      success: false,
      message: outcome.message,
    };
  }

  const normalizedState = outcome.preparedState;

  try {
    const { recordGitOpsChangeInternal } = await import('./gitops-internal');
    await recordGitOpsChangeInternal(
      normalizedState,
      session?.username || 'admin',
      `Updated interface ${cleanName.toUpperCase()} (${role.toUpperCase()}, ${
        role === 'lan' ? (dhcpServer ? 'Authoritative DHCP' : 'Joined Network') : data.type.toUpperCase()
      }) -> ${normalizedDevice}`
    );
  } catch {}

  if (outcome.status === 'applied') {
    return {
      success: true,
      pendingConfirm: true,
      jobId: outcome.jobId,
      message: `Interface ${cleanName.toUpperCase()} (${role.toUpperCase()}) applied on ${validDev ? normalizedDevice : '<none>'}. Commit-Confirm active for 120s — click Confirm in the header bar to keep changes, or they will automatically revert.`,
    };
  }

  // Dev-mode unreachable fallback: apply Kea/ip best-effort when axonwalld is not running in dev mode.
  const localErrors: string[] = [];
  const runLocalStep = (label: string, fn: () => void) => {
    try {
      fn();
    } catch (err: any) {
      localErrors.push(`${label}: ${err?.message || 'failed'}`);
    }
  };

  try {
    const { files } = compileNftables(normalizedState);
    const keaFile = files.find((f) => f.path === '/etc/kea/kea-dhcp4.conf');
    if (keaFile && fs.existsSync('/etc/kea')) {
      fs.writeFileSync('/etc/kea/kea-dhcp4.conf', keaFile.content, { mode: 0o640 });
      runLocalStep('kea reload', () =>
        execFileSync('systemctl', ['reload-or-restart', 'kea-dhcp4-server'], { stdio: 'ignore', timeout: 3000 })
      );
    }
  } catch (err: any) {
    localErrors.push(`kea sync: ${err?.message || 'failed'}`);
  }

  if (validDev) {
    if (normalizedEnabled) {
      runLocalStep('ip link up', () =>
        execFileSync('ip', ['link', 'set', normalizedDevice, 'up'], { stdio: 'ignore', timeout: 2000 })
      );
      if (data.type === 'static' && data.ipv4Address) {
        const newAddr = data.ipv4Address;
        let addrAddError: string | null = null;
        try {
          execFileSync('ip', ['addr', 'add', newAddr, 'dev', normalizedDevice], { stdio: 'ignore', timeout: 2000 });
        } catch (err: any) {
          addrAddError = err?.message || 'failed';
        }
        try {
          const shown = execFileSync('ip', ['-j', 'addr', 'show', 'dev', normalizedDevice], {
            encoding: 'utf8',
            timeout: 2000,
            stdio: ['ignore', 'pipe', 'ignore'],
          });
          const parsed = JSON.parse(shown) as Array<{ addr_info?: Array<{ family?: string; local?: string; prefixlen?: number }> }>;
          const oldAddrs = (parsed?.[0]?.addr_info ?? [])
            .filter((a) => a.family === 'inet' && a.local)
            .map((a) => `${a.local}/${a.prefixlen}`)
            .filter((a) => a !== newAddr);
          for (const old of oldAddrs) {
            runLocalStep(`ip addr del ${old}`, () =>
              execFileSync('ip', ['addr', 'del', old, 'dev', normalizedDevice], { stdio: 'ignore', timeout: 2000 })
            );
          }
        } catch (err: any) {
          localErrors.push(`ip addr list: ${err?.message || 'failed'}`);
        }
        try {
          const after = execFileSync('ip', ['addr', 'show', 'dev', normalizedDevice], {
            encoding: 'utf8',
            timeout: 2000,
            stdio: ['ignore', 'pipe', 'ignore'],
          });
          if (!after.includes(newAddr)) {
            localErrors.push(
              `ip addr add: ${newAddr} is not present on ${normalizedDevice} after applying${addrAddError ? ` (add failed: ${addrAddError})` : ''}`
            );
          }
        } catch (err: any) {
          localErrors.push(`ip addr verify: ${err?.message || 'failed'}`);
        }
        if (role === 'wan' && data.ipv4Gateway) {
          const gateway = data.ipv4Gateway;
          runLocalStep('ip route replace', () =>
            execFileSync('ip', ['route', 'replace', 'default', 'via', gateway, 'dev', normalizedDevice], {
              stdio: 'ignore',
              timeout: 2000,
            })
          );
        }
      } else if (data.type === 'dhcp') {
        let handledByDhcpcd = false;
        if (fs.existsSync('/usr/sbin/dhcpcd') || fs.existsSync('/sbin/dhcpcd')) {
          const dhcpcdBin = fs.existsSync('/usr/sbin/dhcpcd') ? '/usr/sbin/dhcpcd' : '/sbin/dhcpcd';
          const before = localErrors.length;
          runLocalStep('dhcpcd', () =>
            execFileSync(
              dhcpcdBin,
              role !== 'wan'
                ? ['-4', '-G', '-C', 'resolv.conf', normalizedDevice]
                : ['-4', normalizedDevice],
              { stdio: 'ignore', timeout: 8000 }
            )
          );
          handledByDhcpcd = localErrors.length === before;
        }
        if (!handledByDhcpcd) {
          runLocalStep('dhclient release', () =>
            execFileSync('dhclient', ['-r', normalizedDevice], { stdio: 'ignore', timeout: 3000 })
          );
          runLocalStep('dhclient', () =>
            execFileSync('dhclient', [normalizedDevice], { stdio: 'ignore', timeout: 5000 })
          );
        }
      }
    } else {
      runLocalStep('ip link down', () =>
        execFileSync('ip', ['link', 'set', normalizedDevice, 'down'], { stdio: 'ignore', timeout: 2000 })
      );
    }
  }

  const localNote =
    localErrors.length > 0
      ? ` Local fallback steps failed: ${localErrors.join('; ')}.`
      : ' Local interface commands ran as a best-effort fallback only.';
  return {
    success: false,
    message: `Interface ${cleanName.toUpperCase()} was saved to disk but NOT applied: axonwalld is unreachable (${outcome.reason}).${localNote}`,
  };
}

export async function deleteInterfaceAssignment(
  name: string
): Promise<{ success: boolean; message: string; pendingConfirm?: boolean; jobId?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');

  const cleanName = (name || '').trim().toLowerCase();
  if (!cleanName) {
    throw new Error('Interface name is required');
  }

  const state = await getCurrentDesiredState();
  state.interfaces = state.interfaces.filter((i) => i.name !== cleanName);
  if (state.dhcp?.subnets) {
    state.dhcp.subnets = state.dhcp.subnets.filter((s) => s.interface !== cleanName);
  }
  const lanNames = state.interfaces
    .filter((i) => inferInterfaceRole(i) === 'lan' && i.enabled && isValidDevice(i.device))
    .map((i) => i.name);
  if (lanNames.length === 0) lanNames.push('lan');
  if (state.system?.antiLockout) {
    state.system.antiLockout.interfaces = Array.from(new Set(lanNames));
    state.system.antiLockout.interface = lanNames[0] || 'lan';
  }

  const outcome = await submitInterfaceMutationBundle({
    state,
    jobPrefix: 'iface-del',
    label: `Interface ${cleanName.toUpperCase()}`,
    actionNoun: 'the interface removal',
    verbPast: 'removed',
  });

  if (outcome.status === 'failed') {
    return {
      success: false,
      message: outcome.message,
    };
  }

  if (outcome.status === 'dev_unreachable') {
    return {
      success: false,
      message: `Interface ${cleanName.toUpperCase()} was removed from disk state but NOT applied: axonwalld is unreachable (${outcome.reason}).`,
    };
  }

  try {
    const { recordGitOpsChangeInternal } = await import('./gitops-internal');
    await recordGitOpsChangeInternal(
      outcome.preparedState,
      session?.username || 'admin',
      `Removed interface ${cleanName.toUpperCase()}`
    );
  } catch {}

  return {
    success: true,
    pendingConfirm: true,
    jobId: outcome.jobId,
    message: `Interface ${cleanName.toUpperCase()} removed. Commit-Confirm active for 120s — click Confirm in the header bar to keep changes, or they will automatically revert.`,
  };
}

export interface LiveGatewayInfo {
  name: string;
  interface: string;
  ip: string;
  monitor: string;
  status: 'online' | 'standby' | 'offline';
  latency: number;
  packetLoss: number;
  tier: number;
}

export async function getGatewaysTelemetry(): Promise<LiveGatewayInfo[]> {
  const session = await getSession();
  assertActionPermitted(session);

  try {
    const routesJson = execSync('ip -json route show 2>/dev/null', { encoding: 'utf8', timeout: 500 });
    const routes = JSON.parse(routesJson);
    const defRoute = routes.find((r: any) => r.dst === 'default');

    if (defRoute && defRoute.gateway) {
      return [
        {
          name: 'DEFAULT_GATEWAY',
          interface: defRoute.dev || 'eth0',
          ip: defRoute.gateway,
          monitor: '1.1.1.1',
          status: 'online',
          latency: 8,
          packetLoss: 0,
          tier: 1,
        },
      ];
    }
  } catch {}

  return [];
}

export interface ThreatAlert {
  timestamp: string;
  signature: string;
  category: string;
  severity: number;
  srcIp: string;
  dstIp: string;
  action: 'blocked' | 'allowed';
}

export async function getRecentThreatAlerts(): Promise<ThreatAlert[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('suricata-ids');
  const evePath = '/var/log/suricata/eve.json';
  if (!fs.existsSync(evePath)) {
    return [];
  }

  try {
    const raw = execFileSync('tail', ['-n', '50', evePath], {
      encoding: 'utf8',
      timeout: 1000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const lines = raw.trim().split('\n');
    const alerts: ThreatAlert[] = [];

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line);
        if (parsed.event_type === 'alert' && parsed.alert) {
          alerts.push({
            timestamp: parsed.timestamp || new Date().toISOString(),
            signature: parsed.alert.signature || 'Threat Signature',
            category: parsed.alert.category || 'Security Alert',
            severity: parsed.alert.severity || 2,
            srcIp: parsed.src_ip || '0.0.0.0',
            dstIp: parsed.dest_ip || '0.0.0.0',
            action: parsed.alert.action === 'blocked' ? 'blocked' : 'allowed',
          });
        }
      } catch {}
    }

    return alerts.slice(-10).reverse();
  } catch {
    return [];
  }
}

export interface LiveFlowRecord {
  srcIp: string;
  dstIp: string;
  protocol: 'TCP' | 'UDP';
  state: string;
}

export interface NetworkInsightTelemetry {
  // G8: null when the /proc read fails (no nf_conntrack module,
  // unreadable /proc) — 0 is a legitimate count, so null marks
  // "unavailable" distinctly.
  conntrackCount: number | null;
  totalRxBytes: number;
  totalTxBytes: number;
  flows: LiveFlowRecord[];
}

export async function getNetworkInsightTelemetry(): Promise<NetworkInsightTelemetry> {
  const session = await getSession();
  assertActionPermitted(session);

  let conntrackCount: number | null = null;
  try {
    const raw = fs.readFileSync('/proc/sys/net/netfilter/nf_conntrack_count', 'utf8');
    const parsed = parseInt(raw.trim(), 10);
    conntrackCount = Number.isNaN(parsed) ? null : parsed;
  } catch {}

  let totalRxBytes = 0;
  let totalTxBytes = 0;
  try {
    const devRaw = fs.readFileSync('/proc/net/dev', 'utf8');
    const lines = devRaw.split('\n');
    for (const line of lines) {
      if (!line.includes(':')) continue;
      const [iface, stats] = line.split(':');
      if (iface.trim() === 'lo') continue;
      const parts = stats.trim().split(/\s+/);
      const rx = parseInt(parts[0], 10) || 0;
      const tx = parseInt(parts[8], 10) || 0;
      totalRxBytes += rx;
      totalTxBytes += tx;
    }
  } catch {}

  const flows: LiveFlowRecord[] = [];
  try {
    const ssOut = execSync('ss -tun 2>/dev/null', { encoding: 'utf8', timeout: 800 });
    const lines = ssOut.trim().split('\n');
    for (let i = 1; i < lines.length && flows.length < 50; i++) {
      const parts = lines[i].trim().split(/\s+/);
      if (parts.length >= 6) {
        const netid = parts[0].toUpperCase();
        const state = parts[1];
        const local = parts[4];
        const peer = parts[5];
        if (local && peer) {
          flows.push({
            srcIp: local,
            dstIp: peer,
            protocol: netid === 'TCP' ? 'TCP' : 'UDP',
            state,
          });
        }
      }
    }
  } catch {}

  // G8: the old code silently replaced a failed /proc read with the
  // number of displayed flows (capped at 50) and labelled it the
  // kernel conntrack count. Return null (unavailable) instead of
  // substituting an unrelated number.
  return {
    conntrackCount,
    totalRxBytes,
    totalTxBytes,
    flows,
  };
}

export interface ReleaseInfo {
  currentVersion: string;
  latestVersion: string;
  isUpToDate: boolean;
  channel: string;
  releaseNotes?: string;
  publishedAt?: string;
  downloadUrl?: string;
}

let cachedReleaseInfo: { data: ReleaseInfo; timestamp: number } | null = null;

function getCurrentInstalledVersion(): string {
  for (const vpath of ['/etc/axonwall/version', './package.json']) {
    try {
      if (fs.existsSync(vpath)) {
        const raw = fs.readFileSync(vpath, 'utf8').trim();
        if (raw.startsWith('{')) {
          const parsed = JSON.parse(raw);
          if (parsed.version) return parsed.version;
        } else if (raw) {
          return raw.split('\n')[0].trim();
        }
      }
    } catch {}
  }
  return '0.16.4';
}

function compareSemver(v1: string, v2: string): number {
  const parse = (v: string) => v.replace(/^v/, '').split(/[-.]/).map((n) => parseInt(n, 10) || 0);
  const p1 = parse(v1);
  const p2 = parse(v2);
  for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
    const num1 = p1[i] || 0;
    const num2 = p2[i] || 0;
    if (num1 > num2) return 1;
    if (num1 < num2) return -1;
  }
  return 0;
}

export async function getReleaseInfo(forceRefresh = false): Promise<ReleaseInfo> {
  const session = await getSession();
  assertActionPermitted(session);
  if (isPasswordChangeEnforced(session)) throw new Error('Forbidden: Password change required');
  const currentVersion = getCurrentInstalledVersion();
  const now = Date.now();

  if (
    !forceRefresh &&
    cachedReleaseInfo &&
    now - cachedReleaseInfo.timestamp < 60000 &&
    cachedReleaseInfo.data.currentVersion === currentVersion
  ) {
    return cachedReleaseInfo.data;
  }

  let latestVersion = currentVersion;
  let releaseNotes = 'You are running the latest stable release of Axonwall.';
  let publishedAt = new Date().toISOString();
  let downloadUrl = 'https://github.com/axonwall/axonwall/releases';
  let remoteResolved = false;

  const applyReleasePayload = (data: any): boolean => {
    if (data && typeof data.tag_name === 'string' && data.tag_name.trim()) {
      latestVersion = data.tag_name.trim().replace(/^v/, '');
      releaseNotes = data.body || 'No release notes provided.';
      publishedAt = data.published_at || publishedAt;
      downloadUrl = data.html_url || downloadUrl;
      return true;
    }
    return false;
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000);

    const res = await fetch('https://api.github.com/repos/axonwall/axonwall/releases/latest', {
      headers: {
        'User-Agent': `Axonwall-Appliance-Updater/${currentVersion}`,
        Accept: 'application/vnd.github.v3+json',
      },
      cache: 'no-store',
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      if (applyReleasePayload(data)) {
        remoteResolved = true;
      }
    } else {
      // Fallback: Check tags
      const tagController = new AbortController();
      const tagTimeoutId = setTimeout(() => tagController.abort(), 12000);
      const tagRes = await fetch('https://api.github.com/repos/axonwall/axonwall/tags?per_page=10', {
        headers: {
          'User-Agent': `Axonwall-Appliance-Updater/${currentVersion}`,
          Accept: 'application/vnd.github.v3+json',
        },
        cache: 'no-store',
        signal: tagController.signal,
      });
      clearTimeout(tagTimeoutId);
      if (tagRes.ok) {
        const tags = await tagRes.json();
        if (Array.isArray(tags) && tags.length > 0) {
          // E12: exact-match only. The old prefix match admitted
          // prerelease tags (1.2.4-rc1) and compareSemver scores them
          // equal to their release, so a prerelease could be offered as
          // the latest *stable* update. Prerelease-suffixed tags are
          // excluded; if none remain, no stable tag is claimed.
          const semverTags = tags
            .map((t: any) => String(t?.name || '').replace(/^v/, ''))
            .filter((t: string) => /^\d+\.\d+\.\d+$/.test(t))
            .sort((a: string, b: string) => compareSemver(b, a));
          if (semverTags.length > 0) {
            latestVersion = semverTags[0];
            remoteResolved = true;
          }
        }
      }
    }
  } catch {
    // Fallback to curl in case Node fetch timed out on primary DNS resolver failover
    try {
      const raw = execFileSync(
        'curl',
        [
          '-fsSL',
          '--connect-timeout',
          '6',
          '--max-time',
          '12',
          '-H',
          `User-Agent: Axonwall-Appliance-Updater/${currentVersion}`,
          '-H',
          'Accept: application/vnd.github.v3+json',
          'https://api.github.com/repos/axonwall/axonwall/releases/latest',
        ],
        { encoding: 'utf8', timeout: 14000, stdio: ['ignore', 'pipe', 'ignore'] }
      );
      if (raw && applyReleasePayload(JSON.parse(raw))) {
        remoteResolved = true;
      }
    } catch {
      // In airgapped or offline VM environments, default to current installed version
      latestVersion = currentVersion;
    }
  }

  const isUpToDate = compareSemver(currentVersion, latestVersion) >= 0;

  const result: ReleaseInfo = {
    currentVersion,
    latestVersion,
    isUpToDate,
    channel: 'stable',
    releaseNotes,
    publishedAt,
    downloadUrl,
  };

  if (remoteResolved) {
    cachedReleaseInfo = { data: result, timestamp: now };
  }
  return result;
}

export interface PartitionSlotInfo {
  slot: 'A' | 'B';
  name: string;
  isActive: boolean;
  isHealthy: boolean;
  // E8: false when no verification of this slot's health has ever run.
  // The daemon's healthVerified flag describes the running system only,
  // so standby health is unknown — never healthy by inheritance. The
  // page renders healthKnown === false as "Unverified", and must check
  // it before trusting isHealthy.
  healthKnown?: boolean;
  version: string;
  kernel: string;
  device: string;
  label: string;
  size: string;
  lastUpdated: string;
}

export interface HealthCheckItem {
  name: string;
  status: 'PASS' | 'FAIL' | 'WARN';
  detail: string;
  durationMs: number;
}

export interface ZfsSnapshotDetailTelemetry {
  name: string;
  fullName: string;
  dataset: string;
  beName: string;
  usedSize: string;
  referSize: string;
  createdAt: string;
}

export interface ZfsBootEnvironmentTelemetry {
  name: string;
  dataset: string;
  activeNow: boolean;
  activeNext: boolean;
  version: string;
  usedSize: string;
  createdAt: string;
  snapshots: string[];
  snapshotDetails?: ZfsSnapshotDetailTelemetry[];
}

export interface BtrfsSnapperSnapshotTelemetry {
  id: number;
  type: string;
  preNum?: number;
  date: string;
  description: string;
  cleanup?: string;
  important?: boolean;
  bootable: boolean;
  subvolume: string;
}

export interface SystemPartitionsTelemetry {
  installMode?: 'ab' | 'rolling' | 'zbm' | 'btrfs';
  slots: PartitionSlotInfo[];
  bootCount: number;
  bootLimit: number;
  healthVerified: boolean;
  kernelVersion: string;
  osVersion: string;
  checks: HealthCheckItem[];
  // E8: true when the daemon could not be reached and this telemetry
  // was assembled from local files only. Slot health is unverified in
  // that case; the page must show an unavailable banner, not PASS.
  daemonUnreachable?: boolean;
  zbmPoolName?: string;
  zbmPoolTopology?: string;
  zbmPoolHealth?: string;
  bootEnvironments?: ZfsBootEnvironmentTelemetry[];
  btrfsLabel?: string;
  btrfsTopology?: string;
  btrfsSnapshots?: BtrfsSnapperSnapshotTelemetry[];
}

export async function getSystemInstallMode(): Promise<'ab' | 'rolling' | 'zbm' | 'btrfs'> {
  const session = await getSession();
  assertActionPermitted(session);

  // 1. Direct file inspection (/etc/axonwall/install-mode, /var/lib/axonwall/install-mode)
  for (const p of ['/etc/axonwall/install-mode', '/var/lib/axonwall/install-mode']) {
    try {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf8').toLowerCase();
        if (content.includes('zbm') || content.includes('zfsbootmenu')) {
          return 'zbm';
        }
        if (content.includes('btrfs') || content.includes('snapper')) {
          return 'btrfs';
        }
        if (content.includes('rolling')) {
          return 'rolling';
        }
        if (content.includes('ab')) {
          return 'ab';
        }
      }
    } catch {}
  }

  // 2. Kernel cmdline inspection
  try {
    if (fs.existsSync('/proc/cmdline')) {
      const cmdline = fs.readFileSync('/proc/cmdline', 'utf8').toLowerCase();
      if (cmdline.includes('root=zfs:') || cmdline.includes('zfsbootmenu') || cmdline.includes('spl.spl_hostid')) {
        return 'zbm';
      }
      if (cmdline.includes('axon_btrfs') || cmdline.includes('rootfstype=btrfs') || cmdline.includes('subvol=@')) {
        return 'btrfs';
      }
      if (cmdline.includes('axon_rolling') || cmdline.includes('rolling')) {
        return 'rolling';
      }
    }
  } catch {}

  try {
    if (fs.existsSync('/proc/mounts') && fs.readFileSync('/proc/mounts', 'utf8').includes(' / btrfs ')) {
      return 'btrfs';
    }
  } catch {}

  // 3. Fallback to daemon if available
  try {
    const daemonData = await callAgentApi<any>('/v1/system/partitions');
    if (
      daemonData?.installMode === 'zbm' ||
      daemonData?.installMode === 'btrfs' ||
      daemonData?.installMode === 'rolling' ||
      daemonData?.installMode === 'ab'
    ) {
      return daemonData.installMode;
    }
  } catch {}

  return 'ab';
}

function detectLocalInstallMode(): 'ab' | 'rolling' | 'zbm' | 'btrfs' {
  for (const p of ['/etc/axonwall/install-mode', '/var/lib/axonwall/install-mode']) {
    try {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf8').toLowerCase();
        if (content.includes('zbm') || content.includes('zfsbootmenu')) {
          return 'zbm';
        }
        if (content.includes('btrfs') || content.includes('snapper')) {
          return 'btrfs';
        }
        if (content.includes('rolling')) {
          return 'rolling';
        }
        if (content.includes('ab')) {
          return 'ab';
        }
      }
    } catch {}
  }
  try {
    if (fs.existsSync('/proc/cmdline')) {
      const cmdline = fs.readFileSync('/proc/cmdline', 'utf8').toLowerCase();
      if (cmdline.includes('root=zfs:') || cmdline.includes('zfsbootmenu') || cmdline.includes('spl.spl_hostid')) {
        return 'zbm';
      }
      if (cmdline.includes('axon_btrfs') || cmdline.includes('rootfstype=btrfs') || cmdline.includes('subvol=@')) {
        return 'btrfs';
      }
    }
  } catch {}
  try {
    if (fs.existsSync('/proc/mounts') && fs.readFileSync('/proc/mounts', 'utf8').includes(' / btrfs ')) {
      return 'btrfs';
    }
  } catch {}
  return 'ab';
}

export async function getSystemPartitionsTelemetry(): Promise<SystemPartitionsTelemetry> {
  const session = await getSession();
  assertActionPermitted(session);
  if (isPasswordChangeEnforced(session)) throw new Error('Forbidden: Password change required');
  const currentVersion = getCurrentInstalledVersion();
  const kernel = os.release() || '6.12.0';
  const localInstallMode = detectLocalInstallMode();

  // 1. Check daemon API if available
  const daemonData = await callAgentApi<any>('/v1/system/partitions');
  if (daemonData && daemonData.activeSlot) {
    const installMode: 'ab' | 'rolling' | 'zbm' | 'btrfs' =
      daemonData.installMode === 'zbm' || localInstallMode === 'zbm'
        ? 'zbm'
        : daemonData.installMode === 'btrfs' || localInstallMode === 'btrfs'
          ? 'btrfs'
          : daemonData.installMode === 'rolling' || localInstallMode === 'rolling'
            ? 'rolling'
            : 'ab';
    const activeSlot = daemonData.activeSlot.toUpperCase();
    const defaultInactive = 'Standby';
    const slotAVer = daemonData.slotAVersion || (activeSlot === 'A' ? currentVersion : defaultInactive);
    const slotBVer = daemonData.slotBVersion || (activeSlot === 'B' ? currentVersion : defaultInactive);
    // E8: healthVerified describes the running system only. The running
    // slot's health is known only when the daemon actually sent the flag;
    // the standby slot's health is never known from this flag.
    const runningHealthKnown =
      daemonData.healthVerified !== undefined && daemonData.healthVerified !== null;
    const runningHealthy = Boolean(daemonData.healthVerified);
    // E-L5 (round-3): derive the standby BE's device from the daemon's
    // bootEnvironments list instead of synthesising it from the version
    // string. The old code assumed every BE is named axonwall-<version>
    // and produced the literal "zroot/ROOT/axonwall-Standby BE" when no
    // BE was known. Prefer the armed (ActiveNext) BE, else the last
    // non-running entry in list order; with no BE known, fall back to
    // the parent dataset label rather than inventing a dataset.
    const standbyBe =
      (daemonData.bootEnvironments || []).find((be: any) => be.activeNext) ||
      [...(daemonData.bootEnvironments || [])].reverse().find((be: any) => !be.activeNow);
    return {
      installMode,
      zbmPoolName: daemonData.zbmPoolName || 'zroot',
      // E2-9: no healthy defaults — when the daemon omits topology /
      // health (its ZFS reads failed), the page renders them unknown
      // instead of a fabricated mirror/ONLINE.
      zbmPoolTopology: daemonData.zbmPoolTopology,
      zbmPoolHealth: daemonData.zbmPoolHealth,
      // E2-9: no synthesised Boot Environment — when the daemon sends
      // no bootEnvironments (an empty list is omitted from its JSON),
      // the page shows no BE rows instead of an invented BE that
      // claims activeNow and activeNext with a made-up size.
      bootEnvironments: daemonData.bootEnvironments || [],
      btrfsLabel: daemonData.btrfsLabel,
      btrfsTopology: daemonData.btrfsTopology,
      btrfsSnapshots: daemonData.btrfsSnapshots || [],
      slots:
        installMode === 'rolling'
          ? [
              {
                slot: 'A',
                name: 'Rolling Root Filesystem (/)',
                isActive: true,
                isHealthy: runningHealthy,
                healthKnown: runningHealthKnown,
                version: slotAVer,
                kernel: daemonData.kernelVersion || kernel,
                device: daemonData.activeRootDevice || '/dev/disk/by-label/axon_root',
                label: 'axon_root',
                size: 'Single-Root / (Full Disk ext4)',
                lastUpdated: 'In-Place Rolling Root + Full APT',
              },
            ]
          : installMode === 'btrfs'
            ? [
                {
                  slot: 'A',
                  name: 'Btrfs + Snapper Root (@)',
                  isActive: true,
                  isHealthy: runningHealthy,
                  healthKnown: runningHealthKnown,
                  version: slotAVer,
                  kernel: daemonData.kernelVersion || kernel,
                  device: daemonData.activeRootDevice || '/dev/disk/by-label/axon_btrfs',
                  label: daemonData.btrfsLabel || 'axon_btrfs',
                  size: 'Btrfs CoW Subvolumes (@ + Snapper)',
                  lastUpdated: slotBVer || 'Btrfs + Snapper Snapshots',
                },
              ]
            : installMode === 'zbm'
            ? [
                {
                  slot: 'A',
                  name: `Boot Environment (${slotAVer})`,
                  isActive: true,
                  isHealthy: runningHealthy,
                  healthKnown: runningHealthKnown,
                  version: slotAVer,
                  kernel: daemonData.kernelVersion || kernel,
                  device: daemonData.activeRootDevice || `zroot/ROOT/axonwall-${slotAVer}`,
                  label: 'zroot/ROOT',
                  size: 'Root-on-ZFS (Copy-on-Write)',
                  lastUpdated: 'Active Running Boot Environment',
                },
                {
                  slot: 'B',
                  name: `Standby BE (${slotBVer})`,
                  isActive: false,
                  // E8: the standby BE was never checked; unknown, not healthy.
                  isHealthy: false,
                  healthKnown: false,
                  version: slotBVer,
                  kernel: daemonData.kernelVersion || kernel,
                  device: standbyBe ? standbyBe.dataset : 'zroot/ROOT',
                  label: 'zroot/ROOT',
                  size: 'Root-on-ZFS (Copy-on-Write)',
                  lastUpdated: 'Standby Boot Environment',
                },
              ]
            : [
              {
                slot: 'A',
                name: 'Slot A (Primary Rootfs)',
                isActive: activeSlot === 'A',
                // E8: only the running slot inherits healthVerified; the
                // standby slot's health is unknown, not healthy.
                isHealthy: activeSlot === 'A' ? runningHealthy : false,
                healthKnown: activeSlot === 'A' ? runningHealthKnown : false,
                version: slotAVer,
                kernel: daemonData.kernelVersion || kernel,
                device: activeSlot === 'A' && daemonData.activeRootDevice ? daemonData.activeRootDevice : '/dev/disk/by-label/axon_root_a',
                label: 'axon_root_a',
                size: '16.0 GB (ext4)',
                lastUpdated: activeSlot === 'A' ? 'Active Running Slot' : 'Standby Slot',
              },
              {
                slot: 'B',
                name: 'Slot B (Alternate Standby)',
                isActive: activeSlot === 'B',
                isHealthy: activeSlot === 'B' ? runningHealthy : false,
                healthKnown: activeSlot === 'B' ? runningHealthKnown : false,
                version: slotBVer,
                kernel: daemonData.kernelVersion || kernel,
                device: activeSlot === 'B' && daemonData.activeRootDevice ? daemonData.activeRootDevice : '/dev/disk/by-label/axon_root_b',
                label: 'axon_root_b',
                size: '16.0 GB (ext4)',
                lastUpdated: activeSlot === 'B' ? 'Active Running Slot' : 'Standby Slot',
              },
            ],
      bootCount: daemonData.bootCount ?? 0,
      bootLimit: daemonData.bootLimit ?? 3,
      healthVerified: Boolean(daemonData.healthVerified),
      kernelVersion: daemonData.kernelVersion || kernel,
      osVersion: daemonData.osVersion || `Axonwall OS v${currentVersion}`,
      // B22: when the daemon omits checks, do not substitute three
      // hardcoded PASS checks that never ran — an empty list means
      // "checks unavailable" and the page renders it as such.
      checks: daemonData.checks ?? [],
    };
  }

  // 2. Fallback: Inspect local OS environment
  let activeSlot: 'A' | 'B' = 'A';
  let bootCount = 0;
  let rootDevice = '/dev/sda2';

  try {
    const cmdline = fs.readFileSync('/proc/cmdline', 'utf8');
    if (cmdline.includes('axon_root_b') || cmdline.includes('slot=B')) {
      activeSlot = 'B';
      rootDevice = '/dev/disk/by-label/axon_root_b';
    } else {
      activeSlot = 'A';
      rootDevice = localInstallMode === 'rolling' ? '/dev/disk/by-label/axon_root' : '/dev/disk/by-label/axon_root_a';
    }
  } catch {}

  try {
    const grubenv = execSync('grub-editenv /boot/grub/grubenv list 2>/dev/null', { encoding: 'utf8', timeout: 500 });
    const countMatch = grubenv.match(/bootcount=(\d+)/);
    if (countMatch) bootCount = parseInt(countMatch[1], 10);
  } catch {}

  let slotAVersion = activeSlot === 'A' ? currentVersion : 'Standby';
  let slotBVersion = activeSlot === 'B' ? currentVersion : 'Standby';
  try {
    for (const svPath of ['/var/lib/axonwall/slot_versions.json', '/etc/axonwall/slot_versions.json']) {
      if (fs.existsSync(svPath)) {
        const data = JSON.parse(fs.readFileSync(svPath, 'utf8'));
        if (data.slotA) slotAVersion = data.slotA;
        if (data.slotB) slotBVersion = data.slotB;
        break;
      }
    }
  } catch {}
  if (activeSlot === 'A') slotAVersion = currentVersion;
  if (activeSlot === 'B') slotBVersion = currentVersion;

  // E8: the daemon is unreachable, so this telemetry comes from local
  // files only. Nothing was verified: slot health is unknown and the
  // checks list must not claim PASS results that never ran.
  return {
    installMode: localInstallMode,
    daemonUnreachable: true,
    btrfsLabel: localInstallMode === 'btrfs' ? 'axon_btrfs' : undefined,
    slots:
      localInstallMode === 'rolling'
        ? [
            {
              slot: 'A',
              name: 'Rolling Root Filesystem (/)',
              isActive: true,
              isHealthy: false,
              healthKnown: false,
              version: slotAVersion,
              kernel,
              device: rootDevice,
              label: 'axon_root',
              size: 'Single-Root / (Full Disk ext4)',
              lastUpdated: 'In-Place Rolling Root + Full APT',
            },
          ]
        : localInstallMode === 'btrfs'
          ? [
              {
                slot: 'A',
                name: 'Btrfs + Snapper Root (@)',
                isActive: true,
                isHealthy: false,
                healthKnown: false,
                version: slotAVersion,
                kernel,
                device: '/dev/disk/by-label/axon_btrfs',
                label: 'axon_btrfs',
                size: 'Btrfs CoW Subvolumes (@ + Snapper)',
                lastUpdated: slotBVersion || 'Btrfs + Snapper Snapshots',
              },
            ]
          : [
            {
              slot: 'A',
              name: 'Slot A (Primary Rootfs)',
              isActive: activeSlot === 'A',
              isHealthy: false,
              healthKnown: false,
              version: slotAVersion,
              kernel,
              device: activeSlot === 'A' ? rootDevice : '/dev/disk/by-label/axon_root_a',
              label: 'axon_root_a',
              size: '16.0 GB (ext4)',
              lastUpdated: activeSlot === 'A' ? 'Current System' : 'Standby Slot',
            },
            {
              slot: 'B',
              name: 'Slot B (Alternate Standby)',
              isActive: activeSlot === 'B',
              isHealthy: false,
              healthKnown: false,
              version: slotBVersion,
              kernel,
              device: activeSlot === 'B' ? rootDevice : '/dev/disk/by-label/axon_root_b',
              label: 'axon_root_b',
              size: '16.0 GB (ext4)',
              lastUpdated: activeSlot === 'B' ? 'Current System' : 'Standby Slot',
            },
          ],
    bootCount,
    bootLimit: 3,
    healthVerified: false,
    kernelVersion: kernel,
    osVersion: `Axonwall OS v${currentVersion}`,
    checks: [
      {
        name: 'Daemon telemetry unavailable',
        status: 'WARN',
        detail: 'axonwalld unreachable — health checks were not run and slot health is unverified',
        durationMs: 0,
      },
    ],
  };
}

function isAdminSession(session: Awaited<ReturnType<typeof getSession>>): boolean {
  if (!session) return false;
  if (isPasswordChangeEnforced(session)) return false;
  if (session.source === 'service_token') {
    return Array.isArray(session.scopes) && session.scopes.includes('*') && Boolean(session.roles?.includes('admin'));
  }
  if (session.source === 'local_admin') return true;
  if (Array.isArray(session.roles) && session.roles.includes('admin')) return true;
  if (Array.isArray(session.privileges) && session.privileges.includes('*')) return true;
  return false;
}

function writeAndMirrorAbGrubEnv(
  args: string[],
  actionLabel: string
): string | null {
  try {
    execFileSync('grub-editenv', ['/boot/grub/grubenv', 'set', ...args], {
      stdio: 'ignore',
      timeout: 1500,
    });
  } catch (err: any) {
    return `${actionLabel}: ${err?.message || 'grub-editenv write failed'}`;
  }

  // E2-4: when running on slot B, GRUB reads slot A's grubenv, so mirror onto slot A.
  try {
    const cmdline = fs.existsSync('/proc/cmdline') ? fs.readFileSync('/proc/cmdline', 'utf8') : '';
    if (cmdline.includes('axon_root_b') || cmdline.includes('slot=B')) {
      const slotADev = '/dev/disk/by-label/axon_root_a';
      if (!fs.existsSync(slotADev)) {
        return `${actionLabel}, but the Slot A mirror could not be made (device ${slotADev} not found)`;
      }
      const runParent = isDevRuntime() ? path.join(getStateDir(), 'run') : '/run/axonwall';
      fs.mkdirSync(runParent, { recursive: true, mode: 0o700 });
      const mntDir = fs.mkdtempSync(path.join(runParent, 'grubenv-slot-a-'));
      let mounted = false;
      try {
        try {
          execFileSync('mount', [slotADev, mntDir], { stdio: 'ignore', timeout: 5000 });
          mounted = true;
        } catch (mountErr: any) {
          return `${actionLabel}, but Slot A could not be mounted to mirror it (${mountErr?.message || 'mount failed'})`;
        }
        try {
          execFileSync('grub-editenv', [`${mntDir}/boot/grub/grubenv`, 'set', ...args], {
            stdio: 'ignore',
            timeout: 1500,
          });
        } catch (mirrorErr: any) {
          return `${actionLabel}, but the Slot A grubenv mirror failed (${mirrorErr?.message || 'grub-editenv failed'})`;
        }
      } finally {
        if (mounted) {
          try {
            execFileSync('umount', [mntDir], { stdio: 'ignore', timeout: 5000 });
          } catch {}
        }
        try {
          fs.rmdirSync(mntDir);
        } catch {}
      }
    }
  } catch (err: any) {
    return `Failed to mirror the GRUB environment to Slot A: ${err?.message || 'mirror failed'}`;
  }
  return null;
}

export async function activatePartitionSlot(slot: 'A' | 'B'): Promise<{ success: boolean; message: string }> {
  // C14: never coerce an invalid slot to 'B'. The type says 'A' |
  // 'B', but a runtime caller can still pass anything; fail closed.
  if (slot !== 'A' && slot !== 'B') {
    return { success: false, message: `Invalid slot: ${JSON.stringify(slot)}. Expected 'A' or 'B'; refusing to arm a slot that was not explicitly requested.` };
  }
  const cleanSlot: 'A' | 'B' = slot;
  try {
    const session = await getSession();
    if (!isAdminSession(session)) {
      return { success: false, message: 'Unauthorized: Admin credentials required to activate partition slot' };
    }

    // 1. Try daemon endpoint
    const daemonResp = await callAgentApi<any>('/v1/system/slot/activate', 'POST', { slot: cleanSlot });
    if (daemonResp) {
      if (daemonResp.success) {
        return { success: true, message: daemonResp.message };
      }
      return {
        success: false,
        message: daemonResp.message || daemonResp.error || `Failed to activate partition Slot ${cleanSlot}`,
      };
    }

    // 2. Direct grub-editenv execution if running as root or with sudo.
    // E-L6 (round-3): this grubenv fallback only arms dual-root A/B
    // installs. On rolling installs there are no slots to arm, and on
    // ZBM installs GRUB's grubenv is not the boot mechanism at all
    // (bootfs is) — neither installer creates /boot/grub/grubenv on
    // those modes, so a write there would report an arming that never
    // happens (grub-editenv creates the file if it does not exist).
    // Refuse instead of reporting success.
    const localInstallMode = detectLocalInstallMode();
    if (localInstallMode !== 'ab') {
      return {
        success: false,
        message:
          localInstallMode === 'zbm'
            ? `Cannot arm Slot ${cleanSlot} via the GRUB environment: this is a ZFSBootMenu install, where the boot target is the pool's bootfs property, not grubenv. The daemon is unreachable, so the slot was NOT armed; do not reboot on the basis of this result.`
            : localInstallMode === 'btrfs'
              ? `Cannot arm Slot ${cleanSlot}: this is a Btrfs + Snapper install with no A/B slots; select a Snapper snapshot to roll back.`
              : `Cannot arm Slot ${cleanSlot}: this is a Rolling Single-Root install with no A/B slots. The slot was NOT armed.`,
      };
    }
    const grubErr = writeAndMirrorAbGrubEnv(
      [`active_slot=${cleanSlot}`, 'bootcount=0'],
      `Failed to arm Slot ${cleanSlot}`
    );
    if (grubErr) {
      return {
        success: false,
        message: `${grubErr}. The active slot was not changed; do not reboot on the basis of this result.`,
      };
    }

    return {
      success: true,
      message: `Partition Slot ${cleanSlot} armed in GRUB environment. System will boot into Slot ${cleanSlot} on next reboot.`,
    };
  } catch (err: any) {
    return {
      success: false,
      message: err?.message || 'Failed to activate partition slot',
    };
  }
}

export async function verifySystemHealthQuorum(): Promise<SystemPartitionsTelemetry> {
  // C-B3: the daemon's verify verdict is the verdict. A null response
  // means axonwalld is unreachable (no tests ran), and healthVerified
  // false means the quorum did not pass — both must fail loudly instead
  // of returning local telemetry that the caller then reports as PASSED.
  // A successful daemon verify really does reset bootcount to 0 and mark
  // the partition permanently healthy (watchdog RunVerification), so the
  // success path below is the only one that may claim that.
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin credentials required to verify system health');
  }
  const verifyResp = await callAgentApi<any>('/v1/system/health/verify', 'POST');
  if (!verifyResp) {
    throw new Error(
      'Health verification unavailable: axonwalld is unreachable — no verification tests ran and bootcount was not reset.'
    );
  }
  if (verifyResp.success === false) {
    throw new Error(verifyResp.message || verifyResp.error || 'Daemon health verification failed.');
  }
  if (verifyResp.healthVerified !== true) {
    const failed = Array.isArray(verifyResp.checks)
      ? verifyResp.checks
          .filter((c: any) => c?.status && c.status !== 'PASS')
          .map((c: any) => `${c.name || 'check'} (${c.status})`)
          .join(', ')
      : '';
    throw new Error(
      `Daemon health verification did not pass${failed ? `: ${failed}` : ''}. Bootcount was not reset.`
    );
  }
  return getSystemPartitionsTelemetry();
}

export interface FirmwareUpgradeResult {
  success: boolean;
  message: string;
  targetSlot: 'A' | 'B';
  newVersion: string;
}

export async function applySystemFirmwareUpdate(targetSlot: 'A' | 'B'): Promise<FirmwareUpgradeResult> {
  // C14: never coerce an invalid slot to 'B'. The type says 'A' |
  // 'B', but a runtime caller can still pass anything; fail closed
  // before any session or daemon work. The echoed targetSlot carries
  // the rejected value verbatim (cast only to satisfy the type) so
  // the failure never masquerades as a flash of the other slot.
  if (targetSlot !== 'A' && targetSlot !== 'B') {
    return {
      success: false,
      message: `Invalid target slot: ${JSON.stringify(targetSlot)}. Expected 'A' or 'B'; refusing to flash a slot that was not explicitly requested.`,
      targetSlot: targetSlot as 'A' | 'B',
      newVersion: getCurrentInstalledVersion(),
    };
  }
  const cleanSlot: 'A' | 'B' = targetSlot;
  const session = await getSession();
  assertInteractiveSession(session);
  try {
    if (!isAdminSession(session)) {
      return {
        success: false,
        message: 'Unauthorized: Administrator credentials required for firmware upgrades',
        targetSlot: cleanSlot,
        newVersion: getCurrentInstalledVersion(),
      };
    }

    const currentVersion = getCurrentInstalledVersion();
    const release = await getReleaseInfo(true);
    const targetVersion = (release.latestVersion || '0.16.4').replace(/[^0-9a-zA-Z._-]/g, '');

    // 1. Delegate privileged firmware update to root daemon (axonwalld) first
    const daemonResp = await callAgentApi<any>(
      '/v1/system/update',
      'POST',
      { slot: cleanSlot, version: targetVersion },
      300000
    );
    if (daemonResp) {
      if (daemonResp.success) {
        cachedReleaseInfo = null;
        return {
          success: true,
          message:
            daemonResp.message ||
            `Firmware v${targetVersion} successfully prepared and flashed to Slot ${cleanSlot}! Watchdog bootcount armed (bootlimit=3). Reboot when ready.`,
          targetSlot: cleanSlot,
          newVersion: daemonResp.newVersion || targetVersion,
        };
      }
      return {
        success: false,
        message:
          daemonResp.message ||
          daemonResp.error ||
          `Firmware update to v${targetVersion} on Slot ${cleanSlot} failed.`,
        targetSlot: cleanSlot,
        newVersion: currentVersion,
      };
    }

    // 2. Fallback: Check if system has axonwall-update utility
    const localInstallMode = detectLocalInstallMode();
    const updaterPaths = ['/usr/local/bin/axonwall-update', '/usr/sbin/axonwall-update'];
    // C6: track whether any flasher actually ran. If neither the daemon
    // nor a local updater exists, the function must report failure — never
    // fall through to GRUB/version writes and an unconditional success.
    let flasherRan = false;
    for (const up of updaterPaths) {
      if (fs.existsSync(up)) {
        flasherRan = true;
        try {
          const cliArgs =
            localInstallMode === 'zbm'
              ? ['--zbm', '--version', targetVersion]
              : localInstallMode === 'btrfs'
                ? ['--btrfs', '--version', targetVersion]
                : localInstallMode === 'rolling'
                  ? ['--rolling', '--version', targetVersion]
                  : ['--slot', cleanSlot, '--version', targetVersion];
          execFileSync(up, cliArgs, {
            stdio: 'pipe',
            timeout: 300000,
          });
        } catch (execErr: any) {
          const stderr = execErr?.stderr ? String(execErr.stderr).trim() : '';
          const stdout = execErr?.stdout ? String(execErr.stdout).trim() : '';
          return {
            success: false,
            message: `axonwall-update failed: ${stderr || stdout || execErr?.message || 'exit error'}`,
            targetSlot: cleanSlot,
            newVersion: currentVersion,
          };
        }
        break;
      }
    }

    // C6: no update backend ran at all — report failure before any GRUB
    // or version-metadata write can make the lie persistent.
    if (!flasherRan) {
      return {
        success: false,
        message: `No firmware update backend available: axonwalld did not answer and no local axonwall-update binary was found; Slot ${cleanSlot} was not flashed.`,
        targetSlot: cleanSlot,
        newVersion: currentVersion,
      };
    }

    // Update GRUB environment only for A/B partitioned installs (skip on Rolling & ZBM)
    if (localInstallMode === 'ab') {
      const grubErr = writeAndMirrorAbGrubEnv(
        [`active_slot=${cleanSlot}`, 'bootcount=0', 'bootlimit=3'],
        `Firmware v${targetVersion} was flashed to Slot ${cleanSlot}, but the watchdog bootcount could NOT be armed`
      );
      if (grubErr) {
        return {
          success: false,
          message: `${grubErr}. A failed boot will not count toward the rollback limit; fix /boot/grub/grubenv and re-arm before relying on watchdog rollback.`,
          targetSlot: cleanSlot,
          newVersion: targetVersion,
        };
      }
    }

    // Persist per-slot version metadata
    try {
      const svPaths = ['/var/lib/axonwall/slot_versions.json', '/etc/axonwall/slot_versions.json'];
      let existing: any = {};
      for (const p of svPaths) {
        if (fs.existsSync(p)) {
          try {
            existing = JSON.parse(fs.readFileSync(p, 'utf8'));
            break;
          } catch {}
        }
      }
      if (cleanSlot === 'A') {
        existing.slotA = targetVersion;
        if (!existing.slotB) existing.slotB = currentVersion;
      } else {
        existing.slotB = targetVersion;
        if (!existing.slotA) existing.slotA = currentVersion;
      }
      existing.updatedAt = new Date().toISOString();
      const content = JSON.stringify(existing, null, 2);
      for (const p of svPaths) {
        try {
          const dir = p.substring(0, p.lastIndexOf('/'));
          if (fs.existsSync(dir)) {
            fs.writeFileSync(p, content, 'utf8');
          }
        } catch {}
      }
    } catch {}

    // Update /etc/axonwall/version if writing to currently active rootfs
    try {
      if (fs.existsSync('/etc/axonwall')) {
        const cmdline = fs.existsSync('/proc/cmdline') ? fs.readFileSync('/proc/cmdline', 'utf8') : '';
        const currentSlot = cmdline.includes('axon_root_b') || cmdline.includes('slot=B') ? 'B' : 'A';
        if (cleanSlot === currentSlot) {
          fs.writeFileSync('/etc/axonwall/version', targetVersion + '\n', 'utf8');
        }
      }
    } catch {}

    cachedReleaseInfo = null;

    return {
      success: true,
      message: `Firmware v${targetVersion} successfully prepared and flashed to Slot ${cleanSlot}! Watchdog bootcount armed (bootlimit=3). Reboot when ready.`,
      targetSlot: cleanSlot,
      newVersion: targetVersion,
    };
  } catch (err: any) {
    return {
      success: false,
      message: err?.message || 'An unexpected error occurred while applying the firmware update.',
      targetSlot: cleanSlot,
      newVersion: getCurrentInstalledVersion(),
    };
  }
}

export async function createZbmSnapshot(
  beName: string,
  label: string,
  newBeName?: string
): Promise<{ success: boolean; message: string; snapshot?: string; dataset?: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    return { success: false, message: 'Unauthorized: Administrator credentials required' };
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/system/zbm',
    'POST',
    {
      action: 'snapshot',
      beName,
      label,
      newBeName,
    },
    120_000
  );
  if (daemonResp && daemonResp.success) {
    return {
      success: true,
      message: daemonResp.message,
      snapshot: daemonResp.snapshot,
      dataset: daemonResp.dataset,
    };
  }
  return { success: false, message: daemonResp?.message || 'Failed to create ZBM snapshot' };
}

export async function deleteZbmSnapshot(snapshot: string): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    return { success: false, message: 'Unauthorized: Administrator credentials required' };
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/system/zbm',
    'POST',
    {
      action: 'delete-snapshot',
      snapshot,
    },
    120_000
  );
  if (daemonResp && daemonResp.success) {
    return { success: true, message: daemonResp.message };
  }
  return { success: false, message: daemonResp?.message || 'Failed to delete ZBM snapshot' };
}

export async function rollbackZbmSnapshot(snapshot: string): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    return { success: false, message: 'Unauthorized: Administrator credentials required' };
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/system/zbm',
    'POST',
    {
      action: 'rollback-snapshot',
      snapshot,
    },
    120_000
  );
  if (daemonResp && daemonResp.success) {
    return { success: true, message: daemonResp.message };
  }
  return { success: false, message: daemonResp?.message || 'Failed to rollback ZBM snapshot' };
}

export async function cloneZbmSnapshot(
  snapshot: string,
  newBeName: string
): Promise<{ success: boolean; message: string; dataset?: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    return { success: false, message: 'Unauthorized: Administrator credentials required' };
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/system/zbm',
    'POST',
    { action: 'clone', snapshot, newBeName },
    120_000
  );
  if (daemonResp && daemonResp.success) {
    return { success: true, message: daemonResp.message, dataset: daemonResp.dataset };
  }
  return { success: false, message: daemonResp?.message || 'Failed to clone ZBM snapshot' };
}

export async function activateZbmBootEnvironment(beName: string): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    return { success: false, message: 'Unauthorized: Administrator credentials required' };
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/system/zbm',
    'POST',
    { action: 'activate', beName },
    120_000
  );
  if (daemonResp && daemonResp.success) {
    return { success: true, message: daemonResp.message };
  }
  return { success: false, message: daemonResp?.message || 'Failed to activate Boot Environment' };
}

export async function deleteZbmBootEnvironment(beName: string): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    return { success: false, message: 'Unauthorized: Administrator credentials required' };
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/system/zbm',
    'POST',
    { action: 'delete', beName },
    120_000
  );
  if (daemonResp && daemonResp.success) {
    return { success: true, message: daemonResp.message };
  }
  return { success: false, message: daemonResp?.message || 'Failed to delete Boot Environment' };
}

async function callBtrfsAction(
  body: Record<string, unknown>,
  fallbackError: string
): Promise<{ success: boolean; message: string; snapshotId?: number }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    return { success: false, message: 'Unauthorized: Administrator credentials required' };
  }
  const daemonResp = await callAgentApiResponse<any>('/v1/system/btrfs', 'POST', body, 120_000);
  if (daemonResp && daemonResp.success) {
    return {
      success: true,
      message: daemonResp.message,
      snapshotId: typeof daemonResp.snapshotId === 'number' ? daemonResp.snapshotId : undefined,
    };
  }
  return { success: false, message: daemonResp?.message || fallbackError };
}

export async function createBtrfsSnapshot(
  description: string,
  important = false
): Promise<{ success: boolean; message: string; snapshotId?: number }> {
  return callBtrfsAction({ action: 'snapshot', description, important }, 'Failed to create Btrfs Snapper snapshot');
}

export async function deleteBtrfsSnapshot(snapshotId: number): Promise<{ success: boolean; message: string }> {
  if (!Number.isInteger(snapshotId) || snapshotId < 1) {
    return { success: false, message: 'Invalid snapshot ID' };
  }
  return callBtrfsAction({ action: 'delete-snapshot', snapshotId }, 'Failed to delete Btrfs Snapper snapshot');
}

export async function rollbackBtrfsSnapshot(snapshotId: number): Promise<{ success: boolean; message: string }> {
  if (!Number.isInteger(snapshotId) || snapshotId < 1) {
    return { success: false, message: 'Invalid snapshot ID' };
  }
  return callBtrfsAction({ action: 'rollback-snapshot', snapshotId }, 'Failed to roll back Btrfs Snapper snapshot');
}

export async function syncBtrfsGrubSnapshots(): Promise<{ success: boolean; message: string }> {
  return callBtrfsAction({ action: 'sync-grub' }, 'Failed to synchronize GRUB Btrfs snapshot menu');
}

export interface PowerActionResult {
  success: boolean;
  message: string;
  action: 'reboot' | 'poweroff';
  slot?: 'A' | 'B';
}

export async function rebootSystemAction(slot?: 'A' | 'B'): Promise<PowerActionResult> {
  const session = await getSession();
  assertInteractiveSession(session);
  if (!isAdminSession(session)) {
    return {
      success: false,
      message: 'Unauthorized: Administrator privileges required to reboot system',
      action: 'reboot',
    };
  }

  const cleanSlot = slot === 'A' || slot === 'B' ? slot : undefined;

  // 1. Try privileged daemon API
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/system/power',
    'POST',
    {
      action: 'reboot',
      slot: cleanSlot,
    },
    60_000
  );
  if (daemonResp && daemonResp.success) {
    return {
      success: true,
      message: daemonResp.message || `System reboot initiated${cleanSlot ? ` into Slot ${cleanSlot}` : ''}.`,
      action: 'reboot',
      slot: cleanSlot,
    };
  }

  // C8: the daemon answered and refused (success: false) — propagate the
  // refusal. Only a null response (daemon unreachable) may fall through
  // to the local fallback below; never reboot around an explicit refusal.
  if (daemonResp) {
    return {
      success: false,
      message:
        daemonResp.message ||
        daemonResp.error ||
        `Daemon refused reboot${cleanSlot ? ` into Slot ${cleanSlot}` : ''}.`,
      action: 'reboot',
      slot: cleanSlot,
    };
  }

  // 2. Direct fallback (daemon unreachable only)
  if (cleanSlot) {
    try {
      const activation = await activatePartitionSlot(cleanSlot);
      if (!activation.success) {
        return {
          success: false,
          message: `Reboot aborted: ${activation.message}`,
          action: 'reboot',
          slot: cleanSlot,
        };
      }
    } catch (err: any) {
      return {
        success: false,
        message: `Reboot aborted: slot activation failed: ${err?.message || 'unknown error'}`,
        action: 'reboot',
        slot: cleanSlot,
      };
    }
  }

  try {
    setTimeout(() => {
      try {
        execSync('systemctl reboot || reboot', { stdio: 'ignore' });
      } catch {}
    }, 500);
    return {
      success: true,
      message: `System reboot initiated${cleanSlot ? ` into Slot ${cleanSlot}` : ''}. Cleanly unmounting storage...`,
      action: 'reboot',
      slot: cleanSlot,
    };
  } catch (err: any) {
    return {
      success: false,
      message: err?.message || 'Failed to execute system reboot',
      action: 'reboot',
      slot: cleanSlot,
    };
  }
}

export async function poweroffSystemAction(): Promise<PowerActionResult> {
  const session = await getSession();
  assertInteractiveSession(session);
  if (!isAdminSession(session)) {
    return {
      success: false,
      message: 'Unauthorized: Administrator privileges required to power off system',
      action: 'poweroff',
    };
  }

  // 1. Try privileged daemon API
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/system/power',
    'POST',
    {
      action: 'poweroff',
    },
    60_000
  );
  if (daemonResp) {
    return {
      success: Boolean(daemonResp.success),
      message:
        daemonResp.message ||
        (daemonResp.success ? 'System power off initiated.' : 'System power off refused by daemon.'),
      action: 'poweroff',
    };
  }

  // 2. Direct fallback
  try {
    setTimeout(() => {
      try {
        execSync('systemctl poweroff || poweroff', { stdio: 'ignore' });
      } catch {}
    }, 500);
    return {
      success: true,
      message: 'System power off sequence initiated. Cleanly halting system...',
      action: 'poweroff',
    };
  } catch (err: any) {
    return {
      success: false,
      message: err?.message || 'Failed to execute system poweroff',
      action: 'poweroff',
    };
  }
}

export interface SensorReading {
  name: string;
  label: string;
  value: number;
  unit: string;
  warning?: number;
  critical?: number;
}

export interface FanReading {
  name: string;
  label: string;
  rpm: number;
}

export interface OpticalModule {
  interface: string;
  vendor: string;
  partNumber: string;
  temperature: number;
  voltage: number;
  txPowerDbm: number;
  rxPowerDbm: number;
  biasCurrentMa: number;
  status: string;
}

export interface HardwareTelemetry {
  hostname: string;
  cpuTempC: number;
  temperatures: SensorReading[];
  fans: FanReading[];
  voltages: SensorReading[];
  transceivers: OpticalModule[];
}

export interface TerminalExecResponse {
  command: string;
  output: string;
  exitCode: number;
  latencyMs: number;
  success: boolean;
}

export async function getHardwareTelemetry(): Promise<HardwareTelemetry> {
  const session = await getSession();
  assertActionPermitted(session);

  // Try live communication with root daemon
  const daemonTelem = await callAgentApi<HardwareTelemetry>('/v1/system/telemetry/hardware');
  if (daemonTelem) {
    return daemonTelem;
  }

  // C-B5: the daemon did not answer, so no sensor was ever read. Never
  // return invented healthy-looking readings — an operator checking a
  // thermal/fan/optic incident would be told everything is normal.
  // Callers render an "unavailable" state instead (see terminal page).
  throw new Error(
    'Hardware telemetry unavailable: axonwalld is unreachable — no sensor readings were taken.'
  );
}

export async function executeTerminalCommand(command: string): Promise<TerminalExecResponse> {
  const session = await getSession();
  assertInteractiveSession(session);
  await enforceRateLimit(30, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('web-terminal');

  const cleanCmd = command.trim();
  if (!cleanCmd) {
    return { command: '', output: '', exitCode: 0, latencyMs: 0, success: true };
  }

  // Try live execution on axonwalld privileged agent
  const execRes = await callAgentApiDetailed<TerminalExecResponse>(
    '/v1/terminal/exec',
    'POST',
    {
      command: cleanCmd,
    },
    60_000
  );
  if (execRes.kind === 'ok') {
    return execRes.data;
  }
  if (execRes.kind === 'http_error') {
    return {
      command: cleanCmd,
      output: execRes.message || 'Terminal command failed on daemon.',
      exitCode: 1,
      latencyMs: 0,
      success: false,
    };
  }
  if (execRes.kind === 'timeout') {
    return {
      command: cleanCmd,
      output: 'Terminal command timed out after 60s on axonwalld.',
      exitCode: 124,
      latencyMs: 60000,
      success: false,
    };
  }

  return {
    command: cleanCmd,
    output: 'Terminal execution unavailable: axonwalld agent socket is offline.',
    exitCode: 1,
    latencyMs: 0,
    success: false,
  };
}

export interface NasDiskItem {
  name: string;
  path: string;
  sizeBytes: number;
  model: string;
  serial: string;
  type: string;
  fsType: string;
  mountpoint: string;
  partLabel: string;
  rotational: boolean;
  smartPassed: boolean;
  temperatureC: number;
  eligibleForZfs: boolean;
  role: string;
}

export interface NasPoolStatus {
  name: string;
  topology: string;
  sizeBytes: number;
  allocBytes: number;
  freeBytes: number;
  fragmentation: number;
  capacityPct: number;
  health: string;
  dataDisks: string[];
}

export interface NasSnapshotItem {
  name: string;
  dataset: string;
  usedBytes: number;
  createdAt: string;
}

export interface K3sNodeTaintItem {
  key: string;
  value?: string;
  effect: 'NoSchedule' | 'PreferNoSchedule' | 'NoExecute';
}

export interface K3sNodeUpdatePayload {
  nodeName: string;
  roles: string[];
  customLabels?: Record<string, string>;
  removeLabels?: string[];
  taints: K3sNodeTaintItem[];
  removeTaints?: K3sNodeTaintItem[];
  unschedulable?: boolean;
}

export interface K3sRuntimeStatus {
  enabled: boolean;
  installed: boolean;
  serviceActive: boolean;
  clusterJoined: boolean;
  role: string;
  nodes: Array<{
    name: string;
    status: string;
    roles: string;
    version: string;
    internalIp: string;
    unschedulable?: boolean;
    labels?: Record<string, string>;
    taints?: K3sNodeTaintItem[];
  }>;
  storageClasses: string[];
  podsRunning: number;
  podsTotal: number;
  openEbsHealthy: boolean;
  // C-H3: true when the daemon did not answer, so the page can say the
  // cluster state is unknown instead of rendering a healthy cluster.
  daemonDown: boolean;
}

export async function getNasDisksInventory(): Promise<{
  disks: NasDiskItem[];
  installSpec: {
    poolName: string;
    topology: string;
    vdevs: string[];
    sizeGb: number;
    systemRaidMode: string;
    systemRaidDisks: string;
    autoCreatePool: boolean;
  } | null;
  // C-M9: true when the daemon did not answer, so callers can say the
  // inventory is unknown instead of rendering an empty (or invented) list.
  daemonDown: boolean;
}> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-nas');

  const daemonResp = await callAgentApi<any>('/v1/nas/disks');
  if (daemonResp && Array.isArray(daemonResp.disks)) {
    return {
      disks: daemonResp.disks,
      installSpec: daemonResp.installSpec || null,
      daemonDown: false,
    };
  }

  if (!isDevModeRuntime()) {
    throw new Error('Daemon unavailable: could not load disk inventory from axonwalld.');
  }

  let installSpec: any = null;
  try {
    if (fs.existsSync('/var/lib/axonwall/install-zfs.json')) {
      installSpec = JSON.parse(fs.readFileSync('/var/lib/axonwall/install-zfs.json', 'utf8'));
    }
  } catch {}

  // C-M9: the daemon did not answer, so no disk inventory is known.
  // Returning invented disks with serial numbers and passing SMART
  // results told the operator a failing (or absent) disk set was healthy.
  // The install spec above is real local file data, so it is kept.
  return {
    disks: [],
    installSpec,
    daemonDown: true,
  };
}

export async function getNasPoolsRuntime(): Promise<NasPoolStatus[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-nas');

  const daemonResp = await callAgentApi<any>('/v1/nas/pools');
  if (daemonResp && Array.isArray(daemonResp.pools)) {
    return daemonResp.pools;
  }

  if (!isDevModeRuntime()) {
    throw new Error('Daemon unavailable: could not load ZFS pool telemetry from axonwalld.');
  }

  const state = await getCurrentDesiredState();
  // C-M9: the daemon did not answer, so no pool runtime is known. Report
  // each configured pool as UNKNOWN with zeroed counters (sizes are
  // unknown, not zero) instead of inventing a 4 TB ONLINE pool.
  return (state.nas?.pools ?? []).map((p) => ({
    name: p.name,
    topology: p.topology,
    sizeBytes: 0,
    allocBytes: 0,
    freeBytes: 0,
    fragmentation: 0,
    capacityPct: 0,
    health: 'UNKNOWN',
    dataDisks: p.dataDisks,
  }));
}

export async function getNasSnapshotsRuntime(): Promise<NasSnapshotItem[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-nas');

  const daemonResp = await callAgentApi<any>('/v1/nas/snapshots');
  if (daemonResp && Array.isArray(daemonResp.snapshots)) {
    return daemonResp.snapshots;
  }

  // R4-C-M2: daemon-down must not collapse to an empty list — the
  // snapshots page cannot tell "no snapshots exist" from "the daemon
  // did not answer". Throw in production (same shape as
  // getNasDisksInventory / getNasPoolsRuntime); the page renders an
  // explicit "Daemon unavailable — snapshot list unknown" banner.
  // Dev mode keeps the empty demo list.
  if (!isDevModeRuntime()) {
    throw new Error('Daemon unavailable: could not load snapshots from axonwalld.');
  }

  return [];
}

export async function createNasSnapshotAction(
  dataset: string,
  label?: string
): Promise<{ success: boolean; snapshot: string; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-nas');

  if (!/^[a-zA-Z0-9][a-zA-Z0-9_./-]*$/.test(dataset) || dataset.includes('..')) {
    throw new Error('Invalid ZFS dataset name');
  }
  if (label !== undefined && label !== '' && !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(label)) {
    throw new Error('Invalid ZFS snapshot label');
  }

  const daemonResp = await callAgentApiResponse<any>('/v1/nas/snapshots', 'POST', { dataset, label }, 120_000);
  if (daemonResp) {
    return {
      success: Boolean(daemonResp.success),
      snapshot: daemonResp.snapshot || '',
      message: daemonResp.message || 'Snapshot created',
    };
  }

  return {
    success: false,
    snapshot: '',
    message: 'Snapshot not created: axonwalld is unreachable. No snapshot exists for this dataset.',
  };
}

export async function scrubNasPoolAction(poolName: string): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-nas');

  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(poolName)) {
    throw new Error('Invalid ZFS pool name');
  }

  const daemonResp = await callAgentApiResponse<any>('/v1/nas/scrub', 'POST', { pool: poolName }, 120_000);
  if (daemonResp) {
    return {
      success: Boolean(daemonResp.success),
      message: daemonResp.message || `Scrub started on pool ${poolName}`,
    };
  }

  return {
    success: false,
    message: `Daemon unavailable: ZFS pool scrub was not started on '${poolName}'.`,
  };
}

export async function rollbackNasSnapshotAction(
  snapshot: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-nas');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_./-]*@[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(snapshot) || snapshot.includes('..')) {
    throw new Error('Invalid ZFS snapshot identifier (expected dataset@label)');
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/nas/snapshots/rollback',
    'POST',
    {
      snapshot,
      destroyNewer: false,
    },
    120_000
  );
  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: snapshot '${snapshot}' was NOT rolled back.`,
    };
  }
  return {
    success: Boolean(daemonResp.success),
    message: daemonResp.message || daemonResp.error || `Rolled back to ${snapshot}`,
  };
}

export async function deleteNasSnapshotAction(
  snapshot: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-nas');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_./-]*@[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(snapshot) || snapshot.includes('..')) {
    throw new Error('Invalid ZFS snapshot identifier (expected dataset@label)');
  }
  const daemonResp = await callAgentApiResponse<any>(
    `/v1/nas/snapshots?snapshot=${encodeURIComponent(snapshot)}`,
    'DELETE',
    undefined,
    60_000
  );
  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: snapshot '${snapshot}' was NOT deleted.`,
    };
  }
  return {
    success: Boolean(daemonResp.success),
    message: daemonResp.message || daemonResp.error || `Deleted snapshot ${snapshot}`,
  };
}

export async function trimNasPoolAction(
  poolName: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-nas');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(poolName)) {
    throw new Error('Invalid ZFS pool name');
  }
  const daemonResp = await callAgentApiResponse<any>('/v1/nas/trim', 'POST', { pool: poolName }, 120_000);
  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: NVMe/SSD TRIM was not started on '${poolName}'.`,
    };
  }
  return {
    success: Boolean(daemonResp.success),
    message: daemonResp.message || daemonResp.error || `Started TRIM on pool ${poolName}`,
  };
}

export async function checkpointNasPoolAction(
  poolName: string,
  discard = false
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-nas');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(poolName)) {
    throw new Error('Invalid ZFS pool name');
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/nas/checkpoint',
    'POST',
    {
      pool: poolName,
      discard: Boolean(discard),
    },
    60_000
  );
  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: ZFS pool checkpoint action did not run on '${poolName}'.`,
    };
  }
  return {
    success: Boolean(daemonResp.success),
    message:
      daemonResp.message ||
      daemonResp.error ||
      (discard ? `Discarded checkpoint on pool ${poolName}` : `Created pool-wide checkpoint on ${poolName}`),
  };
}

export async function manageNasDatasetEncryptionAction(
  dataset: string,
  action: 'load-key' | 'unload-key',
  keyMaterial = ''
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-nas');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_./-]*$/.test(dataset) || dataset.includes('..')) {
    throw new Error('Invalid ZFS dataset name');
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/nas/encryption',
    'POST',
    {
      dataset,
      action,
      keyMaterial,
    },
    60_000
  );
  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: ZFS encryption ${action} did not run on '${dataset}'.`,
    };
  }
  return {
    success: Boolean(daemonResp.success),
    message: daemonResp.message || daemonResp.error || `Dataset ${dataset} ${action} completed.`,
  };
}

export async function runNasSmartTestAction(
  device: string,
  testType: 'short' | 'long' = 'short'
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-nas');
  if (!/^\/dev\/[a-zA-Z0-9/_-]+$/.test(device) || device.includes('..')) {
    throw new Error('Invalid block device path');
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/nas/smart-test',
    'POST',
    {
      device,
      testType,
    },
    60_000
  );
  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: S.M.A.R.T. ${testType} test did not start on '${device}'.`,
    };
  }
  return {
    success: Boolean(daemonResp.success),
    message:
      daemonResp.output ||
      daemonResp.message ||
      daemonResp.error ||
      `Initiated S.M.A.R.T. ${testType} self-test on ${device}`,
  };
}

export async function runNasCloudSyncAction(
  taskName: string
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-nas');
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(taskName)) {
    throw new Error('Invalid Cloud Sync task name');
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/nas/cloud-sync',
    'POST',
    {
      taskName,
    },
    120_000
  );
  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: Cloud Sync task '${taskName}' was not executed.`,
    };
  }
  return {
    success: Boolean(daemonResp.success),
    message:
      daemonResp.output ||
      daemonResp.message ||
      daemonResp.error ||
      `Executed Cloud Sync task '${taskName}'.`,
  };
}

export async function syncDdnsNowAction(): Promise<{
  success: boolean;
  message: string;
  entries?: Array<{ hostname: string; provider: string; lastIp?: string; status?: string }>;
}> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  const daemonResp = await callAgentApi<any>('/v1/ddns/status', 'POST', {});
  if (!daemonResp) {
    return {
      success: false,
      message: 'Daemon unavailable: DDNS sync was not triggered.',
    };
  }
  const count = Array.isArray(daemonResp.entries) ? daemonResp.entries.length : 0;
  return {
    success: true,
    message: `Triggered DDNS sync across ${count} configured record(s).`,
    entries: daemonResp.entries,
  };
}

export interface K3sEtcdSnapshotItem {
  name: string;
  location?: string;
  sizeBytes?: number;
  createdAt?: string;
}

export async function getK3sEtcdSnapshotsAction(): Promise<K3sEtcdSnapshotItem[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-k3s');
  const daemonResp = await callAgentApi<{ snapshots?: K3sEtcdSnapshotItem[] }>('/v1/k3s/etcd-snapshots');
  if (!daemonResp && !isDevModeRuntime()) {
    throw new Error('Daemon unavailable: could not load K3s etcd snapshots from axonwalld.');
  }
  return Array.isArray(daemonResp?.snapshots) ? daemonResp!.snapshots! : [];
}

export async function manageK3sEtcdSnapshotAction(
  action: 'save' | 'restore',
  name = ''
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-k3s');
  if (name && !/^[a-zA-Z0-9_.-]{1,128}$/.test(name)) {
    throw new Error('Invalid etcd snapshot name');
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/k3s/etcd-snapshots',
    'POST',
    {
      action,
      name,
    },
    120_000
  );
  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: K3s etcd snapshot ${action} was not executed.`,
    };
  }
  return {
    success: Boolean(daemonResp.success),
    message: daemonResp.message || daemonResp.error || `K3s etcd snapshot ${action} completed.`,
  };
}

export async function getK3sRuntimeStatus(): Promise<K3sRuntimeStatus> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-k3s');

  const daemonResp = await callAgentApi<any>('/v1/k3s/status');
  if (daemonResp) {
    return {
      enabled: Boolean(daemonResp.enabled ?? daemonResp.service_active ?? daemonResp.serviceActive),
      installed: Boolean(daemonResp.installed ?? false),
      serviceActive: Boolean(daemonResp.service_active ?? daemonResp.serviceActive),
      clusterJoined: Boolean(daemonResp.cluster_joined ?? daemonResp.clusterJoined),
      role: daemonResp.role || (daemonResp.is_server || daemonResp.isServer ? 'primary-server' : 'agent-worker'),
      nodes: (daemonResp.nodes || []).map((n: any) => ({
        name: n.name || '',
        status: n.status || 'Unknown',
        roles: n.roles || n.role || '',
        version: n.version || '',
        internalIp: n.internal_ip || n.internalIp || '',
        unschedulable: Boolean(n.unschedulable),
        labels: n.labels && typeof n.labels === 'object' ? n.labels : {},
        taints: Array.isArray(n.taints) ? n.taints : [],
      })),
      storageClasses: daemonResp.storage_classes || daemonResp.storageClasses || [],
      podsRunning: Number(daemonResp.pods_running ?? daemonResp.podsRunning ?? 0),
      podsTotal: Number(daemonResp.pods_total ?? daemonResp.podsTotal ?? 0),
      openEbsHealthy: Boolean(daemonResp.openebs_healthy ?? daemonResp.openEbsHealthy),
      daemonDown: false,
    };
  }

  if (!isDevModeRuntime()) {
    throw new Error('Daemon unavailable: could not load K3s runtime status from axonwalld.');
  }

  const state = await getCurrentDesiredState();
  const k3sEnabled = Boolean(state.capabilities?.k3sEnabled ?? state.k3s?.enabled);

  // C-H3: the daemon did not answer, so the live cluster state is
  // unknown. Report that (plus the configured enabled flag, which is real
  // desired-state data) instead of fabricating a healthy Ready cluster
  // with an invented node, version, storage classes and pod counts.
  return {
    enabled: k3sEnabled,
    installed: false,
    serviceActive: false,
    clusterJoined: false,
    role: 'unknown',
    nodes: [],
    storageClasses: [],
    podsRunning: 0,
    podsTotal: 0,
    openEbsHealthy: false,
    daemonDown: true,
  };
}

export async function updateK3sNodeSchedulingAction(
  payload: K3sNodeUpdatePayload
): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-k3s');
  const nodeName = (payload.nodeName || '').trim();
  if (!/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/.test(nodeName)) {
    throw new Error(`Invalid Kubernetes node name: ${payload.nodeName}`);
  }
  const daemonResp = await callAgentApiResponse<any>(
    '/v1/k3s/nodes/scheduling',
    'POST',
    {
      ...payload,
      nodeName,
    },
    30_000
  );
  if (!daemonResp) {
    return {
      success: false,
      message: `Daemon unavailable: could not update scheduling on node '${nodeName}'.`,
    };
  }
  return {
    success: Boolean(daemonResp.success),
    message:
      daemonResp.message ||
      daemonResp.error ||
      `Updated roles and taints on node ${nodeName}.`,
  };
}

export async function triggerK3sHaAutoJoin(): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!isAdminSession(session)) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  await assertPluginEnabled('core-k3s');

  const state = await getCurrentDesiredState();
  const peerIp = state.ha?.peerIp || state.ha?.peerAddress || '';
  const syncPort = state.ha?.sqliteSync?.listenPort || state.ha?.peerPort || 9876;
  const authToken = state.ha?.sqliteSync?.authToken || '';

  const daemonResp = await callAgentApiResponse<any>(
    '/v1/k3s/join',
    'POST',
    {
      peerIp,
      syncPort,
      authToken,
    },
    120_000
  );
  if (daemonResp) {
    if (!daemonResp.success) {
      throw new Error(daemonResp.message || daemonResp.error || 'Failed to auto-join K3s cluster');
    }
    return {
      success: Boolean(daemonResp.success),
      message: daemonResp.message || 'Joined HA K3s cluster and reconciled OpenEBS storage.',
    };
  }

  // C-H4 (round-3) is preserved in production by the non-dev branch
  // above: a null response means the daemon never ran the join, so it is
  // a failure, not a success. The dev-mode success below is main's
  // deliberate dev-mode simulation, explicitly labelled DEV MODE.
  if (!isDevModeRuntime()) {
    return {
      success: false,
      message: 'Daemon unavailable: K3s HA peer auto-join requires live axonwalld.',
    };
  }

  return {
    success: true,
    message: 'Fetched K3s join token from HA primary node over mTLS and joined cluster with OpenEBS storage classes (DEV MODE).',
  };
}

export interface AutoDetectedSubnet {
  id: string;
  label: string;
  device: string;
  role: string;
  ip: string;
  cidr: string;
  gateway?: string;
  operstate: string;
  suggestedCommands: {
    pingSweep: string;
    fastPorts: string;
    serviceOs: string;
    vulnAudit: string;
  };
}

export interface AutoCliDefaults {
  hostname: string;
  defaultInterface: string;
  defaultSubnetCidr: string;
  defaultGatewayIp: string;
  defaultDnsServer: string;
  subnets: AutoDetectedSubnet[];
  interfaces: string[];
  availableTools: Record<string, boolean>;
}

function ipNetmaskToCidr(ip: string, netmask: string): string {
  const ipParts = ip.split('.').map(Number);
  const maskParts = netmask.split('.').map(Number);
  if (ipParts.length !== 4 || maskParts.length !== 4) return `${ip}/24`;
  const netParts = ipParts.map((p, idx) => p & (maskParts[idx] ?? 255));
  const prefix = maskParts.reduce((acc, octet) => acc + (octet.toString(2).match(/1/g) || []).length, 0);
  return `${netParts.join('.')}/${prefix}`;
}

function ipCidrToNetworkCidr(ipCidr: string): { ip: string; cidr: string } {
  const [ipPart = '192.168.1.1', prefixStr = '24'] = ipCidr.split('/');
  const prefix = Math.min(32, Math.max(8, Number(prefixStr) || 24));
  const parts = ipPart.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) {
    return { ip: ipPart, cidr: ipCidr.includes('/') ? ipCidr : `${ipCidr}/24` };
  }
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const ipInt = (((parts[0] ?? 0) << 24) | ((parts[1] ?? 0) << 16) | ((parts[2] ?? 0) << 8) | (parts[3] ?? 0)) >>> 0;
  const netInt = (ipInt & mask) >>> 0;
  const netIp = [
    (netInt >>> 24) & 255,
    (netInt >>> 16) & 255,
    (netInt >>> 8) & 255,
    netInt & 255,
  ].join('.');
  return { ip: ipPart, cidr: `${netIp}/${prefix}` };
}

function hasBinary(bin: string): boolean {
  for (const dir of ['/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin', '/usr/local/sbin']) {
    if (fs.existsSync(path.join(dir, bin))) return true;
  }
  return false;
}

export async function getAutoCliDefaults(): Promise<AutoCliDefaults> {
  const session = await getSession();
  assertActionPermitted(session);

  const state = await getCurrentDesiredState();
  const subnets: AutoDetectedSubnet[] = [];
  const seenCidrs = new Set<string>();
  const interfaceNames = new Set<string>();

  // 1. Add configured Axonwall interfaces (LAN, WAN, OPT1, OPT2, etc.)
  for (const iface of state.interfaces || []) {
    if (iface.device) interfaceNames.add(iface.device);
    if (iface.ipv4Address) {
      const { ip, cidr } = ipCidrToNetworkCidr(iface.ipv4Address);
      if (!seenCidrs.has(cidr)) {
        seenCidrs.add(cidr);
        subnets.push({
          id: `cfg-${iface.name}`,
          label: `${iface.name.toUpperCase()} (${iface.device}) — ${iface.description || cidr}`,
          device: iface.device,
          role: iface.name.toUpperCase(),
          ip,
          cidr,
          gateway: iface.ipv4Gateway,
          operstate: iface.enabled ? 'UP' : 'DOWN',
          suggestedCommands: {
            pingSweep: `nmap -sn -T4 ${cidr}`,
            fastPorts: `nmap -F -T4 ${cidr}`,
            serviceOs: `nmap -sV -O --version-light -T4 ${cidr}`,
            vulnAudit: `nmap -sV --script=banner,http-title,ssl-cert -T4 ${cidr}`,
          },
        });
      }
    }
  }

  // 2. Add live OS network interfaces
  const osNet = os.networkInterfaces();
  for (const [ifName, addrs] of Object.entries(osNet)) {
    if (!addrs) continue;
    if (ifName !== 'lo') interfaceNames.add(ifName);
    for (const addr of addrs) {
      if ((addr.family === 'IPv4' || (addr as any).family === 4) && !addr.internal) {
        const cidr = ipNetmaskToCidr(addr.address, addr.netmask);
        if (!seenCidrs.has(cidr)) {
          seenCidrs.add(cidr);
          subnets.push({
            id: `os-${ifName}-${addr.address}`,
            label: `${ifName} (Live OS NIC) — ${cidr}`,
            device: ifName,
            role: 'LIVE',
            ip: addr.address,
            cidr,
            operstate: 'UP',
            suggestedCommands: {
              pingSweep: `nmap -sn -T4 ${cidr}`,
              fastPorts: `nmap -F -T4 ${cidr}`,
              serviceOs: `nmap -sV -O --version-light -T4 ${cidr}`,
              vulnAudit: `nmap -sV --script=banner,http-title,ssl-cert -T4 ${cidr}`,
            },
          });
        }
      }
    }
  }

  // 3. Add configured static routes from routing.yaml
  for (const route of state.routes || []) {
    if (route.enabled !== false && route.network && !seenCidrs.has(route.network)) {
      seenCidrs.add(route.network);
      subnets.push({
        id: `route-${route.network}`,
        label: `Static Route (${route.interface || 'routed'}) — ${route.network}${route.description ? ` [${route.description}]` : ''}`,
        device: route.interface || 'eth0',
        role: 'ROUTE',
        ip: route.gateway,
        cidr: route.network,
        gateway: route.gateway,
        operstate: 'ROUTED',
        suggestedCommands: {
          pingSweep: `nmap -sn -T4 ${route.network}`,
          fastPorts: `nmap -F -T4 ${route.network}`,
          serviceOs: `nmap -sV -O --version-light -T4 ${route.network}`,
          vulnAudit: `nmap -sV --script=banner,http-title,ssl-cert -T4 ${route.network}`,
        },
      });
    }
  }

  const lanSubnet =
    subnets.find((s) => s.role === 'LAN') ||
    subnets.find((s) => s.role === 'LIVE') ||
    subnets[0];

  const defaultGateway =
    state.gateways?.find((g) => g.isDefault)?.gatewayIp ||
    state.gateways?.[0]?.gatewayIp ||
    lanSubnet?.ip ||
    '192.168.1.1';

  const defaultDns =
    state.dns?.dotUpstreams?.[0] ||
    state.system?.dnsServers?.[0] ||
    '1.1.1.1';

  const allIfaces = Array.from(interfaceNames);
  if (allIfaces.length === 0) allIfaces.push('eth0', 'eth1');

  return {
    hostname: state.system?.hostname || os.hostname() || 'axonwall',
    defaultInterface: lanSubnet?.device || allIfaces[0] || 'eth0',
    defaultSubnetCidr: lanSubnet?.cidr || '192.168.1.0/24',
    defaultGatewayIp: defaultGateway,
    defaultDnsServer: defaultDns,
    subnets,
    interfaces: allIfaces,
    availableTools: {
      nmap: hasBinary('nmap'),
      btop: hasBinary('btop'),
      htop: hasBinary('htop'),
      mpstat: hasBinary('mpstat'),
      iostat: hasBinary('iostat'),
      iotop: hasBinary('iotop'),
      iftop: hasBinary('iftop'),
      slurm: hasBinary('slurm'),
      netstat: hasBinary('netstat'),
      arp: hasBinary('arp'),
      dig: hasBinary('dig'),
      zsh: hasBinary('zsh'),
      vim: hasBinary('vim'),
    },
  };
}

export async function runNmapScan(params: {
  target: string;
  profile: 'ping' | 'fast_ports' | 'service_os' | 'vuln_audit' | 'traceroute';
  simulated?: boolean;
}): Promise<{
  success: boolean;
  xml?: string;
  command: string;
  mode: 'live' | 'simulated';
  durationMs: number;
  error?: string;
}> {
  const session = await getSession();
  await enforceRateLimit(10, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('cli-diagnostics-nastymap');

  const cleanTarget = params.target.trim();
  const invalidTargetResp = {
    success: false,
    command: '',
    mode: 'simulated' as const,
    durationMs: 0,
    error: 'Invalid scan target. Specify a valid IPv4/IPv6 address, narrow CIDR subnet, or hostname.',
  };
  if (!cleanTarget || cleanTarget.startsWith('-')) {
    return invalidTargetResp;
  }

  // Prevent denial of service from scanning broad CIDR blocks or hyphenated IP ranges (e.g. 192.168.1.1-254)
  if (cleanTarget.includes('/')) {
    const parts = cleanTarget.split('/');
    const ipPart = parts[0] || '';
    const prefixStr = parts[1] || '';
    const ipFamily = net.isIP(ipPart);
    if (parts.length !== 2 || ipFamily === 0 || !/^\d+$/.test(prefixStr)) {
      return invalidTargetResp;
    }
    const prefix = parseInt(prefixStr, 10);
    if (ipFamily === 6 ? prefix < 120 || prefix > 128 : prefix < 24 || prefix > 32) {
      return {
        success: false,
        command: '',
        mode: 'simulated',
        durationMs: 0,
        error: 'Subnet scan range is too broad. Minimum allowed prefix is /24 for IPv4 and /120 for IPv6.',
      };
    }
  } else if (net.isIP(cleanTarget) === 0) {
    const isValidHostname =
      cleanTarget.length <= 253 &&
      /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(
        cleanTarget
      ) &&
      /[a-zA-Z]/.test(cleanTarget) &&
      !/(?:^|\.)\d+-\d+(?:\.|$)/.test(cleanTarget);
    if (!isValidHostname) {
      return invalidTargetResp;
    }
  }

  const profileFlags: Record<typeof params.profile, string[]> = {
    ping: ['-sn', '-T4'],
    fast_ports: ['-F', '-T4'],
    service_os: ['-sV', '--version-light', '-T4'],
    vuln_audit: ['-sV', '--version-light', '--script=banner,http-title,ssl-cert', '-T4'],
    traceroute: ['-F', '--traceroute', '-T4'],
  };

  const flags = profileFlags[params.profile] || ['-F', '-T4'];
  const displayCmd = `nmap ${flags.join(' ')} ${cleanTarget}`;
  const startMs = Date.now();

  if (!params.simulated) {
    if (!hasBinary('nmap')) {
      return {
        success: false,
        command: displayCmd,
        mode: 'live',
        durationMs: Date.now() - startMs,
        error: 'nmap binary is not installed on this appliance',
      };
    }
    try {
      const args = [...flags, '-oX', '-', cleanTarget];
      const { stdout: xmlOut } = await execFileAsync('nmap', args, {
        encoding: 'utf-8',
        timeout: 60000,
        maxBuffer: 10 * 1024 * 1024,
      });
      if (xmlOut && xmlOut.includes('<nmaprun')) {
        return {
          success: true,
          xml: xmlOut,
          command: displayCmd,
          mode: 'live',
          durationMs: Date.now() - startMs,
        };
      }
      return {
        success: false,
        command: displayCmd,
        mode: 'live',
        durationMs: Date.now() - startMs,
        error: 'Live Nmap scan completed without valid XML output',
      };
    } catch (err: any) {
      const stdoutStr = typeof err?.stdout === 'string' ? err.stdout : err?.stdout?.toString?.('utf-8') || '';
      if (stdoutStr.includes('<nmaprun')) {
        return {
          success: true,
          xml: stdoutStr,
          command: displayCmd,
          mode: 'live',
          durationMs: Date.now() - startMs,
        };
      }
      return {
        success: false,
        command: displayCmd,
        mode: 'live',
        durationMs: Date.now() - startMs,
        error: err?.message || 'Live Nmap scan failed',
      };
    }
  }

  // Return empty xml marker so client uses NastyMap's built-in scenario generator for cleanTarget
  return {
    success: true,
    command: displayCmd,
    mode: 'simulated',
    durationMs: Math.max(120, Date.now() - startMs),
  };
}

export type CliUtilityId =
  | 'sysstat'
  | 'net_tools'
  | 'dnsutils'
  | 'bandwidth'
  | 'top_procs'
  | 'iotop';

export async function runCliToolSnapshot(
  tool: CliUtilityId,
  options?: {
    iface?: string;
    target?: string;
    dnsServer?: string;
    recordType?: string;
  }
): Promise<{
  success: boolean;
  command: string;
  output: string;
  timestamp: string;
}> {
  const session = await getSession();
  await enforceRateLimit(20, 60000);
  assertActionPermitted(session, 'operator');

  const safeIface =
    options?.iface && /^[a-zA-Z0-9._-]+$/.test(options.iface) && !options.iface.startsWith('-')
      ? options.iface
      : 'eth0';
  const safeTarget =
    options?.target && /^[a-zA-Z0-9.:-]+$/.test(options.target) && !options.target.startsWith('-')
      ? options.target
      : 'cloudflare.com';
  const safeDns =
    options?.dnsServer && /^[a-zA-Z0-9.:-]+$/.test(options.dnsServer) && !options.dnsServer.startsWith('-')
      ? options.dnsServer
      : '1.1.1.1';
  const safeRecordType =
    options?.recordType && /^(A|AAAA|MX|TXT|NS|SOA|PTR|CNAME|SRV)$/.test(options.recordType.toUpperCase())
      ? options.recordType.toUpperCase()
      : 'A';

  const runExecFileSafe = (bin: string, args: string[]): string | null => {
    try {
      return execFileSync(bin, args, {
        encoding: 'utf-8',
        timeout: 6000,
        maxBuffer: 2 * 1024 * 1024,
      });
    } catch {
      return null;
    }
  };

  let command = '';
  let output = '';

  switch (tool) {
    case 'sysstat': {
      command = 'mpstat -P ALL && iostat -xz';
      const mpOut = runExecFileSafe('mpstat', ['-P', 'ALL']);
      const ioOut = runExecFileSafe('iostat', ['-xz']);
      const sections: string[] = [];
      if (mpOut) {
        sections.push('=== CPU Utilization (sysstat mpstat -P ALL) ===\n' + mpOut.trim());
      } else {
        const load = os.loadavg().map((n) => n.toFixed(2)).join(', ');
        const cpus = os.cpus();
        sections.push(
          `=== CPU Utilization (${cpus.length} cores — Load Avg: ${load}) ===\n` +
            cpus
              .slice(0, 16)
              .map((c, idx) => {
                const total = Object.values(c.times).reduce((a, b) => a + b, 0) || 1;
                const busy = (((total - c.times.idle) / total) * 100).toFixed(1);
                return `CPU ${String(idx).padStart(2, ' ')}: ${busy.padStart(5, ' ')}% busy  (${c.model})`;
              })
              .join('\n')
        );
      }
      if (ioOut) {
        sections.push('\n=== Block Device Extended I/O (sysstat iostat -xz) ===\n' + ioOut.trim());
      } else if (fs.existsSync('/proc/diskstats')) {
        const diskLines = fs
          .readFileSync('/proc/diskstats', 'utf-8')
          .trim()
          .split('\n')
          .filter((l) => /\b(sd[a-z]|vd[a-z]|nvme\d+n\d+|mmcblk\d+)\b/.test(l))
          .slice(0, 10);
        sections.push(
          '\n=== Block Device Statistics (/proc/diskstats) ===\n' +
            'Device       ReadsCompleted  SectorsRead  WritesCompleted  SectorsWritten\n' +
            diskLines
              .map((l) => {
                const p = l.trim().split(/\s+/);
                return `${(p[2] || '').padEnd(12, ' ')} ${(p[3] || '0').padEnd(15, ' ')} ${(p[5] || '0').padEnd(12, ' ')} ${(p[7] || '0').padEnd(16, ' ')} ${p[9] || '0'}`;
              })
              .join('\n')
        );
      }
      output = sections.join('\n');
      break;
    }

    case 'net_tools': {
      command = 'netstat -tulnp && arp -an && ip route show';
      const netstatOut =
        runExecFileSafe('netstat', ['-tuln']) ||
        runExecFileSafe('ss', ['-tuln']) ||
        'No socket output available.';
      const arpOut =
        runExecFileSafe('arp', ['-an']) ||
        runExecFileSafe('ip', ['neigh', 'show']) ||
        'No ARP entries found.';
      const routeOut =
        runExecFileSafe('ip', ['route', 'show']) ||
        runExecFileSafe('netstat', ['-rn']) ||
        'No routing table output available.';
      output = [
        '=== Active Listening Sockets (net-tools / netstat -tuln) ===',
        netstatOut.trim(),
        '',
        '=== Neighbor / ARP Cache (arp -an) ===',
        arpOut.trim(),
        '',
        '=== Kernel Routing Table (ip route show) ===',
        routeOut.trim(),
      ].join('\n');
      break;
    }

    case 'dnsutils': {
      command = `dig @${safeDns} ${safeTarget} ${safeRecordType} + stats`;
      const digOut =
        runExecFileSafe('dig', [`@${safeDns}`, safeTarget, safeRecordType]) ||
        runExecFileSafe('nslookup', ['-type=' + safeRecordType, safeTarget, safeDns]);
      output = digOut
        ? digOut.trim()
        : `; <<>> DiG 9.20 <<>> @${safeDns} ${safeTarget} ${safeRecordType}\n;; Unable to invoke dig binary on host.`;
      break;
    }

    case 'bandwidth': {
      command = `slurm -i ${safeIface} / iftop -t -s 1 -n -N -i ${safeIface}`;
      const sections: string[] = [];
      const statsDir = `/sys/class/net/${safeIface}/statistics`;
      if (fs.existsSync(statsDir)) {
        const readStat = (name: string) => {
          try {
            return Number(fs.readFileSync(path.join(statsDir, name), 'utf-8').trim()) || 0;
          } catch {
            return 0;
          }
        };
        const rxBytes = readStat('rx_bytes');
        const txBytes = readStat('tx_bytes');
        const rxPkts = readStat('rx_packets');
        const txPkts = readStat('tx_packets');
        const rxErrs = readStat('rx_errors');
        const txErrs = readStat('tx_errors');
        const rxDrop = readStat('rx_dropped');
        const txDrop = readStat('tx_dropped');
        const fmtBytes = (b: number) =>
          b > 1024 ** 3
            ? `${(b / 1024 ** 3).toFixed(2)} GB`
            : b > 1024 ** 2
              ? `${(b / 1024 ** 2).toFixed(2)} MB`
              : `${(b / 1024).toFixed(1)} KB`;

        sections.push(
          `=== Interface Bandwidth & Packet Counters (${safeIface} — slurm / kernel telemetry) ===`,
          `Interface      : ${safeIface}`,
          `RX Traffic     : ${fmtBytes(rxBytes)} (${rxPkts.toLocaleString()} packets, ${rxErrs} errors, ${rxDrop} dropped)`,
          `TX Traffic     : ${fmtBytes(txBytes)} (${txPkts.toLocaleString()} packets, ${txErrs} errors, ${txDrop} dropped)`
        );
      }
      const ssFlows = runExecFileSafe('ss', ['-tin']);
      if (ssFlows) {
        sections.push('\n=== Active TCP Flows & Congestion Telemetry (iftop / ss -tin) ===\n' + ssFlows.trim().slice(0, 3500));
      }
      output = sections.join('\n') || `Interface ${safeIface} telemetry collected.`;
      break;
    }

    case 'top_procs': {
      command = 'btop / htop (ps aux --sort=-%cpu)';
      const psOut =
        runExecFileSafe('ps', ['aux', '--sort=-%cpu']) ||
        runExecFileSafe('ps', ['aux']);
      const memInfo = `System Memory: ${((os.totalmem() - os.freemem()) / 1024 ** 3).toFixed(2)} GB / ${(os.totalmem() / 1024 ** 3).toFixed(2)} GB (${(((os.totalmem() - os.freemem()) / (os.totalmem() || 1)) * 100).toFixed(1)}%) | Load Avg: ${os.loadavg().map((l) => l.toFixed(2)).join(', ')}`;
      output = [
        '=== Process & Resource Monitor (btop / htop snapshot) ===',
        memInfo,
        '',
        psOut ? psOut.split('\n').slice(0, 28).join('\n') : 'Process table unavailable.',
      ].join('\n');
      break;
    }

    case 'iotop': {
      command = 'iotop -b -n 1 -o';
      const iotopOut =
        runExecFileSafe('iotop', ['-b', '-n', '1', '-o']) ||
        runExecFileSafe('iostat', ['-d', '-x']);
      if (iotopOut) {
        output = '=== Disk I/O Top Monitor (iotop -b -n 1 -o) ===\n' + iotopOut.trim();
      } else if (fs.existsSync('/proc/diskstats')) {
        const raw = fs.readFileSync('/proc/diskstats', 'utf-8').trim().split('\n').slice(0, 20).join('\n');
        output = '=== Kernel Disk I/O Counters (/proc/diskstats) ===\n' + raw;
      } else {
        output = 'Disk I/O statistics unavailable.';
      }
      break;
    }
  }

  return {
    success: true,
    command,
    output,
    timestamp: new Date().toISOString(),
  };
}

// ============================================================================
// Security AI / VigilSOC MCP Control Plane Management Actions
// ============================================================================

const MCP_GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function getMcpKeysStoragePath(): string {
  if (process.env.AXONWALL_MCP_KEYS_PATH) return process.env.AXONWALL_MCP_KEYS_PATH;
  const primary = getStateDir();
  const primaryFile = path.join(primary, 'mcp-keys.json');
  try {
    if (fs.existsSync(primaryFile)) {
      fs.accessSync(primaryFile, fs.constants.R_OK);
      return primaryFile;
    }
    fs.mkdirSync(primary, { recursive: true, mode: 0o700 });
    fs.accessSync(primary, fs.constants.W_OK);
    return primaryFile;
  } catch {
    for (const candidate of [
      path.join(PERSIST_CONFIG_DIR, 'mcp-keys.json'),
      path.join(ETC_CONFIG_DIR, 'mcp-keys.json'),
    ]) {
      if (fs.existsSync(candidate)) return candidate;
    }
    const fallback = isDevRuntime() ? path.join(getStateDir(), 'run') : '/run/axonwall';
    fs.mkdirSync(fallback, { recursive: true, mode: 0o700 });
    return path.join(fallback, 'mcp-keys.json');
  }
}

function getMcpAuditStoragePath(): string {
  if (process.env.AXONWALL_MCP_AUDIT_PATH) return process.env.AXONWALL_MCP_AUDIT_PATH;
  const dirs = isDevRuntime()
    ? [getStateDir(), path.join(getStateDir(), 'log'), path.join(getStateDir(), 'run')]
    : [getStateDir(), '/var/log/axonwall', '/run/axonwall'];
  for (const dir of dirs) {
    const file = path.join(dir, 'mcp-audit.jsonl');
    try {
      if (fs.existsSync(file)) {
        fs.accessSync(file, fs.constants.R_OK);
        return file;
      }
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.accessSync(dir, fs.constants.W_OK);
      return file;
    } catch {}
  }
  throw new Error('Unable to initialize a private MCP audit storage directory');
}

function readStoredMcpKeys(): McpApiKey[] {
  const candidates = process.env.AXONWALL_MCP_KEYS_PATH
    ? [process.env.AXONWALL_MCP_KEYS_PATH]
    : Array.from(
        new Set([
          getMcpKeysStoragePath(),
          path.join(getStateDir(), 'mcp-keys.json'),
          path.join(PERSIST_CONFIG_DIR, 'mcp-keys.json'),
          path.join(ETC_CONFIG_DIR, 'mcp-keys.json'),
        ]),
      );
  for (const filePath of candidates) {
    if (!fs.existsSync(filePath)) continue;
    try {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (!Array.isArray(parsed)) continue;
      const out: McpApiKey[] = [];
      for (const item of parsed) {
        const res = McpApiKeySchema.safeParse(item);
        if (res.success) out.push(res.data);
      }
      return out;
    } catch {}
  }
  return [];
}

function writeStoredMcpKeys(keys: McpApiKey[]): void {
  const serialized = JSON.stringify(keys, null, 2);
  const targets = process.env.AXONWALL_MCP_KEYS_PATH
    ? [process.env.AXONWALL_MCP_KEYS_PATH]
    : [
        getMcpKeysStoragePath(),
        path.join(PERSIST_CONFIG_DIR, 'mcp-keys.json'),
        path.join(ETC_CONFIG_DIR, 'mcp-keys.json'),
      ];
  for (const filePath of Array.from(new Set(targets))) {
    writeConfigFileSafe(filePath, serialized, 0o660);
  }
}

function readAndVerifyMcpAuditLog(limit = 100): {
  entries: McpAuditLogEntry[];
  integrity: { valid: boolean; totalEntries: number; brokenAtIndex?: number; headHash: string };
} {
  const auditPath = getMcpAuditStoragePath();
  if (!fs.existsSync(auditPath)) {
    return {
      entries: [],
      integrity: { valid: true, totalEntries: 0, headHash: MCP_GENESIS_HASH },
    };
  }
  const raw = fs.readFileSync(auditPath, 'utf8').trim();
  if (!raw) {
    return {
      entries: [],
      integrity: { valid: true, totalEntries: 0, headHash: MCP_GENESIS_HASH },
    };
  }

  const lines = raw.split('\n').filter((l) => l.trim().length > 0);
  let expectedPrev = MCP_GENESIS_HASH;
  let valid = true;
  let brokenAtIndex: number | undefined;

  for (let i = 0; i < lines.length; i++) {
    try {
      const entry = JSON.parse(lines[i]!) as McpAuditLogEntry;
      const canonical = JSON.stringify({
        id: entry.id,
        timestamp: entry.timestamp,
        keyId: entry.keyId,
        keyName: entry.keyName,
        agentType: entry.agentType,
        clientIp: entry.clientIp,
        toolName: entry.toolName,
        requiredScope: entry.requiredScope,
        decision: entry.decision,
        denialReason: entry.denialReason ?? null,
        paramsSummary: entry.paramsSummary,
        auditMetadata: entry.auditMetadata ?? null,
        leaseId: entry.leaseId ?? null,
        prevHash: entry.prevHash,
      });
      const recomputed = crypto.createHash('sha256').update(canonical).digest('hex');
      if (entry.prevHash !== expectedPrev || recomputed !== entry.entryHash) {
        valid = false;
        brokenAtIndex = i;
        break;
      }
      expectedPrev = entry.entryHash;
    } catch {
      valid = false;
      brokenAtIndex = i;
      break;
    }
  }

  const entries: McpAuditLogEntry[] = [];
  for (const line of lines.slice(Math.max(0, lines.length - limit)).reverse()) {
    try {
      entries.push(JSON.parse(line) as McpAuditLogEntry);
    } catch {
      // skip
    }
  }

  return {
    entries,
    integrity: {
      valid,
      totalEntries: lines.length,
      brokenAtIndex,
      headHash: expectedPrev,
    },
  };
}

export interface McpDashboardData {
  serverStatus: McpServerStatus;
  keys: McpApiKeyPublic[];
  leases: McpTacticalLease[];
  protectedPosture: {
    applianceIps: string[];
    gatewayAndHaIps: string[];
    antiLockoutPorts: number[];
  };
  auditEntries: McpAuditLogEntry[];
  auditIntegrity: {
    valid: boolean;
    totalEntries: number;
    brokenAtIndex?: number;
    headHash: string;
  };
  // C-M7: true when the daemon did not answer the posture call, so the
  // page can say lease/posture state is unknown instead of rendering an
  // empty lease list and invented anti-lockout data as fact.
  daemonDown: boolean;
}

export async function getMcpDashboardData(): Promise<McpDashboardData> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('mcp-ai-control');

  const keys = readStoredMcpKeys().map(({ secretHashSha256: _omit, ...pub }) => pub);
  const { entries, integrity } = readAndVerifyMcpAuditLog(100);

  let leases: McpTacticalLease[] = [];
  // C-M7: no invented posture. When the daemon does not answer, the
  // anti-lockout posture is unknown — the daemon owns the kernel leases
  // and the protected IPs/ports, so empty arrays plus daemonDown: true is
  // the honest answer, not a plausible-looking default.
  let protectedPosture = {
    applianceIps: [] as string[],
    gatewayAndHaIps: [] as string[],
    antiLockoutPorts: [] as number[],
  };
  let daemonDown = false;

  const postureRes = await callAgentApi<any>('/v1/mcp/posture');
  if (postureRes && postureRes.success) {
    if (Array.isArray(postureRes.leases)) {
      leases = postureRes.leases;
    }
    if (postureRes.posture) {
      protectedPosture = {
        applianceIps: postureRes.posture.applianceIps || ['192.168.1.1'],
        gatewayAndHaIps: postureRes.posture.gatewayAndHaIps || [],
        antiLockoutPorts: postureRes.posture.antiLockoutPorts || [2966, 22, 9876],
      };
    }
  } else {
    daemonDown = true;
  }

  const serverStatus = getMcpServerStatus();

  return {
    serverStatus,
    keys,
    leases,
    protectedPosture,
    auditEntries: entries,
    auditIntegrity: integrity,
    daemonDown,
  };
}

export async function createMcpApiKeyAction(input: {
  name: string;
  agentType: 'vigilsoc' | 'soar' | 'custom-ai' | 'readonly-analyst';
  scopes: McpScope[];
  allowedSourceCidrs: string[];
  mtlsCertFingerprintSha256?: string;
  policyLimits: Partial<McpPolicyLimits>;
  expiresInDays?: number;
}): Promise<{ success: boolean; rawToken?: string; key?: McpApiKeyPublic; error?: string }> {
  const session = await getSession();
  assertInteractiveSession(session);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('mcp-ai-control');

  if (!input.name || input.name.trim().length < 2) {
    return { success: false, error: 'Key name must be at least 2 characters' };
  }
  if (!Array.isArray(input.scopes) || input.scopes.length === 0) {
    return { success: false, error: 'Select at least one capability scope' };
  }

  const shortId = crypto.randomBytes(4).toString('hex');
  const secretHex = crypto.randomBytes(32).toString('hex');
  const keyPrefix = `axw_mcp_${shortId}`;
  const rawToken = `${keyPrefix}_${secretHex}`;
  const secretHashSha256 = crypto.createHash('sha256').update(rawToken).digest('hex');

  const now = new Date();
  const expiresAt =
    input.expiresInDays && input.expiresInDays > 0
      ? new Date(now.getTime() + input.expiresInDays * 86400 * 1000).toISOString()
      : undefined;

  // C-L8: a Zod throw here used to surface as an unhandled rejection in
  // the page (modal stuck open, no key, no message). Return it as a
  // structured failure like the sibling key actions do.
  let parsedLimits: McpPolicyLimits;
  try {
    parsedLimits = McpPolicyLimitsSchema.parse(input.policyLimits || {});
  } catch (err: any) {
    return { success: false, error: `Invalid policy limits: ${err?.message || 'out-of-range value'}` };
  }

  const record = McpApiKeySchema.parse({
    id: `mcp_key_${shortId}`,
    name: input.name.trim(),
    agentType: input.agentType || 'vigilsoc',
    keyPrefix,
    secretHashSha256,
    scopes: input.scopes,
    allowedSourceCidrs: (input.allowedSourceCidrs || []).map((c) => c.trim()).filter(Boolean),
    mtlsCertFingerprintSha256: input.mtlsCertFingerprintSha256?.trim() || undefined,
    policyLimits: parsedLimits,
    enabled: true,
    createdAt: now.toISOString(),
    expiresAt,
    createdBy: session?.username || 'admin',
  });

  const existing = readStoredMcpKeys();
  existing.unshift(record);
  writeStoredMcpKeys(existing);

  const { secretHashSha256: _omit, ...pub } = record;
  return {
    success: true,
    rawToken,
    key: pub,
  };
}

export async function revokeMcpApiKeyAction(keyId: string): Promise<{ success: boolean; error?: string }> {
  const session = await getSession();
  assertInteractiveSession(session);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('mcp-ai-control');

  const existing = readStoredMcpKeys();
  const idx = existing.findIndex((k) => k.id === keyId);
  if (idx === -1) {
    return { success: false, error: 'MCP API key not found' };
  }
  existing.splice(idx, 1);
  writeStoredMcpKeys(existing);
  return { success: true };
}

export async function toggleMcpApiKeyAction(
  keyId: string,
  enabled: boolean
): Promise<{ success: boolean; error?: string }> {
  const session = await getSession();
  assertInteractiveSession(session);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('mcp-ai-control');

  const existing = readStoredMcpKeys();
  const target = existing.find((k) => k.id === keyId);
  if (!target) {
    return { success: false, error: 'MCP API key not found' };
  }
  target.enabled = Boolean(enabled);
  writeStoredMcpKeys(existing);
  return { success: true };
}

export async function revertMcpLeaseAction(
  leaseId: string,
  reason = 'Manual revert by administrator from Web Console'
): Promise<{ success: boolean; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('mcp-ai-control');

  const res = await callAgentApiResponse<any>('/v1/mcp/revert', 'POST', { leaseId, reason }, 30_000);
  if (!res) {
    return { success: false, error: 'Daemon unavailable — lease was not reverted.' };
  }
  if (!res.success) {
    return { success: false, error: res.error || res.message || 'Failed to revert lease' };
  }
  return { success: true };
}

export async function emergencyFlushMcpLeasesAction(
  reason = 'Emergency Panic Flush triggered by administrator from Web Console'
): Promise<{ success: boolean; clearedCount: number; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('mcp-ai-control');

  const res = await callAgentApiResponse<any>('/v1/mcp/flush', 'POST', { reason }, 30_000);
  // C-B6: a null response means the daemon never ran the flush — the
  // blackholes/shapers/DNAT/DNS sinkholes are all still in the kernel.
  // A daemon-reported failure is a failure too. Never report purged
  // leases that were never purged.
  if (!res) {
    return { success: false, clearedCount: 0, error: 'Daemon unavailable — no leases were purged.' };
  }
  if (res.success === false) {
    return {
      success: false,
      clearedCount: 0,
      error: res.error || res.message || 'Emergency flush failed on the daemon.',
    };
  }
  return {
    success: true,
    clearedCount: res?.clearedCount ?? 0,
  };
}

export async function toggleMcpServerMasterSwitchAction(
  enabled: boolean,
  reason?: string
): Promise<{ success: boolean; status: McpServerStatus; error?: string }> {
  const session = await getSession();
  assertInteractiveSession(session);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('mcp-ai-control');

  const settingsPath = resolveMcpSettingsPath();
  const currentStatus = getMcpServerStatus(settingsPath);

  // If locked via environment variable, refuse modification and inform user
  if (currentStatus.source === 'env') {
    return {
      success: false,
      status: currentStatus,
      error: `Cannot toggle MCP server state from Web Console: ${currentStatus.disabledReason}. Remove the environment variable to manage via console.`,
    };
  }

  const payload = {
    enabled: Boolean(enabled),
    disabledReason: enabled ? undefined : (reason?.trim() || 'Disabled by administrator from Web Console'),
    disabledAt: enabled ? undefined : new Date().toISOString(),
    disabledBy: session.username || 'admin',
  };

  try {
    // When disabling MCP, flush active tactical & XDP leases BEFORE disabling mcp-settings.json
    // so axonwalld does not reject the flush once disabled.
    if (!enabled) {
      await callAgentApi<any>(
        '/v1/mcp/flush',
        'POST',
        { reason: 'Master MCP Server switch disabled by administrator' },
        30_000
      ).catch(() => {});
      await callAgentApi<any>('/v1/ebpf/xdp/block', 'DELETE', { clearAll: true }, 15_000).catch(() => {});
    }

    const serialized = JSON.stringify(payload, null, 2);
    const targets = process.env.AXONWALL_MCP_SETTINGS_PATH
      ? [process.env.AXONWALL_MCP_SETTINGS_PATH]
      : [
          settingsPath,
          path.join(PERSIST_CONFIG_DIR, 'mcp-settings.json'),
          path.join(ETC_CONFIG_DIR, 'mcp-settings.json'),
        ];
    for (const target of Array.from(new Set(targets))) {
      writeConfigFileSafe(target, serialized, 0o660);
    }

    return {
      success: true,
      status: getMcpServerStatus(settingsPath),
    };
  } catch (err: any) {
    return {
      success: false,
      status: currentStatus,
      error: `Failed to persist MCP server settings: ${err?.message || err}`,
    };
  }
}

// ============================================================================
// Rosenpass Post-Quantum Hybrid Dual-KEM (Classic McEliece + ML-KEM) Actions
// ============================================================================

export interface RosenpassLivePeerKey {
  name: string;
  path: string;
  sizeBytes: number;
  sha256: string;
  updatedAt: string;
}

export interface RosenpassLiveWgPeerTelemetry {
  wgPeerPublicKey: string;
  pskStatus: 'active_pq_psk' | 'unseeded_classical_only';
  pskSha256Prefix?: string;
  latestHandshakeUnix: number;
}

export interface RosenpassLiveStatus {
  binaryInstalled: boolean;
  serviceActive: boolean;
  publicKeyExists: boolean;
  secretKeyExists: boolean;
  publicKeyPath: string;
  publicKeySizeBytes: number;
  publicKeySha256: string;
  publicKeyUpdatedAt?: string;
  peerKeys: RosenpassLivePeerKey[];
  wireguardPeers: RosenpassLiveWgPeerTelemetry[];
  daemonDown?: boolean;
}

export async function getRosenpassStatusAction(wgDevice = 'wg0'): Promise<RosenpassLiveStatus> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('rosenpass');

  const safeDev = /^[a-zA-Z0-9_.-]{1,15}$/.test(wgDevice) ? wgDevice : 'wg0';
  const res = await callAgentApi<RosenpassLiveStatus>(
    `/v1/vpn/rosenpass/status?wgDevice=${encodeURIComponent(safeDev)}`,
    'GET',
    undefined,
    5000,
  );
  if (res) {
    return {
      binaryInstalled: Boolean(res.binaryInstalled),
      serviceActive: Boolean(res.serviceActive),
      publicKeyExists: Boolean(res.publicKeyExists),
      secretKeyExists: Boolean(res.secretKeyExists),
      publicKeyPath: res.publicKeyPath || '/etc/rosenpass/pq.pk',
      publicKeySizeBytes: Number(res.publicKeySizeBytes || 0),
      publicKeySha256: res.publicKeySha256 || '',
      publicKeyUpdatedAt: res.publicKeyUpdatedAt,
      peerKeys: Array.isArray(res.peerKeys) ? res.peerKeys : [],
      wireguardPeers: Array.isArray(res.wireguardPeers) ? res.wireguardPeers : [],
      daemonDown: false,
    };
  }

  return {
    binaryInstalled: false,
    serviceActive: false,
    publicKeyExists: false,
    secretKeyExists: false,
    publicKeyPath: '/etc/rosenpass/pq.pk',
    publicKeySizeBytes: 0,
    publicKeySha256: '',
    peerKeys: [],
    wireguardPeers: [],
    daemonDown: true,
  };
}

export async function generateRosenpassKeypairAction(
  force = false,
): Promise<{ success: boolean; publicKeyPath?: string; sizeBytes?: number; sha256?: string; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('rosenpass');

  const res = await callAgentApiResponse<any>('/v1/vpn/rosenpass/keygen', 'POST', { force: Boolean(force) }, 30000);
  if (res && res.success) {
    return {
      success: true,
      publicKeyPath: res.publicKeyPath || '/etc/rosenpass/pq.pk',
      sizeBytes: Number(res.sizeBytes || 524160),
      sha256: res.sha256 || '',
    };
  }
  if (res) {
    return {
      success: false,
      error: res.error || res.message || 'Daemon failed to generate Rosenpass PQ keypair.',
    };
  }
  if (!isDevModeRuntime()) {
    return {
      success: false,
      error: 'Daemon unavailable: failed to generate Rosenpass PQ keypair.',
    };
  }

  // Dev preview fallback
  const randomSeed = crypto.randomBytes(64);
  const sha = crypto.createHash('sha256').update(randomSeed).digest('hex');
  return {
    success: true,
    publicKeyPath: '/etc/rosenpass/pq.pk',
    sizeBytes: 524160,
    sha256: sha,
  };
}

export async function exportRosenpassPublicKeyAction(): Promise<{
  success: boolean;
  publicKeyBase64?: string;
  sizeBytes?: number;
  sha256?: string;
  error?: string;
}> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('rosenpass');

  const res = await callAgentApiResponse<any>('/v1/vpn/rosenpass/pubkey', 'GET', undefined, 10000);
  if (res && res.success && res.publicKeyBase64) {
    return {
      success: true,
      publicKeyBase64: res.publicKeyBase64,
      sizeBytes: Number(res.sizeBytes || 524160),
      sha256: res.sha256 || '',
    };
  }
  return {
    success: false,
    error: 'Local Classic McEliece 460896 public key (/etc/rosenpass/pq.pk) has not been generated on the appliance yet.',
  };
}

export async function uploadRosenpassPeerPublicKeyAction(
  peerName: string,
  publicKeyBase64: string,
): Promise<{ success: boolean; path?: string; sha256?: string; sizeBytes?: number; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('rosenpass');

  const cleanName = peerName.trim();
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(cleanName)) {
    return {
      success: false,
      error: 'Invalid peer name: must be 1–64 alphanumeric, dash, or underscore characters.',
    };
  }
  if (!publicKeyBase64 || publicKeyBase64.length > 1500000) {
    return {
      success: false,
      error: 'Peer public key payload must be valid base64 up to 1 MB.',
    };
  }

  const res = await callAgentApiResponse<any>(
    '/v1/vpn/rosenpass/peer-pubkey',
    'POST',
    { peerName: cleanName, publicKeyBase64 },
    30000,
  );
  if (res && res.success) {
    return {
      success: true,
      path: res.path,
      sha256: res.sha256,
      sizeBytes: Number(res.sizeBytes || 0),
    };
  }
  if (res) {
    return {
      success: false,
      error: res.error || res.message || 'Daemon refused Rosenpass peer public key.',
    };
  }
  if (!isDevModeRuntime()) {
    return {
      success: false,
      error: 'Daemon unavailable: failed to upload Rosenpass peer public key.',
    };
  }

  // Offline/dev fallback
  try {
    const buf = Buffer.from(publicKeyBase64, 'base64');
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    return {
      success: true,
      path: `/etc/rosenpass/peers/${cleanName}-pq.pk`,
      sha256,
      sizeBytes: buf.length,
    };
  } catch {
    return {
      success: false,
      error: 'Invalid base64 key payload.',
    };
  }
}

export interface HostRootkitAuditApiResponse {
  timestamp: string;
  overallVerdict: string;
  kernelPosture: {
    taintValue: number;
    ioUringDisabled: string;
    ioUringGroup: string;
    unprivilegedBpfDisabled: string;
    bpfJitHarden: string;
    lockdownMode: string;
    activeLsms: string[];
    bpfLsmActive: boolean;
    ldSoPreloadPresent: boolean;
    ldSoPreloadEntries?: string;
  };
  scanners: Array<{
    id: string;
    name: string;
    binary: string;
    installed: boolean;
    path?: string;
    category: string;
    layer: string;
  }>;
  ioUringRings: Array<{
    pid: number;
    comm: string;
    exe: string;
    fd: number;
    sqThread: number;
    sqThreadCpu: number;
    sqHead: number;
    sqTail: number;
    cqHead: number;
    cqTail: number;
    userFiles: number;
    sqPollActive: boolean;
    fixedFilesActive: boolean;
    severity: 'INFO' | 'HIGH' | 'CRITICAL';
    reasons: string[];
  }>;
  trampolineHooks: string[];
  bpfLsmGuardAttached?: boolean;
  bpfLsmAttachedHooks?: string[];
  bpfLsmAllowlist?: Array<{
    path: string;
    dev: number;
    ino: number;
    flags: number;
  }>;
  bpfLsmDenialEvents?: Array<{
    timestamp: string;
    pid: number;
    uid: number;
    hookId: number;
    hook: string;
    blocked: boolean;
    dev: number;
    ino: number;
    comm: string;
    detail: string;
    mitreTechnique: string;
  }>;
  findings: Array<{
    detector: string;
    category: string;
    severity: string;
    target: string;
    description: string;
    mitreTechnique: string;
  }>;
}

export async function getHostRootkitAuditStatus(): Promise<HostRootkitAuditApiResponse | null> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('host-malware-rootkit');
  await enforceRateLimit(30, 60000, 'rootkit-status');
  return callAgentApi<HostRootkitAuditApiResponse>('/v1/security/rootkit/status', 'GET', undefined, 10000);
}

export async function runHostRootkitScan(): Promise<HostRootkitAuditApiResponse | null> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('host-malware-rootkit');
  await enforceRateLimit(10, 60000, 'rootkit-scan');
  return callAgentApi<HostRootkitAuditApiResponse>('/v1/security/rootkit/scan', 'POST', {}, 30000);
}

// ============================================================================
// Ring-0 eBPF Dataplane, Linux 6.9+ BPF_TOKEN_CREATE & Cross-Duty Telemetry
// ============================================================================

export type {
  BpfTokenProfileStatus,
  BpfTokenCapabilityReport,
  XdpVerdictStats,
  XdpPerCpuStat,
  XdpFlowEntry,
  XdpProtocolSummary,
  XdpPortSummary,
  XdpVlanSummary,
  XdpSynMeterEntry,
  XdpBlockedEntry,
  BpfLsmAllowlistEntry,
  BpfLsmEventEntry,
  BpfProgramInventoryItem,
  BpfMapInventoryItem,
  BpfTypeAggregate,
  KernelBpfInventory,
  KernelRcaTelemetry,
  NetdevTrafficStat,
  VirtWorkloadSummary,
  NasPoolIoStat,
  ThreatHarvesterOverviewSummary,
  ZfsDeepTelemetry,
  VirtDutyTelemetry,
  K3sDutyTelemetry,
  EbpfOverviewTelemetry,
};

type CanonicalBpfTokenPreset =
  | 'socket-observability'
  | 'network-dataplane'
  | 'cgroup-microsegmentation';

type BpfTokenPresetInput =
  | CanonicalBpfTokenPreset
  | 'networking-safe'
  | 'cgroup-observability'
  | 'firewall-xdp-tc';

function mapBpfTokenPreset(preset?: string): CanonicalBpfTokenPreset {
  switch (preset) {
    case 'socket-observability':
      return 'socket-observability';
    case 'cgroup-observability':
    case 'cgroup-microsegmentation':
      return 'cgroup-microsegmentation';
    case 'networking-safe':
    case 'firewall-xdp-tc':
    case 'network-dataplane':
    default:
      return 'network-dataplane';
  }
}

export async function getEbpfOverviewTelemetry(): Promise<EbpfOverviewTelemetry> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('coroot-ebpf-apm');
  await enforceRateLimit(60, 60000, 'ebpf-overview');

  const res = await callAgentApi<any>('/v1/ebpf/overview?limit=100', 'GET', undefined, 8000);
  if (res && (res.bpfTokens || res.dataplane)) {
    return normalizeEbpfOverviewResponse(res);
  }

  const rel = os.release() || '6.12.0';
  const m = rel.match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  const major = m ? parseInt(m[1], 10) : 6;
  const minor = m ? parseInt(m[2], 10) : 12;
  const patch = m && m[3] ? parseInt(m[3], 10) : 0;
  const supportsBpfToken = major > 6 || (major === 6 && minor >= 9);

  // Daemon-down fallback: report unknown, never assert capabilities the
  // daemon never reported (C-M1). The page renders these as unknown.
  return {
    daemonDown: true,
    dataplane: {
      running: false,
      attachedInterfaces: [],
      dualStackEnabled: false,
      vlanPeelingEnabled: false,
      xdpStats: {
        rxPackets: 0,
        rxBytes: 0,
        ipv4Packets: 0,
        ipv6Packets: 0,
        vlanTaggedPackets: 0,
        xdpDropPackets: 0,
        xdpDropBytes: 0,
        xdpPassPackets: 0,
        tcpSynPackets: 0,
        lpmCidrDrops: 0,
        synFloodDrops: 0,
      },
      perCpuStats: [],
      totalFlowCount: 0,
      totalFlowCountV4: 0,
      totalFlowCountV6: 0,
      protocolBreakdown: [],
      topPorts: [],
      vlanBreakdown: [],
      synRateMeters: [],
      topFlows: [],
      blockedIps: [],
      topFlowsCount: 0,
    },
    bpfLsm: {
      attached: false,
      attachedHooks: [],
      denialEventsCount: 0,
      allowlist: [],
      recentEvents: [],
    },
    bpfTokens: {
      kernelRelease: rel,
      major,
      minor,
      patch,
      supportsBpfToken,
      supportsUserNsBpf: supportsBpfToken,
      bpffsRootMounted: fs.existsSync('/sys/fs/bpf'),
      unprivilegedBpfSysctl: '',
      bpfLsmActive: false,
      forbiddenRing0ProgTypes: FORBIDDEN_RING0_PROG_TYPES,
      activeProfiles: [],
      presets: {
        'network-dataplane': {
          delegateCmds: 'prog_load:map_create:btf_load:link_create:link_update:link_detach:obj_pin:obj_get:map_lookup_elem:map_update_elem:map_delete_elem:map_get_next_key',
          delegateProgs: 'xdp:sched_cls:sched_act:socket_filter:cgroup_skb:cgroup_sock_addr:sk_skb:sk_msg',
          delegateMaps: 'array:percpu_array:hash:percpu_hash:lru_hash:lru_percpu_hash:lpm_trie:ringbuf:devmap:sockmap:sockhash',
          delegateAttachs: 'xdp:tcx_ingress:tcx_egress:cgroup_inet_ingress:cgroup_inet_egress:cgroup_inet4_connect:cgroup_inet6_connect:sk_skb_stream_verdict:sk_msg_verdict',
        },
        'socket-observability': {
          delegateCmds: 'prog_load:map_create:btf_load:map_lookup_elem:map_update_elem:map_delete_elem:map_get_next_key',
          delegateProgs: 'socket_filter:cgroup_skb',
          delegateMaps: 'array:hash:lru_hash:percpu_array:ringbuf',
          delegateAttachs: 'cgroup_inet_ingress:cgroup_inet_egress',
        },
        'cgroup-microsegmentation': {
          delegateCmds: 'prog_load:map_create:btf_load:link_create:map_lookup_elem:map_update_elem:map_delete_elem',
          delegateProgs: 'cgroup_skb:cgroup_sock:cgroup_sock_addr',
          delegateMaps: 'array:hash:lru_hash:lpm_trie:ringbuf',
          delegateAttachs: 'cgroup_inet_ingress:cgroup_inet_egress:cgroup_inet4_bind:cgroup_inet6_bind:cgroup_inet4_connect:cgroup_inet6_connect',
        },
      },
    },
    bpfInventory: createEmptyKernelBpfInventory(),
    kernelRca: createEmptyKernelRca(),
    softnet: createEmptySoftnetTelemetry(),
    sockets: createEmptyKernelSocketTelemetry(),
    virt: {
      timestamp: new Date().toISOString(),
      kvmAvailable: fs.existsSync('/dev/kvm'),
      iommuGroupsCount: 0,
      lxcInstalled: false,
      qemuInstalled: false,
      vnetInterfaces: [],
      workloads: [],
      bridgeStats: [],
      runningQemuCount: 0,
      runningLxcCount: 0,
      unprivilegedLxcTokenMounts: [],
    },
    k3s: {
      timestamp: new Date().toISOString(),
      serviceActive: false,
      binaryPresent: false,
      userNamespacesSupported: supportsBpfToken,
      cniInterfaces: [],
      kubepodsCgroupV2: fs.existsSync('/sys/fs/cgroup/cgroup.controllers'),
      bpfTokenReady: supportsBpfToken,
      openEbsDatasets: [],
    },
    nas: {
      timestamp: new Date().toISOString(),
      zfsModuleLoaded: fs.existsSync('/proc/spl/kstat/zfs'),
      arc: {
        sizeBytes: 0,
        maxSizeBytes: 0,
        minSizeBytes: 0,
        hits: 0,
        misses: 0,
        hitRatioPct: 0,
        demandDataHits: 0,
        demandDataMisses: 0,
        l2Hits: 0,
        l2Misses: 0,
        l2SizeBytes: 0,
        memoryThrottleCount: 0,
      },
      zil: {
        zilCommitCount: 0,
        zilCommitWriterCount: 0,
        itxCount: 0,
        itxIndirectBytes: 0,
        itxCopiedBytes: 0,
        itxNeedcopyBytes: 0,
      },
      pools: [],
      poolIoStats: [],
    },
  };
}

export async function manageBpfTokenProfileAction(input: {
  action: 'create' | 'delete';
  name: string;
  preset?: BpfTokenPresetInput;
  workloadTarget?: string;
}): Promise<{ success: boolean; profile?: BpfTokenProfileStatus; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('coroot-ebpf-apm');
  await enforceRateLimit(20, 60000, 'ebpf-token-manage');

  const cleanName = (input.name || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{1,62}$/.test(cleanName)) {
    return { success: false, error: 'Profile ID must match ^[a-z0-9][a-z0-9._-]{1,62}$.' };
  }

  if (input.action === 'delete') {
    const res = await callAgentApiResponse<any>(`/v1/ebpf/tokens?id=${encodeURIComponent(cleanName)}`, 'DELETE', undefined, 10000);
    if (!res) {
      return { success: false, error: 'Daemon unavailable — cannot unmount bpffs delegation profile.' };
    }
    if (!res.success) {
      return { success: false, error: res.error || 'Failed to delete BPF token profile.' };
    }
    return { success: true };
  }

  const targetRef = (input.workloadTarget || 'k3s-userns').trim();
  const targetKind = targetRef.startsWith('ct-') || targetRef.startsWith('lxc:')
    ? 'lxc'
    : targetRef.includes('k3s') || targetRef.includes('/')
      ? 'k3s-pod'
      : 'standalone';

  const res = await callAgentApiResponse<any>(
    '/v1/ebpf/tokens',
    'POST',
    {
      id: cleanName,
      targetKind,
      targetRef,
      preset: mapBpfTokenPreset(input.preset),
      enabled: true,
      auditViaBpfLsm: true,
    },
    10000
  );
  if (!res) {
    return { success: false, error: 'Daemon unavailable — cannot mount delegated bpffs token instance.' };
  }
  if (!res.success) {
    return { success: false, error: res.error || 'Failed to create BPF token profile.' };
  }
  return { success: true, profile: res.profile };
}

export async function manageXdpFastDropAction(input: {
  action: 'block' | 'unblock';
  ip: string;
  ttlSeconds?: number;
}): Promise<{ success: boolean; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('coroot-ebpf-apm');
  await enforceRateLimit(30, 60000, 'ebpf-xdp-block');

  const cleanIp = (input.ip || '').trim();
  if (!cleanIp) {
    return { success: false, error: 'Target IPv4 or IPv6 address is required.' };
  }

  if (input.action === 'unblock') {
    const res = await callAgentApiResponse<any>(`/v1/ebpf/xdp/block?ip=${encodeURIComponent(cleanIp)}`, 'DELETE', undefined, 8000);
    if (!res) {
      return { success: false, error: 'Daemon unavailable — XDP blocklist map was not modified.' };
    }
    if (!res.success) {
      return { success: false, error: res.error || 'Failed to remove IP from XDP blocklist map.' };
    }
    return { success: true };
  }

  const ttl = Math.max(10, Math.min(604800, Number(input.ttlSeconds) || 3600));
  const res = await callAgentApiResponse<any>('/v1/ebpf/xdp/block', 'POST', { ip: cleanIp, ttlSeconds: ttl }, 8000);
  if (!res) {
    return { success: false, error: 'Daemon unavailable — XDP blocklist map was not updated.' };
  }
  if (!res.success) {
    return { success: false, error: res.error || 'Failed to insert IP into XDP blocklist map.' };
  }
  return { success: true };
}

export async function getXdpSynLimitAction(): Promise<{ maxSynPps: number; daemonDown: boolean }> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('coroot-ebpf-apm');
  const res = await callAgentApi<{ maxSynPps?: number }>('/v1/ebpf/xdp/syn-limit', 'GET', undefined, 5000);
  if (!res) {
    return { maxSynPps: 0, daemonDown: true };
  }
  return { maxSynPps: Number(res.maxSynPps ?? 0), daemonDown: false };
}

export async function setXdpSynLimitAction(
  maxSynPps: number
): Promise<{ success: boolean; maxSynPps: number; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('coroot-ebpf-apm');
  await enforceRateLimit(20, 60000, 'ebpf-xdp-syn-limit');

  const val = Math.floor(Number(maxSynPps));
  if (!Number.isFinite(val) || val < 0 || (val > 0 && val < 20) || val > 10_000_000) {
    return {
      success: false,
      maxSynPps: 0,
      error: 'SYN flood rate limit must be 0 (disabled) or between 20 and 10,000,000 PPS.',
    };
  }
  const res = await callAgentApiResponse<any>('/v1/ebpf/xdp/syn-limit', 'POST', { maxSynPps: val }, 8000);
  if (!res) {
    return { success: false, maxSynPps: 0, error: 'Daemon unavailable — XDP SYN rate limit was not updated.' };
  }
  if (!res.success) {
    return { success: false, maxSynPps: 0, error: res.error || 'Failed to update XDP SYN-flood rate limit.' };
  }
  return { success: true, maxSynPps: Number(res.maxSynPps ?? val) };
}

export async function toggleKernelBpfStatsAction(
  enabled: boolean
): Promise<{ success: boolean; statsEnabled: boolean; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('coroot-ebpf-apm');
  await enforceRateLimit(20, 60000, 'ebpf-bpf-stats');

  const res = await callAgentApiResponse<any>(
    '/v1/ebpf/bpf-stats',
    'POST',
    { enabled: Boolean(enabled) },
    8000
  );
  if (!res) {
    return {
      success: false,
      statsEnabled: !enabled,
      error: 'Daemon unavailable — kernel.bpf_stats_enabled sysctl was not modified.',
    };
  }
  if (!res.success) {
    return {
      success: false,
      statsEnabled: !enabled,
      error: res.error || 'Failed to toggle kernel.bpf_stats_enabled sysctl.',
    };
  }
  return { success: true, statsEnabled: Boolean(res.statsEnabled ?? enabled) };
}

export async function renderK3sBpfTokenManifestAction(input: {
  name: string;
  namespace?: string;
  image?: string;
  profileName?: string;
  preset?: BpfTokenPresetInput;
  kind?: 'Pod' | 'DaemonSet';
}): Promise<{ success: boolean; manifestYaml: string; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('coroot-ebpf-apm');
  await enforceRateLimit(30, 60000, 'ebpf-render-k3s');

  const cleanName = /^[a-z0-9-]{2,48}$/.test((input.name || '').trim()) ? input.name.trim() : 'ebpf-packet-sensor';
  const cleanNs = /^[a-z0-9-]{1,48}$/.test((input.namespace || '').trim()) ? input.namespace!.trim() : 'default';
  const cleanImg = (input.image || 'ghcr.io/cilium/ebpf-sensor:latest').trim();
  const profileName = /^[a-z0-9][a-z0-9._-]{1,62}$/.test((input.profileName || '').trim().toLowerCase())
    ? input.profileName!.trim().toLowerCase()
    : 'k3s-net-safe';
  const kind = input.kind === 'DaemonSet' ? 'DaemonSet' : 'Pod';
  const mappedPreset = mapBpfTokenPreset(input.preset);

  const res = await callAgentApi<any>(
    '/v1/ebpf/tokens/render-k3s',
    'POST',
    {
      profileId: profileName,
      profile: {
        id: profileName,
        preset: mappedPreset,
        targetKind: 'k3s-pod',
        targetRef: cleanName,
        enabled: true,
      },
      workloadName: cleanName,
      namespace: cleanNs,
      image: cleanImg,
      kind,
    },
    5000
  );
  if (res && res.success && typeof res.manifestYaml === 'string') {
    return { success: true, manifestYaml: res.manifestYaml };
  }

  if (!res) {
    return { success: false, manifestYaml: '', error: 'Daemon unavailable — K3s manifest was not rendered.' };
  }
  return {
    success: false,
    manifestYaml: '',
    error: res.error || 'Failed to render K3s manifest on the daemon.',
  };
}

// =============================================================================
// Axonwall Blackbox: Extreme eBPF Threat-LLM Harvester
// =============================================================================

export interface ThreatEpisode {
  id: string;
  createdAt: string;
  timestampUnixMs: number;
  labelTier: 'gold_malicious' | 'silver_malicious' | 'benign_sampled' | 'unlabeled_anomaly' | string;
  reviewStatus: 'pending' | 'approved_malicious' | 'marked_benign' | 'pinned_gold' | string;
  pinned: boolean;
  verdictScore: number;
  oracleSources: string[];
  mitreAttack: string[];
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  proto: number;
  protoName: string;
  pktCount: number;
  byteCount: number;
  durationMs: number;
  dnsEntropy: number;
  ja4t: string;
  sni?: string;
  cgroupId: number;
  procComm?: string;
  procPid?: number;
  memfdExec: boolean;
  redactionCount: number;
  pktSizes: number[];
  iatUs: number[];
  scrubbedPayload?: string;
  causalDsl: string;
  reasoningTrace: string;
  recommendedMcpTool?: string;
  spoolBytes: number;
}

export interface ThreatHarvesterStats {
  packetsSeen: number;
  tier0Events: number;
  tier1PayloadEvents: number;
  ringbufDrops: number;
  darkPortHits: number;
  memfdAlerts: number;
  tlsUprobeEvents: number;
  totalEpisodes: number;
  goldEpisodes: number;
  silverEpisodes: number;
  benignEpisodes: number;
  pinnedEpisodes: number;
  pendingReview: number;
  redactedSecrets: number;
  spoolUsedBytes: number;
  spoolQuotaBytes: number;
  zfsBacked: boolean;
  backpressureTripped: boolean;
}

export interface ThreatHarvesterStatusSnapshot {
  daemonDown?: boolean;
  config: ThreatHarvesterConfig;
  bpfAttached: boolean;
  attachedInterfaces: string[];
  activeHooks: string[];
  excludedUprobeDaemons: string[];
  bpfLoadError?: string;
  stats: ThreatHarvesterStats;
  timestamp: string;
}

export async function getThreatHarvesterStatus(): Promise<ThreatHarvesterStatusSnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('ebpf-threat-harvester');
  await enforceRateLimit(60, 60000, 'threat-harvester-status');

  const res = await callAgentApi<ThreatHarvesterStatusSnapshot>(
    '/v1/security/threat-harvester/status',
    'GET',
    undefined,
    8000
  );
  if (res && res.config && res.stats) {
    if (!isAdminSession(session)) {
      const cloned: ThreatHarvesterStatusSnapshot = structuredClone(res);
      if (cloned.config?.anonymizationSalt) {
        cloned.config.anonymizationSalt = '********';
      }
      if (cloned.config?.teacherLlm?.apiKey) {
        cloned.config.teacherLlm.apiKey = '********';
      }
      if (cloned.config?.fleetShipper?.accessKey) {
        cloned.config.fleetShipper.accessKey = '********';
      }
      if (cloned.config?.fleetShipper?.secretKey) {
        cloned.config.fleetShipper.secretKey = '********';
      }
      return cloned;
    }
    return res;
  }

  const state = await getCurrentDesiredState().catch(() => null);
  const cfg = ThreatHarvesterConfigSchema.parse(state?.threatHarvester ?? {});
  if (!isAdminSession(session)) {
    if (cfg.anonymizationSalt) cfg.anonymizationSalt = '********';
    if (cfg.teacherLlm?.apiKey) cfg.teacherLlm.apiKey = '********';
    if (cfg.fleetShipper?.accessKey) cfg.fleetShipper.accessKey = '********';
    if (cfg.fleetShipper?.secretKey) cfg.fleetShipper.secretKey = '********';
  }
  return {
    daemonDown: true,
    config: cfg,
    bpfAttached: false,
    attachedInterfaces: [],
    activeHooks: [],
    excludedUprobeDaemons: [
      'axonwalld',
      'sshd',
      'eluvix',
      'slapd',
      'vault',
      'minio',
      'k3s',
      'containerd',
      'systemd',
      'postgres',
    ],
    stats: {
      packetsSeen: 0,
      tier0Events: 0,
      tier1PayloadEvents: 0,
      ringbufDrops: 0,
      darkPortHits: 0,
      memfdAlerts: 0,
      tlsUprobeEvents: 0,
      totalEpisodes: 0,
      goldEpisodes: 0,
      silverEpisodes: 0,
      benignEpisodes: 0,
      pinnedEpisodes: 0,
      pendingReview: 0,
      redactedSecrets: 0,
      spoolUsedBytes: 0,
      spoolQuotaBytes: (cfg.maxSpoolGb || 10) * 1024 * 1024 * 1024,
      zfsBacked: false,
      backpressureTripped: false,
    },
    timestamp: new Date().toISOString(),
  };
}

export async function listThreatHarvesterEpisodes(params?: {
  tier?: string;
  reviewStatus?: string;
  limit?: number;
}): Promise<{ episodes: ThreatEpisode[]; total: number; daemonDown?: boolean }> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('ebpf-threat-harvester');
  await enforceRateLimit(60, 60000, 'threat-harvester-episodes');

  const qs = new URLSearchParams();
  if (params?.tier && params.tier !== 'all') qs.set('tier', params.tier);
  if (params?.reviewStatus && params.reviewStatus !== 'all') qs.set('reviewStatus', params.reviewStatus);
  qs.set('limit', String(params?.limit && params.limit > 0 ? params.limit : 100));

  const res = await callAgentApi<{ episodes?: ThreatEpisode[]; total?: number }>(
    `/v1/security/threat-harvester/episodes?${qs.toString()}`,
    'GET',
    undefined,
    8000
  );
  if (!res || !Array.isArray(res.episodes)) {
    return { episodes: [], total: 0, daemonDown: !res };
  }
  return {
    episodes: res.episodes,
    total: typeof res.total === 'number' ? res.total : res.episodes.length,
    daemonDown: false,
  };
}

export async function updateThreatHarvesterLiveConfigAction(
  cfg: Partial<ThreatHarvesterConfig>
): Promise<{ success: boolean; status?: ThreatHarvesterStatusSnapshot; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('ebpf-threat-harvester');
  await enforceRateLimit(20, 60000, 'threat-harvester-config');

  const validated = ThreatHarvesterConfigSchema.parse(cfg);
  const res = await callAgentApiResponse<{ success?: boolean; status?: ThreatHarvesterStatusSnapshot; error?: string; message?: string }>(
    '/v1/security/threat-harvester/config',
    'POST',
    validated,
    10000
  );
  if (!res) {
    return { success: false, error: 'axonwalld threat-harvester config endpoint unreachable' };
  }
  if (res.success === false) {
    return { success: false, error: res.error || res.message || 'Failed to update live harvester config' };
  }
  return { success: true, status: res.status };
}

export async function reviewThreatHarvesterEpisodeAction(input: {
  id: string;
  action: 'pinned_gold' | 'approved_malicious' | 'marked_benign' | 'delete';
}): Promise<{ success: boolean; episode?: ThreatEpisode; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');
  await assertPluginEnabled('ebpf-threat-harvester');
  await enforceRateLimit(60, 60000, 'threat-harvester-review');

  const cleanId = String(input?.id || '').trim();
  if (!cleanId) {
    return { success: false, error: 'Episode ID is required' };
  }

  const res = await callAgentApiResponse<{ success?: boolean; episode?: ThreatEpisode; error?: string; message?: string }>(
    '/v1/security/threat-harvester/episodes/review',
    'POST',
    { id: cleanId, action: input.action },
    8000
  );
  if (!res) {
    return { success: false, error: 'axonwalld threat-harvester review endpoint unreachable' };
  }
  if (res.success === false) {
    return { success: false, error: res.error || res.message || 'Failed to review episode' };
  }
  return { success: true, episode: res.episode };
}

export async function annotateThreatHarvesterEpisodeAction(
  id: string
): Promise<{ success: boolean; episode?: ThreatEpisode; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'operator');
  await assertPluginEnabled('ebpf-threat-harvester');
  await enforceRateLimit(30, 60000, 'threat-harvester-annotate');

  const cleanId = String(id || '').trim();
  if (!cleanId) {
    return { success: false, error: 'Episode ID is required' };
  }

  const res = await callAgentApiResponse<{ success?: boolean; episode?: ThreatEpisode; error?: string; message?: string }>(
    '/v1/security/threat-harvester/episodes/annotate',
    'POST',
    { id: cleanId },
    25000
  );
  if (!res) {
    return { success: false, error: 'axonwalld threat-harvester annotate endpoint unreachable' };
  }
  if (res.success === false) {
    return { success: false, error: res.error || res.message || 'Failed to annotate episode' };
  }
  return { success: true, episode: res.episode };
}

export async function simulateThreatHarvesterEpisodeAction(
  scenario:
    | 'honeypot_rce_memfd'
    | 'dns_c2_exfil'
    | 'credential_stuffing_redacted'
    | 'benign_k3s_egress'
): Promise<{ success: boolean; episode?: ThreatEpisode; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('ebpf-threat-harvester');
  await enforceRateLimit(30, 60000, 'threat-harvester-simulate');

  const res = await callAgentApiResponse<{ success?: boolean; episode?: ThreatEpisode; error?: string; message?: string }>(
    '/v1/security/threat-harvester/simulate',
    'POST',
    { scenario },
    10000
  );
  if (!res) {
    return { success: false, error: 'axonwalld threat-harvester simulate endpoint unreachable' };
  }
  if (res.success === false) {
    return { success: false, error: res.error || res.message || 'Failed to simulate threat episode' };
  }
  return { success: true, episode: res.episode };
}

export async function shipThreatHarvesterCorpusAction(): Promise<{
  success: boolean;
  objectKey?: string;
  error?: string;
}> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('ebpf-threat-harvester');
  await enforceRateLimit(10, 60000, 'threat-harvester-ship');

  const res = await callAgentApiResponse<{ success?: boolean; objectKey?: string; error?: string; message?: string }>(
    '/v1/security/threat-harvester/ship',
    'POST',
    {},
    60_000
  );
  if (!res) {
    return { success: false, error: 'axonwalld threat-harvester ship endpoint unreachable' };
  }
  if (res.success === false) {
    return { success: false, error: res.error || res.message || 'Failed to ship corpus to S3' };
  }
  return { success: true, objectKey: res.objectKey };
}

// ============================================================================
// Kubernetes (K3s) Browser K9s Explorer, Pulse, Topology & Operations Actions
// ============================================================================

function emptyK3sClusterPulse(error: string): K3sClusterPulse {
  return {
    available: false,
    error,
    timestamp: new Date().toISOString(),
    metricsAvailable: false,
    cniPlugin: 'flannel',
    k3sVersion: '',
    counts: {
      nodesReady: 0,
      nodesTotal: 0,
      nodesCordoned: 0,
      podsRunning: 0,
      podsPending: 0,
      podsFailed: 0,
      podsSucceeded: 0,
      podsUnknown: 0,
      podsTotal: 0,
      totalRestarts: 0,
      deploymentsReady: 0,
      deploymentsTotal: 0,
      statefulSetsReady: 0,
      statefulSetsTotal: 0,
      daemonSetsReady: 0,
      daemonSetsTotal: 0,
      jobsActive: 0,
      jobsSucceeded: 0,
      jobsFailed: 0,
      cronJobsTotal: 0,
      servicesTotal: 0,
      ingressesTotal: 0,
      pvcsBound: 0,
      pvcsTotal: 0,
      pvsTotal: 0,
      storageClassesTotal: 0,
      namespacesTotal: 0,
      configMapsTotal: 0,
      secretsTotal: 0,
      networkPoliciesTotal: 0,
      hpasTotal: 0,
      crdsTotal: 0,
      warningEventsCount: 0,
      normalEventsCount: 0,
    },
    podPhaseDistribution: [],
    namespaceStats: [],
    nodes: [],
    storageByClass: [],
    topRestartingPods: [],
    topResourcePods: [],
    recentEvents: [],
    workloadsSummary: [],
    servicesSummary: [],
    ingressesSummary: [],
    pvcsSummary: [],
    topology: { nodes: [], edges: [] },
  };
}

export async function getK3sClusterPulseAction(): Promise<K3sClusterPulse> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-k3s');

  const res = await callAgentApiDetailed<K3sClusterPulse>('/v1/k3s/pulse', 'GET', undefined, 15_000);
  if (res.kind === 'ok') {
    return res.data;
  }
  if (res.kind === 'http_error') {
    return emptyK3sClusterPulse(res.message || `Failed to load cluster pulse (HTTP ${res.status})`);
  }
  return emptyK3sClusterPulse(
    res.kind === 'timeout'
      ? 'Timed out waiting for K3s cluster pulse from axonwalld.'
      : 'axonwalld daemon unreachable: cannot query live K3s cluster telemetry.'
  );
}

export async function getK3sApiResourcesAction(): Promise<K3sAPIResource[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-k3s');

  const res = await callAgentApiDetailed<{ resources?: K3sAPIResource[]; error?: string }>(
    '/v1/k3s/api-resources',
    'GET',
    undefined,
    15_000
  );
  if (res.kind === 'ok' && Array.isArray(res.data?.resources)) {
    return res.data.resources;
  }
  return [];
}

export async function getK3sNamespacesAction(): Promise<K3sNamespaceSummary[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-k3s');

  const res = await callAgentApiDetailed<{ namespaces?: K3sNamespaceSummary[]; error?: string }>(
    '/v1/k3s/namespaces',
    'GET',
    undefined,
    15_000
  );
  if (res.kind === 'ok' && Array.isArray(res.data?.namespaces)) {
    return res.data.namespaces;
  }
  return [];
}

export async function listK3sResourcesAction(params: {
  resource: string;
  namespace?: string;
  labelSelector?: string;
}): Promise<K3sResourceListResponse> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-k3s');

  const qs = new URLSearchParams();
  qs.set('resource', (params.resource || 'pods').trim());
  if (params.namespace) {
    qs.set('namespace', params.namespace.trim());
  }
  if (params.labelSelector) {
    qs.set('labelSelector', params.labelSelector.trim());
  }

  const res = await callAgentApiDetailed<K3sResourceListResponse>(
    `/v1/k3s/resources?${qs.toString()}`,
    'GET',
    undefined,
    15_000
  );
  if (res.kind === 'ok') {
    return res.data;
  }
  const errMsg =
    res.kind === 'http_error'
      ? res.message
      : res.kind === 'timeout'
        ? 'Timed out listing Kubernetes resources.'
        : 'axonwalld daemon unreachable: could not list Kubernetes resources.';
  return {
    resource: params.resource || 'pods',
    namespace: params.namespace || '_all',
    namespaced: true,
    items: [],
    count: 0,
    error: errMsg,
  };
}

export async function inspectK3sResourceAction(params: {
  resource: string;
  name: string;
  namespace?: string;
  decodeSecret?: boolean;
}): Promise<K3sResourceInspectResponse> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-k3s');
  if (params.decodeSecret) {
    assertActionPermitted(session, 'admin');
  }

  const qs = new URLSearchParams();
  qs.set('resource', params.resource.trim());
  qs.set('name', params.name.trim());
  if (params.namespace && params.namespace !== '_all') {
    qs.set('namespace', params.namespace.trim());
  }
  if (params.decodeSecret) {
    qs.set('decode', 'true');
  }

  const res = await callAgentApiDetailed<K3sResourceInspectResponse>(
    `/v1/k3s/resource/inspect?${qs.toString()}`,
    'GET',
    undefined,
    15_000
  );
  if (res.kind === 'ok') {
    return res.data;
  }
  const errMsg =
    res.kind === 'http_error'
      ? res.message
      : res.kind === 'timeout'
        ? 'Timed out inspecting Kubernetes resource.'
        : 'axonwalld daemon unreachable: could not inspect Kubernetes resource.';
  return {
    resource: params.resource,
    kind: '',
    apiVersion: '',
    name: params.name,
    namespace: params.namespace,
    object: {},
    yaml: '',
    describe: '',
    events: [],
    related: [],
    error: errMsg,
  };
}

export async function getK3sPodLogsAction(params: {
  namespace: string;
  name: string;
  resource?: string;
  container?: string;
  tail?: number;
  previous?: boolean;
  timestamps?: boolean;
  sinceSeconds?: number;
}): Promise<K3sLogsResponse> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('core-k3s');

  const qs = new URLSearchParams();
  qs.set('namespace', (params.namespace || 'default').trim());
  qs.set('name', params.name.trim());
  if (params.resource) qs.set('resource', params.resource.trim());
  if (params.container) qs.set('container', params.container.trim());
  if (params.tail) qs.set('tail', String(params.tail));
  if (params.previous) qs.set('previous', 'true');
  if (params.timestamps) qs.set('timestamps', 'true');
  if (params.sinceSeconds) qs.set('sinceSeconds', String(params.sinceSeconds));

  const res = await callAgentApiDetailed<K3sLogsResponse>(
    `/v1/k3s/logs?${qs.toString()}`,
    'GET',
    undefined,
    15_000
  );
  if (res.kind === 'ok') {
    return res.data;
  }
  const errMsg =
    res.kind === 'http_error'
      ? res.message
      : res.kind === 'timeout'
        ? 'Timed out fetching pod logs.'
        : 'axonwalld daemon unreachable: could not fetch pod logs.';
  return {
    logs: '',
    linesCount: 0,
    truncated: false,
    container: params.container,
    previous: Boolean(params.previous),
    error: errMsg,
  };
}

export async function executeK3sAction(payload: K3sActionRequest): Promise<K3sActionResponse> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('core-k3s');

  const timeoutMs = payload.action === 'drain' ? 90_000 : 30_000;
  const res = await callAgentApiDetailed<K3sActionResponse>('/v1/k3s/action', 'POST', payload, timeoutMs);
  if (res.kind === 'ok') {
    return res.data;
  }
  if (res.kind === 'http_error') {
    const d = res.data as Partial<K3sActionResponse> | undefined;
    return {
      success: false,
      message: d?.message || res.message,
      output: d?.output || res.message,
      exitCode: d?.exitCode ?? 1,
      latencyMs: d?.latencyMs,
    };
  }
  return {
    success: false,
    message:
      res.kind === 'timeout'
        ? `Timed out executing Kubernetes action '${payload.action}'.`
        : `Daemon unavailable: could not execute '${payload.action}'.`,
    exitCode: 1,
  };
}

export interface NetBoxPodStatusSnapshot {
  name: string;
  phase: string;
  ready: boolean;
  image?: string;
  node?: string;
  reason?: string;
}

export interface NetBoxSyncCountsSnapshot {
  created: number;
  updated: number;
  unchanged: number;
}

export interface NetBoxSyncResultSnapshot {
  success: boolean;
  dryRun: boolean;
  timestamp: string;
  endpoint: string;
  devicesSynced: number;
  vrfs: NetBoxSyncCountsSnapshot;
  vlans: NetBoxSyncCountsSnapshot;
  interfaces: NetBoxSyncCountsSnapshot;
  prefixes: NetBoxSyncCountsSnapshot;
  ipAddresses: NetBoxSyncCountsSnapshot;
  virtualMachines: NetBoxSyncCountsSnapshot;
  warnings?: string[];
  error?: string;
}

export interface NetBoxStatusSnapshot {
  daemonDown?: boolean;
  enabled: boolean;
  k3sDependencyMet: boolean;
  k3sReady: boolean;
  manifestPresent: boolean;
  ldapBound: boolean;
  apiReachable: boolean;
  netboxVersion?: string;
  namespace: string;
  domain: string;
  endpointUrl: string;
  internalServiceUrl: string;
  clusterIp?: string;
  siteName: string;
  siteSlug: string;
  pods: NetBoxPodStatusSnapshot[];
  podReadyCount: number;
  podTotalCount: number;
  lastSync?: NetBoxSyncResultSnapshot;
  plannedSummary?: {
    vrfsCount: number;
    vlansCount: number;
    interfacesCount: number;
    prefixesCount: number;
    ipAddressesCount: number;
    virtualMachinesCount: number;
    totalObjects: number;
  };
  statusError?: string;
}

export interface NetBoxCredentialsSnapshot {
  configured: boolean;
  superuserUsername: string;
  superuserEmail: string;
  endpointUrl: string;
  internalServiceUrl: string;
  tokenPreview?: string;
  apiToken?: string;
  superuserPassword?: string;
}

export async function getNetBoxStatusAction(): Promise<NetBoxStatusSnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('netbox');

  const res = await callAgentApiDetailed<NetBoxStatusSnapshot>('/v1/netbox/status', 'GET', undefined, 8_000);
  if (res.kind === 'ok' && res.data) {
    return {
      ...res.data,
      daemonDown: false,
      pods: Array.isArray(res.data.pods) ? res.data.pods : [],
    };
  }

  const state = await getCurrentDesiredState().catch(() => null);
  const cfg = resolveNetBoxConfig(state);
  const plan = state ? buildNetBoxSyncPlan(state) : undefined;
  const proto = cfg.ingressTls ? 'https' : 'http';
  const endpointUrl = cfg.externalUrl?.trim() || `${proto}://${cfg.domain}`;

  return {
    daemonDown: true,
    enabled: cfg.enabled,
    k3sDependencyMet: Boolean(state?.capabilities?.k3sEnabled ?? state?.k3s?.enabled),
    k3sReady: false,
    manifestPresent: false,
    ldapBound: false,
    apiReachable: false,
    namespace: cfg.namespace,
    domain: cfg.domain,
    endpointUrl,
    internalServiceUrl: `http://netbox.${cfg.namespace}.svc.cluster.local:${cfg.servicePort}`,
    siteName: cfg.siteName,
    siteSlug: cfg.siteSlug,
    pods: [],
    podReadyCount: 0,
    podTotalCount: 0,
    plannedSummary: plan?.summary,
    statusError:
      res.kind === 'http_error'
        ? res.message
        : res.kind === 'timeout'
          ? 'Timed out querying NetBox status from axonwalld.'
          : 'axonwalld daemon unreachable.',
  };
}

async function validateServiceOverrideUrl(
  rawOverride: string,
  serviceLabel: string,
  candidateUrls: Array<string | undefined>
): Promise<string> {
  const trimmed = rawOverride.trim();
  const { url } = await assertSafeOutboundUrl(trimmed, {
    allowHttp: true,
    allowPrivate: true,
  });
  const allowedOrigins = new Set<string>();
  for (const cand of candidateUrls) {
    const clean = cand?.trim();
    if (!clean) continue;
    try {
      allowedOrigins.add(new URL(clean).origin);
    } catch {}
  }
  if (!allowedOrigins.has(url.origin)) {
    throw new Error(
      `Forbidden: ${serviceLabel} endpointOverride origin (${url.origin}) does not match configured service origin`
    );
  }
  return trimmed;
}

function resolveNetBoxAllowedOrigins(state: DesiredState | null | undefined): Array<string | undefined> {
  const cfg = resolveNetBoxConfig(state);
  return [
    cfg.externalUrl,
    `https://${cfg.domain}`,
    `http://${cfg.domain}`,
    `http://netbox.${cfg.namespace}.svc.cluster.local:${cfg.servicePort}`,
  ];
}

function resolveLibreNmsAllowedOrigins(state: DesiredState | null | undefined): Array<string | undefined> {
  const cfg = resolveLibreNmsConfig(state);
  return [
    cfg.externalUrl,
    `https://${cfg.domain}`,
    `http://${cfg.domain}`,
    `http://librenms.${cfg.namespace}.svc.cluster.local:${cfg.servicePort}`,
  ];
}

export async function triggerNetBoxSyncAction(options?: {
  dryRun?: boolean;
  endpointOverride?: string;
}): Promise<NetBoxSyncResultSnapshot> {
  const session = await getSession();
  await enforceRateLimit(10, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('netbox');

  let validatedOverride: string | undefined;
  if (options?.endpointOverride?.trim()) {
    const state = await getDesiredStateInternal().catch(() => null);
    validatedOverride = await validateServiceOverrideUrl(
      options.endpointOverride,
      'NetBox',
      resolveNetBoxAllowedOrigins(state)
    );
  }

  const payload = {
    dryRun: Boolean(options?.dryRun),
    ...(validatedOverride ? { endpointOverride: validatedOverride } : {}),
  };
  const res = await callAgentApiDetailed<NetBoxSyncResultSnapshot | { error?: string; result?: NetBoxSyncResultSnapshot }>(
    '/v1/netbox/sync',
    'POST',
    payload,
    45_000,
  );
  if (res.kind === 'ok' && res.data) {
    return res.data as NetBoxSyncResultSnapshot;
  }
  const errData = (res.kind === 'http_error' ? res.data : undefined) as
    | { error?: string; result?: NetBoxSyncResultSnapshot }
    | undefined;
  if (errData?.result) {
    return errData.result;
  }
  return {
    success: false,
    dryRun: Boolean(options?.dryRun),
    timestamp: new Date().toISOString(),
    endpoint: options?.endpointOverride?.trim() || '',
    devicesSynced: 0,
    vrfs: { created: 0, updated: 0, unchanged: 0 },
    vlans: { created: 0, updated: 0, unchanged: 0 },
    interfaces: { created: 0, updated: 0, unchanged: 0 },
    prefixes: { created: 0, updated: 0, unchanged: 0 },
    ipAddresses: { created: 0, updated: 0, unchanged: 0 },
    virtualMachines: { created: 0, updated: 0, unchanged: 0 },
    error:
      errData?.error ||
      (res.kind === 'http_error'
        ? res.message
        : res.kind === 'timeout'
          ? 'Timed out waiting for NetBox inventory sync.'
          : 'axonwalld daemon unreachable: could not sync inventory to NetBox.'),
  };
}

export async function getNetBoxCredentialsAction(reveal = false): Promise<NetBoxCredentialsSnapshot> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('netbox');

  const suffix = reveal ? '?reveal=true' : '';
  const res = await callAgentApiDetailed<NetBoxCredentialsSnapshot>(
    `/v1/netbox/credentials${suffix}`,
    'GET',
    undefined,
    5_000,
  );
  if (res.kind === 'ok' && res.data) {
    return res.data;
  }
  return {
    configured: false,
    superuserUsername: 'admin',
    superuserEmail: 'admin@axonwall.local',
    endpointUrl: 'https://netbox.axonwall.local',
    internalServiceUrl: 'http://netbox.netbox.svc.cluster.local:8080',
  };
}











export interface LibreNmsStatusSnapshot {
  daemonDown?: boolean;
  enabled: boolean;
  mode: 'k3s' | 'external';
  k3sDependencyMet: boolean;
  k3sReady: boolean;
  manifestPresent: boolean;
  ldapBound: boolean;
  apiReachable: boolean;
  librenmsVersion?: string;
  namespace: string;
  domain: string;
  endpointUrl: string;
  internalServiceUrl: string;
  clusterIp?: string;
  deviceCount: number;
  portCount: number;
  linkCount: number;
  activeAlertCount: number;
  webhookAlertCount: number;
  pods: NetBoxPodStatusSnapshot[];
  podReadyCount: number;
  podTotalCount: number;
  lastSync?: LibreNmsSyncResultSnapshot;
  enrollmentPlan?: {
    snmpEnabledOnLocal: boolean;
    targets: Array<{
      id: string;
      hostname: string;
      displayName: string;
      source: string;
      snmpVersion: string;
      port: number;
      sysRole: string;
    }>;
    discoverySubnets: Array<{ cidr: string; label: string }>;
    summary: { targetsCount: number; subnetsCount: number };
  };
  statusError?: string;
}

export interface LibreNmsSyncResultSnapshot {
  success: boolean;
  dryRun: boolean;
  timestamp: string;
  endpoint: string;
  enrolled: number;
  existing: number;
  failed: number;
  subnets: number;
  warnings?: string[];
  error?: string;
}

export interface LibreNmsCredentialsSnapshot {
  configured: boolean;
  adminUsername: string;
  adminEmail: string;
  endpointUrl: string;
  internalServiceUrl: string;
  webhookPath: string;
  tokenPreview?: string;
  apiToken?: string;
  adminPassword?: string;
  webhookSecret?: string;
}

export interface LibreNmsTopologySnapshot {
  available: boolean;
  endpoint?: string;
  timestamp: string;
  devices: Array<{
    deviceId: number;
    hostname: string;
    sysName?: string;
    ip?: string;
    os?: string;
    hardware?: string;
    version?: string;
    serial?: string;
    status: boolean;
    disabled: boolean;
    location?: string;
    purpose?: string;
    uptime?: number;
  }>;
  ports: Array<{
    portId: number;
    deviceId: number;
    deviceHost?: string;
    ifName: string;
    ifDescr?: string;
    ifAlias?: string;
    ifOperStatus: string;
    ifAdminStatus: string;
    ifSpeedBps?: number;
    inRateBps?: number;
    outRateBps?: number;
    inErrors?: number;
    outErrors?: number;
    ifVlan?: string;
    ifMtu?: number;
    ifPhysAddress?: string;
    ifType?: string;
  }>;
  links: Array<{
    id: number;
    localDeviceId: number;
    localDevice?: string;
    localPortId: number;
    localPort: string;
    remoteDeviceId?: number;
    remoteDevice: string;
    remotePortId?: number;
    remotePort: string;
    protocol: string;
    active: boolean;
  }>;
  fdb: Array<{ deviceId: number; portId: number; vlanId?: number; macAddress: string }>;
  arp: Array<{ deviceId: number; portId?: number; macAddress: string; ipAddress: string }>;
  healthSensors: Array<{
    deviceId: number;
    class: string;
    descr: string;
    current: number;
    highLimit?: number;
    lowLimit?: number;
    alerted: boolean;
  }>;
  alerts: Array<{
    id: string;
    deviceId?: number;
    deviceHostname: string;
    deviceIp?: string;
    rule: string;
    severity: string;
    state: number;
    timestamp: string;
    portName?: string;
    message: string;
    source: string;
  }>;
  webhookAlerts: Array<{
    id: string;
    deviceId?: number;
    deviceHostname: string;
    deviceIp?: string;
    rule: string;
    severity: string;
    state: number;
    timestamp: string;
    portName?: string;
    message: string;
    source: string;
  }>;
  error?: string;
}

export interface LibreNmsNetBoxSyncResultSnapshot {
  success: boolean;
  action: 'preview' | 'push' | 'pull';
  dryRun: boolean;
  timestamp: string;
  librenmsEndpoint?: string;
  netboxEndpoint?: string;
  devicesQueued: number;
  cablesQueued: number;
  netboxResult?: {
    success: boolean;
    dryRun: boolean;
    timestamp: string;
    endpoint: string;
    devices: { created: number; updated: number; unchanged: number };
    interfaces: { created: number; updated: number; unchanged: number };
    cables: { created: number; updated: number; unchanged: number };
    conflicts: Array<{ key: string; field: string; axonwallVal: string; netboxVal: string; resolution?: string }>;
    warnings?: string[];
    error?: string;
  };
  pullResult?: LibreNmsSyncResultSnapshot;
  warnings?: string[];
  error?: string;
}

export async function getLibreNmsStatusAction(): Promise<LibreNmsStatusSnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('librenms');

  const res = await callAgentApiDetailed<LibreNmsStatusSnapshot>('/v1/librenms/status', 'GET', undefined, 8_000);
  if (res.kind === 'ok' && res.data) {
    return {
      ...res.data,
      daemonDown: false,
      pods: Array.isArray(res.data.pods) ? res.data.pods : [],
    };
  }

  const state = await getCurrentDesiredState().catch(() => null);
  const cfg = resolveLibreNmsConfig(state);
  const plan = buildLibreNmsEnrollmentPlan(state);
  const proto = cfg.ingressTls ? 'https' : 'http';
  const endpointUrl = cfg.externalUrl?.trim() || `${proto}://${cfg.domain}`;

  return {
    daemonDown: true,
    enabled: cfg.enabled,
    mode: cfg.mode,
    k3sDependencyMet:
      cfg.mode === 'external' || Boolean(state?.capabilities?.k3sEnabled ?? state?.k3s?.enabled),
    k3sReady: false,
    manifestPresent: false,
    ldapBound: false,
    apiReachable: false,
    namespace: cfg.namespace,
    domain: cfg.domain,
    endpointUrl,
    internalServiceUrl: `http://librenms.${cfg.namespace}.svc.cluster.local:${cfg.servicePort}`,
    deviceCount: 0,
    portCount: 0,
    linkCount: 0,
    activeAlertCount: 0,
    webhookAlertCount: 0,
    pods: [],
    podReadyCount: 0,
    podTotalCount: 0,
    enrollmentPlan: plan,
    statusError:
      res.kind === 'http_error'
        ? res.message
        : res.kind === 'timeout'
          ? 'Timed out querying LibreNMS status from axonwalld.'
          : 'axonwalld daemon unreachable.',
  };
}

export async function triggerLibreNmsSyncAction(options?: {
  dryRun?: boolean;
  endpointOverride?: string;
}): Promise<LibreNmsSyncResultSnapshot> {
  const session = await getSession();
  await enforceRateLimit(10, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('librenms');

  let validatedOverride: string | undefined;
  if (options?.endpointOverride?.trim()) {
    const state = await getDesiredStateInternal().catch(() => null);
    validatedOverride = await validateServiceOverrideUrl(
      options.endpointOverride,
      'LibreNMS',
      resolveLibreNmsAllowedOrigins(state)
    );
  }

  const payload = {
    dryRun: Boolean(options?.dryRun),
    ...(validatedOverride ? { endpointOverride: validatedOverride } : {}),
  };
  const res = await callAgentApiDetailed<
    LibreNmsSyncResultSnapshot | { error?: string; result?: LibreNmsSyncResultSnapshot }
  >('/v1/librenms/sync', 'POST', payload, 45_000);
  if (res.kind === 'ok' && res.data) {
    return res.data as LibreNmsSyncResultSnapshot;
  }
  const errData = (res.kind === 'http_error' ? res.data : undefined) as
    | { error?: string; result?: LibreNmsSyncResultSnapshot }
    | undefined;
  if (errData?.result) {
    return errData.result;
  }
  return {
    success: false,
    dryRun: Boolean(options?.dryRun),
    timestamp: new Date().toISOString(),
    endpoint: options?.endpointOverride?.trim() || '',
    enrolled: 0,
    existing: 0,
    failed: 0,
    subnets: 0,
    error:
      errData?.error ||
      (res.kind === 'http_error'
        ? res.message
        : res.kind === 'timeout'
          ? 'Timed out waiting for LibreNMS device enrollment.'
          : 'axonwalld daemon unreachable: could not sync devices to LibreNMS.'),
  };
}

export async function getLibreNmsCredentialsAction(reveal = false): Promise<LibreNmsCredentialsSnapshot> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('librenms');

  const suffix = reveal ? '?reveal=true' : '';
  const res = await callAgentApiDetailed<LibreNmsCredentialsSnapshot>(
    `/v1/librenms/credentials${suffix}`,
    'GET',
    undefined,
    5_000,
  );
  if (res.kind === 'ok' && res.data) {
    return res.data;
  }
  return {
    configured: false,
    adminUsername: 'admin',
    adminEmail: 'admin@axonwall.local',
    endpointUrl: 'https://librenms.axonwall.local',
    internalServiceUrl: 'http://librenms.librenms.svc.cluster.local:8000',
    webhookPath: '/api/v1/services/librenms/webhook',
  };
}

export async function getLibreNmsTopologyAction(endpointOverride?: string): Promise<LibreNmsTopologySnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('librenms');
  if (endpointOverride && endpointOverride.trim()) {
    throw new Error('Forbidden: Custom endpoint overrides are not permitted on LibreNMS topology reads');
  }

  const res = await callAgentApiDetailed<LibreNmsTopologySnapshot>(
    '/v1/librenms/topology',
    'GET',
    undefined,
    10_000,
  );
  if (res.kind === 'ok' && res.data) {
    return {
      ...res.data,
      devices: Array.isArray(res.data.devices) ? res.data.devices : [],
      ports: Array.isArray(res.data.ports) ? res.data.ports : [],
      links: Array.isArray(res.data.links) ? res.data.links : [],
      fdb: Array.isArray(res.data.fdb) ? res.data.fdb : [],
      arp: Array.isArray(res.data.arp) ? res.data.arp : [],
      healthSensors: Array.isArray(res.data.healthSensors) ? res.data.healthSensors : [],
      alerts: Array.isArray(res.data.alerts) ? res.data.alerts : [],
      webhookAlerts: Array.isArray(res.data.webhookAlerts) ? res.data.webhookAlerts : [],
    };
  }
  return {
    available: false,
    timestamp: new Date().toISOString(),
    devices: [],
    ports: [],
    links: [],
    fdb: [],
    arp: [],
    healthSensors: [],
    alerts: [],
    webhookAlerts: [],
    error: res.kind === 'http_error' ? res.message : 'axonwalld daemon unreachable.',
  };
}

export async function triggerLibreNmsNetBoxSyncAction(options?: {
  action?: 'preview' | 'push' | 'pull';
  dryRun?: boolean;
  overwriteLabels?: boolean;
  endpointOverride?: string;
  netboxOverride?: string;
}): Promise<LibreNmsNetBoxSyncResultSnapshot> {
  const session = await getSession();
  await enforceRateLimit(10, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('librenms');

  let validatedLibreOverride: string | undefined;
  let validatedNetboxOverride: string | undefined;
  if (options?.endpointOverride?.trim() || options?.netboxOverride?.trim()) {
    const state = await getDesiredStateInternal().catch(() => null);
    if (options?.endpointOverride?.trim()) {
      validatedLibreOverride = await validateServiceOverrideUrl(
        options.endpointOverride,
        'LibreNMS',
        resolveLibreNmsAllowedOrigins(state)
      );
    }
    if (options?.netboxOverride?.trim()) {
      validatedNetboxOverride = await validateServiceOverrideUrl(
        options.netboxOverride,
        'NetBox',
        resolveNetBoxAllowedOrigins(state)
      );
    }
  }

  const action = options?.action || 'preview';
  const payload = {
    action,
    dryRun: options?.dryRun ?? action === 'preview',
    overwriteLabels: Boolean(options?.overwriteLabels),
    ...(validatedLibreOverride ? { endpointOverride: validatedLibreOverride } : {}),
    ...(validatedNetboxOverride ? { netboxOverride: validatedNetboxOverride } : {}),
  };
  const res = await callAgentApiDetailed<
    LibreNmsNetBoxSyncResultSnapshot | { error?: string; result?: LibreNmsNetBoxSyncResultSnapshot }
  >('/v1/librenms/netbox-sync', 'POST', payload, 45_000);
  if (res.kind === 'ok' && res.data) {
    return res.data as LibreNmsNetBoxSyncResultSnapshot;
  }
  const errData = (res.kind === 'http_error' ? res.data : undefined) as
    | { error?: string; result?: LibreNmsNetBoxSyncResultSnapshot }
    | undefined;
  if (errData?.result) {
    return errData.result;
  }
  return {
    success: false,
    action,
    dryRun: payload.dryRun,
    timestamp: new Date().toISOString(),
    devicesQueued: 0,
    cablesQueued: 0,
    error: errData?.error || (res.kind === 'http_error' ? res.message : 'axonwalld daemon unreachable.'),
  };
}

export interface TopologyLocalProbeSnapshot {
  timestamp: string;
  localHostId: string;
  nics: Array<{
    hostId: string;
    device: string;
    name?: string;
    role?: string;
    adminUp: boolean;
    carrierUp: boolean;
    speedMbps?: number;
    mtu?: number;
    mac?: string;
    ipv4Addresses?: string[];
    domAlarm?: boolean;
    rxErrors?: number;
    txErrors?: number;
    lldpNeighbors?: Array<{ chassisName: string; portId: string; portDescr?: string }>;
  }>;
  tunnels: Array<{
    hostId: string;
    name: string;
    kind: 'wireguard' | 'ipsec' | 'headscale';
    up: boolean;
    handshakeAgeSec?: number;
    peerEndpoint?: string;
  }>;
  transceivers: Array<{
    interface: string;
    vendor: string;
    partNumber: string;
    temperature: number;
    voltage: number;
    txPowerDbm: number;
    rxPowerDbm: number;
    biasCurrentMa: number;
    status: string;
  }>;
  vms: Array<{ vmid: number; name: string; status: string; cores?: number; memoryMb?: number }>;
  containers: Array<{ ctid: number; name: string; status: string; ipAddress?: string }>;
  k3s?: {
    available: boolean;
    nodes: Array<{ name: string; status: string; roles?: string; internalIp?: string; unschedulable?: boolean }>;
    ingresses: Array<{
      name: string;
      namespace: string;
      hosts?: string[];
      backendServices: Array<{ name: string; port?: number }>;
      tlsSecretNames?: string[];
      kind: 'Ingress' | 'IngressRoute' | 'HTTPRoute';
    }>;
    services: Array<{
      name: string;
      namespace: string;
      type?: string;
      clusterIp?: string;
      ports?: number[];
      readyEndpoints: number;
      selector?: Record<string, string>;
    }>;
    workloads: Array<{
      kind: 'Deployment' | 'StatefulSet' | 'DaemonSet';
      name: string;
      namespace: string;
      readyReplicas: number;
      desiredReplicas: number;
      selector?: Record<string, string>;
    }>;
    pvcs: Array<{
      name: string;
      namespace: string;
      storageClass?: string;
      capacity?: string;
      bound: boolean;
    }>;
    networkPolicies: Array<{
      kind: 'NetworkPolicy' | 'CiliumNetworkPolicy';
      name: string;
      namespace: string;
    }>;
  };
}

export interface TopologyFabricSnapshot {
  daemonDown?: boolean;
  timestamp: string;
  local: TopologyLocalProbeSnapshot | null;
  peers: Array<{
    peerId: string;
    name: string;
    role: string;
    reachable: boolean;
    authError?: string;
    error?: string;
    nics: TopologyLocalProbeSnapshot['nics'];
    tunnels: TopologyLocalProbeSnapshot['tunnels'];
  }>;
  librenms?: LibreNmsTopologySnapshot;
  netbox?: {
    available: boolean;
    endpoint?: string;
    timestamp: string;
    sites: string[];
    racks: Array<{ id: number; name: string; site?: string; uHeight?: number }>;
    devices: Array<{ id: number; name: string; role?: string; deviceType?: string; site?: string; rack?: string; primaryIp?: string; status?: string; comments?: string }>;
    interfaces: Array<{ id: number; deviceId: number; deviceName: string; name: string; type?: string; enabled: boolean; mtu?: number; macAddress?: string; description?: string }>;
    cables: Array<{ id: number; aDevice: string; aInterface: string; bDevice: string; bInterface: string; type?: string; status?: string; label?: string; color?: string; length?: number; lengthUnit?: string; comments?: string }>;
    prefixes: string[];
    vlans: number[];
    error?: string;
  };
  netflow?: NetFlowTopologyOverlaySnapshot;
  error?: string;
}

export interface TopologyApplyTargetResultSnapshot {
  phase: number;
  targetType: 'k3s' | 'peer' | 'local';
  targetId: string;
  success: boolean;
  rolledBack?: boolean;
  message?: string;
  error?: string;
}

export interface TopologyApplyPlanResultSnapshot {
  success: boolean;
  dryRun: boolean;
  timestamp: string;
  confirmTimeoutSeconds: number;
  rolledBackAny: boolean;
  results: TopologyApplyTargetResultSnapshot[];
  error?: string;
}

export async function getLocalTopologyProbeAction(): Promise<TopologyLocalProbeSnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('topology-studio');

  const res = await callAgentApiDetailed<TopologyLocalProbeSnapshot>('/v1/topology/probe', 'GET', undefined, 8_000);
  if (res.kind === 'ok' && res.data) {
    return {
      ...res.data,
      nics: Array.isArray(res.data.nics) ? res.data.nics : [],
      tunnels: Array.isArray(res.data.tunnels) ? res.data.tunnels : [],
      transceivers: Array.isArray(res.data.transceivers) ? res.data.transceivers : [],
      vms: Array.isArray(res.data.vms) ? res.data.vms : [],
      containers: Array.isArray(res.data.containers) ? res.data.containers : [],
    };
  }
  return {
    timestamp: new Date().toISOString(),
    localHostId: 'axonwall-local',
    nics: [],
    tunnels: [],
    transceivers: [],
    vms: [],
    containers: [],
  };
}

export async function getFabricTopologyAction(): Promise<TopologyFabricSnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('topology-studio');

  const res = await callAgentApiDetailed<TopologyFabricSnapshot>('/v1/topology/fabric', 'GET', undefined, 12_000);
  if (res.kind === 'ok' && res.data) {
    return {
      ...res.data,
      daemonDown: false,
      peers: Array.isArray(res.data.peers) ? res.data.peers : [],
    };
  }
  return {
    daemonDown: true,
    timestamp: new Date().toISOString(),
    local: null,
    peers: [],
    error:
      res.kind === 'http_error'
        ? res.message
        : res.kind === 'timeout'
          ? 'Timed out aggregating fabric topology probe.'
          : 'axonwalld daemon unreachable.',
  };
}

export async function applyFabricPlanAction(input: {
  dryRun?: boolean;
  confirmTimeoutSeconds?: number;
  k3sEdits?: Array<{
    kind: string;
    name: string;
    namespace?: string;
    manifestYaml?: string;
    scaleReplicas?: number;
    nodeRoles?: string[];
  }>;
  peerEdits?: Array<{
    peerId: string;
    name?: string;
    state: DesiredState;
  }>;
  localState?: DesiredState;
}): Promise<TopologyApplyPlanResultSnapshot> {
  const session = await getSession();
  await enforceRateLimit(10, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('topology-studio');

  const timeout = Math.max(10, Math.min(3600, Math.round(input.confirmTimeoutSeconds ?? 120)));
  const dryRun = Boolean(input.dryRun);
  const k3sEdits = input.k3sEdits ?? [];
  const peerEdits = input.peerEdits ?? [];

  if (input.localState) {
    DesiredStateSchema.parse(input.localState);
  }

  let baseResult: TopologyApplyPlanResultSnapshot = {
    success: true,
    dryRun,
    timestamp: new Date().toISOString(),
    confirmTimeoutSeconds: timeout,
    rolledBackAny: false,
    results: [],
  };

  if (dryRun || k3sEdits.length > 0 || peerEdits.length > 0) {
    const res = await callAgentApiDetailed<
      TopologyApplyPlanResultSnapshot | { error?: string; result?: TopologyApplyPlanResultSnapshot }
    >(
      '/v1/topology/apply',
      'POST',
      {
        dryRun,
        confirmTimeoutSeconds: timeout,
        k3sEdits,
        peerEdits,
        hasLocalChanges: Boolean(input.localState),
      },
      45_000,
    );
    if (res.kind === 'ok' && res.data) {
      baseResult = res.data as TopologyApplyPlanResultSnapshot;
    } else {
      const errData = (res.kind === 'http_error' ? res.data : undefined) as
        | { error?: string; result?: TopologyApplyPlanResultSnapshot }
        | undefined;
      if (errData?.result) return errData.result;
      return {
        ...baseResult,
        success: false,
        error: errData?.error || (res.kind === 'http_error' ? res.message : 'axonwalld daemon unreachable.'),
      };
    }
  }

  if (!dryRun && input.localState && baseResult.success) {
    try {
      const localRes = await applyDesiredState(input.localState, timeout);
      baseResult.results = [
        ...(baseResult.results ?? []),
        {
          phase: 3,
          targetType: 'local',
          targetId: 'local-appliance',
          success: localRes.success,
          message: localRes.message,
        },
      ];
      if (!localRes.success) {
        baseResult.success = false;
        baseResult.error = localRes.message;
      }
    } catch (err) {
      baseResult.success = false;
      baseResult.error = err instanceof Error ? err.message : 'Local apply failed';
      baseResult.results = [
        ...(baseResult.results ?? []),
        {
          phase: 3,
          targetType: 'local',
          targetId: 'local-appliance',
          success: false,
          error: baseResult.error,
        },
      ];
    }
  }

  return baseResult;
}

export async function syncTopologyNetBoxAction(options: {
  action: 'preview' | 'push' | 'pull';
  dryRun?: boolean;
  overwriteLabels?: boolean;
  devices?: Array<{ name: string; role?: string; model?: string; mfg?: string; primaryIp?: string; status?: string; comments?: string }>;
  cables?: Array<{ aDevice: string; aInterface: string; bDevice: string; bInterface: string; type?: string; status?: string; label?: string; color?: string; length?: number; lengthUnit?: string; comments?: string }>;
}): Promise<Record<string, unknown>> {
  const session = await getSession();
  await enforceRateLimit(10, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('topology-studio');

  const res = await callAgentApiDetailed<Record<string, unknown>>(
    '/v1/topology/sync/netbox',
    'POST',
    options,
    45_000,
  );
  if (res.kind === 'ok' && res.data) {
    return res.data;
  }
  const errData = (res.kind === 'http_error' ? res.data : undefined) as Record<string, unknown> | undefined;
  return (
    (errData?.result as Record<string, unknown> | undefined) ?? {
      success: false,
      error: (errData?.error as string) || (res.kind === 'http_error' ? res.message : 'axonwalld unreachable'),
    }
  );
}

export async function syncTopologyLibreNmsAction(options: {
  action: 'preview' | 'push' | 'pull' | 'enroll';
  dryRun?: boolean;
  overwriteLabels?: boolean;
}): Promise<Record<string, unknown>> {
  const session = await getSession();
  await enforceRateLimit(10, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('topology-studio');

  const res = await callAgentApiDetailed<Record<string, unknown>>(
    '/v1/topology/sync/librenms',
    'POST',
    options,
    45_000,
  );
  if (res.kind === 'ok' && res.data) {
    return res.data;
  }
  const errData = (res.kind === 'http_error' ? res.data : undefined) as Record<string, unknown> | undefined;
  return (
    (errData?.result as Record<string, unknown> | undefined) ?? {
      success: false,
      error: (errData?.error as string) || (res.kind === 'http_error' ? res.message : 'axonwalld unreachable'),
    }
  );
}

// =========================================================================
// NetFlow / IPFIX / sFlow Collector & Analytics Actions
// =========================================================================

export interface NetFlowTopologyOverlaySnapshot {
  available: boolean;
  timestamp: string;
  windowSec: number;
  totalBps: number;
  totalFlows: number;
  interfaces: Array<{
    exporterIp: string;
    device: string;
    rxBps: number;
    txBps: number;
    flows: number;
  }>;
}

export interface NetFlowListenerStatusSnapshot {
  id: string;
  name: string;
  protocol: string;
  transport: string;
  address: string;
  listening: boolean;
  packetsReceived: number;
  decodeErrors: number;
  droppedUnknownTemplates: number;
  lastError?: string;
}

export interface NetFlowStatusSnapshot {
  daemonDown?: boolean;
  enabled: boolean;
  running: boolean;
  timestamp: string;
  listeners: NetFlowListenerStatusSnapshot[];
  packetsReceived: number;
  flowsIngested: number;
  bytesIngested: number;
  replicatedPackets: number;
  selfExportedFlows: number;
  decodeErrors: number;
  hotRingCount: number;
  hotRingCapacity: number;
  diskChunksCount: number;
  diskUsageMb: number;
  storageMode: string;
  clickHouseConnected: boolean;
  exportersCount: number;
  templatesCount: number;
  activeAlertsCount: number;
  geoipCityLoaded?: boolean;
  geoipAsnLoaded?: boolean;
  geoipUpdatedAt?: string;
  baselineEntities?: number;
  bgpPrefixes?: number;
  k3sWorkloads?: number;
  lastError?: string;
}

export interface NetFlowQueryRecordSnapshot {
  id: string;
  timestamp: string;
  flowStartMs?: number;
  flowEndMs?: number;
  version: 'netflow5' | 'netflow9' | 'ipfix' | 'sflow5';
  exporterIp: string;
  exporterName?: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: number;
  protocolName: string;
  appName?: string;
  srcHost?: string;
  dstHost?: string;
  srcAsn?: number;
  srcOrg?: string;
  dstAsn?: number;
  dstOrg?: string;
  srcCountry?: string;
  dstCountry?: string;
  srcCity?: string;
  dstCity?: string;
  srcLat?: number;
  srcLon?: number;
  dstLat?: number;
  dstLon?: number;
  peerAs?: number;
  asPath?: number[];
  bgpNextHop?: string;
  direction?: 'internal' | 'ingress' | 'egress' | 'transit';
  inIfIndex?: number;
  outIfIndex?: number;
  inIfName?: string;
  outIfName?: string;
  vlanId?: number;
  bytes: number;
  packets: number;
  bps: number;
  pps?: number;
  tcpFlags?: number;
  tcpFlagsStr?: string;
  tos?: number;
  dscp?: number;
  postNatSrcIp?: string;
  postNatDstIp?: string;
  postNatSrcPort?: number;
  postNatDstPort?: number;
  srcMac?: string;
  dstMac?: string;
  k3sNamespace?: string;
  k3sWorkload?: string;
  k3sPodName?: string;
  k3sServiceName?: string;
  rttMs?: number;
  retransmits?: number;
  hostId?: string;
  hostName?: string;
  threatMatch?: string;
  samplingRate?: number;
}

export interface NetFlowSessionRecordSnapshot {
  id: string;
  initiatorIp: string;
  initiatorHost?: string;
  responderIp: string;
  responderHost?: string;
  initiatorPort: number;
  responderPort: number;
  protocol: number;
  protocolName: string;
  appName?: string;
  direction?: string;
  firstSeenMs: number;
  lastSeenMs: number;
  durationMs: number;
  bytesFwd: number;
  bytesRev: number;
  packetsFwd: number;
  packetsRev: number;
  flowsCount: number;
  asymmetryRatio: number;
  unansweredSyn?: boolean;
  avgRttMs?: number;
  totalRetransmits?: number;
  threatMatch?: string;
}

export interface NetFlowHeatmapMatrixSnapshot {
  rowLabels: string[];
  colLabels: string[];
  values: number[][];
  maxValue: number;
}

export interface NetFlowGeoArcSnapshot {
  srcCountry: string;
  dstCountry: string;
  srcCity?: string;
  dstCity?: string;
  srcLat: number;
  srcLon: number;
  dstLat: number;
  dstLon: number;
  bytes: number;
  flows: number;
  threat?: boolean;
}

export interface NetFlowFleetPeerErrorSnapshot {
  peerId: string;
  peerName: string;
  error: string;
}

export interface NetFlowTopEntrySnapshot {
  key: string;
  label?: string;
  meta?: string;
  bytes: number;
  packets: number;
  flows: number;
  bps: number;
}

export interface NetFlowQueryResponseSnapshot {
  daemonDown?: boolean;
  timestamp: string;
  engine?: string;
  fqlError?: string;
  totalMatchedFlows: number;
  totalBytes: number;
  totalPackets: number;
  avgBps: number;
  uniqueSources: number;
  uniqueDestinations: number;
  seriesKeys: string[];
  timeseries: Array<{
    timestampMs: number;
    timeLabel: string;
    totalBytes: number;
    totalPackets: number;
    flowsCount: number;
    bps: number;
    pps: number;
    series: Record<string, number>;
  }>;
  topSources: NetFlowTopEntrySnapshot[];
  topDestinations: NetFlowTopEntrySnapshot[];
  topApps: NetFlowTopEntrySnapshot[];
  topProtocols: NetFlowTopEntrySnapshot[];
  topCountries: NetFlowTopEntrySnapshot[];
  topAsns: NetFlowTopEntrySnapshot[];
  topExporters: NetFlowTopEntrySnapshot[];
  topInterfaces: NetFlowTopEntrySnapshot[];
  topVlans: NetFlowTopEntrySnapshot[];
  topConversations: Array<{
    srcIp: string;
    srcHost?: string;
    dstIp: string;
    dstHost?: string;
    dstPort: number;
    protocolName: string;
    appName?: string;
    direction?: string;
    bytes: number;
    packets: number;
    flows: number;
    bps: number;
    threatMatch?: string;
  }>;
  sankeyLinks: Array<{
    source: string;
    target: string;
    bytes: number;
    stage: 'src-to-app' | 'app-to-dst';
  }>;
  flows: NetFlowQueryRecordSnapshot[];
  sessions?: NetFlowSessionRecordSnapshot[];
  hostHeatmap?: NetFlowHeatmapMatrixSnapshot;
  portTimeHeatmap?: NetFlowHeatmapMatrixSnapshot;
  geoArcs?: NetFlowGeoArcSnapshot[];
  peerErrors?: NetFlowFleetPeerErrorSnapshot[];
}

export interface NetFlowPercentileRowSnapshot {
  groupKey: string;
  p95Bps: number;
  p99Bps: number;
  peakBps: number;
  avgBps: number;
  totalBytes: number;
  totalFlows: number;
  sampleCount: number;
}

export interface NetFlowReportResponseSnapshot {
  daemonDown?: boolean;
  generatedAt: string;
  rangeDays: number;
  startMs: number;
  endMs: number;
  groupBy: string;
  bucketSeconds: number;
  rows: NetFlowPercentileRowSnapshot[];
  savedSnapshots?: string[];
  rendered?: string;
}

export interface NetFlowBaselineSummarySnapshot {
  entity: string;
  dayOfWeek: number;
  hourOfDay: number;
  samples: number;
  ewmaBps: number;
  stddevBps: number;
  ewmaPps: number;
  stddevPps: number;
  lastSeenSec: number;
}

export interface NetFlowExporterSnapshot {
  exporterIp: string;
  name: string;
  vendor: string;
  site?: string;
  lastSeen: string;
  lastSeenUnixMs: number;
  status: 'green' | 'yellow' | 'red';
  versions: string[];
  packetsReceived: number;
  flowsReceived: number;
  bytesAccounted: number;
  samplingRate: number;
  templatesCount: number;
  fpsEstimate: number;
  bpsEstimate: number;
  interfaces?: Array<{
    exporterIp: string;
    ifIndex: number;
    ifName?: string;
    inOctets: number;
    outOctets: number;
    inErrors: number;
    outErrors: number;
    updatedAt: string;
  }>;
}

export interface NetFlowTemplateSnapshot {
  exporterIp: string;
  sourceId: number;
  version: string;
  templateId: number;
  isOptions: boolean;
  scopeCount?: number;
  fieldCount: number;
  totalBytes: number;
  updatedAt: string;
  lastUsedAt: string;
  packetsUsing: number;
  fields: Array<{
    enterpriseId?: number;
    fieldType: number;
    fieldName: string;
    length: number;
    isScope?: boolean;
  }>;
}

export interface NetFlowAlertSnapshot {
  id: string;
  timestamp: string;
  ruleId: string;
  ruleName: string;
  kind: string;
  severity: string;
  culpritIp: string;
  exporterIp?: string;
  metricValue: number;
  threshold: number;
  summary: string;
  actionsTaken: string[];
  acknowledged: boolean;
}

export async function getNetFlowStatusAction(): Promise<NetFlowStatusSnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('netflow-collector');

  const res = await callAgentApiDetailed<NetFlowStatusSnapshot>('/v1/netflow/status', 'GET', undefined, 5_000);
  if (res.kind === 'ok' && res.data) {
    return {
      ...res.data,
      daemonDown: false,
      listeners: Array.isArray(res.data.listeners) ? res.data.listeners : [],
    };
  }
  return {
    daemonDown: true,
    enabled: false,
    running: false,
    timestamp: new Date().toISOString(),
    listeners: [],
    packetsReceived: 0,
    flowsIngested: 0,
    bytesIngested: 0,
    replicatedPackets: 0,
    selfExportedFlows: 0,
    decodeErrors: 0,
    hotRingCount: 0,
    hotRingCapacity: 50000,
    diskChunksCount: 0,
    diskUsageMb: 0,
    storageMode: 'local',
    clickHouseConnected: false,
    exportersCount: 0,
    templatesCount: 0,
    activeAlertsCount: 0,
    lastError: res.kind === 'http_error' ? res.message : 'axonwalld daemon unreachable.',
  };
}

export async function queryNetFlowAction(options?: {
  rangeMinutes?: number;
  startMs?: number;
  endMs?: number;
  fql?: string;
  groupBy?: string;
  limit?: number;
  offset?: number;
  sortBy?: string;
  biflow?: boolean;
  scope?: 'local' | 'fleet';
  peerIds?: string[];
}): Promise<NetFlowQueryResponseSnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('netflow-collector');

  const res = await callAgentApiDetailed<NetFlowQueryResponseSnapshot>(
    '/v1/netflow/query',
    'POST',
    {
      rangeMinutes: options?.rangeMinutes ?? 60,
      startMs: options?.startMs,
      endMs: options?.endMs,
      fql: options?.fql ?? '',
      groupBy: options?.groupBy ?? 'protocol',
      limit: options?.limit ?? 200,
      offset: options?.offset ?? 0,
      sortBy: options?.sortBy ?? 'time',
      biflow: options?.biflow ?? false,
      scope: options?.scope ?? 'local',
      peerIds: options?.peerIds,
    },
    10_000,
  );
  if (res.kind === 'ok' && res.data) {
    return {
      ...res.data,
      daemonDown: false,
      seriesKeys: Array.isArray(res.data.seriesKeys) ? res.data.seriesKeys : [],
      timeseries: Array.isArray(res.data.timeseries) ? res.data.timeseries : [],
      topSources: Array.isArray(res.data.topSources) ? res.data.topSources : [],
      topDestinations: Array.isArray(res.data.topDestinations) ? res.data.topDestinations : [],
      topApps: Array.isArray(res.data.topApps) ? res.data.topApps : [],
      topProtocols: Array.isArray(res.data.topProtocols) ? res.data.topProtocols : [],
      topCountries: Array.isArray(res.data.topCountries) ? res.data.topCountries : [],
      topAsns: Array.isArray(res.data.topAsns) ? res.data.topAsns : [],
      topExporters: Array.isArray(res.data.topExporters) ? res.data.topExporters : [],
      topInterfaces: Array.isArray(res.data.topInterfaces) ? res.data.topInterfaces : [],
      topVlans: Array.isArray(res.data.topVlans) ? res.data.topVlans : [],
      topConversations: Array.isArray(res.data.topConversations) ? res.data.topConversations : [],
      sankeyLinks: Array.isArray(res.data.sankeyLinks) ? res.data.sankeyLinks : [],
      flows: Array.isArray(res.data.flows) ? res.data.flows : [],
    };
  }
  return {
    daemonDown: true,
    timestamp: new Date().toISOString(),
    totalMatchedFlows: 0,
    totalBytes: 0,
    totalPackets: 0,
    avgBps: 0,
    uniqueSources: 0,
    uniqueDestinations: 0,
    seriesKeys: [],
    timeseries: [],
    topSources: [],
    topDestinations: [],
    topApps: [],
    topProtocols: [],
    topCountries: [],
    topAsns: [],
    topExporters: [],
    topInterfaces: [],
    topVlans: [],
    topConversations: [],
    sankeyLinks: [],
    flows: [],
    fqlError: res.kind === 'http_error' ? res.message : 'axonwalld daemon unreachable.',
  };
}

export async function getNetFlowExportersAction(): Promise<NetFlowExporterSnapshot[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{ exporters?: NetFlowExporterSnapshot[] }>('/v1/netflow/exporters', 'GET', undefined, 5_000);
  if (res.kind === 'ok' && Array.isArray(res.data?.exporters)) {
    return res.data.exporters;
  }
  return [];
}

export async function getNetFlowTemplatesAction(): Promise<NetFlowTemplateSnapshot[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{ templates?: NetFlowTemplateSnapshot[] }>('/v1/netflow/templates', 'GET', undefined, 5_000);
  if (res.kind === 'ok' && Array.isArray(res.data?.templates)) {
    return res.data.templates;
  }
  return [];
}

export async function getNetFlowAlertsAction(): Promise<NetFlowAlertSnapshot[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{ alerts?: NetFlowAlertSnapshot[] }>('/v1/netflow/alerts', 'GET', undefined, 5_000);
  if (res.kind === 'ok' && Array.isArray(res.data?.alerts)) {
    return res.data.alerts;
  }
  return [];
}

export async function ackNetFlowAlertAction(id: string): Promise<{ success: boolean }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{ success?: boolean }>('/v1/netflow/alerts/ack', 'POST', { id }, 5_000);
  return { success: res.kind === 'ok' && Boolean(res.data?.success) };
}

export async function injectNetFlowTestBurstAction(protocol = 'ipfix', count = 12): Promise<{ success: boolean; injected: number; error?: string }> {
  const session = await getSession();
  await enforceRateLimit(15, 60000);
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{ success?: boolean; injected?: number }>('/v1/netflow/test-inject', 'POST', { protocol, count }, 8_000);
  if (res.kind === 'ok' && res.data) {
    return { success: Boolean(res.data.success), injected: res.data.injected ?? 0 };
  }
  return {
    success: false,
    injected: 0,
    error: res.kind === 'http_error' ? res.message : 'axonwalld daemon unreachable.',
  };
}

export async function getNetFlowReportAction(options?: {
  rangeDays?: number;
  groupBy?: string;
  format?: 'json' | 'csv' | 'markdown';
}): Promise<NetFlowReportResponseSnapshot> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('netflow-collector');
  const qs = new URLSearchParams({
    rangeDays: String(options?.rangeDays ?? 7),
    groupBy: options?.groupBy ?? 'interface',
    format: options?.format ?? 'json',
  });
  const res = await callAgentApiDetailed<NetFlowReportResponseSnapshot>(`/v1/netflow/reports?${qs.toString()}`, 'GET', undefined, 8_000);
  if (res.kind === 'ok' && res.data) {
    return {
      ...res.data,
      daemonDown: false,
      rows: Array.isArray(res.data.rows) ? res.data.rows : [],
    };
  }
  return {
    daemonDown: true,
    generatedAt: new Date().toISOString(),
    rangeDays: options?.rangeDays ?? 7,
    startMs: 0,
    endMs: 0,
    groupBy: options?.groupBy ?? 'interface',
    bucketSeconds: 300,
    rows: [],
  };
}

export async function generateNetFlowReportAction(options?: {
  rangeDays?: number;
  groupBy?: string;
  format?: 'json' | 'csv' | 'markdown';
}): Promise<{ success: boolean; savedPath?: string; report?: NetFlowReportResponseSnapshot }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{ success?: boolean; savedPath?: string; report?: NetFlowReportResponseSnapshot }>(
    '/v1/netflow/reports/generate',
    'POST',
    {
      rangeDays: options?.rangeDays ?? 7,
      groupBy: options?.groupBy ?? 'interface',
      format: options?.format ?? 'markdown',
    },
    10_000,
  );
  if (res.kind === 'ok' && res.data) {
    return {
      success: Boolean(res.data.success),
      savedPath: res.data.savedPath,
      report: res.data.report,
    };
  }
  return { success: false };
}

export async function getNetFlowBaselinesAction(limit = 50): Promise<NetFlowBaselineSummarySnapshot[]> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{ entries?: NetFlowBaselineSummarySnapshot[] }>(
    `/v1/netflow/baselines?limit=${Math.max(1, limit)}`,
    'GET',
    undefined,
    5_000,
  );
  if (res.kind === 'ok' && Array.isArray(res.data?.entries)) {
    return res.data.entries;
  }
  return [];
}

export async function resetNetFlowBaselinesAction(): Promise<{ success: boolean }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{ success?: boolean }>('/v1/netflow/baselines', 'DELETE', undefined, 5_000);
  return { success: res.kind === 'ok' && Boolean(res.data?.success) };
}

export async function triggerNetFlowGeoIPUpdateAction(): Promise<{ success: boolean; error?: string }> {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{ success?: boolean; error?: string }>('/v1/netflow/geoip/update', 'POST', undefined, 50_000);
  if (res.kind === 'ok') {
    return { success: Boolean(res.data?.success), error: res.data?.error };
  }
  return {
    success: false,
    error: res.kind === 'http_error' ? res.message : 'axonwalld daemon unreachable.',
  };
}

export async function getObservabilityStatusAction(): Promise<{
  daemonDown: boolean;
  daemon?: Record<string, unknown> | null;
  error?: string;
}> {
  const session = await getSession();
  assertActionPermitted(session);
  const res = await callAgentApiDetailed<Record<string, unknown>>('/v1/observability/status', 'GET', undefined, 5_000);
  if (res.kind === 'ok') {
    return { daemonDown: false, daemon: res.data };
  }
  return {
    daemonDown: res.kind !== 'http_error',
    daemon: null,
    error: res.kind === 'http_error' ? res.message : 'axonwalld daemon unreachable.',
  };
}

export async function getNetFlowNodesAction(): Promise<
  Array<{ nodeId: string; nodeName: string; exporterIp: string; flowsCount: number; lastSeenMs: number }>
> {
  const session = await getSession();
  assertActionPermitted(session);
  await assertPluginEnabled('netflow-collector');
  const res = await callAgentApiDetailed<{
    nodes?: Array<{ nodeId: string; nodeName: string; exporterIp: string; flowsCount: number; lastSeenMs: number }>;
  }>('/v1/netflow/nodes', 'GET', undefined, 5_000);
  if (res.kind === 'ok' && Array.isArray(res.data?.nodes)) {
    return res.data.nodes;
  }
  return [];
}
