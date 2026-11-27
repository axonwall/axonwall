import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import crypto from 'node:crypto';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { dump as yamlDump } from 'js-yaml';
import {
  getVigilanteContainmentsDir,
  ensureVigilanteConfig,
  getHostEvidenceDir,
  loadConfig,
  resolvePathInside,
  assertDnsLabel
} from './config.js';
import { getClusterContextArgs, getKubeExecutionEnv } from './k8s.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { logger } from '../utils/logger.js';

export const PROTECTED_K8S_NAMESPACES = new Set([
  'kube-system',
  'kube-public',
  'kube-node-lease',
  'vigil-soc'
]);

const QUARANTINE_LABEL_KEY = 'vigilante.containment/id';
const K8S_LABEL_VALUE_REGEX = /^[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$/;
const DEFAULT_K8S_SERVICE_CIDRS = ['10.43.0.0/16'];

let soarTestOverrides = null;

/**
 * Configure deterministic network/routing/cluster sources or protected-IP test override
 * exclusively for automated tests.
 * @param {Object|null} overrides
 */
export function setSoarTestOverridesForTest(overrides = null) {
  soarTestOverrides = overrides ? { ...overrides } : null;
}

function generateContainmentId(prefix = 'cont') {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
}

function assertValidLabelValue(value, label = 'labelValue') {
  const str = String(value ?? '').trim();
  if (!str || !K8S_LABEL_VALUE_REGEX.test(str)) {
    throw new Error(`Invalid Kubernetes ${label} '${value}'`);
  }
  return str;
}

function parseIpv4ToInt(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    val = ((val << 8) | n) >>> 0;
  }
  return val;
}

function intToIpv4(v4) {
  return `${(v4 >>> 24) & 0xff}.${(v4 >>> 16) & 0xff}.${(v4 >>> 8) & 0xff}.${v4 & 0xff}`;
}

function parseIpv6ToBigInt(ip) {
  let clean = String(ip || '').replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  if (!clean) return null;

  if (clean.includes('.')) {
    const lastColon = clean.lastIndexOf(':');
    if (lastColon === -1) return null;
    const v4Int = parseIpv4ToInt(clean.slice(lastColon + 1));
    if (v4Int === null) return null;
    const hi = ((v4Int >>> 16) & 0xffff).toString(16);
    const lo = (v4Int & 0xffff).toString(16);
    clean = `${clean.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const halves = clean.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
  if (missing < 0 || (halves.length === 1 && left.length !== 8)) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;

  let val = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    val = (val << 16n) | BigInt(parseInt(g, 16));
  }
  return val;
}

function isIpv4InCidr(v4Int, cidr) {
  const [netIp, prefixStr] = String(cidr).split('/');
  const base = parseIpv4ToInt(netIp);
  const prefix = Number(prefixStr);
  if (base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (v4Int & mask) === (base & mask);
}

function isIpv6InCidr(v6Big, cidr) {
  const [netIp, prefixStr] = String(cidr).split('/');
  const base = parseIpv6ToBigInt(netIp);
  const prefix = Number(prefixStr);
  if (base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  if (prefix === 0) return true;
  const shift = BigInt(128 - prefix);
  return (v6Big >> shift) === (base >> shift);
}

function normalizeIpLiteral(rawIp) {
  if (rawIp === undefined || rawIp === null) return null;
  const trimmed = String(rawIp).trim();
  if (!trimmed) return null;
  const hasBrackets = trimmed.startsWith('[') && trimmed.endsWith(']');
  const unbracketed = hasBrackets ? trimmed.slice(1, -1) : trimmed;
  const clean = unbracketed.split('%')[0];
  const family = net.isIP(clean);
  if (family === 0) return null;
  if (hasBrackets && family !== 6) return null;
  return { ip: clean, family };
}

function unwrapEmbeddedIpv4FromV6(v6Big) {
  // ::ffff:0:0/96 (IPv4-mapped)
  if ((v6Big >> 32n) === 0xffffn) {
    return Number(v6Big & 0xffffffffn);
  }
  // ::/96 deprecated IPv4-compatible when non-unspecified/non-loopback
  if ((v6Big >> 32n) === 0n && v6Big > 1n) {
    return Number(v6Big & 0xffffffffn);
  }
  // 64:ff9b::/96 (NAT64 Well-Known Prefix)
  if ((v6Big >> 32n) === 0x0064ff9b0000000000000000n) {
    return Number(v6Big & 0xffffffffn);
  }
  // 64:ff9b:1::/48 (NAT64 local-use)
  if ((v6Big >> 80n) === 0x0064ff9b0001n) {
    return Number(v6Big & 0xffffffffn);
  }
  // 2002::/16 (6to4: bits 16..47 carry embedded IPv4)
  if ((v6Big >> 112n) === 0x2002n) {
    return Number((v6Big >> 80n) & 0xffffffffn);
  }
  return null;
}

function parseProcRouteHexIpv4(hexStr) {
  if (!/^[0-9a-fA-F]{8}$/.test(hexStr) || hexStr === '00000000') return null;
  const buf = Buffer.from(hexStr, 'hex');
  if (os.endianness() === 'LE') {
    buf.reverse();
  }
  return `${buf[0]}.${buf[1]}.${buf[2]}.${buf[3]}`;
}

function parseProcRouteHexIpv6(hexStr) {
  if (!/^[0-9a-fA-F]{32}$/.test(hexStr) || /^0{32}$/.test(hexStr)) return null;
  const groups = [];
  for (let i = 0; i < 32; i += 4) {
    groups.push(hexStr.slice(i, i + 4));
  }
  const big = parseIpv6ToBigInt(groups.join(':'));
  return big;
}

function collectDynamicProtectedTargets() {
  const v4Exact = new Set();
  const v6Exact = new Set();
  const cidrsV4 = new Set(DEFAULT_K8S_SERVICE_CIDRS);
  const cidrsV6 = new Set();

  const addCandidateIp = (candidate) => {
    const norm = normalizeIpLiteral(candidate);
    if (!norm) return;
    if (norm.family === 4) {
      const v4 = parseIpv4ToInt(norm.ip);
      if (v4 !== null) v4Exact.add(v4);
    } else if (norm.family === 6) {
      const v6 = parseIpv6ToBigInt(norm.ip);
      if (v6 !== null) v6Exact.add(v6);
    }
  };

  const addCandidateTarget = (target) => {
    if (!target || typeof target !== 'string') return;
    const trimmed = target.trim();
    if (!trimmed) return;
    if (trimmed.includes('/')) {
      const [baseIp] = trimmed.split('/');
      const fam = net.isIP(baseIp);
      if (fam === 4) cidrsV4.add(trimmed);
      else if (fam === 6) cidrsV6.add(trimmed);
      return;
    }
    addCandidateIp(trimmed);
  };

  // 1. Local host interface IPs and IPv4 subnet broadcast addresses
  try {
    const netIfacesFn = soarTestOverrides?.networkInterfacesFn || os.networkInterfaces;
    const ifaces = netIfacesFn();
    for (const entries of Object.values(ifaces || {})) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        if (!entry?.address) continue;
        addCandidateIp(entry.address);
        if (entry.family === 'IPv4' || net.isIP(entry.address) === 4) {
          const addrInt = parseIpv4ToInt(entry.address);
          const maskInt = entry.netmask ? parseIpv4ToInt(entry.netmask) : null;
          if (addrInt !== null && maskInt !== null && maskInt !== 0xffffffff && maskInt !== 0xfffffffe) {
            const bcastInt = ((addrInt & maskInt) | (~maskInt >>> 0)) >>> 0;
            v4Exact.add(bcastInt);
          }
        }
      }
    }
  } catch {
    // Best-effort interface enumeration
  }

  // 2. DNS resolvers from /etc/resolv.conf
  const resolvPath = soarTestOverrides?.resolvConfPath ?? '/etc/resolv.conf';
  try {
    if (resolvPath && fsSync.existsSync(resolvPath)) {
      const content = fsSync.readFileSync(resolvPath, 'utf8');
      for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.split(/[#;]/)[0].trim();
        const match = line.match(/^nameserver\s+(\S+)/i);
        if (match) addCandidateIp(match[1]);
      }
    }
  } catch {
    // Best-effort resolv.conf inspection
  }

  // 3. Default gateways / next-hop routers from /proc/net/route and /proc/net/ipv6_route
  const routePath = soarTestOverrides?.routePath ?? '/proc/net/route';
  try {
    if (routePath && fsSync.existsSync(routePath)) {
      const content = fsSync.readFileSync(routePath, 'utf8');
      const lines = content.split(/\r?\n/).slice(1);
      for (const line of lines) {
        const cols = line.trim().split(/\s+/);
        if (cols.length < 4) continue;
        const gwIp = parseProcRouteHexIpv4(cols[2]);
        if (gwIp) addCandidateIp(gwIp);
      }
    }
  } catch {
    // Best-effort route inspection
  }

  const ipv6RoutePath = soarTestOverrides?.ipv6RoutePath ?? '/proc/net/ipv6_route';
  try {
    if (ipv6RoutePath && fsSync.existsSync(ipv6RoutePath)) {
      const content = fsSync.readFileSync(ipv6RoutePath, 'utf8');
      for (const line of content.split(/\r?\n/)) {
        const cols = line.trim().split(/\s+/);
        if (cols.length < 5) continue;
        const gwV6 = parseProcRouteHexIpv6(cols[4]);
        if (gwV6 !== null) v6Exact.add(gwV6);
      }
    }
  } catch {
    // Best-effort IPv6 route inspection
  }

  // 4. Configured Kubernetes API, service, and cluster IPs / CIDRs
  const envMap = soarTestOverrides?.env || process.env;
  addCandidateTarget(envMap.KUBERNETES_SERVICE_HOST);
  addCandidateTarget(envMap.VIGILANTE_SERVICE_CIDR);
  addCandidateTarget(envMap.VIGILANTE_CLUSTER_CIDR);

  try {
    const cfg = loadConfig();
    addCandidateTarget(cfg?.defaults?.ip);
    addCandidateTarget(cfg?.k3s?.serviceCidr);
    addCandidateTarget(cfg?.k3s?.clusterIp);
    addCandidateTarget(cfg?.k3s?.apiServerIp);
  } catch {
    // Config may be uninitialized
  }

  const k8sConfigPath = soarTestOverrides?.k8sConfigPath ?? '/etc/axonwall/managed/k3s_config.json';
  try {
    if (k8sConfigPath && fsSync.existsSync(k8sConfigPath)) {
      const k3sMeta = JSON.parse(fsSync.readFileSync(k8sConfigPath, 'utf8'));
      addCandidateTarget(k3sMeta?.serviceCidr);
      addCandidateTarget(k3sMeta?.clusterDns);
      addCandidateTarget(k3sMeta?.apiServerIp);
      addCandidateTarget(k3sMeta?.apiserverIp);
      addCandidateTarget(k3sMeta?.nodeIp);
    }
  } catch {
    // Ignore unreadable k3s metadata
  }

  if (Array.isArray(soarTestOverrides?.configuredTargets)) {
    for (const target of soarTestOverrides.configuredTargets) {
      addCandidateTarget(target);
    }
  }

  return { v4Exact, v6Exact, cidrsV4, cidrsV6 };
}

function classifyProtectedIpv4Reason(v4Int, dynamicTargets) {
  const a = (v4Int >>> 24) & 0xff;
  const b = (v4Int >>> 16) & 0xff;
  if (a === 127) return 'loopback (127.0.0.0/8)';
  if (a === 0) return 'unspecified (0.0.0.0/8)';
  if (a === 169 && b === 254) return 'link-local/IMDS (169.254.0.0/16)';
  if (a >= 224 && a <= 239) return 'multicast (224.0.0.0/4)';
  if (a >= 240) return 'broadcast/reserved (240.0.0.0/4)';
  if (dynamicTargets.v4Exact.has(v4Int)) return 'protected host/gateway/DNS/cluster IP';
  for (const cidr of dynamicTargets.cidrsV4) {
    if (isIpv4InCidr(v4Int, cidr)) return `protected Kubernetes/service CIDR (${cidr})`;
  }
  return null;
}

function classifyProtectedIpv6Reason(v6Big, dynamicTargets) {
  if (v6Big === 1n) return 'loopback (::1)';
  if (v6Big === 0n) return 'unspecified (::)';
  if ((v6Big >> 118n) === 0x3fan) return 'link-local (fe80::/10)';
  if (v6Big === 0xfd000ec2000000000000000000000254n) return 'cloud IMDS (fd00:ec2::254)';
  if ((v6Big >> 120n) === 0xffn) return 'multicast (ff00::/8)';
  if (dynamicTargets.v6Exact.has(v6Big)) return 'protected host/gateway/DNS/cluster IP';
  for (const cidr of dynamicTargets.cidrsV6) {
    if (isIpv6InCidr(v6Big, cidr)) return `protected Kubernetes/service CIDR (${cidr})`;
  }
  const embeddedV4 = unwrapEmbeddedIpv4FromV6(v6Big);
  if (embeddedV4 !== null) {
    const v4Reason = classifyProtectedIpv4Reason(embeddedV4, dynamicTargets);
    if (v4Reason) return `IPv6-embedded ${intToIpv4(embeddedV4)} (${v4Reason})`;
  }
  return null;
}

/**
 * Validate and canonicalize an IP address for SOAR blackhole containment,
 * rejecting empty/malformed values and protected infrastructure IPs.
 * @param {string} rawIp
 * @returns {string} Canonical IP address string
 */
export function assertSafeBlockTargetIp(rawIp) {
  const norm = normalizeIpLiteral(rawIp);
  if (!norm) {
    throw new Error(`Invalid IP address '${rawIp ?? ''}'`);
  }

  if (soarTestOverrides?.allowProtectedIps === true) {
    return norm.ip;
  }

  const dynamicTargets = collectDynamicProtectedTargets();
  if (norm.family === 4) {
    const v4 = parseIpv4ToInt(norm.ip);
    const reason = classifyProtectedIpv4Reason(v4, dynamicTargets);
    if (reason) {
      throw new Error(`Refusing SOAR IP block on protected infrastructure address '${norm.ip}': ${reason}`);
    }
  } else if (norm.family === 6) {
    const v6 = parseIpv6ToBigInt(norm.ip);
    const reason = classifyProtectedIpv6Reason(v6, dynamicTargets);
    if (reason) {
      throw new Error(`Refusing SOAR IP block on protected infrastructure address '${norm.ip}': ${reason}`);
    }
  }

  return norm.ip;
}

function buildQuarantinePolicyName(podName) {
  const base = `quarantine-${podName}`;
  if (base.length <= 63) return base;
  const suffix = crypto.createHash('sha256').update(podName).digest('hex').slice(0, 8);
  const head = podName.slice(0, 63 - 'quarantine-'.length - 1 - suffix.length).replace(/-+$/, '');
  return `quarantine-${head || 'pod'}-${suffix}`;
}

function resolveSoarPodTarget(arg1, arg2 = 'default', arg3 = {}) {
  let rawPod;
  let rawNs = 'default';
  let options = {};

  if (typeof arg1 === 'object' && arg1 !== null) {
    rawPod = arg1.podName ?? arg1.name;
    rawNs = arg1.namespace || 'default';
    options = arg1;
  } else {
    rawPod = arg1;
    rawNs = typeof arg2 === 'string' && arg2.trim() ? arg2.trim() : 'default';
    options = typeof arg3 === 'object' && arg3 !== null ? arg3 : {};
  }

  if (typeof rawPod !== 'string' || !rawPod.trim()) {
    throw new Error('Invalid podName: pod name is required');
  }

  const podName = assertDnsLabel(rawPod.trim(), 'podName');
  const namespace = assertDnsLabel(rawNs, 'namespace');
  return { podName, namespace, options };
}

function assertSafeIsolationNamespace(namespace) {
  if (PROTECTED_K8S_NAMESPACES.has(namespace)) {
    throw new Error(`Refusing SOAR isolation in protected Kubernetes namespace '${namespace}'`);
  }
}

/**
 * Generate Kubernetes NetworkPolicy manifest to completely air-gap a single pod
 * via a unique per-containment quarantine label selector.
 * Accepts either (podName, namespace, options) or ({ podName, namespace, ... })
 * @returns {string} NetworkPolicy YAML string
 */
export function generateQuarantineNetworkPolicy(arg1, arg2 = 'default', arg3 = {}) {
  const { podName, namespace, options } = resolveSoarPodTarget(arg1, arg2, arg3);
  assertSafeIsolationNamespace(namespace);
  const policyName = buildQuarantinePolicyName(podName);
  const containmentId = assertValidLabelValue(
    options.containmentId || generateContainmentId('cont'),
    'containmentId'
  );
  const matchLabels = { [QUARANTINE_LABEL_KEY]: containmentId };

  const manifest = {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: policyName,
      namespace,
      labels: {
        'vigilante.containment/quarantine': 'true',
        [QUARANTINE_LABEL_KEY]: containmentId,
        'vigilante.containment/target-pod': String(podName).slice(0, 63).replace(/-+$/, ''),
        'app.kubernetes.io/managed-by': 'vigilante-soar'
      },
      annotations: {
        'vigilante.io/quarantine-reason': options.reason || 'Active Threat Containment',
        'vigilante.io/isolated-at': new Date().toISOString()
      }
    },
    spec: {
      podSelector: {
        matchLabels
      },
      policyTypes: ['Ingress', 'Egress'],
      ingress: [],
      egress: []
    }
  };

  const yaml = yamlDump(manifest);
  return yaml;
}

/**
 * Isolate a single Kubernetes pod by stamping a unique quarantine label on that pod
 * and applying a strict air-gap NetworkPolicy targeting strictly that label.
 * Accepts ({ podName, namespace, reason }) or (podName, namespace, options)
 * @returns {Promise<Object>} Containment record
 */
export async function isolatePod(arg1, arg2 = 'default', arg3 = {}) {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  const { podName, namespace, options } = resolveSoarPodTarget(arg1, arg2, arg3);
  assertSafeIsolationNamespace(namespace);

  const policyName = buildQuarantinePolicyName(podName);
  const containmentId = generateContainmentId('cont');
  const kubeEnv = getKubeExecutionEnv();
  const ctxArgs = options.apply !== false
    ? await getClusterContextArgs(options.clusterName || 'vigilante-dev', options.clusterProvider || null)
    : [];

  const manifestYaml = generateQuarantineNetworkPolicy(podName, namespace, {
    ...options,
    containmentId
  });

  const record = {
    id: containmentId,
    containmentId,
    type: 'NETWORK_ISOLATION',
    target: podName,
    namespace,
    clusterName: options.clusterName || 'vigilante-dev',
    policyName,
    quarantineLabel: `${QUARANTINE_LABEL_KEY}=${containmentId}`,
    policyYaml: manifestYaml,
    active: options.apply === false,
    status: options.apply === false ? 'STAGED' : 'PENDING',
    isolatedAt: new Date().toISOString(),
    reason: options.reason || 'Active Threat Containment',
    appliedToCluster: false
  };

  // Stamp unique per-pod quarantine label, then apply NetworkPolicy; fail closed on any error.
  if (options.apply !== false) {
    let podLabeled = false;
    try {
      await execa(
        'kubectl',
        [...ctxArgs, 'label', 'pod', podName, '-n', namespace, `${QUARANTINE_LABEL_KEY}=${containmentId}`, '--overwrite'],
        { timeout: 5000, env: kubeEnv }
      );
      podLabeled = true;

      await execa('kubectl', [...ctxArgs, 'apply', '-f', '-'], {
        input: manifestYaml,
        timeout: 5000,
        env: kubeEnv
      });
      record.appliedToCluster = true;
      record.active = true;
      record.status = 'ACTIVE';
      logger.info('SOAR', `Applied isolation NetworkPolicy ${record.policyName} in ${namespace} (${record.quarantineLabel})`);
    } catch (err) {
      if (podLabeled) {
        await execa(
          'kubectl',
          [...ctxArgs, 'label', 'pod', podName, '-n', namespace, `${QUARANTINE_LABEL_KEY}-`],
          { timeout: 5000, env: kubeEnv }
        ).catch(() => {});
      }
      record.appliedToCluster = false;
      record.active = false;
      record.status = 'FAILED';
      record.error = err.message;
      const failedFile = resolvePathInside(containmentsDir, `${containmentId}.json`);
      await fs.writeFile(failedFile, JSON.stringify(record, null, 2), 'utf8').catch(() => {});
      throw new Error(`SOAR pod isolation failed closed for ${namespace}/${podName}: ${err.message}`);
    }
  }

  // Persist containment record
  const recordFile = resolvePathInside(containmentsDir, `${containmentId}.json`);
  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');

  // Save signed evidence
  try {
    await saveEvidenceFile('containments', namespace, `${containmentId}.json`, JSON.stringify(record, null, 2));
    await autoSignIfConfigured(path.join(getHostEvidenceDir('containments', namespace), `${containmentId}.json`));
  } catch (evErr) {
    logger.warn('SOAR', `Failed to sign containment evidence: ${evErr.message}`);
  }

  return record;
}

/**
 * Freeze a pod or container execution while preserving memory
 * Accepts ({ podName, namespace, reason }) or (podName, namespace, options)
 * @returns {Promise<Object>}
 */
export async function freezePod(arg1, arg2 = 'default', arg3 = {}) {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  const { podName, namespace, options } = resolveSoarPodTarget(arg1, arg2, arg3);
  assertSafeIsolationNamespace(namespace);

  const containmentId = generateContainmentId('cont-freeze');
  const record = {
    id: containmentId,
    containmentId,
    type: 'CONTAINER_FREEZE',
    target: podName,
    namespace,
    active: true,
    status: 'FROZEN',
    frozenAt: new Date().toISOString(),
    reason: options.reason || 'Cryptominer / High Severity Malicious Execution',
    appliedToCluster: false
  };

  const recordFile = resolvePathInside(containmentsDir, `${containmentId}.json`);
  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');
  return record;
}

async function postToAxonwalldAgentSocket(apiPath, bodyObj) {
  const sockPath = process.env.AXONWALL_AGENT_API_SOCK || '/run/axonwall/agent-api.sock';
  if (!fsSync.existsSync(sockPath)) {
    return { socketPresent: false, status: 0, data: {} };
  }
  const httpMod = await import('node:http');
  let agentToken = process.env.AXONWALL_AGENT_TOKEN || '';
  if (!agentToken) {
    for (const p of ['/etc/axonwall/agent.token', '/var/lib/axonwall/etc-axonwall/agent.token']) {
      if (fsSync.existsSync(p)) {
        agentToken = fsSync.readFileSync(p, 'utf8').trim();
        if (agentToken) break;
      }
    }
  }
  const payload = JSON.stringify(bodyObj);
  const resp = await new Promise((resolve, reject) => {
    const req = httpMod.request(
      {
        socketPath: sockPath,
        path: apiPath,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          ...(agentToken ? { 'X-Axonwall-Agent-Token': agentToken } : {})
        },
        timeout: 5000
      },
      (res) => {
        let body = '';
        res.on('data', (c) => { body += c.toString(); });
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(body || '{}') });
          } catch {
            resolve({ status: res.statusCode, data: {} });
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('Axonwalld socket request timed out')));
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
  return { socketPresent: true, ...resp };
}

/**
 * Apply local firewall or Kubernetes egress block on a malicious IP address
 * Accepts ({ ip, reason }) or (ip, options)
 * @returns {Promise<Object>}
 */
export async function blockIp(arg1, arg2 = {}) {
  let rawIp;
  let options = {};

  if (typeof arg1 === 'object' && arg1 !== null) {
    rawIp = arg1.ip ?? arg1.target;
    options = arg1;
  } else {
    rawIp = arg1;
    options = typeof arg2 === 'object' && arg2 !== null ? arg2 : {};
  }

  const ipAddress = assertSafeBlockTargetIp(rawIp);

  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  const containmentId = generateContainmentId('cont-ip');
  const reasonStr = options.reason || 'Malicious C2 / Port Scan Source';
  const record = {
    id: containmentId,
    containmentId,
    type: 'IP_BLOCK',
    target: ipAddress,
    active: true,
    status: 'BLOCKED',
    blockedAt: new Date().toISOString(),
    reason: reasonStr,
    iptablesRule: `nft add element inet axonwall_mcp blackhole { ${ipAddress} }`,
    mcpLeaseId: null,
    enforcedInKernel: false
  };

  // If running on an Axonwall appliance, enforce in the kernel via axonwalld /v1/mcp/blackhole
  try {
    const daemonResp = await postToAxonwalldAgentSocket('/v1/mcp/blackhole', {
      target: ipAddress,
      mode: 'nft_drop',
      direction: 'both',
      protocol: 'any',
      killActiveConnections: true,
      ttlSeconds: Number(options.ttlSeconds) || 3600,
      keyId: 'vigilante-soar-local',
      keyName: 'Vigilante SOAR Engine',
      audit: {
        reason: reasonStr.length >= 10 ? reasonStr : `Vigilante SOAR: ${reasonStr}`
      }
    });
    if (daemonResp.socketPresent) {
      if (daemonResp.status === 200 && daemonResp.data?.lease?.id) {
        record.mcpLeaseId = daemonResp.data.lease.id;
        record.enforcedInKernel = true;
      } else if (daemonResp.data?.error) {
        record.kernelGuardNotice = daemonResp.data.error;
      }
    }
  } catch (err) {
    logger.warn('SOAR', `Could not enforce IP block via axonwalld socket: ${err.message}`);
  }

  const recordFile = resolvePathInside(containmentsDir, `${containmentId}.json`);
  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');
  return record;
}

/**
 * Generate remediation action to quarantine or disable a compromised account
 * Accepts ({ accountName, namespace, reason }) or (accountName, namespace, options)
 * @returns {Promise<Object>}
 */
export async function quarantineAccount(arg1, arg2 = 'default', arg3 = {}) {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  let accountName;
  let namespace = 'default';
  let options = {};

  if (typeof arg1 === 'object' && arg1 !== null) {
    accountName = arg1.accountName || arg1.username || 'target-account';
    namespace = arg1.namespace || arg1.domain || 'default';
    options = arg1;
  } else {
    accountName = arg1 || 'target-account';
    namespace = typeof arg2 === 'string' ? arg2 : 'default';
    options = typeof arg3 === 'object' && arg3 !== null ? arg3 : {};
  }

  const containmentId = generateContainmentId('cont-acct');
  const record = {
    id: containmentId,
    containmentId,
    type: 'ACCOUNT_QUARANTINE',
    target: accountName,
    namespace,
    active: true,
    status: 'REVOKED',
    revokedAt: new Date().toISOString(),
    reason: options.reason || 'Compromised Token / Lateral Movement Credentials'
  };

  const recordFile = resolvePathInside(containmentsDir, `${containmentId}.json`);
  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');
  return record;
}

/**
 * List all active and historical containment actions
 * @returns {Promise<Array<Object>>}
 */
export async function listActiveContainments() {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  try {
    const files = await fs.readdir(containmentsDir);
    const records = [];
    for (const f of files) {
      if (f.endsWith('.json')) {
        try {
          const raw = await fs.readFile(path.join(containmentsDir, f), 'utf8');
          const parsed = JSON.parse(raw);
          if (parsed.active !== false && parsed.status !== 'RELEASED') {
            parsed.active = true;
          }
          records.push(parsed);
        } catch {
          // ignore corrupted file
        }
      }
    }
    return records.sort((a, b) => new Date(b.isolatedAt || b.blockedAt || 0) - new Date(a.isolatedAt || a.blockedAt || 0));
  } catch (err) {
    logger.warn('SOAR', `Failed to list containments: ${err.message}`);
    return [];
  }
}

/**
 * Release an active containment (rollback NetworkPolicy or unblock)
 * @param {string} containmentId
 * @returns {Promise<Object>}
 */
export async function releaseContainment(containmentId) {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();
  // The record file must stay inside the containments directory: an id with
  // '../' would otherwise read, weaponize (kubectl delete from file values),
  // and overwrite an arbitrary JSON file. Legitimate ids are 'cont-…' slugs.
  const recordFile = resolvePathInside(containmentsDir, `${containmentId}.json`);

  if (!fsSync.existsSync(recordFile)) {
    throw new Error(`Containment record '${containmentId}' not found.`);
  }

  const raw = await fs.readFile(recordFile, 'utf8');
  const record = JSON.parse(raw);

  if (record.policyName && record.namespace) {
    try {
      const safePolicy = assertDnsLabel(record.policyName, 'policyName');
      const safeNs = assertDnsLabel(record.namespace, 'namespace');
      const kubeEnv = getKubeExecutionEnv();
      const ctxArgs = await getClusterContextArgs(record.clusterName || 'vigilante-dev');
      await execa('kubectl', [...ctxArgs, 'delete', 'networkpolicy', safePolicy, '-n', safeNs], {
        timeout: 5000,
        env: kubeEnv
      });
      if (record.type === 'NETWORK_ISOLATION' && record.target) {
        const safePod = assertDnsLabel(record.target, 'podName');
        await execa(
          'kubectl',
          [...ctxArgs, 'label', 'pod', safePod, '-n', safeNs, `${QUARANTINE_LABEL_KEY}-`],
          { timeout: 5000, env: kubeEnv }
        ).catch(() => {});
      }
      logger.info('SOAR', `Removed isolation NetworkPolicy ${safePolicy}`);
    } catch (err) {
      logger.warn('SOAR', `Could not delete NetworkPolicy: ${err.message}`);
    }
  }

  if (record.mcpLeaseId) {
    const sockPath = process.env.AXONWALL_AGENT_API_SOCK || '/run/axonwall/agent-api.sock';
    const revertResp = await postToAxonwalldAgentSocket('/v1/mcp/revert', { leaseId: record.mcpLeaseId });
    if (!revertResp.socketPresent) {
      throw new Error(`Cannot revert MCP blackhole lease '${record.mcpLeaseId}': axonwalld socket not found at ${sockPath}`);
    }
    if (revertResp.status !== 200 || revertResp.data?.success !== true) {
      throw new Error(
        `Failed to revert MCP lease '${record.mcpLeaseId}' via axonwalld: HTTP ${revertResp.status}${revertResp.data?.error ? ` (${revertResp.data.error})` : ''}`
      );
    }
    record.enforcedInKernel = false;
  }

  record.status = 'RELEASED';
  record.active = false;
  record.releasedAt = new Date().toISOString();

  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');
  return { success: true, record };
}
