#!/usr/bin/env node
import React, { useState, useEffect, useCallback } from 'react';
import { render, Box, Text, useApp, useInput } from 'ink';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as http from 'node:http';
import * as crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  AXONWALL_YAML_FILENAMES,
  parseDesiredStateFromYamlFiles,
  serializeDesiredStateToYamlFiles,
} from '@axonwall/lib/yaml';
import { compileNftables } from '@axonwall/lib/compile/nft';
import {
  BUILTIN_PLUGINS,
  CORE_ROLE_PLUGIN_IDS,
  isPluginEnabled,
  resolveCapabilities,
  enablePluginWithDependencies,
  disablePluginWithDependents,
} from '@axonwall/lib';
import { getMcpServerStatus, resolveMcpSettingsPath } from '@axonwall/lib/mcp';
import { acquireMcpLockFile, desiredStateLockPath } from './mcp/lockfile.js';
import type { DesiredState } from '@axonwall/lib/schemas';
import { App as NastyMapApp } from './tui/nastymap/App.js';

const ETC_CONFIG_DIR = process.env.AXONWALL_CONFIG_DIR || '/etc/axonwall';
const VAR_ETC_CONFIG_DIR = process.env.AXONWALL_PERSIST_YAML_DIR || '/var/lib/axonwall/etc-axonwall';
const STATE_JSON_PATH = process.env.AXONWALL_STATE_FILE || '/var/lib/axonwall/state.json';
const AGENT_API_SOCKET =
  process.env.AXONWALL_AGENT_API_SOCK || process.env.AGENT_API_SOCKET || '/run/axonwall/agent-api.sock';
const AGENT_TOKEN_PATH = process.env.AXONWALL_AGENT_TOKEN_FILE || '/etc/axonwall/agent.token';

export type TopTab =
  | 'dashboard'
  | 'interfaces'
  | 'firewall'
  | 'routing'
  | 'services'
  | 'storage'
  | 'compute'
  | 'plugins'
  | 'nastymap'
  | 'updates'
  | 'cli_ops';

function detectLocalInstallMode(): 'zbm' | 'rolling' | 'ab' {
  for (const p of [path.join(ETC_CONFIG_DIR, 'install-mode'), '/var/lib/axonwall/install-mode']) {
    try {
      if (fs.existsSync(p)) {
        const raw = fs.readFileSync(p, 'utf-8').trim().toLowerCase();
        if (raw.includes('zbm') || raw.includes('zfs')) return 'zbm';
        if (raw.includes('rolling')) return 'rolling';
        if (raw.includes('ab')) return 'ab';
      }
    } catch {}
  }
  try {
    if (fs.existsSync('/proc/mounts')) {
      const mounts = fs.readFileSync('/proc/mounts', 'utf-8');
      for (const line of mounts.split('\n')) {
        const parts = line.split(' ');
        if (parts[1] === '/' && parts[2] === 'zfs') {
          return 'zbm';
        }
      }
    }
  } catch {}
  return 'ab';
}

function getTopTabs(installMode: string): Array<{ id: TopTab; key: string; label: string }> {
  const updatesLabel =
    installMode === 'zbm'
      ? 'ZFS Boot Env'
      : installMode === 'rolling'
        ? 'Rolling Updates'
        : 'A/B Updates';
  return [
    { id: 'dashboard', key: '1', label: 'Dashboard' },
    { id: 'interfaces', key: '2', label: 'Interfaces' },
    { id: 'firewall', key: '3', label: 'Firewall & NAT' },
    { id: 'routing', key: '4', label: 'Routing & FRR' },
    { id: 'services', key: '5', label: 'Services & VPN' },
    { id: 'storage', key: '6', label: 'ZFS Storage' },
    { id: 'compute', key: '7', label: 'K3s, Virt & SOC' },
    { id: 'plugins', key: '8', label: 'Plugins & Shell' },
    { id: 'nastymap', key: '9', label: 'NastyMap' },
    { id: 'updates', key: 'u', label: updatesLabel },
    { id: 'cli_ops', key: '0', label: 'System & Ops' },
  ];
}

export function getViewportSlice<T>(
  items: T[],
  cursorIdx: number,
  maxRows = 13
): { slice: T[]; startIndex: number; activeIndex: number } {
  if (items.length === 0) {
    return { slice: [], startIndex: 0, activeIndex: 0 };
  }
  const activeIndex = ((cursorIdx % items.length) + items.length) % items.length;
  if (items.length <= maxRows) {
    return { slice: items, startIndex: 0, activeIndex };
  }
  const half = Math.floor(maxRows / 2);
  let startIndex = Math.max(0, activeIndex - half);
  if (startIndex + maxRows > items.length) {
    startIndex = Math.max(0, items.length - maxRows);
  }
  return {
    slice: items.slice(startIndex, startIndex + maxRows),
    startIndex,
    activeIndex,
  };
}

function readLayeredYamlMap(): Record<string, string> {
  const files: Record<string, string> = {};
  for (const filename of AXONWALL_YAML_FILENAMES) {
    const etcPath = path.join(ETC_CONFIG_DIR, filename);
    const varPath = path.join(VAR_ETC_CONFIG_DIR, filename);
    let etcMtime = -1;
    let varMtime = -1;
    try {
      if (fs.existsSync(etcPath)) {
        etcMtime = fs.statSync(etcPath).mtimeMs;
      }
    } catch {}
    try {
      if (fs.existsSync(varPath)) {
        varMtime = fs.statSync(varPath).mtimeMs;
      }
    } catch {}

    const candidates =
      etcMtime >= 0 && varMtime >= 0
        ? etcMtime >= varMtime
          ? [etcPath, varPath]
          : [varPath, etcPath]
        : etcMtime >= 0
          ? [etcPath]
          : varMtime >= 0
            ? [varPath]
            : [];

    for (const cand of candidates) {
      try {
        files[filename] = fs.readFileSync(cand, 'utf-8');
        break;
      } catch {}
    }
  }
  return files;
}

function loadCurrentState(): DesiredState {
  const files = readLayeredYamlMap();
  let base: Partial<DesiredState> | undefined;
  for (const stPath of [STATE_JSON_PATH, path.join(ETC_CONFIG_DIR, 'state.json')]) {
    try {
      if (fs.existsSync(stPath)) {
        base = JSON.parse(fs.readFileSync(stPath, 'utf-8'));
        break;
      }
    } catch {}
  }
  if (Object.keys(files).length > 0) {
    try {
      return parseDesiredStateFromYamlFiles(files, base);
    } catch {}
  }
  if (base) {
    try {
      return parseDesiredStateFromYamlFiles({}, base);
    } catch {}
  }
  return parseDesiredStateFromYamlFiles({});
}

// B2-M5: snapshot/restore for the on-disk config
// handleApplyConfig overwrites (see the CLI twin in
// axonwallctl.ts). The snapshot maps every path saveStateToDisk
// writes to its previous contents, or null when the path did not
// exist, so a daemon rejection can put disk back exactly as it was.
type TuiConfigSnapshot = Map<string, Buffer | null>;

function snapshotTuiConfigFiles(state: DesiredState): TuiConfigSnapshot {
  const snap: TuiConfigSnapshot = new Map();
  const paths: string[] = [];
  const serialized = serializeDesiredStateToYamlFiles(state);
  for (const dir of [VAR_ETC_CONFIG_DIR, ETC_CONFIG_DIR]) {
    for (const fn of Object.keys(serialized)) paths.push(path.join(dir, fn));
    paths.push(path.join(dir, 'conf.d', '99-cloudinit.yaml'));
  }
  for (const jsonTarget of [STATE_JSON_PATH, path.join(VAR_ETC_CONFIG_DIR, 'state.json'), path.join(ETC_CONFIG_DIR, 'state.json')]) {
    paths.push(jsonTarget);
  }
  for (const p of paths) {
    try {
      snap.set(p, fs.existsSync(p) ? fs.readFileSync(p) : null);
    } catch {
      snap.set(p, null);
    }
  }
  return snap;
}

function restoreTuiConfigSnapshot(snap: TuiConfigSnapshot): void {
  for (const [p, content] of snap.entries()) {
    try {
      if (content === null) {
        fs.rmSync(p, { force: true });
      } else {
        fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o775 });
        fs.writeFileSync(p, content, { encoding: 'utf-8', mode: 0o660 });
      }
    } catch {}
  }
}

// B2-M4 follow-up: the B2-M5 restore is itself a full-state disk
// write, so it takes the same lock — a restore that lands while an
// MCP propose (or a CLI apply) is persisting would clobber that
// writer's rule exactly like the original race. Returns false when
// the lock could not be acquired, in which case the caller must
// NOT claim the restore happened.
function restoreTuiConfigSnapshotLocked(snap: TuiConfigSnapshot): boolean {
  let release: (() => void) | null = null;
  try {
    try {
      release = acquireMcpLockFile(desiredStateLockPath(), TUI_STATE_LOCK_TIMEOUT_MS);
    } catch {
      return false;
    }
    restoreTuiConfigSnapshot(snap);
    return true;
  } finally {
    release?.();
  }
}

// B2-M4 follow-up: how long a TUI save waits for the DesiredState
// lock. The lock is normally held for milliseconds (a synchronous
// disk write), so 2 s is ample; longer would freeze the interactive
// UI on a stale lock, and a crashed holder's lock is broken by the
// dead-pid check immediately anyway.
const TUI_STATE_LOCK_TIMEOUT_MS = 2000;

// B2-M4 follow-up: every TUI disk save — the apply path and every
// in-place toggle/edit handler below — funnels through here, and
// the whole read -> mutate -> persist window now holds the SAME
// lockfile the MCP propose_firewall_rule path uses
// (acquireMcpLockFile/desiredStateLockPath), so a propose racing a
// TUI save serializes instead of interleaving full-state writes
// and losing one side's rules. The B2-M5 snapshot is taken inside
// the same acquisition, so the snapshot and the write it guards
// cannot be split by a concurrent writer. The lock is released
// before the caller talks to the daemon: the apply is a network
// round-trip that can outlast the lockfile's stale threshold, and
// holding the lock across it would let a concurrent writer break
// it as stale and re-admit the race. Returns null when the lock
// could not be acquired — nothing was written, and the caller must
// report that instead of claiming a save. (Callers that ignore the
// return keep their in-memory edit; the next save retries.)
// Exported for tests: the TUI module only renders on direct
// execution (isDirectExecution), so importing it in a test is
// inert and this is the only way to drive a save without an Ink UI.
export function saveStateToDisk(state: DesiredState): { daemonFiles: Record<string, string>; snapshot: TuiConfigSnapshot } | null {
  let release: (() => void) | null = null;
  try {
    try {
      release = acquireMcpLockFile(desiredStateLockPath(), TUI_STATE_LOCK_TIMEOUT_MS);
    } catch {
      return null;
    }
    const snapshot = snapshotTuiConfigFiles(state);
    const serialized = serializeDesiredStateToYamlFiles(state);
    const daemonFiles: Record<string, string> = {};
    for (const [fn, content] of Object.entries(serialized)) {
      daemonFiles[path.join(ETC_CONFIG_DIR, fn)] = content;
      daemonFiles[path.join(VAR_ETC_CONFIG_DIR, fn)] = content;
    }
    for (const dir of [VAR_ETC_CONFIG_DIR, ETC_CONFIG_DIR]) {
      try {
        fs.mkdirSync(dir, { recursive: true, mode: 0o775 });
        for (const [fn, content] of Object.entries(serialized)) {
          const filePath = path.join(dir, fn);
          fs.writeFileSync(filePath, content, { encoding: 'utf-8', mode: 0o660 });
          try {
            fs.chmodSync(filePath, 0o660);
          } catch {}
        }
        const ciOverride = path.join(dir, 'conf.d', '99-cloudinit.yaml');
        if (fs.existsSync(ciOverride)) {
          fs.rmSync(ciOverride, { force: true });
        }
      } catch {}
    }
    const serializedJson = JSON.stringify(state, null, 2);
    for (const jsonTarget of [STATE_JSON_PATH, path.join(VAR_ETC_CONFIG_DIR, 'state.json'), path.join(ETC_CONFIG_DIR, 'state.json')]) {
      try {
        fs.mkdirSync(path.dirname(jsonTarget), { recursive: true, mode: 0o775 });
        fs.writeFileSync(jsonTarget, serializedJson, { encoding: 'utf-8', mode: 0o660 });
        try {
          fs.chmodSync(jsonTarget, 0o660);
        } catch {}
      } catch {}
    }
    return { daemonFiles, snapshot };
  } finally {
    release?.();
  }
}

// B2-M6: callDaemon used to resolve `null` for every failure —
// socket missing, request error, timeout, and non-JSON 2xx alike
// — so callers could not tell a daemon rejection from an outage
// and handleApplyConfig reported an offline apply as rejected
// (and vice versa). Failures now carry a typed errorKind; the
// offline/malformed cases still resolve (they are not throws),
// but the caller can tell them apart from a real rejection.
export type DaemonErrorKind = 'offline' | 'timeout' | 'malformed' | 'daemon-error';
export interface DaemonErrorResponse {
  success: false;
  errorKind: DaemonErrorKind;
  error: string;
  message: string;
}

function daemonErrorResponse(errorKind: DaemonErrorKind, error: string): DaemonErrorResponse {
  return { success: false, errorKind, error, message: error };
}

function callDaemon(
  endpoint: string,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  payload?: unknown,
  timeoutMs = 8000
): Promise<any> {
  return new Promise((resolve) => {
    if (!fs.existsSync(AGENT_API_SOCKET)) {
      resolve(daemonErrorResponse('offline', 'Daemon socket not available'));
      return;
    }
    const body = payload ? JSON.stringify(payload) : '';
    let token = process.env.AXONWALL_AGENT_TOKEN || '';
    if (!token) {
      for (const candidate of [
        AGENT_TOKEN_PATH,
        '/var/lib/axonwall/etc-axonwall/agent.token',
        '/run/axonwall/agent.token',
      ]) {
        try {
          if (fs.existsSync(candidate)) {
            token = fs.readFileSync(candidate, 'utf-8').trim();
            if (token) break;
          }
        } catch {}
      }
    }

    const req = http.request(
      {
        socketPath: AGENT_API_SOCKET,
        path: endpoint,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
          ...(token ? { 'X-Axonwall-Agent-Token': token, Authorization: `Bearer ${token}` } : {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          const status = res.statusCode || 500;
          if (status < 200 || status >= 300) {
            try {
              const parsed = JSON.parse(data);
              resolve({
                success: false,
                errorKind: 'daemon-error',
                error: parsed.error || parsed.message || `HTTP ${status}`,
                message: parsed.message || parsed.error || `HTTP ${status}`,
              });
            } catch {
              resolve({
                success: false,
                errorKind: 'daemon-error',
                error: data.trim() || `HTTP ${status}`,
                message: data.trim() || `HTTP ${status}`,
              });
            }
            return;
          }
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(daemonErrorResponse('malformed', 'Daemon returned a non-JSON response'));
          }
        });
      }
    );
    req.on('error', (err: any) => resolve(daemonErrorResponse('offline', `Daemon unreachable: ${err?.message || 'request failed'}`)));
    req.on('timeout', () => {
      req.destroy();
      resolve(daemonErrorResponse('timeout', `Daemon request timed out after ${timeoutMs}ms`));
    });
    if (body) req.write(body);
    req.end();
  });
}

function detectApplianceSubnets(state: DesiredState): Array<{ role: string; cidr: string; device: string }> {
  const list: Array<{ role: string; cidr: string; device: string }> = [];
  const seen = new Set<string>();

  for (const iface of state.interfaces || []) {
    if (iface.ipv4Address) {
      const [ip = '192.168.1.1', prefix = '24'] = iface.ipv4Address.split('/');
      const parts = ip.split('.');
      const cidr = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/${prefix}` : iface.ipv4Address;
      if (!seen.has(cidr)) {
        seen.add(cidr);
        list.push({ role: iface.name.toUpperCase(), cidr, device: iface.device });
      }
    }
  }

  for (const route of state.routes || []) {
    if (route.enabled !== false && route.network && !seen.has(route.network)) {
      seen.add(route.network);
      list.push({
        role: `ROUTE${route.description ? `:${route.description}` : ''}`,
        cidr: route.network,
        device: route.interface || 'eth0',
      });
    }
  }

  const osIfaces = os.networkInterfaces();
  for (const [ifName, addrs] of Object.entries(osIfaces)) {
    if (!addrs || ifName === 'lo') continue;
    for (const a of addrs) {
      if ((a.family === 'IPv4' || (a as any).family === 4) && !a.internal) {
        const parts = a.address.split('.');
        const cidr = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
        if (!seen.has(cidr)) {
          seen.add(cidr);
          list.push({ role: ifName.toUpperCase(), cidr, device: ifName });
        }
      }
    }
  }

  if (list.length === 0) {
    list.push({ role: 'LAN', cidr: '192.168.1.0/24', device: 'eth1' });
  }
  return list;
}

function execSafe(bin: string, args: string[]): string {
  try {
    return execFileSync(bin, args, { encoding: 'utf-8', timeout: 4000, maxBuffer: 1024 * 1024 }).trim();
  } catch {
    return '';
  }
}

interface InlinePrompt {
  title: string;
  placeholder: string;
  value: string;
  onSubmit: (val: string) => void;
}

export function AxonwallTuiApp({
  initialTab = 'dashboard',
  readOnly = false,
}: {
  initialTab?: TopTab;
  readOnly?: boolean;
}) {
  const { exit } = useApp();
  const [activeTab, setActiveTab] = useState<TopTab>(initialTab);
  const [ifSubView, setIfSubView] = useState<'interfaces' | 'vlans' | 'bonds' | 'bridges'>('interfaces');
  const [fwSubView, setFwSubView] = useState<'rules' | 'nat' | 'aliases' | 'shaper' | 'security'>('rules');
  const [rtSubView, setRtSubView] = useState<'routes' | 'gateways' | 'frr'>('routes');
  const [stSubView, setStSubView] = useState<'pools' | 'datasets' | 'snapshots' | 'shares'>('pools');
  const [cmpSubView, setCmpSubView] = useState<'roles' | 'vms' | 'containers' | 'soc'>('roles');
  const [updSubView, setUpdSubView] = useState<'be' | 'snapshots' | 'checks'>('be');
  const [opsSubView, setOpsSubView] = useState<'toolkit' | 'users' | 'gitops' | 'power'>('toolkit');

  const [state, setState] = useState<DesiredState>(() => loadCurrentState());
  const [daemonStatus, setDaemonStatus] = useState<any>(null);
  const [partitionStatus, setPartitionStatus] = useState<any>(() => ({
    installMode: detectLocalInstallMode(),
    bootEnvironments: [],
    checks: [],
  }));
  const [mcpStatus, setMcpStatus] = useState<{ masterEnabled: boolean; leases?: any[]; disabledReason?: string }>({
    masterEnabled: false,
    disabledReason: 'Disabled by default',
  });
  const [hostPlugins, setHostPlugins] = useState<Record<string, any>>({});
  const [liveNasPools, setLiveNasPools] = useState<any[]>([]);
  const [liveNasSnapshots, setLiveNasSnapshots] = useState<any[]>([]);
  const [liveNasDisks, setLiveNasDisks] = useState<any[]>([]);
  const [liveVms, setLiveVms] = useState<any[]>([]);
  const [liveContainers, setLiveContainers] = useState<any[]>([]);
  const [soarBlockedIps, setSoarBlockedIps] = useState<any[]>([]);
  const [rootkitStatus, setRootkitStatus] = useState<any>(null);
  const [directoryUsers, setDirectoryUsers] = useState<any[]>([]);
  const [directoryStatus, setDirectoryStatus] = useState<any>(null);
  const [etckeeperHistory, setEtckeeperHistory] = useState<any[]>([]);
  const [hwTelemetry, setHwTelemetry] = useState<any>(null);
  const [haTrustStatus, setHaTrustStatus] = useState<any>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [promptState, setPromptState] = useState<InlinePrompt | null>(null);
  const [lastJobId, setLastJobId] = useState<string | null>(null);

  const [statusMessage, setStatusMessage] = useState<string>(
    readOnly
      ? 'Ready [READ-ONLY OPERATOR MODE] — Use [1-9,u,0] or [Tab] to inspect tabs, [↑/↓] to scroll, [q] to exit.'
      : 'Ready — Use [1-9,u,0] or [Tab] to switch tabs, [n] Subview, [↑/↓] Select, [Space] Toggle, [a] Apply, [q] Quit.'
  );
  const [cursorIdx, setCursorIdx] = useState<number>(0);
  const [cliOutput, setCliOutput] = useState<string>('');
  const [storageOutput, setStorageOutput] = useState<string>('');
  const [computeOutput, setComputeOutput] = useState<string>('');

  const refreshAll = useCallback(async () => {
    const fresh = loadCurrentState();
    setState(fresh);
    const localMcp = getMcpServerStatus();
    const [st, mcpLeases, plg, parts] = await Promise.all([
      callDaemon('/v1/status', 'GET'),
      callDaemon('/v1/mcp/leases', 'GET'),
      callDaemon('/v1/system/plugins', 'GET'),
      callDaemon('/v1/system/partitions', 'GET'),
    ]);
    if (st && !st.error) setDaemonStatus(st);
    if (parts && !parts.error) {
      setPartitionStatus(parts);
    }
    setMcpStatus({
      masterEnabled: localMcp.enabled,
      disabledReason: localMcp.disabledReason,
      leases: Array.isArray(mcpLeases?.leases) ? mcpLeases.leases : [],
    });
    if (plg?.plugins && Array.isArray(plg.plugins)) {
      const map: Record<string, any> = {};
      for (const p of plg.plugins) {
        map[p.id] = p;
      }
      setHostPlugins(map);
    }

    // Fetch tab-specific live telemetry in background
    if (activeTab === 'storage') {
      const [poolsRes, snapsRes, disksRes] = await Promise.all([
        callDaemon('/v1/nas/pools', 'GET'),
        callDaemon('/v1/nas/snapshots', 'GET'),
        callDaemon('/v1/nas/disks', 'GET'),
      ]);
      if (Array.isArray(poolsRes?.pools)) setLiveNasPools(poolsRes.pools);
      if (Array.isArray(snapsRes?.snapshots)) setLiveNasSnapshots(snapsRes.snapshots);
      if (Array.isArray(disksRes?.disks)) setLiveNasDisks(disksRes.disks);
    } else if (activeTab === 'compute') {
      const [vmsRes, ctsRes, soarRes, rkRes] = await Promise.all([
        callDaemon('/v1/virt/vms', 'GET'),
        callDaemon('/v1/virt/containers', 'GET'),
        callDaemon('/v1/vigilante/soar/blocked-ips', 'GET'),
        callDaemon('/v1/security/rootkit/status', 'GET'),
      ]);
      if (Array.isArray(vmsRes?.vms)) setLiveVms(vmsRes.vms);
      if (Array.isArray(ctsRes?.containers)) setLiveContainers(ctsRes.containers);
      if (Array.isArray(soarRes?.blockedIPs)) setSoarBlockedIps(soarRes.blockedIPs);
      if (rkRes && !rkRes.error) setRootkitStatus(rkRes);
    } else if (activeTab === 'cli_ops') {
      const [usrRes, dirRes, etcRes, hwRes] = await Promise.all([
        callDaemon('/v1/system/users', 'GET'),
        callDaemon('/v1/system/directory/status', 'GET'),
        callDaemon('/v1/system/etckeeper/history', 'GET'),
        callDaemon('/v1/system/telemetry/hardware', 'GET'),
      ]);
      if (Array.isArray(usrRes?.users)) setDirectoryUsers(usrRes.users);
      if (dirRes && !dirRes.error) setDirectoryStatus(dirRes);
      if (Array.isArray(etcRes?.history)) setEtckeeperHistory(etcRes.history);
      if (hwRes && !hwRes.error) setHwTelemetry(hwRes);
    } else if (activeTab === 'dashboard' || activeTab === 'services') {
      const [hwRes, haRes] = await Promise.all([
        callDaemon('/v1/system/telemetry/hardware', 'GET'),
        callDaemon('/v1/ha/sync-trust', 'GET'),
      ]);
      if (hwRes && !hwRes.error) setHwTelemetry(hwRes);
      if (haRes && !haRes.error) setHaTrustStatus(haRes);
    }
  }, [activeTab]);

  useEffect(() => {
    refreshAll();
    const timer = setInterval(refreshAll, 3000);
    return () => clearInterval(timer);
  }, [refreshAll]);

  const handleApplyConfig = async () => {
    setStatusMessage('Compiling nftables & subsystem configurations and applying with 120s commit-confirm...');
    // B2-M5: the snapshot is taken inside saveStateToDisk, under
    // the same lock acquisition as the write (see there), so the
    // snapshot and the write it guards cannot be split by a
    // concurrent writer. A daemon outage is different: the disk-only
    // save below deliberately keeps the new files, and only an
    // explicit rejection restores.
    const saved = saveStateToDisk(state);
    // B2-M4 follow-up: the save could not take the DesiredState
    // lock — another save or MCP propose holds it — so nothing was
    // written. Do not call the daemon (there is nothing new to
    // apply) and say so plainly instead of claiming a save.
    if (!saved) {
      setStatusMessage('✖ Could not lock DesiredState — another save or MCP propose is in progress; nothing was written. Try again.');
      return;
    }
    const diskSnapshot = saved.snapshot;
    const yamlDaemonFiles = saved.daemonFiles;
    const { nftScript, files, reloadServices } = compileNftables(state);
    const hashInput = JSON.stringify({
      nftScript,
      files: [...files]
        .sort((a, b) => a.path.localeCompare(b.path))
        .map((f) => ({ path: f.path, content: f.content, fileMode: f.fileMode })),
      reloadServices: [...reloadServices].sort(),
    });
    const bundleHash = crypto.createHash('sha256').update(hashInput).digest('hex');

    const allFiles = [
      ...files.map((f: any) => ({
        ...f,
        fileMode: f.fileMode ?? f.file_mode ?? 0o600,
        file_mode: f.file_mode ?? f.fileMode ?? 0o600,
      })),
      ...Object.entries(yamlDaemonFiles).map(([filePath, content]) => ({
        path: filePath,
        content,
        fileMode: 0o660,
        file_mode: 0o660,
      })),
    ];

    const jobId = `tui-${Date.now()}`;
    setLastJobId(jobId);
    const resp = await callDaemon(
      '/v1/apply',
      'POST',
      {
        jobId,
        job_id: jobId,
        bundleHash,
        bundle_hash: bundleHash,
        nftablesRuleset: nftScript,
        nftScript,
        nft_script: nftScript,
        files: allFiles,
        reloadServices,
        reload_services: reloadServices,
        commitConfirmTimeoutSec: 120,
        confirmTimeoutSeconds: 120,
        confirm_timeout_seconds: 120,
      },
      20000
    );

    // B2-M6: a timeout is neither a rejection nor an offline save
    // — the apply may have landed on the daemon, so neither
    // restore the disk nor claim success; tell the operator to
    // check the daemon's pending job. This branch is checked
    // before the generic error branch because timeout objects
    // also carry .error. Offline/malformed likewise keep the
    // disk-only save (no restore); only an explicit daemon
    // rejection restores.
    if (resp?.errorKind === 'timeout') {
      setStatusMessage('✖ Apply status unknown — the daemon did not answer in time; the bundle may still be pending on the daemon. Check the daemon\'s pending job before retrying.');
    } else if (resp && (resp.success || resp.status === 'applied_pending_confirm' || resp.status === 'applied')) {
      setStatusMessage('✔ Applied to live daemon! Press [c] within 120s to confirm, or [r] to rollback.');
      await refreshAll();
    } else if (resp?.errorKind === 'offline' || resp?.errorKind === 'malformed') {
      setStatusMessage('✔ Saved to /etc/axonwall/*.yaml (daemon socket offline or standalone mode).');
    } else if (resp?.error) {
      // B2-M4 follow-up: the restore takes the same lock; a restore
      // that cannot take it must not claim to have restored anything.
      const restored = restoreTuiConfigSnapshotLocked(diskSnapshot);
      setStatusMessage(
        restored
          ? `✖ Apply rejected by daemon: ${resp.message || resp.error} (previous on-disk configuration restored)`
          : `✖ Apply rejected by daemon: ${resp.message || resp.error} (could NOT restore the previous on-disk configuration — the DesiredState lock is held by another save; check /etc/axonwall/*.yaml before retrying)`,
      );
    } else {
      setStatusMessage('✔ Saved to /etc/axonwall/*.yaml (daemon socket offline or standalone mode).');
    }
  };

  const handleConfirm = async () => {
    const activeJobId = daemonStatus?.pending_job_id || daemonStatus?.pendingJobId || lastJobId;
    if (!activeJobId) {
      setStatusMessage('No pending commit-confirm job ID found.');
      return;
    }
    const resp = await callDaemon('/v1/confirm', 'POST', { jobId: activeJobId, job_id: activeJobId });
    if (resp && (resp.success || resp.status === 'confirmed')) {
      setStatusMessage('✔ Configuration confirmed and persisted as last-known-good!');
      await refreshAll();
    } else {
      setStatusMessage(resp?.message || 'No pending commit-confirm timer active.');
    }
  };

  const handleRollback = async () => {
    const resp = await callDaemon('/v1/rollback', 'POST', { reason: 'TUI operator rollback' });
    if (resp && (resp.success || resp.status === 'rolled_back')) {
      setStatusMessage('↺ Rolled back to previous last-known-good configuration!');
      await refreshAll();
    } else {
      setStatusMessage(resp?.message || 'Rollback requested.');
    }
  };

  const toggleCoreRoleInState = (next: DesiredState, roleId: string): boolean => {
    const caps = resolveCapabilities(next);
    const nextCaps = {
      firewallEnabled: roleId === 'core-firewall' ? !caps.firewallEnabled : caps.firewallEnabled,
      nasEnabled: roleId === 'core-nas' ? !caps.nasEnabled : caps.nasEnabled,
      k3sEnabled: roleId === 'core-k3s' ? !caps.k3sEnabled : caps.k3sEnabled,
      virtEnabled: roleId === 'core-virt' ? !caps.virtEnabled : caps.virtEnabled,
      vigilanteEnabled: roleId === 'core-vigilante' ? !caps.vigilanteEnabled : caps.vigilanteEnabled,
    };
    next.capabilities = nextCaps;
    if (roleId === 'core-nas') {
      next.nas = { ...(next.nas || ({} as any)), enabled: nextCaps.nasEnabled };
    } else if (roleId === 'core-k3s') {
      next.k3s = { ...(next.k3s || ({} as any)), enabled: nextCaps.k3sEnabled };
      if (!nextCaps.k3sEnabled) {
        const depRes = disablePluginWithDependents('core-k3s', next);
        Object.assign(next, depRes.state);
      }
    } else if (roleId === 'core-virt') {
      next.virt = { ...(next.virt || ({} as any)), enabled: nextCaps.virtEnabled };
    } else if (roleId === 'core-vigilante') {
      if (nextCaps.vigilanteEnabled) {
        const depRes = enablePluginWithDependencies('core-vigilante', next);
        Object.assign(next, depRes.state);
      } else {
        const depRes = disablePluginWithDependents('core-vigilante', next);
        Object.assign(next, depRes.state);
      }
    }
    return roleId === 'core-firewall'
      ? nextCaps.firewallEnabled
      : roleId === 'core-nas'
        ? nextCaps.nasEnabled
        : roleId === 'core-k3s'
          ? nextCaps.k3sEnabled
          : roleId === 'core-virt'
            ? nextCaps.virtEnabled
            : nextCaps.vigilanteEnabled;
  };

  const toggleExtensionPluginInState = async (pluginId: string) => {
    let next = structuredClone(state);
    const currentlyEnabled = isPluginEnabled(pluginId, next);
    const nextEnabled = !currentlyEnabled;
    let depNotice = '';

    if (pluginId === 'vigilant-octo-waffle' || pluginId === 'host-malware-rootkit' || pluginId === 'eluvix') {
      if (nextEnabled) {
        const depRes = enablePluginWithDependencies(pluginId, next);
        next = depRes.state;
        if (depRes.autoEnabledDependencies.length > 0) {
          depNotice = ` (auto-enabled dependency: ${depRes.autoEnabledDependencies.join(', ')})`;
        }
      } else {
        const depRes = disablePluginWithDependents(pluginId, next);
        next = depRes.state;
      }
    } else {
      const filtered = (next.plugins || []).filter((p: any) => p.id !== pluginId);
      filtered.push({ id: pluginId, enabled: nextEnabled, config: {} });
      next.plugins = filtered;

      if (pluginId === 'rosenpass') {
        next.rosenpass = { ...(next.rosenpass || ({} as any)), enabled: nextEnabled };
      } else if (pluginId === 'haproxy') {
        next.haproxy = { ...(next.haproxy || ({} as any)), enabled: nextEnabled };
      } else if (pluginId === 'freeradius') {
        next.freeradius = { ...(next.freeradius || ({} as any)), enabled: nextEnabled };
      } else if (pluginId === 'snmp') {
        next.snmp = { ...(next.snmp || ({} as any)), enabled: nextEnabled };
      } else if (pluginId === 'nut-ups') {
        next.ups = { ...(next.ups || ({} as any)), enabled: nextEnabled };
      } else if (pluginId === 'headscale') {
        next.headscale = {
          ...(next.headscale || ({} as any)),
          enabled: nextEnabled,
        };
      }
    }

    setState(next);
    saveStateToDisk(next);
    await callDaemon('/v1/system/plugins/action', 'POST', {
      pluginId,
      action: nextEnabled ? 'enable' : 'disable',
    });
    setStatusMessage(
      `Toggled plugin '${pluginId}' -> ${nextEnabled ? 'ENABLED' : 'DISABLED'}${depNotice}. Press [a] to apply.`
    );
    await refreshAll();
  };

  const serviceRows = [
    {
      id: 'dhcp',
      name: 'Kea DHCPv4 Server',
      enabled: Boolean(state.dhcp?.enabled),
      detail: `${state.dhcp?.subnets?.length || 0} subnets, ${(state.dhcp?.subnets || []).reduce((acc, s) => acc + (s.staticMappings?.length || 0), 0)} static leases`,
    },
    {
      id: 'dns',
      name: 'Unbound DNS Resolver (DNSSEC/DoT)',
      enabled: Boolean(state.dns?.enabled),
      detail: `Upstreams: ${(state.dns?.dotUpstreams || state.system?.dnsServers || []).join(', ') || 'Root Hints'}`,
    },
    {
      id: 'dnsBlocklist',
      name: 'DNS Blocklist & Sinkhole (RPZ)',
      enabled: Boolean(state.dns?.blocklist?.enabled ?? (state as any).dnsBlocklist?.enabled),
      detail: `${state.dns?.blocklist?.feeds?.length || 0} threat feeds, ${(state.dns?.blocklist as any)?.customBlockedDomains?.length || 0} custom domains`,
    },
    {
      id: 'wireguard',
      name: 'WireGuard Kernel VPN',
      enabled: Boolean(state.wireguard?.enabled),
      detail: `UDP ${state.wireguard?.listenPort || 51820} (${state.wireguard?.peers?.length || 0} peers)`,
    },
    {
      id: 'rosenpass',
      name: 'Rosenpass Post-Quantum WireGuard PSK',
      enabled: Boolean(state.rosenpass?.enabled),
      detail: `Classic McEliece + Kyber PSK rotation on UDP ${state.rosenpass?.listenPort || 9999} ([g] Keygen)`,
    },
    {
      id: 'headscale',
      name: 'Headscale Mesh Coordination Server',
      enabled: Boolean(state.headscale?.enabled),
      detail: `MagicDNS: ${state.headscale?.magicDnsDomain || 'mesh.axonwall.local'}`,
    },
    {
      id: 'openvpn',
      name: 'OpenVPN Server / Site-to-Site',
      enabled: Boolean((state as any).openvpn?.enabled),
      detail: `Instances: ${(state as any).openvpn?.instances?.length || 0}`,
    },
    {
      id: 'ipsec',
      name: 'IPsec / StrongSwan IKEv2 VPN',
      enabled: Boolean((state as any).ipsec?.enabled),
      detail: `Tunnels: ${(state as any).ipsec?.tunnels?.length || 0}`,
    },
    {
      id: 'suricata',
      name: 'Suricata IDS/IPS Engine',
      enabled: Boolean(state.suricata?.enabled),
      detail: `Mode: ${(state.suricata?.mode || 'ids').toUpperCase()} (${state.suricata?.interfaces?.join(', ') || 'WAN'})`,
    },
    {
      id: 'crowdsec',
      name: 'CrowdSec Collaborative IPS Bouncer',
      enabled: Boolean(state.crowdsec?.enabled),
      detail: `nftables set @${state.crowdsec?.remediationSetName || 'crowdsec_blackhole'} (${state.crowdsec?.action || 'drop'})`,
    },
    {
      id: 'geoip',
      name: 'GeoIP Country Filtering',
      enabled: Boolean(state.geoip?.enabled),
      detail: `Mode: ${state.geoip?.mode || 'block'} (${state.geoip?.countries?.join(', ') || 'none'})`,
    },
    {
      id: 'haproxy',
      name: 'HAProxy L4/L7 Reverse Proxy',
      enabled: Boolean(state.haproxy?.enabled),
      detail: `${state.haproxy?.frontends?.length || 0} frontends, ${state.haproxy?.backends?.length || 0} backends`,
    },
    {
      id: 'freeradius',
      name: 'FreeRADIUS 802.1X Authentication',
      enabled: Boolean(state.freeradius?.enabled),
      detail: `UDP ${state.freeradius?.authPort || 1812}/${state.freeradius?.acctPort || 1813} (${state.freeradius?.clients?.length || 0} NAS clients)`,
    },
    {
      id: 'captivePortal',
      name: 'Captive Portal & Voucher Gateway',
      enabled: Boolean(state.captivePortal?.enabled),
      detail: `Zones: ${(state.captivePortal?.zones || []).map((z) => z.interface).join(', ') || 'none'}`,
    },
    {
      id: 'iap',
      name: 'Identity-Aware Zero-Trust Proxy (IAP)',
      enabled: Boolean(state.zeroTrust?.enabled ?? (state as any).iap?.enabled),
      detail: `${state.zeroTrust?.apps?.length || 0} protected applications`,
    },
    {
      id: 'acme',
      name: 'ACME / Let’s Encrypt Automated TLS',
      enabled: Boolean(state.acme?.enabled),
      detail: `Certs: ${state.acme?.certificates?.length || 0} (${state.acme?.accounts?.[0]?.email || 'no account'})`,
    },
    {
      id: 'ddns',
      name: 'Dynamic DNS (DDNS) Client',
      enabled: Boolean((state as any).ddns?.enabled),
      detail: `Provider: ${(state as any).ddns?.provider || 'cloudflare'} (${(state as any).ddns?.hostname || 'unconfigured'})`,
    },
    {
      id: 'mdns',
      name: 'mDNS / Avahi Multicast Reflector',
      enabled: Boolean((state as any).mdns?.enabled),
      detail: `Reflect across: ${(state as any).mdns?.interfaces?.join(', ') || 'LAN/VLANs'}`,
    },
    {
      id: 'snmp',
      name: 'Net-SNMP Telemetry Agent',
      enabled: Boolean(state.snmp?.enabled),
      detail: `SNMP v2c/v3 on UDP ${state.snmp?.listenPort || 161} (${state.snmp?.sysLocation || 'Server Room'})`,
    },
    {
      id: 'ups',
      name: 'Network UPS Tools (NUT)',
      enabled: Boolean(state.ups?.enabled),
      detail: `Driver ${state.ups?.driver || 'usbhid-ups'} (Shutdown battery: ${state.ups?.shutdownBatteryPct || 20}%)`,
    },
    {
      id: 'ha',
      name: 'High Availability (Keepalived VRRP + mTLS)',
      enabled: Boolean(state.ha?.enabled),
      detail: state.ha?.enabled
        ? `${(state.ha?.nodeRole || 'MASTER').toUpperCase()} (${state.ha?.vrrpInstances?.length || 0} VIPs, PKI: ${haTrustStatus?.pkiEnrolled ? 'ENROLLED' : 'PENDING'})`
        : 'Standalone Node',
    },
    {
      id: 'mcp',
      name: 'Axonwall MCP Server (AI Control Plane)',
      enabled: Boolean(mcpStatus.masterEnabled),
      detail: mcpStatus.masterEnabled
        ? `ACTIVE (${mcpStatus.leases?.length || 0} active leases — [f] Emergency Flush)`
        : `DISABLED BY DEFAULT (${mcpStatus.disabledReason || 'Explicit opt-in required'})`,
    },
  ];

  const cliTools = [
    {
      id: 'bandwidth',
      name: 'slurm / iftop (Live NIC Bandwidth & Flows)',
      desc: 'Auto-selects active gateway interface & displays RX/TX stats + TCP congestion flows',
    },
    {
      id: 'nftables',
      name: 'nftables (nft list ruleset)',
      desc: 'Live kernel nftables firewall & NAT tables currently enforced in netfilter',
    },
    {
      id: 'kubectl',
      name: 'kubectl (k3s kubectl get nodes,pods,svc -A)',
      desc: 'Kubernetes cluster nodes, workloads, and OpenEBS storage status',
    },
    {
      id: 'zfs',
      name: 'zpool & zfs (zpool status & zfs list)',
      desc: 'ZFS storage pool health, scrub status, and dataset space usage',
    },
    {
      id: 'sysstat',
      name: 'sysstat (mpstat -P ALL & iostat -xz)',
      desc: 'Multi-core CPU utilization and extended block device I/O latency metrics',
    },
    {
      id: 'netstat',
      name: 'net-tools (ss -tuln, ip neigh, ip route)',
      desc: 'Active listening sockets, ARP neighbor table, and kernel routing table',
    },
    {
      id: 'dnsutils',
      name: 'dnsutils (dig @auto-dns cloudflare.com)',
      desc: 'DNS resolution query & latency check against appliance forwarder',
    },
    {
      id: 'top_procs',
      name: 'btop / htop (Top CPU & Memory Processes)',
      desc: 'Snapshot of highest CPU/Memory processes on the appliance',
    },
    {
      id: 'logs',
      name: 'journalctl (axonwalld & nftables recent logs)',
      desc: 'Recent systemd journal entries for axonwalld, k3s, and kernel firewall logs',
    },
  ];

  const runCliToolInline = (idx: number) => {
    const item = cliTools[idx % cliTools.length]!;
    const subnets = detectApplianceSubnets(state);
    const defaultIf = subnets[0]?.device || 'eth0';
    const defaultDns = state.dns?.dotUpstreams?.[0] || state.system?.dnsServers?.[0] || '1.1.1.1';

    if (item.id === 'bandwidth') {
      const ipLink = execSafe('ip', ['-s', 'link', 'show', 'dev', defaultIf]);
      const ssOut = execSafe('ss', ['-tin']);
      setCliOutput(
        `=== Interface Bandwidth (${defaultIf}) ===\n${ipLink || 'Interface stats collected.'}\n\n=== Active Flows (ss -tin) ===\n${ssOut.slice(0, 1200)}`
      );
    } else if (item.id === 'nftables') {
      const nftOut = execSafe('nft', ['list', 'ruleset']) || compileNftables(state).nftScript;
      setCliOutput(`=== Kernel nftables Ruleset ===\n${nftOut.split('\n').slice(0, 28).join('\n')}`);
    } else if (item.id === 'kubectl') {
      const kOut =
        execSafe('kubectl', ['get', 'nodes,pods,svc', '-A', '-o', 'wide']) ||
        execSafe('k3s', ['kubectl', 'get', 'nodes,pods,svc', '-A']) ||
        'k3s cluster is not currently running or no nodes registered.';
      setCliOutput(`=== Kubernetes Cluster (kubectl get nodes,pods,svc -A) ===\n${kOut.split('\n').slice(0, 26).join('\n')}`);
    } else if (item.id === 'zfs') {
      const zp = execSafe('zpool', ['status']) || 'No ZFS pools imported.';
      const zl = execSafe('zfs', ['list']) || '';
      setCliOutput(`=== ZFS Pool Status ===\n${zp}\n\n=== ZFS Datasets ===\n${zl}`);
    } else if (item.id === 'sysstat') {
      const mp =
        execSafe('mpstat', ['-P', 'ALL']) ||
        `Load Avg: ${os.loadavg().map((n) => n.toFixed(2)).join(', ')} (${os.cpus().length} cores)`;
      const io = execSafe('iostat', ['-xz']) || execSafe('df', ['-h']);
      setCliOutput(`=== CPU Telemetry (mpstat) ===\n${mp}\n\n=== Disk I/O (iostat -xz) ===\n${io}`);
    } else if (item.id === 'netstat') {
      const ns = execSafe('ss', ['-tuln']) || execSafe('netstat', ['-tuln']);
      const arp = execSafe('ip', ['neigh', 'show']) || execSafe('arp', ['-an']);
      const rt = execSafe('ip', ['route', 'show']);
      setCliOutput(`=== Listening Sockets ===\n${ns}\n\n=== ARP Cache ===\n${arp}\n\n=== Kernel Routes ===\n${rt}`);
    } else if (item.id === 'dnsutils') {
      const dig =
        execSafe('dig', [`@${defaultDns}`, 'cloudflare.com', 'A', '+stats']) ||
        execSafe('nslookup', ['cloudflare.com', defaultDns]);
      setCliOutput(`=== DNS Lookup (dig @${defaultDns} cloudflare.com) ===\n${dig}`);
    } else if (item.id === 'top_procs') {
      const ps = execSafe('ps', ['aux', '--sort=-%cpu']);
      setCliOutput(`=== Top Processes (btop / htop snapshot) ===\n${ps.split('\n').slice(0, 18).join('\n')}`);
    } else if (item.id === 'logs') {
      const j =
        execSafe('journalctl', ['-u', 'axonwalld', '-n', '20', '--no-pager']) ||
        execSafe('dmesg', ['-T']);
      setCliOutput(`=== Recent System Journal Logs ===\n${j.split('\n').slice(-20).join('\n')}`);
    }
    setStatusMessage(`Executed ${item.name} (NIC: ${defaultIf}, DNS: ${defaultDns}).`);
  };

  const installMode = partitionStatus?.installMode || detectLocalInstallMode();
  const topTabs = getTopTabs(installMode);

  // Flatten all ZBM snapshots across Boot Environments
  const allZbmSnapshots: any[] = [];
  for (const be of partitionStatus?.bootEnvironments || []) {
    if (Array.isArray(be.snapshotDetails) && be.snapshotDetails.length > 0) {
      for (const sd of be.snapshotDetails) {
        allZbmSnapshots.push(sd);
      }
    } else if (Array.isArray(be.snapshots)) {
      for (const sName of be.snapshots) {
        allZbmSnapshots.push({
          name: sName.includes('@') ? sName.split('@')[1] : sName,
          fullName: sName.includes('@') ? sName : `${be.dataset}@${sName}`,
          dataset: be.dataset,
          beName: be.name,
          usedSize: '-',
          referSize: be.usedSize || '-',
          createdAt: be.createdAt || '-',
        });
      }
    }
  }

  useInput((input, key) => {
    // Handle inline text prompt mode first
    if (promptState) {
      if (key.escape) {
        setPromptState(null);
        setStatusMessage('Cancelled input prompt.');
        return;
      }
      if (key.return) {
        const finalVal = (promptState.value.trim() || promptState.placeholder).trim();
        const cb = promptState.onSubmit;
        setPromptState(null);
        cb(finalVal);
        return;
      }
      if (key.backspace || key.delete) {
        setPromptState((prev) => (prev ? { ...prev, value: prev.value.slice(0, -1) } : null));
        return;
      }
      if (input && !key.ctrl && !key.meta && input.length === 1) {
        setPromptState((prev) => (prev ? { ...prev, value: prev.value + input } : null));
      }
      return;
    }

    if (input === 'q' || input === 'Q') {
      exit();
      return;
    }
    if (key.tab) {
      const idx = topTabs.findIndex((t) => t.id === activeTab);
      const nextTab = topTabs[(idx + 1) % topTabs.length]!;
      setActiveTab(nextTab.id);
      setCursorIdx(0);
      return;
    }
    if (input === '1') {
      setActiveTab('dashboard');
      setCursorIdx(0);
      return;
    } else if (input === '2') {
      setActiveTab('interfaces');
      setCursorIdx(0);
      return;
    } else if (input === '3') {
      setActiveTab('firewall');
      setCursorIdx(0);
      return;
    } else if (input === '4') {
      setActiveTab('routing');
      setCursorIdx(0);
      return;
    } else if (input === '5') {
      setActiveTab('services');
      setCursorIdx(0);
      return;
    } else if (input === '6') {
      setActiveTab('storage');
      setCursorIdx(0);
      return;
    } else if (input === '7') {
      setActiveTab('compute');
      setCursorIdx(0);
      return;
    } else if (input === '8') {
      setActiveTab('plugins');
      setCursorIdx(0);
      return;
    } else if (input === '9') {
      setActiveTab('nastymap');
      setCursorIdx(0);
      return;
    } else if (input === 'u' && activeTab !== 'plugins' && activeTab !== 'compute') {
      setActiveTab('updates');
      setCursorIdx(0);
      return;
    } else if (input === '0') {
      setActiveTab('cli_ops');
      setCursorIdx(0);
      if (!cliOutput) runCliToolInline(0);
      return;
    }

    if (activeTab === 'nastymap') return;

    if (input === 'c' && activeTab !== 'updates') {
      if (readOnly) {
        setStatusMessage('Read-only operator session: confirming commit is disabled.');
        return;
      }
      handleConfirm();
      return;
    } else if (input === 'r') {
      if (readOnly) {
        setStatusMessage('Read-only operator session: configuration rollback is disabled.');
        return;
      }
      handleRollback();
      return;
    } else if (input === 'a') {
      if (readOnly) {
        setStatusMessage('Read-only operator session: applying configuration changes is disabled.');
        return;
      }
      handleApplyConfig();
      return;
    } else if (input === 'd' && activeTab !== 'interfaces') {
      refreshAll();
      setStatusMessage('Reloaded live state & telemetry from /etc/axonwall/*.yaml and axonwalld.');
      return;
    }

    // Subview cycling with [n] across all multi-view tabs
    if (input === 'n') {
      if (activeTab === 'interfaces') {
        const order: Array<'interfaces' | 'vlans' | 'bonds' | 'bridges'> = ['interfaces', 'vlans', 'bonds', 'bridges'];
        const nextSub = order[(order.indexOf(ifSubView) + 1) % order.length]!;
        setIfSubView(nextSub);
        setCursorIdx(0);
        setStatusMessage(`Switched Interfaces view to ${nextSub.toUpperCase()}.`);
        return;
      }
      if (activeTab === 'firewall') {
        const order: Array<'rules' | 'nat' | 'aliases' | 'shaper' | 'security'> = [
          'rules',
          'nat',
          'aliases',
          'shaper',
          'security',
        ];
        const nextSub = order[(order.indexOf(fwSubView) + 1) % order.length]!;
        setFwSubView(nextSub);
        setCursorIdx(0);
        setStatusMessage(`Switched Firewall view to ${nextSub.toUpperCase()}.`);
        return;
      }
      if (activeTab === 'routing') {
        const order: Array<'routes' | 'gateways' | 'frr'> = ['routes', 'gateways', 'frr'];
        const nextSub = order[(order.indexOf(rtSubView) + 1) % order.length]!;
        setRtSubView(nextSub);
        setCursorIdx(0);
        setStatusMessage(`Switched Routing view to ${nextSub.toUpperCase()}.`);
        return;
      }
      if (activeTab === 'storage') {
        const order: Array<'pools' | 'datasets' | 'snapshots' | 'shares'> = ['pools', 'datasets', 'snapshots', 'shares'];
        const nextSub = order[(order.indexOf(stSubView) + 1) % order.length]!;
        setStSubView(nextSub);
        setCursorIdx(0);
        setStatusMessage(`Switched Storage view to ${nextSub.toUpperCase()}.`);
        return;
      }
      if (activeTab === 'compute') {
        const order: Array<'roles' | 'vms' | 'containers' | 'soc'> = ['roles', 'vms', 'containers', 'soc'];
        const nextSub = order[(order.indexOf(cmpSubView) + 1) % order.length]!;
        setCmpSubView(nextSub);
        setCursorIdx(0);
        setStatusMessage(`Switched Compute view to ${nextSub.toUpperCase()}.`);
        return;
      }
      if (activeTab === 'updates') {
        const order: Array<'be' | 'snapshots' | 'checks'> = ['be', 'snapshots', 'checks'];
        const nextSub = order[(order.indexOf(updSubView) + 1) % order.length]!;
        setUpdSubView(nextSub);
        setCursorIdx(0);
        setStatusMessage(`Switched Updates / ZBM view to ${nextSub.toUpperCase()}.`);
        return;
      }
      if (activeTab === 'cli_ops') {
        const order: Array<'toolkit' | 'users' | 'gitops' | 'power'> = ['toolkit', 'users', 'gitops', 'power'];
        const nextSub = order[(order.indexOf(opsSubView) + 1) % order.length]!;
        setOpsSubView(nextSub);
        setCursorIdx(0);
        setStatusMessage(`Switched System & Ops view to ${nextSub.toUpperCase()}.`);
        return;
      }
    }

    // Tab-specific hotkeys
    if (activeTab === 'interfaces' && !readOnly && ifSubView === 'interfaces' && state.interfaces.length > 0) {
      const idx = cursorIdx % state.interfaces.length;
      if (input === 'm') {
        const next = structuredClone(state);
        const target = next.interfaces[idx]!;
        target.type = target.type === 'dhcp' ? 'static' : 'dhcp';
        if (target.type === 'static' && !target.ipv4Address) {
          target.ipv4Address = '192.168.10.1/24';
        }
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(`Switched ${target.name} (${target.device}) mode to ${target.type.toUpperCase()}. Press [a] to apply.`);
        return;
      }
      if (input === 'd') {
        const next = structuredClone(state);
        const target = next.interfaces[idx]!;
        target.dhcpServer = !target.dhcpServer;
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(
          `Toggled DHCPv4 Server on ${target.name} -> ${target.dhcpServer ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
        );
        return;
      }
    }

    if (activeTab === 'firewall' && !readOnly && fwSubView === 'rules' && state.rules.length > 0) {
      const idx = cursorIdx % state.rules.length;
      if (input === 'p') {
        const next = structuredClone(state);
        const rule = next.rules[idx]!;
        const order: Array<'pass' | 'block' | 'reject'> = ['pass', 'block', 'reject'];
        rule.action = order[(order.indexOf(rule.action as any) + 1) % order.length]!;
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(`Rule '${rule.description || rule.id}' action -> ${rule.action.toUpperCase()}. Press [a] to apply.`);
        return;
      }
      if (input === 'l') {
        const next = structuredClone(state);
        const rule = next.rules[idx]!;
        rule.log = !rule.log;
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(`Rule '${rule.description || rule.id}' logging -> ${rule.log ? 'ON' : 'OFF'}. Press [a] to apply.`);
        return;
      }
      if ((input === '+' || input === 'K') && idx > 0) {
        const next = structuredClone(state);
        const tmp = next.rules[idx - 1]!;
        next.rules[idx - 1] = next.rules[idx]!;
        next.rules[idx] = tmp;
        setState(next);
        saveStateToDisk(next);
        setCursorIdx(idx - 1);
        setStatusMessage(`Moved firewall rule up to priority #${idx}. Press [a] to apply.`);
        return;
      }
      if ((input === '-' || input === 'J') && idx < state.rules.length - 1) {
        const next = structuredClone(state);
        const tmp = next.rules[idx + 1]!;
        next.rules[idx + 1] = next.rules[idx]!;
        next.rules[idx] = tmp;
        setState(next);
        saveStateToDisk(next);
        setCursorIdx(idx + 1);
        setStatusMessage(`Moved firewall rule down to priority #${idx + 2}. Press [a] to apply.`);
        return;
      }
    }

    if (activeTab === 'services' && !readOnly) {
      if (input === 'g') {
        setStatusMessage('Generating / rotating Rosenpass Post-Quantum McEliece 460896 keypair...');
        callDaemon('/v1/vpn/rosenpass/keygen', 'POST', { force: true }, 20000).then((res) => {
          setStatusMessage(res?.success ? '✔ Rosenpass Post-Quantum keypair rotated!' : `Rosenpass keygen: ${res?.message || 'done'}`);
          refreshAll();
        });
        return;
      }
      if (input === 'f') {
        setStatusMessage('Flushing all active MCP tactical leases...');
        callDaemon('/v1/mcp/flush', 'POST', { reason: 'TUI operator flush' }).then(() => {
          setStatusMessage('✔ All active MCP leases flushed and revoked.');
          refreshAll();
        });
        return;
      }
    }

    if (activeTab === 'storage') {
      if (input === 's' && !readOnly) {
        const datasets = state.nas?.datasets || [];
        const dsName =
          stSubView === 'datasets' && datasets[cursorIdx % Math.max(1, datasets.length)]
            ? `${datasets[cursorIdx % datasets.length]!.pool || 'tank'}/${datasets[cursorIdx % datasets.length]!.name}`
            : liveNasPools[0]?.name || state.nas?.pools?.[0]?.name || 'tank';
        const defaultLabel = `manual-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}`;
        setPromptState({
          title: `Create ZFS Snapshot on '${dsName}' (Enter label)`,
          placeholder: defaultLabel,
          value: '',
          onSubmit: (label) => {
            setStatusMessage(`Creating ZFS snapshot ${dsName}@${label}...`);
            callDaemon('/v1/nas/snapshots', 'POST', { dataset: dsName, label }).then((res) => {
              if (res?.success) {
                setStatusMessage(`✔ Created ZFS snapshot: ${res.snapshot || `${dsName}@${label}`}`);
              } else {
                setStatusMessage(`✖ Snapshot failed: ${res?.message || 'ZFS pool not imported'}`);
              }
              refreshAll();
            });
          },
        });
        return;
      }
      if (input === 'w' && !readOnly) {
        const poolName = liveNasPools[cursorIdx % Math.max(1, liveNasPools.length)]?.name || state.nas?.pools?.[0]?.name || 'tank';
        setStatusMessage(`Starting ZFS scrub on pool '${poolName}'...`);
        callDaemon('/v1/nas/scrub', 'POST', { pool: poolName }).then((res) => {
          setStatusMessage(res?.success ? `✔ ${res.message}` : `✖ Scrub failed: ${res?.message || 'pool unavailable'}`);
          refreshAll();
        });
        return;
      }
      if (input === 'z') {
        const zp = execSafe('zpool', ['status']) || 'No live ZFS pools imported in kernel.';
        const zl = execSafe('zfs', ['list']) || '';
        setStorageOutput(`${zp}\n${zl}`.trim());
        setStatusMessage('Queried live ZFS pool & dataset telemetry.');
        return;
      }
    }

    if (activeTab === 'compute') {
      if (input === 'k') {
        const ko =
          execSafe('kubectl', ['get', 'nodes,pods', '-A', '-o', 'wide']) ||
          execSafe('k3s', ['kubectl', 'get', 'nodes,pods', '-A']) ||
          'k3s server not currently running.';
        setComputeOutput(ko);
        setStatusMessage('Queried live Kubernetes (k3s) cluster status.');
        return;
      }
      if (input === 'v') {
        const vo =
          execSafe('virsh', ['list', '--all']) ||
          execSafe('lxc-ls', ['--fancy']) ||
          'libvirtd / LXC not currently running.';
        setComputeOutput(vo);
        setStatusMessage('Queried live KVM/LXC hypervisor domains.');
        return;
      }
      if (!readOnly && cmpSubView === 'vms' && liveVms.length > 0) {
        const vm = liveVms[cursorIdx % liveVms.length]!;
        if (input === 's' || input === 'x' || input === 'b') {
          const action = input === 's' ? 'start' : input === 'x' ? 'stop' : 'reset';
          setStatusMessage(`Executing '${action}' on KVM VM #${vm.vmid} (${vm.name})...`);
          callDaemon('/v1/virt/vms', 'POST', { action, vmid: vm.vmid }).then((res) => {
            setStatusMessage(res?.success ? `✔ VM #${vm.vmid} ${action} initiated.` : `✖ VM ${action} failed: ${res?.message}`);
            refreshAll();
          });
          return;
        }
      }
      if (!readOnly && cmpSubView === 'containers' && liveContainers.length > 0) {
        const ct = liveContainers[cursorIdx % liveContainers.length]!;
        if (input === 's' || input === 'x') {
          const action = input === 's' ? 'start' : 'stop';
          setStatusMessage(`Executing '${action}' on LXC Container #${ct.ctid} (${ct.name})...`);
          callDaemon('/v1/virt/containers', 'POST', { action, ctid: ct.ctid }).then((res) => {
            setStatusMessage(res?.success ? `✔ CT #${ct.ctid} ${action} initiated.` : `✖ CT ${action} failed: ${res?.message}`);
            refreshAll();
          });
          return;
        }
      }
      if (cmpSubView === 'soc') {
        if (input === 'h') {
          setStatusMessage('Running Host Malware, Rootkit & Ghost-in-the-Ring Kernel Audit...');
          callDaemon('/v1/security/rootkit/scan', 'POST', {}, 30000).then((res) => {
            if (res && !res.error) setRootkitStatus(res);
            setStatusMessage('✔ Rootkit & Kernel Integrity Audit complete.');
            refreshAll();
          });
          return;
        }
        if (!readOnly && input === 'b') {
          setPromptState({
            title: 'Quarantine & Block IP via Vigilante SOAR (Enter IPv4/IPv6)',
            placeholder: '198.51.100.42',
            value: '',
            onSubmit: (ip) => {
              callDaemon('/v1/vigilante/soar/block-ip', 'POST', { ip, timeoutSec: 3600 }).then((res) => {
                setStatusMessage(res?.success ? `✔ ${res.message}` : `✖ Block failed: ${res?.message}`);
                refreshAll();
              });
            },
          });
          return;
        }
        if (!readOnly && input === 'u' && soarBlockedIps.length > 0) {
          const targetIp = soarBlockedIps[cursorIdx % soarBlockedIps.length]?.ip;
          if (targetIp) {
            callDaemon('/v1/vigilante/soar/unblock-ip', 'POST', { ip: targetIp }).then((res) => {
              setStatusMessage(res?.success ? `✔ ${res.message}` : `✖ Unblock failed: ${res?.message}`);
              refreshAll();
            });
          }
          return;
        }
      }
    }

    // ZFSBootMenu (ZBM) & A/B Updates Tab Actions
    if (activeTab === 'updates' && !readOnly) {
      const bes = partitionStatus?.bootEnvironments || [];
      if (input === 'h') {
        setStatusMessage('Running partition & ZBM boot health verification...');
        callDaemon('/v1/system/health/verify', 'POST', {}, 15000).then((res) => {
          setStatusMessage(res?.success !== false ? '✔ System boot health verified and bootcount cleared!' : `✖ Health check: ${res?.message}`);
          refreshAll();
        });
        return;
      }
      if (installMode === 'zbm') {
        if (input === 's') {
          const selectedBe =
            updSubView === 'be' && bes[cursorIdx % Math.max(1, bes.length)]
              ? bes[cursorIdx % bes.length]!.name
              : bes.find((b: any) => b.activeNow)?.name || bes[0]?.name || '';
          const defaultLabel = `snap-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}`;
          setPromptState({
            title: `Create Arbitrary ZFS Snapshot on Boot Environment '${selectedBe || 'active'}' (Enter label)`,
            placeholder: defaultLabel,
            value: '',
            onSubmit: (label) => {
              setBusyAction(`Creating snapshot @${label}...`);
              setStatusMessage(`Creating ZFS Boot Environment snapshot ${selectedBe}@${label}...`);
              callDaemon('/v1/system/zbm', 'POST', { action: 'snapshot', beName: selectedBe, label }, 30000).then(
                (res) => {
                  setBusyAction(null);
                  if (res?.success) {
                    setStatusMessage(`✔ ${res.message || `Created snapshot ${res.snapshot}`}`);
                  } else {
                    setStatusMessage(`✖ Snapshot failed: ${res?.message || 'ZBM error'}`);
                  }
                  refreshAll();
                }
              );
            },
          });
          return;
        }
        if (input === 'c') {
          const snapObj =
            updSubView === 'snapshots' && allZbmSnapshots[cursorIdx % Math.max(1, allZbmSnapshots.length)]
              ? allZbmSnapshots[cursorIdx % allZbmSnapshots.length]
              : allZbmSnapshots[0];
          if (!snapObj) {
            setStatusMessage('No ZFS snapshot available to clone. Press [s] to create a snapshot first.');
            return;
          }
          const defaultNewBe = `axonwall-clone-${new Date().toISOString().slice(0, 10)}`;
          setPromptState({
            title: `Clone '${snapObj.fullName}' into new Boot Environment (Enter new BE name)`,
            placeholder: defaultNewBe,
            value: '',
            onSubmit: (newBeName) => {
              setBusyAction(`Cloning to ${newBeName}...`);
              callDaemon(
                '/v1/system/zbm',
                'POST',
                { action: 'clone', snapshot: snapObj.fullName, newBeName },
                30000
              ).then((res) => {
                setBusyAction(null);
                setStatusMessage(
                  res?.success ? `✔ ${res.message}` : `✖ Clone failed: ${res?.message || 'ZBM error'}`
                );
                refreshAll();
              });
            },
          });
          return;
        }
        if (input === 'b' && updSubView === 'be' && bes.length > 0) {
          const targetBe = bes[cursorIdx % bes.length]!;
          setStatusMessage(`Activating Boot Environment '${targetBe.name}' for next reboot...`);
          callDaemon('/v1/system/zbm', 'POST', { action: 'activate', beName: targetBe.name }, 15000).then((res) => {
            setStatusMessage(
              res?.success ? `✔ ${res.message}` : `✖ Activate failed: ${res?.message || 'ZBM error'}`
            );
            refreshAll();
          });
          return;
        }
        if (input === 'x') {
          if (updSubView === 'be' && bes.length > 0) {
            const targetBe = bes[cursorIdx % bes.length]!;
            if (targetBe.activeNow) {
              setStatusMessage(`✖ Cannot delete currently mounted Boot Environment '${targetBe.name}'.`);
              return;
            }
            setStatusMessage(`Deleting Boot Environment '${targetBe.name}'...`);
            callDaemon('/v1/system/zbm', 'POST', { action: 'delete', beName: targetBe.name }, 20000).then((res) => {
              setStatusMessage(res?.success ? `✔ ${res.message}` : `✖ Delete failed: ${res?.message}`);
              refreshAll();
            });
          } else if (updSubView === 'snapshots' && allZbmSnapshots.length > 0) {
            const targetSnap = allZbmSnapshots[cursorIdx % allZbmSnapshots.length]!;
            setStatusMessage(`Deleting ZFS snapshot '${targetSnap.fullName}'...`);
            callDaemon(
              '/v1/system/zbm',
              'POST',
              { action: 'delete-snapshot', snapshot: targetSnap.fullName },
              20000
            ).then((res) => {
              setStatusMessage(res?.success ? `✔ ${res.message}` : `✖ Delete snapshot failed: ${res?.message}`);
              refreshAll();
            });
          }
          return;
        }
      } else {
        // A/B or Rolling mode
        if (input === 'b') {
          const standby = partitionStatus?.inactiveSlot || (partitionStatus?.activeSlot === 'A' ? 'B' : 'A');
          setStatusMessage(`Activating standby partition Slot ${standby} for next boot...`);
          callDaemon('/v1/system/slot/activate', 'POST', { slot: standby }, 15000).then((res) => {
            setStatusMessage(res?.success ? `✔ ${res.message}` : `✖ Slot activation failed: ${res?.message}`);
            refreshAll();
          });
          return;
        }
      }
    }

    if (activeTab === 'cli_ops' && !readOnly && opsSubView === 'gitops') {
      if (input === 's') {
        setPromptState({
          title: 'Commit /etc changes to Etckeeper GitOps (Enter commit message)',
          placeholder: 'Manual operator snapshot via Axonwall TUI',
          value: '',
          onSubmit: (msg) => {
            callDaemon('/v1/system/etckeeper/commit', 'POST', { message: msg, author: 'tui-operator' }).then((res) => {
              setStatusMessage(res?.success ? `✔ ${res.message}` : `✖ Etckeeper commit failed: ${res?.message}`);
              refreshAll();
            });
          },
        });
        return;
      }
    }

    if (activeTab === 'plugins' && !readOnly && (input === 'i' || input === 'u' || input === 's')) {
      const plg = BUILTIN_PLUGINS[cursorIdx % BUILTIN_PLUGINS.length]!;
      if (CORE_ROLE_PLUGIN_IDS.has(plg.id)) {
        setStatusMessage(`Core role '${plg.id}' is built into the appliance image. Use [Space] to enable/disable.`);
        return;
      }
      const action = input === 'i' ? 'install' : input === 'u' ? 'uninstall' : 'reconfigure';
      setBusyAction(`${action.toUpperCase()} ${plg.id}...`);
      setStatusMessage(
        `⏳ Executing '${action}' for plugin '${plg.id}' (downloading & configuring packages, up to 5m)...`
      );
      callDaemon('/v1/system/plugins/action', 'POST', { pluginId: plg.id, action }, 300000).then((res) => {
        setBusyAction(null);
        if (res?.success) {
          setStatusMessage(`✔ ${res.message}`);
        } else {
          setStatusMessage(`✖ Plugin ${action} failed: ${res?.message || 'daemon communication timeout'}`);
        }
        refreshAll();
      });
      return;
    }

    if (key.upArrow) {
      setCursorIdx((prev) => Math.max(0, prev - 1));
    } else if (key.downArrow) {
      setCursorIdx((prev) => prev + 1);
    } else if (input === ' ' || key.return) {
      if (readOnly && activeTab !== 'cli_ops') {
        setStatusMessage('Read-only operator session: configuration modifications are disabled.');
        return;
      }
      if (activeTab === 'interfaces') {
        if (ifSubView === 'interfaces' && state.interfaces.length > 0) {
          const next = structuredClone(state);
          const target = next.interfaces[cursorIdx % next.interfaces.length]!;
          target.enabled = !target.enabled;
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled interface '${target.name}' (${target.device}) -> ${target.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        }
      } else if (activeTab === 'firewall') {
        if (fwSubView === 'rules' && state.rules.length > 0) {
          const next = structuredClone(state);
          const rule = next.rules[cursorIdx % next.rules.length]!;
          rule.enabled = !rule.enabled;
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled firewall rule '${rule.description || rule.id}' -> ${rule.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        } else if (fwSubView === 'nat' && (state.nat?.length || 0) > 0) {
          const next = structuredClone(state);
          const nr = next.nat![cursorIdx % next.nat!.length]!;
          nr.enabled = !nr.enabled;
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled NAT rule '${nr.description || nr.id}' -> ${nr.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        } else if (fwSubView === 'aliases' && (state.aliases?.length || 0) > 0) {
          const next = structuredClone(state);
          const al = next.aliases![cursorIdx % next.aliases!.length]!;
          al.enabled = !al.enabled;
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled alias '${al.name}' -> ${al.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        } else if (fwSubView === 'shaper') {
          const next = structuredClone(state);
          const nextEnabled = !next.trafficShaper?.enabled;
          next.trafficShaper = {
            interfaces: next.trafficShaper?.interfaces || [],
            enabled: nextEnabled,
          };
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled QoS Traffic Shaper -> ${nextEnabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        }
      } else if (activeTab === 'routing') {
        if (rtSubView === 'routes' && (state.routes?.length || 0) > 0) {
          const next = structuredClone(state);
          const rt = next.routes![cursorIdx % next.routes!.length]!;
          rt.enabled = rt.enabled === false ? true : false;
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled static route '${rt.network} via ${rt.gateway}' -> ${rt.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        } else if (rtSubView === 'gateways' && (state.gateways?.length || 0) > 0) {
          const next = structuredClone(state);
          const gw = next.gateways![cursorIdx % next.gateways!.length]!;
          gw.enabled = !gw.enabled;
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled upstream gateway '${gw.name}' (${gw.gatewayIp}) -> ${gw.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        } else if (rtSubView === 'frr') {
          const next = structuredClone(state);
          const frrObj = (next.frr || { bgp: { enabled: false, asNumber: 65001, neighbors: [] }, ospf: { enabled: false, areas: [] } }) as any;
          if (cursorIdx % 2 === 0) {
            frrObj.bgp = { ...(frrObj.bgp || { asNumber: 65001, neighbors: [] }), enabled: !frrObj.bgp?.enabled };
            setStatusMessage(`Toggled FRR BGP -> ${frrObj.bgp.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`);
          } else {
            frrObj.ospf = { ...(frrObj.ospf || { areas: [] }), enabled: !frrObj.ospf?.enabled };
            setStatusMessage(`Toggled FRR OSPF -> ${frrObj.ospf.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`);
          }
          next.frr = frrObj;
          setState(next);
          saveStateToDisk(next);
        }
      } else if (activeTab === 'services') {
        const row = serviceRows[cursorIdx % serviceRows.length]!;
        if (row.id === 'mcp') {
          const nextEnabled = !mcpStatus.masterEnabled;
          const settingsObj = {
            enabled: nextEnabled,
            ...(nextEnabled
              ? {}
              : {
                  disabledReason: 'Disabled via Axonwall TUI',
                  disabledAt: new Date().toISOString(),
                  disabledBy: 'tui',
                }),
          };
          const serialized = JSON.stringify(settingsObj, null, 2);
          for (const p of Array.from(
            new Set([
              resolveMcpSettingsPath(),
              '/var/lib/axonwall/mcp-settings.json',
              '/var/lib/axonwall/etc-axonwall/mcp-settings.json',
              '/etc/axonwall/mcp-settings.json',
            ])
          )) {
            try {
              fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o775 });
              fs.writeFileSync(p, serialized, { mode: 0o660 });
            } catch {}
          }
          if (!nextEnabled) {
            callDaemon('/v1/mcp/flush', 'POST', {}).catch(() => {});
          }
          setMcpStatus({
            masterEnabled: nextEnabled,
            disabledReason: nextEnabled ? undefined : 'Disabled via Axonwall TUI',
            leases: nextEnabled ? mcpStatus.leases : [],
          });
          setStatusMessage(`Toggled MCP Server Master Switch -> ${nextEnabled ? 'ENABLED' : 'DISABLED'}.`);
          return;
        }
        const next = structuredClone(state);
        if (row.id === 'dhcp') next.dhcp = { ...(next.dhcp || { subnets: [] }), enabled: !next.dhcp?.enabled };
        else if (row.id === 'dns') next.dns = { ...(next.dns || ({} as any)), enabled: !next.dns?.enabled };
        else if (row.id === 'dnsBlocklist') {
          next.dns = next.dns || ({ enabled: true, listenPort: 53, dnssec: true, dotEnabled: true, dotUpstreams: [], hostOverrides: [] } as any);
          (next.dns as any).blocklist = { ...((next.dns as any).blocklist || { feeds: [] }), enabled: !next.dns?.blocklist?.enabled };
        }
        else if (row.id === 'wireguard')
          next.wireguard = { ...(next.wireguard || ({} as any)), enabled: !next.wireguard?.enabled };
        else if (row.id === 'rosenpass')
          next.rosenpass = { ...(next.rosenpass || ({} as any)), enabled: !next.rosenpass?.enabled };
        else if (row.id === 'headscale')
          next.headscale = { ...(next.headscale || ({} as any)), enabled: !next.headscale?.enabled };
        else if (row.id === 'openvpn')
          (next as any).openvpn = { ...((next as any).openvpn || {}), enabled: !(next as any).openvpn?.enabled };
        else if (row.id === 'ipsec')
          (next as any).ipsec = { ...((next as any).ipsec || {}), enabled: !(next as any).ipsec?.enabled };
        else if (row.id === 'suricata')
          next.suricata = { ...(next.suricata || ({} as any)), enabled: !next.suricata?.enabled };
        else if (row.id === 'crowdsec')
          next.crowdsec = { ...(next.crowdsec || ({} as any)), enabled: !next.crowdsec?.enabled };
        else if (row.id === 'geoip')
          next.geoip = { ...(next.geoip || ({} as any)), enabled: !next.geoip?.enabled };
        else if (row.id === 'haproxy')
          next.haproxy = { ...(next.haproxy || ({} as any)), enabled: !next.haproxy?.enabled };
        else if (row.id === 'freeradius')
          next.freeradius = { ...(next.freeradius || ({} as any)), enabled: !next.freeradius?.enabled };
        else if (row.id === 'captivePortal')
          next.captivePortal = { ...(next.captivePortal || ({} as any)), enabled: !next.captivePortal?.enabled };
        else if (row.id === 'iap')
          next.zeroTrust = { ...(next.zeroTrust || ({ apps: [] } as any)), enabled: !next.zeroTrust?.enabled };
        else if (row.id === 'acme')
          next.acme = { ...(next.acme || ({} as any)), enabled: !next.acme?.enabled };
        else if (row.id === 'ddns')
          (next as any).ddns = { ...((next as any).ddns || {}), enabled: !(next as any).ddns?.enabled };
        else if (row.id === 'mdns')
          (next as any).mdns = { ...((next as any).mdns || {}), enabled: !(next as any).mdns?.enabled };
        else if (row.id === 'snmp')
          next.snmp = { ...(next.snmp || ({} as any)), enabled: !next.snmp?.enabled };
        else if (row.id === 'ups')
          next.ups = { ...(next.ups || ({} as any)), enabled: !next.ups?.enabled };
        else if (row.id === 'ha')
          next.ha = { ...(next.ha || ({} as any)), enabled: !next.ha?.enabled };
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(`Toggled ${row.name}. Press [a] to compile & apply.`);
      } else if (activeTab === 'storage') {
        const next = structuredClone(state);
        const nowEnabled = toggleCoreRoleInState(next, 'core-nas');
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(
          `Toggled Enterprise Grade ZFS NAS (core-nas) -> ${nowEnabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
        );
      } else if (activeTab === 'compute') {
        if (cmpSubView === 'roles') {
          const roles = ['core-k3s', 'core-virt', 'core-vigilante', 'vigilant-octo-waffle', 'eluvix', 'host-malware-rootkit'];
          const roleId = roles[cursorIdx % roles.length]!;
          if (CORE_ROLE_PLUGIN_IDS.has(roleId)) {
            const next = structuredClone(state);
            const nowEnabled = toggleCoreRoleInState(next, roleId);
            setState(next);
            saveStateToDisk(next);
            setStatusMessage(`Toggled ${roleId} -> ${nowEnabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`);
          } else {
            toggleExtensionPluginInState(roleId);
          }
        }
      } else if (activeTab === 'plugins') {
        const plg = BUILTIN_PLUGINS[cursorIdx % BUILTIN_PLUGINS.length]!;
        if (CORE_ROLE_PLUGIN_IDS.has(plg.id)) {
          const next = structuredClone(state);
          const nowEnabled = toggleCoreRoleInState(next, plg.id);
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled Core Role '${plg.id}' -> ${nowEnabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        } else {
          toggleExtensionPluginInState(plg.id);
        }
      } else if (activeTab === 'cli_ops') {
        if (opsSubView === 'toolkit') {
          runCliToolInline(cursorIdx);
        }
      }
    }
  });

  const totalMemGb = (os.totalmem() / 1024 ** 3).toFixed(1);
  const usedMemGb = ((os.totalmem() - os.freemem()) / 1024 ** 3).toFixed(1);
  const memPct = Math.round(((os.totalmem() - os.freemem()) / (os.totalmem() || 1)) * 100);
  const loadStr = os.loadavg().map((n) => n.toFixed(2)).join(', ');
  const pendingConfirm = Boolean(daemonStatus?.pending_confirm ?? daemonStatus?.pendingConfirm);
  const confirmDeadline = Number(daemonStatus?.confirm_deadline_unix ?? daemonStatus?.confirmDeadlineUnix ?? 0);
  const remainingSec = pendingConfirm
    ? Math.max(0, Math.floor(confirmDeadline - Date.now() / 1000))
    : 0;
  const detectedSubnets = detectApplianceSubnets(state);
  const caps = resolveCapabilities(state);
  const workstationEnabled = isPluginEnabled('cli-workstation', state);

  const fwRulesViewport = getViewportSlice(state.rules || [], cursorIdx, 13);
  const servicesViewport = getViewportSlice(serviceRows, cursorIdx, 13);
  const pluginsViewport = getViewportSlice(BUILTIN_PLUGINS, cursorIdx, 13);
  const zbmBeViewport = getViewportSlice(partitionStatus?.bootEnvironments || [], cursorIdx, 11);
  const zbmSnapViewport = getViewportSlice(allZbmSnapshots, cursorIdx, 11);

  return (
    <Box flexDirection="column" paddingX={1}>
      {/* Top Appliance Header */}
      <Box
        borderStyle="round"
        borderColor={pendingConfirm ? 'yellow' : 'green'}
        paddingX={1}
        justifyContent="space-between"
      >
        <Text wrap="truncate-end">
          <Text bold color="green">AXONWALL TUI</Text>
          <Text color="gray"> · </Text>
          <Text color="white">Host: <Text bold color="cyan">{state.system?.hostname || os.hostname()}</Text></Text>
          <Text color="gray"> · </Text>
          <Text color="white">Mode: <Text bold color="magenta">{installMode.toUpperCase()}</Text></Text>
          <Text color="gray"> · </Text>
          <Text color="white">Load: <Text color="yellow">{loadStr}</Text></Text>
          <Text color="gray"> · </Text>
          <Text color="white">RAM: <Text color="cyan">{usedMemGb}/{totalMemGb}G ({memPct}%)</Text></Text>
          <Text color="gray"> · </Text>
          <Text color={mcpStatus.masterEnabled ? 'yellow' : 'gray'}>
            MCP:{mcpStatus.masterEnabled ? 'ON' : 'OFF'}
          </Text>
          <Text color="gray"> · </Text>
          <Text color={daemonStatus ? 'green' : 'yellow'}>
            ● {daemonStatus ? 'axonwalld' : 'YAML Direct'}
          </Text>
          {busyAction ? <Text bold color="yellow"> ⏳ [{busyAction}]</Text> : null}
          {readOnly ? <Text bold color="yellow"> [READ-ONLY]</Text> : null}
        </Text>
      </Box>

      {/* Inline Interactive Input Prompt Bar */}
      {promptState && (
        <Box borderStyle="double" borderColor="cyan" paddingX={1} flexDirection="column">
          <Text bold color="cyan">
            ✎ {promptState.title}:
          </Text>
          <Text>
            <Text color="green" bold>{'> '}</Text>
            <Text color="white" bold>{promptState.value}</Text>
            <Text color="gray">{promptState.value ? '█' : `${promptState.placeholder} (Press Enter for default, Esc to cancel)`}</Text>
          </Text>
        </Box>
      )}

      {/* Commit-Confirm Safety Banner if Active */}
      {pendingConfirm && (
        <Box
          borderStyle="double"
          borderColor="yellow"
          paddingX={1}
          justifyContent="space-between"
        >
          <Text bold color="yellow">
            ⚠ COMMIT-CONFIRM ACTIVE: Auto-rollback in {remainingSec}s unless confirmed!
          </Text>
          <Text bold color="white">
            Press [c] Confirm Changes  ·  Press [r] Rollback Immediately
          </Text>
        </Box>
      )}

      {/* Global Navigation Tab Bar */}
      <Box marginY={0} gap={1} flexWrap="wrap" paddingX={1}>
        {topTabs.map((t) => {
          const isAct = activeTab === t.id;
          return (
            <Text
              key={t.id}
              bold={isAct}
              color={isAct ? 'black' : 'white'}
              backgroundColor={isAct ? 'green' : undefined}
            >
              {isAct ? ` ▸ [${t.key}] ${t.label} ` : `[${t.key}] ${t.label}`}
            </Text>
          );
        })}
      </Box>

      {/* Main Content Area */}
      {activeTab === 'dashboard' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1} gap={0}>
          <Text bold color="cyan" underline wrap="truncate-end">
            Appliance Overview & Active Stack (/etc/axonwall/*.yaml)
          </Text>
          <Box gap={2}>
            <Box flexDirection="column" width="50%">
              <Text bold color="white">Configured Network Interfaces ({state.interfaces.length}):</Text>
              {state.interfaces.map((iface) => (
                <Text key={iface.name} wrap="truncate-end">
                  {' '}
                  <Text color={iface.enabled ? 'green' : 'red'} bold>
                    {iface.enabled ? '● UP  ' : '○ DOWN'}
                  </Text>{' '}
                  <Text bold color="white">
                    {iface.name.toUpperCase().padEnd(5, ' ')}
                  </Text>{' '}
                  <Text color="cyan">{iface.device.padEnd(7, ' ')}</Text>{' '}
                  <Text color="yellow">{iface.ipv4Address || iface.type}</Text>
                </Text>
              ))}
              <Box marginTop={1} flexDirection="column">
                <Text bold color="white">Active Appliance Core Roles:</Text>
                <Text wrap="truncate-end">
                  {'  '}• Firewall : <Text color={caps.firewallEnabled ? 'green' : 'gray'} bold>{caps.firewallEnabled ? 'ON ' : 'OFF'}</Text>
                  {'  '}• ZFS NAS : <Text color={caps.nasEnabled ? 'green' : 'gray'} bold>{caps.nasEnabled ? 'ON' : 'OFF'}</Text>
                </Text>
                <Text wrap="truncate-end">
                  {'  '}• K3s/EBS  : <Text color={caps.k3sEnabled ? 'green' : 'gray'} bold>{caps.k3sEnabled ? 'ON ' : 'OFF'}</Text>
                  {'  '}• KVM/LXC : <Text color={caps.virtEnabled ? 'green' : 'gray'} bold>{caps.virtEnabled ? 'ON' : 'OFF'}</Text>
                </Text>
                <Text wrap="truncate-end">
                  {'  '}• Vigilante: <Text color={caps.vigilanteEnabled ? 'green' : 'gray'} bold>{caps.vigilanteEnabled ? 'ON ' : 'OFF'}</Text>
                </Text>
              </Box>
            </Box>
            <Box flexDirection="column" width="50%">
              <Text bold color="white">Control Plane, Boot & Security Summary:</Text>
              <Text wrap="truncate-end">
                {'  '}• Boot Architecture :{' '}
                <Text color="magenta" bold>
                  {installMode === 'zbm'
                    ? `ZFSBootMenu (${partitionStatus?.bootEnvironments?.length || 1} BEs, ${allZbmSnapshots.length} snaps)`
                    : installMode === 'rolling'
                      ? 'Rolling Standard Linux'
                      : `A/B Dual-Root (Slot ${partitionStatus?.activeSlot || 'A'})`}
                </Text>
              </Text>
              <Text wrap="truncate-end">  • Firewall & NAT    : <Text color="green" bold>{state.rules.length}</Text> rules, <Text color="cyan" bold>{state.nat?.length || 0}</Text> NAT, <Text color="yellow" bold>{state.aliases?.length || 0}</Text> aliases</Text>
              <Text wrap="truncate-end">  • Routing & FRR     : <Text color="cyan" bold>{state.routes?.length || 0}</Text> static, <Text color="yellow" bold>{state.gateways?.length || 0}</Text> gateways, BGP:{state.frr?.bgp?.enabled ? 'ON' : 'OFF'}</Text>
              <Text wrap="truncate-end">  • DHCPv4 / Unbound  : <Text color="green" bold>{state.dhcp?.subnets?.length || 0}</Text> subnets, DNS:{state.dns?.enabled !== false ? 'ON' : 'OFF'}</Text>
              <Text wrap="truncate-end">  • Post-Quantum VPN  : WG:{state.wireguard?.enabled ? 'ON' : 'OFF'} · Rosenpass PQ:{state.rosenpass?.enabled ? 'ON' : 'OFF'}</Text>
              <Text wrap="truncate-end">  • MCP Control Plane : <Text color={mcpStatus.masterEnabled ? 'yellow' : 'green'} bold>{mcpStatus.masterEnabled ? `ENABLED (${mcpStatus.leases?.length || 0} leases)` : 'DISABLED (Safe)'}</Text></Text>
              <Text wrap="truncate-end">  • Shell Workstation : <Text color={workstationEnabled ? 'cyan' : 'gray'} bold>{workstationEnabled ? 'ENABLED (ZSH+Starship+Nvim)' : 'MINIMAL'}</Text></Text>
            </Box>
          </Box>
        </Box>
      )}

      {activeTab === 'interfaces' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1}>
          <Text bold color="cyan" wrap="truncate-end">
            Network Interfaces [{ifSubView.toUpperCase()}]{' '}
            <Text color="gray" bold={false}>
              — [n] View ({state.interfaces.length} NICs, {state.vlans?.length || 0} VLANs, {state.bonds?.length || 0} Bonds, {state.bridges?.length || 0} Bridges) · [Space] Toggle · [m] Mode · [d] DHCP · [a] Apply
            </Text>
          </Text>
          {ifSubView === 'interfaces' &&
            state.interfaces.map((iface, idx) => {
              const sel = idx === cursorIdx % Math.max(1, state.interfaces.length);
              return (
                <Text key={iface.name} wrap="truncate-end">
                  <Text color={sel ? 'cyan' : 'gray'} bold>
                    {sel ? '▶ ' : '  '}
                  </Text>
                  <Text color={iface.enabled ? 'green' : 'red'} bold>
                    {iface.enabled ? '[ENABLED]  ' : '[DISABLED] '}
                  </Text>
                  <Text bold color={sel ? 'white' : 'gray'}>
                    {iface.name.toUpperCase().padEnd(8, ' ')}
                  </Text>
                  <Text color="cyan">{iface.device.padEnd(10, ' ')}</Text>
                  <Text color="yellow">{(iface.ipv4Address || iface.type).padEnd(19, ' ')}</Text>
                  <Text color={iface.dhcpServer ? 'green' : 'gray'}>
                    {iface.dhcpServer ? '[DHCP:ON]  ' : '[DHCP:OFF] '}
                  </Text>
                  <Text color="white">{iface.description || ''}</Text>
                </Text>
              );
            })}
          {ifSubView === 'vlans' &&
            ((state.vlans || []).length === 0 ? (
              <Text color="gray">  No 802.1Q VLANs configured in /etc/axonwall/interfaces.yaml.</Text>
            ) : (
              (state.vlans || []).map((v, idx) => {
                const sel = idx === cursorIdx % Math.max(1, (state.vlans || []).length);
                return (
                  <Text key={v.id || v.vlanInterface || idx} wrap="truncate-end">
                    <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                    <Text bold color="cyan">{`VLAN ${v.tag}`.padEnd(10, ' ')}</Text>
                    <Text color="yellow">{(v.vlanInterface || `${v.parentInterface}.${v.tag}`).padEnd(14, ' ')}</Text>
                    <Text color="white">{`Parent: ${v.parentInterface}`.padEnd(16, ' ')}</Text>
                    <Text color="gray">{v.description || ''}</Text>
                  </Text>
                );
              })
            ))}
          {ifSubView === 'bonds' &&
            ((state.bonds || []).length === 0 ? (
              <Text color="gray">  No LACP / LAGG link aggregation bonds configured.</Text>
            ) : (
              (state.bonds || []).map((b: any, idx: number) => {
                const sel = idx === cursorIdx % Math.max(1, (state.bonds || []).length);
                return (
                  <Text key={b.name || idx} wrap="truncate-end">
                    <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                    <Text bold color="cyan">{(b.name || 'bond0').padEnd(12, ' ')}</Text>
                    <Text color="yellow">{(b.mode || '802.3ad').padEnd(14, ' ')}</Text>
                    <Text color="white">Members: {(b.interfaces || b.members || []).join(', ')}</Text>
                  </Text>
                );
              })
            ))}
          {ifSubView === 'bridges' &&
            ((state.bridges || []).length === 0 ? (
              <Text color="gray">  No Layer-2 bridges configured.</Text>
            ) : (
              (state.bridges || []).map((br: any, idx: number) => {
                const sel = idx === cursorIdx % Math.max(1, (state.bridges || []).length);
                return (
                  <Text key={br.name || idx} wrap="truncate-end">
                    <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                    <Text bold color="cyan">{(br.name || 'br0').padEnd(12, ' ')}</Text>
                    <Text color="yellow">{`STP: ${br.stp ? 'ON' : 'OFF'}`.padEnd(12, ' ')}</Text>
                    <Text color="white">Ports: {(br.interfaces || br.ports || []).join(', ')}</Text>
                  </Text>
                );
              })
            ))}
        </Box>
      )}

      {activeTab === 'firewall' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1}>
          <Text bold color="cyan" wrap="truncate-end">
            Firewall & NAT [{fwSubView.toUpperCase()}]{' '}
            <Text color="gray" bold={false}>
              — [n] View · [↑/↓] Select · [Space] Toggle · [p] Action · [l] Log · [+/-] Reorder · [a] Apply
            </Text>
          </Text>
          {fwSubView === 'rules' &&
            fwRulesViewport.slice.map((rule, i) => {
              const absIdx = fwRulesViewport.startIndex + i;
              const sel = absIdx === fwRulesViewport.activeIndex;
              const actionColor =
                rule.action === 'pass' ? 'green' : rule.action === 'block' ? 'red' : 'yellow';
              return (
                <Text key={rule.id || absIdx} wrap="truncate-end">
                  <Text color={sel ? 'cyan' : 'gray'} bold>
                    {sel ? '▶ ' : '  '}
                  </Text>
                  <Text color={rule.enabled ? 'green' : 'gray'}>
                    {rule.enabled ? '[ON]  ' : '[OFF] '}
                  </Text>
                  <Text bold color={actionColor}>
                    {rule.action.toUpperCase().padEnd(7, ' ')}
                  </Text>
                  <Text color="cyan">{rule.interface.padEnd(6, ' ')}</Text>
                  <Text color="yellow">{rule.protocol.toUpperCase().padEnd(6, ' ')}</Text>
                  <Text color="white">
                    {`${rule.source || 'any'} -> ${rule.destination || 'any'}${rule.destinationPort ? ':' + rule.destinationPort : ''}`.padEnd(26, ' ')}
                  </Text>
                  {rule.log ? <Text color="magenta">[LOG] </Text> : null}
                  <Text color="gray">{rule.description || ''}</Text>
                </Text>
              );
            })}
          {fwSubView === 'nat' &&
            ((state.nat || []).length === 0 ? (
              <Text color="gray">  Automatic WAN Masquerade active (no custom DNAT/SNAT rules).</Text>
            ) : (
              (state.nat || []).map((nr, idx) => {
                const sel = idx === cursorIdx % Math.max(1, (state.nat || []).length);
                return (
                  <Text key={nr.id || idx} wrap="truncate-end">
                    <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                    <Text color={nr.enabled ? 'green' : 'gray'}>{nr.enabled ? '[ON]  ' : '[OFF] '}</Text>
                    <Text bold color="yellow">{nr.type.toUpperCase().padEnd(11, ' ')}</Text>
                    <Text color="cyan">{nr.interface.padEnd(6, ' ')}</Text>
                    <Text color="white">{`${nr.protocol.toUpperCase()} :${nr.destinationPort || '*'} -> ${nr.targetIp || 'masquerade'}${nr.targetPort ? ':' + nr.targetPort : ''}`.padEnd(32, ' ')}</Text>
                    <Text color="gray">{nr.description || ''}</Text>
                  </Text>
                );
              })
            ))}
          {fwSubView === 'aliases' &&
            ((state.aliases || []).length === 0 ? (
              <Text color="gray">  No firewall aliases configured in /etc/axonwall/firewall.yaml.</Text>
            ) : (
              (state.aliases || []).map((al, idx) => {
                const sel = idx === cursorIdx % Math.max(1, (state.aliases || []).length);
                return (
                  <Text key={al.id || idx} wrap="truncate-end">
                    <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                    <Text color={al.enabled ? 'green' : 'gray'}>{al.enabled ? '[ON]  ' : '[OFF] '}</Text>
                    <Text bold color="cyan">{al.name.padEnd(18, ' ')}</Text>
                    <Text color="yellow">{al.type.toUpperCase().padEnd(10, ' ')}</Text>
                    <Text color="white">{(al.entries || []).join(', ')} </Text>
                    <Text color="gray">{al.description || ''}</Text>
                  </Text>
                );
              })
            ))}
          {fwSubView === 'shaper' && (
            <Box flexDirection="column">
              <Text wrap="truncate-end">
                QoS Traffic Shaper / SQM Cake :{' '}
                <Text bold color={state.trafficShaper?.enabled ? 'green' : 'gray'}>
                  {state.trafficShaper?.enabled ? '[ENABLED]' : '[DISABLED]'}
                </Text>{' '}
                — Interfaces: {state.trafficShaper?.interfaces?.length || 0}
              </Text>
              {(state.trafficShaper?.interfaces || []).map((q, idx: number) => (
                <Text key={q.id || idx} color="white" wrap="truncate-end">
                  {'  '}• Shaper on <Text bold color="cyan">{q.interface}</Text> — Down: {q.downloadBandwidthMbps} Mbps / Up: {q.uploadBandwidthMbps} Mbps ({q.scheduler || 'cake'})
                </Text>
              ))}
            </Box>
          )}
          {fwSubView === 'security' && (
            <Box flexDirection="column">
              <Text wrap="truncate-end">  • Suricata IDS/IPS   : <Text bold color={state.suricata?.enabled ? 'green' : 'gray'}>{state.suricata?.enabled ? `ENABLED (${state.suricata.mode.toUpperCase()})` : 'DISABLED'}</Text></Text>
              <Text wrap="truncate-end">  • CrowdSec IPS       : <Text bold color={state.crowdsec?.enabled ? 'green' : 'gray'}>{state.crowdsec?.enabled ? `ENABLED (${state.crowdsec.action})` : 'DISABLED'}</Text></Text>
              <Text wrap="truncate-end">  • GeoIP Filtering    : <Text bold color={state.geoip?.enabled ? 'green' : 'gray'}>{state.geoip?.enabled ? `ENABLED (${state.geoip.countries?.join(', ')})` : 'DISABLED'}</Text></Text>
              <Text wrap="truncate-end">  • DNS Blocklist RPZ  : <Text bold color={state.dns?.blocklist?.enabled ? 'green' : 'gray'}>{state.dns?.blocklist?.enabled ? `ENABLED (${state.dns.blocklist.feeds?.length || 0} feeds)` : 'DISABLED'}</Text></Text>
              <Text wrap="truncate-end">  • Captive Portal     : <Text bold color={state.captivePortal?.enabled ? 'green' : 'gray'}>{state.captivePortal?.enabled ? 'ENABLED' : 'DISABLED'}</Text></Text>
              <Text wrap="truncate-end">  • Zero-Trust IAP     : <Text bold color={state.zeroTrust?.enabled ? 'green' : 'gray'}>{state.zeroTrust?.enabled ? `ENABLED (${state.zeroTrust.apps?.length || 0} apps)` : 'DISABLED'}</Text></Text>
            </Box>
          )}
        </Box>
      )}

      {activeTab === 'routing' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1}>
          <Text bold color="cyan" wrap="truncate-end">
            Gateways, Static Routes & FRR BGP/OSPF [{rtSubView.toUpperCase()}]{' '}
            <Text color="gray" bold={false}>— [n] View · [↑/↓] Select · [Space] Toggle · [a] Apply</Text>
          </Text>
          {rtSubView === 'gateways' && (
            <Box flexDirection="column">
              <Text bold color="white">Upstream Gateways ({state.gateways?.length || 0}):</Text>
              {(state.gateways || []).map((gw, idx) => {
                const sel = idx === cursorIdx % Math.max(1, (state.gateways || []).length);
                return (
                  <Text key={gw.name} wrap="truncate-end">
                    <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                    <Text color={gw.enabled ? 'green' : 'red'} bold>{gw.enabled ? '[ENABLED]  ' : '[DISABLED] '}</Text>
                    <Text bold color="white">{gw.name.padEnd(14, ' ')}</Text>
                    <Text color="cyan">{gw.interface.padEnd(8, ' ')}</Text>
                    <Text color="yellow">{gw.gatewayIp.padEnd(16, ' ')}</Text>
                    <Text color="gray">Monitor: {gw.monitorIp || 'none'} {gw.isDefault ? '(Default)' : ''}</Text>
                  </Text>
                );
              })}
            </Box>
          )}
          {rtSubView === 'routes' && (
            <Box flexDirection="column">
              <Text bold color="white">Static Routes ({state.routes?.length || 0}):</Text>
              {(state.routes || []).length === 0 ? (
                <Text color="gray">  No static routes configured in /etc/axonwall/routing.yaml.</Text>
              ) : (
                (state.routes || []).map((rt, idx) => {
                  const sel = idx === cursorIdx % Math.max(1, (state.routes || []).length);
                  return (
                    <Text key={`${rt.network}-${rt.gateway}-${idx}`} wrap="truncate-end">
                      <Text color={sel ? 'cyan' : 'gray'} bold>
                        {sel ? '▶ ' : '  '}
                      </Text>
                      <Text color={rt.enabled !== false ? 'green' : 'red'} bold>
                        {rt.enabled !== false ? '[ACTIVE]   ' : '[DISABLED] '}
                      </Text>
                      <Text bold color="white">{rt.network.padEnd(18, ' ')}</Text>
                      <Text color="yellow">{`via ${rt.gateway}`.padEnd(19, ' ')}</Text>
                      <Text color="cyan">{`dev ${rt.interface || 'auto'}`.padEnd(11, ' ')}</Text>
                      <Text color="gray">{rt.description ? `# ${rt.description}` : ''}</Text>
                    </Text>
                  );
                })
              )}
            </Box>
          )}
          {rtSubView === 'frr' && (
            <Box flexDirection="column">
              <Text wrap="truncate-end">
                <Text color={cursorIdx % 2 === 0 ? 'cyan' : 'gray'} bold>{cursorIdx % 2 === 0 ? '▶ ' : '  '}</Text>
                <Text color={state.frr?.bgp?.enabled ? 'green' : 'gray'} bold>{state.frr?.bgp?.enabled ? '[ENABLED]  ' : '[DISABLED] '}</Text>
                <Text bold color="white">FRRouting BGPv4 Daemon </Text>
                <Text color="yellow">ASN: {state.frr?.bgp?.asNumber || 65001} · Router ID: {state.frr?.bgp?.routerId || 'auto'} · Neighbors: {state.frr?.bgp?.neighbors?.length || 0}</Text>
              </Text>
              <Text wrap="truncate-end">
                <Text color={cursorIdx % 2 === 1 ? 'cyan' : 'gray'} bold>{cursorIdx % 2 === 1 ? '▶ ' : '  '}</Text>
                <Text color={state.frr?.ospf?.enabled ? 'green' : 'gray'} bold>{state.frr?.ospf?.enabled ? '[ENABLED]  ' : '[DISABLED] '}</Text>
                <Text bold color="white">FRRouting OSPFv2/v3    </Text>
                <Text color="yellow">Router ID: {state.frr?.ospf?.routerId || 'auto'} · Areas: {state.frr?.ospf?.areas?.length || 0}</Text>
              </Text>
            </Box>
          )}
        </Box>
      )}

      {activeTab === 'services' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1}>
          <Text bold color="cyan" wrap="truncate-end">
            Network Services, Post-Quantum VPN, HA & MCP ({servicesViewport.activeIndex + 1}/{serviceRows.length}){' '}
            <Text color="gray" bold={false}>— [↑/↓] Select · [Space] Toggle · [g] PQ Keygen · [f] MCP Flush · [a] Apply</Text>
          </Text>
          {servicesViewport.slice.map((row, i) => {
            const absIdx = servicesViewport.startIndex + i;
            const sel = absIdx === servicesViewport.activeIndex;
            return (
              <Text key={row.id} wrap="truncate-end">
                <Text color={sel ? 'cyan' : 'gray'} bold>
                  {sel ? '▶ ' : '  '}
                </Text>
                <Text color={row.enabled ? 'green' : 'gray'} bold>
                  {row.enabled ? '[ENABLED]  ' : '[DISABLED] '}
                </Text>
                <Text bold={sel} color={sel ? 'white' : 'cyan'}>
                  {row.name.padEnd(40, ' ')}
                </Text>
                <Text color="gray">{row.detail}</Text>
              </Text>
            );
          })}
        </Box>
      )}

      {activeTab === 'storage' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1} gap={0}>
          <Text bold color="cyan" wrap="truncate-end">
            Enterprise Grade OpenZFS Storage & Shares [{stSubView.toUpperCase()}]{' '}
            <Text color="gray" bold={false}>— [n] View · [Space] Toggle NAS · [s] Create Snapshot · [w] Scrub · [z] zpool status</Text>
          </Text>
          <Text wrap="truncate-end">
            Enterprise Grade ZFS NAS Role :{' '}
            <Text bold color={caps.nasEnabled ? 'green' : 'gray'}>
              {caps.nasEnabled ? '[ENABLED]' : '[DISABLED]'}
            </Text>{' '}
            — Live Pools: <Text bold color="cyan">{liveNasPools.length || state.nas?.pools?.length || 0}</Text> · Datasets:{' '}
            <Text bold color="cyan">{state.nas?.datasets?.length || 0}</Text> · Snapshots:{' '}
            <Text bold color="cyan">{liveNasSnapshots.length}</Text> · Shares:{' '}
            <Text bold color="cyan">{(state.nas?.smbShares?.length || 0) + (state.nas?.nfsExports?.length || 0)}</Text>
          </Text>
          {stSubView === 'pools' && (
            <Box flexDirection="column" marginTop={1}>
              <Text bold color="white">ZFS Storage Pools & Physical Disks ({liveNasDisks.length} disks):</Text>
              {(liveNasPools.length > 0 ? liveNasPools : state.nas?.pools || []).map((p: any, idx: number) => {
                const sel = idx === cursorIdx % Math.max(1, liveNasPools.length || state.nas?.pools?.length || 1);
                return (
                  <Text key={p.name || idx} color="white" wrap="truncate-end">
                    <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                    Pool <Text bold color="cyan">{(p.name || 'tank').padEnd(12, ' ')}</Text>{' '}
                    <Text color={p.health === 'ONLINE' ? 'green' : 'yellow'}>[{p.health || p.topology || 'ONLINE'}]</Text>{' '}
                    Size: {p.size || '-'} · Used: {p.alloc || '-'} · Free: {p.free || '-'}
                  </Text>
                );
              })}
            </Box>
          )}
          {stSubView === 'datasets' && (
            <Box flexDirection="column" marginTop={1}>
              <Text bold color="white">Configured ZFS Datasets (Press [s] to snapshot selected dataset):</Text>
              {(state.nas?.datasets || []).length === 0 ? (
                <Text color="gray">  No datasets configured in /etc/axonwall/storage.yaml.</Text>
              ) : (
                (state.nas?.datasets || []).map((ds: any, idx: number) => {
                  const sel = idx === cursorIdx % Math.max(1, (state.nas?.datasets || []).length);
                  return (
                    <Text key={`${ds.pool}/${ds.name}`} wrap="truncate-end">
                      <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                      <Text bold color="cyan">{`${ds.pool || 'tank'}/${ds.name}`.padEnd(26, ' ')}</Text>
                      <Text color="yellow">{`Comp: ${ds.compression || 'lz4'}`.padEnd(14, ' ')}</Text>
                      <Text color="white">Quota: {ds.quota || 'none'} · Mount: {ds.mountpoint || 'auto'}</Text>
                    </Text>
                  );
                })
              )}
            </Box>
          )}
          {stSubView === 'snapshots' && (
            <Box flexDirection="column" marginTop={1}>
              <Text bold color="white">Live ZFS Snapshots ({liveNasSnapshots.length}) — Press [s] to create snapshot:</Text>
              {liveNasSnapshots.length === 0 ? (
                <Text color="gray">  No live NAS snapshots found. Press [s] to create a snapshot.</Text>
              ) : (
                liveNasSnapshots.slice(0, 11).map((sn: any, idx: number) => (
                  <Text key={sn.name || idx} wrap="truncate-end">
                    {'  '}• <Text bold color="cyan">{(sn.name || sn).toString().padEnd(36, ' ')}</Text>{' '}
                    <Text color="yellow">Used: {sn.used || '-'}</Text>{' '}
                    <Text color="gray">{sn.creation || ''}</Text>
                  </Text>
                ))
              )}
            </Box>
          )}
          {stSubView === 'shares' && (
            <Box flexDirection="column" marginTop={1}>
              <Text bold color="white">SMB Shares ({state.nas?.smbShares?.length || 0}) & NFSv4 Exports ({state.nas?.nfsExports?.length || 0}):</Text>
              {(state.nas?.smbShares || []).map((sh: any, idx: number) => (
                <Text key={sh.name || idx} wrap="truncate-end">
                  {'  '}• <Text color="green">[SMB]</Text> <Text bold color="white">{sh.name.padEnd(16, ' ')}</Text> Path: <Text color="cyan">{sh.path}</Text>
                </Text>
              ))}
              {(state.nas?.nfsExports || []).map((nf: any, idx: number) => (
                <Text key={nf.path || idx} wrap="truncate-end">
                  {'  '}• <Text color="yellow">[NFS]</Text> <Text bold color="cyan">{nf.path.padEnd(24, ' ')}</Text> Network: <Text color="white">{nf.network || '*'}</Text>
                </Text>
              ))}
            </Box>
          )}
          {storageOutput && (
            <Box borderStyle="single" borderColor="green" paddingX={1} flexDirection="column" marginTop={1}>
              <Text color="green">{storageOutput}</Text>
            </Box>
          )}
        </Box>
      )}

      {activeTab === 'compute' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1} gap={0}>
          <Text bold color="cyan" wrap="truncate-end">
            K3s + OpenEBS, KVM/LXC Hypervisor & Vigilante SOC [{cmpSubView.toUpperCase()}]{' '}
            <Text color="gray" bold={false}>— [n] View · [↑/↓] Select · [Space] Toggle · [k] kubectl · [v] virsh</Text>
          </Text>
          {cmpSubView === 'roles' &&
            [
              {
                id: 'core-k3s',
                name: 'K3s Kubernetes Cluster + OpenEBS LocalPV',
                enabled: caps.k3sEnabled,
                detail: `CIDR: ${state.k3s?.clusterCidr || '10.42.0.0/16'}, OpenEBS ZFS`,
              },
              {
                id: 'core-virt',
                name: 'KVM/QEMU & LXC Virtualization Hypervisor',
                enabled: caps.virtEnabled,
                detail: `${liveVms.length || state.virt?.vms?.length || 0} KVM VMs, ${liveContainers.length || state.virt?.containers?.length || 0} LXC containers`,
              },
              {
                id: 'core-vigilante',
                name: 'Vigilante Autonomous SOC & Threat Hunting',
                enabled: caps.vigilanteEnabled,
                detail: `${soarBlockedIps.length} SOAR blocked IPs, automated IOC containment`,
              },
              {
                id: 'vigilant-octo-waffle',
                name: 'Vigilant Octo Waffle (K8s GitOps Platform)',
                enabled: isPluginEnabled('vigilant-octo-waffle', state),
                detail: 'In-house K3s GitOps & App Platform (requires core-k3s)',
              },
              {
                id: 'eluvix',
                name: 'Eluvix Sovereign AI Router & Prompt Guard',
                enabled: isPluginEnabled('eluvix', state),
                detail: 'Enterprise Tokenomics & PII Guard (:3588)',
              },
              {
                id: 'host-malware-rootkit',
                name: 'Host Malware, Rootkit & Kernel Hunter',
                enabled: isPluginEnabled('host-malware-rootkit', state),
                detail: 'rkhunter, AIDE, YARA, io_uring & eBPF ring audit',
              },
            ].map((r, idx) => {
              const sel = idx === cursorIdx % 6;
              return (
                <Text key={r.id} wrap="truncate-end">
                  <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                  <Text color={r.enabled ? 'green' : 'gray'} bold>{r.enabled ? '[ENABLED]  ' : '[DISABLED] '}</Text>
                  <Text bold={sel} color="white">{r.name.padEnd(42, ' ')}</Text>
                  <Text color="gray">{r.detail}</Text>
                </Text>
              );
            })}
          {cmpSubView === 'vms' && (
            <Box flexDirection="column">
              <Text bold color="white">KVM Virtual Machines ({liveVms.length}) — [s] Start · [x] Stop · [b] Reset:</Text>
              {liveVms.length === 0 ? (
                <Text color="gray">  No KVM virtual machines registered.</Text>
              ) : (
                liveVms.map((vm: any, idx: number) => {
                  const sel = idx === cursorIdx % liveVms.length;
                  return (
                    <Text key={vm.vmid || idx} wrap="truncate-end">
                      <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                      <Text color={vm.status === 'running' ? 'green' : 'gray'} bold>
                        {`[${(vm.status || 'stopped').toUpperCase()}]`.padEnd(11, ' ')}
                      </Text>
                      <Text bold color="cyan">{`VM #${vm.vmid}`.padEnd(9, ' ')}</Text>
                      <Text bold color="white">{(vm.name || 'vm').padEnd(20, ' ')}</Text>
                      <Text color="yellow">{`${vm.cpus || 2} vCPU / ${vm.memoryMb || 2048} MB`}</Text>
                    </Text>
                  );
                })
              )}
            </Box>
          )}
          {cmpSubView === 'containers' && (
            <Box flexDirection="column">
              <Text bold color="white">LXC System Containers ({liveContainers.length}) — [s] Start · [x] Stop:</Text>
              {liveContainers.length === 0 ? (
                <Text color="gray">  No LXC containers registered.</Text>
              ) : (
                liveContainers.map((ct: any, idx: number) => {
                  const sel = idx === cursorIdx % liveContainers.length;
                  return (
                    <Text key={ct.ctid || idx} wrap="truncate-end">
                      <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                      <Text color={ct.status === 'running' ? 'green' : 'gray'} bold>
                        {`[${(ct.status || 'stopped').toUpperCase()}]`.padEnd(11, ' ')}
                      </Text>
                      <Text bold color="cyan">{`CT #${ct.ctid}`.padEnd(9, ' ')}</Text>
                      <Text bold color="white">{(ct.name || 'ct').padEnd(20, ' ')}</Text>
                      <Text color="yellow">{`${ct.cpus || 1} vCPU / ${ct.memoryMb || 512} MB`}</Text>
                    </Text>
                  );
                })
              )}
            </Box>
          )}
          {cmpSubView === 'soc' && (
            <Box flexDirection="column">
              <Text bold color="white">
                Vigilante SOAR Blocked IPs ({soarBlockedIps.length}) — [b] Block IP · [u] Unblock Selected · [h] Rootkit Audit:
              </Text>
              {soarBlockedIps.length === 0 ? (
                <Text color="gray">  No IPs currently quarantined in SOAR blocklist.</Text>
              ) : (
                soarBlockedIps.slice(0, 8).map((item: any, idx: number) => {
                  const sel = idx === cursorIdx % soarBlockedIps.length;
                  return (
                    <Text key={item.ip || idx} wrap="truncate-end">
                      <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                      <Text color="red" bold>[BLOCKED] </Text>
                      <Text bold color="white">{(item.ip || '').padEnd(20, ' ')}</Text>
                      <Text color="gray">Expires: {item.expiresAt || 'permanent'}</Text>
                    </Text>
                  );
                })
              )}
              {rootkitStatus && (
                <Text color="cyan" wrap="truncate-end">
                  Rootkit & Kernel Hunter: {rootkitStatus.summary || `Scanners ready (${(rootkitStatus.scanners || []).length})`}
                </Text>
              )}
            </Box>
          )}
          {computeOutput && (
            <Box borderStyle="single" borderColor="green" paddingX={1} flexDirection="column" marginTop={1}>
              <Text color="green">{computeOutput}</Text>
            </Box>
          )}
        </Box>
      )}

      {activeTab === 'plugins' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1}>
          <Text bold color="cyan" wrap="truncate-end">
            Appliance Roles, Extension Plugins & Shell ({pluginsViewport.activeIndex + 1}/{BUILTIN_PLUGINS.length}){' '}
            <Text color="gray" bold={false}>— [↑/↓] Select · [Space] Toggle · [i] Install · [u] Uninstall · [s] Re-sync · [a] Apply</Text>
          </Text>
          <Text color="green" wrap="truncate-end">
            ★ Oh My Zsh + Starship + Neovim Super Configurator ENABLED BY DEFAULT (git, kubectl, helm, systemd, sudo, tmux, axonwall).
          </Text>
          {pluginsViewport.slice.map((p, i) => {
            const absIdx = pluginsViewport.startIndex + i;
            const sel = absIdx === pluginsViewport.activeIndex;
            const isCore = CORE_ROLE_PLUGIN_IDS.has(p.id);
            const enabled = isCore
              ? p.id === 'core-firewall'
                ? caps.firewallEnabled
                : p.id === 'core-nas'
                  ? caps.nasEnabled
                  : p.id === 'core-k3s'
                    ? caps.k3sEnabled
                    : p.id === 'core-virt'
                      ? caps.virtEnabled
                      : caps.vigilanteEnabled
              : isPluginEnabled(p.id, state);
            const hostInfo = hostPlugins[p.id];
            const pkgStatus = isCore
              ? 'Core Role'
              : hostInfo?.bundled
                ? 'Bundled'
                : hostInfo?.installed
                  ? 'Installed'
                  : p.defaultEnabled
                    ? 'Default ON'
                    : 'Extension';
            return (
              <Text key={p.id} wrap="truncate-end">
                <Text color={sel ? 'cyan' : 'gray'} bold>
                  {sel ? '▶ ' : '  '}
                </Text>
                <Text color={enabled ? 'green' : 'gray'} bold>
                  {enabled ? '[ENABLED]  ' : '[DISABLED] '}
                </Text>
                <Text color={hostInfo?.installed || hostInfo?.bundled || isCore ? 'green' : 'yellow'}>
                  {`[${pkgStatus}]`.padEnd(13, ' ')}
                </Text>
                <Text bold={sel} color={sel ? 'white' : 'cyan'}>
                  {p.id.padEnd(24, ' ')}
                </Text>
                <Text color="white">
                  {p.name}
                  {p.dependencies && p.dependencies.length > 0 ? ` [req: ${p.dependencies.join(', ')}]` : ''}
                </Text>
              </Text>
            );
          })}
        </Box>
      )}

      {activeTab === 'nastymap' && (
        <NastyMapApp embedded={true} detectedSubnets={detectedSubnets} readOnly={readOnly} />
      )}

      {activeTab === 'updates' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1}>
          {installMode === 'zbm' ? (
            <>
              <Text bold color="cyan" wrap="truncate-end">
                ZFSBootMenu Root-on-ZFS System Updates & Boot Environments [{updSubView.toUpperCase()}]{' '}
                <Text color="gray" bold={false}>
                  — [n] View (BEs / Snapshots / Health) · [s] Create Snapshot · [c] Clone · [b] Activate BE · [x] Delete · [h] Verify
                </Text>
              </Text>
              <Text wrap="truncate-end">
                Pool: <Text bold color="cyan">{partitionStatus?.zbmPoolName || 'zroot'}</Text>{' '}
                (<Text color="green">{partitionStatus?.zbmPoolHealth || 'ONLINE'}</Text>) · Active Root:{' '}
                <Text bold color="yellow">{partitionStatus?.activeRootDevice || 'zroot/ROOT/default'}</Text> · Watchdog:{' '}
                <Text bold color={partitionStatus?.healthVerified ? 'green' : 'yellow'}>
                  {partitionStatus?.healthVerified ? 'VERIFIED (bootcount=0)' : `PENDING (${partitionStatus?.bootCount || 0}/${partitionStatus?.bootLimit || 3})`}
                </Text>
              </Text>
              {updSubView === 'be' && (
                <Box flexDirection="column" marginTop={1}>
                  <Text bold color="white">
                    ZFS Boot Environments ({(partitionStatus?.bootEnvironments || []).length}) — [s] Snapshot Selected BE · [b] Activate for Next Boot · [x] Delete:
                  </Text>
                  {zbmBeViewport.slice.length === 0 ? (
                    <Text color="gray">  No ZFS Boot Environments discovered.</Text>
                  ) : (
                    zbmBeViewport.slice.map((be: any, i: number) => {
                      const absIdx = zbmBeViewport.startIndex + i;
                      const sel = absIdx === zbmBeViewport.activeIndex;
                      return (
                        <Text key={be.dataset || be.name || absIdx} wrap="truncate-end">
                          <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                          <Text color={be.activeNow ? 'green' : 'gray'} bold>
                            {be.activeNow ? '[ACTIVE NOW] ' : '             '}
                          </Text>
                          <Text color={be.activeNext ? 'magenta' : 'gray'} bold>
                            {be.activeNext ? '[NEXT BOOT] ' : '            '}
                          </Text>
                          <Text bold color="white">{(be.name || '').padEnd(22, ' ')}</Text>
                          <Text color="cyan">{(be.dataset || '').padEnd(30, ' ')}</Text>
                          <Text color="yellow">{`Used: ${(be.usedSize || '-').padEnd(8, ' ')}`}</Text>
                          <Text color="gray">Snaps: {be.snapshots?.length || 0} · {be.createdAt || ''}</Text>
                        </Text>
                      );
                    })
                  )}
                </Box>
              )}
              {updSubView === 'snapshots' && (
                <Box flexDirection="column" marginTop={1}>
                  <Text bold color="white">
                    ZFS Boot Environment Snapshots ({allZbmSnapshots.length}) — [s] New Snapshot · [c] Clone to Boot Env · [x] Destroy Snapshot:
                  </Text>
                  {zbmSnapViewport.slice.length === 0 ? (
                    <Text color="gray">  No ZFS Boot Environment snapshots yet. Press [s] to create an arbitrary snapshot!</Text>
                  ) : (
                    zbmSnapViewport.slice.map((sn: any, i: number) => {
                      const absIdx = zbmSnapViewport.startIndex + i;
                      const sel = absIdx === zbmSnapViewport.activeIndex;
                      return (
                        <Text key={sn.fullName || absIdx} wrap="truncate-end">
                          <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶ ' : '  '}</Text>
                          <Text bold color="cyan">{(sn.name || '').padEnd(24, ' ')}</Text>
                          <Text color="white">{(sn.fullName || '').padEnd(42, ' ')}</Text>
                          <Text color="yellow">{`Used: ${(sn.usedSize || '-').padEnd(7, ' ')} Refer: ${(sn.referSize || '-').padEnd(7, ' ')}`}</Text>
                          <Text color="gray">{sn.createdAt || ''}</Text>
                        </Text>
                      );
                    })
                  )}
                </Box>
              )}
              {updSubView === 'checks' && (
                <Box flexDirection="column" marginTop={1}>
                  <Text bold color="white">Boot Watchdog Health Quorum Checks ({(partitionStatus?.checks || []).length}):</Text>
                  {(partitionStatus?.checks || []).map((chk: any, idx: number) => (
                    <Text key={chk.name || idx} wrap="truncate-end">
                      {'  '}
                      <Text color={chk.status === 'PASS' ? 'green' : chk.status === 'WARN' ? 'yellow' : 'red'} bold>
                        [{chk.status}]
                      </Text>{' '}
                      <Text bold color="white">{(chk.name || '').padEnd(28, ' ')}</Text>{' '}
                      <Text color="gray">{chk.detail} ({chk.durationMs || 0}ms)</Text>
                    </Text>
                  ))}
                </Box>
              )}
            </>
          ) : (
            <>
              <Text bold color="cyan" wrap="truncate-end">
                {installMode === 'rolling' ? 'Rolling Standard Linux System Updates' : 'Dual-Root A/B Partition System Updates'}{' '}
                <Text color="gray" bold={false}>— [b] Activate Standby Slot · [h] Verify Health</Text>
              </Text>
              <Text wrap="truncate-end">
                Active Slot: <Text bold color="green">Slot {partitionStatus?.activeSlot || 'A'}</Text> ({partitionStatus?.slotAVersion || 'current'}) · Standby Slot:{' '}
                <Text bold color="yellow">Slot {partitionStatus?.inactiveSlot || 'B'}</Text> ({partitionStatus?.slotBVersion || 'standby'}) · Health:{' '}
                <Text bold color={partitionStatus?.healthVerified ? 'green' : 'yellow'}>
                  {partitionStatus?.healthVerified ? 'VERIFIED' : 'PENDING'}
                </Text>
              </Text>
              <Box flexDirection="column" marginTop={1}>
                <Text bold color="white">Boot Watchdog Health Checks:</Text>
                {(partitionStatus?.checks || []).map((chk: any, idx: number) => (
                  <Text key={chk.name || idx} wrap="truncate-end">
                    {'  '}
                    <Text color={chk.status === 'PASS' ? 'green' : 'red'} bold>[{chk.status}]</Text>{' '}
                    <Text color="white">{chk.name}: </Text>
                    <Text color="gray">{chk.detail}</Text>
                  </Text>
                ))}
              </Box>
            </>
          )}
        </Box>
      )}

      {activeTab === 'cli_ops' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" paddingX={1}>
          <Text bold color="cyan" wrap="truncate-end">
            System Administration, Directory, GitOps & CLI Ops [{opsSubView.toUpperCase()}]{' '}
            <Text color="gray" bold={false}>— [n] View (Toolkit / Users / GitOps / Power) · [↑/↓] Select · [Enter/Space] Execute</Text>
          </Text>
          {opsSubView === 'toolkit' && (
            <>
              {cliTools.map((t, idx) => {
                const sel = idx === cursorIdx % cliTools.length;
                return (
                  <Text key={t.id} wrap="truncate-end">
                    <Text color={sel ? 'cyan' : 'gray'} bold>
                      {sel ? '▶ ' : '  '}
                    </Text>
                    <Text bold={sel} color={sel ? 'green' : 'white'}>
                      {t.name.padEnd(38, ' ')}
                    </Text>
                    <Text color="gray">{t.desc}</Text>
                  </Text>
                );
              })}
              {cliOutput && (
                <Box
                  marginTop={1}
                  borderStyle="single"
                  borderColor="green"
                  paddingX={1}
                  flexDirection="column"
                >
                  <Text color="green">{cliOutput}</Text>
                </Box>
              )}
            </>
          )}
          {opsSubView === 'users' && (
            <Box flexDirection="column">
              <Text wrap="truncate-end">
                OpenLDAP Directory:{' '}
                <Text bold color={directoryStatus?.slapdRunning ? 'green' : 'yellow'}>
                  {directoryStatus?.slapdRunning ? 'ONLINE' : 'LOCAL PAM'}
                </Text>{' '}
                · Base DN: <Text color="cyan">{directoryStatus?.baseDn || 'dc=axonwall,dc=local'}</Text> · Users: <Text bold color="white">{directoryUsers.length}</Text>
              </Text>
              {directoryUsers.slice(0, 12).map((u: any, idx: number) => (
                <Text key={u.username || idx} wrap="truncate-end">
                  {'  '}• <Text bold color="cyan">{(u.username || '').padEnd(16, ' ')}</Text>{' '}
                  <Text color="yellow">{`[${(u.applianceRole || 'operator').toUpperCase()}]`.padEnd(12, ' ')}</Text>{' '}
                  <Text color="white">UID: {String(u.uid || '-').padEnd(7, ' ')} Shell: {(u.shell || '/bin/zsh').padEnd(15, ' ')}</Text>{' '}
                  <Text color="gray">SSH Keys: {u.sshKeys?.length || 0}</Text>
                </Text>
              ))}
            </Box>
          )}
          {opsSubView === 'gitops' && (
            <Box flexDirection="column">
              <Text bold color="white">Etckeeper /etc Git Commit History ({etckeeperHistory.length}) — Press [s] to commit snapshot:</Text>
              {etckeeperHistory.length === 0 ? (
                <Text color="gray">  No etckeeper commits recorded yet. Press [s] to create an /etc git commit.</Text>
              ) : (
                etckeeperHistory.slice(0, 11).map((h: any, idx: number) => (
                  <Text key={h.commit || h.hash || idx} wrap="truncate-end">
                    {'  '}• <Text bold color="yellow">{(h.commit || h.hash || '').slice(0, 8)}</Text>{' '}
                    <Text color="cyan">{(h.date || h.timestamp || '').slice(0, 19).padEnd(20, ' ')}</Text>{' '}
                    <Text color="white">{h.message || h.subject || ''}</Text>
                  </Text>
                ))
              )}
            </Box>
          )}
          {opsSubView === 'power' && (
            <Box flexDirection="column">
              <Text bold color="white">Hardware Telemetry & System Environment:</Text>
              <Text wrap="truncate-end">  • CPU Model    : <Text color="cyan">{hwTelemetry?.cpuModel || os.cpus()[0]?.model || 'x86_64'}</Text> ({os.cpus().length} logical cores)</Text>
              <Text wrap="truncate-end">  • Kernel / OS  : <Text color="yellow">{os.type()} {os.release()} ({os.arch()})</Text></Text>
              <Text wrap="truncate-end">  • System Uptime: <Text color="green">{Math.floor(os.uptime() / 3600)}h {Math.floor((os.uptime() % 3600) / 60)}m</Text></Text>
              <Text wrap="truncate-end">  • Thermal Zones: <Text color="cyan">{(hwTelemetry?.temperatures || []).map((t: any) => `${t.label}: ${t.celsius}°C`).join(', ') || 'Nominal'}</Text></Text>
            </Box>
          )}
        </Box>
      )}

      {/* Status Bar & Hotkey Legend */}
      <Box marginTop={0} flexDirection="column" paddingX={1}>
        <Text color={readOnly ? 'yellow' : 'green'} wrap="truncate-end">{statusMessage}</Text>
        <Text color="gray" wrap="truncate-end">
          {readOnly
            ? '[1-9,u,0/Tab] Switch Tabs · [n] Subview · [d] Reload · [q] Quit [READ-ONLY]'
            : '[1-9,u,0/Tab] Switch Tabs · [n] Subview · [a] Apply · [c] Confirm · [r] Rollback · [d] Reload · [q] Quit'}
        </Text>
      </Box>
    </Box>
  );
}

export function resolveTabFromArg(val: string): TopTab {
  const v = val.toLowerCase();
  if (v === 'nastymap' || v === 'nmap') return 'nastymap';
  if (v === 'routing' || v === 'routes' || v === 'frr') return 'routing';
  if (v === 'firewall' || v === 'fw' || v === 'nat') return 'firewall';
  if (v === 'interfaces' || v === 'if' || v === 'vlans') return 'interfaces';
  if (v === 'services' || v === 'vpn' || v === 'mcp') return 'services';
  if (v === 'storage' || v === 'zfs' || v === 'nas') return 'storage';
  if (v === 'compute' || v === 'k3s' || v === 'virt' || v === 'vigilante') return 'compute';
  if (v === 'plugins' || v === 'shell') return 'plugins';
  if (v === 'updates' || v === 'update' || v === 'zbm' || v === 'be' || v === 'bootenv') return 'updates';
  if (
    v === 'cli' ||
    v === 'ops' ||
    v === 'cli_ops' ||
    v === 'cli-tools' ||
    v === 'logs' ||
    v === 'users' ||
    v === 'gitops' ||
    v === 'system'
  )
    return 'cli_ops';
  return 'dashboard';
}

// Parse CLI arguments (--tab nastymap, --readonly, etc.)
const isDirectExecution =
  process.argv[1] &&
  (process.argv[1].endsWith('axonwall-tui.js') ||
    process.argv[1].endsWith('axonwall-tui.tsx') ||
    process.argv[1].endsWith('axonwall-tui'));

if (isDirectExecution) {
  const args = process.argv.slice(2);
  let startTab: TopTab = 'dashboard';
  let readOnlyMode = process.env.AXONWALL_TUI_READONLY === '1';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h' || arg === 'help') {
      console.log(`axonwall-tui — Unified Axonwall Appliance Ink TUI

Usage:
  axonwall-tui [--tab <tab>] [--readonly]

Tabs:
  dashboard, interfaces, firewall (nat), routing, services (vpn, mcp),
  storage (zfs), compute (k3s, virt, vigilante), plugins (shell),
  nastymap, cli_ops (users, gitops, logs), updates (zbm, be)`);
      process.exit(0);
    } else if (arg === '--readonly' || arg === '-r') {
      readOnlyMode = true;
    } else if ((arg === '--tab' || arg === '-t' || arg === '--view') && args[i + 1]) {
      startTab = resolveTabFromArg(args[++i]!);
    } else if (arg?.startsWith('--view=')) {
      startTab = resolveTabFromArg(arg.slice(7));
    } else if (arg?.startsWith('--tab=')) {
      startTab = resolveTabFromArg(arg.slice(6));
    }
  }

  render(<AxonwallTuiApp initialTab={startTab} readOnly={readOnlyMode} />);
}
