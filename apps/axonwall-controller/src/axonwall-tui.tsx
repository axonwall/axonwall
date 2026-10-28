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
import type { DesiredState } from '@axonwall/lib/schemas';
import { App as NastyMapApp } from './tui/nastymap/App.js';

const ETC_CONFIG_DIR = process.env.AXONWALL_CONFIG_DIR || '/etc/axonwall';
const VAR_ETC_CONFIG_DIR = '/var/lib/axonwall/etc-axonwall';
const STATE_JSON_PATH = process.env.AXONWALL_STATE_FILE || '/var/lib/axonwall/state.json';
const AGENT_API_SOCKET = process.env.AGENT_API_SOCKET || '/run/axonwall/agent-api.sock';
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
  | 'cli_ops';

const TOP_TABS: Array<{ id: TopTab; key: string; label: string }> = [
  { id: 'dashboard', key: '1', label: 'Dashboard' },
  { id: 'interfaces', key: '2', label: 'Interfaces' },
  { id: 'firewall', key: '3', label: 'Firewall & NAT' },
  { id: 'routing', key: '4', label: 'Routing & FRR' },
  { id: 'services', key: '5', label: 'Services & MCP' },
  { id: 'storage', key: '6', label: 'ZFS Storage' },
  { id: 'compute', key: '7', label: 'K3s, Virt & SOC' },
  { id: 'plugins', key: '8', label: 'Plugins & Shell' },
  { id: 'nastymap', key: '9', label: 'NastyMap' },
  { id: 'cli_ops', key: '0', label: 'CLI Ops & Logs' },
];

function readLayeredYamlMap(): Record<string, string> {
  const files: Record<string, string> = {};
  for (const filename of AXONWALL_YAML_FILENAMES) {
    const etcPath = path.join(ETC_CONFIG_DIR, filename);
    const varPath = path.join(VAR_ETC_CONFIG_DIR, filename);
    const etcExists = fs.existsSync(etcPath);
    const varExists = fs.existsSync(varPath);
    if (etcExists && varExists) {
      const etcMtime = fs.statSync(etcPath).mtimeMs;
      const varMtime = fs.statSync(varPath).mtimeMs;
      files[filename] = fs.readFileSync(etcMtime >= varMtime ? etcPath : varPath, 'utf-8');
    } else if (etcExists) {
      files[filename] = fs.readFileSync(etcPath, 'utf-8');
    } else if (varExists) {
      files[filename] = fs.readFileSync(varPath, 'utf-8');
    }
  }
  return files;
}

function loadCurrentState(): DesiredState {
  const files = readLayeredYamlMap();
  if (Object.keys(files).length > 0) {
    try {
      let base: Partial<DesiredState> | undefined;
      if (fs.existsSync(STATE_JSON_PATH)) {
        base = JSON.parse(fs.readFileSync(STATE_JSON_PATH, 'utf-8'));
      }
      return parseDesiredStateFromYamlFiles(files, base);
    } catch {}
  }
  if (fs.existsSync(STATE_JSON_PATH)) {
    try {
      return parseDesiredStateFromYamlFiles({}, JSON.parse(fs.readFileSync(STATE_JSON_PATH, 'utf-8')));
    } catch {}
  }
  return parseDesiredStateFromYamlFiles({});
}

function saveStateToDisk(state: DesiredState): Record<string, string> {
  const serialized = serializeDesiredStateToYamlFiles(state);
  const daemonFiles: Record<string, string> = {};
  for (const [fn, content] of Object.entries(serialized)) {
    daemonFiles[path.join(ETC_CONFIG_DIR, fn)] = content;
    daemonFiles[path.join(VAR_ETC_CONFIG_DIR, fn)] = content;
  }
  for (const dir of [VAR_ETC_CONFIG_DIR, ETC_CONFIG_DIR]) {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      for (const [fn, content] of Object.entries(serialized)) {
        const filePath = path.join(dir, fn);
        fs.writeFileSync(filePath, content, { encoding: 'utf-8', mode: 0o600 });
        try {
          fs.chmodSync(filePath, 0o600);
        } catch {}
      }
    } catch {}
  }
  try {
    fs.mkdirSync(path.dirname(STATE_JSON_PATH), { recursive: true, mode: 0o700 });
    fs.writeFileSync(STATE_JSON_PATH, JSON.stringify(state, null, 2), { encoding: 'utf-8', mode: 0o600 });
    try {
      fs.chmodSync(STATE_JSON_PATH, 0o600);
    } catch {}
  } catch {}
  return daemonFiles;
}

function callDaemon(endpoint: string, method: 'GET' | 'POST', payload?: unknown): Promise<any> {
  return new Promise((resolve) => {
    if (!fs.existsSync(AGENT_API_SOCKET)) {
      resolve(null);
      return;
    }
    const body = payload ? JSON.stringify(payload) : '';
    let token = '';
    try {
      token = fs.readFileSync(AGENT_TOKEN_PATH, 'utf-8').trim();
    } catch {}

    const req = http.request(
      {
        socketPath: AGENT_API_SOCKET,
        path: endpoint,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        timeout: 4000,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(null);
          }
        });
      }
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
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

export function AxonwallTuiApp({
  initialTab = 'dashboard',
  readOnly = false,
}: {
  initialTab?: TopTab;
  readOnly?: boolean;
}) {
  const { exit } = useApp();
  const [activeTab, setActiveTab] = useState<TopTab>(initialTab);
  const [fwSubView, setFwSubView] = useState<'rules' | 'nat' | 'aliases'>('rules');
  const [state, setState] = useState<DesiredState>(() => loadCurrentState());
  const [daemonStatus, setDaemonStatus] = useState<any>(null);
  const [mcpStatus, setMcpStatus] = useState<{ masterEnabled: boolean; leases?: any[]; disabledReason?: string }>({
    masterEnabled: false,
    disabledReason: 'Disabled by default',
  });
  const [hostPlugins, setHostPlugins] = useState<Record<string, any>>({});
  const [statusMessage, setStatusMessage] = useState<string>(
    readOnly
      ? 'Ready [READ-ONLY OPERATOR MODE] — Use [1-9,0] or [Tab] to inspect tabs, [↑/↓] to scroll, [q] to exit.'
      : 'Ready — Use [1-9,0] or [Tab] to switch tabs, [↑/↓] to select, [Space] to toggle, [a] to apply, [q] to exit.'
  );
  const [cursorIdx, setCursorIdx] = useState<number>(0);
  const [cliOutput, setCliOutput] = useState<string>('');
  const [storageOutput, setStorageOutput] = useState<string>('');
  const [computeOutput, setComputeOutput] = useState<string>('');

  const refreshAll = useCallback(async () => {
    const fresh = loadCurrentState();
    setState(fresh);
    const [st, mcp, plg] = await Promise.all([
      callDaemon('/v1/status', 'GET'),
      callDaemon('/v1/mcp/status', 'GET'),
      callDaemon('/v1/system/plugins', 'GET'),
    ]);
    if (st) setDaemonStatus(st);
    if (mcp && typeof mcp.masterEnabled === 'boolean') {
      setMcpStatus(mcp);
    }
    if (plg?.plugins && Array.isArray(plg.plugins)) {
      const map: Record<string, any> = {};
      for (const p of plg.plugins) {
        map[p.id] = p;
      }
      setHostPlugins(map);
    }
  }, []);

  useEffect(() => {
    refreshAll();
    const timer = setInterval(refreshAll, 3000);
    return () => clearInterval(timer);
  }, [refreshAll]);

  const handleApplyConfig = async () => {
    setStatusMessage('Compiling nftables & subsystem configurations and applying with 120s commit-confirm...');
    const yamlDaemonFiles = saveStateToDisk(state);
    const { nftScript, files, reloadServices } = compileNftables(state);
    const bundleHash = crypto.createHash('sha256').update(nftScript).digest('hex');

    const allFiles = [
      ...files.map((f: any) => ({
        ...f,
        fileMode: f.fileMode ?? f.file_mode ?? 0o600,
        file_mode: f.file_mode ?? f.fileMode ?? 0o600,
      })),
      ...Object.entries(yamlDaemonFiles).map(([filePath, content]) => ({
        path: filePath,
        content,
        fileMode: 0o600,
        file_mode: 0o600,
      })),
    ];

    const resp = await callDaemon('/v1/apply', 'POST', {
      job_id: `tui-${Date.now()}`,
      bundle_hash: bundleHash,
      nft_script: nftScript,
      files: allFiles,
      reload_services: reloadServices,
      confirm_timeout_seconds: 120,
    });

    if (resp?.success) {
      setStatusMessage('✔ Applied to live daemon! Press [c] within 120s to confirm, or [r] to rollback.');
      await refreshAll();
    } else {
      setStatusMessage('✔ Saved to /etc/axonwall/*.yaml (daemon socket offline or mock mode).');
    }
  };

  const handleConfirm = async () => {
    const resp = await callDaemon('/v1/confirm', 'POST');
    if (resp?.success) {
      setStatusMessage('✔ Configuration confirmed and persisted as last-known-good!');
      await refreshAll();
    } else {
      setStatusMessage('No pending commit-confirm timer active.');
    }
  };

  const handleRollback = async () => {
    const resp = await callDaemon('/v1/rollback', 'POST', { reason: 'TUI operator rollback' });
    if (resp?.success) {
      setStatusMessage('↺ Rolled back to previous last-known-good configuration!');
      await refreshAll();
    } else {
      setStatusMessage('Rollback requested.');
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
    } else if (roleId === 'core-virt') {
      next.virt = { ...(next.virt || ({} as any)), enabled: nextCaps.virtEnabled };
    } else if (roleId === 'core-vigilante') {
      next.vigilante = { ...(next.vigilante || ({} as any)), enabled: nextCaps.vigilanteEnabled };
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
      id: 'wireguard',
      name: 'WireGuard Kernel VPN',
      enabled: Boolean(state.wireguard?.enabled),
      detail: `UDP ${state.wireguard?.listenPort || 51820} (${state.wireguard?.peers?.length || 0} peers)`,
    },
    {
      id: 'rosenpass',
      name: 'Rosenpass Post-Quantum WireGuard PSK',
      enabled: Boolean(state.rosenpass?.enabled),
      detail: `Classic McEliece + Kyber PSK rotation on UDP ${state.rosenpass?.listenPort || 9999}`,
    },
    {
      id: 'headscale',
      name: 'Headscale Mesh Coordination Server',
      enabled: Boolean(state.headscale?.enabled),
      detail: `MagicDNS: ${state.headscale?.magicDnsDomain || 'mesh.axonwall.local'}`,
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
      name: 'High Availability (Keepalived VRRP + Conntrackd)',
      enabled: Boolean(state.ha?.enabled),
      detail: state.ha?.enabled
        ? `${(state.ha?.nodeRole || 'MASTER').toUpperCase()} (${state.ha?.vrrpInstances?.length || 0} VRRP VIPs)`
        : 'Standalone Node',
    },
    {
      id: 'mcp',
      name: 'Axonwall MCP Server (AI Agent Control Plane)',
      enabled: Boolean(mcpStatus.masterEnabled),
      detail: mcpStatus.masterEnabled
        ? `ACTIVE (${mcpStatus.leases?.length || 0} active leases)`
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

  useInput((input, key) => {
    if (input === 'q') {
      exit();
      return;
    }
    if (key.tab) {
      const idx = TOP_TABS.findIndex((t) => t.id === activeTab);
      const nextTab = TOP_TABS[(idx + 1) % TOP_TABS.length]!;
      setActiveTab(nextTab.id);
      setCursorIdx(0);
      return;
    }
    if (input === '1') {
      setActiveTab('dashboard');
      setCursorIdx(0);
    } else if (input === '2') {
      setActiveTab('interfaces');
      setCursorIdx(0);
    } else if (input === '3') {
      setActiveTab('firewall');
      setCursorIdx(0);
    } else if (input === '4') {
      setActiveTab('routing');
      setCursorIdx(0);
    } else if (input === '5') {
      setActiveTab('services');
      setCursorIdx(0);
    } else if (input === '6') {
      setActiveTab('storage');
      setCursorIdx(0);
    } else if (input === '7') {
      setActiveTab('compute');
      setCursorIdx(0);
    } else if (input === '8') {
      setActiveTab('plugins');
      setCursorIdx(0);
    } else if (input === '9') {
      setActiveTab('nastymap');
      setCursorIdx(0);
    } else if (input === '0') {
      setActiveTab('cli_ops');
      setCursorIdx(0);
      if (!cliOutput) runCliToolInline(0);
    } else if (input === 'c') {
      if (readOnly) {
        setStatusMessage('Read-only operator session: confirming commit is disabled.');
        return;
      }
      handleConfirm();
    } else if (input === 'r') {
      if (readOnly) {
        setStatusMessage('Read-only operator session: configuration rollback is disabled.');
        return;
      }
      handleRollback();
    } else if (input === 'a') {
      if (readOnly) {
        setStatusMessage('Read-only operator session: applying configuration changes is disabled.');
        return;
      }
      handleApplyConfig();
    } else if (input === 'd') {
      refreshAll();
      setStatusMessage('Reloaded configuration from /etc/axonwall/*.yaml.');
    }

    if (activeTab === 'nastymap') return;

    if (activeTab === 'firewall' && input === 'n') {
      const order: Array<'rules' | 'nat' | 'aliases'> = ['rules', 'nat', 'aliases'];
      const nextSub = order[(order.indexOf(fwSubView) + 1) % order.length]!;
      setFwSubView(nextSub);
      setCursorIdx(0);
      setStatusMessage(`Switched Firewall view to ${nextSub.toUpperCase()}.`);
      return;
    }

    if (activeTab === 'storage' && input === 's') {
      const zp = execSafe('zpool', ['status']) || 'No live ZFS pools imported in kernel.';
      const zl = execSafe('zfs', ['list']) || '';
      setStorageOutput(`${zp}\n${zl}`.trim());
      setStatusMessage('Queried live ZFS pool & dataset telemetry.');
      return;
    }

    if (activeTab === 'compute' && input === 'k') {
      const ko =
        execSafe('kubectl', ['get', 'nodes,pods', '-A', '-o', 'wide']) ||
        execSafe('k3s', ['kubectl', 'get', 'nodes,pods', '-A']) ||
        'k3s server not currently running.';
      setComputeOutput(ko);
      setStatusMessage('Queried live Kubernetes (k3s) cluster status.');
      return;
    }

    if (activeTab === 'compute' && input === 'v') {
      const vo =
        execSafe('virsh', ['list', '--all']) ||
        execSafe('lxc-ls', ['--fancy']) ||
        'libvirtd / LXC not currently running.';
      setComputeOutput(vo);
      setStatusMessage('Queried live KVM/LXC hypervisor domains.');
      return;
    }

    if (activeTab === 'plugins' && !readOnly && (input === 'i' || input === 'u' || input === 's')) {
      const plg = BUILTIN_PLUGINS[cursorIdx % BUILTIN_PLUGINS.length]!;
      if (CORE_ROLE_PLUGIN_IDS.has(plg.id)) {
        setStatusMessage(`Core role '${plg.id}' is built into the appliance image. Use [Space] to enable/disable.`);
        return;
      }
      const action = input === 'i' ? 'install' : input === 'u' ? 'uninstall' : 'reconfigure';
      setStatusMessage(`Executing '${action}' for plugin '${plg.id}'...`);
      callDaemon('/v1/system/plugins/action', 'POST', { pluginId: plg.id, action }).then((res) => {
        if (res?.success) {
          setStatusMessage(`✔ ${res.message}`);
        } else {
          setStatusMessage(`Plugin ${action} finished (${res?.message || 'daemon offline'}).`);
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
      if (activeTab === 'interfaces' && state.interfaces[cursorIdx]) {
        const next = structuredClone(state);
        const target = next.interfaces[cursorIdx]!;
        target.enabled = !target.enabled;
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(
          `Toggled interface '${target.name}' (${target.device}) -> ${target.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
        );
      } else if (activeTab === 'firewall') {
        if (fwSubView === 'rules' && state.rules[cursorIdx]) {
          const next = structuredClone(state);
          const rule = next.rules[cursorIdx]!;
          rule.enabled = !rule.enabled;
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled firewall rule '${rule.description || rule.id}' -> ${rule.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        } else if (fwSubView === 'nat' && state.nat?.[cursorIdx]) {
          const next = structuredClone(state);
          const nr = next.nat[cursorIdx]!;
          nr.enabled = !nr.enabled;
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled NAT rule '${nr.description || nr.id}' -> ${nr.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        } else if (fwSubView === 'aliases' && state.aliases?.[cursorIdx]) {
          const next = structuredClone(state);
          const al = next.aliases[cursorIdx]!;
          al.enabled = !al.enabled;
          setState(next);
          saveStateToDisk(next);
          setStatusMessage(
            `Toggled alias '${al.name}' -> ${al.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
          );
        }
      } else if (activeTab === 'routing' && state.routes?.[cursorIdx]) {
        const next = structuredClone(state);
        const rt = next.routes![cursorIdx]!;
        rt.enabled = rt.enabled === false ? true : false;
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(
          `Toggled static route '${rt.network} via ${rt.gateway}' -> ${rt.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
        );
      } else if (activeTab === 'services') {
        const row = serviceRows[cursorIdx % serviceRows.length]!;
        if (row.id === 'mcp') {
          const nextEnabled = !mcpStatus.masterEnabled;
          callDaemon('/v1/mcp/toggle', 'POST', {
            enabled: nextEnabled,
            reason: nextEnabled ? undefined : 'Disabled via Axonwall TUI',
          }).then((res) => {
            if (res && typeof res.masterEnabled === 'boolean') {
              setMcpStatus(res);
              setStatusMessage(
                `Toggled MCP Server Master Switch -> ${res.masterEnabled ? 'ENABLED' : 'DISABLED'}.`
              );
            } else {
              setMcpStatus({
                masterEnabled: nextEnabled,
                disabledReason: nextEnabled ? undefined : 'Disabled via Axonwall TUI',
              });
              setStatusMessage(
                `Toggled MCP Server Master Switch -> ${nextEnabled ? 'ENABLED' : 'DISABLED'}.`
              );
            }
          });
          return;
        }
        const next = structuredClone(state);
        if (row.id === 'dhcp') next.dhcp = { ...(next.dhcp || { subnets: [] }), enabled: !next.dhcp?.enabled };
        else if (row.id === 'dns') next.dns = { ...(next.dns || ({} as any)), enabled: !next.dns?.enabled };
        else if (row.id === 'wireguard') {
          next.wireguard = { ...(next.wireguard || ({} as any)), enabled: !next.wireguard?.enabled };
        } else if (row.id === 'rosenpass') {
          next.rosenpass = { ...(next.rosenpass || ({} as any)), enabled: !next.rosenpass?.enabled };
        } else if (row.id === 'headscale') {
          next.headscale = { ...(next.headscale || ({} as any)), enabled: !next.headscale?.enabled };
        } else if (row.id === 'suricata') {
          next.suricata = { ...(next.suricata || ({} as any)), enabled: !next.suricata?.enabled };
        } else if (row.id === 'crowdsec') {
          next.crowdsec = { ...(next.crowdsec || ({} as any)), enabled: !next.crowdsec?.enabled };
        } else if (row.id === 'haproxy') {
          next.haproxy = { ...(next.haproxy || ({} as any)), enabled: !next.haproxy?.enabled };
        } else if (row.id === 'freeradius') {
          next.freeradius = { ...(next.freeradius || ({} as any)), enabled: !next.freeradius?.enabled };
        } else if (row.id === 'snmp') {
          next.snmp = { ...(next.snmp || ({} as any)), enabled: !next.snmp?.enabled };
        } else if (row.id === 'ups') {
          next.ups = { ...(next.ups || ({} as any)), enabled: !next.ups?.enabled };
        } else if (row.id === 'ha') {
          next.ha = { ...(next.ha || ({} as any)), enabled: !next.ha?.enabled };
        }
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(`Toggled ${row.name}. Press [a] to compile & apply.`);
      } else if (activeTab === 'storage') {
        const next = structuredClone(state);
        const nowEnabled = toggleCoreRoleInState(next, 'core-nas');
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(
          `Toggled ZFS NAS & Storage Manager (core-nas) -> ${nowEnabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
        );
      } else if (activeTab === 'compute') {
        const roles = ['core-k3s', 'core-virt', 'core-vigilante'];
        const roleId = roles[cursorIdx % roles.length]!;
        const next = structuredClone(state);
        const nowEnabled = toggleCoreRoleInState(next, roleId);
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(
          `Toggled ${roleId} -> ${nowEnabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`
        );
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
        runCliToolInline(cursorIdx);
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

  return (
    <Box flexDirection="column" paddingX={1}>
      {/* Top Appliance Header */}
      <Box
        borderStyle="round"
        borderColor={pendingConfirm ? 'yellow' : 'green'}
        paddingX={1}
        justifyContent="space-between"
      >
        <Box gap={2}>
          <Text bold color="green">
            🛡️ AXONWALL SSH/CONSOLE TUI
          </Text>
          <Text color="white">
            Host: <Text bold color="cyan">{state.system?.hostname || os.hostname()}</Text>
          </Text>
          <Text color="gray">|</Text>
          <Text color="white">
            Load: <Text color="yellow">{loadStr}</Text>
          </Text>
          <Text color="gray">|</Text>
          <Text color="white">
            RAM: <Text color="cyan">{usedMemGb}/{totalMemGb} GB ({memPct}%)</Text>
          </Text>
        </Box>
        <Box gap={2}>
          {readOnly && (
            <Text bold color="yellow">
              [READ-ONLY OPERATOR MODE]
            </Text>
          )}
          <Text color={mcpStatus.masterEnabled ? 'yellow' : 'gray'}>
            MCP: {mcpStatus.masterEnabled ? 'ON' : 'OFF'}
          </Text>
          <Text color={daemonStatus ? 'green' : 'yellow'}>
            ● {daemonStatus ? 'axonwalld Connected' : 'YAML Direct Mode'}
          </Text>
        </Box>
      </Box>

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
      <Box marginY={1} gap={1} flexWrap="wrap">
        {TOP_TABS.map((t) => {
          const isAct = activeTab === t.id;
          return (
            <Box
              key={t.id}
              borderStyle="single"
              borderColor={isAct ? 'green' : 'gray'}
              paddingX={1}
            >
              <Text bold={isAct} color={isAct ? 'green' : 'white'}>
                [{t.key}] {t.label}
              </Text>
            </Box>
          );
        })}
      </Box>

      {/* Main Content Area */}
      {activeTab === 'dashboard' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1} gap={1}>
          <Text bold color="cyan" underline>
            Appliance Overview & Active Stack (/etc/axonwall/*.yaml)
          </Text>
          <Box gap={4}>
            <Box flexDirection="column" width="50%">
              <Text bold color="white">Configured Network Interfaces ({state.interfaces.length}):</Text>
              {state.interfaces.map((iface) => (
                <Box key={iface.name} gap={2} paddingLeft={1}>
                  <Text color={iface.enabled ? 'green' : 'red'} bold>
                    {iface.enabled ? '● UP  ' : '○ DOWN'}
                  </Text>
                  <Text bold color="white">
                    {iface.name.toUpperCase().padEnd(6, ' ')}
                  </Text>
                  <Text color="cyan">{iface.device.padEnd(8, ' ')}</Text>
                  <Text color="yellow">{(iface.ipv4Address || iface.type).padEnd(18, ' ')}</Text>
                  <Text color="gray">{iface.description || ''}</Text>
                </Box>
              ))}
              <Box marginTop={1} flexDirection="column">
                <Text bold color="white">Active Appliance Core Roles:</Text>
                <Text>
                  {'  '}• Firewall & Gateway : <Text color={caps.firewallEnabled ? 'green' : 'gray'} bold>{caps.firewallEnabled ? 'ENABLED' : 'DISABLED'}</Text>
                  {'  '}• ZFS NAS : <Text color={caps.nasEnabled ? 'green' : 'gray'} bold>{caps.nasEnabled ? 'ENABLED' : 'DISABLED'}</Text>
                </Text>
                <Text>
                  {'  '}• K3s + OpenEBS      : <Text color={caps.k3sEnabled ? 'green' : 'gray'} bold>{caps.k3sEnabled ? 'ENABLED' : 'DISABLED'}</Text>
                  {'  '}• KVM/LXC : <Text color={caps.virtEnabled ? 'green' : 'gray'} bold>{caps.virtEnabled ? 'ENABLED' : 'DISABLED'}</Text>
                </Text>
                <Text>
                  {'  '}• Vigilante SOC      : <Text color={caps.vigilanteEnabled ? 'green' : 'gray'} bold>{caps.vigilanteEnabled ? 'ENABLED' : 'DISABLED'}</Text>
                </Text>
              </Box>
            </Box>
            <Box flexDirection="column" width="50%">
              <Text bold color="white">Control Plane & Security Summary:</Text>
              <Text>  • Firewall & NAT   : <Text color="green" bold>{state.rules.length}</Text> rules, <Text color="cyan" bold>{state.nat?.length || 0}</Text> NAT rules</Text>
              <Text>  • Static Routes    : <Text color="cyan" bold>{state.routes?.length || 0}</Text> routes ({(state.routes || []).map((r) => r.network).join(', ') || 'none'})</Text>
              <Text>  • Gateways         : <Text color="yellow" bold>{state.gateways?.length || 0}</Text> upstream gateways</Text>
              <Text>  • DHCPv4 Subnets   : <Text color="green" bold>{state.dhcp?.subnets?.length || 0}</Text> configured</Text>
              <Text>  • MCP Server       : <Text color={mcpStatus.masterEnabled ? 'yellow' : 'green'} bold>{mcpStatus.masterEnabled ? 'ENABLED' : 'DISABLED (Default Safe)'}</Text></Text>
              <Text>  • Shell Experience : <Text color={workstationEnabled ? 'cyan' : 'gray'} bold>{workstationEnabled ? 'ENABLED (ZSH + Oh My Zsh + kubectl + Starship + VIM)' : 'MINIMAL (Disabled)'}</Text></Text>
            </Box>
          </Box>
        </Box>
      )}

      {activeTab === 'interfaces' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Network Interfaces, VLANs ({state.vlans?.length || 0}), Bonds ({state.bonds?.length || 0}) & Bridges ({state.bridges?.length || 0})
            </Text>
            <Text color="gray">
              [↑/↓] Select · [Space] Toggle Enable · [a] Apply Changes
            </Text>
          </Box>
          {state.interfaces.map((iface, idx) => {
            const sel = idx === cursorIdx % Math.max(1, state.interfaces.length);
            return (
              <Box key={iface.name} gap={2} paddingLeft={1}>
                <Text color={sel ? 'cyan' : 'gray'} bold>
                  {sel ? '▶' : ' '}
                </Text>
                <Text color={iface.enabled ? 'green' : 'red'} bold>
                  {iface.enabled ? '[ENABLED] ' : '[DISABLED]'}
                </Text>
                <Text bold color={sel ? 'white' : 'gray'}>
                  {iface.name.toUpperCase().padEnd(8, ' ')}
                </Text>
                <Text color="cyan">{iface.device.padEnd(10, ' ')}</Text>
                <Text color="yellow">{(iface.ipv4Address || iface.type).padEnd(20, ' ')}</Text>
                <Text color="white">{iface.description || ''}</Text>
              </Box>
            );
          })}
          {(state.vlans?.length || 0) > 0 && (
            <Box marginTop={1} flexDirection="column">
              <Text bold color="white">Configured 802.1Q VLANs:</Text>
              {(state.vlans || []).map((v) => (
                <Text key={v.id || v.vlanInterface} color="gray">
                  {'  '}• VLAN {v.tag} on {v.parentInterface} ({v.vlanInterface}) — {v.description || 'tagged'}
                </Text>
              ))}
            </Box>
          )}
        </Box>
      )}

      {activeTab === 'firewall' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Firewall & NAT (/etc/axonwall/firewall.yaml) — View: [{fwSubView.toUpperCase()}]
            </Text>
            <Text color="gray">
              [n] Switch View (Rules/NAT/Aliases) · [↑/↓] Select · [Space] Toggle · [a] Apply
            </Text>
          </Box>
          {fwSubView === 'rules' &&
            state.rules.slice(0, 16).map((rule, idx) => {
              const sel = idx === cursorIdx % Math.max(1, state.rules.length);
              const actionColor =
                rule.action === 'pass' ? 'green' : rule.action === 'block' ? 'red' : 'yellow';
              return (
                <Box key={rule.id || idx} gap={2} paddingLeft={1}>
                  <Text color={sel ? 'cyan' : 'gray'} bold>
                    {sel ? '▶' : ' '}
                  </Text>
                  <Text color={rule.enabled ? 'green' : 'gray'}>
                    {rule.enabled ? '[ON] ' : '[OFF]'}
                  </Text>
                  <Text bold color={actionColor}>
                    {rule.action.toUpperCase().padEnd(7, ' ')}
                  </Text>
                  <Text color="cyan">{rule.interface.padEnd(6, ' ')}</Text>
                  <Text color="yellow">{rule.protocol.toUpperCase().padEnd(6, ' ')}</Text>
                  <Text color="white">
                    {`${rule.source || 'any'} -> ${rule.destination || 'any'}${rule.destinationPort ? ':' + rule.destinationPort : ''}`.padEnd(28, ' ')}
                  </Text>
                  <Text color="gray">{rule.description || ''}</Text>
                </Box>
              );
            })}
          {fwSubView === 'nat' &&
            ((state.nat || []).length === 0 ? (
              <Text color="gray">  Automatic WAN Masquerade active (no custom DNAT/SNAT rules).</Text>
            ) : (
              (state.nat || []).map((nr, idx) => {
                const sel = idx === cursorIdx % Math.max(1, (state.nat || []).length);
                return (
                  <Box key={nr.id || idx} gap={2} paddingLeft={1}>
                    <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶' : ' '}</Text>
                    <Text color={nr.enabled ? 'green' : 'gray'}>{nr.enabled ? '[ON] ' : '[OFF]'}</Text>
                    <Text bold color="yellow">{nr.type.toUpperCase().padEnd(11, ' ')}</Text>
                    <Text color="cyan">{nr.interface.padEnd(6, ' ')}</Text>
                    <Text color="white">{`${nr.protocol.toUpperCase()} :${nr.destinationPort || '*'} -> ${nr.targetIp || 'masquerade'}${nr.targetPort ? ':' + nr.targetPort : ''}`.padEnd(34, ' ')}</Text>
                    <Text color="gray">{nr.description || ''}</Text>
                  </Box>
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
                  <Box key={al.id || idx} gap={2} paddingLeft={1}>
                    <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶' : ' '}</Text>
                    <Text color={al.enabled ? 'green' : 'gray'}>{al.enabled ? '[ON] ' : '[OFF]'}</Text>
                    <Text bold color="cyan">{al.name.padEnd(20, ' ')}</Text>
                    <Text color="yellow">{al.type.toUpperCase().padEnd(10, ' ')}</Text>
                    <Text color="white">{(al.entries || []).join(', ')}</Text>
                    <Text color="gray">{al.description || ''}</Text>
                  </Box>
                );
              })
            ))}
        </Box>
      )}

      {activeTab === 'routing' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Gateways, Static Routes & FRR BGP/OSPF (/etc/axonwall/routing.yaml)
            </Text>
            <Text color="gray">
              [↑/↓] Select Route · [Space] Toggle Route · [d] Reload Disk · [a] Apply Routes
            </Text>
          </Box>
          <Text bold color="white">Upstream Gateways ({state.gateways?.length || 0}):</Text>
          {(state.gateways || []).map((gw) => (
            <Box key={gw.name} gap={2} paddingLeft={2}>
              <Text color={gw.enabled ? 'green' : 'red'}>●</Text>
              <Text bold color="white">{gw.name.padEnd(14, ' ')}</Text>
              <Text color="cyan">{gw.interface.padEnd(8, ' ')}</Text>
              <Text color="yellow">{gw.gatewayIp.padEnd(16, ' ')}</Text>
              <Text color="gray">Monitor: {gw.monitorIp || 'none'} {gw.isDefault ? '(Default)' : ''}</Text>
            </Box>
          ))}
          <Box marginTop={1} flexDirection="column">
            <Text bold color="white">Static Routes ({state.routes?.length || 0}):</Text>
            {(state.routes || []).length === 0 ? (
              <Text color="gray">  No static routes configured in /etc/axonwall/routing.yaml.</Text>
            ) : (
              (state.routes || []).map((rt, idx) => {
                const sel = idx === cursorIdx % Math.max(1, (state.routes || []).length);
                return (
                  <Box key={`${rt.network}-${rt.gateway}-${idx}`} gap={2} paddingLeft={1}>
                    <Text color={sel ? 'cyan' : 'gray'} bold>
                      {sel ? '▶' : ' '}
                    </Text>
                    <Text color={rt.enabled !== false ? 'green' : 'red'} bold>
                      {rt.enabled !== false ? '[ACTIVE]  ' : '[DISABLED]'}
                    </Text>
                    <Text bold color="white">{rt.network.padEnd(18, ' ')}</Text>
                    <Text color="yellow">{`via ${rt.gateway}`.padEnd(20, ' ')}</Text>
                    <Text color="cyan">{`dev ${rt.interface || 'auto'}`.padEnd(12, ' ')}</Text>
                    <Text color="gray">{rt.description ? `# ${rt.description}` : ''}</Text>
                  </Box>
                );
              })
            )}
          </Box>
          <Box marginTop={1}>
            <Text color="gray">
              FRRouting Dynamic Routing: BGP {state.frr?.bgp?.enabled ? `ENABLED (ASN ${state.frr.bgp.asNumber}, ${state.frr.bgp.neighbors?.length || 0} peers)` : 'DISABLED'} · OSPF {state.frr?.ospf?.enabled ? `ENABLED (${state.frr.ospf.areas?.length || 0} areas)` : 'DISABLED'}
            </Text>
          </Box>
        </Box>
      )}

      {activeTab === 'services' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Network Services, Post-Quantum VPN, HA & MCP Control Plane
            </Text>
            <Text color="gray">
              [↑/↓] Select Service · [Space] Toggle Enable/Disable · [a] Compile & Apply
            </Text>
          </Box>
          {serviceRows.map((row, idx) => {
            const sel = idx === cursorIdx % serviceRows.length;
            return (
              <Box key={row.id} gap={2} paddingLeft={1}>
                <Text color={sel ? 'cyan' : 'gray'} bold>
                  {sel ? '▶' : ' '}
                </Text>
                <Text color={row.enabled ? 'green' : 'gray'} bold>
                  {row.enabled ? '[ENABLED] ' : '[DISABLED]'}
                </Text>
                <Text bold={sel} color={sel ? 'white' : 'cyan'}>
                  {row.name.padEnd(44, ' ')}
                </Text>
                <Text color="gray">{row.detail}</Text>
              </Box>
            );
          })}
        </Box>
      )}

      {activeTab === 'storage' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1} gap={1}>
          <Box justifyContent="space-between">
            <Text bold color="cyan">
              OpenZFS Storage Pools, Datasets & NAS Shares (/etc/axonwall/storage.yaml)
            </Text>
            <Text color="gray">
              [Space] Toggle NAS Role · [s] Live zpool status · [a] Apply
            </Text>
          </Box>
          <Text>
            ZFS NAS Core Role :{' '}
            <Text bold color={caps.nasEnabled ? 'green' : 'gray'}>
              {caps.nasEnabled ? '[ENABLED]' : '[DISABLED]'}
            </Text>{' '}
            — Pools: <Text bold color="cyan">{state.nas?.pools?.length || 0}</Text> · Datasets:{' '}
            <Text bold color="cyan">{state.nas?.datasets?.length || 0}</Text> · SMB/NFS Shares:{' '}
            <Text bold color="cyan">{(state.nas?.smbShares?.length || 0) + (state.nas?.nfsExports?.length || 0)}</Text>
          </Text>
          {(state.nas?.pools || []).map((p: any) => (
            <Text key={p.name} color="white">
              {'  '}• Pool <Text bold color="cyan">{p.name}</Text> ({p.topology || 'mirror'}) — Compression: {p.compression || 'lz4'}, Auto-Scrub: {p.autoScrub ? 'ON' : 'OFF'}
            </Text>
          ))}
          {storageOutput && (
            <Box borderStyle="single" borderColor="green" paddingX={1} flexDirection="column">
              <Text color="green">{storageOutput}</Text>
            </Box>
          )}
        </Box>
      )}

      {activeTab === 'compute' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1} gap={1}>
          <Box justifyContent="space-between">
            <Text bold color="cyan">
              K3s Kubernetes + OpenEBS, KVM/LXC Virtualization & Vigilante SOC
            </Text>
            <Text color="gray">
              [↑/↓] Select Role · [Space] Toggle Role · [k] Live kubectl · [v] Live virsh · [a] Apply
            </Text>
          </Box>
          {[
            {
              id: 'core-k3s',
              name: 'K3s Kubernetes Cluster + OpenEBS LocalPV',
              enabled: caps.k3sEnabled,
              detail: `CIDR: ${state.k3s?.clusterCidr || '10.42.0.0/16'}, Service CIDR: ${state.k3s?.serviceCidr || '10.43.0.0/16'}, OpenEBS ZFS LocalPV`,
            },
            {
              id: 'core-virt',
              name: 'KVM/QEMU & LXC Virtualization Hypervisor',
              enabled: caps.virtEnabled,
              detail: `${state.virt?.vms?.length || 0} KVM VMs, ${state.virt?.containers?.length || 0} LXC containers`,
            },
            {
              id: 'core-vigilante',
              name: 'Vigilante Autonomous SOC & Threat Hunting',
              enabled: caps.vigilanteEnabled,
              detail: `Automated IOC enrichment, telemetry correlation & active response`,
            },
          ].map((r, idx) => {
            const sel = idx === cursorIdx % 3;
            return (
              <Box key={r.id} gap={2} paddingLeft={1}>
                <Text color={sel ? 'cyan' : 'gray'} bold>{sel ? '▶' : ' '}</Text>
                <Text color={r.enabled ? 'green' : 'gray'} bold>{r.enabled ? '[ENABLED] ' : '[DISABLED]'}</Text>
                <Text bold={sel} color="white">{r.name.padEnd(44, ' ')}</Text>
                <Text color="gray">{r.detail}</Text>
              </Box>
            );
          })}
          {computeOutput && (
            <Box borderStyle="single" borderColor="green" paddingX={1} flexDirection="column">
              <Text color="green">{computeOutput}</Text>
            </Box>
          )}
        </Box>
      )}

      {activeTab === 'plugins' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Appliance Roles, Extension Plugins & First-Class Shell Experience
            </Text>
            <Text color="gray">
              [↑/↓] Select · [Space] Enable/Disable · [i] Install · [u] Remove · [s] Re-Sync · [a] Apply
            </Text>
          </Box>
          <Box marginBottom={1} paddingX={1}>
            <Text color="green">
              ★ Oh My Zsh (/usr/share/oh-my-zsh) + Starship + VIM + Tmux is ENABLED BY DEFAULT. Active ZSH plugins: git, kubectl, helm, systemd, sudo, tmux, extract, colored-man-pages, docker, axonwall.
            </Text>
          </Box>
          {BUILTIN_PLUGINS.map((p, idx) => {
            const sel = idx === cursorIdx % BUILTIN_PLUGINS.length;
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
              <Box key={p.id} gap={2} paddingLeft={1}>
                <Text color={sel ? 'cyan' : 'gray'} bold>
                  {sel ? '▶' : ' '}
                </Text>
                <Text color={enabled ? 'green' : 'gray'} bold>
                  {enabled ? '[ENABLED] ' : '[DISABLED]'}
                </Text>
                <Text color="yellow">{`[${pkgStatus}]`.padEnd(13, ' ')}</Text>
                <Text bold={sel} color={sel ? 'white' : 'cyan'}>
                  {p.id.padEnd(26, ' ')}
                </Text>
                <Text color="white">
                  {p.name}
                  {p.dependencies && p.dependencies.length > 0 ? ` [requires: ${p.dependencies.join(', ')}]` : ''}
                </Text>
              </Box>
            );
          })}
        </Box>
      )}

      {activeTab === 'nastymap' && (
        <NastyMapApp embedded={true} detectedSubnets={detectedSubnets} readOnly={readOnly} />
      )}

      {activeTab === 'cli_ops' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Modern CLI Ops & Telemetry Toolkit (Auto-Default NIC: {detectedSubnets[0]?.device || 'eth0'})
            </Text>
            <Text color="gray">
              [↑/↓] Select Tool · [Enter/Space] Execute with Auto-Defaults
            </Text>
          </Box>
          {cliTools.map((t, idx) => {
            const sel = idx === cursorIdx % cliTools.length;
            return (
              <Box key={t.id} gap={2} paddingLeft={1}>
                <Text color={sel ? 'cyan' : 'gray'} bold>
                  {sel ? '▶' : ' '}
                </Text>
                <Text bold={sel} color={sel ? 'green' : 'white'}>
                  {t.name.padEnd(44, ' ')}
                </Text>
                <Text color="gray">{t.desc}</Text>
              </Box>
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
        </Box>
      )}

      {/* Status Bar & Hotkey Legend */}
      <Box marginTop={1} justifyContent="space-between">
        <Text color={readOnly ? 'yellow' : 'green'}>{statusMessage}</Text>
        <Text color="gray">
          {readOnly
            ? '[1-9,0/Tab] Tabs · [d] Reload · [q] Quit [READ-ONLY]'
            : '[1-9,0/Tab] Tabs · [a] Apply · [c] Confirm · [r] Rollback · [d] Reload · [q] Quit'}
        </Text>
      </Box>
    </Box>
  );
}

function resolveTabFromArg(val: string): TopTab {
  const v = val.toLowerCase();
  if (v === 'nastymap' || v === 'nmap') return 'nastymap';
  if (v === 'routing' || v === 'routes' || v === 'frr') return 'routing';
  if (v === 'firewall' || v === 'fw' || v === 'nat') return 'firewall';
  if (v === 'interfaces' || v === 'if' || v === 'vlans') return 'interfaces';
  if (v === 'services' || v === 'vpn' || v === 'mcp') return 'services';
  if (v === 'storage' || v === 'zfs' || v === 'nas') return 'storage';
  if (v === 'compute' || v === 'k3s' || v === 'virt' || v === 'vigilante') return 'compute';
  if (v === 'plugins' || v === 'shell') return 'plugins';
  if (v === 'cli' || v === 'ops' || v === 'cli_ops' || v === 'cli-tools' || v === 'logs') return 'cli_ops';
  return 'dashboard';
}

// Parse CLI arguments (--tab nastymap, --readonly, etc.)
const args = process.argv.slice(2);
let startTab: TopTab = 'dashboard';
let readOnlyMode = process.env.AXONWALL_TUI_READONLY === '1';

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--readonly' || arg === '-r') {
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
