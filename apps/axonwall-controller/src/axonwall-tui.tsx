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
import type { DesiredState } from '@axonwall/lib/schemas';
import { App as NastyMapApp } from './tui/nastymap/App.js';

const ETC_CONFIG_DIR = process.env.AXONWALL_CONFIG_DIR || '/etc/axonwall';
const VAR_ETC_CONFIG_DIR = '/var/lib/axonwall/etc-axonwall';
const STATE_JSON_PATH = process.env.AXONWALL_STATE_FILE || '/var/lib/axonwall/state.json';
const AGENT_API_SOCKET = process.env.AGENT_API_SOCKET || '/run/axonwall/agent-api.sock';
const AGENT_TOKEN_PATH = process.env.AXONWALL_AGENT_TOKEN_FILE || '/etc/axonwall/agent.token';

type TopTab =
  | 'dashboard'
  | 'interfaces'
  | 'firewall'
  | 'routing'
  | 'services'
  | 'nastymap'
  | 'cli_ops';

const TOP_TABS: Array<{ id: TopTab; key: string; label: string }> = [
  { id: 'dashboard', key: '1', label: 'Dashboard' },
  { id: 'interfaces', key: '2', label: 'Interfaces' },
  { id: 'firewall', key: '3', label: 'Firewall & NAT' },
  { id: 'routing', key: '4', label: 'Routing & FRR' },
  { id: 'services', key: '5', label: 'Services & VPN' },
  { id: 'nastymap', key: '6', label: 'NastyMap (Nmap)' },
  { id: 'cli_ops', key: '7', label: 'CLI Ops Toolkit' },
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
      fs.mkdirSync(dir, { recursive: true });
      for (const [fn, content] of Object.entries(serialized)) {
        fs.writeFileSync(path.join(dir, fn), content, 'utf-8');
      }
    } catch {}
  }
  try {
    fs.mkdirSync(path.dirname(STATE_JSON_PATH), { recursive: true });
    fs.writeFileSync(STATE_JSON_PATH, JSON.stringify(state, null, 2), 'utf-8');
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

export function AxonwallTuiApp({ initialTab = 'dashboard' }: { initialTab?: TopTab }) {
  const { exit } = useApp();
  const [activeTab, setActiveTab] = useState<TopTab>(initialTab);
  const [state, setState] = useState<DesiredState>(() => loadCurrentState());
  const [daemonStatus, setDaemonStatus] = useState<any>(null);
  const [statusMessage, setStatusMessage] = useState<string>(
    'Ready — Use [1-7] to switch tabs, [↑/↓] to select, [Space] to toggle, [a] to apply, [q] to exit.'
  );
  const [cursorIdx, setCursorIdx] = useState<number>(0);
  const [cliOutput, setCliOutput] = useState<string>('');

  const refreshAll = useCallback(async () => {
    const fresh = loadCurrentState();
    setState(fresh);
    const st = await callDaemon('/v1/status', 'GET');
    if (st) setDaemonStatus(st);
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

  const cliTools = [
    {
      id: 'bandwidth',
      name: 'slurm / iftop (Live NIC Bandwidth & Flows)',
      desc: 'Auto-selects active gateway interface & displays RX/TX stats + TCP congestion flows',
    },
    {
      id: 'sysstat',
      name: 'sysstat (mpstat -P ALL & iostat -xz)',
      desc: 'Multi-core CPU utilization and extended block device I/O latency metrics',
    },
    {
      id: 'netstat',
      name: 'net-tools (netstat -tuln, arp -an, ip route)',
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
      id: 'iotop',
      name: 'iotop (Disk I/O Monitor)',
      desc: 'Batch disk I/O throughput and per-device utilization snapshot',
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
        `=== Interface Bandwidth (${defaultIf}) ===\n${ipLink || 'Interface stats collected.'}\n\n=== Active Flows (iftop / ss -tin) ===\n${ssOut.slice(0, 1200)}`
      );
    } else if (item.id === 'sysstat') {
      const mp = execSafe('mpstat', ['-P', 'ALL']) || `Load Avg: ${os.loadavg().map((n) => n.toFixed(2)).join(', ')} (${os.cpus().length} cores)`;
      const io = execSafe('iostat', ['-xz']) || execSafe('df', ['-h']);
      setCliOutput(`=== CPU Telemetry (mpstat) ===\n${mp}\n\n=== Disk I/O (iostat -xz) ===\n${io}`);
    } else if (item.id === 'netstat') {
      const ns = execSafe('netstat', ['-tuln']) || execSafe('ss', ['-tuln']);
      const arp = execSafe('arp', ['-an']) || execSafe('ip', ['neigh', 'show']);
      const rt = execSafe('ip', ['route', 'show']);
      setCliOutput(`=== Listening Sockets ===\n${ns}\n\n=== ARP Cache ===\n${arp}\n\n=== Kernel Routes ===\n${rt}`);
    } else if (item.id === 'dnsutils') {
      const dig = execSafe('dig', [`@${defaultDns}`, 'cloudflare.com', 'A', '+stats']) || execSafe('nslookup', ['cloudflare.com', defaultDns]);
      setCliOutput(`=== DNS Lookup (dig @${defaultDns} cloudflare.com) ===\n${dig}`);
    } else if (item.id === 'top_procs') {
      const ps = execSafe('ps', ['aux', '--sort=-%cpu']);
      setCliOutput(`=== Top Processes (btop / htop snapshot) ===\n${ps.split('\n').slice(0, 18).join('\n')}`);
    } else if (item.id === 'iotop') {
      const io = execSafe('iotop', ['-b', '-n', '1', '-o']) || execSafe('iostat', ['-d', '-x']) || execSafe('lsblk', []);
      setCliOutput(`=== Disk I/O Telemetry (iotop) ===\n${io}`);
    }
    setStatusMessage(`Executed ${item.name} with auto-detected defaults (NIC: ${defaultIf}, DNS: ${defaultDns}).`);
  };

  useInput((input, key) => {
    if (input === 'q') {
      exit();
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
      setActiveTab('nastymap');
      setCursorIdx(0);
    } else if (input === '7') {
      setActiveTab('cli_ops');
      setCursorIdx(0);
      if (!cliOutput) runCliToolInline(0);
    } else if (input === 'c') {
      handleConfirm();
    } else if (input === 'r') {
      handleRollback();
    } else if (input === 'a') {
      handleApplyConfig();
    } else if (input === 'd') {
      refreshAll();
      setStatusMessage('Reloaded configuration from /etc/axonwall/*.yaml.');
    }

    if (activeTab === 'nastymap') return;

    if (key.upArrow) {
      setCursorIdx((prev) => Math.max(0, prev - 1));
    } else if (key.downArrow) {
      setCursorIdx((prev) => prev + 1);
    } else if (input === ' ' || key.return) {
      if (activeTab === 'interfaces' && state.interfaces[cursorIdx]) {
        const next = structuredClone(state);
        const target = next.interfaces[cursorIdx]!;
        target.enabled = !target.enabled;
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(`Toggled interface '${target.name}' (${target.device}) -> ${target.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`);
      } else if (activeTab === 'firewall' && state.rules[cursorIdx]) {
        const next = structuredClone(state);
        const rule = next.rules[cursorIdx]!;
        rule.enabled = !rule.enabled;
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(`Toggled firewall rule '${rule.description || rule.id}' -> ${rule.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`);
      } else if (activeTab === 'routing' && state.routes?.[cursorIdx]) {
        const next = structuredClone(state);
        const rt = next.routes![cursorIdx]!;
        rt.enabled = rt.enabled === false ? true : false;
        setState(next);
        saveStateToDisk(next);
        setStatusMessage(`Toggled static route '${rt.network} via ${rt.gateway}' -> ${rt.enabled ? 'ENABLED' : 'DISABLED'}. Press [a] to apply.`);
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
            Appliance Overview & Live Interfaces (/etc/axonwall/*.yaml)
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
            </Box>
            <Box flexDirection="column" width="50%">
              <Text bold color="white">Control Plane Summary:</Text>
              <Text>  • Firewall Rules   : <Text color="green" bold>{state.rules.length}</Text> rules</Text>
              <Text>  • Static Routes    : <Text color="cyan" bold>{state.routes?.length || 0}</Text> routes ({(state.routes || []).map((r) => r.network).join(', ') || 'none'})</Text>
              <Text>  • Gateways         : <Text color="yellow" bold>{state.gateways?.length || 0}</Text> upstream gateways</Text>
              <Text>  • DHCPv4 Subnets   : <Text color="green" bold>{state.dhcp?.subnets?.length || 0}</Text> configured</Text>
              <Text>  • Default Shell/Ed : <Text color="cyan" bold>ZSH + VIM (update-alternatives)</Text></Text>
            </Box>
          </Box>
        </Box>
      )}

      {activeTab === 'interfaces' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Network Interfaces, VLANs & LAGG (/etc/axonwall/interfaces.yaml)
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
        </Box>
      )}

      {activeTab === 'firewall' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Firewall & NAT Rules (/etc/axonwall/firewall.yaml — {state.rules.length} rules)
            </Text>
            <Text color="gray">
              [↑/↓] Select · [Space] Toggle Rule · [a] Compile & Apply nftables
            </Text>
          </Box>
          {state.rules.slice(0, 16).map((rule, idx) => {
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
        </Box>
      )}

      {activeTab === 'routing' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Gateways, Static Routes & FRR (/etc/axonwall/routing.yaml)
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
        </Box>
      )}

      {activeTab === 'services' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1} gap={1}>
          <Text bold color="cyan" underline>
            Core Network Services, VPN & High Availability
          </Text>
          <Text>
            • <Text bold color="white">Kea DHCPv4 Server</Text> :{' '}
            <Text color={state.dhcp?.enabled ? 'green' : 'gray'}>
              {state.dhcp?.enabled ? 'ENABLED' : 'DISABLED'} ({state.dhcp?.subnets?.length || 0} subnets,{' '}
              {(state.dhcp?.subnets || []).reduce((acc, s) => acc + (s.staticMappings?.length || 0), 0)} static reservations)
            </Text>
          </Text>
          <Text>
            • <Text bold color="white">Unbound DNS Resolver</Text> :{' '}
            <Text color={state.dns?.enabled ? 'green' : 'gray'}>
              {state.dns?.enabled ? 'ENABLED' : 'DISABLED'} (Upstreams: {(state.dns?.dotUpstreams || state.system?.dnsServers || []).join(', ') || 'Root Hints'})
            </Text>
          </Text>
          <Text>
            • <Text bold color="white">WireGuard VPN</Text> :{' '}
            <Text color={state.wireguard?.enabled ? 'green' : 'gray'}>
              {state.wireguard?.enabled ? `ENABLED (Port ${state.wireguard.listenPort}, ${state.wireguard.peers?.length || 0} peers)` : 'DISABLED'}
            </Text>
          </Text>
          <Text>
            • <Text bold color="white">Suricata IDS/IPS</Text> :{' '}
            <Text color={state.suricata?.enabled ? 'green' : 'gray'}>
              {state.suricata?.enabled ? `ENABLED (${state.suricata.mode?.toUpperCase()})` : 'DISABLED'}
            </Text>
          </Text>
          <Text>
            • <Text bold color="white">HA Cluster (VRRP/Conntrackd)</Text> :{' '}
            <Text color={state.ha?.enabled ? 'green' : 'gray'}>
              {state.ha?.enabled ? `ENABLED (${state.ha.nodeRole?.toUpperCase()} — ${state.ha.vrrpInstances?.length || 0} VRRP instances)` : 'STANDALONE'}
            </Text>
          </Text>
        </Box>
      )}

      {activeTab === 'nastymap' && (
        <NastyMapApp embedded={true} detectedSubnets={detectedSubnets} />
      )}

      {activeTab === 'cli_ops' && (
        <Box flexDirection="column" borderStyle="single" borderColor="gray" padding={1}>
          <Box justifyContent="space-between" marginBottom={1}>
            <Text bold color="cyan">
              Debian/Alpine Modern CLI Ops Toolkit (Auto-Default NIC: {detectedSubnets[0]?.device || 'eth0'})
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
        <Text color="green">{statusMessage}</Text>
        <Text color="gray">
          [1-7] Tabs · [a] Apply · [c] Confirm · [r] Rollback · [d] Reload · [q] Quit
        </Text>
      </Box>
    </Box>
  );
}

// Parse CLI arguments (--tab nastymap, etc.)
const args = process.argv.slice(2);
let startTab: TopTab = 'dashboard';
for (let i = 0; i < args.length; i++) {
  if ((args[i] === '--tab' || args[i] === '-t') && args[i + 1]) {
    const val = args[i + 1]!.toLowerCase();
    if (val === 'nastymap' || val === 'nmap') startTab = 'nastymap';
    else if (val === 'routing' || val === 'routes') startTab = 'routing';
    else if (val === 'firewall' || val === 'fw') startTab = 'firewall';
    else if (val === 'interfaces' || val === 'if') startTab = 'interfaces';
    else if (val === 'services') startTab = 'services';
    else if (val === 'cli' || val === 'ops' || val === 'cli_ops') startTab = 'cli_ops';
  }
}

render(<AxonwallTuiApp initialTab={startTab} />);
