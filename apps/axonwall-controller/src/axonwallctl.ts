import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';
import * as crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  AXONWALL_YAML_DOMAINS,
  AXONWALL_YAML_FILENAMES,
  serializeDesiredStateToYamlFiles,
  serializeDesiredStateToSingleYaml,
  validateYamlConfigFiles,
} from '@axonwall/lib/yaml';
import { compileNftables } from '@axonwall/lib/compile/nft';
import { synthesizeDefaultDhcpSubnet } from '@axonwall/lib/compile/kea';
import { DesiredStateSchema, VigilanteConfigSchema, inferInterfaceRole, type DesiredState } from '@axonwall/lib/schemas';
import {
  BUILTIN_PLUGINS,
  resolveCapabilities,
  isPluginEnabled,
  enablePluginWithDependencies,
  disablePluginWithDependents,
} from '@axonwall/lib/plugins';
import { getMcpServerStatus, resolveMcpSettingsPath } from '@axonwall/lib/mcp';
import { isValidDevice } from '@axonwall/lib/util';
import {
  parseCloudInitYaml,
  parseCloudInitNetworkConfig,
  serializeYaml,
  parseStorageFromLsblk,
  buildCloudInitFromSystem,
  exportCloudInitYaml,
  generateCloudInitMetaData,
  buildNoCloudIso,
  type FullCloudInit,
  type CloudInitExportOptions,
} from '@axonwall/lib/cloudinit';

const ETC_DIR = process.env.AXONWALL_ETC_DIR || process.env.AXONWALL_CONFIG_DIR || '/etc/axonwall';
const PERSIST_YAML_DIR = process.env.AXONWALL_PERSIST_YAML_DIR || '/var/lib/axonwall/etc-axonwall';
const STATE_JSON_PATH = process.env.AXONWALL_STATE_FILE || '/var/lib/axonwall/state.json';
const GITOPS_DIR = process.env.AXONWALL_GITOPS_DIR || '/var/lib/axonwall/gitops';
const AGENT_API_SOCK = process.env.AXONWALL_AGENT_API_SOCK || '/run/axonwall/agent-api.sock';

const cReset = '\x1b[0m';
const cBold = '\x1b[1m';
const cDim = '\x1b[2m';
const cGreen = '\x1b[32m';
const cYellow = '\x1b[33m';
const cRed = '\x1b[31m';
const cCyan = '\x1b[36m';

function readYamlConfigFiles(): Record<string, string> {
  const files: Record<string, string> = {};

  // Read fallback from /var/lib/axonwall/etc-axonwall first, then overlay /etc/axonwall
  for (const dir of [PERSIST_YAML_DIR, ETC_DIR]) {
    if (!fs.existsSync(dir)) continue;
    for (const filename of AXONWALL_YAML_FILENAMES) {
      const fullPath = path.join(dir, filename);
      if (fs.existsSync(fullPath)) {
        try {
          files[filename] = fs.readFileSync(fullPath, 'utf-8');
        } catch {}
      }
    }
    const singlePath = path.join(dir, 'axonwall.yaml');
    if (fs.existsSync(singlePath)) {
      try {
        files['axonwall.yaml'] = fs.readFileSync(singlePath, 'utf-8');
      } catch {}
    }
    const confDPath = path.join(dir, 'conf.d');
    if (fs.existsSync(confDPath)) {
      try {
        const entries = fs.readdirSync(confDPath).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml')).sort();
        for (const entry of entries) {
          files[`conf.d/${entry}`] = fs.readFileSync(path.join(confDPath, entry), 'utf-8');
        }
      } catch {}
    }
  }

  return files;
}

function loadFallbackState(): DesiredState {
  for (const candidate of [STATE_JSON_PATH, path.join(ETC_DIR, 'state.json')]) {
    if (fs.existsSync(candidate)) {
      try {
        const raw = JSON.parse(fs.readFileSync(candidate, 'utf-8'));
        const parsed = DesiredStateSchema.safeParse(raw);
        if (parsed.success) return parsed.data;
      } catch {}
    }
  }

  let wanDev = 'eth0';
  let lanDev = 'eth1';
  let opt1Dev = '';
  let opt2Dev = '';
  let wanMode: 'dhcp' | 'static' = 'dhcp';
  let wanAddr: string | undefined;
  let wanGw: string | undefined;
  let lanMode: 'dhcp' | 'static' = 'static';
  let lanAddr = '192.168.1.1/24';
  let opt1Mode: 'dhcp' | 'static' = 'dhcp';
  let opt1Addr: string | undefined;
  let opt2Mode: 'dhcp' | 'static' = 'dhcp';
  let opt2Addr: string | undefined;
  const extraIfaces: Array<{
    name: string;
    role: 'wan' | 'lan';
    device: string;
    type: 'dhcp' | 'static';
    ipv4Address?: string;
    ipv4Gateway?: string;
    dhcpServer: boolean;
    enabled: boolean;
    mtu: number;
    description: string;
  }> = [];

  try {
    const confPath = path.join(ETC_DIR, 'interfaces.conf');
    if (fs.existsSync(confPath)) {
      wanDev = '';
      lanDev = '';
      const rawKv: Record<string, string> = {};
      for (const rawLine of fs.readFileSync(confPath, 'utf-8').split('\n')) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#') || !line.includes('=')) continue;
        const eqIdx = line.indexOf('=');
        const k = line.slice(0, eqIdx).trim();
        const v = line.slice(eqIdx + 1).trim();
        rawKv[k] = v;
        if (k === 'WAN_INTERFACE') wanDev = isValidDevice(v) ? v : '';
        else if (k === 'LAN_INTERFACE') lanDev = isValidDevice(v) ? v : '';
        else if (k === 'OPT1_INTERFACE') opt1Dev = isValidDevice(v) ? v : '';
        else if (k === 'OPT2_INTERFACE') opt2Dev = isValidDevice(v) ? v : '';
        else if (k === 'WAN_MODE' && (v === 'static' || v === 'dhcp')) wanMode = v;
        else if (k === 'WAN_IPV4_ADDRESS' && v) wanAddr = v;
        else if (k === 'WAN_IPV4_GATEWAY' && v) wanGw = v;
        else if (k === 'LAN_MODE' && (v === 'static' || v === 'dhcp')) lanMode = v;
        else if (k === 'LAN_IPV4_ADDRESS' && v) lanAddr = v;
        else if (k === 'OPT1_MODE' && (v === 'static' || v === 'dhcp')) opt1Mode = v;
        else if (k === 'OPT1_IPV4_ADDRESS' && v) opt1Addr = v;
        else if (k === 'OPT2_MODE' && (v === 'static' || v === 'dhcp')) opt2Mode = v;
        else if (k === 'OPT2_IPV4_ADDRESS' && v) opt2Addr = v;
      }

      const seenNames = new Set(['wan', 'lan', 'opt1', 'opt2']);
      for (const [k, v] of Object.entries(rawKv)) {
        if (k.startsWith('IFACE_') && k.endsWith('_DEVICE') && isValidDevice(v)) {
          const keyCore = k.slice('IFACE_'.length, -'_DEVICE'.length);
          const name = (rawKv[`IFACE_${keyCore}_NAME`] || keyCore).trim().toLowerCase();
          if (!name || seenNames.has(name)) continue;
          seenNames.add(name);
          const roleRaw = (rawKv[`IFACE_${keyCore}_ROLE`] || '').toLowerCase();
          const role: 'wan' | 'lan' = roleRaw === 'wan' || name.startsWith('wan') ? 'wan' : 'lan';
          const modeRaw = (rawKv[`IFACE_${keyCore}_MODE`] || '').toLowerCase();
          const type: 'dhcp' | 'static' = modeRaw === 'static' ? 'static' : 'dhcp';
          const ipv4Address = rawKv[`IFACE_${keyCore}_IPV4_ADDRESS`] || undefined;
          const ipv4Gateway = rawKv[`IFACE_${keyCore}_IPV4_GATEWAY`] || undefined;
          const dhcpServer = role === 'lan' && type === 'static' && rawKv[`IFACE_${keyCore}_DHCP_SERVER`] === 'true';
          extraIfaces.push({
            name,
            role,
            device: v,
            type,
            ipv4Address,
            ipv4Gateway,
            dhcpServer,
            enabled: true,
            mtu: 1500,
            description: `${name.toUpperCase()} ${role === 'wan' ? 'WAN Uplink' : 'LAN Network'}`,
          });
        }
      }
    }
  } catch {}

  const interfacesList = [
    {
      name: 'wan',
      role: 'wan' as const,
      device: wanDev || 'none',
      type: wanMode,
      ipv4Address: wanMode === 'static' ? wanAddr : undefined,
      ipv4Gateway: wanMode === 'static' ? wanGw : undefined,
      dhcpServer: false,
      enabled: Boolean(wanDev),
      mtu: 1500,
      description: 'WAN Uplink',
    },
    {
      name: 'lan',
      role: 'lan' as const,
      device: lanDev || 'none',
      type: lanMode,
      ipv4Address: lanMode === 'static' ? lanAddr : undefined,
      dhcpServer: Boolean(lanDev) && lanMode === 'static',
      enabled: Boolean(lanDev),
      mtu: 1500,
      description: 'LAN Network',
    },
    ...(opt1Dev
      ? [
          {
            name: 'opt1',
            role: 'lan' as const,
            device: opt1Dev,
            type: opt1Mode,
            ipv4Address: opt1Mode === 'static' ? opt1Addr : undefined,
            dhcpServer: false,
            enabled: true,
            mtu: 1500,
            description: 'OPT1 Network',
          },
        ]
      : []),
    ...(opt2Dev
      ? [
          {
            name: 'opt2',
            role: 'lan' as const,
            device: opt2Dev,
            type: opt2Mode,
            ipv4Address: opt2Mode === 'static' ? opt2Addr : undefined,
            dhcpServer: false,
            enabled: true,
            mtu: 1500,
            description: 'OPT2 Network',
          },
        ]
      : []),
    ...extraIfaces,
  ];

  const antiLockoutIfaces = interfacesList
    .filter((i) => inferInterfaceRole(i) === 'lan' && i.enabled)
    .map((i) => i.name);
  if (antiLockoutIfaces.length === 0) antiLockoutIfaces.push('lan');

  return DesiredStateSchema.parse({
    version: 1,
    system: {
      hostname: 'axonwall',
      domain: 'home.arpa',
      timezone: 'UTC',
      dnsServers: ['1.1.1.1', '9.9.9.9'],
      antiLockout: {
        enabled: true,
        interface: antiLockoutIfaces[0] || 'lan',
        interfaces: antiLockoutIfaces,
        ports: [22, 80, 443, 2966, 3000],
      },
    },
    interfaces: interfacesList,
    rules: [],
  });
}

function fixSharedConfigOwnership(): void {
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    try {
      execFileSync(
        'chgrp',
        ['-R', 'axonwall-api', ETC_DIR, PERSIST_YAML_DIR, STATE_JSON_PATH],
        { stdio: 'ignore' }
      );
    } catch {}
    try {
      if (fs.existsSync(GITOPS_DIR)) {
        execFileSync('chown', ['-R', 'axonwall:axonwall-api', GITOPS_DIR], { stdio: 'ignore' });
        execFileSync('chmod', ['-R', 'g+rwX', GITOPS_DIR], { stdio: 'ignore' });
      }
    } catch {}
  }
}

function ensureInitializedYamlFiles(): void {
  const files = readYamlConfigFiles();
  if (Object.keys(files).length > 0) return;

  const fallback = loadFallbackState();
  const serialized = serializeDesiredStateToYamlFiles(fallback);
  for (const dir of [ETC_DIR, PERSIST_YAML_DIR]) {
    try {
      fs.mkdirSync(path.join(dir, 'conf.d'), { recursive: true, mode: 0o775 });
      for (const [filename, content] of Object.entries(serialized)) {
        const p = path.join(dir, filename);
        fs.writeFileSync(p, content, { mode: 0o660 });
        try { fs.chmodSync(p, 0o660); } catch {}
      }
    } catch {}
  }
  fixSharedConfigOwnership();
}

// axonwalld requires a per-install token on every agent API call.
// The daemon provisions it at /etc/axonwall/agent.token (0640
// root:axonwall); AXONWALL_AGENT_TOKEN overrides for dev setups.
function getAgentToken(): string | undefined {
  if (process.env.AXONWALL_AGENT_TOKEN) return process.env.AXONWALL_AGENT_TOKEN;
  try {
    return (
      fs
        .readFileSync(process.env.AXONWALL_AGENT_TOKEN_FILE || '/etc/axonwall/agent.token', 'utf8')
        .trim() || undefined
    );
  } catch {
    return undefined;
  }
}

function sendAgentSocketRequest<T>(reqPath: string, method: 'GET' | 'POST', body?: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(AGENT_API_SOCK)) {
      reject(new Error(`Socket not found at ${AGENT_API_SOCK}`));
      return;
    }
    const payload = body ? JSON.stringify(body) : undefined;
    const req = http.request(
      {
        socketPath: AGENT_API_SOCK,
        path: reqPath,
        method,
        headers: {
          ...(payload
            ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
            : {}),
          ...(getAgentToken() ? { 'X-Axonwall-Agent-Token': getAgentToken() } : {}),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(data) as T);
            } catch (err) {
              reject(err);
            }
          } else {
            reject(new Error(data || `HTTP ${res.statusCode}`));
          }
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function commitToGitOps(state: DesiredState, message: string): string | null {
  try {
    fs.mkdirSync(GITOPS_DIR, { recursive: true, mode: 0o775 });
    const gitBaseArgs = ['-c', `safe.directory=${GITOPS_DIR}`];
    if (!fs.existsSync(path.join(GITOPS_DIR, '.git'))) {
      execFileSync('git', [...gitBaseArgs, 'init'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', [...gitBaseArgs, 'config', 'user.name', 'Axonwall CLI'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', [...gitBaseArgs, 'config', 'user.email', 'cli@axonwall.local'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', [...gitBaseArgs, 'config', 'core.sharedRepository', 'group'], { cwd: GITOPS_DIR, stdio: 'ignore' });
    }
    fs.writeFileSync(path.join(GITOPS_DIR, 'state.json'), JSON.stringify(state, null, 2), { encoding: 'utf-8', mode: 0o660 });
    const yamlFiles = serializeDesiredStateToYamlFiles(state);
    for (const [filename, content] of Object.entries(yamlFiles)) {
      fs.writeFileSync(path.join(GITOPS_DIR, filename), content, { encoding: 'utf-8', mode: 0o660 });
    }
    execFileSync('git', [...gitBaseArgs, 'add', 'state.json', ...AXONWALL_YAML_FILENAMES], { cwd: GITOPS_DIR, stdio: 'ignore' });
    const status = execFileSync('git', [...gitBaseArgs, 'status', '--porcelain'], { cwd: GITOPS_DIR }).toString().trim();
    if (status.length > 0) {
      execFileSync('git', [...gitBaseArgs, 'commit', '-m', message], { cwd: GITOPS_DIR, stdio: 'ignore' });
    }
    fixSharedConfigOwnership();
    return execFileSync('git', [...gitBaseArgs, 'rev-parse', '--short', 'HEAD'], { cwd: GITOPS_DIR }).toString().trim();
  } catch {
    return null;
  }
}

async function cmdStatus() {
  ensureInitializedYamlFiles();
  console.log(`${cCyan}${cBold}=== Axonwall YAML Configuration Status (/etc/axonwall/) ===${cReset}\n`);

  for (const filename of AXONWALL_YAML_FILENAMES) {
    const etcPath = path.join(ETC_DIR, filename);
    const persistPath = path.join(PERSIST_YAML_DIR, filename);
    const activePath = fs.existsSync(etcPath) ? etcPath : fs.existsSync(persistPath) ? persistPath : null;
    if (activePath) {
      const stat = fs.statSync(activePath);
      console.log(
        `  ${cGreen}●${cReset} ${cBold}/etc/axonwall/${filename.padEnd(18)}${cReset} ${stat.size
          .toString()
          .padStart(5)} B   modified ${stat.mtime.toISOString()}`
      );
    } else {
      console.log(`  ${cYellow}○${cReset} /etc/axonwall/${filename.padEnd(18)} ${cDim}(using defaults)${cReset}`);
    }
  }

  const files = readYamlConfigFiles();
  const confDKeys = Object.keys(files).filter((k) => k.startsWith('conf.d/'));
  if (confDKeys.length > 0) {
    console.log(`\n  ${cCyan}conf.d Overrides (${confDKeys.length}):${cReset} ${confDKeys.join(', ')}`);
  }

  const validation = validateYamlConfigFiles(files);
  console.log(
    `\n  ${cBold}Schema Validation:${cReset} ${
      validation.valid ? `${cGreen}VALID (Zod schema verified)${cReset}` : `${cRed}INVALID (${validation.errors.length} errors)${cReset}`
    }`
  );

  try {
    const status = await sendAgentSocketRequest<any>('/v1/status', 'GET');
    console.log(`  ${cBold}Privileged Daemon:${cReset} ${cGreen}ONLINE${cReset} (${status.nodeId || 'axonwalld'}, v${status.version || '0.5.2'})`);
    console.log(`  ${cBold}Active Bundle:${cReset}     ${status.activeBundleHash ? status.activeBundleHash.slice(0, 12) : 'none'}`);
    if (status.pendingConfirm) {
      const remaining = status.secondsUntilRollback ?? 0;
      console.log(
        `  ${cRed}${cBold}Commit-Confirm:${cReset}    ${cRed}PENDING (Auto-rollback in ${remaining}s)${cReset} — run '${cCyan}axonwallctl confirm${cReset}' to confirm or '${cYellow}axonwallctl rollback${cReset}' to revert`
      );
    }
  } catch {
    console.log(`  ${cBold}Privileged Daemon:${cReset} ${cYellow}OFFLINE / STANDALONE MODE${cReset}`);
  }
}

function reconcileInterfacesFromConf(state: DesiredState): void {
  try {
    const confPath = fs.existsSync(path.join(PERSIST_YAML_DIR, 'interfaces.conf'))
      ? path.join(PERSIST_YAML_DIR, 'interfaces.conf')
      : path.join(ETC_DIR, 'interfaces.conf');
    if (!fs.existsSync(confPath)) return;

    // If interfaces.yaml was edited more recently than interfaces.conf (e.g. via vim /etc/axonwall/interfaces.yaml),
    // treat interfaces.yaml as authoritative so deleted interfaces are not resurrected from a stale interfaces.conf.
    const confMtimeMs = fs.statSync(confPath).mtimeMs;
    for (const yamlPath of [path.join(ETC_DIR, 'interfaces.yaml'), path.join(PERSIST_YAML_DIR, 'interfaces.yaml')]) {
      if (fs.existsSync(yamlPath)) {
        const yamlMtimeMs = fs.statSync(yamlPath).mtimeMs;
        if (yamlMtimeMs > confMtimeMs + 2000 && state.interfaces.length > 0) {
          return;
        }
      }
    }

    const rawKv: Record<string, string> = {};
    for (const rawLine of fs.readFileSync(confPath, 'utf-8').split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || !line.includes('=')) continue;
      const eqIdx = line.indexOf('=');
      rawKv[line.slice(0, eqIdx).trim()] = line.slice(eqIdx + 1).trim();
    }
    if (!('AXONWALL_INTERFACES' in rawKv)) return;
    const activeNames = (rawKv.AXONWALL_INTERFACES || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    for (const name of activeNames) {
      const keyPrefix = `IFACE_${name.toUpperCase().replace(/[^A-Z0-9_]/g, '_')}`;
      const dev = (rawKv[`${keyPrefix}_DEVICE`] || '').trim();
      if (!isValidDevice(dev)) continue;
      const roleRaw = (rawKv[`${keyPrefix}_ROLE`] || '').toLowerCase();
      const role: 'wan' | 'lan' = roleRaw === 'wan' || name.startsWith('wan') ? 'wan' : 'lan';
      const modeRaw = (rawKv[`${keyPrefix}_MODE`] || '').toLowerCase();
      const type: 'dhcp' | 'static' = modeRaw === 'static' ? 'static' : 'dhcp';
      const ipv4Address = rawKv[`${keyPrefix}_IPV4_ADDRESS`] || undefined;
      const ipv4Gateway = rawKv[`${keyPrefix}_IPV4_GATEWAY`] || undefined;
      const dhcpServer = role === 'lan' && type === 'static' && rawKv[`${keyPrefix}_DHCP_SERVER`] === 'true';

      const existingIdx = state.interfaces.findIndex((i) => i.name.toLowerCase() === name);
      const devUsedElsewhere = state.interfaces.some(
        (i, idx) => idx !== existingIdx && i.enabled && i.device === dev
      );
      if (devUsedElsewhere) continue;

      if (existingIdx < 0) {
        state.interfaces.push({
          name,
          role,
          device: dev,
          type,
          enabled: true,
          dhcpServer,
          ipv4Address: type === 'static' ? ipv4Address : undefined,
          ipv4Gateway: type === 'static' ? ipv4Gateway : undefined,
          mtu: 1500,
          description: `${name.toUpperCase()} ${role === 'wan' ? 'WAN Uplink' : dhcpServer ? 'LAN (Authoritative DHCP)' : 'LAN (Joined Network)'}`,
        });
      }
      if (role === 'lan' && state.system?.antiLockout?.interfaces && !state.system.antiLockout.interfaces.includes(name)) {
        state.system.antiLockout.interfaces.push(name);
      }
    }
  } catch {}

  // Ensure any enabled static LAN interface with dhcpServer: true has a matching subnet in state.dhcp.subnets
  try {
    if (state.dhcp?.enabled !== false) {
      if (!state.dhcp) {
        state.dhcp = { enabled: true, subnets: [] };
      }
      for (const iface of state.interfaces || []) {
        if (!iface.enabled || !isValidDevice(iface.device)) continue;
        if (inferInterfaceRole(iface) === 'wan') continue;
        if (iface.type !== 'static' || iface.dhcpServer !== true || !iface.ipv4Address) continue;
        const hasSubnet = (state.dhcp.subnets || []).some((s) => s.interface === iface.name);
        if (!hasSubnet) {
          const synth = synthesizeDefaultDhcpSubnet(iface);
          if (synth) {
            state.dhcp.subnets.push(synth);
          }
        }
      }
    }
  } catch {}
}

function cmdValidate(silent = false): DesiredState {
  ensureInitializedYamlFiles();
  const files = readYamlConfigFiles();
  const result = validateYamlConfigFiles(files);

  if (!result.valid || !result.state) {
    console.error(`${cRed}${cBold}[✗] Validation failed for /etc/axonwall/*.yaml:${cReset}`);
    for (const err of result.errors) {
      console.error(`  - ${cYellow}${err.file}${cReset}${err.path ? ` (${err.path})` : ''}: ${err.message}`);
    }
    process.exit(1);
  }

  reconcileInterfacesFromConf(result.state);

  if (!silent) {
    console.log(`${cGreen}${cBold}[✓] All /etc/axonwall/*.yaml files passed schema and syntax validation.${cReset}`);
    console.log(
      `    Interfaces: ${result.state.interfaces.length} | Firewall Rules: ${result.state.rules.length} | NAT Rules: ${
        result.state.nat?.length || 0
      } | DHCP Pools: ${result.state.dhcp?.subnets?.length || 0}`
    );
  }
  return result.state;
}

function cmdDiff() {
  const state = cmdValidate();
  const { nftScript } = compileNftables(state);

  if (fs.existsSync(path.join(GITOPS_DIR, '.git'))) {
    try {
      const yamlFiles = serializeDesiredStateToYamlFiles(state);
      const tmpDir = fs.mkdtempSync('/tmp/axonwall-diff-');
      let hasDiff = false;
      for (const [filename, content] of Object.entries(yamlFiles)) {
        const committedPath = path.join(GITOPS_DIR, filename);
        const diskContent = fs.existsSync(path.join(ETC_DIR, filename))
          ? fs.readFileSync(path.join(ETC_DIR, filename), 'utf-8')
          : content;
        const candidatePath = path.join(tmpDir, filename);
        fs.writeFileSync(candidatePath, diskContent, 'utf-8');
        if (fs.existsSync(committedPath)) {
          const res = spawnSync(
            'diff',
            ['-u', '--label', `committed/${filename}`, '--label', `/etc/axonwall/${filename}`, committedPath, candidatePath],
            { encoding: 'utf-8' }
          );
          if (res.stdout && res.stdout.trim()) {
            hasDiff = true;
            console.log(res.stdout);
          }
        }
      }
      fs.rmSync(tmpDir, { recursive: true, force: true });
      if (!hasDiff) {
        console.log(`${cGreen}[✓] No uncommitted differences between /etc/axonwall/*.yaml and active GitOps HEAD.${cReset}`);
      }
    } catch {}
  }

  console.log(`\n${cCyan}${cBold}--- Compiled nftables Ruleset Preview (first 35 lines) ---${cReset}`);
  console.log(nftScript.split('\n').slice(0, 35).join('\n'));
}

async function cmdApply(autoConfirm = true) {
  const state = cmdValidate();

  // Persist normalized YAML files + state.json
  const yamlFiles = serializeDesiredStateToYamlFiles(state);
  const serializedJson = JSON.stringify(state, null, 2);

  for (const dir of [ETC_DIR, PERSIST_YAML_DIR]) {
    try {
      fs.mkdirSync(path.join(dir, 'conf.d'), { recursive: true, mode: 0o775 });
      for (const [filename, content] of Object.entries(yamlFiles)) {
        const target = path.join(dir, filename);
        fs.writeFileSync(target, content, { mode: 0o660 });
        try { fs.chmodSync(target, 0o660); } catch {}
      }
    } catch {}
  }

  for (const jsonTarget of [STATE_JSON_PATH, path.join(PERSIST_YAML_DIR, 'state.json'), path.join(ETC_DIR, 'state.json')]) {
    try {
      fs.mkdirSync(path.dirname(jsonTarget), { recursive: true, mode: 0o775 });
      fs.writeFileSync(jsonTarget, serializedJson, { mode: 0o660 });
      try { fs.chmodSync(jsonTarget, 0o660); } catch {}
    } catch {}
  }
  fixSharedConfigOwnership();

  // Compile artifacts via compileNftables(state)
  const { nftScript, files, reloadServices } = compileNftables(state);
  const bundleHash = crypto.createHash('sha256').update(nftScript).digest('hex');
  const jobId = `cli-${Date.now()}`;

  const filesPayload = [
    ...files.map((f) => ({ ...f, file_mode: f.fileMode })),
    ...Object.entries(yamlFiles).map(([filename, content]) => ({
      path: `/etc/axonwall/${filename}`,
      content,
      fileMode: 0o660,
      file_mode: 0o660,
    })),
    { path: '/etc/axonwall/state.json', content: serializedJson, fileMode: 0o660, file_mode: 0o660 },
  ];

  try {
    const resp = await sendAgentSocketRequest<{ success: boolean; message: string }>('/v1/apply', 'POST', {
      jobId,
      bundleHash,
      nftScript,
      files: filesPayload,
      reloadServices,
      confirmTimeoutSeconds: 120,
    });

    if (!resp.success) {
      console.error(`${cRed}[✗] Daemon rejected bundle: ${resp.message}${cReset}`);
      process.exit(1);
    }

    if (autoConfirm) {
      await sendAgentSocketRequest('/v1/confirm', 'POST', { jobId });
      console.log(`${cGreen}${cBold}[✓] Applied /etc/axonwall/*.yaml to kernel nftables and system daemons (hash: ${bundleHash.slice(0, 12)}).${cReset}`);
    } else {
      console.log(`${cYellow}${cBold}[!] Applied with Commit-Confirm (120s timeout). Run 'axonwallctl confirm' to confirm or 'axonwallctl rollback' to revert.${cReset}`);
    }
  } catch (err: any) {
    console.log(
      `${cYellow}[!] Synchronized /etc/axonwall/*.yaml and state.json on disk (daemon socket offline: ${err?.message || 'standalone'}).${cReset}`
    );
  }

  const commitHash = commitToGitOps(state, `CLI apply via axonwallctl (${bundleHash.slice(0, 8)})`);
  if (commitHash) {
    console.log(`${cGreen}[✓] Committed configuration revision ${commitHash} to GitOps repository.${cReset}`);
  }
}

async function cmdEdit(domainArg?: string, extraArgs: string[] = []) {
  if (extraArgs.includes('--nvim') || extraArgs.includes('--super') || process.env.AXONWALL_SUPER_EDITOR === '1') {
    await cmdConfig(domainArg);
    return;
  }
  ensureInitializedYamlFiles();
  const domainNames = AXONWALL_YAML_DOMAINS.map((d) => d.filename.replace(/\.ya?ml$/, ''));
  const domain = (domainArg || 'firewall').replace(/\.ya?ml$/i, '').toLowerCase();
  if (!domainNames.includes(domain as any)) {
    console.error(
      `${cRed}Unknown configuration section '${domainArg}'. Valid sections: ${domainNames.join(', ')}${cReset}`
    );
    process.exit(1);
  }

  const targetPath = path.join(ETC_DIR, `${domain}.yaml`);
  if (!fs.existsSync(targetPath)) {
    const state = loadFallbackState();
    const serialized = serializeDesiredStateToYamlFiles(state) as Record<string, string>;
    fs.mkdirSync(ETC_DIR, { recursive: true, mode: 0o775 });
    fs.writeFileSync(targetPath, serialized[`${domain}.yaml`] || '', { mode: 0o660 });
    try { fs.chmodSync(targetPath, 0o660); } catch {}
    fixSharedConfigOwnership();
  }

  const editor = process.env.EDITOR || process.env.VISUAL || 'vi';
  const res = spawnSync(editor, [targetPath], { stdio: 'inherit' });
  if (res.status !== 0) {
    process.exit(res.status || 1);
  }

  console.log(`\n${cCyan}Validating modified /etc/axonwall/${domain}.yaml...${cReset}`);
  await cmdApply(true);
}

async function cmdConfig(domainArg?: string) {
  ensureInitializedYamlFiles();
  const domain = (domainArg || 'firewall').replace(/\.ya?ml$/i, '').toLowerCase();
  const initLocations = [
    process.env.AXONWALL_NVIM_INIT || '',
    '/etc/axonwall/nvim/init.lua',
    path.resolve(process.cwd(), 'packaging/iso/config/includes.chroot/etc/axonwall/nvim/init.lua'),
  ].filter(Boolean);

  const initLua = initLocations.find((p) => fs.existsSync(p));
  if (!initLua) {
    console.error(`${cRed}Neovim Super Configurator init.lua not found at /etc/axonwall/nvim/init.lua${cReset}`);
    process.exit(1);
  }

  const res = spawnSync('nvim', ['--clean', '-u', initLua], {
    stdio: 'inherit',
    env: {
      ...process.env,
      AXONWALL_NVIM_DOMAIN: domain,
      AXONWALL_CONFIG_DIR: ETC_DIR,
    },
  });
  if (res.status !== 0) {
    process.exit(res.status || 1);
  }
}

function cmdDumpJson() {
  ensureInitializedYamlFiles();
  const state = cmdValidate(true);
  process.stdout.write(JSON.stringify(state, null, 2) + '\n');
}

function cmdSaveJson(fileArg?: string) {
  let raw = '';
  try {
    if (fileArg && fileArg !== '-') {
      raw = fs.readFileSync(fileArg, 'utf-8');
    } else {
      raw = fs.readFileSync(0, 'utf-8');
    }
  } catch (err: any) {
    process.stdout.write(JSON.stringify({ ok: false, errors: [`Failed to read JSON input: ${err?.message || err}`] }) + '\n');
    process.exit(1);
  }

  let parsedJson: any;
  try {
    parsedJson = JSON.parse(raw);
  } catch (err: any) {
    process.stdout.write(JSON.stringify({ ok: false, errors: [`Invalid JSON syntax: ${err?.message || err}`] }) + '\n');
    process.exit(1);
  }

  // Normalize empty Lua tables (`[]`) back to `{}` for record/object fields
  if (parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
    const objectKeys = [
      'capabilities',
      'plugins',
      'system',
      'frr',
      'dhcp',
      'dns',
      'wireguard',
      'rosenpass',
      'headscale',
      'suricata',
      'crowdsec',
      'geoip',
      'ha',
      'nas',
      'k3s',
      'virt',
      'vigilante',
      'aiCopilot',
      'observability',
      'snmp',
      'nut',
      'acme',
    ];
    for (const k of objectKeys) {
      if (Array.isArray(parsedJson[k]) && parsedJson[k].length === 0) {
        parsedJson[k] = {};
      }
    }
  }

  const validation = DesiredStateSchema.safeParse(parsedJson);
  if (!validation.success) {
    const errors = validation.error.issues.map((i) => `${i.path.join('.') || 'root'}: ${i.message}`);
    process.stdout.write(JSON.stringify({ ok: false, errors }) + '\n');
    process.exit(1);
  }

  const state = validation.data;
  const serialized = serializeDesiredStateToYamlFiles(state);
  for (const dir of [ETC_DIR, PERSIST_YAML_DIR]) {
    try {
      fs.mkdirSync(path.join(dir, 'conf.d'), { recursive: true, mode: 0o775 });
      for (const [fn, content] of Object.entries(serialized)) {
        const fp = path.join(dir, fn);
        fs.writeFileSync(fp, content, { encoding: 'utf-8', mode: 0o660 });
        try { fs.chmodSync(fp, 0o660); } catch {}
      }
    } catch {}
  }
  try {
    fs.mkdirSync(path.dirname(STATE_JSON_PATH), { recursive: true, mode: 0o775 });
    fs.writeFileSync(STATE_JSON_PATH, JSON.stringify(state, null, 2), { encoding: 'utf-8', mode: 0o660 });
    try { fs.chmodSync(STATE_JSON_PATH, 0o660); } catch {}
  } catch {}
  fixSharedConfigOwnership();

  process.stdout.write(
    JSON.stringify({
      ok: true,
      rulesCount: state.rules.length,
      interfacesCount: state.interfaces.length,
    }) + '\n'
  );
}

function cmdExport() {
  const state = cmdValidate();
  process.stdout.write(serializeDesiredStateToSingleYaml(state));
}

async function cmdConfirm() {
  console.log(`${cCyan}Confirming pending ruleset and configuration commit...${cReset}`);
  try {
    const resp = await sendAgentSocketRequest<{ success: boolean; message: string }>('/v1/confirm', 'POST', {});
    if (resp.success) {
      console.log(`${cGreen}${cBold}[✓] Active ruleset and configuration successfully confirmed. Auto-rollback disarmed.${cReset}`);
    } else {
      console.warn(`${cYellow}[!] Daemon response: ${resp.message}${cReset}`);
    }
  } catch (err: any) {
    console.error(`${cRed}[✗] Failed to confirm ruleset: ${err?.message || err}${cReset}`);
    process.exit(1);
  }
}

async function cmdRollback() {
  console.log(`${cYellow}Rolling back to last-known-good ruleset and configuration...${cReset}`);
  try {
    const resp = await sendAgentSocketRequest<{ success: boolean; message: string }>('/v1/rollback', 'POST', {});
    if (resp.success) {
      console.log(`${cGreen}${cBold}[✓] Rolled back to last-known-good ruleset and restored /etc/axonwall/*.yaml.${cReset}`);
    } else {
      console.warn(`${cYellow}[!] Daemon response: ${resp.message}${cReset}`);
    }
  } catch (err: any) {
    console.error(`${cRed}[✗] Failed to trigger rollback: ${err?.message || err}${cReset}`);
    process.exit(1);
  }
}

async function cmdCloudInitExport(userArgs: string[]) {
  let outputFile: string | undefined;
  let isoFile: string | undefined;
  let redactSecrets = true;
  let templateMode = false;
  let includeStorage = true;
  let includeUsers = true;
  let includePackages = true;
  let hostnameOverride: string | undefined;

  for (let i = 0; i < userArgs.length; i++) {
    const arg = userArgs[i]!;
    if ((arg === '-o' || arg === '--output') && userArgs[i + 1]) {
      outputFile = userArgs[++i];
    } else if (arg.startsWith('--output=')) {
      outputFile = arg.slice('--output='.length);
    } else if (arg === '--iso' && userArgs[i + 1]) {
      isoFile = userArgs[++i];
    } else if (arg.startsWith('--iso=')) {
      isoFile = arg.slice('--iso='.length);
    } else if (arg === '--hostname' && userArgs[i + 1]) {
      hostnameOverride = userArgs[++i];
    } else if (arg.startsWith('--hostname=')) {
      hostnameOverride = arg.slice('--hostname='.length);
    } else if (arg === '--redact') {
      redactSecrets = true;
    } else if (arg === '--no-redact' || arg === '--include-secrets') {
      redactSecrets = false;
    } else if (arg === '--template') {
      templateMode = true;
    } else if (arg === '--no-storage') {
      includeStorage = false;
    } else if (arg === '--no-users') {
      includeUsers = false;
    } else if (arg === '--no-packages') {
      includePackages = false;
    }
  }

  const desiredState = cmdValidate(true);
  const hostname = os.hostname() || desiredState.system?.hostname || 'axonwall-fw';
  let timezone = desiredState.system?.timezone || 'UTC';
  try {
    if (fs.existsSync('/etc/timezone')) {
      const tz = fs.readFileSync('/etc/timezone', 'utf8').trim();
      if (tz) timezone = tz;
    }
  } catch {}

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
          const zfsOut = execFileSync(
            'zfs',
            ['list', '-H', '-r', '-o', 'name,mountpoint,compression', poolName],
            { encoding: 'utf8', timeout: 2000, stdio: ['ignore', 'pipe', 'ignore'] }
          ).trim();
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

  let adminUsername = 'admin';
  let adminPassword: string | undefined;
  for (const envPath of [path.join(ETC_DIR, 'admin.env'), path.join(PERSIST_YAML_DIR, 'admin.env')]) {
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
    const ctrlEnvPath = path.join(ETC_DIR, 'controller.env');
    if (fs.existsSync(ctrlEnvPath)) {
      const raw = fs.readFileSync(ctrlEnvPath, 'utf8');
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

  try {
    const daemonUsers = await sendAgentSocketRequest<{ users: any[] }>('/v1/system/users', 'GET');
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
          shell: u.shell || '/usr/bin/zsh',
          lockPasswd: Boolean(u.passwordLocked),
          sshAuthorizedKeys: Array.isArray(u.sshKeys) ? u.sshKeys : [],
        });
      }
    }
  } catch {}

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
            shell: '/usr/bin/zsh',
            sshAuthorizedKeys: keys,
          });
        }
      }
    }
  } catch {}

  const options: CloudInitExportOptions = {
    redactSecrets,
    templateMode,
    includeStorage,
    includeUsers,
    includePackages,
    hostnameOverride,
  };

  const hostData = {
    desiredState,
    hostname,
    timezone,
    storage,
    adminUsername,
    adminPassword,
    ztp: ztpEnabled ? { enabled: true, controllerUrl, enrollmentToken } : { enabled: false },
    osUsers: Array.from(osUsersMap.values()),
  };

  const fullConfig = buildCloudInitFromSystem(hostData, options);
  const yamlText = exportCloudInitYaml(hostData, options);
  const metaData = generateCloudInitMetaData(undefined, fullConfig.hostname);

  if (outputFile) {
    fs.mkdirSync(path.dirname(path.resolve(outputFile)), { recursive: true });
    fs.writeFileSync(outputFile, yamlText, { mode: 0o600 });
    try { fs.chmodSync(outputFile, 0o600); } catch {}
    console.error(`${cGreen}[✓] Exported #cloud-config YAML (${yamlText.length} bytes) to ${outputFile}${cReset}`);
  }

  if (isoFile) {
    const isoBytes = buildNoCloudIso(yamlText, metaData);
    fs.mkdirSync(path.dirname(path.resolve(isoFile)), { recursive: true });
    fs.writeFileSync(isoFile, isoBytes, { mode: 0o600 });
    try { fs.chmodSync(isoFile, 0o600); } catch {}
    console.error(
      `${cGreen}[✓] Generated bootable NoCloud seed ISO (label='cidata', ${isoBytes.byteLength} bytes) at ${isoFile}${cReset}`
    );
  }

  if (!outputFile && !isoFile) {
    process.stdout.write(yamlText);
  }
}

async function cmdCloudInit(userArgs: string[]) {
  if (userArgs[0]?.toLowerCase() === 'export') {
    await cmdCloudInitExport(userArgs.slice(1));
    return;
  }

  let explicitFile: string | undefined;
  let autoApply = true;

  for (const arg of userArgs) {
    if (arg === '--no-apply') {
      autoApply = false;
    } else if (arg === '--apply') {
      autoApply = true;
    } else if (!arg.startsWith('-') && !explicitFile) {
      explicitFile = arg;
    }
  }

  // 1. Locate candidate cloud-init user-data file
  const candidatePaths = [
    explicitFile,
    process.env.CLOUD_INIT_USER_DATA,
    '/var/lib/cloud/instance/user-data.txt',
    '/var/lib/cloud/seed/nocloud-net/user-data',
    '/var/lib/cloud/seed/nocloud/user-data',
    '/etc/axonwall/cloud-config.yaml',
  ].filter(Boolean) as string[];

  let resolvedPath = '';
  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      resolvedPath = p;
      break;
    }
  }

  if (!resolvedPath) {
    console.log(`${cYellow}[Axonwall Cloud-Init] No cloud-init user-data detected in standard locations.${cReset}`);
    return;
  }

  console.log(`${cCyan}${cBold}[Axonwall Cloud-Init] Found cloud-config at ${resolvedPath}${cReset}`);
  const rawContent = fs.readFileSync(resolvedPath, 'utf-8');

  let cloudConfig: FullCloudInit;
  try {
    cloudConfig = parseCloudInitYaml(rawContent);
  } catch (err: any) {
    console.error(`${cRed}[✗] Failed to parse cloud-config YAML: ${err.message}${cReset}`);
    process.exit(1);
  }

  const isRoot = typeof process.getuid === 'function' ? process.getuid() === 0 : false;
  const isDryRun = userArgs.includes('--dry-run');

  // 2. Reconcile hostname
  if (cloudConfig.hostname) {
    console.log(`[+] Setting system hostname to: ${cloudConfig.hostname}`);
    if (!isDryRun && isRoot) {
      try {
        execFileSync('hostnamectl', ['--no-ask-password', 'set-hostname', '--', cloudConfig.hostname], {
          stdio: 'ignore',
          timeout: 2000,
        });
      } catch {
        try {
          fs.writeFileSync('/etc/hostname', cloudConfig.hostname.trim() + '\n', 'utf-8');
        } catch {}
      }
    }
  }

  // 3. Reconcile SSH keys from top-level ssh_authorized_keys and privileged users (root, admin, or sudoers)
  const allKeys: string[] = [];
  const openSshRegex = /^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+[A-Za-z0-9+/=]+(\s+[^\r\n]*)?$/;

  if (Array.isArray(cloudConfig.ssh_authorized_keys)) {
    for (const k of cloudConfig.ssh_authorized_keys) {
      const trimmed = k.trim();
      if (trimmed && openSshRegex.test(trimmed)) {
        allKeys.push(trimmed);
      }
    }
  }
  if (cloudConfig.users && cloudConfig.users.length > 0) {
    for (const u of cloudConfig.users) {
      const isPrivileged = u.name === 'root' || u.name === 'admin' || (u.sudo && u.sudo.includes('ALL'));
      if (isPrivileged && u.ssh_authorized_keys && u.ssh_authorized_keys.length > 0) {
        for (const k of u.ssh_authorized_keys) {
          const trimmed = k.trim();
          if (trimmed && openSshRegex.test(trimmed)) {
            allKeys.push(trimmed);
          }
        }
      }
    }
  }
  if (allKeys.length > 0) {
    console.log(`[+] Found ${allKeys.length} validated administrative SSH public key(s) in cloud-config.`);
    if (!isDryRun && isRoot) {
      try {
        const sshDir = '/root/.ssh';
        const authKeysPath = path.join(sshDir, 'authorized_keys');
        fs.mkdirSync(sshDir, { recursive: true, mode: 0o700 });
        try { fs.chmodSync(sshDir, 0o700); } catch {}
        let existingKeys = '';
        if (fs.existsSync(authKeysPath)) {
          existingKeys = fs.readFileSync(authKeysPath, 'utf-8');
        }
        const newKeys = allKeys.filter((k) => !existingKeys.includes(k));
        if (newKeys.length > 0) {
          fs.appendFileSync(authKeysPath, '\n' + newKeys.join('\n') + '\n', { mode: 0o600 });
          console.log(`[+] Injected ${newKeys.length} SSH public key(s) into /root/.ssh/authorized_keys.`);
        }
        try { fs.chmodSync(authKeysPath, 0o600); } catch {}
      } catch (err: any) {
        console.warn(`[!] Unable to write SSH keys: ${err.message}`);
      }
    }
  }

  // 4. Reconcile Axonwall specific configuration and standard Cloud-Init credentials / network-config
  const axon = cloudConfig.axonwall;
  const rawAdminUser = axon?.auth?.admin_username || cloudConfig.user || 'admin';
  let rawAdminPass = axon?.auth?.admin_password;
  if (!rawAdminPass || rawAdminPass === 'CHANGE_ME_ON_DEPLOY') {
    rawAdminPass = cloudConfig.password;
  }
  if (!rawAdminPass || rawAdminPass === 'CHANGE_ME_ON_DEPLOY') {
    rawAdminPass = cloudConfig.users?.find((u) => u.plain_text_passwd)?.plain_text_passwd;
  }
  if (rawAdminPass === 'CHANGE_ME_ON_DEPLOY') {
    rawAdminPass = undefined;
  }

  if (rawAdminPass) {
    console.log(`[+] Administrator credentials configured for user '${rawAdminUser}'.`);
    if (!isDryRun) {
      try {
        let finalAdminPass = rawAdminPass;
        if (!rawAdminPass.startsWith('scrypt$') && !/^\$(1|5|6|y|2a|2b|2y)\$/.test(rawAdminPass)) {
          const salt = crypto.randomBytes(16).toString('hex');
          const hash = crypto.scryptSync(rawAdminPass, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
          finalAdminPass = `scrypt$${salt}$${hash}`;
        }
        if (!/^\$(1|5|6|y|2a|2b|2y)\$/.test(finalAdminPass)) {
          if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(rawAdminUser)) {
            throw new Error(`Invalid administrator username: ${rawAdminUser}`);
          }
          fs.mkdirSync(ETC_DIR, { recursive: true, mode: 0o775 });
          const adminEnvPath = path.join(ETC_DIR, 'admin.env');
          const envContent = `LOCAL_ADMIN_USER=${rawAdminUser}\nLOCAL_ADMIN_PASSWORD=${finalAdminPass}\n`;
          fs.writeFileSync(adminEnvPath, envContent, { mode: 0o660 });
          try { fs.chmodSync(adminEnvPath, 0o660); } catch {}

          const nowIso = new Date().toISOString();
          try {
            fs.writeFileSync(path.join(ETC_DIR, '.password_changed'), `${nowIso}\n`, { mode: 0o644 });
          } catch {}

          // Mirror to persistent /var/lib/axonwall/etc-axonwall/admin.env for A/B slot survival
          try {
            const persistDir = '/var/lib/axonwall/etc-axonwall';
            fs.mkdirSync(persistDir, { recursive: true, mode: 0o775 });
            fs.writeFileSync(path.join(persistDir, 'admin.env'), envContent, { mode: 0o660 });
            fs.chmodSync(path.join(persistDir, 'admin.env'), 0o660);
            fs.writeFileSync('/var/lib/axonwall/.password_changed', `${nowIso}\n`, { mode: 0o644 });
          } catch {}
          fixSharedConfigOwnership();
        }
      } catch (err: any) {
        console.warn(`[!] Unable to write admin.env: ${err.message}`);
      }
    }
  }

  if (axon?.auth?.ztp?.enabled) {
    console.log(`[+] Zero-Touch Provisioning (ZTP) enabled via ${axon.auth.ztp.controller_url || '<default-controller>'}.`);
    if (!isDryRun) {
      try {
        fs.mkdirSync(ETC_DIR, { recursive: true, mode: 0o775 });
        const ctrlEnvPath = path.join(ETC_DIR, 'controller.env');
        const tokenVal =
          axon.auth.ztp.enrollment_token && axon.auth.ztp.enrollment_token !== 'CHANGE_ME_ON_DEPLOY'
            ? axon.auth.ztp.enrollment_token
            : '';
        const content = `AXONWALL_ZTP_TOKEN=${tokenVal}\nAXONWALL_CONTROLLER_URL=${axon.auth.ztp.controller_url || ''}\n`;
        fs.writeFileSync(ctrlEnvPath, content, { mode: 0o640 });
        try { fs.chmodSync(ctrlEnvPath, 0o640); } catch {}
        try {
          const persistDir = '/var/lib/axonwall/etc-axonwall';
          fs.mkdirSync(persistDir, { recursive: true, mode: 0o775 });
          fs.writeFileSync(path.join(persistDir, 'controller.env'), content, { mode: 0o640 });
          fs.chmodSync(path.join(persistDir, 'controller.env'), 0o640);
        } catch {}
        fixSharedConfigOwnership();
      } catch (err: any) {
        console.warn(`[!] Unable to write controller.env: ${err.message}`);
      }
    }
  }

  // 4b. Desired State & Cloud-Init network-config reconciliation
  const mergedDesiredState: Record<string, any> = axon?.desired_state
    ? structuredClone(axon.desired_state)
    : {};

  if (cloudConfig.hostname || cloudConfig.timezone) {
    mergedDesiredState.system = { ...(mergedDesiredState.system || {}) };
    if (cloudConfig.hostname && !mergedDesiredState.system.hostname) {
      mergedDesiredState.system.hostname = cloudConfig.hostname;
    }
    if (cloudConfig.timezone && !mergedDesiredState.system.timezone) {
      mergedDesiredState.system.timezone = cloudConfig.timezone;
    }
  }

  // Check for companion network-config file (e.g. from Proxmox VE Cloud-Init or NoCloud seed)
  const netConfigCandidates = [
    path.join(path.dirname(resolvedPath), 'network-config'),
    '/var/lib/cloud/seed/nocloud-net/network-config',
    '/var/lib/cloud/seed/nocloud/network-config',
    '/var/lib/partman/network-config',
  ];
  for (const ncPath of netConfigCandidates) {
    if (fs.existsSync(ncPath)) {
      try {
        const netRaw = fs.readFileSync(ncPath, 'utf-8');
        let physicalNics: string[] = [];
        try {
          if (fs.existsSync('/sys/class/net')) {
            physicalNics = fs
              .readdirSync('/sys/class/net')
              .filter(
                (n) =>
                  !/^(lo|wg.*|tailscale.*|tun.*|tap.*|sit.*|ip6tnl.*|gre.*|gretap.*|erspan.*|ip_vti.*|ip6_vti.*|ip6gre.*|docker.*|veth.*|br-.*|virbr.*|dummy.*|bond.*|pimreg)$/.test(
                    n
                  )
              );
          }
        } catch {}
        const parsedNet = parseCloudInitNetworkConfig(netRaw, physicalNics);
        if (parsedNet) {
          console.log(`[+] Found Cloud-Init network-config at ${ncPath} (${parsedNet.interfaces.length} interface(s)).`);
          if (!Array.isArray(mergedDesiredState.interfaces) || mergedDesiredState.interfaces.length === 0) {
            if (parsedNet.interfaces.length > 0) {
              mergedDesiredState.interfaces = parsedNet.interfaces;
            }
          }
          if (parsedNet.dnsServers.length > 0 || parsedNet.searchDomain) {
            mergedDesiredState.system = { ...(mergedDesiredState.system || {}) };
            if (parsedNet.dnsServers.length > 0 && !mergedDesiredState.system.dnsServers) {
              mergedDesiredState.system.dnsServers = parsedNet.dnsServers;
            }
            if (parsedNet.searchDomain && !mergedDesiredState.system.domain) {
              mergedDesiredState.system.domain = parsedNet.searchDomain;
            }
          }
        }
      } catch {}
      break;
    }
  }

  if (Object.keys(mergedDesiredState).length > 0) {
    console.log(`[+] Staging declarative desired_state from cloud-config into /etc/axonwall/conf.d/99-cloudinit.yaml...`);
    if (!isDryRun) {
      try {
        const yamlPayload = serializeYaml(mergedDesiredState);
        for (const baseDir of [ETC_DIR, PERSIST_YAML_DIR]) {
          const confD = path.join(baseDir, 'conf.d');
          fs.mkdirSync(confD, { recursive: true, mode: 0o775 });
          const cloudInitYamlPath = path.join(confD, '99-cloudinit.yaml');
          fs.writeFileSync(cloudInitYamlPath, yamlPayload, { mode: 0o660 });
          try { fs.chmodSync(cloudInitYamlPath, 0o660); } catch {}
        }
        fixSharedConfigOwnership();
      } catch (err: any) {
        console.warn(`[!] Unable to write 99-cloudinit.yaml: ${err.message}`);
      }
    }
  }

  // 5. Secure cloud-init seed files so secrets are not world-readable
  if (!isDryRun && isRoot) {
    try {
      for (const p of [
        '/var/lib/cloud/seed/nocloud-net/user-data',
        '/var/lib/cloud/seed/nocloud/user-data',
        '/var/lib/partman/cloud-config.yaml',
      ]) {
        if (fs.existsSync(p)) {
          fs.chmodSync(p, 0o600);
        }
      }
    } catch {}
  }

  // 6. Expand data partition if growpart is available (QCOW2 / Cloud Image auto-grow)
  if (!isDryRun && isRoot) {
    try {
      const res = spawnSync('which', ['growpart'], { stdio: 'pipe' });
      if (res.status === 0) {
        const findmnt = spawnSync('findmnt', ['-n', '-o', 'SOURCE', '/var/lib/axonwall'], { encoding: 'utf-8' });
        const dev = findmnt.stdout?.trim();
        if (dev && dev.startsWith('/dev/')) {
          const diskRes = spawnSync('lsblk', ['-no', 'PKNAME', dev], { encoding: 'utf-8' });
          const disk = diskRes.stdout?.trim();
          const partMatch = dev.match(/\d+$/);
          if (disk && partMatch) {
            const partNum = partMatch[0];
            console.log(`[+] Attempting dynamic partition resize of /dev/${disk} partition ${partNum}...`);
            spawnSync('growpart', [`/dev/${disk}`, partNum], { stdio: 'inherit' });
            const fstypeRes = spawnSync('lsblk', ['-no', 'FSTYPE', dev], { encoding: 'utf-8' });
            const fstype = fstypeRes.stdout?.trim();
            if (fstype === 'xfs') {
              spawnSync('xfs_growfs', ['/var/lib/axonwall'], { stdio: 'inherit' });
            } else {
              spawnSync('resize2fs', [dev], { stdio: 'inherit' });
            }
          }
        }
      }
    } catch {}
  }

  // 6. Apply if requested
  if (autoApply && !isDryRun) {
    console.log(`\n${cCyan}Compiling and applying configuration from cloud-init...${cReset}`);
    await cmdApply(true);
  } else if (isDryRun) {
    console.log(`\n${cGreen}[✓] Cloud-init dry-run completed successfully. All schemas and parameters validated.${cReset}`);
  }
}

const CORE_ROLE_PLUGIN_IDS = new Set(['core-firewall', 'core-nas', 'core-k3s', 'core-virt', 'core-vigilante']);

async function setCoreRolePlugin(pluginId: string, enable: boolean) {
  const state = cmdValidate(true);
  const currentCaps = resolveCapabilities(state);
  const nextCaps = {
    firewallEnabled: pluginId === 'core-firewall' ? enable : currentCaps.firewallEnabled,
    nasEnabled: pluginId === 'core-nas' ? enable : currentCaps.nasEnabled,
    k3sEnabled: pluginId === 'core-k3s' ? enable : currentCaps.k3sEnabled,
    virtEnabled: pluginId === 'core-virt' ? enable : currentCaps.virtEnabled,
    vigilanteEnabled: pluginId === 'core-vigilante' ? enable : currentCaps.vigilanteEnabled,
  };
  state.capabilities = nextCaps;

  if (pluginId === 'core-nas') {
    state.nas = state.nas || {
      enabled: enable,
      workgroup: 'WORKGROUP',
      serverString: 'Axonwall Enterprise ZFS NAS',
      pools: [],
      datasets: [],
      snapshotPolicies: [],
      smbShares: [],
      nfsExports: [],
      iscsiTargets: [],
    };
    state.nas.enabled = enable;
  } else if (pluginId === 'core-k3s') {
    state.k3s = state.k3s || {
      enabled: enable,
      clusterCidr: '10.42.0.0/16',
      serviceCidr: '10.43.0.0/16',
      nodeIpInterface: 'lan',
      flannelBackend: 'wireguard-native',
      disableTraefik: false,
      autoJoinHaPeer: true,
      openEbs: {
        enabled: true,
        zfsLocalPvEnabled: true,
        zfsLocalPvPool: 'tank',
        replicatedStorageEnabled: true,
        defaultReplicaCount: 2,
        replicatedBackingPool: 'tank/openebs-replicated',
      },
      workloads: [],
    };
    state.k3s.enabled = enable;
    if (!enable) {
      const depRes = disablePluginWithDependents('core-k3s', state);
      Object.assign(state, depRes.state);
      if (depRes.autoDisabledDependents.length > 0) {
        console.log(
          `${cYellow}[!] Auto-disabled dependent plugins requiring core-k3s: ${depRes.autoDisabledDependents.join(', ')}${cReset}`
        );
      }
    }
  } else if (pluginId === 'core-virt') {
    state.virt = state.virt || {
      enabled: enable,
      defaultPool: 'tank',
      isoPool: 'tank',
      vms: [],
      containers: [],
      isos: [],
      pciDevices: [],
      backupJobs: [],
      vxlanZones: [],
    };
    state.virt.enabled = enable;
  } else if (pluginId === 'core-vigilante') {
    state.vigilante =
      state.vigilante ||
      VigilanteConfigSchema.parse({
        enabled: enable,
      });
    state.vigilante.enabled = enable;
  }

  const yamlFiles = serializeDesiredStateToYamlFiles(state);
  for (const dir of [ETC_DIR, PERSIST_YAML_DIR]) {
    try {
      fs.mkdirSync(path.join(dir, 'conf.d'), { recursive: true });
      for (const [filename, content] of Object.entries(yamlFiles)) {
        fs.writeFileSync(path.join(dir, filename), content, { mode: 0o660 });
      }
      // Remove stale conf.d/99-cloudinit.yaml override now that state is persisted to canonical domain files
      const ciOverride = path.join(dir, 'conf.d', '99-cloudinit.yaml');
      if (fs.existsSync(ciOverride)) {
        fs.rmSync(ciOverride, { force: true });
      }
    } catch {}
  }

  console.log(
    `[+] ${enable ? 'Enabling' : 'Disabling'} core role '${pluginId}' (capabilities: firewall=${nextCaps.firewallEnabled}, nas=${nextCaps.nasEnabled}, k3s=${nextCaps.k3sEnabled}, virt=${nextCaps.virtEnabled}, vigilante=${nextCaps.vigilanteEnabled})...`
  );
  await cmdApply(true);
}

async function setExtensionPlugin(pluginId: string, enable: boolean) {
  const manifest = BUILTIN_PLUGINS.find((p) => p.id === pluginId && p.category !== 'core_role');
  if (!manifest) {
    console.error(
      `${cRed}Unknown plugin '${pluginId}'. Valid plugins: ${BUILTIN_PLUGINS.map((p) => p.id).join(', ')}${cReset}`
    );
    process.exit(1);
  }

  const state = cmdValidate(true);

  const nextPlugins = (state.plugins || []).filter((p: any) => p.id !== pluginId);
  nextPlugins.push({ id: pluginId, enabled: enable, config: {} });
  state.plugins = nextPlugins;

  if (pluginId === 'rosenpass') {
    state.rosenpass = {
      ...(state.rosenpass || {
        listenPort: 9999,
        listenAddresses: ['0.0.0.0:9999', '[::]:9999'],
        wgDevice: 'wg0',
        verbosity: 'Quiet',
        rekeyIntervalSeconds: 120,
        failClosedBootGuard: true,
        memfdSecret: true,
        publicKeyPath: '/etc/rosenpass/pq.pk',
        secretKeyPath: '/etc/rosenpass/pq.sk',
        peers: [],
      }),
      enabled: enable,
    };
  } else if (pluginId === 'haproxy') {
    state.haproxy = {
      ...(state.haproxy || { mode: 'http', frontends: [], backends: [] }),
      enabled: enable,
    };
  } else if (pluginId === 'freeradius') {
    state.freeradius = {
      ...(state.freeradius || { authPort: 1812, acctPort: 1813, clients: [], ldapSync: true }),
      enabled: enable,
    };
  } else if (pluginId === 'snmp') {
    state.snmp = {
      ...(state.snmp || {
        community: 'public',
        sysLocation: 'Server Room',
        sysContact: 'admin@axonwall.local',
        listenPort: 161,
      }),
      enabled: enable,
    };
  } else if (pluginId === 'nut-ups') {
    state.ups = {
      ...(state.ups || {
        name: 'ups',
        driver: 'usbhid-ups',
        port: 'auto',
        shutdownBatteryPct: 20,
        lowBatteryRuntimeSec: 300,
      }),
      enabled: enable,
    };
  } else if (pluginId === 'headscale') {
    state.headscale = {
      ...(state.headscale || {
        magicDnsDomain: 'mesh.axonwall.local',
      }),
      enabled: enable,
    };
  } else if (pluginId === 'vigilant-octo-waffle') {
    if (enable) {
      const depRes = enablePluginWithDependencies('vigilant-octo-waffle', state);
      Object.assign(state, depRes.state);
      if (depRes.autoEnabledDependencies.length > 0) {
        console.log(
          `${cCyan}[+] Auto-enabled required plugin dependency: ${depRes.autoEnabledDependencies.join(', ')}${cReset}`
        );
      }
    } else {
      const depRes = disablePluginWithDependents('vigilant-octo-waffle', state);
      Object.assign(state, depRes.state);
    }
  }

  const yamlFiles = serializeDesiredStateToYamlFiles(state);
  for (const dir of [ETC_DIR, PERSIST_YAML_DIR]) {
    try {
      fs.mkdirSync(path.join(dir, 'conf.d'), { recursive: true });
      for (const [filename, content] of Object.entries(yamlFiles)) {
        fs.writeFileSync(path.join(dir, filename), content, { mode: 0o660 });
      }
    } catch {}
  }

  console.log(`[+] ${enable ? 'Enabling' : 'Disabling'} extension plugin '${pluginId}' (${manifest.name})...`);

  try {
    await sendAgentSocketRequest('/v1/system/plugins/action', 'POST', {
      pluginId,
      action: enable ? 'enable' : 'disable',
    });
  } catch {
    // Daemon may be offline in test/chroot environments
  }

  await cmdApply(true);
}

async function cmdPlugin(args: string[]) {
  const subcmd = (args[0] || 'list').toLowerCase();
  const pluginId = args[1];

  switch (subcmd) {
    case 'list':
    case 'ls': {
      const state = cmdValidate(true);
      const caps = resolveCapabilities(state);
      const coreRoles = BUILTIN_PLUGINS.filter((p) => p.category === 'core_role');

      console.log(`\n${cCyan}${cBold}=== Axonwall Core Appliance Roles (/etc/axonwall/system.yaml) ===${cReset}\n`);
      console.log(
        `  ${cBold}${'ID'.padEnd(28)} ${'NAME'.padEnd(46)} ${'STATUS'.padEnd(16)} SYSTEMD UNITS${cReset}`
      );
      console.log(`  ${'-'.repeat(105)}`);
      for (const role of coreRoles) {
        const enabled =
          role.id === 'core-firewall'
            ? caps.firewallEnabled
            : role.id === 'core-nas'
              ? caps.nasEnabled
              : role.id === 'core-k3s'
                ? caps.k3sEnabled
                : role.id === 'core-virt'
                  ? caps.virtEnabled
                  : caps.vigilanteEnabled;
        const statusStr = enabled ? `${cGreen}ENABLED${cReset}` : `${cDim}DISABLED${cReset}`;
        const unitsList = (role.systemdUnits || []).join(' ');
        console.log(
          `  ${role.id.padEnd(28)} ${role.name.padEnd(46)} ${statusStr.padEnd(25)} ${cDim}${unitsList}${cReset}`
        );
      }

      try {
        const res = await sendAgentSocketRequest<{ plugins: any[]; osFamily: string }>('/v1/system/plugins', 'GET');
        console.log(`\n${cCyan}${cBold}=== Axonwall Extension Plugins (${res.osFamily.toUpperCase()} Host) ===${cReset}\n`);
        console.log(
          `  ${cBold}${'ID'.padEnd(28)} ${'NAME'.padEnd(46)} ${'STATE'.padEnd(14)} ${'INSTALL'.padEnd(14)} PACKAGES${cReset}`
        );
        console.log(`  ${'-'.repeat(115)}`);
        for (const p of res.plugins) {
          const enabled = isPluginEnabled(p.id, state);
          const stateStr = enabled ? `${cGreen}ENABLED${cReset}` : `${cDim}DISABLED${cReset}`;
          let installStr = `${cDim}Available${cReset}`;
          if (p.bundled) {
            installStr = `${cGreen}Bundled (OS)${cReset}`;
          } else if (p.installed) {
            installStr = `${cCyan}Installed${cReset}`;
          }
          const pkgList = (p.packages || []).join(' ');
          console.log(
            `  ${p.id.padEnd(28)} ${p.name.padEnd(46)} ${stateStr.padEnd(23)} ${installStr.padEnd(23)} ${cDim}${pkgList}${cReset}`
          );
        }
        console.log('');
      } catch (err: any) {
        const extPlugins = BUILTIN_PLUGINS.filter((p) => p.category !== 'core_role');
        console.log(`\n${cCyan}${cBold}=== Axonwall Extension Plugins (/etc/axonwall/system.yaml) ===${cReset}\n`);
        for (const p of extPlugins) {
          const enabled = isPluginEnabled(p.id, state);
          const stateStr = enabled ? `${cGreen}ENABLED${cReset}` : `${cDim}DISABLED${cReset}`;
          console.log(`  ${p.id.padEnd(28)} ${p.name.padEnd(46)} ${stateStr}`);
        }
        console.log('');
      }
      break;
    }
    case 'enable': {
      if (!pluginId) {
        console.error(`${cRed}Usage: axonwallctl plugin enable <plugin-id>${cReset}`);
        process.exit(1);
      }
      if (CORE_ROLE_PLUGIN_IDS.has(pluginId)) {
        await setCoreRolePlugin(pluginId, true);
      } else {
        await setExtensionPlugin(pluginId, true);
      }
      break;
    }
    case 'disable': {
      if (!pluginId) {
        console.error(`${cRed}Usage: axonwallctl plugin disable <plugin-id>${cReset}`);
        process.exit(1);
      }
      if (CORE_ROLE_PLUGIN_IDS.has(pluginId)) {
        await setCoreRolePlugin(pluginId, false);
      } else {
        await setExtensionPlugin(pluginId, false);
      }
      break;
    }
    case 'install':
    case 'add': {
      if (!pluginId) {
        console.error(`${cRed}Usage: axonwallctl plugin install <plugin-id>${cReset}`);
        process.exit(1);
      }
      if (CORE_ROLE_PLUGIN_IDS.has(pluginId)) {
        await setCoreRolePlugin(pluginId, true);
        break;
      }
      console.log(`[+] Installing plugin '${pluginId}'...`);
      try {
        const res = await sendAgentSocketRequest<{ success: boolean; message: string; output?: string }>(
          '/v1/system/plugins/action',
          'POST',
          { pluginId, action: 'install' }
        );
        if (res.success) {
          console.log(`${cGreen}[✓] ${res.message}${cReset}`);
        } else {
          console.error(`${cRed}[!] ${res.message}${cReset}`);
          if (res.output) console.error(res.output);
          process.exit(1);
        }
      } catch (err: any) {
        console.error(`${cRed}Failed to install plugin:${cReset}`, err?.message || err);
        process.exit(1);
      }
      break;
    }
    case 'remove':
    case 'uninstall':
    case 'del': {
      if (!pluginId) {
        console.error(`${cRed}Usage: axonwallctl plugin remove <plugin-id>${cReset}`);
        process.exit(1);
      }
      if (CORE_ROLE_PLUGIN_IDS.has(pluginId)) {
        await setCoreRolePlugin(pluginId, false);
        break;
      }
      console.log(`[+] Removing plugin '${pluginId}'...`);
      try {
        const res = await sendAgentSocketRequest<{ success: boolean; message: string; output?: string }>(
          '/v1/system/plugins/action',
          'POST',
          { pluginId, action: 'uninstall' }
        );
        if (res.success) {
          console.log(`${cGreen}[✓] ${res.message}${cReset}`);
        } else {
          console.error(`${cRed}[!] ${res.message}${cReset}`);
          if (res.output) console.error(res.output);
          process.exit(1);
        }
      } catch (err: any) {
        console.error(`${cRed}Failed to remove plugin:${cReset}`, err?.message || err);
        process.exit(1);
      }
      break;
    }
    case 'reconfigure':
    case 're-sync':
    case 'sync': {
      if (!pluginId) {
        console.error(`${cRed}Usage: axonwallctl plugin re-sync <plugin-id>${cReset}`);
        process.exit(1);
      }
      console.log(`[+] Re-syncing configuration for plugin '${pluginId}'...`);
      try {
        const res = await sendAgentSocketRequest<{ success: boolean; message: string }>(
          '/v1/system/plugins/action',
          'POST',
          { pluginId, action: 'reconfigure' }
        );
        if (res.success) {
          console.log(`${cGreen}[✓] ${res.message}${cReset}`);
        } else {
          console.error(`${cRed}[!] ${res.message}${cReset}`);
          process.exit(1);
        }
      } catch (err: any) {
        console.error(`${cRed}Failed to re-sync plugin:${cReset}`, err?.message || err);
        process.exit(1);
      }
      break;
    }
    default:
      console.error(`${cRed}Unknown plugin subcommand: ${subcmd}${cReset}`);
      console.log(`Usage: axonwallctl plugin <list|enable|disable|install|remove|re-sync> [plugin-id]`);
      process.exit(1);
  }
}

async function cmdUpdate(args: string[]) {
  let targetVersion = '';
  let targetSlot: 'A' | 'B' | undefined;
  let aptUpgrade = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if ((arg === '--version' || arg === '-v') && args[i + 1]) {
      targetVersion = args[++i]!;
    } else if (arg.startsWith('--version=')) {
      targetVersion = arg.slice('--version='.length);
    } else if ((arg === '--slot' || arg === '-s') && args[i + 1]) {
      const s = args[++i]!.toUpperCase();
      if (s === 'A' || s === 'B') targetSlot = s;
    } else if (arg === '--apt' || arg === '--apt-upgrade') {
      aptUpgrade = true;
    }
  }

  let installMode: 'ab' | 'rolling' = 'ab';
  for (const modePath of [path.join(ETC_DIR, 'install-mode'), '/var/lib/axonwall/install-mode']) {
    try {
      if (fs.existsSync(modePath) && fs.readFileSync(modePath, 'utf8').toLowerCase().includes('rolling')) {
        installMode = 'rolling';
        break;
      }
    } catch {}
  }

  if (installMode === 'rolling') {
    console.log(`${cCyan}${cBold}=== Axonwall Rolling Standard Linux Updater ===${cReset}`);
  } else {
    console.log(`${cCyan}${cBold}=== Axonwall Dual-Root A/B Firmware Updater ===${cReset}`);
  }

  if (aptUpgrade) {
    console.log(`[+] Running Debian APT package upgrade (apt-get update && apt-get upgrade -y)...`);
    const updateRes = spawnSync('apt-get', ['update', '-y'], {
      stdio: 'inherit',
      env: { ...process.env, DEBIAN_FRONTEND: 'noninteractive' },
    });
    if (updateRes.status === 0) {
      spawnSync(
        'apt-get',
        ['-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold', 'upgrade', '-y'],
        {
          stdio: 'inherit',
          env: { ...process.env, DEBIAN_FRONTEND: 'noninteractive' },
        }
      );
    }
  }

  const updaterPaths = ['/usr/local/bin/axonwall-update', '/usr/sbin/axonwall-update'];
  for (const up of updaterPaths) {
    if (fs.existsSync(up)) {
      const cliArgs: string[] = [];
      if (installMode === 'rolling') {
        cliArgs.push('--rolling');
      } else if (targetSlot) {
        cliArgs.push('--slot', targetSlot);
      }
      if (targetVersion) {
        cliArgs.push('--version', targetVersion);
      }
      const res = spawnSync(up, cliArgs, { stdio: 'inherit' });
      if (res.status !== 0) {
        process.exit(res.status || 1);
      }
      return;
    }
  }

  // Fallback to daemon API
  try {
    const resp = await sendAgentSocketRequest<{ success: boolean; message: string }>('/v1/system/update', 'POST', {
      slot: targetSlot || 'B',
      version: targetVersion || undefined,
    });
    if (resp.success) {
      console.log(`${cGreen}[✓] ${resp.message}${cReset}`);
    } else {
      console.error(`${cRed}[✗] ${resp.message}${cReset}`);
      process.exit(1);
    }
  } catch (err: any) {
    console.error(`${cRed}[✗] System update failed: ${err?.message || err}${cReset}`);
    process.exit(1);
  }
}

async function cmdMcp(args: string[]) {
  const subcmd = (args[0] || 'status').toLowerCase();
  switch (subcmd) {
    case 'status': {
      try {
        const res = await sendAgentSocketRequest<any>('/v1/mcp/status', 'GET');
        console.log(`\n${cCyan}${cBold}=== Axonwall MCP Server Status ===${cReset}\n`);
        console.log(
          `  Master Switch : ${res.masterEnabled ? `${cGreen}ENABLED${cReset}` : `${cRed}DISABLED${cReset}`} ${res.disabledReason ? `(${res.disabledReason})` : ''}`
        );
        console.log(`  Active Leases : ${(res.leases || []).length}`);
        for (const l of res.leases || []) {
          console.log(`    - [${l.id}] ${l.clientName} (${l.transport}) expires ${l.expiresAt}`);
        }
        console.log('');
      } catch (err: any) {
        console.error(`${cRed}Failed to fetch MCP status:${cReset}`, err?.message || err);
        process.exit(1);
      }
      break;
    }
    case 'enable': {
      console.log(`[+] Enabling Axonwall MCP Server...`);
      const res = await sendAgentSocketRequest<any>('/v1/mcp/toggle', 'POST', { enabled: true });
      console.log(
        `${cGreen}[✓] MCP Master Switch is now ${res.masterEnabled ? 'ENABLED' : 'DISABLED'}.${cReset}`
      );
      break;
    }
    case 'disable': {
      console.log(`[+] Disabling Axonwall MCP Server and revoking active leases...`);
      const res = await sendAgentSocketRequest<any>('/v1/mcp/toggle', 'POST', {
        enabled: false,
        reason: 'Disabled via axonwallctl',
      });
      console.log(
        `${cGreen}[✓] MCP Master Switch is now ${res.masterEnabled ? 'ENABLED' : 'DISABLED'}.${cReset}`
      );
      break;
    }
    case 'flush': {
      console.log(`[+] Flushing all active MCP session leases...`);
      await sendAgentSocketRequest<any>('/v1/mcp/leases/flush', 'POST', {});
      console.log(`${cGreen}[✓] All MCP leases revoked.${cReset}`);
      break;
    }
    default:
      console.error(`${cRed}Unknown mcp subcommand: ${subcmd}${cReset}`);
      console.log(`Usage: axonwallctl mcp <status|enable|disable|flush>`);
      process.exit(1);
  }
}

function cmdCompletion(args: string[]) {
  const shell = (args[0] || 'zsh').toLowerCase();
  const pluginIds = BUILTIN_PLUGINS.map((p) => p.id).join(' ');
  const sections = AXONWALL_YAML_DOMAINS.map((d) => d.filename.replace(/\.ya?ml$/, '')).join(' ');

  if (shell === 'zsh') {
    const omzPlugin = '/usr/share/oh-my-zsh/plugins/axonwall/axonwall.plugin.zsh';
    if (fs.existsSync(omzPlugin)) {
      console.log(fs.readFileSync(omzPlugin, 'utf8'));
      return;
    }
    console.log(`#compdef axonwallctl ctl
_axonwallctl() {
  local -a commands
  commands=(
    'status:Show status of /etc/axonwall/*.yaml files and daemon connectivity'
    'validate:Validate all /etc/axonwall/*.yaml files against Zod schemas'
    'diff:Show uncommitted YAML changes and preview compiled nftables ruleset'
    'apply:Compile and apply /etc/axonwall/*.yaml'
    'confirm:Confirm pending configuration commit and disarm auto-rollback'
    'rollback:Abort pending commit and revert to last-known-good configuration'
    'reload:Reload all services and Web GUI state from /etc/axonwall/*.yaml'
    'update:Update Axonwall packages in-place or flash standby A/B slot'
    'plugin:Manage core appliance roles and extension plugins'
    'mcp:Manage Axonwall MCP server master switch and leases'
    'cloudinit:Reconcile or export cloud-init (#cloud-config) user-data'
    'edit:Open /etc/axonwall/<section>.yaml in \$EDITOR, validate, and apply'
    'export:Output complete unified configuration as a single YAML document'
    'completion:Generate shell completion script (zsh, bash)'
    'help:Display help information'
  )
  _describe -t commands 'axonwallctl command' commands
}
compdef _axonwallctl axonwallctl ctl`);
  } else if (shell === 'bash') {
    console.log(`# bash completion for axonwallctl
_axonwallctl_completions() {
  local cur prev words cword
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  case "\${prev}" in
    axonwallctl|ctl)
      COMPREPLY=( $(compgen -W "status validate diff apply confirm rollback reload update plugin mcp cloudinit edit export completion help" -- "\${cur}") )
      return 0
      ;;
    edit)
      COMPREPLY=( $(compgen -W "${sections}" -- "\${cur}") )
      return 0
      ;;
    plugin|plugins)
      COMPREPLY=( $(compgen -W "list enable disable install remove re-sync" -- "\${cur}") )
      return 0
      ;;
    enable|disable|install|remove|re-sync)
      COMPREPLY=( $(compgen -W "${pluginIds}" -- "\${cur}") )
      return 0
      ;;
    mcp)
      COMPREPLY=( $(compgen -W "status enable disable flush" -- "\${cur}") )
      return 0
      ;;
  esac
}
complete -F _axonwallctl_completions axonwallctl ctl`);
  } else {
    console.error(`${cRed}Unsupported shell '${shell}'. Supported shells: zsh, bash${cReset}`);
    process.exit(1);
  }
}

function showHelp() {
  console.log(`${cCyan}${cBold}axonwallctl — Axonwall Declarative YAML CLI (/etc/axonwall/*.yaml)${cReset}

${cBold}USAGE:${cReset}
  axonwallctl <command> [arguments]

${cBold}COMMANDS:${cReset}
  status              Show status of /etc/axonwall/*.yaml files, validation state, and daemon connectivity
  validate            Validate all /etc/axonwall/*.yaml and /etc/axonwall/conf.d/*.yaml files against Zod schemas
  diff                Show uncommitted YAML changes and preview compiled Linux nftables ruleset
  apply [--no-confirm] Compile and apply /etc/axonwall/*.yaml (auto-confirms unless --no-confirm)
  confirm             Confirm the currently pending configuration commit and disarm auto-rollback
  rollback            Immediately abort pending commit and revert to last-known-good configuration
  reload              Alias for 'apply' — reload all services and Web GUI state from /etc/axonwall/*.yaml
  update [options]    Update Axonwall packages in-place (Rolling mode) or flash standby slot (A/B mode)
                      Options: [--apt] [--version <ver>] [--slot <A|B>]
  plugin <cmd> [id]   Manage core roles & extension plugins (list, enable, disable, install, remove, re-sync)
  mcp <cmd>           Manage MCP server (status, enable, disable, flush) — disabled by default
  cloudinit [path]    Reconcile cloud-init (#cloud-config) user-data into /etc/axonwall config and state
  cloudinit export    Export running appliance into #cloud-config YAML or bootable NoCloud cidata.iso
                      Options: [-o <file.yaml>] [--iso <cidata.iso>] [--template] [--no-redact] [--hostname <name>]
  config [section]    Launch the Neovim Super Configurator (form-driven Lua TUI with full Vim field motions)
  edit [section]      Open /etc/axonwall/<section>.yaml in \$EDITOR (or pass --nvim for Super Configurator)
  export              Output the complete unified configuration as a single YAML document to stdout
  completion [shell]  Output shell completion script for zsh or bash

${cBold}SECTIONS (/etc/axonwall/<section>.yaml):${cReset}
  ${AXONWALL_YAML_DOMAINS.map((d) => d.filename.replace(/\.ya?ml$/, '')).join(', ')}
`);
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = (args[0] || 'status').toLowerCase();

  switch (cmd) {
    case 'status':
      await cmdStatus();
      break;
    case 'validate':
    case 'check':
      cmdValidate();
      break;
    case 'diff':
      cmdDiff();
      break;
    case 'apply':
    case 'reload': {
      const noConfirm = args.includes('--no-confirm');
      await cmdApply(!noConfirm);
      break;
    }
    case 'confirm':
      await cmdConfirm();
      break;
    case 'rollback':
      await cmdRollback();
      break;
    case 'update':
    case 'upgrade':
      await cmdUpdate(args.slice(1));
      break;
    case 'plugin':
    case 'plugins':
      await cmdPlugin(args.slice(1));
      break;
    case 'mcp':
      await cmdMcp(args.slice(1));
      break;
    case 'cloudinit':
    case 'cloud-init':
      await cmdCloudInit(args.slice(1));
      break;
    case 'config':
    case 'nvim':
    case 'super':
      await cmdConfig(args[1]);
      break;
    case 'dump-json':
      cmdDumpJson();
      break;
    case 'save-json':
      cmdSaveJson(args[1]);
      break;
    case 'edit': {
      const domainArg = args.slice(1).find((a) => !a.startsWith('-'));
      await cmdEdit(domainArg, args.slice(1));
      break;
    }
    case 'export':
      cmdExport();
      break;
    case 'completion':
      cmdCompletion(args.slice(1));
      break;
    case '-h':
    case '--help':
    case 'help':
      showHelp();
      break;
    default:
      console.error(`${cRed}Unknown command: ${cmd}${cReset}\n`);
      showHelp();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(`${cRed}Error:${cReset}`, err?.message || err);
  process.exit(1);
});
