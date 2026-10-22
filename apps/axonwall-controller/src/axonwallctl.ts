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
import { DesiredStateSchema, type DesiredState } from '@axonwall/lib/schemas';
import {
  parseCloudInitYaml,
  serializeYaml,
  parseStorageFromLsblk,
  buildCloudInitFromSystem,
  exportCloudInitYaml,
  generateCloudInitMetaData,
  buildNoCloudIso,
  type FullCloudInit,
  type CloudInitExportOptions,
} from '@axonwall/lib/cloudinit';

const ETC_DIR = process.env.AXONWALL_ETC_DIR || '/etc/axonwall';
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
  try {
    const confPath = path.join(ETC_DIR, 'interfaces.conf');
    if (fs.existsSync(confPath)) {
      for (const rawLine of fs.readFileSync(confPath, 'utf-8').split('\n')) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#') || !line.includes('=')) continue;
        const [k, v] = line.split('=', 2).map((s) => s.trim());
        if (k === 'WAN_INTERFACE' && v) wanDev = v;
        else if (k === 'LAN_INTERFACE' && v) lanDev = v;
        else if (k === 'OPT1_INTERFACE' && v) opt1Dev = v;
        else if (k === 'OPT2_INTERFACE' && v) opt2Dev = v;
      }
    }
  } catch {}

  const antiLockoutIfaces = ['lan'];
  if (opt1Dev) antiLockoutIfaces.push('opt1');
  if (opt2Dev) antiLockoutIfaces.push('opt2');

  return DesiredStateSchema.parse({
    version: 1,
    system: {
      hostname: 'axonwall',
      domain: 'home.arpa',
      timezone: 'UTC',
      dnsServers: ['1.1.1.1', '9.9.9.9'],
      antiLockout: {
        enabled: true,
        interface: 'lan',
        interfaces: antiLockoutIfaces,
        ports: [22, 80, 443, 2966, 3000],
      },
    },
    interfaces: [
      { name: 'wan', device: wanDev, type: 'dhcp', enabled: true, mtu: 1500, description: 'WAN Uplink' },
      { name: 'lan', device: lanDev, type: 'static', ipv4Address: '192.168.1.1/24', enabled: true, mtu: 1500, description: 'LAN Network' },
      ...(opt1Dev ? [{ name: 'opt1', device: opt1Dev, type: 'dhcp' as const, enabled: true, mtu: 1500, description: 'OPT1 Network' }] : []),
      ...(opt2Dev ? [{ name: 'opt2', device: opt2Dev, type: 'dhcp' as const, enabled: true, mtu: 1500, description: 'OPT2 Network' }] : []),
    ],
    rules: [],
  });
}

function ensureInitializedYamlFiles(): void {
  const files = readYamlConfigFiles();
  if (Object.keys(files).length > 0) return;

  const fallback = loadFallbackState();
  const serialized = serializeDesiredStateToYamlFiles(fallback);
  for (const dir of [ETC_DIR, PERSIST_YAML_DIR]) {
    try {
      fs.mkdirSync(path.join(dir, 'conf.d'), { recursive: true });
      for (const [filename, content] of Object.entries(serialized)) {
        fs.writeFileSync(path.join(dir, filename), content, { mode: 0o644 });
      }
    } catch {}
  }
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
    fs.mkdirSync(GITOPS_DIR, { recursive: true });
    if (!fs.existsSync(path.join(GITOPS_DIR, '.git'))) {
      execFileSync('git', ['init'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', ['config', 'user.name', 'Axonwall CLI'], { cwd: GITOPS_DIR, stdio: 'ignore' });
      execFileSync('git', ['config', 'user.email', 'cli@axonwall.local'], { cwd: GITOPS_DIR, stdio: 'ignore' });
    }
    fs.writeFileSync(path.join(GITOPS_DIR, 'state.json'), JSON.stringify(state, null, 2), 'utf-8');
    const yamlFiles = serializeDesiredStateToYamlFiles(state);
    for (const [filename, content] of Object.entries(yamlFiles)) {
      fs.writeFileSync(path.join(GITOPS_DIR, filename), content, 'utf-8');
    }
    execFileSync('git', ['add', 'state.json', ...AXONWALL_YAML_FILENAMES], { cwd: GITOPS_DIR, stdio: 'ignore' });
    const status = execFileSync('git', ['status', '--porcelain'], { cwd: GITOPS_DIR }).toString().trim();
    if (status.length > 0) {
      execFileSync('git', ['commit', '-m', message], { cwd: GITOPS_DIR, stdio: 'ignore' });
    }
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: GITOPS_DIR }).toString().trim();
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
      fs.mkdirSync(path.join(dir, 'conf.d'), { recursive: true });
      for (const [filename, content] of Object.entries(yamlFiles)) {
        const target = path.join(dir, filename);
        if (!fs.existsSync(target) || dir === PERSIST_YAML_DIR) {
          fs.writeFileSync(target, content, { mode: 0o644 });
        }
      }
    } catch {}
  }

  for (const jsonTarget of [STATE_JSON_PATH, path.join(ETC_DIR, 'state.json')]) {
    try {
      fs.mkdirSync(path.dirname(jsonTarget), { recursive: true });
      fs.writeFileSync(jsonTarget, serializedJson, { mode: 0o600 });
    } catch {}
  }

  // Compile artifacts via compileNftables(state)
  const { nftScript, files, reloadServices } = compileNftables(state);
  const bundleHash = crypto.createHash('sha256').update(nftScript).digest('hex');
  const jobId = `cli-${Date.now()}`;

  const filesPayload = [
    ...files.map((f) => ({ ...f, file_mode: f.fileMode })),
    ...Object.entries(yamlFiles).map(([filename, content]) => ({
      path: `/etc/axonwall/${filename}`,
      content,
      fileMode: 0o600,
      file_mode: 0o600,
    })),
    { path: '/etc/axonwall/state.json', content: serializedJson, fileMode: 0o600, file_mode: 0o600 },
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

async function cmdEdit(domainArg?: string) {
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
    fs.mkdirSync(ETC_DIR, { recursive: true });
    fs.writeFileSync(targetPath, serialized[`${domain}.yaml`] || '', { mode: 0o600 });
    try { fs.chmodSync(targetPath, 0o600); } catch {}
  }

  const editor = process.env.EDITOR || process.env.VISUAL || 'vi';
  const res = spawnSync(editor, [targetPath], { stdio: 'inherit' });
  if (res.status !== 0) {
    process.exit(res.status || 1);
  }

  console.log(`\n${cCyan}Validating modified /etc/axonwall/${domain}.yaml...${cReset}`);
  await cmdApply(true);
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

  // 3. Reconcile SSH keys from privileged users (root, admin, or sudoers)
  if (cloudConfig.users && cloudConfig.users.length > 0) {
    const allKeys: string[] = [];
    const openSshRegex = /^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+[A-Za-z0-9+/=]+(\s+[^\r\n]*)?$/;

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
  }

  // 4. Reconcile Axonwall specific configuration
  const axon = cloudConfig.axonwall;
  if (axon) {
    // 4a. Auth
    if (axon.auth) {
      if (axon.auth.admin_password) {
        console.log(`[+] Administrator credentials configured for user '${axon.auth.admin_username || 'admin'}'.`);
        if (!isDryRun) {
          try {
            fs.mkdirSync(ETC_DIR, { recursive: true, mode: 0o770 });
            const adminEnvPath = path.join(ETC_DIR, 'admin.env');
            const envContent = `LOCAL_ADMIN_USER=${axon.auth.admin_username || 'admin'}\nLOCAL_ADMIN_PASSWORD=${axon.auth.admin_password}\n`;
            fs.writeFileSync(adminEnvPath, envContent, { mode: 0o600 });
            try { fs.chmodSync(adminEnvPath, 0o600); } catch {}

            // Mirror to persistent /var/lib/axonwall/etc-axonwall/admin.env for A/B slot survival
            try {
              const persistDir = '/var/lib/axonwall/etc-axonwall';
              fs.mkdirSync(persistDir, { recursive: true, mode: 0o755 });
              fs.writeFileSync(path.join(persistDir, 'admin.env'), envContent, { mode: 0o600 });
              fs.chmodSync(path.join(persistDir, 'admin.env'), 0o600);
            } catch {}
          } catch (err: any) {
            console.warn(`[!] Unable to write admin.env: ${err.message}`);
          }
        }
      }
      if (axon.auth.ztp?.enabled) {
        console.log(`[+] Zero-Touch Provisioning (ZTP) enabled via ${axon.auth.ztp.controller_url || '<default-controller>'}.`);
        if (!isDryRun) {
          try {
            fs.mkdirSync(ETC_DIR, { recursive: true, mode: 0o770 });
            const ctrlEnvPath = path.join(ETC_DIR, 'controller.env');
            const content = `AXONWALL_ZTP_TOKEN=${axon.auth.ztp.enrollment_token || ''}\nAXONWALL_CONTROLLER_URL=${axon.auth.ztp.controller_url || ''}\n`;
            fs.writeFileSync(ctrlEnvPath, content, { mode: 0o600 });
            try { fs.chmodSync(ctrlEnvPath, 0o600); } catch {}
          } catch (err: any) {
            console.warn(`[!] Unable to write controller.env: ${err.message}`);
          }
        }
      }
    }

    // 4b. Desired State
    if (axon.desired_state && Object.keys(axon.desired_state).length > 0) {
      console.log(`[+] Staging declarative desired_state from cloud-config into /etc/axonwall/conf.d/99-cloudinit.yaml...`);
      if (!isDryRun) {
        try {
          const confD = path.join(ETC_DIR, 'conf.d');
          fs.mkdirSync(confD, { recursive: true, mode: 0o755 });
          const cloudInitYamlPath = path.join(confD, '99-cloudinit.yaml');
          fs.writeFileSync(cloudInitYamlPath, serializeYaml(axon.desired_state), { mode: 0o600 });
          try { fs.chmodSync(cloudInitYamlPath, 0o600); } catch {}
        } catch (err: any) {
          console.warn(`[!] Unable to write 99-cloudinit.yaml: ${err.message}`);
        }
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

async function cmdPlugin(args: string[]) {
  const subcmd = (args[0] || 'list').toLowerCase();
  const pluginId = args[1];

  switch (subcmd) {
    case 'list':
    case 'ls': {
      try {
        const res = await sendAgentSocketRequest<{ plugins: any[]; osFamily: string }>('/v1/system/plugins', 'GET');
        console.log(`\n${cCyan}${cBold}=== Axonwall Extension Plugins (${res.osFamily.toUpperCase()} Host) ===${cReset}\n`);
        console.log(
          `  ${cBold}${'ID'.padEnd(28)} ${'NAME'.padEnd(46)} ${'STATUS'.padEnd(16)} PACKAGES${cReset}`
        );
        console.log(`  ${'-'.repeat(105)}`);
        for (const p of res.plugins) {
          let statusStr = `${cDim}Available${cReset}`;
          if (p.bundled) {
            statusStr = `${cGreen}Bundled (OS)${cReset}`;
          } else if (p.installed) {
            statusStr = `${cCyan}Installed${cReset}`;
          }
          const pkgList = (p.packages || []).join(' ');
          console.log(
            `  ${p.id.padEnd(28)} ${p.name.padEnd(46)} ${statusStr.padEnd(25)} ${cDim}${pkgList}${cReset}`
          );
        }
        console.log('');
      } catch (err: any) {
        console.error(`${cRed}Failed to fetch plugins from agent daemon:${cReset}`, err?.message || err);
        process.exit(1);
      }
      break;
    }
    case 'install':
    case 'add': {
      if (!pluginId) {
        console.error(`${cRed}Usage: axonwallctl plugin install <plugin-id>${cReset}`);
        process.exit(1);
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
      console.log(`Usage: axonwallctl plugin <list|install|remove|re-sync> [plugin-id]`);
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
  plugin <cmd> [id]   Manage extension plugins (list, install, remove, re-sync)
  cloudinit [path]    Reconcile cloud-init (#cloud-config) user-data into /etc/axonwall config and state
  cloudinit export    Export running appliance into #cloud-config YAML or bootable NoCloud cidata.iso
                      Options: [-o <file.yaml>] [--iso <cidata.iso>] [--template] [--no-redact] [--hostname <name>]
  edit [section]      Open /etc/axonwall/<section>.yaml in \$EDITOR, then automatically validate and apply
  export              Output the complete unified configuration as a single YAML document to stdout

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
    case 'plugin':
    case 'plugins':
      await cmdPlugin(args.slice(1));
      break;
    case 'cloudinit':
    case 'cloud-init':
      await cmdCloudInit(args.slice(1));
      break;
    case 'edit':
      await cmdEdit(args[1]);
      break;
    case 'export':
      cmdExport();
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
