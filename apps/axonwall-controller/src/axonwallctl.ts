import * as fs from 'node:fs';
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
  return DesiredStateSchema.parse({
    version: 1,
    system: {
      hostname: 'axonwall',
      domain: 'home.arpa',
      timezone: 'UTC',
      dnsServers: ['1.1.1.1', '9.9.9.9'],
    },
    interfaces: [
      { name: 'wan', device: 'eth0', type: 'dhcp', enabled: true, mtu: 1500, description: 'WAN Uplink' },
      { name: 'lan', device: 'eth1', type: 'static', ipv4Address: '192.168.1.1/24', enabled: true, mtu: 1500, description: 'LAN Network' },
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
  } catch {
    console.log(`  ${cBold}Privileged Daemon:${cReset} ${cYellow}OFFLINE / STANDALONE MODE${cReset}`);
  }
}

function cmdValidate(): DesiredState {
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

  console.log(`${cGreen}${cBold}[✓] All /etc/axonwall/*.yaml files passed schema and syntax validation.${cReset}`);
  console.log(
    `    Interfaces: ${result.state.interfaces.length} | Firewall Rules: ${result.state.rules.length} | NAT Rules: ${
      result.state.nat?.length || 0
    } | DHCP Pools: ${result.state.dhcp?.subnets?.length || 0}`
  );
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
    }
    console.log(`${cGreen}${cBold}[✓] Applied /etc/axonwall/*.yaml to kernel nftables and system daemons (hash: ${bundleHash.slice(0, 12)}).${cReset}`);
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
  const domain = (domainArg || 'firewall').replace(/\.ya?ml$/i, '').toLowerCase();
  if (!AXONWALL_YAML_DOMAINS.includes(domain as any)) {
    console.error(
      `${cRed}Unknown configuration section '${domainArg}'. Valid sections: ${AXONWALL_YAML_DOMAINS.join(', ')}${cReset}`
    );
    process.exit(1);
  }

  const targetPath = path.join(ETC_DIR, `${domain}.yaml`);
  if (!fs.existsSync(targetPath)) {
    const state = loadFallbackState();
    const serialized = serializeDesiredStateToYamlFiles(state) as Record<string, string>;
    fs.mkdirSync(ETC_DIR, { recursive: true });
    fs.writeFileSync(targetPath, serialized[`${domain}.yaml`] || '', { mode: 0o644 });
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

function showHelp() {
  console.log(`${cCyan}${cBold}axonwallctl — Axonwall Declarative YAML CLI (/etc/axonwall/*.yaml)${cReset}

${cBold}USAGE:${cReset}
  axonwallctl <command> [arguments]

${cBold}COMMANDS:${cReset}
  status              Show status of /etc/axonwall/*.yaml files, validation state, and daemon connectivity
  validate            Validate all /etc/axonwall/*.yaml and /etc/axonwall/conf.d/*.yaml files against Zod schemas
  diff                Show uncommitted YAML changes and preview compiled Linux nftables ruleset
  apply               Compile and atomically apply /etc/axonwall/*.yaml to kernel nftables, daemons, and GitOps
  reload              Alias for 'apply' — reload all services and Web GUI state from /etc/axonwall/*.yaml
  edit [section]      Open /etc/axonwall/<section>.yaml in \$EDITOR, then automatically validate and apply
  export              Output the complete unified configuration as a single YAML document to stdout

${cBold}SECTIONS (/etc/axonwall/<section>.yaml):${cReset}
  ${AXONWALL_YAML_DOMAINS.join(', ')}
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
    case 'reload':
      await cmdApply(true);
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
