import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface HostOSInfo {
  id: string;
  idLike: string;
  prettyName: string;
  family: 'arch' | 'alpine' | 'debian' | 'linux';
  kernelVersion: string;
}

const VIRTUAL_NETDEV_PREFIXES = [
  'lo',
  'veth',
  'docker',
  'br-',
  'cni',
  'flannel',
  'virbr',
  'tun',
  'tap',
  'wg',
  'tailscale',
  'kube',
  'cali',
  'dummy',
];

export function isApplianceRuntime(): boolean {
  try {
    return fs.existsSync('/etc/axonwall/.axonwall-os');
  } catch {
    return false;
  }
}

export function isDevRuntime(): boolean {
  if (isApplianceRuntime()) {
    return false;
  }
  if (
    process.env.AXONWALL_DEV === '1' ||
    process.env.AXONWALL_DEV_MODE === '1' ||
    Boolean(process.env.AXONWALL_DEV_DIR)
  ) {
    return true;
  }
  if (process.env.NODE_ENV === 'test') {
    return false;
  }
  return process.env.NODE_ENV !== 'production';
}

export function resolveDevRootDir(): string {
  const explicit = process.env.AXONWALL_DEV_DIR;
  if (explicit && explicit.trim()) {
    return path.resolve(explicit.trim());
  }
  let cur = process.cwd();
  for (;;) {
    if (fs.existsSync(path.join(cur, 'pnpm-workspace.yaml')) || fs.existsSync(path.join(cur, '.git'))) {
      return path.join(cur, '.axonwall-dev');
    }
    const parent = path.dirname(cur);
    if (parent === cur) {
      break;
    }
    cur = parent;
  }
  return path.resolve('.axonwall-dev');
}

function parseEnvValue(filePath: string, key: string): string | undefined {
  try {
    if (!fs.existsSync(filePath)) return undefined;
    const raw = fs.readFileSync(filePath, 'utf8');
    for (const rawLine of raw.split('\n')) {
      const line = rawLine.trim();
      if (line.startsWith(`${key}=`)) {
        const v = line.slice(key.length + 1).trim();
        if (v) return v;
      }
    }
  } catch {}
  return undefined;
}

export function ensureDevRuntimeBootstrapped(): {
  etcDir: string;
  stateDir: string;
  persistDir: string;
  runDir: string;
} {
  const devRoot = resolveDevRootDir();
  const etcDir = path.join(devRoot, 'etc');
  const stateDir = path.join(devRoot, 'var');
  const persistDir = path.join(stateDir, 'etc-axonwall');
  const runDir = path.join(devRoot, 'run');

  if (!isDevRuntime()) {
    return { etcDir, stateDir, persistDir, runDir };
  }

  for (const dir of [devRoot, etcDir, stateDir, persistDir, runDir]) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
  }

  const envFile = path.join(etcDir, 'axonwall.env');
  let jwtSecret = parseEnvValue(envFile, 'JWT_SECRET');
  if (!jwtSecret) {
    jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(envFile, `JWT_SECRET=${jwtSecret}\n`, { mode: 0o600 });
    try {
      fs.chmodSync(envFile, 0o600);
    } catch {}
  }
  if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = jwtSecret;
  }

  const adminEnvFile = path.join(etcDir, 'admin.env');
  if (!fs.existsSync(adminEnvFile)) {
    const adminUser = process.env.LOCAL_ADMIN_USER || 'admin';
    const rawPass = process.env.LOCAL_ADMIN_PASSWORD || 'axonwall';
    const storedSecret = rawPass.startsWith('scrypt$')
      ? rawPass
      : (() => {
          const salt = crypto.randomBytes(16).toString('hex');
          const hash = crypto.scryptSync(rawPass, salt, 64).toString('hex');
          return `scrypt$${salt}$${hash}`;
        })();
    fs.writeFileSync(
      adminEnvFile,
      `LOCAL_ADMIN_USER=${adminUser}\nLOCAL_ADMIN_PASSWORD=${storedSecret}\n`,
      { mode: 0o600 }
    );
    try {
      fs.chmodSync(adminEnvFile, 0o600);
    } catch {}
  }

  const pwdMarker = path.join(stateDir, '.password_changed');
  if (!fs.existsSync(pwdMarker) && process.env.FORCE_PASSWORD_CHANGE !== 'true') {
    fs.writeFileSync(pwdMarker, 'dev-auto-bootstrapped\n', { mode: 0o600 });
  }

  return { etcDir, stateDir, persistDir, runDir };
}

export function getEtcConfigDir(): string {
  const override = process.env.AXONWALL_CONFIG_DIR || process.env.AXONWALL_ETC_DIR;
  if (override && override.trim()) return override.trim();
  if (isDevRuntime()) {
    return ensureDevRuntimeBootstrapped().etcDir;
  }
  return '/etc/axonwall';
}

export function getStateDir(): string {
  const override = process.env.AXONWALL_STATE_DIR;
  if (override && override.trim()) return override.trim();
  if (isDevRuntime()) {
    return ensureDevRuntimeBootstrapped().stateDir;
  }
  return '/var/lib/axonwall';
}

export function getPersistConfigDir(): string {
  const override = process.env.AXONWALL_PERSIST_YAML_DIR;
  if (override && override.trim()) return override.trim();
  if (isDevRuntime()) {
    return ensureDevRuntimeBootstrapped().persistDir;
  }
  return '/var/lib/axonwall/etc-axonwall';
}

export function getStateJsonPath(): string {
  const override = process.env.AXONWALL_STATE_FILE || process.env.AXONWALL_STATE_JSON_PATH;
  if (override && override.trim()) return override.trim();
  return path.join(getStateDir(), 'state.json');
}

export function getAgentApiSocketPath(): string {
  const explicit = process.env.AGENT_API_SOCKET || process.env.AXONWALL_AGENT_API_SOCK;
  if (explicit && explicit.trim()) return explicit.trim();
  if (isDevRuntime()) {
    const devSock = path.join(ensureDevRuntimeBootstrapped().runDir, 'agent-api.sock');
    if (fs.existsSync(devSock)) {
      return devSock;
    }
    const prodSock = '/run/axonwall/agent-api.sock';
    try {
      if (fs.existsSync(prodSock)) {
        fs.accessSync(prodSock, fs.constants.R_OK | fs.constants.W_OK);
        return prodSock;
      }
    } catch {}
    return devSock;
  }
  return '/run/axonwall/agent-api.sock';
}

export function getAgentTokenCandidatePaths(): string[] {
  const paths: string[] = [];
  if (process.env.AXONWALL_AGENT_TOKEN_FILE) {
    paths.push(process.env.AXONWALL_AGENT_TOKEN_FILE);
  }
  if (isDevRuntime()) {
    const { etcDir, runDir } = ensureDevRuntimeBootstrapped();
    paths.push(path.join(etcDir, 'agent.token'), path.join(runDir, 'agent.token'));
  }
  paths.push('/etc/axonwall/agent.token', '/var/lib/axonwall/etc-axonwall/agent.token', '/run/axonwall/agent.token');
  return Array.from(new Set(paths));
}

export function readHostOSRelease(): HostOSInfo {
  let id = 'linux';
  let idLike = '';
  let prettyName = 'Linux';
  try {
    if (fs.existsSync('/etc/os-release')) {
      const raw = fs.readFileSync('/etc/os-release', 'utf8');
      for (const rawLine of raw.split('\n')) {
        const line = rawLine.trim();
        if (line.startsWith('ID=')) {
          id = line.slice(3).replace(/^["']|["']$/g, '').toLowerCase() || 'linux';
        } else if (line.startsWith('ID_LIKE=')) {
          idLike = line.slice(8).replace(/^["']|["']$/g, '').toLowerCase();
        } else if (line.startsWith('PRETTY_NAME=')) {
          prettyName = line.slice(12).replace(/^["']|["']$/g, '') || prettyName;
        }
      }
    }
  } catch {}

  const tokens = new Set([id, ...idLike.split(/\s+/).filter(Boolean)]);
  let family: HostOSInfo['family'] = 'linux';
  if (
    tokens.has('arch') ||
    tokens.has('omarchy') ||
    tokens.has('manjaro') ||
    tokens.has('endeavouros') ||
    tokens.has('cachyos')
  ) {
    family = 'arch';
  } else if (tokens.has('alpine') || fs.existsSync('/etc/alpine-release')) {
    family = 'alpine';
  } else if (tokens.has('debian') || tokens.has('ubuntu')) {
    family = 'debian';
  }

  return {
    id,
    idLike,
    prettyName,
    family,
    kernelVersion: os.release() || 'Linux',
  };
}

export function isVirtualOrLoopbackInterface(name: string): boolean {
  if (!name || name === 'lo') return true;
  return VIRTUAL_NETDEV_PREFIXES.some((pfx) => name === pfx || name.startsWith(pfx));
}

export function discoverHostPrimaryDevices(): string[] {
  const physical: string[] = [];
  try {
    if (fs.existsSync('/sys/class/net')) {
      const entries = fs.readdirSync('/sys/class/net').sort();
      for (const name of entries) {
        if (isVirtualOrLoopbackInterface(name)) continue;
        // Prefer entries backed by a hardware device symlink when available
        if (fs.existsSync(path.join('/sys/class/net', name, 'device'))) {
          physical.push(name);
        }
      }
      if (physical.length > 0) return physical;
      for (const name of entries) {
        if (!isVirtualOrLoopbackInterface(name)) {
          physical.push(name);
        }
      }
      if (physical.length > 0) return physical;
    }
  } catch {}

  const netIfaces = os.networkInterfaces();
  for (const name of Object.keys(netIfaces).sort()) {
    if (!isVirtualOrLoopbackInterface(name)) {
      physical.push(name);
    }
  }
  return physical;
}
