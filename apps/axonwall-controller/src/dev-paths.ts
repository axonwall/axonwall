import * as fs from 'node:fs';
import * as path from 'node:path';

export interface ControllerDirs {
  devMode: boolean;
  etcDir: string;
  persistYamlDir: string;
  varDir: string;
  logDir: string;
  runDir: string;
  stateFile: string;
  gitopsDir: string;
  agentSock: string;
  agentTokenPaths: string[];
  certPath: string;
  keyPath: string;
  caPath: string;
  haStatePaths: string[];
  syncedRoutesStatePaths: string[];
  desiredStateCandidates: string[];
}

export function findWorkspaceRoot(): string | null {
  let cur = process.cwd();
  for (;;) {
    if (fs.existsSync(path.join(cur, 'pnpm-workspace.yaml'))) {
      return cur;
    }
    const parent = path.dirname(cur);
    if (parent === cur) {
      return null;
    }
    cur = parent;
  }
}

export function resolveDevRootDir(): string {
  const explicit = process.env.AXONWALL_DEV_DIR;
  if (explicit && explicit.trim()) {
    return path.resolve(explicit.trim());
  }
  const wsRoot = findWorkspaceRoot();
  return wsRoot ? path.join(wsRoot, '.axonwall-dev') : path.resolve('.axonwall-dev');
}

export function isControllerDevRuntime(): boolean {
  try {
    if (fs.existsSync('/etc/axonwall/.axonwall-os')) {
      return false;
    }
  } catch {
    return false;
  }
  if (
    process.env.AXONWALL_DEV === '1' ||
    process.env.AXONWALL_DEV_MODE === '1' ||
    Boolean(process.env.AXONWALL_DEV_DIR)
  ) {
    return true;
  }
  if (process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'production') {
    return false;
  }
  const wsRoot = findWorkspaceRoot();
  if (!wsRoot) {
    return false;
  }
  const devRoot = path.join(wsRoot, '.axonwall-dev');
  return fs.existsSync(devRoot) || !fs.existsSync('/etc/axonwall');
}

export function detectHostOSFamily(): 'arch' | 'alpine' | 'debian' | 'linux' {
  let id = '';
  let idLike = '';
  try {
    if (fs.existsSync('/etc/os-release')) {
      const raw = fs.readFileSync('/etc/os-release', 'utf8');
      for (const rawLine of raw.split('\n')) {
        const line = rawLine.trim();
        if (line.startsWith('ID=')) {
          id = line.slice(3).replace(/^["']|["']$/g, '').toLowerCase();
        } else if (line.startsWith('ID_LIKE=')) {
          idLike = line.slice(8).replace(/^["']|["']$/g, '').toLowerCase();
        }
      }
    }
  } catch {}
  const combined = `${id} ${idLike}`;
  if (combined.includes('arch') || combined.includes('omarchy')) return 'arch';
  if (combined.includes('alpine')) return 'alpine';
  if (combined.includes('debian') || combined.includes('ubuntu') || combined.includes('axonwall')) {
    return 'debian';
  }
  return 'linux';
}

function resolveAgentSocket(runDir: string, devMode: boolean): string {
  const explicit = process.env.AXONWALL_AGENT_API_SOCK || process.env.AGENT_API_SOCKET;
  if (explicit && explicit.trim()) {
    return explicit.trim();
  }
  const primarySock = path.join(runDir, 'agent-api.sock');
  if (devMode) {
    if (fs.existsSync(primarySock)) {
      return primarySock;
    }
    const systemSock = '/run/axonwall/agent-api.sock';
    try {
      if (fs.existsSync(systemSock)) {
        fs.accessSync(systemSock, fs.constants.R_OK | fs.constants.W_OK);
        return systemSock;
      }
    } catch {}
  }
  return primarySock;
}

export function resolveControllerDirs(): ControllerDirs {
  const devMode = isControllerDevRuntime();
  const devRoot = devMode ? resolveDevRootDir() : '';

  const etcDir =
    process.env.AXONWALL_ETC_DIR ||
    process.env.AXONWALL_CONFIG_DIR ||
    (devMode ? path.join(devRoot, 'etc') : '/etc/axonwall');
  const varDir =
    process.env.AXONWALL_STATE_DIR || (devMode ? path.join(devRoot, 'var') : '/var/lib/axonwall');
  const persistYamlDir =
    process.env.AXONWALL_PERSIST_YAML_DIR || path.join(varDir, 'etc-axonwall');
  const logDir =
    process.env.AXONWALL_LOG_DIR || (devMode ? path.join(varDir, 'log') : '/var/log/axonwall');
  const runDir = devMode ? path.join(devRoot, 'run') : '/run/axonwall';

  const stateFile =
    process.env.AXONWALL_STATE_FILE ||
    process.env.AXONWALL_STATE_JSON_PATH ||
    path.join(varDir, 'state.json');
  const gitopsDir = process.env.AXONWALL_GITOPS_DIR || path.join(varDir, 'gitops');
  const agentSock = resolveAgentSocket(runDir, devMode);

  const agentTokenPaths = process.env.AXONWALL_AGENT_TOKEN_FILE
    ? [process.env.AXONWALL_AGENT_TOKEN_FILE]
    : Array.from(
        new Set([
          path.join(etcDir, 'agent.token'),
          path.join(persistYamlDir, 'agent.token'),
          path.join(runDir, 'agent.token'),
          ...(!devMode || agentSock === '/run/axonwall/agent-api.sock'
            ? ['/etc/axonwall/agent.token', '/var/lib/axonwall/etc-axonwall/agent.token', '/run/axonwall/agent.token']
            : []),
        ]),
      );

  const haStatePaths = process.env.AXONWALL_HA_STATE_PATH
    ? [process.env.AXONWALL_HA_STATE_PATH]
    : Array.from(
        new Set([path.join(varDir, 'active-ha-edge.json'), path.join(etcDir, 'active-ha-edge.json')]),
      );

  const syncedRoutesStatePaths = process.env.AXONWALL_SYNCED_ROUTES_PATH
    ? [process.env.AXONWALL_SYNCED_ROUTES_PATH]
    : Array.from(
        new Set([path.join(varDir, 'synced-routes.json'), path.join(etcDir, 'synced-routes.json')]),
      );

  const customState = process.env.AXONWALL_STATE_JSON_PATH || process.env.AXONWALL_STATE_FILE;
  const desiredStateCandidates = Array.from(
    new Set([
      ...(customState ? [customState] : []),
      path.join(etcDir, 'state.json'),
      path.join(varDir, 'state.json'),
    ]),
  );

  return {
    devMode,
    etcDir,
    persistYamlDir,
    varDir,
    logDir,
    runDir,
    stateFile,
    gitopsDir,
    agentSock,
    agentTokenPaths,
    certPath: path.join(etcDir, 'certs', 'hub.crt'),
    keyPath: path.join(etcDir, 'certs', 'hub.key'),
    caPath: path.join(etcDir, 'certs', 'ca.crt'),
    haStatePaths,
    syncedRoutesStatePaths,
    desiredStateCandidates,
  };
}

export function readAgentToken(dirs: ControllerDirs = resolveControllerDirs()): string | undefined {
  if (process.env.AXONWALL_AGENT_TOKEN) {
    return process.env.AXONWALL_AGENT_TOKEN.trim() || undefined;
  }
  for (const candidate of dirs.agentTokenPaths) {
    try {
      if (fs.existsSync(candidate)) {
        const token = fs.readFileSync(candidate, 'utf8').trim();
        if (token) return token;
      }
    } catch {}
  }
  return undefined;
}
