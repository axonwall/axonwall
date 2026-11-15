import * as esbuild from 'esbuild';
import * as net from 'node:net';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../..');

function canConnectUnixSocket(socketPath, timeoutMs = 250) {
  return new Promise((resolve) => {
    const sock = net.connect(socketPath);
    const timer = setTimeout(() => {
      sock.destroy();
      resolve(false);
    }, timeoutMs);
    sock.once('connect', () => {
      clearTimeout(timer);
      sock.end();
      resolve(true);
    });
    sock.once('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

let daemonProc = null;

async function startDevDaemonIfNeeded() {
  if (process.env.AXONWALL_NO_DEV_DAEMON === '1') {
    return;
  }
  const prodSock = process.env.AXONWALL_AGENT_API_SOCK || '/run/axonwall/agent-api.sock';
  if (await canConnectUnixSocket(prodSock)) {
    console.log(`[axonwall-controller] Using existing daemon socket at ${prodSock}`);
    return;
  }

  const daemonDir = path.join(repoRoot, 'apps/axonwalld');
  const devDir = process.env.AXONWALL_DEV_DIR || path.join(repoRoot, '.axonwall-dev');
  const binPath = path.join(daemonDir, 'bin', 'axonwalld');

  console.log('[axonwall-controller] Building rootless axonwalld dev binary...');
  const buildRes = spawnSync('go', ['build', '-o', 'bin/axonwalld', '.'], {
    cwd: daemonDir,
    stdio: 'inherit',
  });
  if (buildRes.status !== 0) {
    console.warn('[axonwall-controller] Warning: failed to build axonwalld; continuing without dev daemon.');
    return;
  }

  console.log(`[axonwall-controller] Starting rootless axonwalld --dev (state: ${devDir})...`);
  daemonProc = spawn(binPath, ['--dev'], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      AXONWALL_DEV_DIR: devDir,
      AXONWALL_DEV_MODE: '1',
    },
  });
  daemonProc.once('exit', (code, signal) => {
    if (code !== null && code !== 0) {
      console.warn(`[axonwall-controller] Dev daemon exited unexpectedly (code=${code}, signal=${signal})`);
    }
    daemonProc = null;
  });
}

const banner = {
  js: 'import { createRequire } from "module"; const require = createRequire(import.meta.url);',
};

const targets = [
  { entry: 'src/index.ts', outfile: 'dist/index.js' },
  { entry: 'src/axonwallctl.ts', outfile: 'dist/axonwallctl.js' },
  { entry: 'src/axonwall-mcp.ts', outfile: 'dist/axonwall-mcp.js' },
  {
    entry: 'src/axonwall-tui.tsx',
    outfile: 'dist/axonwall-tui.js',
    alias: { 'react-devtools-core': './src/tui/devtools-stub.ts' },
  },
];

await startDevDaemonIfNeeded();

const contexts = await Promise.all(
  targets.map((target) =>
    esbuild.context({
      entryPoints: [target.entry],
      bundle: true,
      platform: 'node',
      format: 'esm',
      outfile: target.outfile,
      banner,
      ...(target.alias ? { alias: target.alias } : {}),
    })
  )
);

await Promise.all(contexts.map((ctx) => ctx.watch()));
console.log('[axonwall-controller] Watching esbuild bundles...');

let shuttingDown = false;
const shutdown = async () => {
  if (shuttingDown) return;
  shuttingDown = true;
  if (daemonProc && !daemonProc.killed) {
    daemonProc.kill('SIGTERM');
  }
  await Promise.all(contexts.map((ctx) => ctx.dispose()));
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('exit', () => {
  if (daemonProc && !daemonProc.killed) {
    try {
      daemonProc.kill('SIGTERM');
    } catch {}
  }
});
