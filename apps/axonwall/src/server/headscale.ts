import { execFile } from 'child_process';
import fs from 'fs';

const HEADSCALE_SOCKET_PATH = process.env.HEADSCALE_SOCKET_PATH || '/run/headscale/headscale.sock';
const HEADSCALE_CONFIG_PATH = process.env.HEADSCALE_CONFIG_PATH || '/etc/headscale/config.yaml';
const HEADSCALE_BIN = process.env.HEADSCALE_BIN || '/usr/sbin/headscale';

function getHeadscaleBin(): string {
  if (fs.existsSync(HEADSCALE_BIN)) return HEADSCALE_BIN;
  if (fs.existsSync('/usr/local/bin/headscale')) return '/usr/local/bin/headscale';
  return 'headscale';
}

function runHeadscale(args: string[]): Promise<any> {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(HEADSCALE_SOCKET_PATH)) {
      return reject(
        new Error(`Headscale service is not running (${HEADSCALE_SOCKET_PATH} not found). Ensure the headscale service is started.`)
      );
    }

    const bin = getHeadscaleBin();
    const fullArgs = fs.existsSync(HEADSCALE_CONFIG_PATH)
      ? ['--config', HEADSCALE_CONFIG_PATH, ...args]
      : args;

    execFile(bin, fullArgs, { timeout: 10000 }, (err, stdout, stderr) => {
      if (err) {
        return reject(new Error(stderr?.trim() || err.message));
      }
      const trimmed = stdout.trim();
      if (!trimmed || trimmed === 'null') {
        return resolve(null);
      }
      try {
        resolve(JSON.parse(trimmed));
      } catch {
        resolve(trimmed);
      }
    });
  });
}

// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------

export async function listUsers() {
  const data = await runHeadscale(['users', 'list', '-o', 'json']);
  if (!Array.isArray(data)) return [];
  return data.map((u: any) => ({
    id: u.id,
    name: u.name,
    createdAt: u.created_at ? new Date((u.created_at.seconds || 0) * 1000).toISOString() : new Date().toISOString(),
  }));
}

export async function createUser(name: string) {
  const data = await runHeadscale(['users', 'create', name, '-o', 'json']);
  return {
    id: data?.id,
    name: data?.name || name,
    createdAt: data?.created_at ? new Date((data.created_at.seconds || 0) * 1000).toISOString() : new Date().toISOString(),
  };
}

export async function deleteUser(name: string) {
  return runHeadscale(['users', 'destroy', name, '--force']);
}

// -----------------------------------------------------------------------------
// PreAuthKeys
// -----------------------------------------------------------------------------

export async function createPreAuthKey(user: string | number, reusable: boolean, ephemeral: boolean, expiration?: string) {
  let userId = user;
  if (typeof user === 'string' && isNaN(Number(user))) {
    const users = await listUsers();
    const found = users.find((u: any) => u.name === user);
    if (found) {
      userId = found.id;
    } else {
      const created = await createUser(user);
      userId = created.id;
    }
  }

  const args = ['preauthkeys', 'create', '--user', String(userId), '-o', 'json'];
  if (reusable) args.push('--reusable');
  if (ephemeral) args.push('--ephemeral');
  if (expiration) {
    const ms = new Date(expiration).getTime() - Date.now();
    if (ms > 0) {
      const hours = Math.max(1, Math.round(ms / (1000 * 60 * 60)));
      args.push('--expiration', `${hours}h`);
    }
  }

  const data = await runHeadscale(args);
  return {
    id: data?.id,
    key: data?.key,
    reusable: data?.reusable,
    ephemeral: data?.ephemeral,
    expiration: data?.expiration ? new Date((data.expiration.seconds || 0) * 1000).toISOString() : undefined,
    user: data?.user || { id: userId, name: String(user) },
  };
}

export async function listPreAuthKeys(user?: string) {
  const data = await runHeadscale(['preauthkeys', 'list', '-o', 'json']);
  if (!Array.isArray(data)) return [];
  const keys = data.map((k: any) => ({
    id: k.id,
    key: k.key,
    reusable: k.reusable,
    ephemeral: k.ephemeral,
    used: k.used,
    expiration: k.expiration ? new Date((k.expiration.seconds || 0) * 1000).toISOString() : undefined,
    createdAt: k.created_at ? new Date((k.created_at.seconds || 0) * 1000).toISOString() : undefined,
    user: k.user,
  }));
  if (user) {
    return keys.filter((k: any) => k.user?.name === user || String(k.user?.id) === String(user));
  }
  return keys;
}

export async function expirePreAuthKey(user: string, key: string) {
  return runHeadscale(['preauthkeys', 'expire', key]);
}

// -----------------------------------------------------------------------------
// Machines / Nodes
// -----------------------------------------------------------------------------

export async function listMachines(user?: string) {
  const data = await runHeadscale(['nodes', 'list', '-o', 'json']);
  if (!Array.isArray(data)) return [];
  const nodes = data.map((n: any) => ({
    id: n.id,
    name: n.given_name || n.name,
    ipAddresses: n.ip_addresses || [],
    user: n.user,
    lastSeen: n.last_seen ? new Date(n.last_seen).toISOString() : null,
    online: n.online ?? false,
    routes: n.approved_routes || [],
  }));
  if (user) {
    return nodes.filter((n: any) => n.user?.name === user || String(n.user?.id) === String(user));
  }
  return nodes;
}

export async function deleteMachine(machineId: string | number) {
  return runHeadscale(['nodes', 'delete', '-i', String(machineId), '--force']);
}

export async function renameMachine(machineId: string | number, newName: string) {
  return runHeadscale(['nodes', 'rename', newName, '-i', String(machineId)]);
}

export async function expireMachine(machineId: string | number) {
  return runHeadscale(['nodes', 'expire', '-i', String(machineId)]);
}

// -----------------------------------------------------------------------------
// Routes
// -----------------------------------------------------------------------------

export async function getMachineRoutes(machineId: string | number) {
  const data = await runHeadscale(['nodes', 'list-routes', '-i', String(machineId), '-o', 'json']);
  return Array.isArray(data) ? data : [];
}

export async function enableMachineRoutes(machineId: string | number, routes: string[]) {
  return runHeadscale(['nodes', 'approve-routes', '-i', String(machineId), '--routes', routes.join(',')]);
}
