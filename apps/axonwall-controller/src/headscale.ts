import { execFile } from 'child_process';
import fs from 'fs';
import { isValidCIDR } from '@axonwall/lib';

function assertSafeIdentifier(val: string | number, paramName: string): string {
  const str = String(val).trim();
  if (!str) {
    throw new Error(`${paramName} is required`);
  }
  if (str.startsWith('-')) {
    throw new Error(`${paramName} cannot start with a hyphen`);
  }
  if (!/^[a-zA-Z0-9_.-]+$/.test(str)) {
    throw new Error(`${paramName} contains invalid characters`);
  }
  return str;
}

const HEADSCALE_SOCKET_PATH = process.env.HEADSCALE_SOCKET_PATH || '/run/headscale/headscale.sock';
const HEADSCALE_CONFIG_PATH = process.env.HEADSCALE_CONFIG_PATH || '/etc/headscale/config.yaml';
const HEADSCALE_BIN = process.env.HEADSCALE_BIN || '/usr/sbin/headscale';

// B-L4: headscale CLI `-o json` timestamps are not one shape. The
// current CLI (v0.29 line) marshals its generated API types with
// encoding/json, so timestamps are camelCase RFC3339 strings
// (`createdAt`, `expiration`, `lastSeen` — a time.Time field). Older
// protobuf-shaped output used snake_case `{seconds}` objects, and a
// numeric epoch is accepted too. Parsing only `.seconds` off a
// snake_case key collapsed every timestamp: a created key's
// expiration became epoch 1970 (already expired), and user
// creation times fell back to "now". This helper accepts all three
// shapes, and callers pass both key spellings.
export function parseHeadscaleTimestamp(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'string') {
    const ms = Date.parse(value);
    return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Epoch seconds (small) vs milliseconds (large); the boundary
    // is far from any real timestamp in either unit.
    const ms = value > 1e12 ? value : value * 1000;
    return new Date(ms).toISOString();
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    if (typeof obj.seconds === 'number') {
      return new Date(obj.seconds * 1000).toISOString();
    }
    if (typeof obj.seconds === 'string' && obj.seconds !== '') {
      const s = Number(obj.seconds);
      if (Number.isFinite(s)) return new Date(s * 1000).toISOString();
    }
  }
  return undefined;
}

function headscaleTimestamp(record: any, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const parsed = parseHeadscaleTimestamp(record?.[key]);
    if (parsed !== undefined) return parsed;
  }
  return undefined;
}

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
    createdAt: headscaleTimestamp(u, 'createdAt', 'created_at') ?? new Date().toISOString(),
  }));
}

export async function createUser(name: string) {
  const safeName = assertSafeIdentifier(name, 'User name');
  const data = await runHeadscale(['users', 'create', safeName, '-o', 'json']);
  return {
    id: data?.id,
    name: data?.name || safeName,
    createdAt: headscaleTimestamp(data, 'createdAt', 'created_at') ?? new Date().toISOString(),
  };
}

export async function deleteUser(name: string) {
  const safeName = assertSafeIdentifier(name, 'User name');
  return runHeadscale(['users', 'destroy', safeName, '--force']);
}

// -----------------------------------------------------------------------------
// PreAuthKeys
// -----------------------------------------------------------------------------

export async function createPreAuthKey(user: string | number, reusable: boolean, ephemeral: boolean, expiration?: string) {
  let userId: string | number = user;
  if (typeof user === 'string' && isNaN(Number(user))) {
    const safeUserName = assertSafeIdentifier(user, 'User name');
    const users = await listUsers();
    const found = users.find((u: any) => u.name === safeUserName);
    if (found) {
      userId = found.id;
    } else {
      const created = await createUser(safeUserName);
      userId = created.id;
    }
  }

  const safeUserId = typeof userId === 'number' ? userId : assertSafeIdentifier(userId, 'User ID');
  const args = ['preauthkeys', 'create', '--user', String(safeUserId), '-o', 'json'];
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
    expiration: headscaleTimestamp(data, 'expiration'),
    user: data?.user || { id: safeUserId, name: String(user) },
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
    expiration: headscaleTimestamp(k, 'expiration'),
    createdAt: headscaleTimestamp(k, 'createdAt', 'created_at'),
    user: k.user,
  }));
  if (user) {
    const safeUser = assertSafeIdentifier(user, 'User');
    return keys.filter((k: any) => k.user?.name === safeUser || String(k.user?.id) === safeUser);
  }
  return keys;
}

export async function expirePreAuthKey(user: string, key: string) {
  const safeKey = assertSafeIdentifier(key, 'Preauth key');
  return runHeadscale(['preauthkeys', 'expire', safeKey]);
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
    lastSeen: headscaleTimestamp(n, 'lastSeen', 'last_seen') ?? null,
    online: n.online ?? false,
    routes: n.approved_routes || [],
  }));
  if (user) {
    const safeUser = assertSafeIdentifier(user, 'User');
    return nodes.filter((n: any) => n.user?.name === safeUser || String(n.user?.id) === safeUser);
  }
  return nodes;
}

export async function deleteMachine(machineId: string | number) {
  const safeId = assertSafeIdentifier(machineId, 'Machine ID');
  return runHeadscale(['nodes', 'delete', '-i', safeId, '--force']);
}

export async function renameMachine(machineId: string | number, newName: string) {
  const safeId = assertSafeIdentifier(machineId, 'Machine ID');
  const safeName = assertSafeIdentifier(newName, 'New machine name');
  return runHeadscale(['nodes', 'rename', safeName, '-i', safeId]);
}

export async function expireMachine(machineId: string | number) {
  const safeId = assertSafeIdentifier(machineId, 'Machine ID');
  return runHeadscale(['nodes', 'expire', '-i', safeId]);
}

// -----------------------------------------------------------------------------
// Routes
// -----------------------------------------------------------------------------

export async function getMachineRoutes(machineId: string | number) {
  const safeId = assertSafeIdentifier(machineId, 'Machine ID');
  const data = await runHeadscale(['nodes', 'list-routes', '-i', safeId, '-o', 'json']);
  return Array.isArray(data) ? data : [];
}

export async function enableMachineRoutes(machineId: string | number, routes: string[]) {
  const safeId = assertSafeIdentifier(machineId, 'Machine ID');
  if (!Array.isArray(routes)) {
    throw new Error('Routes must be an array of CIDR strings');
  }
  const sanitizedRoutes: string[] = [];
  for (const r of routes) {
    const trimmed = typeof r === 'string' ? r.trim() : '';
    if (!trimmed || trimmed.startsWith('-') || !isValidCIDR(trimmed)) {
      throw new Error(`Invalid CIDR route: "${r}"`);
    }
    sanitizedRoutes.push(trimmed);
  }
  return runHeadscale(['nodes', 'approve-routes', '-i', safeId, '--routes', sanitizedRoutes.join(',')]);
}
