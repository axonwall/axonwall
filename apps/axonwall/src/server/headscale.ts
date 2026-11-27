import { execFile } from 'child_process';
import crypto from 'crypto';
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

export function parseHeadscaleTimestamp(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'string') {
    const ms = Date.parse(value);
    return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
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

export interface HeadscaleUserRecord {
  id: string | number;
  name: string;
  createdAt?: string;
}

export interface HeadscaleMachineRecord {
  id: string | number;
  name: string;
  hostname?: string;
  givenName?: string;
  ipAddresses: string[];
  user?: { id?: string | number; name?: string };
  lastSeen: string | null;
  online: boolean;
  routes: string[];
  approvedRoutes: string[];
  availableRoutes: string[];
  expiry: string | null;
  createdAt: string | null;
}

export interface HeadscalePreAuthKeyRecord {
  id: string | number;
  key: string;
  keyPreview: string;
  reusable: boolean;
  ephemeral: boolean;
  used: boolean;
  expired: boolean;
  expiration?: string;
  createdAt?: string;
  user?: { id?: string | number; name?: string };
}

export function isHeadscaleSocketReady(): boolean {
  try {
    return fs.existsSync(HEADSCALE_SOCKET_PATH);
  } catch {
    return false;
  }
}

export function readHeadscaleConfigDefaults(): { serverUrl: string; magicDnsDomain: string } {
  let serverUrl = '';
  let magicDnsDomain = '';
  try {
    if (!fs.existsSync(HEADSCALE_CONFIG_PATH)) {
      return { serverUrl, magicDnsDomain };
    }
    const raw = fs.readFileSync(HEADSCALE_CONFIG_PATH, 'utf-8');
    let inDns = false;
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed === '---') continue;
      const isIndented = line.startsWith(' ') || line.startsWith('\t');
      if (!isIndented) {
        inDns = trimmed === 'dns:' || trimmed.startsWith('dns:');
        if (trimmed.startsWith('server_url:')) {
          const val = trimmed.slice('server_url:'.length).trim().replace(/^["']|["']$/g, '');
          if (val) serverUrl = val.replace(/\/+$/, '');
        }
      } else if (inDns && trimmed.startsWith('base_domain:')) {
        const val = trimmed.slice('base_domain:'.length).trim().replace(/^["']|["']$/g, '');
        if (val) magicDnsDomain = val;
      }
    }
  } catch {}
  return { serverUrl, magicDnsDomain };
}

export function resolveHeadscaleUsername(
  sessionOrUsername: string | { username?: string; email?: string; source?: string }
): string {
  const source = typeof sessionOrUsername === 'object' ? sessionOrUsername.source : undefined;
  const rawInput =
    typeof sessionOrUsername === 'string'
      ? sessionOrUsername
      : sessionOrUsername.username || sessionOrUsername.email || '';
  const trimmed = rawInput.trim().toLowerCase();
  if (!trimmed) {
    throw new Error('Username is required to resolve Headscale namespace');
  }
  const raw =
    source === 'oidc' && !trimmed.startsWith('oidc:')
      ? `oidc:${trimmed}`
      : source === 'ldap' && !trimmed.startsWith('ldap:')
        ? `ldap:${trimmed}`
        : trimmed;
  if (/^[a-z][a-z0-9_-]{0,31}$/.test(raw)) {
    return raw;
  }
  let slug = raw
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  if (!slug || !/^[a-z]/.test(slug)) {
    slug = slug ? `u-${slug}` : 'user';
  }
  slug = slug.slice(0, 22).replace(/-+$/, '') || 'user';
  const hash = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 8);
  return `${slug}-${hash}`;
}

export function maskPreAuthKey(raw: unknown): string {
  if (typeof raw !== 'string' || !raw) return '';
  if (raw.length <= 10) return `${raw.slice(0, 3)}•••`;
  return `${raw.slice(0, 8)}•••${raw.slice(-4)}`;
}

// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------

export async function listUsers(): Promise<HeadscaleUserRecord[]> {
  const data = await runHeadscale(['users', 'list', '-o', 'json']);
  if (!Array.isArray(data)) return [];
  return data.map((u: any) => ({
    id: u.id,
    name: u.name,
    // B-L5: no fabricated "now" — when the timestamp is missing or
    // unparsable the creation time is unknown, not the moment of listing.
    createdAt: headscaleTimestamp(u, 'createdAt', 'created_at'),
  }));
}

export async function createUser(name: string): Promise<HeadscaleUserRecord> {
  const safeName = assertSafeIdentifier(name, 'User name');
  const data = await runHeadscale(['users', 'create', safeName, '-o', 'json']);
  return {
    id: data?.id,
    name: data?.name || safeName,
    // B-L5: no fabricated "now" — see listUsers above.
    createdAt: headscaleTimestamp(data, 'createdAt', 'created_at'),
  };
}

export async function ensureUser(name: string): Promise<HeadscaleUserRecord> {
  const safeName = assertSafeIdentifier(name, 'User name');
  const users = await listUsers();
  const existing = users.find((u) => u.name === safeName);
  if (existing) return existing;
  try {
    return await createUser(safeName);
  } catch (err: any) {
    if (String(err?.message || '').toLowerCase().includes('already')) {
      const retryUsers = await listUsers();
      const found = retryUsers.find((u) => u.name === safeName);
      if (found) return found;
    }
    throw err;
  }
}

export async function deleteUser(nameOrId: string | number) {
  const raw = String(nameOrId).trim();
  if (!raw) throw new Error('User name or ID is required');
  let targetId: string | number | undefined = /^\d+$/.test(raw) ? raw : undefined;
  let safeName: string | undefined;
  if (targetId === undefined) {
    safeName = assertSafeIdentifier(raw, 'User name');
    const users = await listUsers();
    const found = users.find((u) => u.name === safeName);
    if (found?.id !== undefined && found?.id !== null) {
      targetId = found.id;
    }
  }
  if (targetId !== undefined) {
    try {
      return await runHeadscale(['users', 'destroy', '-i', String(targetId), '--force']);
    } catch (err: any) {
      const msg = String(err?.message || '').toLowerCase();
      if (!safeName || (!msg.includes('unknown') && !msg.includes('shorthand') && !msg.includes('flag'))) {
        throw err;
      }
    }
  }
  return runHeadscale(['users', 'destroy', safeName ?? assertSafeIdentifier(raw, 'User name'), '--force']);
}

// -----------------------------------------------------------------------------
// PreAuthKeys
// -----------------------------------------------------------------------------

export async function createPreAuthKey(user: string | number, reusable: boolean, ephemeral: boolean, expiration?: string) {
  let userId: string | number = user;
  let resolvedName = String(user);
  if (typeof user === 'string' && !/^\d+$/.test(user.trim())) {
    const ensured = await ensureUser(user);
    userId = ensured.id;
    resolvedName = ensured.name;
  }

  const safeUserId = typeof userId === 'number' ? userId : assertSafeIdentifier(userId, 'User ID');
  const args = ['preauthkeys', 'create', '--user', String(safeUserId), '-o', 'json'];
  if (reusable) args.push('--reusable');
  if (ephemeral) args.push('--ephemeral');
  if (expiration !== undefined && expiration !== '') {
    const parsedTime = new Date(expiration).getTime();
    if (Number.isNaN(parsedTime)) {
      throw new Error('Invalid expiration timestamp');
    }
    const ms = parsedTime - Date.now();
    if (ms <= 0) {
      throw new Error('Expiration timestamp must be in the future');
    }
    const seconds = Math.ceil(ms / 1000);
    args.push('--expiration', `${seconds}s`);
  }

  const data = await runHeadscale(args);
  return {
    id: data?.id,
    key: data?.key,
    keyPreview: maskPreAuthKey(data?.key),
    reusable: Boolean(data?.reusable),
    ephemeral: Boolean(data?.ephemeral),
    expiration: headscaleTimestamp(data, 'expiration'),
    user: data?.user || { id: safeUserId, name: resolvedName },
  };
}

export async function listPreAuthKeys(user?: string): Promise<HeadscalePreAuthKeyRecord[]> {
  const data = await runHeadscale(['preauthkeys', 'list', '-o', 'json']);
  if (!Array.isArray(data)) return [];
  const now = Date.now();
  const keys: HeadscalePreAuthKeyRecord[] = data.map((k: any) => {
    const expiration = headscaleTimestamp(k, 'expiration');
    const expMs = expiration ? Date.parse(expiration) : NaN;
    return {
      id: k.id,
      key: k.key ?? '',
      keyPreview: maskPreAuthKey(k.key),
      reusable: Boolean(k.reusable),
      ephemeral: Boolean(k.ephemeral),
      used: Boolean(k.used),
      expired: Number.isFinite(expMs) ? expMs <= now : false,
      expiration,
      createdAt: headscaleTimestamp(k, 'createdAt', 'created_at'),
      user: k.user,
    };
  });
  if (user) {
    const safeUser = assertSafeIdentifier(user, 'User');
    return keys.filter((k) => k.user?.name === safeUser || String(k.user?.id) === safeUser);
  }
  return keys;
}

export async function expirePreAuthKey(user: string, keyOrId: string | number, keyId?: string | number) {
  const numericId =
    keyId !== undefined && keyId !== '' && /^\d+$/.test(String(keyId).trim())
      ? String(keyId).trim()
      : /^\d+$/.test(String(keyOrId).trim())
        ? String(keyOrId).trim()
        : undefined;

  if (numericId) {
    try {
      return await runHeadscale(['preauthkeys', 'expire', '--id', numericId]);
    } catch (err: any) {
      const msg = String(err?.message || '').toLowerCase();
      if (!msg.includes('unknown') && !msg.includes('flag')) {
        throw err;
      }
    }
  }

  const safeKey = assertSafeIdentifier(keyOrId, 'Preauth key');
  const args = ['preauthkeys', 'expire', safeKey];
  if (user && String(user).trim()) {
    const safeUser = assertSafeIdentifier(user, 'User');
    args.push('--user', safeUser);
  }
  return runHeadscale(args);
}

// -----------------------------------------------------------------------------
// Machines / Nodes
// -----------------------------------------------------------------------------

export async function listMachines(user?: string): Promise<HeadscaleMachineRecord[]> {
  const data = await runHeadscale(['nodes', 'list', '-o', 'json']);
  if (!Array.isArray(data)) return [];
  const nodes: HeadscaleMachineRecord[] = data.map((n: any) => {
    const approvedRoutes = n.approved_routes || n.approvedRoutes || [];
    const availableRoutes = n.available_routes || n.availableRoutes || [];
    const givenName = n.given_name || n.givenName || n.name;
    return {
      id: n.id,
      name: givenName,
      hostname: n.name,
      givenName,
      ipAddresses: n.ip_addresses || n.ipAddresses || [],
      user: n.user,
      lastSeen: headscaleTimestamp(n, 'lastSeen', 'last_seen') ?? null,
      online: n.online ?? false,
      routes: approvedRoutes,
      approvedRoutes,
      availableRoutes,
      expiry: headscaleTimestamp(n, 'expiry') ?? null,
      createdAt: headscaleTimestamp(n, 'createdAt', 'created_at') ?? null,
    };
  });
  if (user) {
    const safeUser = assertSafeIdentifier(user, 'User');
    return nodes.filter((n) => n.user?.name === safeUser || String(n.user?.id) === safeUser);
  }
  return nodes;
}

export function extractRegistrationToken(
  input: string
): { kind: 'auth_id' | 'machine_key'; token: string } {
  const trimmed = String(input || '').trim();
  if (!trimmed) {
    throw new Error('Registration key or command is required');
  }

  let kind: 'auth_id' | 'machine_key' | undefined;
  let token = '';

  const authIdFlagMatch = trimmed.match(/--auth[-_]?id(?:=|\s+)([^\s"']+)/i);
  const keyFlagMatch = trimmed.match(/(?:--key|-k)(?:=|\s+)([^\s"']+)/i);
  const authReqMatch = trimmed.match(/\b(hskey-authreq-[a-zA-Z0-9_.:-]{4,})\b/);
  const legacyKeyMatch = trimmed.match(/\b((?:mkey|nodekey):[a-zA-Z0-9_.:-]{6,})\b/);

  if (authIdFlagMatch) {
    kind = 'auth_id';
    token = authIdFlagMatch[1];
  } else if (keyFlagMatch) {
    token = keyFlagMatch[1];
    kind = token.startsWith('hskey-authreq-') ? 'auth_id' : 'machine_key';
  } else if (authReqMatch) {
    kind = 'auth_id';
    token = authReqMatch[1];
  } else if (legacyKeyMatch) {
    kind = 'machine_key';
    token = legacyKeyMatch[1];
  } else if (!/\s/.test(trimmed)) {
    token = trimmed;
    kind = trimmed.startsWith('hskey-authreq-') ? 'auth_id' : 'machine_key';
  } else {
    throw new Error(
      'Unrecognized registration key format. Paste an auth ID (hskey-authreq-...), machine/node key (mkey:/nodekey:), or the full headscale register command.'
    );
  }

  token = token.replace(/^["']|["']$/g, '').trim();
  if (!token || token.startsWith('-') || !/^[a-zA-Z0-9_.:-]{6,256}$/.test(token)) {
    throw new Error('Registration token contains invalid characters or invalid length');
  }

  return { kind: kind ?? 'machine_key', token };
}

export async function registerMachine(user: string | number, rawKeyOrCommand: string) {
  let targetUser = String(user).trim();
  if (!targetUser) {
    throw new Error('User is required to register a machine');
  }
  if (/^\d+$/.test(targetUser)) {
    const users = await listUsers();
    const found = users.find((u) => String(u.id) === targetUser);
    if (!found) {
      throw new Error(`Headscale user ID ${targetUser} not found`);
    }
    targetUser = found.name;
  } else {
    const ensured = await ensureUser(targetUser);
    targetUser = ensured.name;
  }

  const { kind, token } = extractRegistrationToken(rawKeyOrCommand);
  if (kind === 'auth_id') {
    return runHeadscale(['auth', 'register', '--user', targetUser, '--auth-id', token, '-o', 'json']);
  }
  return runHeadscale(['nodes', 'register', '--user', targetUser, '--key', token, '-o', 'json']);
}

export function findOwnedMachine(
  machines: HeadscaleMachineRecord[],
  ownerUser: string,
  machineId: string | number
): HeadscaleMachineRecord {
  const safeOwner = assertSafeIdentifier(ownerUser, 'Owner user');
  const safeId = assertSafeIdentifier(machineId, 'Machine ID');
  const match = machines.find(
    (m) => String(m.id) === String(safeId) && m.user?.name === safeOwner
  );
  if (!match) {
    const err = new Error('Machine not found');
    (err as any).code = 'NOT_FOUND';
    throw err;
  }
  return match;
}

export async function assertMachineOwnedByUser(
  ownerUser: string,
  machineId: string | number
): Promise<HeadscaleMachineRecord> {
  const safeOwner = assertSafeIdentifier(ownerUser, 'Owner user');
  const machines = await listMachines(safeOwner);
  return findOwnedMachine(machines, safeOwner, machineId);
}

export function findOwnedPreAuthKey(
  keys: HeadscalePreAuthKeyRecord[],
  ownerUser: string,
  keyIdOrKey: string | number
): HeadscalePreAuthKeyRecord {
  const safeOwner = assertSafeIdentifier(ownerUser, 'Owner user');
  const safeTarget = assertSafeIdentifier(keyIdOrKey, 'Preauth key identifier');
  const match = keys.find(
    (k) =>
      k.user?.name === safeOwner &&
      (String(k.id) === String(safeTarget) || k.key === String(safeTarget))
  );
  if (!match) {
    const err = new Error('Pre-auth key not found');
    (err as any).code = 'NOT_FOUND';
    throw err;
  }
  return match;
}

export async function assertPreAuthKeyOwnedByUser(
  ownerUser: string,
  keyIdOrKey: string | number
): Promise<HeadscalePreAuthKeyRecord> {
  const safeOwner = assertSafeIdentifier(ownerUser, 'Owner user');
  const keys = await listPreAuthKeys(safeOwner);
  return findOwnedPreAuthKey(keys, safeOwner, keyIdOrKey);
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
