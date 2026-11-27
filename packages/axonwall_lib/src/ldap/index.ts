import { Client, type ClientOptions } from 'ldapts';
import { SignJWT, jwtVerify } from 'jose';
import * as crypto from 'node:crypto';
import type * as tls from 'node:tls';
import { type Privilege, type UserSession, DEFAULT_ROLES } from '../rbac/index.js';

export interface LdapConfig {
  url: string; // e.g. ldap://127.0.0.1:389 or ldaps://ldap.example.com:636
  baseDn: string; // e.g. dc=axonwall,dc=local
  groupBaseDn?: string; // e.g. ou=groups,dc=axonwall,dc=local (defaults to ou=groups,<baseDn>)
  bindDn?: string; // service account DN e.g. cn=admin,dc=axonwall,dc=local
  bindPassword?: string;
  userSearchFilter: string; // e.g. (&(objectClass=inetOrgPerson)(uid={{username}}))
  groupSearchFilter: string; // e.g. (&(objectClass=groupOfNames)(member={{userDn}}))
  groupRoleMap?: Record<string, string>; // e.g. { "cn=admins,ou=groups,dc=axonwall,dc=local": "admin" } or { "admins": "admin" }
  groupMapping?: Record<string, string>;
  allowUnmappedReadonly?: boolean;
  startTls?: boolean;
  tlsOptions?: tls.ConnectionOptions;
  timeoutMs?: number;
}

export interface AuthResult {
  success: boolean;
  error?: string;
  session?: UserSession;
}

export function escapeLdapFilter(str: string): string {
  return str.replace(/[*()\\\x00]/g, (c) => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

function splitDnRdns(dn: string): string[] {
  const parts: string[] = [];
  let current = '';
  let escaped = false;
  for (let i = 0; i < dn.length; i++) {
    const ch = dn[i]!;
    if (escaped) {
      current += ch;
      escaped = false;
    } else if (ch === '\\') {
      current += ch;
      escaped = true;
    } else if (ch === ',') {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts;
}

export function normalizeLdapDn(dn: string): string {
  return splitDnRdns(dn)
    .map((rdn) => {
      const eqIdx = rdn.indexOf('=');
      if (eqIdx === -1) return rdn.trim().toLowerCase();
      const attr = rdn.slice(0, eqIdx).trim().toLowerCase();
      const val = rdn.slice(eqIdx + 1).trim().toLowerCase();
      return `${attr}=${val}`;
    })
    .filter(Boolean)
    .join(',');
}

function resolveGroupBaseDn(config: LdapConfig): string {
  const explicit = config.groupBaseDn?.trim();
  if (explicit) return normalizeLdapDn(explicit);
  const base = config.baseDn?.trim();
  if (base) return normalizeLdapDn(`ou=groups,${base}`);
  return '';
}

function resolveRoleForGroupDn(
  rawGroupDn: string,
  expectedGroupBaseDn: string,
  fullDnRoleMap: Record<string, string>,
  cnRoleMap: Record<string, string>,
): string | null {
  const normDn = normalizeLdapDn(rawGroupDn);
  if (!normDn) return null;

  if (Object.prototype.hasOwnProperty.call(fullDnRoleMap, normDn)) {
    return fullDnRoleMap[normDn]!;
  }

  // Short CN keys are ONLY accepted when the entry's normalized DN resides under the
  // configured groupBaseDn (or ou=groups,<baseDn>) and its leading RDN is cn=<name>.
  if (expectedGroupBaseDn && normDn.endsWith(`,${expectedGroupBaseDn}`)) {
    const rdns = splitDnRdns(normDn);
    const firstRdn = rdns[0] ?? '';
    if (firstRdn.startsWith('cn=')) {
      const cn = firstRdn.slice(3).trim();
      if (cn && Object.prototype.hasOwnProperty.call(cnRoleMap, cn)) {
        return cnRoleMap[cn]!;
      }
    }
  }

  return null;
}

function buildLdapClientConfig(config: LdapConfig, isLdaps: boolean, tlsOpts?: tls.ConnectionOptions): ClientOptions {
  const timeout = config.timeoutMs || 5000;
  return {
    url: config.url,
    timeout,
    connectTimeout: timeout,
    ...(isLdaps && tlsOpts ? { tlsOptions: tlsOpts } : {}),
  };
}

export async function authenticateLdap(
  config: LdapConfig,
  username: string,
  password: string
): Promise<AuthResult> {
  if (!username || !password) {
    return { success: false, error: 'Username and password are required' };
  }

  const isLdaps = config.url.trim().toLowerCase().startsWith('ldaps://');
  const useStartTls = !isLdaps && Boolean(config.startTls);
  const tlsOpts: tls.ConnectionOptions | undefined =
    isLdaps || useStartTls || config.tlsOptions
      ? { rejectUnauthorized: true, ...(config.tlsOptions ?? {}) }
      : undefined;

  const client = new Client(buildLdapClientConfig(config, isLdaps, tlsOpts));

  try {
    if (useStartTls) {
      await client.startTLS(tlsOpts);
    }

    // 1. Initial bind as service account or anonymous
    if (config.bindDn && config.bindPassword) {
      await client.bind(config.bindDn, config.bindPassword);
    }

    // 2. Search for the user DN
    const safeUsername = escapeLdapFilter(username);
    const filter = config.userSearchFilter.replace(/\{\{username\}\}/g, () => safeUsername);
    const searchRes = await client.search(config.baseDn, {
      filter,
      scope: 'sub',
      attributes: ['dn', 'cn', 'mail', 'memberOf'],
    });

    if (searchRes.searchEntries.length === 0) {
      return { success: false, error: 'User not found in LDAP directory' };
    }
    if (searchRes.searchEntries.length !== 1) {
      return { success: false, error: 'Ambiguous LDAP user match: multiple directory entries returned' };
    }

    const userEntry = searchRes.searchEntries[0];
    const userDn = userEntry.dn;

    // 3. Authenticate by rebinding as the target user
    const userClient = new Client(buildLdapClientConfig(config, isLdaps, tlsOpts));

    try {
      if (useStartTls) {
        await userClient.startTLS(tlsOpts);
      }
      await userClient.bind(userDn, password);
    } catch {
      return { success: false, error: 'Invalid credentials' };
    } finally {
      try {
        await userClient.unbind();
      } catch {
        // ignore unbind errors on disconnect
      }
    }

    // 4. Resolve group memberships using full normalized DNs / verified groupBaseDn
    const expectedGroupBaseDn = resolveGroupBaseDn(config);
    const groupDns: string[] = [];
    const memberOfRaw = userEntry.memberOf
      ? (Array.isArray(userEntry.memberOf) ? userEntry.memberOf : [userEntry.memberOf])
          .map((g) => String(g).trim())
          .filter(Boolean)
      : [];
    if (memberOfRaw.length > 0) {
      groupDns.push(...memberOfRaw);
    } else if (config.groupSearchFilter) {
      // Query groupOfNames / posixGroup under verified groupBaseDn (or baseDn if configured)
      const safeUserDn = escapeLdapFilter(userDn);
      const groupFilter = config.groupSearchFilter
        .replace(/\{\{userDn\}\}/g, () => safeUserDn)
        .replace(/\{\{username\}\}/g, () => safeUsername);
      const searchBase = config.groupBaseDn?.trim() || (config.baseDn?.trim() ? `ou=groups,${config.baseDn.trim()}` : config.baseDn);
      const groupSearch = await client.search(searchBase, {
        filter: groupFilter,
        scope: 'sub',
        attributes: ['dn', 'cn'],
      });
      for (const entry of groupSearch.searchEntries) {
        if (entry.dn) {
          groupDns.push(String(entry.dn).trim());
        }
      }
    }

    // 5. Map LDAP groups to Axonwall roles and privileges (fail closed when unmapped)
    const configuredRoleMap = config.groupRoleMap ?? config.groupMapping ?? {};
    const fullDnRoleMap: Record<string, string> = {};
    const cnRoleMap: Record<string, string> = {};
    for (const [k, v] of Object.entries(configuredRoleMap)) {
      const trimmedKey = k.trim();
      if (!trimmedKey) continue;
      if (trimmedKey.includes('=')) {
        fullDnRoleMap[normalizeLdapDn(trimmedKey)] = v;
      } else {
        cnRoleMap[trimmedKey.toLowerCase()] = v;
      }
    }

    const roles = new Set<string>();
    for (const dn of groupDns) {
      const mapped = resolveRoleForGroupDn(dn, expectedGroupBaseDn, fullDnRoleMap, cnRoleMap);
      if (mapped) {
        roles.add(mapped);
      }
    }
    if (roles.size === 0) {
      if (config.allowUnmappedReadonly !== true) {
        return { success: false, error: 'User is not a member of any mapped LDAP group' };
      }
      roles.add('readonly');
    }

    const privileges = new Set<Privilege>();
    for (const r of roles) {
      const roleDef = DEFAULT_ROLES[r];
      if (roleDef) {
        for (const p of roleDef.privileges) {
          privileges.add(p);
        }
      }
    }

    const session: UserSession = {
      userId: userDn,
      username,
      displayName: (userEntry.cn as string) || username,
      email: (userEntry.mail as string) || undefined,
      source: 'ldap',
      roles: Array.from(roles),
      privileges: Array.from(privileges),
      exp: Math.floor(Date.now() / 1000) + 8 * 3600, // 8 hours
    };

    return { success: true, session };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: `LDAP error: ${message}` };
  } finally {
    try {
      await client.unbind();
    } catch {
      // ignore
    }
  }
}

/**
 * Break-glass local admin verification for emergency console or initial bootstrap
 */
export function authenticateLocalAdmin(
  username: string,
  pass: string,
  expectedUser: string,
  expectedPassOrHash: string
): AuthResult {
  if (!username || !pass || !expectedUser || !expectedPassOrHash) {
    return { success: false, error: 'Invalid local administrator credentials' };
  }

  const uBuf = Buffer.from(username);
  const expUBuf = Buffer.from(expectedUser);
  const userMatch = uBuf.length === expUBuf.length && crypto.timingSafeEqual(uBuf, expUBuf);

  let passMatch = false;
  if (expectedPassOrHash.startsWith('scrypt$')) {
    const parts = expectedPassOrHash.split('$');
    if (parts.length === 3) {
      const salt = parts[1];
      const expectedHash = parts[2];
      const derived = crypto.scryptSync(pass, salt, 64).toString('hex');
      const dBuf = Buffer.from(derived);
      const eBuf = Buffer.from(expectedHash);
      passMatch = dBuf.length === eBuf.length && crypto.timingSafeEqual(dBuf, eBuf);
    }
  } else {
    const pBuf = Buffer.from(pass);
    const expPBuf = Buffer.from(expectedPassOrHash);
    passMatch = pBuf.length === expPBuf.length && crypto.timingSafeEqual(pBuf, expPBuf);
  }

  if (userMatch && passMatch) {
    const adminRole = DEFAULT_ROLES.admin;
    return {
      success: true,
      session: {
        userId: 'local-admin-root',
        username: expectedUser,
        displayName: 'Emergency Local Administrator',
        source: 'local_admin',
        roles: ['admin'],
        privileges: [...adminRole.privileges],
        exp: Math.floor(Date.now() / 1000) + 8 * 3600,
      },
    };
  }
  return { success: false, error: 'Invalid local administrator credentials' };
}

/**
 * Mints a Supabase-compatible JWT
 */
export async function mintSupabaseToken(
  session: UserSession,
  jwtSecret: string
): Promise<string> {
  const secretKey = new TextEncoder().encode(jwtSecret);

  return new SignJWT({
    sub: session.userId,
    username: session.username,
    role: 'authenticated', // Supabase auth role for RLS
    app_roles: session.roles,
    app_privs: session.privileges,
    ...(session.passwordChangeRequired ? { pwd_change_required: true } : {}),
    session_epoch: session.sessionEpoch ?? 0,
    user_session_epoch: session.userSessionEpoch ?? 0,
    user_metadata: {
      displayName: session.displayName,
      email: session.email,
      source: session.source,
    },
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(session.exp)
    .sign(secretKey);
}

/**
 * Verify and decode JWT
 */
export async function verifyToken(
  token: string,
  jwtSecret: string
): Promise<UserSession | null> {
  try {
    const secretKey = new TextEncoder().encode(jwtSecret);
    // Pin the algorithm: these tokens are HS256 (see mintSupabaseToken).
    // jose already constrains octet keys to HS*, but an explicit
    // allowlist keeps that true by construction (audit suspect B-S7).
    const { payload } = await jwtVerify(token, secretKey, { algorithms: ['HS256'] });

    return {
      userId: payload.sub as string,
      username: (payload.username as string) || (payload.sub as string),
      displayName: (payload.user_metadata as any)?.displayName,
      email: (payload.user_metadata as any)?.email,
      source: (payload.user_metadata as any)?.source || 'ldap',
      roles: (payload.app_roles as string[]) || [],
      privileges: (payload.app_privs as Privilege[]) || [],
      exp: (payload.exp as number) || 0,
      passwordChangeRequired: payload.pwd_change_required === true,
      sessionEpoch: (payload.session_epoch as number) || 0,
      userSessionEpoch: (payload.user_session_epoch as number) || 0,
      jti: payload.jti as string | undefined,
    };
  } catch {
    return null;
  }
}
