import { Client } from 'ldapts';
import { SignJWT, jwtVerify } from 'jose';
import * as crypto from 'node:crypto';
import { type Privilege, type UserSession, DEFAULT_ROLES } from '../rbac/index.js';

export interface LdapConfig {
  url: string; // e.g. ldap://127.0.0.1:389
  baseDn: string; // e.g. dc=axonwall,dc=local
  bindDn?: string; // service account DN e.g. cn=admin,dc=axonwall,dc=local
  bindPassword?: string;
  userSearchFilter: string; // e.g. (&(objectClass=inetOrgPerson)(uid={{username}}))
  groupSearchFilter: string; // e.g. (&(objectClass=groupOfNames)(member={{userDn}}))
  groupRoleMap?: Record<string, string>; // e.g. { "admins": "admin", "operators": "operator" }
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

export async function authenticateLdap(
  config: LdapConfig,
  username: string,
  password: string
): Promise<AuthResult> {
  if (!username || !password) {
    return { success: false, error: 'Username and password are required' };
  }

  const client = new Client({
    url: config.url,
    timeout: config.timeoutMs || 5000,
    connectTimeout: config.timeoutMs || 5000,
  });

  try {
    // 1. Initial bind as service account or anonymous
    if (config.bindDn && config.bindPassword) {
      await client.bind(config.bindDn, config.bindPassword);
    }

    // 2. Search for the user DN
    const safeUsername = escapeLdapFilter(username);
    const filter = config.userSearchFilter.replace(/{{username}}/g, safeUsername);
    const searchRes = await client.search(config.baseDn, {
      filter,
      scope: 'sub',
      attributes: ['dn', 'cn', 'mail', 'memberOf'],
    });

    if (searchRes.searchEntries.length === 0) {
      return { success: false, error: 'User not found in LDAP directory' };
    }

    const userEntry = searchRes.searchEntries[0];
    const userDn = userEntry.dn;

    // 3. Authenticate by rebinding as the target user
    const userClient = new Client({
      url: config.url,
      timeout: config.timeoutMs || 5000,
    });

    try {
      await userClient.bind(userDn, password);
    } catch {
      return { success: false, error: 'Invalid credentials' };
    } finally {
      await userClient.unbind();
    }

    // 4. Resolve group memberships
    let groups: string[] = [];
    if (userEntry.memberOf) {
      const raw = Array.isArray(userEntry.memberOf) ? userEntry.memberOf : [userEntry.memberOf];
      groups = raw.map((g) => {
        // extract CN if full DN
        const match = /cn=([^,]+)/i.exec(String(g));
        return match ? match[1].toLowerCase() : String(g).toLowerCase();
      });
    } else {
      // Query groupOfNames by member
      const safeUserDn = escapeLdapFilter(userDn);
      const groupFilter = config.groupSearchFilter.replace(/{{userDn}}/g, safeUserDn);
      const groupSearch = await client.search(config.baseDn, {
        filter: groupFilter,
        scope: 'sub',
        attributes: ['cn'],
      });
      groups = groupSearch.searchEntries.map((e) => String(e.cn).toLowerCase());
    }

    // 5. Map LDAP groups to Axonwall roles and privileges
    const roleMap = config.groupRoleMap || {
      admins: 'admin',
      operators: 'operator',
      readonly: 'readonly',
    };

    const roles = new Set<string>();
    for (const g of groups) {
      if (roleMap[g]) {
        roles.add(roleMap[g]);
      }
    }
    // Default fallback to readonly if no roles matched
    if (roles.size === 0) {
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
      jti: payload.jti as string | undefined,
    };
  } catch {
    return null;
  }
}
