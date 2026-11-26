import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

import {
  authenticateLdap,
  authenticateLocalAdmin,
  type LdapConfig,
  type AuthResult,
} from '@axonwall/lib/ldap';
import { type UserSession, DEFAULT_ROLES } from '@axonwall/lib/rbac';
import { callAgentApi } from './agent-client';
import {
  ensureDevRuntimeBootstrapped,
  getEtcConfigDir,
  getPersistConfigDir,
  isDevRuntime,
} from './dev-paths';
import { passwordChangeRequiredNow } from './auth-guard';
import { stampSessionEpoch } from './session-revocation';

export const LDAP_CONFIG: LdapConfig = {
  url: process.env.LDAP_URL || 'ldap://127.0.0.1:389',
  baseDn: process.env.LDAP_BASE_DN || 'dc=axonwall,dc=local',
  bindDn: process.env.LDAP_BIND_DN || 'cn=admin,dc=axonwall,dc=local',
  bindPassword: process.env.LDAP_BIND_PASSWORD || '',
  userSearchFilter: process.env.LDAP_USER_FILTER || '(&(objectClass=inetOrgPerson)(uid={{username}}))',
  groupSearchFilter: process.env.LDAP_GROUP_FILTER || '(&(objectClass=groupOfNames)(member={{userDn}}))',
  groupRoleMap: {
    admins: 'admin',
    operators: 'operator',
    auditors: 'readonly',
    'axonwall-admin': 'admin',
    'axonwall-operator': 'operator',
    'axonwall-readonly': 'readonly',
    'axonwall-vpn': 'vpn_user',
    vpn: 'vpn_user',
  },
};

function getMfaEnvPaths(): string[] {
  return Array.from(
    new Set([path.join(getPersistConfigDir(), 'mfa.env'), path.join(getEtcConfigDir(), 'mfa.env')])
  );
}

export function writeAuthFileSafe(filePath: string, content: string, mode = 0o600): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o775 });
  }
  const base = path.basename(filePath);
  const tmpPath = path.join(dir, `.${base}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  let fd: number | null = null;
  try {
    fd = fs.openSync(tmpPath, 'wx', mode);
    fs.writeFileSync(fd, content, 'utf8');
    try {
      fs.fsyncSync(fd);
    } catch {}
    fs.closeSync(fd);
    fd = null;
    try {
      fs.chmodSync(tmpPath, mode);
    } catch {}
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {}
    }
    try {
      if (fs.existsSync(tmpPath)) {
        fs.unlinkSync(tmpPath);
      }
    } catch {}
    throw err;
  }
}

export function readMfaEnv(): Map<string, string> {
  const values = new Map<string, string>();
  for (const mfaPath of getMfaEnvPaths()) {
    try {
      if (!fs.existsSync(mfaPath)) continue;
      for (const line of fs.readFileSync(mfaPath, 'utf-8').split('\n')) {
        const trimmed = line.trim();
        const eq = trimmed.indexOf('=');
        if (eq > 0 && !values.has(trimmed.substring(0, eq))) {
          values.set(trimmed.substring(0, eq), trimmed.substring(eq + 1));
        }
      }
    } catch {}
  }
  return values;
}

/**
 * Resolves the local admin TOTP secret, always preferring on-disk mfa.env
 * over process.env so break-glass resets deleting mfa.env take effect immediately
 * without restarting axonwall-ui (W-H7).
 */
export function getMfaSecret(): string | undefined {
  const diskSecret = readMfaEnv().get('LOCAL_ADMIN_MFA_SECRET');
  if (diskSecret && diskSecret.trim()) {
    return diskSecret.trim();
  }
  // If any mfa.env path exists without LOCAL_ADMIN_MFA_SECRET, or none exist after reset,
  // only fall back to process.env if no mfa.env file management is active.
  const hasAnyMfaFile = getMfaEnvPaths().some((p) => fs.existsSync(p));
  if (hasAnyMfaFile) return undefined;
  return process.env.LOCAL_ADMIN_MFA_SECRET?.trim() || undefined;
}

export function writeMfaEnv(updates: Record<string, string>): void {
  const values = readMfaEnv();
  for (const [k, v] of Object.entries(updates)) values.set(k, v);
  const content = [...values.entries()].map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
  let written = 0;
  let lastErr: unknown;
  for (const mfaPath of getMfaEnvPaths()) {
    try {
      writeAuthFileSafe(mfaPath, content, 0o600);
      written += 1;
    } catch (err) {
      lastErr = err;
    }
  }
  if (written === 0) {
    throw lastErr instanceof Error
      ? lastErr
      : new Error('Unable to persist mfa.env to any configured axonwall directory');
  }
}

export function totpPlugins() {
  const { NobleCryptoPlugin, ScureBase32Plugin } = require('otplib');
  return { crypto: new NobleCryptoPlugin(), base32: new ScureBase32Plugin() };
}

export async function verifyTotpCode(secret: string, token: string): Promise<boolean> {
  const { verify } = require('otplib');
  const lastStep = Number(readMfaEnv().get('LOCAL_ADMIN_MFA_LAST_STEP') || 0);
  const options: Record<string, unknown> = { secret, token, ...totpPlugins(), epochTolerance: 30 };
  if (lastStep > 0) options.afterTimeStep = lastStep;
  const result = await verify(options);
  if (!result.valid) return false;
  if (typeof result.timeStep === 'number' && result.timeStep > lastStep) {
    try {
      writeMfaEnv({ LOCAL_ADMIN_MFA_LAST_STEP: String(result.timeStep) });
    } catch {}
  }
  return true;
}

const LOGIN_MAX_FAILURES = 5;
const LOGIN_LOCKOUT_MS = 5 * 60 * 1000;
const LOGIN_FAILURE_MAX_ENTRIES = 2000;
const loginFailures = new Map<string, { count: number; lockedUntil: number }>();

function pruneLoginFailures(now: number) {
  for (const [k, rec] of loginFailures) {
    if (rec.lockedUntil > 0 && rec.lockedUntil <= now) {
      loginFailures.delete(k);
    }
  }
  if (loginFailures.size >= LOGIN_FAILURE_MAX_ENTRIES) {
    // Never evict actively locked accounts under map pressure; only evict unlocked entries.
    for (const [k, rec] of loginFailures) {
      if (loginFailures.size < LOGIN_FAILURE_MAX_ENTRIES) break;
      if (rec.lockedUntil <= now) {
        loginFailures.delete(k);
      }
    }
  }
}

export async function performAuthentication(
  username: string,
  password: string,
  totpCode?: string
): Promise<AuthResult> {
  if (typeof username !== 'string' || typeof password !== 'string') {
    return { success: false, error: 'Username and password are required' };
  }
  const key = username.toLowerCase();
  const now = Date.now();
  const initialRecord = loginFailures.get(key);
  if (initialRecord && initialRecord.lockedUntil > now) {
    return { success: false, error: 'Too many failed sign-in attempts. Try again in a few minutes.' };
  }
  const result = await performAuthenticationInner(username, password, totpCode);
  const postNow = Date.now();
  const latestRecord = loginFailures.get(key);
  if (latestRecord && latestRecord.lockedUntil > postNow) {
    // Another concurrent attempt triggered lockout while performAuthenticationInner was awaiting.
    return { success: false, error: 'Too many failed sign-in attempts. Try again in a few minutes.' };
  }
  if (result.success) {
    loginFailures.delete(key);
  } else {
    // W-M4: once a prior lockout expires (lockedUntil > 0 && lockedUntil <= postNow),
    // reset the failure counter instead of immediately re-locking on the next typo.
    const activeUnexpiredCount = latestRecord && latestRecord.lockedUntil === 0 ? latestRecord.count : 0;
    const count = activeUnexpiredCount + 1;
    pruneLoginFailures(postNow);
    loginFailures.delete(key);
    loginFailures.set(key, {
      count,
      lockedUntil: count >= LOGIN_MAX_FAILURES ? postNow + LOGIN_LOCKOUT_MS : 0,
    });
  }
  return result;
}

async function performAuthenticationInner(
  username: string,
  password: string,
  totpCode?: string
): Promise<AuthResult> {
  if (!username || !password) {
    return { success: false, error: 'Username and password are required' };
  }

  if (isDevRuntime()) {
    ensureDevRuntimeBootstrapped();
  }

  let localAdminUser = process.env.LOCAL_ADMIN_USER || 'admin';
  let localAdminPass = process.env.LOCAL_ADMIN_PASSWORD || '';

  const adminEnvPaths = Array.from(
    new Set([path.join(getPersistConfigDir(), 'admin.env'), path.join(getEtcConfigDir(), 'admin.env')])
  );
  for (const adminEnvPath of adminEnvPaths) {
    try {
      if (fs.existsSync(adminEnvPath)) {
        const content = fs.readFileSync(adminEnvPath, 'utf-8');
        for (const line of content.split('\n')) {
          const trimmed = line.trim();
          if (trimmed.startsWith('LOCAL_ADMIN_USER=')) {
            localAdminUser = trimmed.substring('LOCAL_ADMIN_USER='.length);
          } else if (trimmed.startsWith('LOCAL_ADMIN_PASSWORD=')) {
            localAdminPass = trimmed.substring('LOCAL_ADMIN_PASSWORD='.length);
          }
        }
        if (localAdminPass) break;
      }
    } catch {}
  }

  if (username === localAdminUser) {
    if (!localAdminPass) {
      return { success: false, error: 'Local administrator account is not configured' };
    }
    const authRes = authenticateLocalAdmin(username, password, localAdminUser, localAdminPass);
    if (!authRes.success) {
      return { success: false, error: 'Invalid username or password' };
    }

    const mfaSecret = getMfaSecret();
    if (mfaSecret && authRes.success) {
      if (!totpCode) {
        return { success: false, error: 'MFA Code (TOTP) is required for this account' };
      }
      if (!(await verifyTotpCode(mfaSecret, totpCode))) {
        return { success: false, error: 'Invalid MFA Code' };
      }
    }
    if (authRes.session) {
      authRes.session.passwordChangeRequired = passwordChangeRequiredNow();
      stampSessionEpoch(authRes.session);
    }
    return authRes;
  }

  try {
    const localUserAuth = await callAgentApi<{
      success: boolean;
      username: string;
      applianceRole: 'admin' | 'operator' | 'readonly' | 'vpn_user' | 'os_only';
      groups: string[];
      message?: string;
    }>('/v1/system/users/auth', 'POST', { username, password }, 2500);

    if (localUserAuth && localUserAuth.success) {
      const role = localUserAuth.applianceRole;
      if (role === 'os_only') {
        return { success: false, error: 'Local Linux user does not have Web Console administrative privileges' };
      }
      const roleDef = DEFAULT_ROLES[role];
      const privileges = roleDef ? Array.from(roleDef.privileges) : [];
      const session: UserSession = {
        userId: `local:${username}`,
        username,
        displayName: username,
        source: 'local',
        roles: [role],
        privileges,
        exp: Math.floor(Date.now() / 1000) + 8 * 3600,
      };
      stampSessionEpoch(session);
      return { success: true, session };
    }
  } catch {
    // Daemon auth check failed or timed out, continue to LDAP fallback
  }

  const isLdapEnabled =
    process.env.LDAP_ENABLED === 'true' ||
    (process.env.LDAP_URL ? !process.env.LDAP_URL.includes('127.0.0.1:389') : false);

  if (isLdapEnabled) {
    if (!LDAP_CONFIG.bindPassword) {
      return { success: false, error: 'LDAP is enabled but LDAP_BIND_PASSWORD is not configured on this appliance' };
    }
    try {
      const ldapRes = await authenticateLdap(LDAP_CONFIG, username, password);
      if (ldapRes.session) stampSessionEpoch(ldapRes.session);
      return ldapRes;
    } catch (err: any) {
      return { success: false, error: `LDAP authentication failed: ${err.message}` };
    }
  }

  return { success: false, error: 'Invalid username or password' };
}
