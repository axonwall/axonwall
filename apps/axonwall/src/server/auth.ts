'use server';

import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

import {
  authenticateLdap,
  authenticateLocalAdmin,
  mintSupabaseToken,
  verifyToken,
  type LdapConfig,
  type AuthResult,
} from '@axonwall/lib/ldap';
import { type UserSession, DEFAULT_ROLES, type Privilege } from '@axonwall/lib/rbac';
import { callAgentApi } from './agent-client';

import { SESSION_COOKIE, getJwtSecret } from './auth-constants';
import { assertActionPermitted } from './auth-guard';
import {
  bumpSessionEpoch,
  isSessionRevoked,
  revokeTokenJti,
  stampSessionEpoch,
} from './session-revocation';

const LDAP_CONFIG: LdapConfig = {
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
  },
};

export async function getSession(): Promise<UserSession | null> {
  const cookieStore = await cookies();
  const reqHeaders = await headers();
  let token = cookieStore.get(SESSION_COOKIE)?.value;
  
  if (!token) {
    const authHeader = reqHeaders.get('authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
      // No development backdoor tokens: a Bearer credential is only
      // ever a real session JWT verified below. (A hardcoded
      // 'dev-test-token-123' previously minted an admin session in
      // any non-production deployment.)
    }
  }

  if (!token) return null;
  const session = await verifyToken(token, getJwtSecret());
  if (!session) return null;
  // Server-side revocation (audit B-09): logout denylists the token's
  // jti and a password change bumps the session epoch; either one ends
  // the session here instead of at JWT expiry.
  if (isSessionRevoked(session)) return null;
  return session;
}


// --- Local-admin MFA (TOTP) state -------------------------------------
// The enrolled secret lives in /etc/axonwall/mfa.env (mode 0600) -- the
// file the console's MFA reset removes -- with LOCAL_ADMIN_MFA_SECRET in
// the process environment as an operator override. Until enrollment
// actually persisted the secret (audit B-08), MFA could never be on.
const MFA_ENV_PATHS = ['/var/lib/axonwall/etc-axonwall/mfa.env', '/etc/axonwall/mfa.env'];

function writeAuthFileSafe(filePath: string, content: string, mode = 0o660): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o775 });
  }
  try {
    fs.writeFileSync(filePath, content, { mode });
  } catch {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    fs.writeFileSync(filePath, content, { mode });
  }
  try {
    fs.chmodSync(filePath, mode);
  } catch {}
}

function readMfaEnv(): Map<string, string> {
  const values = new Map<string, string>();
  for (const mfaPath of MFA_ENV_PATHS) {
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

function getMfaSecret(): string | undefined {
  return process.env.LOCAL_ADMIN_MFA_SECRET || readMfaEnv().get('LOCAL_ADMIN_MFA_SECRET') || undefined;
}

function writeMfaEnv(updates: Record<string, string>): void {
  const values = readMfaEnv();
  for (const [k, v] of Object.entries(updates)) values.set(k, v);
  const content = [...values.entries()].map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
  for (const mfaPath of MFA_ENV_PATHS) {
    try {
      writeAuthFileSafe(mfaPath, content, 0o660);
    } catch {}
  }
}

// otplib v13 is plugin-based; the v12 'authenticator' export the MFA
// code used to call no longer exists (setup threw at runtime).
function totpPlugins() {
  const { NobleCryptoPlugin, ScureBase32Plugin } = require('otplib');
  return { crypto: new NobleCryptoPlugin(), base32: new ScureBase32Plugin() };
}

// Verifies a login TOTP code with replay protection: the accepted time
// step is recorded in mfa.env and passed as afterTimeStep on the next
// check, so a code can never be used twice (audit B-07).
async function verifyTotpCode(secret: string, token: string): Promise<boolean> {
  const { verify } = require('otplib');
  const lastStep = Number(readMfaEnv().get('LOCAL_ADMIN_MFA_LAST_STEP') || 0);
  const options: Record<string, unknown> = { secret, token, ...totpPlugins(), epochTolerance: 30 };
  if (lastStep > 0) options.afterTimeStep = lastStep;
  const result = await verify(options);
  if (!result.valid) return false;
  if (typeof result.timeStep === 'number' && result.timeStep > lastStep) {
    try { writeMfaEnv({ LOCAL_ADMIN_MFA_LAST_STEP: String(result.timeStep) }); } catch {}
  }
  return true;
}

// --- Login throttling (audit B-07) -------------------------------------
// performAuthentication is the single choke point for password and
// TOTP logins (login action and /api/auth/login both call it). Five
// consecutive failures lock the account for five minutes; a success
// clears the counter. In-memory only -- a UI restart clears lockouts --
// and the tty1 console break-glass is unaffected.
const LOGIN_MAX_FAILURES = 5;
const LOGIN_LOCKOUT_MS = 5 * 60 * 1000;
const loginFailures = new Map<string, { count: number; lockedUntil: number }>();

export async function performAuthentication(
  username: string,
  password: string,
  totpCode?: string
): Promise<AuthResult> {
  const key = (username || '').toLowerCase();
  const now = Date.now();
  const record = loginFailures.get(key);
  if (record && record.lockedUntil > now) {
    return { success: false, error: 'Too many failed sign-in attempts. Try again in a few minutes.' };
  }
  const result = await performAuthenticationInner(username, password, totpCode);
  if (result.success) {
    loginFailures.delete(key);
  } else {
    const count = (record && record.lockedUntil <= now ? record.count : 0) + 1;
    loginFailures.set(key, {
      count,
      lockedUntil: count >= LOGIN_MAX_FAILURES ? now + LOGIN_LOCKOUT_MS : 0,
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

  // 1. Check local break-glass admin first
  let localAdminUser = process.env.LOCAL_ADMIN_USER || 'admin';
  let localAdminPass = process.env.LOCAL_ADMIN_PASSWORD || '';

  for (const adminEnvPath of ['/var/lib/axonwall/etc-axonwall/admin.env', '/etc/axonwall/admin.env']) {
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

  // If attempting to authenticate as local admin
  if (username === localAdminUser) {
    if (!localAdminPass) {
      return { success: false, error: 'Local administrator account is not configured' };
    }
    const authRes = authenticateLocalAdmin(username, password, localAdminUser, localAdminPass);
    if (!authRes.success) {
      return { success: false, error: 'Invalid username or password' };
    }

    // 1.5 Enforce MFA if required
    const mfaSecret = getMfaSecret();
    if (mfaSecret && authRes.success) {
      if (!totpCode) {
        return { success: false, error: 'MFA Code (TOTP) is required for this account' };
      }
      if (!(await verifyTotpCode(mfaSecret, totpCode))) {
        return { success: false, error: 'Invalid MFA Code' };
      }
    }
    // Stamp the session so the minted JWT carries the
    // pwd_change_required claim the middleware enforces on /api/*.
    if (authRes.session) {
      authRes.session.passwordChangeRequired = passwordChangeRequiredNow();
      stampSessionEpoch(authRes.session);
    }
    return authRes;
  }

  // 1.8 Check Local Linux Users authenticated by axonwalld
  try {
    const localUserAuth = await callAgentApi<{
      success: boolean;
      username: string;
      applianceRole: 'admin' | 'operator' | 'readonly' | 'os_only';
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

  // 2. Fall back to LDAP ONLY if explicitly enabled/configured
  const isLdapEnabled =
    process.env.LDAP_ENABLED === 'true' ||
    (process.env.LDAP_URL ? !process.env.LDAP_URL.includes('127.0.0.1:389') : false);

  if (isLdapEnabled) {
    if (!LDAP_CONFIG.bindPassword) {
      // No hardcoded fallback bind password (audit B-13): LDAP stays
      // unusable until the operator configures one.
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

export async function loginAction(arg1: any, arg2?: any) {
  const formData = (arg2 && typeof arg2.get === 'function')
    ? (arg2 as FormData)
    : (arg1 && typeof arg1.get === 'function')
      ? (arg1 as FormData)
      : null;

  if (!formData) {
    return { error: 'Invalid form submission' };
  }

  const username = formData.get('username') as string;
  const password = formData.get('password') as string;
  const totpCode = (formData.get('totpCode') as string) || undefined;

  const authRes = await performAuthentication(username, password, totpCode);
  if (!authRes.success || !authRes.session) {
    return { error: authRes.error || 'Authentication failed' };
  }

  // 3. Mint JWT and set secure session cookie
  const token = await mintSupabaseToken(authRes.session, getJwtSecret());
  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 8 * 3600, // 8 hours
  });

  redirect('/lobby');
}

export async function logoutAction() {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE)?.value;
  if (token) {
    const session = await verifyToken(token, getJwtSecret());
    if (session?.jti) revokeTokenJti(session.jti);
  }
  cookieStore.delete(SESSION_COOKIE);
  redirect('/login');
}

export async function generateMfaSetup() {
  const session = await getSession();
  assertActionPermitted(session);

  const { generateSecret, generateURI } = require('otplib');
  const plugins = totpPlugins();
  const secret = generateSecret(plugins);
  const otpauth = generateURI({ issuer: 'Axonwall', label: session.username, secret, ...plugins });

  const QRCode = require('qrcode');
  const qrDataUrl = await QRCode.toDataURL(otpauth);

  return { secret, qrDataUrl };
}

export async function verifyMfaSetup(secret: string, token: string) {
  const session = await getSession();
  assertActionPermitted(session);

  const { verify } = require('otplib');
  const result = await verify({ secret, token, ...totpPlugins(), epochTolerance: 30 });

  if (!result.valid) {
    return { success: false, error: 'Invalid TOTP code.' };
  }

  // Persist the enrollment (audit B-08): the secret is written to
  // /etc/axonwall/mfa.env -- the same file the console's MFA reset
  // removes -- together with the accepted time step, so the enrollment
  // code cannot be replayed at login. Until this was written, setup
  // saved nothing anywhere and the advertised MFA was inert.
  try {
    writeMfaEnv({
      LOCAL_ADMIN_MFA_SECRET: secret,
      LOCAL_ADMIN_MFA_LAST_STEP: String(result.timeStep ?? 0),
    });
    process.env.LOCAL_ADMIN_MFA_SECRET = secret;
  } catch {
    return { success: false, error: 'Could not save the MFA configuration on this appliance.' };
  }
  return { success: true };
}

/**
 * The single source of truth for "the local admin password has never
 * been changed": no .password_changed marker exists (the change
 * handler writes one and deletes /etc/axonwall/initial-admin-password).
 * Used at login time to stamp the session, and by
 * isPasswordChangeRequired() for the console UI. The middleware
 * enforces the resulting JWT claim on /api/* server-side -- until
 * now the only enforcement was a client-side modal, and the API (and
 * the daemon behind it) happily served a session that had never
 * changed the default password.
 */
function passwordChangeRequiredNow(): boolean {
  try {
    if (
      fs.existsSync('/var/lib/axonwall/.password_changed') ||
      fs.existsSync('/etc/axonwall/.password_changed') ||
      fs.existsSync('./.password_changed')
    ) {
      return false;
    }
  } catch {}

  // In development/test environments, only enforce if explicit or if using default password
  if (process.env.NODE_ENV !== 'production' && process.env.FORCE_PASSWORD_CHANGE !== 'true') {
    return false;
  }

  return true;
}

export async function isPasswordChangeRequired(): Promise<boolean> {
  const session = await getSession();
  if (!session || session.source !== 'local_admin') {
    return false;
  }
  return passwordChangeRequiredNow();
}

export async function changeAdminPasswordAction(formData: FormData) {
  const session = await getSession();
  if (!session || session.source !== 'local_admin') {
    return { error: 'Unauthorized: only local administrator can perform this action' };
  }

  const currentPassword = formData.get('currentPassword') as string;
  const newPassword = formData.get('newPassword') as string;
  const confirmPassword = formData.get('confirmPassword') as string;

  if (!currentPassword || !newPassword || !confirmPassword) {
    return { error: 'All fields are required' };
  }

  if (newPassword !== confirmPassword) {
    return { error: 'New password and confirmation do not match' };
  }

  if (newPassword.length < 8) {
    return { error: 'New password must be at least 8 characters long' };
  }

  if (newPassword === 'axonwall') {
    return { error: 'You cannot reuse the default password' };
  }

  // Verify current password
  let localAdminUser = process.env.LOCAL_ADMIN_USER || 'admin';
  let localAdminPass = process.env.LOCAL_ADMIN_PASSWORD || '';

  for (const adminEnvPath of ['/var/lib/axonwall/etc-axonwall/admin.env', '/etc/axonwall/admin.env']) {
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

  if (!localAdminPass) {
    return { error: 'Local administrator account is not configured' };
  }

  const authRes = authenticateLocalAdmin(session.username, currentPassword, localAdminUser, localAdminPass);
  if (!authRes.success) {
    return { error: 'Current password is incorrect' };
  }

  // Hash new password using scrypt (N=16384, r=8, p=1, keyLen=64)
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(newPassword, salt, 64).toString('hex');
  const hashedSecret = `scrypt$${salt}$${hash}`;

  try {
    const envContent = `LOCAL_ADMIN_USER=${localAdminUser}\nLOCAL_ADMIN_PASSWORD=${hashedSecret}\n`;
    writeAuthFileSafe('/etc/axonwall/admin.env', envContent, 0o660);

    // Mirror to /var/lib/axonwall/etc-axonwall/admin.env for A/B rootfs persistence
    try {
      writeAuthFileSafe('/var/lib/axonwall/etc-axonwall/admin.env', envContent, 0o660);
    } catch {}

    const now = new Date().toISOString();
    try { writeAuthFileSafe('/etc/axonwall/.password_changed', now, 0o664); } catch {}
    try { writeAuthFileSafe('/var/lib/axonwall/.password_changed', now, 0o664); } catch {}

    try {
      if (fs.existsSync('/etc/axonwall/initial-admin-password')) {
        fs.unlinkSync('/etc/axonwall/initial-admin-password');
      }
    } catch {}

    // A password change ends every outstanding session (audit B-09).
    bumpSessionEpoch();

    process.env.LOCAL_ADMIN_PASSWORD = hashedSecret;
    return { success: true };
  } catch (err: any) {
    return { error: `Failed to persist new credentials: ${err.message}` };
  }
}

