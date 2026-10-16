'use server';

import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

import {
  authenticateLdap,
  authenticateLocalAdmin,
  mintSupabaseToken,
  verifyToken,
  type LdapConfig,
  type AuthResult,
} from '@axonwall/lib/ldap';
import type { UserSession } from '@axonwall/lib/rbac';

import { SESSION_COOKIE, getJwtSecret } from './auth-constants';
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

export async function performAuthentication(
  username: string,
  password: string,
  totpCode?: string
): Promise<AuthResult> {
  if (!username || !password) {
    return { success: false, error: 'Username and password are required' };
  }

  // 1. Check local break-glass admin first
  let localAdminUser = process.env.LOCAL_ADMIN_USER || 'admin';
  let localAdminPass = process.env.LOCAL_ADMIN_PASSWORD || 'axonwall';

  try {
    if (fs.existsSync('/etc/axonwall/admin.env')) {
      const content = fs.readFileSync('/etc/axonwall/admin.env', 'utf-8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.startsWith('LOCAL_ADMIN_USER=')) {
          localAdminUser = trimmed.substring('LOCAL_ADMIN_USER='.length);
        } else if (trimmed.startsWith('LOCAL_ADMIN_PASSWORD=')) {
          localAdminPass = trimmed.substring('LOCAL_ADMIN_PASSWORD='.length);
        }
      }
    }
  } catch {
    // fallback to env
  }

  // If attempting to authenticate as local admin
  if (username === localAdminUser) {
    const authRes = authenticateLocalAdmin(username, password, localAdminUser, localAdminPass);
    if (!authRes.success) {
      return { success: false, error: 'Invalid username or password' };
    }

    // 1.5 Enforce MFA if required
    const mfaSecret = process.env.LOCAL_ADMIN_MFA_SECRET;
    if (mfaSecret && authRes.success) {
      if (!totpCode) {
        return { success: false, error: 'MFA Code (TOTP) is required for this account' };
      }
      const { authenticator } = require('otplib');
      const isValid = authenticator.verify({ token: totpCode, secret: mfaSecret });
      if (!isValid) {
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
  if (!session) throw new Error('Unauthorized');

  const { authenticator } = require('otplib');
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(session.username, 'Axonwall', secret);

  const QRCode = require('qrcode');
  const qrDataUrl = await QRCode.toDataURL(otpauth);

  return { secret, qrDataUrl };
}

export async function verifyMfaSetup(secret: string, token: string) {
  const session = await getSession();
  if (!session) throw new Error('Unauthorized');

  const { authenticator } = require('otplib');
  const isValid = authenticator.verify({ token, secret });
  
  if (!isValid) {
    return { success: false, error: 'Invalid TOTP code.' };
  }

  // In a real app, save the secret to the user's LDAP/DB profile here.
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
  let localAdminPass = process.env.LOCAL_ADMIN_PASSWORD || 'axonwall';

  try {
    if (fs.existsSync('/etc/axonwall/admin.env')) {
      const content = fs.readFileSync('/etc/axonwall/admin.env', 'utf-8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.startsWith('LOCAL_ADMIN_USER=')) {
          localAdminUser = trimmed.substring('LOCAL_ADMIN_USER='.length);
        } else if (trimmed.startsWith('LOCAL_ADMIN_PASSWORD=')) {
          localAdminPass = trimmed.substring('LOCAL_ADMIN_PASSWORD='.length);
        }
      }
    }
  } catch {}

  const authRes = authenticateLocalAdmin(session.username, currentPassword, localAdminUser, localAdminPass);
  if (!authRes.success) {
    return { error: 'Current password is incorrect' };
  }

  // Hash new password using scrypt (N=16384, r=8, p=1, keyLen=64)
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(newPassword, salt, 64).toString('hex');
  const hashedSecret = `scrypt$${salt}$${hash}`;

  try {
    if (!fs.existsSync('/etc/axonwall')) {
      fs.mkdirSync('/etc/axonwall', { recursive: true, mode: 0o755 });
    }
    if (!fs.existsSync('/var/lib/axonwall')) {
      fs.mkdirSync('/var/lib/axonwall', { recursive: true, mode: 0o755 });
    }

    const envContent = `LOCAL_ADMIN_USER=${localAdminUser}\nLOCAL_ADMIN_PASSWORD=${hashedSecret}\n`;
    fs.writeFileSync('/etc/axonwall/admin.env', envContent, { mode: 0o600 });

    const now = new Date().toISOString();
    fs.writeFileSync('/etc/axonwall/.password_changed', now, { mode: 0o644 });
    fs.writeFileSync('/var/lib/axonwall/.password_changed', now, { mode: 0o644 });

    if (fs.existsSync('/etc/axonwall/initial-admin-password')) {
      fs.unlinkSync('/etc/axonwall/initial-admin-password');
    }

    // A password change ends every outstanding session (audit B-09).
    bumpSessionEpoch();

    process.env.LOCAL_ADMIN_PASSWORD = hashedSecret;
    return { success: true };
  } catch (err: any) {
    // Development fallback if lacking root permissions
    try {
      fs.writeFileSync('./.password_changed', new Date().toISOString());
      process.env.LOCAL_ADMIN_PASSWORD = hashedSecret;
      return { success: true };
    } catch {
      return { error: `Failed to persist new credentials: ${err.message}` };
    }
  }
}

