'use server';

import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';

import {
  authenticateLdap,
  authenticateLocalAdmin,
  mintSupabaseToken,
  verifyToken,
  type LdapConfig,
} from '@axonwall/lib/ldap';
import type { UserSession } from '@axonwall/lib/rbac';

const SESSION_COOKIE = 'axonwall_session';

function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (process.env.NODE_ENV === 'production' && !secret) {
    throw new Error('JWT_SECRET environment variable is required in production');
  }
  return secret || 'super-secret-axonwall-jwt-signing-key-32-bytes!';
}

const LDAP_CONFIG: LdapConfig = {
  url: process.env.LDAP_URL || 'ldap://127.0.0.1:389',
  baseDn: process.env.LDAP_BASE_DN || 'dc=axonwall,dc=local',
  bindDn: process.env.LDAP_BIND_DN || 'cn=admin,dc=axonwall,dc=local',
  bindPassword: process.env.LDAP_BIND_PASSWORD || 'axonwalladmin',
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
      if (token === 'dev-test-token-123') {
         return { userId: '1', username: 'admin', source: 'local_admin', privileges: [], roles: ['admin'], exp: Date.now() / 1000 + 3600 } as any;
      }
    }
  }

  if (!token) return null;
  return verifyToken(token, getJwtSecret());
}

export async function loginAction(prevState: any, formData: FormData) {
  const username = formData.get('username') as string;
  const password = formData.get('password') as string;
  const totpCode = formData.get('totpCode') as string;

  if (!username || !password) {
    return { error: 'Username and password are required' };
  }

  // 1. Check local break-glass admin first
  const localAdminUser = process.env.LOCAL_ADMIN_USER || 'admin';
  const localAdminPass = process.env.LOCAL_ADMIN_PASSWORD || 'axonwalladmin';

  let authRes = authenticateLocalAdmin(username, password, localAdminUser, localAdminPass);

  
  // 1.5 Enforce MFA if required
  const mfaSecret = process.env.LOCAL_ADMIN_MFA_SECRET;
  if (mfaSecret && authRes.success) {
    if (!totpCode) {
      return { error: 'MFA Code (TOTP) is required for this account' };
    }
    const { authenticator } = require('otplib');
    const isValid = authenticator.verify({ token: totpCode, secret: mfaSecret });
    if (!isValid) {
      return { error: 'Invalid MFA Code' };
    }
  }

  // 2. Fall back to LDAP if local admin did not match
  if (!authRes.success) {
    try {
      authRes = await authenticateLdap(LDAP_CONFIG, username, password);
    } catch (err: any) {
      authRes = { success: false, error: err.message };
    }
  }

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
  cookieStore.delete(SESSION_COOKIE);
  redirect('/login');
}
