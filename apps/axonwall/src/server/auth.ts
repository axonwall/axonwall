'use server';

import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

import {
  authenticateLocalAdmin,
  mintSupabaseToken,
  verifyToken,
} from '@axonwall/lib/ldap';
import { DEFAULT_ROLES, type UserSession } from '@axonwall/lib/rbac';
import {
  getEtcConfigDir,
  getPersistConfigDir,
  getStateDir,
} from './dev-paths';

import { SESSION_COOKIE, getJwtSecret } from './auth-constants';
import { assertActionPermitted, isVpnPortalOnlyUser, passwordChangeRequiredNow } from './auth-guard';
import {
  performAuthentication,
  totpPlugins,
  writeAuthFileSafe,
  writeMfaEnv,
} from './auth-internal';
import { verifyServiceToken } from './service-tokens';
import {
  bumpSessionEpoch,
  isSessionRevoked,
  revokeTokenJti,
  stampSessionEpoch,
} from './session-revocation';

export async function getSession(): Promise<UserSession | null> {
  const cookieStore = await cookies();
  const reqHeaders = await headers();
  let token = cookieStore.get(SESSION_COOKIE)?.value;

  if (!token) {
    const authHeader = reqHeaders.get('authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7).trim();
    }
  }

  if (!token) return null;

  if (token.startsWith('axw_svc_')) {
    const rec = verifyServiceToken(token);
    if (!rec) return null;
    const roleDef = DEFAULT_ROLES[rec.role];
    const scopes = Array.isArray(rec.scopes) ? rec.scopes : [];
    const rolePrivileges = roleDef ? Array.from(roleDef.privileges) : [];
    const privileges = scopes.includes('*')
      ? rolePrivileges
      : rolePrivileges.filter((p) => p !== '*');
    const exp = rec.expiresAt
      ? Math.floor(Date.parse(rec.expiresAt) / 1000)
      : Math.floor(Date.now() / 1000) + 3600;
    return {
      userId: `svc:${rec.id}`,
      username: `svc:${rec.name}`,
      source: 'service_token',
      roles: [rec.role],
      privileges,
      exp,
      tokenId: rec.id,
      scopes,
    };
  }

  const session = await verifyToken(token, getJwtSecret());
  if (!session) return null;
  // Server-side revocation (audit B-09): logout denylists the token's
  // jti and a password change bumps the session epoch; either one ends
  // the session here instead of at JWT expiry.
  if (isSessionRevoked(session)) return null;
  return session;
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
    secure: process.env.NODE_ENV === 'production' && process.env.AXONWALL_INSECURE_HTTP !== '1',
    sameSite: 'lax',
    path: '/',
    maxAge: 8 * 3600, // 8 hours
  });

  redirect(isVpnPortalOnlyUser(authRes.session) ? '/vpn' : '/lobby');
}

export async function logoutAction() {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE)?.value;
  if (token) {
    const session = await verifyToken(token, getJwtSecret());
    if (session?.jti) revokeTokenJti(session.jti, session.exp);
  }
  cookieStore.delete(SESSION_COOKIE);
  redirect('/login');
}

// D17: pending MFA enrollments are keyed per user (Map<username, ...>),
// not a single process-global slot. A second admin's Setup must not
// overwrite the first admin's pending secret, and a restart between
// Setup and Verify must fail closed instead of silently falling back to
// trusting whatever secret the client supplies.
const pendingMfaEnrollments = new Map<string, { secret: string; expiresAt: number }>();

export async function generateMfaSetup() {
  const session = await getSession();
  assertActionPermitted(session);
  if (session.source !== 'local_admin') {
    return { exempt: true as const, secret: '', qrDataUrl: '' };
  }
  assertActionPermitted(session, 'admin');

  const { generateSecret, generateURI } = require('otplib');
  const plugins = totpPlugins();
  const secret = generateSecret(plugins);
  // D17: store this admin's pending secret under their own username so a
  // concurrent enrollment by another admin cannot overwrite it. Drop
  // expired entries opportunistically so the map cannot grow unboundedly.
  for (const [user, entry] of pendingMfaEnrollments) {
    if (entry.expiresAt <= Date.now()) pendingMfaEnrollments.delete(user);
  }
  pendingMfaEnrollments.set(session.username, { secret, expiresAt: Date.now() + 10 * 60 * 1000 });
  const otpauth = generateURI({ issuer: 'Axonwall', label: session.username, secret, ...plugins });

  const QRCode = require('qrcode');
  const qrDataUrl = await QRCode.toDataURL(otpauth);

  return { secret, qrDataUrl };
}

export async function verifyMfaSetup(secret: string, token: string) {
  const session = await getSession();
  assertActionPermitted(session, 'admin');
  if (session.source !== 'local_admin') {
    throw new Error('Forbidden: Only the local break-glass administrator can configure local MFA');
  }

  // D17: fail closed when this user has no live pending enrollment for
  // the secret they present. There is no fallback to the client-supplied
  // secret: after a restart (or expiry) the server holds no proof that
  // the secret was ever displayed to this user as a QR code, so Verify
  // must refuse instead of accepting any self-chosen secret whose TOTP
  // happens to check out.
  const pending = pendingMfaEnrollments.get(session.username);
  if (!pending || pending.expiresAt <= Date.now()) {
    if (pending) pendingMfaEnrollments.delete(session.username);
    return { success: false, error: 'MFA setup session expired or secret mismatch. Please generate a new QR code.' };
  }
  if (pending.secret !== secret) {
    return { success: false, error: 'MFA setup session expired or secret mismatch. Please generate a new QR code.' };
  }
  const enrolledSecret = pending.secret;

  const { verify } = require('otplib');
  const result = await verify({ secret: enrolledSecret, token, ...totpPlugins(), epochTolerance: 30 });

  if (!result.valid) {
    return { success: false, error: 'Invalid TOTP code.' };
  }

  pendingMfaEnrollments.delete(session.username);

  // Persist the enrollment (audit B-08): the secret is written to
  // /etc/axonwall/mfa.env -- the same file the console's MFA reset
  // removes -- together with the accepted time step, so the enrollment
  // code cannot be replayed at login. Until this was written, setup
  // saved nothing anywhere and the advertised MFA was inert.
  try {
    writeMfaEnv({
      LOCAL_ADMIN_MFA_SECRET: enrolledSecret,
      LOCAL_ADMIN_MFA_LAST_STEP: String(result.timeStep ?? 0),
    });
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
    let savedAdminEnv = false;
    for (const target of Array.from(
      new Set([path.join(getEtcConfigDir(), 'admin.env'), path.join(getPersistConfigDir(), 'admin.env')])
    )) {
      try {
        writeAuthFileSafe(target, envContent, 0o600);
        savedAdminEnv = true;
      } catch {}
    }

    if (!savedAdminEnv) {
      throw new Error('Unable to write admin.env to configured axonwall directory');
    }
    process.env.LOCAL_ADMIN_PASSWORD = hashedSecret;

    const now = new Date().toISOString();
    try { writeAuthFileSafe(path.join(getEtcConfigDir(), '.password_changed'), now, 0o664); } catch {}
    try { writeAuthFileSafe(path.join(getStateDir(), '.password_changed'), now, 0o664); } catch {}

    try {
      const initPw = path.join(getEtcConfigDir(), 'initial-admin-password');
      if (fs.existsSync(initPw)) {
        fs.unlinkSync(initPw);
      }
    } catch {}

    // A password change ends every outstanding session (audit B-09).
    bumpSessionEpoch();

    // Mint a fresh session cookie for the caller with updated epoch and passwordChangeRequired=false
    try {
      const freshSession = { ...session, passwordChangeRequired: false };
      stampSessionEpoch(freshSession);
      const freshToken = await mintSupabaseToken(freshSession, getJwtSecret());
      const cookieStore = await cookies();
      cookieStore.set(SESSION_COOKIE, freshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production' && process.env.AXONWALL_INSECURE_HTTP !== '1',
        sameSite: 'lax',
        maxAge: 8 * 3600,
        path: '/',
      });
    } catch {}

    process.env.LOCAL_ADMIN_PASSWORD = hashedSecret;
    return { success: true };
  } catch (err: any) {
    return { error: `Failed to persist new credentials: ${err.message}` };
  }
}

