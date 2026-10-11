import { NextRequest, NextResponse } from 'next/server';
import { mintSupabaseToken } from '@axonwall/lib/ldap';
import { DEFAULT_ROLES } from '@axonwall/lib/rbac';
import type { UserSession } from '@axonwall/lib/rbac';

const SESSION_COOKIE = 'axonwall_session';

function getJwtSecret(): string {
  return process.env.JWT_SECRET || 'super-secret-axonwall-jwt-signing-key-32-bytes!';
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');
  const userParam = searchParams.get('user') || 'sso-admin@enterprise.corp';
  const groupParam = searchParams.get('group') || 'Axonwall-Admins';

  if (!code) {
    return NextResponse.redirect(new URL('/login?error=Missing+authorization+code', request.url));
  }

  // Map IdP group claim to Axonwall RBAC role
  let role: 'admin' | 'operator' | 'readonly' = 'readonly';
  if (groupParam.toLowerCase().includes('admin')) {
    role = 'admin';
  } else if (groupParam.toLowerCase().includes('operator') || groupParam.toLowerCase().includes('noc')) {
    role = 'operator';
  }

  const roleObj = DEFAULT_ROLES[role];
  const username = userParam.split('@')[0];

  const session: UserSession = {
    userId: `sso-${username}`,
    username,
    displayName: `${username} (SSO)`,
    email: userParam,
    source: 'sso_oidc' as any,
    roles: [role],
    privileges: [...roleObj.privileges],
    exp: Math.floor(Date.now() / 1000) + 8 * 3600, // 8 hours
  };

  const token = await mintSupabaseToken(session, getJwtSecret());

  const response = NextResponse.redirect(new URL('/lobby', request.url));
  response.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 8 * 3600,
  });

  return response;
}
