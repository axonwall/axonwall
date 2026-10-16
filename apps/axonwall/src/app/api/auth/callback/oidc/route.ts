import { NextRequest, NextResponse } from 'next/server';
import { timingSafeEqual } from 'crypto';
import { mintSupabaseToken } from '@axonwall/lib/ldap';
import { DEFAULT_ROLES } from '@axonwall/lib/rbac';
import type { UserSession } from '@axonwall/lib/rbac';
import { SESSION_COOKIE, getJwtSecret } from '../../../../../server/auth-constants';
import { stampSessionEpoch } from '../../../../../server/session-revocation';
import {
  OIDC_STATE_COOKIE,
  discoverOidc,
  exchangeCodeForIdentity,
  getOidcConfig,
  roleFromGroups,
} from '../../../../../server/oidc';

function fail(request: NextRequest, message: string) {
  const response = NextResponse.redirect(
    new URL(`/login?error=${encodeURIComponent(message)}`, request.url)
  );
  response.cookies.set(OIDC_STATE_COOKIE, '', { path: '/api/auth', maxAge: 0 });
  return response;
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

export async function GET(request: NextRequest) {
  const cfg = getOidcConfig();
  if (!cfg) {
    return fail(request, 'SSO is not configured');
  }

  const { searchParams } = new URL(request.url);
  const code = searchParams.get('code');
  const state = searchParams.get('state');
  const cookieValue = request.cookies.get(OIDC_STATE_COOKIE)?.value;

  // The callback only ever completes a flow this browser started: the
  // state must match the httpOnly cookie set by /api/auth/sso/login.
  // Identity and role never come from query parameters -- they are read
  // from the provider-verified ID token below.
  if (!code || !state || !cookieValue) {
    return fail(request, 'Invalid SSO callback');
  }
  const [expectedState, expectedNonce] = cookieValue.split('.');
  if (!expectedState || !safeEqual(state, expectedState)) {
    return fail(request, 'Invalid SSO state');
  }

  try {
    const discovery = await discoverOidc(cfg);
    const redirectUri = `${request.nextUrl.origin}/api/auth/callback/oidc`;
    const claims = await exchangeCodeForIdentity(
      cfg,
      discovery,
      code,
      redirectUri,
      expectedNonce
    );

    const email =
      (typeof claims.email === 'string' && claims.email) ||
      (typeof claims.preferred_username === 'string' &&
        claims.preferred_username) ||
      '';
    const username =
      email.split('@')[0] ||
      (typeof claims.preferred_username === 'string' &&
        claims.preferred_username) ||
      claims.sub ||
      'sso-user';

    // Map the verified IdP group claim to an Axonwall RBAC role
    const role = roleFromGroups(claims.groups);
    const roleObj = DEFAULT_ROLES[role];

    const session: UserSession = {
      userId: `sso-${claims.sub}`,
      username,
      displayName:
        (typeof claims.name === 'string' && claims.name) || `${username} (SSO)`,
      email,
      source: 'sso_oidc' as any,
      roles: [role],
      privileges: [...roleObj.privileges],
      exp: Math.floor(Date.now() / 1000) + 8 * 3600, // 8 hours
    };

    stampSessionEpoch(session);
    const token = await mintSupabaseToken(session, getJwtSecret());

    const response = NextResponse.redirect(new URL('/lobby', request.url));
    response.cookies.set(SESSION_COOKIE, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 8 * 3600,
    });
    response.cookies.set(OIDC_STATE_COOKIE, '', { path: '/api/auth', maxAge: 0 });

    return response;
  } catch {
    return fail(request, 'SSO sign-in failed');
  }
}
