import { NextRequest, NextResponse } from 'next/server';
import { timingSafeEqual } from 'crypto';
import { mintSupabaseToken } from '@axonwall/lib/ldap';
import { DEFAULT_ROLES } from '@axonwall/lib/rbac';
import type { UserSession } from '@axonwall/lib/rbac';
import { SESSION_COOKIE, getJwtSecret } from '../../../../../server/auth-constants';
import { isVpnPortalOnlyUser } from '../../../../../server/auth-guard';
import { stampSessionEpoch } from '../../../../../server/session-revocation';
import {
  OIDC_STATE_COOKIE,
  discoverOidc,
  exchangeCodeForIdentity,
  getOidcConfig,
  resolveOidcRedirectUri,
  resolvePublicOrigin,
  roleFromGroups,
} from '../../../../../server/oidc';

function fail(publicOrigin: string, message: string) {
  const response = NextResponse.redirect(
    new URL(`/login?error=${encodeURIComponent(message)}`, publicOrigin)
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
  const cfg = await getOidcConfig();
  const publicOrigin = resolvePublicOrigin(
    request.headers,
    request.nextUrl.origin,
    cfg?.redirectUri
  );
  if (!cfg) {
    return fail(publicOrigin, 'SSO is not configured');
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
    return fail(publicOrigin, 'Invalid SSO callback');
  }
  const cookieParts = cookieValue.split('.');
  const expectedState = cookieParts[0];
  const expectedNonce = cookieParts[1];
  if (cookieParts.length !== 2 || !expectedState || !expectedNonce || !safeEqual(state, expectedState)) {
    return fail(publicOrigin, 'Invalid SSO state');
  }

  try {
    const discovery = await discoverOidc(cfg);
    const redirectUri = resolveOidcRedirectUri(publicOrigin, cfg.redirectUri);
    const claims = await exchangeCodeForIdentity(
      cfg,
      discovery,
      code,
      redirectUri,
      expectedNonce
    );

    const verifiedEmail =
      claims.email_verified !== false && typeof claims.email === 'string' && claims.email
        ? claims.email.trim()
        : '';
    const email =
      verifiedEmail ||
      (typeof claims.preferred_username === 'string' && claims.preferred_username.trim()) ||
      '';
    let username =
      verifiedEmail ||
      (typeof claims.preferred_username === 'string' && claims.preferred_username.trim()) ||
      (typeof claims.sub === 'string' && claims.sub ? `oidc:${claims.sub}` : 'oidc:sso-user');
    if (username.toLowerCase() === 'admin' || username.toLowerCase() === 'root') {
      username = `oidc:${username}`;
    }

    // Map the verified IdP group claim to an Axonwall RBAC role
    const claimKey = cfg.groupClaim || 'groups';
    const rawGroups = (claims as Record<string, unknown>)[claimKey] ?? claims.groups;
    const role = roleFromGroups(rawGroups, cfg.roleMappings);
    if (!role) {
      return fail(publicOrigin, 'Your SSO account is not authorized for any Axonwall role');
    }
    const roleObj = DEFAULT_ROLES[role];

    const session: UserSession = {
      userId: `sso-${claims.sub}`,
      username,
      displayName:
        (typeof claims.name === 'string' && claims.name) || `${username} (SSO)`,
      email,
      source: 'oidc',
      roles: [role],
      privileges: [...roleObj.privileges],
      exp: Math.floor(Date.now() / 1000) + 8 * 3600, // 8 hours
    };

    stampSessionEpoch(session);
    const token = await mintSupabaseToken(session, getJwtSecret());

    const targetPath = isVpnPortalOnlyUser(session) ? '/vpn' : '/lobby';
    const response = NextResponse.redirect(new URL(targetPath, publicOrigin));
    response.cookies.set(SESSION_COOKIE, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production' && process.env.AXONWALL_INSECURE_HTTP !== '1',
      sameSite: 'lax',
      path: '/',
      maxAge: 8 * 3600,
    });
    response.cookies.set(OIDC_STATE_COOKIE, '', { path: '/api/auth', maxAge: 0 });

    return response;
  } catch {
    return fail(publicOrigin, 'SSO sign-in failed');
  }
}
