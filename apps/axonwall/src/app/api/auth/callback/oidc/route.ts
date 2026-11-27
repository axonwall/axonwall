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

function relativeRedirect(location: string): NextResponse {
  return new NextResponse(null, {
    status: 302,
    headers: { Location: location, 'Cache-Control': 'no-store' },
  });
}

function fail(code: string) {
  const response = relativeRedirect(`/login?error=${encodeURIComponent(code)}`);
  response.cookies.set(OIDC_STATE_COOKIE, '', { path: '/api/auth', maxAge: 0 });
  return response;
}

function safeFallbackOrigin(nextUrlOrigin: string): string {
  try {
    const u = new URL(nextUrlOrigin);
    const h = u.hostname.toLowerCase();
    if (h === 'localhost' || h === '127.0.0.1' || h === '[::1]') {
      return u.origin;
    }
  } catch {}
  return 'https://axonwall.local';
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
    safeFallbackOrigin(request.nextUrl.origin),
    cfg?.redirectUri
  );
  if (!cfg) {
    return fail('sso_not_configured');
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
    return fail('sso_invalid_callback');
  }
  const cookieParts = cookieValue.split('.');
  const expectedState = cookieParts[0];
  const expectedNonce = cookieParts[1];
  const codeVerifier = cookieParts[2];
  if (
    cookieParts.length !== 3 ||
    !expectedState ||
    !expectedNonce ||
    !codeVerifier ||
    !safeEqual(state, expectedState)
  ) {
    return fail('sso_invalid_state');
  }

  try {
    const discovery = await discoverOidc(cfg);
    const redirectUri = resolveOidcRedirectUri(publicOrigin, cfg.redirectUri);
    const claims = await exchangeCodeForIdentity(
      cfg,
      discovery,
      code,
      redirectUri,
      expectedNonce,
      codeVerifier
    );

    if (claims.email_verified !== true || typeof claims.email !== 'string' || !claims.email.trim()) {
      return fail('sso_email_unverified');
    }
    const email = claims.email.trim();
    const rawIdentity =
      email ||
      (typeof claims.preferred_username === 'string' && claims.preferred_username.trim()) ||
      (typeof claims.sub === 'string' && claims.sub.trim()) ||
      'sso-user';
    const username = rawIdentity.toLowerCase().startsWith('oidc:')
      ? rawIdentity
      : `oidc:${rawIdentity}`;

    // Map the verified IdP group claim to an Axonwall RBAC role
    const claimKey = cfg.groupClaim || 'groups';
    const rawGroups = (claims as Record<string, unknown>)[claimKey] ?? claims.groups;
    const role = roleFromGroups(rawGroups, cfg.roleMappings);
    if (!role) {
      return fail('sso_unauthorized');
    }
    const roleObj = DEFAULT_ROLES[role];

    const session: UserSession = {
      userId: `oidc:${claims.sub}`,
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
    const response = relativeRedirect(targetPath);
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
    return fail('sso_failed');
  }
}
