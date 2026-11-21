import { NextRequest, NextResponse } from 'next/server';
import {
  OIDC_STATE_COOKIE,
  discoverOidc,
  getOidcConfig,
  randomToken,
  resolveOidcRedirectUri,
  resolvePublicOrigin,
} from '../../../../../server/oidc';

export async function GET(request: NextRequest) {
  const cfg = await getOidcConfig();
  const publicOrigin = resolvePublicOrigin(
    request.headers,
    request.nextUrl.origin,
    cfg?.redirectUri
  );

  // No simulation mode: if no live OIDC provider is configured, SSO is
  // simply unavailable. (Previously this redirected into the callback
  // with a simulated admin identity, which minted a real admin session
  // for anyone who could reach the login page.)
  if (!cfg) {
    return NextResponse.redirect(
      new URL('/login?error=SSO+is+not+configured', publicOrigin)
    );
  }

  try {
    const discovery = await discoverOidc(cfg);
    const state = randomToken();
    const nonce = randomToken();
    const redirectUri = resolveOidcRedirectUri(publicOrigin, cfg.redirectUri);

    const authUrl = new URL(discovery.authorization_endpoint);
    authUrl.searchParams.set('client_id', cfg.clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set(
      'scope',
      cfg.scopes && cfg.scopes.length > 0 ? cfg.scopes.join(' ') : 'openid profile email groups'
    );
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('nonce', nonce);

    const response = NextResponse.redirect(authUrl.toString());
    // Bind the flow to this browser: the callback requires the returned
    // state to match this cookie, and the ID token's nonce to match the
    // nonce half.
    response.cookies.set(OIDC_STATE_COOKIE, `${state}.${nonce}`, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production' && process.env.AXONWALL_INSECURE_HTTP !== '1',
      sameSite: 'lax',
      path: '/api/auth',
      maxAge: 600,
    });
    return response;
  } catch {
    return NextResponse.redirect(
      new URL('/login?error=SSO+provider+unreachable', publicOrigin)
    );
  }
}
