import { NextRequest, NextResponse } from 'next/server';
import {
  OIDC_STATE_COOKIE,
  discoverOidc,
  getOidcConfig,
  randomToken,
} from '../../../../../server/oidc';

export async function GET(request: NextRequest) {
  const cfg = getOidcConfig();

  // No simulation mode: if no live OIDC provider is configured, SSO is
  // simply unavailable. (Previously this redirected into the callback
  // with a simulated admin identity, which minted a real admin session
  // for anyone who could reach the login page.)
  if (!cfg) {
    return NextResponse.redirect(
      new URL('/login?error=SSO+is+not+configured', request.url)
    );
  }

  try {
    const discovery = await discoverOidc(cfg);
    const state = randomToken();
    const nonce = randomToken();
    const redirectUri = `${request.nextUrl.origin}/api/auth/callback/oidc`;

    const authUrl = new URL(discovery.authorization_endpoint);
    authUrl.searchParams.set('client_id', cfg.clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email groups');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('nonce', nonce);

    const response = NextResponse.redirect(authUrl.toString());
    // Bind the flow to this browser: the callback requires the returned
    // state to match this cookie, and the ID token's nonce to match the
    // nonce half.
    response.cookies.set(OIDC_STATE_COOKIE, `${state}.${nonce}`, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/api/auth',
      maxAge: 600,
    });
    return response;
  } catch {
    return NextResponse.redirect(
      new URL('/login?error=SSO+provider+unreachable', request.url)
    );
  }
}
