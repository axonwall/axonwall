import { NextRequest, NextResponse } from 'next/server';
import {
  OIDC_STATE_COOKIE,
  computePkceChallenge,
  discoverOidc,
  getOidcConfig,
  isOidcHttpAllowed,
  randomToken,
  resolveOidcRedirectUri,
  resolvePublicOrigin,
  validateOidcAuthorizationEndpoint,
} from '../../../../../server/oidc';

function relativeRedirect(location: string): NextResponse {
  return new NextResponse(null, {
    status: 302,
    headers: { Location: location, 'Cache-Control': 'no-store' },
  });
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

export async function GET(request: NextRequest) {
  const cfg = await getOidcConfig();
  const publicOrigin = resolvePublicOrigin(
    request.headers,
    safeFallbackOrigin(request.nextUrl.origin),
    cfg?.redirectUri
  );

  // No simulation mode: if no live OIDC provider is configured, SSO is
  // simply unavailable.
  if (!cfg) {
    return relativeRedirect('/login?error=sso_not_configured');
  }

  try {
    const discovery = await discoverOidc(cfg);
    const state = randomToken();
    const nonce = randomToken();
    const codeVerifier = randomToken();
    const codeChallenge = computePkceChallenge(codeVerifier);
    const redirectUri = resolveOidcRedirectUri(publicOrigin, cfg.redirectUri);

    const authUrl = validateOidcAuthorizationEndpoint(
      discovery.authorization_endpoint,
      isOidcHttpAllowed(cfg)
    );
    authUrl.searchParams.set('client_id', cfg.clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set(
      'scope',
      cfg.scopes && cfg.scopes.length > 0 ? cfg.scopes.join(' ') : 'openid profile email groups'
    );
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('nonce', nonce);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const response = NextResponse.redirect(authUrl.toString());
    // Bind the flow to this browser: the callback requires the returned
    // state to match this cookie, the ID token's nonce to match the
    // nonce segment, and the token exchange to prove possession of the PKCE verifier.
    response.cookies.set(OIDC_STATE_COOKIE, `${state}.${nonce}.${codeVerifier}`, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production' && process.env.AXONWALL_INSECURE_HTTP !== '1',
      sameSite: 'lax',
      path: '/api/auth',
      maxAge: 600,
    });
    return response;
  } catch {
    return relativeRedirect('/login?error=sso_unreachable');
  }
}
