import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const issuerUrl = process.env.OIDC_ISSUER_URL;
  const clientId = process.env.OIDC_CLIENT_ID;
  const redirectUri = `${request.nextUrl.origin}/api/auth/callback/oidc`;

  // If live OIDC provider is configured, redirect to provider's authorization endpoint
  if (issuerUrl && clientId) {
    const authUrl = new URL(`${issuerUrl.replace(/\/$/, '')}/authorize`);
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email groups');
    authUrl.searchParams.set('state', 'axonwall-sso-state-' + Date.now());
    return NextResponse.redirect(authUrl.toString());
  }

  // Development & Simulation Mode:
  // Render simulated Enterprise Identity Provider prompt (Entra ID / Okta)
  const simulatedCallbackUrl = `${redirectUri}?code=simulated-auth-code&user=sso-admin@enterprise.corp&group=Axonwall-Admins`;
  return NextResponse.redirect(simulatedCallbackUrl);
}
