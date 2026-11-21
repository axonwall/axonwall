import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';

// Server-side enforcement of the forced first-login password change.
//
// Until now the "force password change" was only a React modal: the
// layout rendered it when isPasswordChangeRequired() was true, but
// every /api route (and the root daemon behind them) served a session
// that had never changed the default password to anyone who simply
// didn't use the web UI. Login now stamps such sessions with a
// pwd_change_required claim (see server/auth.ts), and this middleware
// rejects /api/* calls carrying it -- except the auth endpoints
// themselves. The password change is a server action on a page route,
// so the operator can still complete it (and log out) while gated.
//
// Keep SESSION_COOKIE in sync with server/auth-constants.ts (that
// module imports node:fs and cannot be bundled for the edge runtime).

const SESSION_COOKIE = 'axonwall_session';

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const isMutation = !['GET', 'HEAD', 'OPTIONS'].includes(request.method.toUpperCase());

  if (isMutation) {
    const secFetchSite = request.headers.get('sec-fetch-site')?.trim().toLowerCase();
    if (secFetchSite === 'cross-site') {
      return NextResponse.json(
        { error: 'Forbidden: Cross-site request rejected.' },
        { status: 403 }
      );
    }
    const origin = request.headers.get('origin');
    const referer = request.headers.get('referer');
    const host = request.headers.get('x-forwarded-host') || request.headers.get('host');
    const expectedHost = host ? host.split(',')[0].trim().toLowerCase() : '';
    if (origin === 'null') {
      return NextResponse.json(
        { error: 'Forbidden: Null Origin header rejected.' },
        { status: 403 }
      );
    }
    let originVerified = false;
    if (origin) {
      try {
        const originUrl = new URL(origin);
        if (!expectedHost || originUrl.host.toLowerCase() !== expectedHost) {
          return NextResponse.json(
            { error: 'Forbidden: Cross-origin request rejected.' },
            { status: 403 }
          );
        }
        originVerified = true;
      } catch {
        return NextResponse.json({ error: 'Forbidden: Invalid Origin header.' }, { status: 403 });
      }
    } else if (secFetchSite === 'same-origin') {
      originVerified = true;
    } else if (referer) {
      try {
        const refererUrl = new URL(referer);
        if (!expectedHost || refererUrl.host.toLowerCase() !== expectedHost) {
          return NextResponse.json(
            { error: 'Forbidden: Cross-origin Referer rejected.' },
            { status: 403 }
          );
        }
        originVerified = true;
      } catch {
        return NextResponse.json({ error: 'Forbidden: Invalid Referer header.' }, { status: 403 });
      }
    }

    const hasSessionCookie = Boolean(request.cookies.get(SESSION_COOKIE)?.value);
    const hasBearerAuth = Boolean(request.headers.get('authorization')?.startsWith('Bearer '));
    if (hasSessionCookie && !hasBearerAuth && !originVerified) {
      return NextResponse.json(
        { error: 'Forbidden: Missing same-origin request proof for cookie-authenticated mutation.' },
        { status: 403 }
      );
    }
  }

  // Auth endpoints (login, logout, OIDC) must stay reachable without password change.
  // Note: /api/auth/gateway is the zero-trust forward-auth proxy and MUST be gated.
  if (pathname.startsWith('/api/auth/') && pathname !== '/api/auth/gateway') {
    return NextResponse.next();
  }

  let token = request.cookies.get(SESSION_COOKIE)?.value;
  if (!token) {
    const authHeader = request.headers.get('authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7).trim();
    }
  }

  if (!token) {
    // Unauthenticated requests are the routes' own concern (they 401).
    return NextResponse.next();
  }

  // The session secret reaches this process via the environment:
  // packaged units load /etc/axonwall/axonwall.env as an
  // EnvironmentFile (which sets JWT_SECRET), and the Docker
  // deployment requires it explicitly. Without it no session can be
  // verified here -- and none can be minted or verified by the
  // routes either, since getJwtSecret() now fails closed -- so there
  // is nothing extra to gate.
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return NextResponse.next();
  }

  try {
    const { payload } = await jwtVerify(
      token,
      new TextEncoder().encode(secret),
      { algorithms: ['HS256'] }
    );
    if (payload.pwd_change_required === true && (isMutation || pathname === '/api/auth/gateway')) {
      return NextResponse.json(
        {
          error:
            'Password change required: the default admin password must be changed before using the API.',
        },
        { status: 403 }
      );
    }
  } catch {
    // Invalid/expired token: fall through; the route will 401.
  }

  return NextResponse.next();
}

export const config = {
  matcher: '/api/:path*',
};
