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

  // Auth endpoints (login, logout, OIDC, gateway) must stay reachable.
  if (pathname.startsWith('/api/auth/')) {
    return NextResponse.next();
  }

  const token = request.cookies.get(SESSION_COOKIE)?.value;
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
    if (payload.pwd_change_required === true) {
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
