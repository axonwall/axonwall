import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { getCurrentDesiredState } from '@/server/agent';

export async function GET(req: NextRequest) {
  try {
    const session = await getSession();

    if (!session || session.passwordChangeRequired) {
      return NextResponse.json(
        { error: session?.passwordChangeRequired ? 'Password change required' : 'Unauthorized' },
        { status: session?.passwordChangeRequired ? 403 : 401 }
      );
    }

    const searchParams =
      req.nextUrl?.searchParams ?? new URL(req.url, 'http://localhost').searchParams;
    const rolesParam = searchParams.get('roles');
    const hasExplicitRolesParam = Boolean(rolesParam && rolesParam.trim().length > 0);

    if (hasExplicitRolesParam && rolesParam) {
      const requiredRoles = rolesParam
        .split(',')
        .map((r) => r.trim())
        .filter(Boolean);
      if (requiredRoles.length > 0) {
        const userRoles = Array.isArray(session.roles) ? session.roles : [];
        const hasRequiredRole =
          userRoles.includes('admin') ||
          requiredRoles.some((reqRole) => userRoles.includes(reqRole as any));
        if (!hasRequiredRole) {
          return NextResponse.json({ error: 'Forbidden: Insufficient privileges' }, { status: 403 });
        }
      }
    }

    // Check roles based on headers passed by reverse proxy (X-Forwarded-Host or Host)
    const rawHost = req.headers.get('x-forwarded-host') || req.headers.get('host');
    if (!rawHost && !hasExplicitRolesParam) {
      return NextResponse.json({ error: 'Missing Host' }, { status: 400 });
    }

    const host = (rawHost || '').replace(/^https?:\/\//i, '').split(':')[0].trim().toLowerCase();
    if (!host && !hasExplicitRolesParam) {
      return NextResponse.json({ error: 'Invalid Host' }, { status: 400 });
    }

    if (host) {
      const state = await getCurrentDesiredState();
      const matchedApp = state.zeroTrust?.apps?.find(
        (a) => a.publicHostname.replace(/^https?:\/\//i, '').split(':')[0].trim().toLowerCase() === host
      );

      if (matchedApp && !matchedApp.enabled) {
        return NextResponse.json({ error: 'Forbidden: Application not configured or disabled' }, { status: 403 });
      }

      if (!matchedApp && !hasExplicitRolesParam) {
        return NextResponse.json({ error: 'Forbidden: Application not configured or disabled' }, { status: 403 });
      }

      if (matchedApp && !matchedApp.allowAnyAuthenticated) {
        // Fail closed (audit B-S3): an app with no role list admits only
        // admins rather than every authenticated session; open access is
        // the explicit allowAnyAuthenticated choice instead.
        const effectiveRoles =
          matchedApp.allowedRoles && matchedApp.allowedRoles.length > 0 ? matchedApp.allowedRoles : ['admin'];
        const userRoles = Array.isArray(session.roles) ? session.roles : [];
        const hasRole =
          userRoles.includes('admin') || userRoles.some((r) => effectiveRoles.includes(r as any));
        if (!hasRole) {
          return NextResponse.json({ error: 'Forbidden: Insufficient privileges' }, { status: 403 });
        }
      }
    }

    const response = new NextResponse('OK', { status: 200 });
    const rolesHeader = (session.roles || []).join(',');
    // Pass user info downstream to the internal app
    response.headers.set('X-Remote-User', session.username);
    response.headers.set('X-Remote-Roles', rolesHeader);
    response.headers.set('X-Remote-Source', session.source || 'unknown');
    response.headers.set('X-Axonwall-User', session.username);
    response.headers.set('X-Axonwall-Roles', rolesHeader);

    return response;
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || 'Internal Server Error' },
      { status: 500 }
    );
  }
}
