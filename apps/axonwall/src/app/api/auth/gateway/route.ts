import { NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { getCurrentDesiredState } from '@/server/agent';

export async function GET(req: Request) {
  try {
    const session = await getSession();

    if (!session || session.passwordChangeRequired) {
      return NextResponse.json(
        { error: session?.passwordChangeRequired ? 'Password change required' : 'Unauthorized' },
        { status: session?.passwordChangeRequired ? 403 : 401 }
      );
    }

    // Check roles based on headers passed by reverse proxy (X-Forwarded-Host or Host)
    const rawHost = req.headers.get('x-forwarded-host') || req.headers.get('host');
    if (!rawHost) {
      return NextResponse.json({ error: 'Missing Host' }, { status: 400 });
    }

    const host = rawHost.replace(/^https?:\/\//i, '').split(':')[0].trim().toLowerCase();
    if (!host) {
      return NextResponse.json({ error: 'Invalid Host' }, { status: 400 });
    }

    const state = await getCurrentDesiredState();
    const app = state.zeroTrust?.apps?.find(
      (a) => a.enabled && a.publicHostname.replace(/^https?:\/\//i, '').split(':')[0].trim().toLowerCase() === host
    );

    if (!app) {
      return NextResponse.json({ error: 'Forbidden: Application not configured or disabled' }, { status: 403 });
    }

    if (!app.allowAnyAuthenticated) {
      // Fail closed (audit B-S3): an app with no role list admits only
      // admins rather than every authenticated session; open access is
      // the explicit allowAnyAuthenticated choice instead.
      const effectiveRoles =
        app.allowedRoles && app.allowedRoles.length > 0 ? app.allowedRoles : ['admin'];
      const hasRole =
        Array.isArray(session.roles) && session.roles.some((r) => effectiveRoles.includes(r as any));
      if (!hasRole) {
        return NextResponse.json({ error: 'Forbidden: Insufficient privileges' }, { status: 403 });
      }
    }

    const response = new NextResponse('OK', { status: 200 });
    // Pass user info downstream to the internal app
    response.headers.set('X-Remote-User', session.username);
    response.headers.set('X-Remote-Roles', (session.roles || []).join(','));

    return response;
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || 'Internal Server Error' },
      { status: 500 }
    );
  }
}
