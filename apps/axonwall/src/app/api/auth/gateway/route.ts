import { NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { getCurrentDesiredState } from '@/server/agent';

export async function GET(req: Request) {
  const session = await getSession();
  
  if (!session) {
    // If unauthorized, forward auth expects a 401, or we can redirect to login
    // Caddy forward_auth handles the redirect if we return 401
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Check roles based on headers passed by Caddy, like X-Forwarded-Host
  const host = req.headers.get('x-forwarded-host')?.split(':')[0]?.toLowerCase();
  if (host) {
    try {
      const state = await getCurrentDesiredState();
      const app = state.zeroTrust?.apps?.find(
        (a) => a.enabled && a.publicHostname.toLowerCase() === host
      );
      if (app && app.allowedRoles && app.allowedRoles.length > 0) {
        const hasRole = session.roles.some((r) => app.allowedRoles.includes(r as any));
        if (!hasRole) {
          return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
        }
      }
    } catch {}
  }
  
  const response = new NextResponse('OK', { status: 200 });
  // Pass user info downstream to the internal app
  response.headers.set('X-Remote-User', session.username);
  response.headers.set('X-Remote-Roles', session.roles.join(','));
  
  return response;
}
