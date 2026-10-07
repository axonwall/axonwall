import { NextResponse } from 'next/server';
import { getSession } from '@/server/auth';

export async function GET(req: Request) {
  const session = await getSession();
  
  if (!session) {
    // If unauthorized, forward auth expects a 401, or we can redirect to login
    // Caddy forward_auth handles the redirect if we return 401
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Optionally check roles based on headers passed by Caddy, like X-Forwarded-Host
  const host = req.headers.get('x-forwarded-host');
  // For now, any valid session gets access
  
  const response = new NextResponse('OK', { status: 200 });
  // Pass user info downstream to the internal app
  response.headers.set('X-Remote-User', session.username);
  response.headers.set('X-Remote-Roles', session.roles.join(','));
  
  return response;
}
