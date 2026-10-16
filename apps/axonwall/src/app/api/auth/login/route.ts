import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { performAuthentication } from '../../../../server/auth';
import { getJwtSecret, SESSION_COOKIE } from '../../../../server/auth-constants';
import { mintSupabaseToken } from '@axonwall/lib/ldap';

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { username, password, totpCode } = body;

    if (!username || !password) {
      return NextResponse.json(
        { success: false, error: 'Username and password are required' },
        { status: 400 }
      );
    }

    const authRes = await performAuthentication(username, password, totpCode);
    if (!authRes.success || !authRes.session) {
      return NextResponse.json(
        { success: false, error: authRes.error || 'Authentication failed' },
        { status: 401 }
      );
    }

    const token = await mintSupabaseToken(authRes.session, getJwtSecret());
    const cookieStore = await cookies();
    cookieStore.set(SESSION_COOKIE, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 8 * 3600,
    });

    return NextResponse.json({
      success: true,
      // The session token travels only in the httpOnly cookie above;
      // it is not returned in the body (audit B-09).
      user: {
        userId: authRes.session.userId,
        username: authRes.session.username,
        displayName: authRes.session.displayName,
        roles: authRes.session.roles,
        privileges: authRes.session.privileges,
      },
    });
  } catch (err: any) {
    return NextResponse.json(
      { success: false, error: err.message || 'Internal server error' },
      { status: 500 }
    );
  }
}
