import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { mintSupabaseToken } from '@axonwall/lib/ldap';
import { getSession } from '@/server/auth';
import { getJwtSecret, SESSION_COOKIE } from '@/server/auth-constants';
import { assertMeshSelfServicePermitted } from '@/server/auth-guard';
import { callAgentApiResponse } from '@/server/agent-client';
import { bumpUserSessionEpoch, stampSessionEpoch } from '@/server/session-revocation';

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertMeshSelfServicePermitted(session);

    if (session.source !== 'local') {
      return NextResponse.json(
        {
          status: 'error',
          error:
            session.source === 'local_admin'
              ? 'Break-glass admin password must be changed from the Console Security modal'
              : 'Password changes for SSO/external directory accounts are managed by your identity provider',
        },
        { status: 403 }
      );
    }

    const body = await req.json().catch(() => ({}));
    const currentPassword = typeof body?.currentPassword === 'string' ? body.currentPassword : '';
    const newPassword = typeof body?.newPassword === 'string' ? body.newPassword : '';
    const confirmPassword = typeof body?.confirmPassword === 'string' ? body.confirmPassword : '';

    if (!currentPassword || !newPassword || !confirmPassword) {
      return NextResponse.json(
        { status: 'error', error: 'All password fields are required' },
        { status: 400 }
      );
    }
    if (newPassword !== confirmPassword) {
      return NextResponse.json(
        { status: 'error', error: 'New password and confirmation do not match' },
        { status: 400 }
      );
    }
    if (newPassword.length < 8) {
      return NextResponse.json(
        { status: 'error', error: 'New password must be at least 8 characters long' },
        { status: 400 }
      );
    }
    if (/[\r\n\x00]/.test(currentPassword) || /[\r\n\x00]/.test(newPassword)) {
      return NextResponse.json(
        { status: 'error', error: 'Password contains invalid control characters' },
        { status: 400 }
      );
    }

    const daemonRes = await callAgentApiResponse<{ success?: boolean; message?: string; error?: string }>(
      '/v1/system/users/change-password',
      'POST',
      {
        username: session.username,
        currentPassword,
        newPassword,
      }
    );

    if (!daemonRes) {
      return NextResponse.json(
        { status: 'error', error: 'Daemon unavailable: could not update password' },
        { status: 503 }
      );
    }
    if (!daemonRes.success) {
      const msg = daemonRes.error || daemonRes.message || 'Password update failed';
      const isAuthErr = /invalid credentials|verification failed|locked/i.test(msg);
      return NextResponse.json(
        { status: 'error', error: msg },
        { status: isAuthErr ? 401 : 400 }
      );
    }

    bumpUserSessionEpoch(session.username);
    const freshSession = { ...session };
    stampSessionEpoch(freshSession);
    const freshToken = await mintSupabaseToken(freshSession, getJwtSecret());
    const cookieStore = await cookies();
    cookieStore.set(SESSION_COOKIE, freshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production' && process.env.AXONWALL_INSECURE_HTTP !== '1',
      sameSite: 'lax',
      path: '/',
      maxAge: 8 * 3600,
    });

    return NextResponse.json({
      status: 'ok',
      message: daemonRes.message || 'Password updated successfully',
    });
  } catch (err: any) {
    const msg = err?.message || 'Password update failed';
    const status = msg === 'Unauthorized' ? 401 : msg.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ status: 'error', error: msg }, { status });
  }
}
