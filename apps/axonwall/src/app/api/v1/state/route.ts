import { NextResponse } from 'next/server';
import { getSession } from '../../../../server/auth';
import { assertActionPermitted } from '../../../../server/auth-guard';
import { getCurrentDesiredState } from '../../../../server/agent';

export async function GET() {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'readonly');
    const state = await getCurrentDesiredState();
    return NextResponse.json(state);
  } catch (err: any) {
    const msg = String(err?.message || err);
    const statusCode = msg.includes('Unauthorized')
      ? 401
      : msg.includes('Forbidden') || msg.toLowerCase().includes('admin') || msg.toLowerCase().includes('password')
        ? 403
        : 500;
    return NextResponse.json({ status: 'error', error: msg }, { status: statusCode });
  }
}
