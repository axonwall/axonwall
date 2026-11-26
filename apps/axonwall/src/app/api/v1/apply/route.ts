import { NextResponse } from 'next/server';
import { applyDesiredState } from '../../../../server/agent';
import { getSession } from '../../../../server/auth';
import { assertActionPermitted } from '../../../../server/auth-guard';
import { parseConfirmTimeoutSeconds } from '../../../../server/confirm-timeout';
import { DesiredStateSchema } from '@axonwall/lib/schemas';

export async function POST(req: Request) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');

    let body: any;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ status: 'error', error: 'Invalid JSON request body' }, { status: 400 });
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return NextResponse.json({ status: 'error', error: 'Invalid JSON request body' }, { status: 400 });
    }
    // C26: validate the confirm window (integer 10–3600, default 120);
    // invalid values are a 400, not a silently coerced window.
    const timeout = parseConfirmTimeoutSeconds(body.confirmTimeoutSeconds);
    const parsedState = DesiredStateSchema.parse(body.state);

    const result = await applyDesiredState(parsedState, timeout);
    return NextResponse.json({
      status: 'ok',
      data: result,
    });
  } catch (err: any) {
    const statusCode = err.message?.includes('Unauthorized')
      ? 401
      : err.message?.includes('Forbidden') || err.message?.toLowerCase().includes('admin')
        ? 403
        : err.message?.includes('Rate limit') || err.message?.includes('Too Many Requests')
          ? 429
          : 400;
    return NextResponse.json(
      {
        status: 'error',
        error: err.message,
      },
      { status: statusCode }
    );
  }
}
