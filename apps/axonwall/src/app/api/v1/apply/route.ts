import { NextResponse } from 'next/server';
import { applyDesiredState } from '../../../../server/agent';
import { DesiredStateSchema } from '@axonwall/lib/schemas';

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const timeout = body.confirmTimeoutSeconds || 120;
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
