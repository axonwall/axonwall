import { NextResponse } from 'next/server';
import { getAgentStatus } from '../../../../server/agent';

export async function GET() {
  try {
    const status = await getAgentStatus();
    // R4-C-H1: daemon-down is not an "ok" status — the fields in data
    // are UNKNOWN placeholders, so signal it in the envelope too.
    if (status.daemonDown) {
      return NextResponse.json(
        {
          status: 'degraded',
          error: 'Daemon unavailable — status unknown',
          data: status,
        },
        { status: 503 }
      );
    }
    return NextResponse.json({
      status: 'ok',
      data: status,
    });
  } catch (err: any) {
    const statusCode = err.message?.includes('Unauthorized') ? 401 : 500;
    return NextResponse.json(
      {
        status: 'error',
        error: err.message || 'Internal server error',
      },
      { status: statusCode }
    );
  }
}
