import { NextResponse } from 'next/server';
import { getAgentStatus } from '../../../../server/agent';

export async function GET() {
  try {
    const status = await getAgentStatus();
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
