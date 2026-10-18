import { NextResponse } from 'next/server';
import { rollbackActiveRuleset } from '../../../../server/agent';

export async function POST() {
  try {
    const result = await rollbackActiveRuleset();
    return NextResponse.json({
      status: 'ok',
      data: result,
    });
  } catch (err: any) {
    const statusCode = err.message?.includes('Unauthorized')
      ? 401
      : err.message?.includes('Forbidden') || err.message?.toLowerCase().includes('admin')
        ? 403
        : 500;
    return NextResponse.json(
      { status: 'error', error: err.message },
      { status: statusCode }
    );
  }
}
