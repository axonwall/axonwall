import { NextResponse } from 'next/server';
import { confirmActiveRuleset } from '../../../../server/agent';

export async function POST() {
  try {
    const result = await confirmActiveRuleset();
    return NextResponse.json({
      status: 'ok',
      data: result,
    });
  } catch (err: any) {
    const statusCode = err.message?.includes('Unauthorized') ? 401 : err.message?.includes('Admin') ? 403 : 500;
    return NextResponse.json(
      { status: 'error', error: err.message },
      { status: statusCode }
    );
  }
}
