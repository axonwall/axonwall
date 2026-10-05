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
    return NextResponse.json(
      { status: 'error', error: err.message },
      { status: 500 }
    );
  }
}
