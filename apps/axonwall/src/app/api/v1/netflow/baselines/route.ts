import { NextRequest, NextResponse } from 'next/server';
import { getNetFlowBaselinesAction, resetNetFlowBaselinesAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 500;
}

export async function GET(req: NextRequest) {
  try {
    const limit = Number(req.nextUrl.searchParams.get('limit') || 50) || 50;
    const entries = await getNetFlowBaselinesAction(limit);
    return NextResponse.json({ status: 'ok', count: entries.length, entries });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to load baselines';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}

export async function DELETE() {
  try {
    const res = await resetNetFlowBaselinesAction();
    return NextResponse.json({ status: 'ok', ...res });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to reset baselines';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
