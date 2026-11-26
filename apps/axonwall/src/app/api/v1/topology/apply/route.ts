import { NextRequest, NextResponse } from 'next/server';
import { applyFabricPlanAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  if (msg.includes('Rate limit') || msg.includes('Too Many Requests')) return 429;
  return 400;
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const res = await applyFabricPlanAction(body);
    return NextResponse.json({ status: res.success ? 'ok' : 'error', data: res }, { status: res.success ? 200 : 502 });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to apply fabric plan';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
