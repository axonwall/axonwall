import { NextRequest, NextResponse } from 'next/server';
import { queryNetFlowAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 400;
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json().catch(() => ({}))) as Parameters<typeof queryNetFlowAction>[0];
    const data = await queryNetFlowAction(body);
    return NextResponse.json({ status: data.fqlError ? 'error' : 'ok', data }, { status: data.fqlError && !data.daemonDown ? 400 : 200 });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to query flows';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
