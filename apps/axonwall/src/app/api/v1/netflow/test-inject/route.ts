import { NextRequest, NextResponse } from 'next/server';
import { injectNetFlowTestBurstAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  if (msg.includes('Rate limit') || msg.includes('Too Many Requests')) return 429;
  return 500;
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json().catch(() => ({}))) as { protocol?: string; count?: number };
    const data = await injectNetFlowTestBurstAction(body?.protocol || 'ipfix', body?.count ?? 12);
    return NextResponse.json({ status: data.success ? 'ok' : 'error', data }, { status: data.success ? 200 : 502 });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to inject synthetic burst';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
