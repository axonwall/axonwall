import { NextRequest, NextResponse } from 'next/server';
import { triggerNetBoxSyncAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  if (msg.includes('Rate limit')) return 429;
  return 500;
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json().catch(() => ({}))) as {
      dryRun?: boolean;
      endpointOverride?: string;
    };
    const res = await triggerNetBoxSyncAction({
      dryRun: Boolean(body?.dryRun),
      endpointOverride: typeof body?.endpointOverride === 'string' ? body.endpointOverride : undefined,
    });
    return NextResponse.json({ status: res.success ? 'ok' : 'error', data: res }, { status: res.success ? 200 : 502 });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
