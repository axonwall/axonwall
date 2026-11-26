import { NextRequest, NextResponse } from 'next/server';
import { triggerLibreNmsNetBoxSyncAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  if (msg.includes('Rate limit') || msg.includes('Too Many Requests')) return 429;
  return 500;
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json().catch(() => ({}))) as {
      action?: 'preview' | 'push' | 'pull';
      dryRun?: boolean;
      overwriteLabels?: boolean;
      endpointOverride?: string;
      netboxOverride?: string;
    };
    const action = body?.action === 'push' || body?.action === 'pull' ? body.action : 'preview';
    const res = await triggerLibreNmsNetBoxSyncAction({
      action,
      dryRun: body?.dryRun ?? action === 'preview',
      overwriteLabels: Boolean(body?.overwriteLabels),
      endpointOverride: typeof body?.endpointOverride === 'string' ? body.endpointOverride : undefined,
      netboxOverride: typeof body?.netboxOverride === 'string' ? body.netboxOverride : undefined,
    });
    return NextResponse.json({ status: res.success ? 'ok' : 'error', data: res }, { status: res.success ? 200 : 502 });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
