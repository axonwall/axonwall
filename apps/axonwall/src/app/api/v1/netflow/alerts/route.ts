import { NextRequest, NextResponse } from 'next/server';
import { ackNetFlowAlertAction, getNetFlowAlertsAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 500;
}

export async function GET() {
  try {
    const alerts = await getNetFlowAlertsAction();
    return NextResponse.json({ status: 'ok', data: { alerts } });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json().catch(() => ({}))) as { id?: string };
    const id = typeof body?.id === 'string' && body.id.trim() ? body.id.trim() : 'all';
    const data = await ackNetFlowAlertAction(id);
    return NextResponse.json({ status: data.success ? 'ok' : 'error', data });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to acknowledge alert';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
