import { NextRequest, NextResponse } from 'next/server';
import { getThreatHarvesterStatus, updateThreatHarvesterLiveConfigAction } from '@/server/agent';

function errStatus(msg: string): number {
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 500;
}

export async function GET() {
  try {
    const data = await getThreatHarvesterStatus();
    return NextResponse.json({ status: 'ok', data });
  } catch (err: any) {
    const msg = err?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(msg) });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const res = await updateThreatHarvesterLiveConfigAction(body);
    if (!res.success) {
      return NextResponse.json({ status: 'error', error: res.error }, { status: 400 });
    }
    return NextResponse.json({ status: 'ok', ...res });
  } catch (err: any) {
    const msg = err?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(msg) });
  }
}
