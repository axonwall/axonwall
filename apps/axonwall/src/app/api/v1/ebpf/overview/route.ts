import { NextResponse } from 'next/server';
import { getEbpfOverviewTelemetry } from '@/server/agent';

export async function GET() {
  try {
    const data = await getEbpfOverviewTelemetry();
    return NextResponse.json({ status: 'ok', data });
  } catch (err: any) {
    const msg = err?.message || 'Internal server error';
    const code = msg.includes('Unauthorized') ? 401 : msg.includes('Forbidden') ? 403 : 500;
    return NextResponse.json({ status: 'error', error: msg }, { status: code });
  }
}
