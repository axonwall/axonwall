import { NextResponse } from 'next/server';
import { triggerNetFlowGeoIPUpdateAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 500;
}

export async function POST() {
  try {
    const res = await triggerNetFlowGeoIPUpdateAction();
    return NextResponse.json({ status: res.success ? 'ok' : 'error', ...res }, { status: res.success ? 200 : 502 });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to update GeoIP databases';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
