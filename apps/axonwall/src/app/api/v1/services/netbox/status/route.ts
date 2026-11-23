import { NextResponse } from 'next/server';
import { getNetBoxStatusAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 500;
}

export async function GET() {
  try {
    const data = await getNetBoxStatusAction();
    return NextResponse.json({ status: 'ok', data });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
