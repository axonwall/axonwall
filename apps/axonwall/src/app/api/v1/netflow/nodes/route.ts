import { NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { fetchObservabilityNodes } from '@/server/observability-clients';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 500;
}

export async function GET() {
  try {
    const session = await getSession();
    assertActionPermitted(session);
    const nodes = await fetchObservabilityNodes();
    return NextResponse.json({ status: 'ok', nodes });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to query observability nodes';
    return NextResponse.json({ status: 'error', error: msg, nodes: [] }, { status: errStatus(err) });
  }
}
