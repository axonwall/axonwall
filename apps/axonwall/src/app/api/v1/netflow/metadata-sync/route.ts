import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { callAgentApiDetailed } from '@/server/agent-client';
import { hasServiceTokenScope } from '@/server/service-tokens';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 400;
}

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'operator');
    if (
      !hasServiceTokenScope(session, 'observability:ingest') &&
      !hasServiceTokenScope(session, 'netflow:ingest')
    ) {
      return NextResponse.json(
        { status: 'error', error: 'Forbidden: token lacks observability:ingest or netflow:ingest scope.' },
        { status: 403 }
      );
    }

    const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ status: 'error', error: 'Invalid JSON payload' }, { status: 400 });
    }

    let exporterIp = typeof body.exporterIp === 'string' ? body.exporterIp.trim() : '';
    if (!exporterIp) {
      const xff = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
      const realIp = req.headers.get('x-real-ip')?.trim();
      exporterIp = xff || realIp || '';
    }

    const payload = {
      ...body,
      ...(exporterIp ? { exporterIp } : {}),
    };
    const res = await callAgentApiDetailed<{ success?: boolean; nodeId?: string; error?: string }>(
      '/v1/netflow/metadata-sync',
      'POST',
      payload,
      5000
    );
    if (res.kind === 'ok') {
      return NextResponse.json({ status: 'ok', data: res.data });
    }
    if (res.kind === 'http_error') {
      return NextResponse.json({ status: 'error', error: res.message }, { status: res.status });
    }
    return NextResponse.json({ status: 'error', error: 'axonwalld daemon unreachable' }, { status: 503 });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Metadata sync failed';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
