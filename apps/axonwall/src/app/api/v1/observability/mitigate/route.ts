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
    assertActionPermitted(session, 'admin');
    if (!hasServiceTokenScope(session, 'observability:mitigate')) {
      return NextResponse.json(
        { status: 'error', accepted: false, error: 'Forbidden: token lacks observability:mitigate scope.' },
        { status: 403 }
      );
    }

    const body = (await req.json().catch(() => null)) as {
      targetIp?: string;
      ttlSec?: number;
      reason?: string;
    } | null;
    if (!body?.targetIp || typeof body.targetIp !== 'string') {
      return NextResponse.json(
        { status: 'error', accepted: false, error: 'Missing targetIp' },
        { status: 400 }
      );
    }

    const res = await callAgentApiDetailed<{
      success?: boolean;
      accepted?: boolean;
      targetIp?: string;
      ttlSec?: number;
      message?: string;
      error?: string;
    }>(
      '/v1/observability/mitigate',
      'POST',
      {
        targetIp: body.targetIp.trim(),
        ttlSec: typeof body.ttlSec === 'number' ? body.ttlSec : 300,
        reason: typeof body.reason === 'string' ? body.reason : 'Central Analytics SOAR mitigation',
      },
      5000
    );

    if (res.kind === 'ok') {
      return NextResponse.json({ status: 'ok', ...res.data });
    }
    if (res.kind === 'http_error') {
      return NextResponse.json(
        { status: 'error', accepted: false, error: res.message },
        { status: res.status || 403 }
      );
    }
    return NextResponse.json(
      { status: 'error', accepted: false, error: 'axonwalld daemon unreachable' },
      { status: 503 }
    );
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Mitigation failed';
    return NextResponse.json({ status: 'error', accepted: false, error: msg }, { status: errStatus(err) });
  }
}
