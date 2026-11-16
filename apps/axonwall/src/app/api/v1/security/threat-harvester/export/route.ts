import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { callAgentApiBinary } from '@/server/agent-client';

export async function GET(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');

    const anonymize = req.nextUrl.searchParams.get('anonymize') !== 'false';
    const res = await callAgentApiBinary(
      `/v1/security/threat-harvester/export?anonymize=${anonymize ? 'true' : 'false'}`,
      'GET',
      60000
    );
    if (!res.ok || !res.buffer) {
      return NextResponse.json(
        { status: 'error', error: res.error || 'Failed to export threat corpus' },
        { status: res.status || 502 }
      );
    }

    return new NextResponse(new Uint8Array(res.buffer), {
      status: 200,
      headers: {
        'Content-Type': 'application/zstd',
        'Content-Disposition': 'attachment; filename="axonwall-threat-corpus.tar.zst"',
        'Cache-Control': 'no-store',
      },
    });
  } catch (err: any) {
    const msg = err?.message || 'Internal server error';
    const code = msg.includes('Unauthorized') ? 401 : msg.includes('Forbidden') ? 403 : 500;
    return NextResponse.json({ status: 'error', error: msg }, { status: code });
  }
}
