import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { createServiceToken, listServiceTokens, type ServiceTokenRole } from '@/server/service-tokens';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 400;
}

export async function GET() {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    return NextResponse.json({ status: 'ok', tokens: listServiceTokens() });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to list service tokens';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    const body = (await req.json().catch(() => ({}))) as {
      name?: string;
      role?: ServiceTokenRole;
      scopes?: string[];
      expiresAt?: string;
    };
    const created = createServiceToken({
      name: String(body?.name || ''),
      role: body?.role,
      scopes: Array.isArray(body?.scopes) ? body.scopes : undefined,
      expiresAt: body?.expiresAt,
    });
    return NextResponse.json(
      {
        status: 'ok',
        token: created.record,
        plaintextToken: created.plaintextToken,
      },
      { status: 201 }
    );
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to create service token';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
