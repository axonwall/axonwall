import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { revokeServiceToken } from '@/server/service-tokens';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 400;
}

export async function DELETE(
  _req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    const { id } = await context.params;
    const revoked = revokeServiceToken(id);
    if (!revoked) {
      return NextResponse.json({ status: 'error', error: 'Service token not found' }, { status: 404 });
    }
    return NextResponse.json({ status: 'ok', revoked: true, id });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to revoke service token';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
