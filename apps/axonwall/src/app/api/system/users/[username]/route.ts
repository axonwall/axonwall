import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { updateLocalUser, deleteLocalUser } from '@/server/users';

export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ username: string }> }
) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');

    const { username } = await params;
    const body = await req.json();
    const result = await updateLocalUser(username, body);
    return NextResponse.json(result);
  } catch (err: any) {
    const status = err.message === 'Unauthorized' ? 401 : err.message?.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ error: err.message }, { status });
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ username: string }> }
) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');

    const { username } = await params;
    const { searchParams } = new URL(req.url);
    const removeHome = searchParams.get('removeHome') === 'true';

    const result = await deleteLocalUser(username, removeHome);
    return NextResponse.json(result);
  } catch (err: any) {
    const status = err.message === 'Unauthorized' ? 401 : err.message?.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ error: err.message }, { status });
  }
}
