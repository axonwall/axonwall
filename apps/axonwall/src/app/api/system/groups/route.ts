import { NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted, assertInteractiveSession } from '@/server/auth-guard';
import { createLocalGroup, getLocalGroups } from '@/server/users';

export async function GET() {
  try {
    const session = await getSession();
    assertInteractiveSession(session);
    assertActionPermitted(session, 'admin');
    const groups = await getLocalGroups();
    return NextResponse.json({ groups });
  } catch (err: any) {
    const message = err?.message || 'Internal server error';
    const status = message === 'Unauthorized' ? 401 : message.startsWith('Forbidden') ? 403 : 500;
    return NextResponse.json({ error: message }, { status });
  }
}

export async function POST(req: Request) {
  try {
    const session = await getSession();
    assertInteractiveSession(session);
    assertActionPermitted(session, 'admin');

    const body = await req.json();
    const name = typeof body?.name === 'string' ? body.name.trim() : '';
    if (!name) {
      return NextResponse.json({ success: false, error: 'Group name is required' }, { status: 400 });
    }

    const res = await createLocalGroup(name);
    if (!res.success) {
      return NextResponse.json({ success: false, error: res.message }, { status: 400 });
    }
    return NextResponse.json(res);
  } catch (err: any) {
    const message = err?.message || 'Internal server error';
    const status = message === 'Unauthorized' ? 401 : message.startsWith('Forbidden') ? 403 : 500;
    return NextResponse.json({ success: false, error: message }, { status });
  }
}
