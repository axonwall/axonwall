import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { getLocalUsers, getLocalGroups, createLocalUser, getDirectoryStatus } from '@/server/users';

export async function GET() {
  try {
    const session = await getSession();
    assertActionPermitted(session);

    const [users, groups, directoryStatus] = await Promise.all([
      getLocalUsers(),
      getLocalGroups(),
      getDirectoryStatus(),
    ]);
    return NextResponse.json({ users, groups, directoryStatus });
  } catch (err: any) {
    const status = err.message === 'Unauthorized' ? 401 : err.message?.startsWith('Forbidden') ? 403 : 500;
    return NextResponse.json({ error: err.message }, { status });
  }
}

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');

    const body = await req.json();
    const result = await createLocalUser(body);
    return NextResponse.json(result);
  } catch (err: any) {
    const status = err.message === 'Unauthorized' ? 401 : err.message?.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ error: err.message }, { status });
  }
}
