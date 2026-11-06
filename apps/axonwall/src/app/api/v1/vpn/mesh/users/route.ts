import { NextResponse } from 'next/server';
import { listUsers, createUser } from '../../../../../../server/headscale';
import { getSession } from '../../../../../../server/auth';

export async function GET() {
  try {
    const session = await getSession();
    if (!session || session.passwordChangeRequired || !session.roles.includes('admin')) {
      return NextResponse.json(
        { error: session?.passwordChangeRequired ? 'Password change required' : 'Unauthorized' },
        { status: session?.passwordChangeRequired ? 403 : 401 }
      );
    }
    const users = await listUsers();
    return NextResponse.json({ status: 'ok', data: users });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err.message }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    const session = await getSession();
    if (!session || session.passwordChangeRequired || !session.roles.includes('admin')) {
      return NextResponse.json(
        { error: session?.passwordChangeRequired ? 'Password change required' : 'Unauthorized' },
        { status: session?.passwordChangeRequired ? 403 : 401 }
      );
    }
    const body = await req.json();
    // N12: only an explicit 'create' creates a user, mirroring the
    // keys route (C21). The old fall-through created a user for any
    // action value, so a caller that meant 'delete' (or typo'd the
    // action) silently created the user instead.
    if (body.action !== 'create') {
      return NextResponse.json(
        { status: 'error', error: `Invalid action '${body.action}': expected 'create'` },
        { status: 400 }
      );
    }
    if (!body.name) {
      return NextResponse.json({ status: 'error', error: 'Name is required' }, { status: 400 });
    }
    const user = await createUser(body.name);
    return NextResponse.json({ status: 'ok', data: user });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err.message }, { status: 500 });
  }
}
