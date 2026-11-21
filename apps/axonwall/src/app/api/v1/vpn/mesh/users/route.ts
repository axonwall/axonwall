import { NextResponse } from 'next/server';
import { listUsers, createUser, deleteUser } from '../../../../../../server/headscale';
import { getSession } from '../../../../../../server/auth';
import { isPasswordChangeEnforced } from '../../../../../../server/auth-guard';

export async function GET() {
  try {
    const session = await getSession();
    const pwdEnforced = isPasswordChangeEnforced(session);
    if (!session || pwdEnforced || !session.roles.includes('admin')) {
      return NextResponse.json(
        { error: pwdEnforced ? 'Password change required' : 'Unauthorized' },
        { status: pwdEnforced ? 403 : 401 }
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
    const pwdEnforced = isPasswordChangeEnforced(session);
    if (!session || pwdEnforced || !session.roles.includes('admin')) {
      return NextResponse.json(
        { error: pwdEnforced ? 'Password change required' : 'Unauthorized' },
        { status: pwdEnforced ? 403 : 401 }
      );
    }
    const body = await req.json();
    if (body.action === 'delete') {
      if (!body.name) {
        return NextResponse.json({ status: 'error', error: 'Name is required' }, { status: 400 });
      }
      await deleteUser(body.name);
      return NextResponse.json({ status: 'ok' });
    }
    if (body.action !== 'create') {
      return NextResponse.json(
        { status: 'error', error: `Invalid action '${body.action}': expected 'create' or 'delete'` },
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
