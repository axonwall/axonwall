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
    if (!body.name) {
      return NextResponse.json({ status: 'error', error: 'Name is required' }, { status: 400 });
    }
    const user = await createUser(body.name);
    return NextResponse.json({ status: 'ok', data: user });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err.message }, { status: 500 });
  }
}
