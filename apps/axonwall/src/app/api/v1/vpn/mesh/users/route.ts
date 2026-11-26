import { NextResponse } from 'next/server';
import { listUsers, createUser, deleteUser } from '../../../../../../server/headscale';
import { getSession } from '../../../../../../server/auth';
import { assertActionPermitted } from '../../../../../../server/auth-guard';

function mapMeshErrStatus(err: unknown): number {
  if (err instanceof SyntaxError) return 400;
  const msg = err instanceof Error ? err.message : String(err || '');
  if (msg === 'Unauthorized') return 401;
  if (msg.startsWith('Forbidden')) return 403;
  if (/not found/i.test(msg)) return 404;
  if (/invalid|required|cannot start|must be|json/i.test(msg)) return 400;
  return 500;
}

export async function GET() {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    const users = await listUsers();
    return NextResponse.json({ status: 'ok', data: users });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err?.message || 'Failed to list users' }, { status: mapMeshErrStatus(err) });
  }
}

export async function POST(req: Request) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    const body = await req.json();
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return NextResponse.json({ status: 'error', error: 'Invalid JSON request body' }, { status: 400 });
    }
    if (body.action === 'delete') {
      if (typeof body.name !== 'string' || !body.name.trim()) {
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
    if (typeof body.name !== 'string' || !body.name.trim()) {
      return NextResponse.json({ status: 'error', error: 'Name is required' }, { status: 400 });
    }
    const user = await createUser(body.name);
    return NextResponse.json({ status: 'ok', data: user });
  } catch (err: any) {
    const message = err instanceof SyntaxError ? 'Invalid JSON request body' : err?.message || 'User operation failed';
    return NextResponse.json({ status: 'error', error: message }, { status: mapMeshErrStatus(err) });
  }
}
