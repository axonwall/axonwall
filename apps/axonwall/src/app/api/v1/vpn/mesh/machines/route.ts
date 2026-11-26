import { NextResponse } from 'next/server';
import {
  listMachines,
  deleteMachine,
  renameMachine,
  expireMachine,
  registerMachine,
} from '../../../../../../server/headscale';
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

export async function GET(req: Request) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');
    const { searchParams } = new URL(req.url);
    const user = searchParams.get('user') || undefined;
    const machines = await listMachines(user);
    return NextResponse.json({ status: 'ok', data: machines });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err?.message || 'Failed to list machines' }, { status: mapMeshErrStatus(err) });
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
    const { action, machineId, newName, user, key } = body;

    if (action === 'register') {
      if (typeof user !== 'string' || !user.trim() || typeof key !== 'string' || !key.trim()) {
        return NextResponse.json({ error: 'user and key are required' }, { status: 400 });
      }
      const m = await registerMachine(user, key);
      return NextResponse.json({ status: 'ok', data: m });
    }

    if (!machineId || (typeof machineId !== 'string' && typeof machineId !== 'number')) {
      return NextResponse.json({ error: 'machineId is required' }, { status: 400 });
    }

    if (action === 'rename') {
      if (typeof newName !== 'string' || !newName.trim()) {
        return NextResponse.json({ error: 'newName is required' }, { status: 400 });
      }
      const m = await renameMachine(machineId, newName);
      return NextResponse.json({ status: 'ok', data: m });
    } else if (action === 'expire') {
      const m = await expireMachine(machineId);
      return NextResponse.json({ status: 'ok', data: m });
    } else if (action === 'delete') {
      await deleteMachine(machineId);
      return NextResponse.json({ status: 'ok' });
    }
    
    return NextResponse.json({ error: 'invalid action' }, { status: 400 });
  } catch (err: any) {
    const message = err instanceof SyntaxError ? 'Invalid JSON request body' : err?.message || 'Machine operation failed';
    return NextResponse.json({ status: 'error', error: message }, { status: mapMeshErrStatus(err) });
  }
}
