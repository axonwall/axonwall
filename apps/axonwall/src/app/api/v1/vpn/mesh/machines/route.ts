import { NextResponse } from 'next/server';
import {
  listMachines,
  deleteMachine,
  renameMachine,
  expireMachine,
  registerMachine,
} from '../../../../../../server/headscale';
import { getSession } from '../../../../../../server/auth';
import { isPasswordChangeEnforced } from '../../../../../../server/auth-guard';

export async function GET(req: Request) {
  try {
    const session = await getSession();
    const pwdEnforced = isPasswordChangeEnforced(session);
    if (!session || pwdEnforced || !session.roles.includes('admin')) {
      return NextResponse.json(
        { error: pwdEnforced ? 'Password change required' : 'Unauthorized' },
        { status: pwdEnforced ? 403 : 401 }
      );
    }
    const { searchParams } = new URL(req.url);
    const user = searchParams.get('user') || undefined;
    const machines = await listMachines(user);
    return NextResponse.json({ status: 'ok', data: machines });
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
    const { action, machineId, newName, user, key } = body;

    if (action === 'register') {
      if (!user || !key) {
        return NextResponse.json({ error: 'user and key are required' }, { status: 400 });
      }
      const m = await registerMachine(user, key);
      return NextResponse.json({ status: 'ok', data: m });
    }

    if (!machineId) return NextResponse.json({ error: 'machineId is required' }, { status: 400 });

    if (action === 'rename') {
      if (!newName) return NextResponse.json({ error: 'newName is required' }, { status: 400 });
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
    return NextResponse.json({ status: 'error', error: err.message }, { status: 500 });
  }
}
