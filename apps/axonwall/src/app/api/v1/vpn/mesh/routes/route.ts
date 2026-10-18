import { NextResponse } from 'next/server';
import { getMachineRoutes, enableMachineRoutes } from '../../../../../../server/headscale';
import { getSession } from '../../../../../../server/auth';

export async function GET(req: Request) {
  try {
    const session = await getSession();
    if (!session || session.passwordChangeRequired || !session.roles.includes('admin')) {
      return NextResponse.json(
        { error: session?.passwordChangeRequired ? 'Password change required' : 'Unauthorized' },
        { status: session?.passwordChangeRequired ? 403 : 401 }
      );
    }
    const { searchParams } = new URL(req.url);
    const machineId = searchParams.get('machineId');
    if (!machineId) return NextResponse.json({ error: 'machineId is required' }, { status: 400 });

    const routes = await getMachineRoutes(machineId);
    return NextResponse.json({ status: 'ok', data: routes });
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
    const { machineId, routes } = body;
    
    if (!machineId || !Array.isArray(routes)) {
      return NextResponse.json({ error: 'machineId and routes array are required' }, { status: 400 });
    }

    const updatedRoutes = await enableMachineRoutes(machineId, routes);
    return NextResponse.json({ status: 'ok', data: updatedRoutes });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err.message }, { status: 500 });
  }
}
