import { NextResponse } from 'next/server';
import { getMachineRoutes, enableMachineRoutes } from '../../../../../../server/headscale';
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
    const machineId = searchParams.get('machineId');
    if (!machineId) return NextResponse.json({ error: 'machineId is required' }, { status: 400 });

    const routes = await getMachineRoutes(machineId);
    return NextResponse.json({ status: 'ok', data: routes });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err?.message || 'Failed to get routes' }, { status: mapMeshErrStatus(err) });
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
    const { machineId, routes } = body;
    
    if ((!machineId && machineId !== 0) || (typeof machineId !== 'string' && typeof machineId !== 'number') || !Array.isArray(routes)) {
      return NextResponse.json({ error: 'machineId and routes array are required' }, { status: 400 });
    }

    const updatedRoutes = await enableMachineRoutes(machineId, routes);
    return NextResponse.json({ status: 'ok', data: updatedRoutes });
  } catch (err: any) {
    const message = err instanceof SyntaxError ? 'Invalid JSON request body' : err?.message || 'Route operation failed';
    return NextResponse.json({ status: 'error', error: message }, { status: mapMeshErrStatus(err) });
  }
}
