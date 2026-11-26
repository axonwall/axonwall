import { NextRequest, NextResponse } from 'next/server';
import { syncTopologyLibreNmsAction, syncTopologyNetBoxAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  if (msg.includes('Rate limit') || msg.includes('Too Many Requests')) return 429;
  return 500;
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json().catch(() => ({}))) as {
      target?: 'netbox' | 'librenms';
      action?: 'preview' | 'push' | 'pull' | 'enroll';
      dryRun?: boolean;
      overwriteLabels?: boolean;
      devices?: Array<{ name: string; role?: string; model?: string; mfg?: string; primaryIp?: string; status?: string; comments?: string }>;
      cables?: Array<{ aDevice: string; aInterface: string; bDevice: string; bInterface: string; type?: string; status?: string; label?: string; color?: string; length?: number; lengthUnit?: string; comments?: string }>;
    };
    const target = body?.target === 'librenms' ? 'librenms' : 'netbox';
    if (target === 'librenms') {
      const action = body?.action === 'push' || body?.action === 'pull' || body?.action === 'enroll' ? body.action : 'preview';
      const data = await syncTopologyLibreNmsAction({
        action,
        dryRun: body?.dryRun,
        overwriteLabels: Boolean(body?.overwriteLabels),
      });
      return NextResponse.json({ status: data.success ? 'ok' : 'error', data }, { status: data.success ? 200 : 502 });
    }
    const action = body?.action === 'push' || body?.action === 'pull' ? body.action : 'preview';
    const data = await syncTopologyNetBoxAction({
      action,
      dryRun: body?.dryRun,
      overwriteLabels: Boolean(body?.overwriteLabels),
      devices: body?.devices,
      cables: body?.cables,
    });
    return NextResponse.json({ status: data.success !== false ? 'ok' : 'error', data });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
