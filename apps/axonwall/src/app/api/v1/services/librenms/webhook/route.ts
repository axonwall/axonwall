import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { callAgentApiDetailed } from '@/server/agent-client';
import { checkPluginApiGuard } from '@/server/plugin-guard';

export async function GET() {
  try {
    const session = await getSession();
    assertActionPermitted(session);
    const guard = await checkPluginApiGuard('librenms');
    if (guard) return guard;
    const res = await callAgentApiDetailed<{ alerts: unknown[] }>('/v1/librenms/webhook', 'GET', undefined, 5_000);
    if (res.kind !== 'ok') {
      return NextResponse.json({ status: 'error', error: res.kind === 'http_error' ? res.message : 'Daemon unreachable' }, { status: 502 });
    }
    return NextResponse.json({ status: 'ok', data: res.data });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Unauthorized';
    const code = msg.includes('Unauthorized') ? 401 : msg.includes('Forbidden') ? 403 : 500;
    return NextResponse.json({ status: 'error', error: msg }, { status: code });
  }
}

export async function POST(req: NextRequest) {
  try {
    const headerSecret =
      req.headers.get('x-axonwall-webhook-secret')?.trim() ||
      (req.headers.get('authorization')?.toLowerCase().startsWith('bearer ')
        ? req.headers.get('authorization')!.slice(7).trim()
        : '');
    if (!headerSecret) {
      return NextResponse.json({ status: 'error', error: 'Missing X-Axonwall-Webhook-Secret header' }, { status: 401 });
    }
    const guard = await checkPluginApiGuard('librenms');
    if (guard) return guard;
    const payload = await req.json().catch(() => null);
    if (!payload || typeof payload !== 'object') {
      return NextResponse.json({ status: 'error', error: 'Invalid webhook JSON payload' }, { status: 400 });
    }
    const res = await callAgentApiDetailed<{ success: boolean; alert?: unknown }>(
      '/v1/librenms/webhook',
      'POST',
      payload,
      5_000,
      { 'X-Axonwall-Webhook-Secret': headerSecret },
    );
    if (res.kind === 'http_error') {
      return NextResponse.json({ status: 'error', error: res.message }, { status: res.status });
    }
    if (res.kind !== 'ok') {
      return NextResponse.json({ status: 'error', error: 'axonwalld unreachable' }, { status: 502 });
    }
    return NextResponse.json({ status: 'ok', data: res.data });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: 500 });
  }
}
