import { NextRequest, NextResponse } from 'next/server';
import { manageBpfTokenProfileAction } from '@/server/agent';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const res = await manageBpfTokenProfileAction({
      action: 'create',
      name: String(body?.name || ''),
      preset: body?.preset,
      workloadTarget: body?.workloadTarget,
    });
    if (!res.success) {
      return NextResponse.json({ status: 'error', error: res.error }, { status: 400 });
    }
    return NextResponse.json({ status: 'ok', ...res });
  } catch (err: any) {
    const msg = err?.message || 'Internal server error';
    const code = msg.includes('Unauthorized') ? 401 : msg.includes('Forbidden') ? 403 : 500;
    return NextResponse.json({ status: 'error', error: msg }, { status: code });
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const name = req.nextUrl.searchParams.get('name') || '';
    const res = await manageBpfTokenProfileAction({ action: 'delete', name });
    if (!res.success) {
      return NextResponse.json({ status: 'error', error: res.error }, { status: 400 });
    }
    return NextResponse.json({ status: 'ok', ...res });
  } catch (err: any) {
    const msg = err?.message || 'Internal server error';
    const code = msg.includes('Unauthorized') ? 401 : msg.includes('Forbidden') ? 403 : 500;
    return NextResponse.json({ status: 'error', error: msg }, { status: code });
  }
}
