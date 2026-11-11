import { NextRequest, NextResponse } from 'next/server';
import { manageXdpFastDropAction } from '@/server/agent';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const res = await manageXdpFastDropAction({
      action: 'block',
      ip: String(body?.ip || ''),
      ttlSeconds: body?.ttlSeconds ? Number(body.ttlSeconds) : 3600,
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
    const ip = req.nextUrl.searchParams.get('ip') || '';
    const res = await manageXdpFastDropAction({ action: 'unblock', ip });
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
