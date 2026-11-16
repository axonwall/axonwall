import { NextRequest, NextResponse } from 'next/server';
import {
  annotateThreatHarvesterEpisodeAction,
  listThreatHarvesterEpisodes,
  reviewThreatHarvesterEpisodeAction,
  simulateThreatHarvesterEpisodeAction,
} from '@/server/agent';

function errStatus(msg: string): number {
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 500;
}

export async function GET(req: NextRequest) {
  try {
    const sp = req.nextUrl.searchParams;
    const tier = sp.get('tier') || undefined;
    const reviewStatus = sp.get('reviewStatus') || undefined;
    const limitRaw = sp.get('limit');
    const limit = limitRaw ? Number(limitRaw) : undefined;
    const data = await listThreatHarvesterEpisodes({ tier, reviewStatus, limit });
    return NextResponse.json({ status: 'ok', ...data });
  } catch (err: any) {
    const msg = err?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(msg) });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const op = String(body?.op || '');

    if (op === 'review') {
      const res = await reviewThreatHarvesterEpisodeAction({
        id: String(body?.id || ''),
        action: body?.action,
      });
      if (!res.success) {
        return NextResponse.json({ status: 'error', error: res.error }, { status: 400 });
      }
      return NextResponse.json({ status: 'ok', ...res });
    }

    if (op === 'annotate') {
      const res = await annotateThreatHarvesterEpisodeAction(String(body?.id || ''));
      if (!res.success) {
        return NextResponse.json({ status: 'error', error: res.error }, { status: 400 });
      }
      return NextResponse.json({ status: 'ok', ...res });
    }

    if (op === 'simulate') {
      const res = await simulateThreatHarvesterEpisodeAction(body?.scenario);
      if (!res.success) {
        return NextResponse.json({ status: 'error', error: res.error }, { status: 400 });
      }
      return NextResponse.json({ status: 'ok', ...res });
    }

    return NextResponse.json(
      { status: 'error', error: 'Invalid op; expected review, annotate, or simulate' },
      { status: 400 }
    );
  } catch (err: any) {
    const msg = err?.message || 'Internal server error';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(msg) });
  }
}
