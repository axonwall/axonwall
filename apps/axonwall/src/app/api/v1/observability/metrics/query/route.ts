import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import {
  queryVictoriaMetricsInstant,
  queryVictoriaMetricsRange,
} from '@/server/observability-clients';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 400;
}

async function handleQuery(params: {
  query?: string;
  start?: number;
  end?: number;
  step?: number;
  time?: number;
}) {
  const q = String(params.query || '').trim();
  if (!q) {
    return NextResponse.json({ status: 'error', error: 'Missing query parameter' }, { status: 400 });
  }
  const isRange =
    typeof params.start === 'number' &&
    typeof params.end === 'number' &&
    Number.isFinite(params.start) &&
    Number.isFinite(params.end);

  const data = isRange
    ? await queryVictoriaMetricsRange(q, params.start!, params.end!, params.step ?? 60)
    : await queryVictoriaMetricsInstant(q, { timeSec: params.time });

  return NextResponse.json({ status: data.status, data });
}

export async function GET(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session);
    const sp = req.nextUrl.searchParams;
    const toNum = (v: string | null) => (v !== null && v !== '' && !Number.isNaN(Number(v)) ? Number(v) : undefined);
    return await handleQuery({
      query: sp.get('query') || sp.get('q') || '',
      start: toNum(sp.get('start')),
      end: toNum(sp.get('end')),
      step: toNum(sp.get('step')),
      time: toNum(sp.get('time')),
    });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to query metrics';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session);
    const body = (await req.json().catch(() => ({}))) as {
      query?: string;
      start?: number;
      end?: number;
      step?: number;
      time?: number;
    };
    return await handleQuery(body);
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to query metrics';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
