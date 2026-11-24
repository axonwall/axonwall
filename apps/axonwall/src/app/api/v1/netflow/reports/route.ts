import { NextRequest, NextResponse } from 'next/server';
import { generateNetFlowReportAction, getNetFlowReportAction } from '@/server/agent';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 400;
}

export async function GET(req: NextRequest) {
  try {
    const sp = req.nextUrl.searchParams;
    const rangeDays = Number(sp.get('rangeDays') || 7) || 7;
    const groupBy = sp.get('groupBy') || 'interface';
    const format = (sp.get('format') || 'json') as 'json' | 'csv' | 'markdown';
    const data = await getNetFlowReportAction({ rangeDays, groupBy, format });
    if (sp.get('raw') === '1' && (format === 'csv' || format === 'markdown') && data.rendered) {
      return new NextResponse(data.rendered, {
        status: 200,
        headers: {
          'Content-Type': format === 'csv' ? 'text/csv; charset=utf-8' : 'text/markdown; charset=utf-8',
          'Content-Disposition': `attachment; filename="axonwall-netflow-p95-${rangeDays}d.${format === 'csv' ? 'csv' : 'md'}"`,
        },
      });
    }
    return NextResponse.json({ status: 'ok', data });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to compute NetFlow report';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json().catch(() => ({}))) as {
      rangeDays?: number;
      groupBy?: string;
      format?: 'json' | 'csv' | 'markdown';
    };
    const data = await generateNetFlowReportAction(body);
    return NextResponse.json({ status: 'ok', data });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to generate NetFlow report snapshot';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
