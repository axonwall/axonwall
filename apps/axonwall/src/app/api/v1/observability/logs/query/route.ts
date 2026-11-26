import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { queryVictoriaLogs } from '@/server/observability-clients';

function errStatus(err: unknown): number {
  const msg = String((err as { message?: string })?.message || '');
  if (msg.includes('Unauthorized')) return 401;
  if (msg.includes('Forbidden')) return 403;
  return 400;
}

function escapeLogsQLValue(val: string): string {
  return val.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function splitLogsQLTopLevelPipe(rawQ: string): { head: string; pipeSuffix: string } {
  let inQuotes = false;
  let escaped = false;
  let parenDepth = 0;

  for (let i = 0; i < rawQ.length; i += 1) {
    const ch = rawQ[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\' && inQuotes) {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (inQuotes) {
      continue;
    }
    if (ch === '(') {
      parenDepth += 1;
    } else if (ch === ')' && parenDepth > 0) {
      parenDepth -= 1;
    } else if (ch === '|' && parenDepth === 0) {
      return {
        head: rawQ.slice(0, i).trim(),
        pipeSuffix: rawQ.slice(i).trim(),
      };
    }
  }

  return { head: rawQ.trim(), pipeSuffix: '' };
}

function buildLogsQLQuery(params: {
  q?: string;
  nodeId?: string;
  source?: string;
  level?: string;
}): string {
  const clauses: string[] = [];
  const nodeId = String(params.nodeId || '').trim();
  if (nodeId && nodeId !== 'all') {
    clauses.push(`node_id:"${escapeLogsQLValue(nodeId)}"`);
  }
  const source = String(params.source || '').trim();
  if (source && source !== 'all') {
    clauses.push(`source:"${escapeLogsQLValue(source)}"`);
  }
  const level = String(params.level || '').trim();
  if (level && level !== 'all') {
    clauses.push(`level:"${escapeLogsQLValue(level)}"`);
  }
  const rawQ = String(params.q || '').trim();
  if (rawQ) {
    const { head, pipeSuffix } = splitLogsQLTopLevelPipe(rawQ);
    if (head) {
      clauses.push(head === '*' ? '*' : `(${head})`);
    } else if (clauses.length === 0) {
      clauses.push('*');
    }
    if (pipeSuffix) {
      clauses.push(pipeSuffix);
    }
  }
  return clauses.length > 0 ? clauses.join(' ') : '*';
}

async function handleQuery(params: {
  q?: string;
  query?: string;
  nodeId?: string;
  source?: string;
  level?: string;
  start?: string;
  end?: string;
  limit?: number;
}) {
  const logsql = buildLogsQLQuery({
    q: params.query ?? params.q,
    nodeId: params.nodeId,
    source: params.source,
    level: params.level,
  });
  const data = await queryVictoriaLogs(logsql, {
    start: params.start,
    end: params.end,
    limit: params.limit,
  });
  return NextResponse.json({ status: data.status, query: logsql, data });
}

export async function GET(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session);
    const sp = req.nextUrl.searchParams;
    const rawLimit = sp.get('limit');
    const limit = rawLimit && !Number.isNaN(Number(rawLimit)) ? Number(rawLimit) : undefined;
    return await handleQuery({
      q: sp.get('q') || '',
      query: sp.get('query') ?? undefined,
      nodeId: sp.get('nodeId') || '',
      source: sp.get('source') || '',
      level: sp.get('level') || '',
      start: sp.get('start') || undefined,
      end: sp.get('end') || undefined,
      limit,
    });
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to query logs';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session);
    const body = (await req.json().catch(() => ({}))) as {
      q?: string;
      query?: string;
      nodeId?: string;
      source?: string;
      level?: string;
      start?: string;
      end?: string;
      limit?: number;
    };
    return await handleQuery(body);
  } catch (err: unknown) {
    const msg = (err as { message?: string })?.message || 'Failed to query logs';
    return NextResponse.json({ status: 'error', error: msg }, { status: errStatus(err) });
  }
}
