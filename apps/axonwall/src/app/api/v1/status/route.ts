import { NextResponse } from 'next/server';
import { getAgentStatus } from '../../../../server/agent';

export async function GET() {
  const status = await getAgentStatus();
  return NextResponse.json({
    status: 'ok',
    data: status,
  });
}
