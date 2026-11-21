import { NextResponse } from 'next/server';
import { confirmActiveRuleset } from '../../../../server/agent';

export async function POST(req: Request) {
  try {
    let jobId: string | undefined;
    try {
      const body = await req.json();
      if (typeof body?.jobId === 'string' && body.jobId.trim()) {
        jobId = body.jobId.trim();
      }
    } catch {
      // Optional empty POST body stays supported
    }
    const result = await confirmActiveRuleset(jobId);
    if (!result.success) {
      const msg = result.message || 'Failed to confirm ruleset';
      const status = msg.toLowerCase().includes('unavailable') || msg.toLowerCase().includes('unreachable') ? 502 : 409;
      return NextResponse.json(
        { status: 'error', error: msg, data: result },
        { status }
      );
    }
    return NextResponse.json({
      status: 'ok',
      data: result,
    });
  } catch (err: any) {
    const statusCode = err.message?.includes('Unauthorized')
      ? 401
      : err.message?.includes('Forbidden') || err.message?.toLowerCase().includes('admin')
        ? 403
        : 500;
    return NextResponse.json(
      { status: 'error', error: err.message },
      { status: statusCode }
    );
  }
}
