import { NextRequest, NextResponse } from 'next/server';
import {
  getReleaseInfo,
  getSystemPartitionsTelemetry,
  applySystemFirmwareUpdate,
  activatePartitionSlot,
  verifySystemHealthQuorum,
} from '@/server/agent';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const [releaseInfo, telemetry] = await Promise.all([
      getReleaseInfo(),
      getSystemPartitionsTelemetry(),
    ]);
    return NextResponse.json({
      success: true,
      releaseInfo,
      telemetry,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const status = message.includes('Unauthorized')
      ? 401
      : message.includes('Forbidden') || message.toLowerCase().includes('admin')
        ? 403
        : 500;
    return NextResponse.json({ success: false, message }, { status });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const action = body?.action || 'update';
    const slot: 'A' | 'B' = body?.slot === 'A' ? 'A' : 'B';

    if (action === 'update') {
      const result = await applySystemFirmwareUpdate(slot);
      const status = result.success
        ? 200
        : result.message.includes('Unauthorized')
          ? 401
          : result.message.includes('Administrator') || result.message.includes('Forbidden')
            ? 403
            : 400;
      return NextResponse.json(result, { status });
    }

    if (action === 'activate') {
      const result = await activatePartitionSlot(slot);
      const status = result.success
        ? 200
        : result.message.includes('Unauthorized')
          ? 401
          : result.message.includes('Admin') || result.message.includes('Forbidden')
            ? 403
            : 400;
      return NextResponse.json(result, { status });
    }

    if (action === 'verify') {
      const result = await verifySystemHealthQuorum();
      return NextResponse.json({ success: true, ...result });
    }

    return NextResponse.json(
      { success: false, message: `Unknown action: ${action}` },
      { status: 400 }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const status = message.includes('Unauthorized')
      ? 401
      : message.includes('Forbidden') || message.toLowerCase().includes('admin')
        ? 403
        : 500;
    return NextResponse.json({ success: false, message }, { status });
  }
}
