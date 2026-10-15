import { NextRequest, NextResponse } from 'next/server';
import { rebootSystemAction, poweroffSystemAction } from '@/server/agent';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const action = body?.action || 'reboot';
    const slot: 'A' | 'B' | undefined = body?.slot === 'A' || body?.slot === 'B' ? body.slot : undefined;

    if (action === 'reboot') {
      const result = await rebootSystemAction(slot);
      return NextResponse.json(result, { status: result.success ? 200 : 400 });
    }

    if (action === 'poweroff' || action === 'shutdown') {
      const result = await poweroffSystemAction();
      return NextResponse.json(result, { status: result.success ? 200 : 400 });
    }

    return NextResponse.json(
      { success: false, message: `Invalid power action: ${action}. Expected 'reboot' or 'poweroff'.` },
      { status: 400 }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ success: false, message }, { status: 500 });
  }
}
