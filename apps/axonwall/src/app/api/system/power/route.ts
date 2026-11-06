import { NextRequest, NextResponse } from 'next/server';
import { rebootSystemAction, poweroffSystemAction } from '@/server/agent';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    let body: any;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        { success: false, message: 'Invalid JSON body. An explicit action is required: \'reboot\' or \'poweroff\'.' },
        { status: 400 }
      );
    }
    // C-B18: a bare POST used to default to 'reboot' (`body?.action ||
    // 'reboot'`). The update route was fixed per C14 to require an
    // explicit action, but this route still rebooted the box on an
    // empty body. Destructive defaults must fail closed: the action
    // is required and must be known.
    const action = body?.action;
    if (action !== 'reboot' && action !== 'poweroff' && action !== 'shutdown') {
      return NextResponse.json(
        {
          success: false,
          message: `Missing or invalid power action: ${JSON.stringify(action ?? null)}. An explicit action is required: 'reboot' or 'poweroff'.`,
        },
        { status: 400 }
      );
    }
    const slot: 'A' | 'B' | undefined = body?.slot === 'A' || body?.slot === 'B' ? body.slot : undefined;

    if (action === 'reboot') {
      const result = await rebootSystemAction(slot);
      return NextResponse.json(result, { status: result.success ? 200 : 400 });
    }

    const result = await poweroffSystemAction();
    return NextResponse.json(result, { status: result.success ? 200 : 400 });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const status = message === 'Unauthorized' ? 401 : message.startsWith('Forbidden') ? 403 : 500;
    return NextResponse.json({ success: false, message }, { status });
  }
}
