import { NextRequest, NextResponse } from 'next/server';
import {
  getReleaseInfo,
  getSystemPartitionsTelemetry,
  applySystemFirmwareUpdate,
  activatePartitionSlot,
  verifySystemHealthQuorum,
  createZbmSnapshot,
  cloneZbmSnapshot,
  activateZbmBootEnvironment,
  deleteZbmBootEnvironment,
  deleteZbmSnapshot,
  rollbackZbmSnapshot,
} from '@/server/agent';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const forceRefresh = req.nextUrl.searchParams.get('refresh') === '1';
    const [releaseInfo, telemetry] = await Promise.all([
      getReleaseInfo(forceRefresh),
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
    // C14: a bare POST used to default to a firmware update of slot B
    // (`body?.action || 'update'`, any slot other than exactly 'A'
    // coerced to 'B'). Destructive defaults must fail closed: the
    // action is required and must be known, and update/activate
    // require an explicit slot of exactly 'A' or 'B'. The other
    // actions (verify, zbm-*) take no slot.
    const action = body?.action;
    const knownActions = [
      'update',
      'activate',
      'verify',
      'zbm-snapshot',
      'zbm-delete-snapshot',
      'zbm-rollback-snapshot',
      'zbm-clone',
      'zbm-activate',
      'zbm-delete',
    ];
    if (typeof action !== 'string' || !knownActions.includes(action)) {
      return NextResponse.json(
        { success: false, message: `Missing or unknown action: ${typeof action === 'string' ? action : 'none'}. An explicit action is required.` },
        { status: 400 }
      );
    }
    if (action === 'update' || action === 'activate') {
      if (body?.slot !== 'A' && body?.slot !== 'B') {
        return NextResponse.json(
          { success: false, message: `Invalid slot: ${JSON.stringify(body?.slot ?? null)}. An explicit slot of 'A' or 'B' is required for action '${action}'.` },
          { status: 400 }
        );
      }
    }
    const slot: 'A' | 'B' = body?.slot;

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
      // C-B3: a failed quorum used to be wrapped as success: true, which
      // made the page's `if (!data.success)` check dead. Surface the
      // failure so the page reports the actual check statuses.
      try {
        const result = await verifySystemHealthQuorum();
        return NextResponse.json({ success: true, ...result });
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        const status = message.includes('Unauthorized')
          ? 401
          : message.includes('Admin') || message.includes('Forbidden')
            ? 403
            : 400;
        return NextResponse.json({ success: false, message }, { status });
      }
    }

    if (action === 'zbm-snapshot') {
      const result = await createZbmSnapshot(
        body?.beName || '',
        body?.label || '',
        body?.newBeName || undefined
      );
      const status = result.success ? 200 : result.message.includes('Unauthorized') ? 401 : 400;
      return NextResponse.json(result, { status });
    }

    if (action === 'zbm-delete-snapshot') {
      const result = await deleteZbmSnapshot(body?.snapshot || '');
      const status = result.success ? 200 : result.message.includes('Unauthorized') ? 401 : 400;
      return NextResponse.json(result, { status });
    }

    if (action === 'zbm-rollback-snapshot') {
      const result = await rollbackZbmSnapshot(body?.snapshot || '');
      const status = result.success ? 200 : result.message.includes('Unauthorized') ? 401 : 400;
      return NextResponse.json(result, { status });
    }

    if (action === 'zbm-clone') {
      const result = await cloneZbmSnapshot(body?.snapshot || '', body?.newBeName || '');
      const status = result.success ? 200 : result.message.includes('Unauthorized') ? 401 : 400;
      return NextResponse.json(result, { status });
    }

    if (action === 'zbm-activate') {
      const result = await activateZbmBootEnvironment(body?.beName || '');
      const status = result.success ? 200 : result.message.includes('Unauthorized') ? 401 : 400;
      return NextResponse.json(result, { status });
    }

    if (action === 'zbm-delete') {
      const result = await deleteZbmBootEnvironment(body?.beName || '');
      const status = result.success ? 200 : result.message.includes('Unauthorized') ? 401 : 400;
      return NextResponse.json(result, { status });
    }

    // Unreachable: `action` was validated against knownActions above,
    // so every known action has returned by here.
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    // C14: an unparseable (including empty) body is a client error,
    // not a 500 — a bare POST must fail closed with a 400.
    if (err instanceof SyntaxError || message.toLowerCase().includes('json')) {
      return NextResponse.json({ success: false, message: 'Invalid JSON body' }, { status: 400 });
    }
    const status = message.includes('Unauthorized')
      ? 401
      : message.includes('Forbidden') || message.toLowerCase().includes('admin')
        ? 403
        : 500;
    return NextResponse.json({ success: false, message }, { status });
  }
}
