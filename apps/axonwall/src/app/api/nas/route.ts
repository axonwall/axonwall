import { NextResponse } from 'next/server';
import {
  getNasDisksInventory,
  getNasPoolsRuntime,
  getNasSnapshotsRuntime,
  createNasSnapshotAction,
  scrubNasPoolAction,
} from '@/server/agent';

export async function GET() {
  try {
    const [diskData, pools, snapshots] = await Promise.all([
      getNasDisksInventory(),
      getNasPoolsRuntime(),
      getNasSnapshotsRuntime(),
    ]);
    return NextResponse.json({
      disks: diskData.disks,
      installSpec: diskData.installSpec,
      pools,
      snapshots,
    });
  } catch (err: any) {
    const status = err?.message?.includes('Unauthorized')
      ? 401
      : err?.message?.includes('Forbidden') || err?.message?.toLowerCase().includes('admin')
        ? 403
        : 500;
    return NextResponse.json({ error: err?.message || 'Failed to fetch NAS status' }, { status });
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    if (body.action === 'snapshot') {
      const res = await createNasSnapshotAction(body.dataset, body.label);
      return NextResponse.json(res);
    }
    if (body.action === 'scrub') {
      const res = await scrubNasPoolAction(body.pool);
      return NextResponse.json(res);
    }
    return NextResponse.json({ error: 'Unknown NAS action' }, { status: 400 });
  } catch (err: any) {
    const status = err?.message?.includes('Unauthorized')
      ? 401
      : err?.message?.includes('Forbidden') || err?.message?.toLowerCase().includes('admin')
        ? 403
        : 500;
    return NextResponse.json({ error: err?.message || 'NAS action failed' }, { status });
  }
}
