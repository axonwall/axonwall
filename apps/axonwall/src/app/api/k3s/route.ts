import { NextResponse } from 'next/server';
import {
  getK3sRuntimeStatus,
  triggerK3sHaAutoJoin,
  getK3sEtcdSnapshotsAction,
  manageK3sEtcdSnapshotAction,
} from '@/server/agent';

export async function GET() {
  try {
    const [status, etcdSnapshots] = await Promise.all([
      getK3sRuntimeStatus(),
      getK3sEtcdSnapshotsAction().catch(() => []),
    ]);
    return NextResponse.json({ ...status, etcdSnapshots });
  } catch (err: any) {
    const status = err?.message?.includes('Unauthorized')
      ? 401
      : err?.message?.includes('Forbidden') || err?.message?.toLowerCase().includes('admin')
        ? 403
        : 500;
    return NextResponse.json({ error: err?.message || 'Failed to fetch K3s status' }, { status });
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    if (body.action === 'join') {
      const res = await triggerK3sHaAutoJoin();
      return NextResponse.json(res);
    }
    if (body.action === 'etcd-save' || body.action === 'etcd-restore') {
      const res = await manageK3sEtcdSnapshotAction(
        body.action === 'etcd-save' ? 'save' : 'restore',
        body.name || ''
      );
      return NextResponse.json(res);
    }
    return NextResponse.json({ error: 'Unknown K3s action' }, { status: 400 });
  } catch (err: any) {
    const status = err?.message?.includes('Unauthorized')
      ? 401
      : err?.message?.includes('Forbidden') || err?.message?.toLowerCase().includes('admin')
        ? 403
        : 500;
    return NextResponse.json({ error: err?.message || 'K3s action failed' }, { status });
  }
}
