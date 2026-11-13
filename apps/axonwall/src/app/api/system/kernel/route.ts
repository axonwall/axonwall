import { NextRequest, NextResponse } from 'next/server';
import {
  getKernelStudioTelemetry,
  getKernelTaskProgress,
  installBuiltKernelArtifact,
  previewCustomKernelSpec,
  triggerCustomKernelBuild,
} from '@/server/kernel-studio';

export const dynamic = 'force-dynamic';

function mapErrorStatus(message: string): number {
  if (message.includes('Unauthorized')) return 401;
  if (message.includes('Forbidden') || message.toLowerCase().includes('admin')) return 403;
  return 400;
}

export async function GET(req: NextRequest) {
  try {
    const upid = req.nextUrl.searchParams.get('upid');
    if (upid) {
      const progress = await getKernelTaskProgress(upid);
      return NextResponse.json({
        success: true,
        ...(progress || { taskProgress: null, artifacts: [] }),
      });
    }
    const studio = await getKernelStudioTelemetry();
    return NextResponse.json({
      success: true,
      studio,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ success: false, message }, { status: mapErrorStatus(message) });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const action = body?.action;
    if (action !== 'preview' && action !== 'build' && action !== 'install') {
      return NextResponse.json(
        { success: false, message: `Missing or unknown action: ${typeof action === 'string' ? action : 'none'}.` },
        { status: 400 }
      );
    }

    if (action === 'preview') {
      const compiled = await previewCustomKernelSpec(body?.spec || {});
      return NextResponse.json({ success: true, compiled });
    }

    if (action === 'build') {
      const configOnly = Boolean(body?.configOnly);
      const result = await triggerCustomKernelBuild(body?.spec || {}, configOnly);
      return NextResponse.json(result, { status: result.success ? 200 : 400 });
    }

    const result = await installBuiltKernelArtifact(String(body?.artifactName || ''));
    return NextResponse.json(result, { status: result.success ? 200 : 400 });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ success: false, message }, { status: mapErrorStatus(message) });
  }
}
