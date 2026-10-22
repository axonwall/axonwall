import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { exportCloudInitConfigAction } from '@/server/agent';
import { buildNoCloudIso, type CloudInitExportOptions } from '@axonwall/lib/cloudinit';

export async function POST(request: NextRequest) {
  const session = await getSession();
  if (!session || session.passwordChangeRequired || !session.roles.includes('admin')) {
    return new NextResponse(
      session?.passwordChangeRequired
        ? 'Forbidden: Password change required'
        : 'Unauthorized: Admin access required',
      { status: session?.passwordChangeRequired ? 403 : 401 }
    );
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const format: 'yaml' | 'iso' | 'metadata' =
    body.format === 'iso' ? 'iso' : body.format === 'metadata' ? 'metadata' : 'yaml';

  const options: CloudInitExportOptions = {
    redactSecrets: body.redactSecrets !== false,
    templateMode: Boolean(body.templateMode),
    includeStorage: body.includeStorage !== false,
    includeUsers: body.includeUsers !== false,
    includePackages: body.includePackages !== false,
    hostnameOverride:
      typeof body.hostnameOverride === 'string' && body.hostnameOverride.trim()
        ? body.hostnameOverride.trim()
        : undefined,
  };

  try {
    const snapshot = await exportCloudInitConfigAction(options);
    const dateSuffix = new Date().toISOString().slice(0, 10);

    if (format === 'iso') {
      const isoBytes = buildNoCloudIso(snapshot.yaml, snapshot.metaData);
      const filename = `axonwall-${snapshot.hostname}-cidata-${dateSuffix}.iso`;
      return new NextResponse(new Uint8Array(isoBytes), {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Content-Length': isoBytes.byteLength.toString(),
        },
      });
    }

    if (format === 'metadata') {
      return new NextResponse(snapshot.metaData, {
        status: 200,
        headers: {
          'Content-Type': 'text/yaml;charset=utf-8',
          'Content-Disposition': `attachment; filename="meta-data"`,
        },
      });
    }

    const filename = `axonwall-${snapshot.hostname}-cloud-config-${dateSuffix}.yaml`;
    return new NextResponse(snapshot.yaml, {
      status: 200,
      headers: {
        'Content-Type': 'text/yaml;charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
      },
    });
  } catch (err: any) {
    return new NextResponse(err?.message || 'Failed to generate Cloud-Init export', {
      status: 500,
    });
  }
}
