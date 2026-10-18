import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { getCaptureFile } from '@/server/pcap';
import fs from 'fs';

export async function GET(request: NextRequest) {
  const session = await getSession();
  if (!session || !session.roles.includes('admin')) {
    return new NextResponse('Unauthorized: Admin credentials required', { status: 401 });
  }
  if (session.passwordChangeRequired) {
    return new NextResponse('Forbidden: Password change required', { status: 403 });
  }

  const { searchParams } = new URL(request.url);
  const rawId = searchParams.get('id');

  if (!rawId) {
    return new NextResponse('Missing capture id', { status: 400 });
  }

  if (rawId.includes('..') || rawId.includes('/') || rawId.includes('\\')) {
    return new NextResponse('Invalid capture id', { status: 400 });
  }

  const cleanId = rawId.replace(/[^a-zA-Z0-9_.-]/g, '');
  if (!cleanId || cleanId !== rawId) {
    return new NextResponse('Invalid capture id', { status: 400 });
  }

  const { filePath, exists } = getCaptureFile(cleanId);
  if (!exists) {
    return new NextResponse('Capture file not found', { status: 404 });
  }

  const fileBuffer = fs.readFileSync(filePath);

  return new NextResponse(new Uint8Array(fileBuffer), {
    status: 200,
    headers: {
      'Content-Type': 'application/vnd.tcpdump.pcap',
      'Content-Disposition': `attachment; filename="${cleanId}.pcap"`,
      'Content-Length': fileBuffer.length.toString(),
    },
  });
}
