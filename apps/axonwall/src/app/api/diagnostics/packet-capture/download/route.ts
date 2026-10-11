import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { getCaptureFile } from '@/server/pcap';
import fs from 'fs';

export async function GET(request: NextRequest) {
  const session = await getSession();
  if (!session) {
    return new NextResponse('Unauthorized', { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');

  if (!id) {
    return new NextResponse('Missing capture id', { status: 400 });
  }

  const { filePath, exists } = getCaptureFile(id);
  if (!exists) {
    return new NextResponse('Capture file not found', { status: 404 });
  }

  const fileBuffer = fs.readFileSync(filePath);

  return new NextResponse(new Uint8Array(fileBuffer), {
    status: 200,
    headers: {
      'Content-Type': 'application/vnd.tcpdump.pcap',
      'Content-Disposition': `attachment; filename="${id}.pcap"`,
      'Content-Length': fileBuffer.length.toString(),
    },
  });
}
