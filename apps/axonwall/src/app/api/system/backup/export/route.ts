import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { createEncryptedBackup } from '@/server/backup';
import { getCurrentDesiredState } from '@/server/agent';

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

  const passphrase = body.passphrase;
  if (!passphrase || typeof passphrase !== 'string' || passphrase.length < 8) {
    return new NextResponse('Passphrase is required and must be at least 8 characters long', { status: 400 });
  }

  try {
    const liveState = await getCurrentDesiredState();
    const { id, buffer } = await createEncryptedBackup(liveState, passphrase);

    return new NextResponse(new Uint8Array(buffer), {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${id}.axb"`,
        'Content-Length': buffer.length.toString(),
      },
    });
  } catch (err: any) {
    return new NextResponse(err?.message || 'Failed to generate backup', { status: 500 });
  }
}

