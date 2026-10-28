import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { restoreEncryptedBackup } from '@/server/backup';
import { applyDesiredState } from '@/server/agent';
import { DesiredStateSchema } from '@axonwall/lib/schemas';

export async function POST(request: NextRequest) {
  const session = await getSession();
  if (!session || session.passwordChangeRequired || !session.roles.includes('admin')) {
    return NextResponse.json(
      {
        success: false,
        error: session?.passwordChangeRequired
          ? 'Password change required: default admin password must be changed first'
          : 'Unauthorized: Admin access required',
      },
      { status: session?.passwordChangeRequired ? 403 : 401 }
    );
  }

  try {
    const formData = await request.formData();
    const file = formData.get('file') as File | null;
    const passphrase = formData.get('passphrase') as string;

    if (!file) {
      return NextResponse.json({ success: false, error: 'No backup file provided' }, { status: 400 });
    }

    if (file.size > 10 * 1024 * 1024) {
      return NextResponse.json(
        { success: false, error: 'Backup file exceeds maximum allowed size (10 MB)' },
        { status: 413 }
      );
    }

    if (!passphrase) {
      return NextResponse.json({ success: false, error: 'Passphrase is required for decryption' }, { status: 400 });
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    const { metadata, state } = await restoreEncryptedBackup(buffer, passphrase);
    const parsedState = DesiredStateSchema.parse(state);
    await applyDesiredState(parsedState, 120);

    return NextResponse.json({
      success: true,
      message: `Successfully decrypted, validated, and applied backup ${metadata.id}.`,
      metadata,
      stateSummary: {
        hostname: parsedState.system.hostname,
        rulesCount: parsedState.rules.length,
        interfacesCount: parsedState.interfaces.length,
      },
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err?.message || 'Restore failed' }, { status: 400 });
  }
}
