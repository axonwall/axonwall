import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/server/auth';
import { restoreEncryptedBackup } from '@/server/backup';

export async function POST(request: NextRequest) {
  const session = await getSession();
  if (!session || !session.roles.includes('admin')) {
    return NextResponse.json({ success: false, error: 'Unauthorized: Admin access required' }, { status: 401 });
  }

  try {
    const formData = await request.formData();
    const file = formData.get('file') as File | null;
    const passphrase = formData.get('passphrase') as string;

    if (!file) {
      return NextResponse.json({ success: false, error: 'No backup file provided' }, { status: 400 });
    }

    if (!passphrase) {
      return NextResponse.json({ success: false, error: 'Passphrase is required for decryption' }, { status: 400 });
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    const { metadata, state } = await restoreEncryptedBackup(buffer, passphrase);

    return NextResponse.json({
      success: true,
      message: `Successfully decrypted and validated backup ${metadata.id}. Ready to apply.`,
      metadata,
      stateSummary: {
        hostname: state.system.hostname,
        rulesCount: state.rules.length,
        interfacesCount: state.interfaces.length,
      },
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err?.message || 'Restore failed' }, { status: 400 });
  }
}
