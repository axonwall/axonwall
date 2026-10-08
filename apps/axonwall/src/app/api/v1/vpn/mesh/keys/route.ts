import { NextResponse } from 'next/server';
import { listPreAuthKeys, createPreAuthKey, expirePreAuthKey } from '../../../../../../server/headscale';
import { getSession } from '../../../../../../server/auth';

export async function GET(req: Request) {
  try {
    const session = await getSession();
    if (!session || !session.roles.includes('admin')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    const { searchParams } = new URL(req.url);
    const user = searchParams.get('user') || undefined;
    const keys = await listPreAuthKeys(user);
    return NextResponse.json({ status: 'ok', data: keys });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err.message }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    const session = await getSession();
    if (!session || !session.roles.includes('admin')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    const body = await req.json();
    const { action, user, reusable, ephemeral, expiration, key } = body;
    
    if (action === 'expire') {
      if (!user || !key) return NextResponse.json({ error: 'user and key required' }, { status: 400 });
      await expirePreAuthKey(user, key);
      return NextResponse.json({ status: 'ok' });
    }
    
    // Create new key
    if (!user) return NextResponse.json({ error: 'user is required' }, { status: 400 });
    const newKey = await createPreAuthKey(
      user, 
      !!reusable, 
      !!ephemeral, 
      expiration || new Date(Date.now() + 86400000 * 30).toISOString() // default 30 days
    );
    return NextResponse.json({ status: 'ok', data: newKey });
  } catch (err: any) {
    return NextResponse.json({ status: 'error', error: err.message }, { status: 500 });
  }
}
