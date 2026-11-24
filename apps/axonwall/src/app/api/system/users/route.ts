import fs from 'node:fs';
import { NextRequest, NextResponse } from 'next/server';
import { isPluginEnabled } from '@axonwall/lib/plugins';
import { getSession } from '@/server/auth';
import { assertActionPermitted } from '@/server/auth-guard';
import { getDesiredStateInternal } from '@/server/desired-state-internal';
import { getLocalUsers, getLocalGroups, createLocalUser, getDirectoryStatus } from '@/server/users';

export async function GET() {
  try {
    const session = await getSession();
    assertActionPermitted(session);

    const state = await getDesiredStateInternal();
    const ldapEnabled = isPluginEnabled('directory-ldap', state);
    const zshInstalled = fs.existsSync('/usr/bin/zsh');
    const [users, groups, directoryStatus] = await Promise.all([
      getLocalUsers(),
      getLocalGroups(),
      ldapEnabled ? getDirectoryStatus() : Promise.resolve(null),
    ]);
    return NextResponse.json({ users, groups, directoryStatus, ldapEnabled, zshInstalled });
  } catch (err: any) {
    const status = err.message === 'Unauthorized' ? 401 : err.message?.startsWith('Forbidden') ? 403 : 500;
    return NextResponse.json({ error: err.message }, { status });
  }
}

export async function POST(req: NextRequest) {
  try {
    const session = await getSession();
    assertActionPermitted(session, 'admin');

    const body = await req.json();
    const result = await createLocalUser(body);
    return NextResponse.json(result);
  } catch (err: any) {
    const status = err.message === 'Unauthorized' ? 401 : err.message?.startsWith('Forbidden') ? 403 : 400;
    return NextResponse.json({ error: err.message }, { status });
  }
}
