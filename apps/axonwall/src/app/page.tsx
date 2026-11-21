import { redirect } from 'next/navigation';
import { getSession } from '../server/auth';
import { isVpnPortalOnlyUser } from '../server/auth-guard';

export default async function HomePage() {
  const session = await getSession();
  if (session) {
    redirect(isVpnPortalOnlyUser(session) ? '/vpn' : '/lobby');
  } else {
    redirect('/login');
  }
}
