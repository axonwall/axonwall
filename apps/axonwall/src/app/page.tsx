import { redirect } from 'next/navigation';
import { getSession } from '../server/auth';

export default async function HomePage() {
  const session = await getSession();
  if (session) {
    redirect('/lobby');
  } else {
    redirect('/login');
  }
}
