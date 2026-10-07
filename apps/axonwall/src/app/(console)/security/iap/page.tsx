import { getSession } from '@/server/auth';
import { redirect } from 'next/navigation';

export default async function IAPDashboardPage() {
  const session = await getSession();
  if (!session) redirect('/login');

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-slate-100 mb-6">Identity-Aware Proxy (IAP)</h1>
      <p className="text-slate-400 mb-6">Publish internal applications securely with Zero Trust.</p>
      
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold text-slate-200">Published Applications</h2>
          <button className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md text-sm font-medium">
            Add Application
          </button>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="text-xs text-slate-400 uppercase bg-slate-800 border-b border-slate-700">
              <tr>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Public Hostname</th>
                <th className="px-4 py-3">Internal Upstream</th>
                <th className="px-4 py-3">Allowed Roles</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  No applications published yet.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
