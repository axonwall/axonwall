import { getSession } from '@/server/auth';
import { redirect } from 'next/navigation';
import { getTopFlows } from '@/server/clickhouse';

export default async function FlowsDashboardPage() {
  const session = await getSession();
  if (!session) redirect('/login');

  const flows = await getTopFlows();

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-slate-100 mb-6">Historical Flow Forensics</h1>
      
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
        <h2 className="text-xl font-semibold text-slate-200 mb-4">Top Flows (eBPF)</h2>
        {flows.length === 0 ? (
          <p className="text-slate-400">No flow data available or ClickHouse not connected.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="text-xs text-slate-400 uppercase bg-slate-800 border-b border-slate-700">
                <tr>
                  <th className="px-4 py-3">Source IP</th>
                  <th className="px-4 py-3">Destination IP</th>
                  <th className="px-4 py-3">Protocol</th>
                  <th className="px-4 py-3 text-right">Packets</th>
                  <th className="px-4 py-3 text-right">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((flow: any, i: number) => (
                  <tr key={i} className="border-b border-slate-700/50 hover:bg-slate-800/80">
                    <td className="px-4 py-3 font-mono">{flow.src_ip}</td>
                    <td className="px-4 py-3 font-mono">{flow.dst_ip}</td>
                    <td className="px-4 py-3">{flow.protocol}</td>
                    <td className="px-4 py-3 text-right">{flow.total_packets}</td>
                    <td className="px-4 py-3 text-right">{flow.total_bytes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
