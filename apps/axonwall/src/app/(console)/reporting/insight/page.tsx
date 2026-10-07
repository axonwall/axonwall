import React from 'react';

export default function ReportingInsightPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Live Network Insight (eBPF)</h1>
      <p className="text-gray-600 mb-6">Real-time Top 50 Flows measured via XDP.</p>
      
      <div className="bg-white p-4 shadow rounded-lg mb-6">
        <h2 className="text-lg font-semibold mb-2">Active Flows</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Packets</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Bytes</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              <tr>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Waiting for WebSocket...</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500"></td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500"></td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500"></td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500"></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
