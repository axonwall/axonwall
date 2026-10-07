import React from 'react';

export default function SecurityIDSPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Threat Defense (IDS/IPS)</h1>
      <p className="text-gray-600 mb-6">Manage Suricata Rulesets and CrowdSec blocklists.</p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white p-4 shadow rounded-lg">
          <h2 className="text-lg font-semibold mb-2">Engines Status</h2>
          <ul className="space-y-2">
            <li className="flex justify-between">
              <span>Suricata IDS</span>
              <span className="text-green-600 font-medium">Running</span>
            </li>
            <li className="flex justify-between">
              <span>CrowdSec Bouncer</span>
              <span className="text-green-600 font-medium">Running</span>
            </li>
          </ul>
        </div>
        
        <div className="bg-white p-4 shadow rounded-lg">
          <h2 className="text-lg font-semibold mb-2">Rulesets</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span>Emerging Threats (ET) Open</span>
              <button className="bg-blue-600 text-white px-4 py-2 rounded text-sm">Update Now</button>
            </div>
            <div className="flex items-center justify-between">
              <span>CrowdSec Community Blocklist</span>
              <button className="bg-blue-600 text-white px-4 py-2 rounded text-sm">Update Now</button>
            </div>
          </div>
        </div>
      </div>
      
      <div className="bg-white p-4 shadow rounded-lg mt-6">
        <h2 className="text-lg font-semibold mb-2">Recent Alerts</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Signature</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              <tr>
                <td colSpan={5} className="px-6 py-4 text-center text-sm text-gray-500">No recent alerts.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
