'use client';

import React, { useState } from 'react';
import { ShieldAlert, RefreshCw, Server, Activity } from 'lucide-react';

export default function HighAvailabilityPage() {
  const [enabled, setEnabled] = useState(false);
  const [role, setRole] = useState('primary');
  
  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">High Availability (HA)</h1>
          <p className="text-sm text-slate-500 mt-1">Configure active/passive failover using VRRP (Keepalived) and state sync (conntrackd).</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-slate-500">HA Status:</span>
          {enabled ? (
            <span className="px-3 py-1 bg-emerald-100 text-emerald-700 text-sm font-semibold rounded-full flex items-center gap-1">
              <Activity className="w-4 h-4" /> Active ({role})
            </span>
          ) : (
            <span className="px-3 py-1 bg-slate-100 text-slate-600 text-sm font-semibold rounded-full flex items-center gap-1">
              Disabled
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2 space-y-6">
          <div className="bg-white border rounded-lg shadow-sm p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-slate-800 flex items-center gap-2">
                <RefreshCw className="w-5 h-5 text-blue-500" />
                Failover Configuration
              </h2>
              <label className="flex items-center cursor-pointer">
                <div className="relative">
                  <input type="checkbox" className="sr-only" checked={enabled} onChange={() => setEnabled(!enabled)} />
                  <div className={`block w-14 h-8 rounded-full transition-colors ${enabled ? 'bg-blue-500' : 'bg-slate-300'}`}></div>
                  <div className={`dot absolute left-1 top-1 bg-white w-6 h-6 rounded-full transition-transform ${enabled ? 'transform translate-x-6' : ''}`}></div>
                </div>
              </label>
            </div>

            {enabled && (
              <div className="space-y-4 animate-in fade-in slide-in-from-top-2">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Node Role</label>
                    <select 
                      value={role} 
                      onChange={(e) => setRole(e.target.value)}
                      className="w-full border-slate-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 text-sm p-2 border"
                    >
                      <option value="primary">Primary (MASTER)</option>
                      <option value="secondary">Secondary (BACKUP)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Virtual Router ID (VRID)</label>
                    <input type="number" defaultValue="51" className="w-full border-slate-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 text-sm p-2 border" />
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1">Sync Interface (pfsync / conntrackd)</label>
                  <select className="w-full border-slate-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 text-sm p-2 border">
                    <option value="eth3">eth3 (Dedicated Sync Link)</option>
                    <option value="eth1">eth1 (LAN)</option>
                  </select>
                  <p className="text-xs text-slate-500 mt-1">A dedicated crossover cable or isolated VLAN is highly recommended for state synchronization.</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Peer IP Address</label>
                    <input type="text" placeholder="10.0.99.2" className="w-full border-slate-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 text-sm p-2 border" />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Sync Password (XMLRPC / IPsec)</label>
                    <input type="password" placeholder="••••••••" className="w-full border-slate-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 text-sm p-2 border" />
                  </div>
                </div>

                <div className="pt-4 border-t mt-6 flex justify-end">
                  <button className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded text-sm font-medium">
                    Save & Apply HA State
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 flex gap-3">
            <ShieldAlert className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
            <div className="text-sm text-amber-800">
              <p className="font-semibold mb-1">Split-Brain Warning</p>
              <p>Ensure your switch infrastructure does not block VRRP multicast traffic (224.0.0.18). If both nodes stop receiving heartbeats, they will both assume the Primary role, leading to severe network disruption (Split-Brain).</p>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-white border rounded-lg shadow-sm p-6">
            <h3 className="text-sm font-semibold text-slate-800 mb-4 flex items-center gap-2">
              <Server className="w-4 h-4 text-slate-500" />
              Node Status
            </h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center text-sm">
                <span className="text-slate-500">Keepalived (VRRP)</span>
                {enabled ? <span className="text-emerald-600 font-medium">Running</span> : <span className="text-slate-400">Stopped</span>}
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-slate-500">Conntrackd (State)</span>
                {enabled ? <span className="text-emerald-600 font-medium">Synced (1.2k states)</span> : <span className="text-slate-400">Stopped</span>}
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-slate-500">Config Sync</span>
                {enabled && role === 'primary' ? <span className="text-blue-600 font-medium">Pushing to Peer</span> : <span className="text-slate-400">Idle</span>}
              </div>
            </div>
            
            {enabled && (
              <button className="w-full mt-6 bg-slate-100 hover:bg-slate-200 text-slate-700 border px-4 py-2 rounded text-sm font-medium transition-colors">
                Force Failover to Peer
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
