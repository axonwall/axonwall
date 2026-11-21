'use client';

import React, { useState } from 'react';
import { Network, Shield } from 'lucide-react';
import { MeshSelfServicePortal } from './MeshSelfServicePortal';
import { WireGuardPortalSection } from './WireGuardPortalSection';

export function VpnPortalTabs({ canAccessWireGuard }: { canAccessWireGuard: boolean }) {
  const [tab, setTab] = useState<'mesh' | 'wireguard'>('mesh');

  if (!canAccessWireGuard) {
    return <MeshSelfServicePortal />;
  }

  return (
    <div className="space-y-6">
      <div className="border-b border-slate-800 flex items-center gap-6">
        <button
          type="button"
          onClick={() => setTab('mesh')}
          className={`py-3 px-1 border-b-2 text-sm font-medium flex items-center gap-2 cursor-pointer transition ${
            tab === 'mesh'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Network className="w-4 h-4" />
          <span>Mesh VPN (Headscale)</span>
        </button>
        <button
          type="button"
          onClick={() => setTab('wireguard')}
          className={`py-3 px-1 border-b-2 text-sm font-medium flex items-center gap-2 cursor-pointer transition ${
            tab === 'wireguard'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>WireGuard &amp; MFA</span>
        </button>
      </div>

      {tab === 'mesh' ? <MeshSelfServicePortal /> : <WireGuardPortalSection />}
    </div>
  );
}
