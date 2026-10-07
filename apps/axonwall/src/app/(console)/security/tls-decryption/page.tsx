'use client';

import React, { useState } from 'react';
import { Shield, Download, Lock, AlertTriangle, Key } from 'lucide-react';

export default function TlsDecryptionPage() {
  const [enabled, setEnabled] = useState(false);
  
  return (
    <div className="p-8 space-y-8 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" />
          TLS Decryption (SSL Bump)
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Deep Packet Inspection for encrypted traffic. Axonwall acts as a transparent proxy to inspect HTTPS payloads for malware and data exfiltration.
        </p>
      </div>

      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-white">Enable TLS Decryption</h3>
            <p className="text-sm text-slate-400">Transparently intercept port 443 traffic for Suricata inspection.</p>
          </div>
          <button
            onClick={() => setEnabled(!enabled)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${enabled ? 'bg-emerald-500' : 'bg-slate-700'}`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${enabled ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
        </div>

        {enabled && (
          <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-sm text-slate-300">
              <span className="font-semibold text-amber-400 block mb-1">Privacy & Compliance Warning</span>
              Ensure you have legal and HR approval before intercepting employee traffic. Bypassing financial and healthcare domains is strongly recommended.
            </div>
          </div>
        )}
      </div>

      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <Key className="w-5 h-5 text-cyan-400" />
          Decryption Root CA
        </h3>
        <p className="text-sm text-slate-400">
          In order to intercept TLS connections without browser warnings, you must deploy this internal Root CA to your client devices via MDM (Intune, Jamf, etc.).
        </p>
        
        <div className="flex items-center justify-between p-4 bg-slate-950 border border-slate-800 rounded-lg">
          <div>
            <div className="font-mono text-sm text-emerald-400">Axonwall Inspection Root CA (Internal)</div>
            <div className="text-xs text-slate-500 mt-1">Valid until: 2036-10-07</div>
          </div>
          <button className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium rounded-lg transition">
            <Download className="w-4 h-4" />
            Download .crt
          </button>
        </div>
      </div>
    </div>
  );
}
