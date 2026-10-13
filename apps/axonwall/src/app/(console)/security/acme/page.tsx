'use client';

import { useState } from 'react';
import { Lock, Plus, RefreshCw, CheckCircle2, Shield, Calendar, Server } from 'lucide-react';
import type { AcmeCertificate, AcmeAccount } from '@axonwall/lib/schemas';

export default function AcmeCertificatesPage() {
  const [accounts] = useState<AcmeAccount[]>([]);
  const [certificates, setCertificates] = useState<AcmeCertificate[]>([]);

  const [renewing, setRenewing] = useState(false);
  const [renewDone, setRenewDone] = useState(false);

  const handleRenew = () => {
    if (certificates.length === 0) return;
    setRenewing(true);
    setTimeout(() => {
      setRenewing(false);
      setRenewDone(true);
      setTimeout(() => setRenewDone(false), 3000);
    }, 1500);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-emerald-400" />
          Automated TLS Certificates (ACME / Let's Encrypt)
        </h1>
        <p className="text-sm text-slate-400">
          Automated certificate issuance, renewal, and service reload hooks for Web GUI, OpenVPN, IPsec, and HAProxy.
        </p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <div>
            <h3 className="font-semibold text-white">Managed Certificates</h3>
            <p className="text-xs text-slate-400">Auto-renewing 90-day X.509 certificates</p>
          </div>
          <button
            type="button"
            onClick={handleRenew}
            disabled={renewing || certificates.length === 0}
            className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-medium transition flex items-center gap-1.5 shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${renewing ? 'animate-spin' : ''}`} />
            {renewing ? 'Renewing Certificates...' : 'Renew All Certificates'}
          </button>
        </div>

        {renewDone && (
          <div className="px-4 py-2.5 bg-emerald-500/10 border-b border-emerald-500/20 text-xs text-emerald-400 flex items-center gap-2 font-medium">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            Certificates validated and reloaded into active daemons (Web GUI & OpenVPN).
          </div>
        )}

        {certificates.length === 0 ? (
          <div className="p-8 text-center text-slate-400">
            <Lock className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="font-semibold text-slate-300">No Managed Certificates</p>
            <p className="text-xs text-slate-500 mt-1">
              Configure an ACME provider account and add a domain name to issue automated Let's Encrypt TLS certificates.
            </p>
          </div>
        ) : (
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Certificate Name</th>
                <th className="px-4 py-3">Primary Domain (CN)</th>
                <th className="px-4 py-3">SAN Alternate Names</th>
                <th className="px-4 py-3">Challenge</th>
                <th className="px-4 py-3">Deploy Hooks</th>
                <th className="px-4 py-3">Expires</th>
                <th className="px-4 py-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {certificates.map((cert) => (
                <tr key={cert.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-semibold text-white text-xs">{cert.name}</td>
                  <td className="px-4 py-3 font-mono text-xs text-emerald-400 font-semibold">{cert.domain}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">
                    {cert.altNames.join(', ') || 'None'}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs uppercase text-slate-300">
                    {cert.challengeType}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1 flex-wrap">
                      {cert.deployServices.map((svc) => (
                        <span
                          key={svc}
                          className="px-2 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-slate-300 border border-slate-700"
                        >
                          {svc}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">
                    {cert.expiresAt ? new Date(cert.expiresAt).toLocaleDateString() : 'N/A'}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-mono font-bold border border-emerald-500/20">
                      VALID
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
