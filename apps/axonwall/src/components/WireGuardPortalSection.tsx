'use client';

import React, { useState } from 'react';
import { generateWireGuardProfile } from '@/server/wg';
import { generateMfaSetup, verifyMfaSetup } from '@/server/auth';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';

export function WireGuardPortalSection() {
  const { getFingerprint } = useDesiredStateApply();
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [mfaSecret, setMfaSecret] = useState('');
  const [mfaQr, setMfaQr] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [mfaVerified, setMfaVerified] = useState(false);
  const [mfaIdpExempt, setMfaIdpExempt] = useState(false);

  const handleSetupMfa = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await generateMfaSetup();
      if ('exempt' in res && res.exempt) {
        setMfaIdpExempt(true);
        return;
      }
      setMfaSecret(res.secret);
      setMfaQr(res.qrDataUrl);
    } catch (err: any) {
      setError(err.message || 'Failed to initiate MFA setup');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyMfa = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await verifyMfaSetup(mfaSecret, mfaToken);
      if (res.success) {
        setMfaVerified(true);
      } else {
        setError(res.error || 'Invalid code');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateVPN = async () => {
    setLoading(true);
    setError('');
    try {
      const fingerprint = getFingerprint();
      const res = await generateWireGuardProfile(
        fingerprint ? { expectedFingerprint: fingerprint } : undefined
      );
      setProfile(res);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 p-6 rounded-xl border border-slate-800">
        <h2 className="text-lg font-semibold text-white mb-2">Identity & MFA Verification</h2>
        <p className="text-sm text-slate-400 mb-5">
          Verify your Multi-Factor Authentication before minting a static WireGuard tunnel configuration.
        </p>
        {!mfaQr && !mfaIdpExempt ? (
          <button
            type="button"
            onClick={handleSetupMfa}
            disabled={loading}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-sm text-white font-medium disabled:opacity-50 cursor-pointer transition"
          >
            Check / Setup MFA
          </button>
        ) : !mfaVerified && !mfaIdpExempt ? (
          <div className="space-y-4">
            <p className="text-sm text-slate-300">Scan this QR code with an authenticator app:</p>
            <div className="bg-white inline-block p-3 rounded-lg">
              <img src={mfaQr} alt="MFA QR Code" className="w-44 h-44" />
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <input
                type="text"
                placeholder="Enter 6-digit code"
                value={mfaToken}
                onChange={(e) => setMfaToken(e.target.value)}
                className="px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500"
              />
              <button
                type="button"
                onClick={handleVerifyMfa}
                disabled={loading || !mfaToken}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-sm text-white font-medium disabled:opacity-50 cursor-pointer transition"
              >
                Verify Code
              </button>
            </div>
            {error && <p className="text-sm text-red-400">{error}</p>}
          </div>
        ) : mfaIdpExempt ? (
          <div className="text-cyan-300 text-sm font-medium bg-cyan-500/10 border border-cyan-500/30 p-3.5 rounded-lg">
            Directory or SSO session detected — MFA is handled by your authentication provider.
          </div>
        ) : (
          <div className="text-emerald-300 text-sm font-medium bg-emerald-500/10 border border-emerald-500/30 p-3.5 rounded-lg">
            MFA verified for WireGuard provisioning.
          </div>
        )}
      </div>

      <div className="bg-slate-900 p-6 rounded-xl border border-slate-800">
        <h2 className="text-lg font-semibold text-white mb-2">WireGuard Client Profile</h2>
        {!profile ? (
          <div className="py-4">
            <p className="text-sm text-slate-400 mb-5">
              Generate a static WireGuard keypair and client configuration for your laptop or phone.
            </p>
            <button
              type="button"
              onClick={handleGenerateVPN}
              disabled={loading || (!mfaVerified && !mfaIdpExempt)}
              className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer transition"
              title={!mfaVerified && !mfaIdpExempt ? 'Complete MFA check first' : ''}
            >
              {loading ? 'Provisioning...' : 'Generate Device Profile'}
            </button>
            {error && (
              <p className="text-sm text-red-400 mt-3">{error}</p>
            )}
          </div>
        ) : (
          <div className="space-y-6">
            <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 p-3.5 rounded-lg text-sm">
              Profile provisioned! Assigned tunnel IP: <strong className="font-mono">{profile.assignedIp}</strong>
            </div>
            <div className="flex flex-col md:flex-row gap-6">
              <div>
                <h3 className="text-sm font-medium text-slate-200 mb-2">Mobile QR Import</h3>
                <div className="bg-white p-3 rounded-lg inline-block">
                  <img src={profile.qrDataUrl} alt="WireGuard QR Code" className="w-44 h-44" />
                </div>
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-sm font-medium text-slate-200 mb-2">Desktop Config (.conf)</h3>
                <pre className="bg-slate-950 p-3.5 rounded-lg text-xs text-slate-300 overflow-x-auto border border-slate-800 font-mono">
                  {profile.configStr}
                </pre>
                <button
                  type="button"
                  onClick={() => {
                    const blob = new Blob([profile.configStr], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'axonwall.conf';
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="mt-3 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-lg text-xs font-medium cursor-pointer transition border border-slate-700"
                >
                  Download .conf File
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
