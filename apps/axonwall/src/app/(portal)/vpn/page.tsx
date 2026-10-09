'use client';

import React, { useState } from 'react';
import { generateWireGuardProfile } from '@/server/wg';
import { generateMfaSetup, verifyMfaSetup } from '@/server/auth';

export default function VPNPortal() {
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  // MFA state
  const [mfaSecret, setMfaSecret] = useState('');
  const [mfaQr, setMfaQr] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [mfaVerified, setMfaVerified] = useState(false);

  const handleSetupMfa = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await generateMfaSetup();
      setMfaSecret(res.secret);
      setMfaQr(res.qrDataUrl);
    } catch (err: any) {
      setError(err.message);
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
      const res = await generateWireGuardProfile();
      setProfile(res);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="bg-slate-800 p-8 rounded-lg shadow-xl border border-slate-700">
        <h2 className="text-xl font-semibold mb-6">Enterprise Identity & MFA Setup</h2>
        {!mfaQr ? (
          <div>
            <p className="text-slate-400 mb-4">Secure your account by enabling Multi-Factor Authentication (MFA).</p>
            <button onClick={handleSetupMfa} disabled={loading} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded text-white font-medium disabled:opacity-50">
              Setup MFA
            </button>
          </div>
        ) : !mfaVerified ? (
          <div className="space-y-4">
            <p className="text-slate-300">Scan this QR code with Google Authenticator or Authy:</p>
            <div className="bg-white inline-block p-4 rounded">
              <img src={mfaQr} alt="MFA QR Code" className="w-48 h-48" />
            </div>
            <div className="flex items-center">
              <input 
                type="text" 
                placeholder="Enter 6-digit code" 
                value={mfaToken}
                onChange={e => setMfaToken(e.target.value)}
                className="px-3 py-2 bg-slate-900 border border-slate-700 rounded mr-4 text-white"
              />
              <button onClick={handleVerifyMfa} disabled={loading || !mfaToken} className="px-4 py-2 bg-green-600 hover:bg-green-500 rounded text-white font-medium disabled:opacity-50">
                Verify
              </button>
            </div>
            {error && <p className="text-red-400">{error}</p>}
          </div>
        ) : (
          <div className="text-green-400 font-medium bg-green-900/30 border border-green-800 p-4 rounded">
            MFA successfully configured and verified!
          </div>
        )}
      </div>

      <div className="bg-slate-800 p-8 rounded-lg shadow-xl border border-slate-700">
        <h2 className="text-xl font-semibold mb-6">Device VPN Provisioning</h2>
        
        {!profile ? (
          <div className="text-center py-8">
            <p className="text-slate-400 mb-6">
              Generate a new WireGuard VPN profile for your mobile device or laptop.
              This will provision a secure tunnel directly to the corporate network.
            </p>
            <button 
              onClick={handleGenerateVPN}
              disabled={loading || !mfaVerified}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-md font-medium disabled:opacity-50 disabled:cursor-not-allowed"
              title={!mfaVerified ? "Setup MFA first" : ""}
            >
              {loading ? 'Provisioning...' : 'Generate Device Profile'}
            </button>
            {error && !mfaVerified && <p className="text-red-400 mt-4">Please complete MFA setup first.</p>}
            {error && mfaVerified && <p className="text-red-400 mt-4">{error}</p>}
          </div>
        ) : (
          <div className="space-y-6">
            <div className="bg-green-900/30 border border-green-800 text-green-400 p-4 rounded-md">
              Profile provisioned successfully! Assigned IP: <strong>{profile.assignedIp}</strong>
            </div>
            
            <div className="flex flex-col md:flex-row gap-8">
              <div className="flex-1">
                <h3 className="font-medium text-slate-300 mb-2">Mobile Devices</h3>
                <p className="text-sm text-slate-400 mb-4">
                  Download the WireGuard app on your phone and scan this QR code to instantly import the tunnel.
                </p>
                <div className="bg-white p-4 rounded-md inline-block">
                  <img src={profile.qrDataUrl} alt="WireGuard QR Code" className="w-48 h-48" />
                </div>
              </div>
              
              <div className="flex-1">
                <h3 className="font-medium text-slate-300 mb-2">Laptops / Desktops</h3>
                <p className="text-sm text-slate-400 mb-4">
                  Save the configuration block below to a file named <code>axonwall.conf</code> and import it into your WireGuard client.
                </p>
                <pre className="bg-slate-900 p-4 rounded-md text-xs text-slate-300 overflow-x-auto border border-slate-700">
                  {profile.configStr}
                </pre>
                <button 
                  onClick={() => {
                    const blob = new Blob([profile.configStr], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'axonwall.conf';
                    a.click();
                  }}
                  className="mt-4 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-sm font-medium"
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
