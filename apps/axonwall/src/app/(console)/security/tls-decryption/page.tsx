'use client';

import React, { useState, useEffect } from 'react';
import { PluginDisabledGate } from '@/components/PluginDisabledGate';
import { Shield, Download, AlertTriangle, AlertCircle, Key, CheckCircle2, Plus, Trash2 } from 'lucide-react';
import { getCurrentDesiredState } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import { mergeTlsDecryptionConfig } from '@/lib/state-preservation';
import type { DesiredState } from '@axonwall/lib/schemas';

function TlsDecryptionPageContent() {
  const { applyState } = useDesiredStateApply();
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [bypassedDomains, setBypassedDomains] = useState<string[]>([
    '*.bankofamerica.com',
    '*.chase.com',
    '*.apple.com',
  ]);
  const [newDomain, setNewDomain] = useState('');
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        const tls = state.tlsDecryption || state.suricata?.tlsDecryption;
        if (tls) {
          setEnabled(tls.enabled);
          if (tls.bypassedDomains?.length) {
            setBypassedDomains(tls.bypassedDomains);
          }
        }
      })
      .catch(() => {});
  }, []);

  const persistTls = async (nextEnabled: boolean, nextBypass: string[]) => {
    const prevFullState = fullState;
    const prevEnabled = enabled;
    const prevBypassedDomains = bypassedDomains;
    setEnabled(nextEnabled);
    setBypassedDomains(nextBypass);
    setStatusMsg(null);
    try {
      const current = await getCurrentDesiredState();
      const existingTls = current.tlsDecryption || current.suricata?.tlsDecryption;
      const tlsObj = mergeTlsDecryptionConfig(existingTls, {
        enabled: nextEnabled,
        bypassedDomains: nextBypass,
      });
      const nextState: DesiredState = {
        ...current,
        tlsDecryption: tlsObj,
      };
      setFullState(nextState);
      const res = await applyState(nextState);
      setStatusMsg({
        type: 'success',
        text: res.message || 'Saved TLS Decryption policy to /etc/axonwall/security.yaml',
      });
    } catch (err: any) {
      setEnabled(prevEnabled);
      setBypassedDomains(prevBypassedDomains);
      setFullState(prevFullState);
      setStatusMsg({
        type: 'error',
        text: err?.message || 'Failed to save TLS Decryption settings',
      });
    }
  };

  const tlsCfg = fullState?.tlsDecryption || fullState?.suricata?.tlsDecryption;
  const caId = tlsCfg?.caCertificateId;
  const matchedCa =
    (fullState?.acme?.internalCAs ?? []).find((ca) => (caId ? ca.id === caId : ca.isDecryptionRoot)) ??
    (fullState?.acme?.internalCAs ?? []).find((ca) => ca.isDecryptionRoot);
  const rawCaCert = matchedCa?.certificateBase64?.trim() || '';
  const hasDownloadableCa = Boolean(rawCaCert && rawCaCert !== '********');

  const handleDownloadCaCert = () => {
    if (!hasDownloadableCa) {
      setStatusMsg({
        type: 'error',
        text: 'No inspection Root CA certificate is currently provisioned.',
      });
      return;
    }
    try {
      const pem = rawCaCert.includes('-----BEGIN CERTIFICATE-----') ? rawCaCert : atob(rawCaCert);
      const blob = new Blob([pem], { type: 'application/x-x509-ca-cert' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `${(matchedCa?.name || 'axonwall-inspection-root-ca').replace(/[^a-zA-Z0-9._-]+/g, '-')}.crt`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch {
      setStatusMsg({
        type: 'error',
        text: 'Failed to decode configured Root CA certificate for download.',
      });
    }
  };

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;
    const next = [...bypassedDomains, newDomain.trim()];
    setNewDomain('');
    await persistTls(enabled, next);
  };

  return (
    <div className="p-8 space-y-8 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" />
          TLS Decryption (SSL Bump)
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Deep Packet Inspection for encrypted traffic synced with{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/security.yaml</code>.
        </p>
      </div>

      {statusMsg && (
        <div
          className={`p-3 rounded-lg text-xs flex items-center gap-2 border ${
            statusMsg.type === 'error'
              ? 'bg-red-500/10 border-red-500/30 text-red-300'
              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
          }`}
        >
          {statusMsg.type === 'error' ? (
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          )}
          <span>{statusMsg.text}</span>
        </div>
      )}

      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-white">Enable TLS Decryption</h3>
            <p className="text-sm text-slate-400">Transparently intercept port 443 traffic for Suricata inspection.</p>
          </div>
          <button
            type="button"
            onClick={() => persistTls(!enabled, bypassedDomains)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors cursor-pointer ${
              enabled ? 'bg-emerald-500' : 'bg-slate-700'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                enabled ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
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

        <div className="space-y-3 pt-2 border-t border-slate-800">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
            SNI Bypass Domains (Do Not Decrypt)
          </span>
          <div className="flex flex-wrap gap-2">
            {bypassedDomains.map((dom) => (
              <span
                key={dom}
                className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 flex items-center gap-2"
              >
                {dom}
                <button
                  type="button"
                  onClick={() => persistTls(enabled, bypassedDomains.filter((d) => d !== dom))}
                  className="text-slate-500 hover:text-red-400"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </span>
            ))}
          </div>
          <form onSubmit={handleAddDomain} className="flex gap-2 pt-1">
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="*.healthcare.org"
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono flex-1"
            />
            <button
              type="submit"
              className="bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Bypass</span>
            </button>
          </form>
        </div>
      </div>

      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <Key className="w-5 h-5 text-cyan-400" />
          Decryption Root CA
        </h3>
        <p className="text-sm text-slate-400">
          In order to intercept TLS connections without browser warnings, you must deploy this internal Root CA to your client devices via MDM (Intune, Jamf, etc.).
        </p>

        <div className="flex items-center justify-between p-4 bg-slate-950 border border-slate-800 rounded-lg gap-4">
          <div>
            <div className="font-mono text-sm text-emerald-400">
              {matchedCa?.commonName || matchedCa?.name || 'Axonwall Inspection Root CA (Internal)'}
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {hasDownloadableCa
                ? 'Ready for MDM / endpoint trust store deployment (.crt)'
                : 'No inspection Root CA certificate generated yet — provision a Decryption Root CA under Security → ACME / PKI.'}
            </div>
          </div>
          <button
            type="button"
            disabled={!hasDownloadableCa}
            onClick={handleDownloadCaCert}
            title={
              hasDownloadableCa
                ? 'Download Root CA certificate (.crt)'
                : 'No Root CA certificate generated yet'
            }
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition shrink-0 cursor-pointer"
          >
            <Download className="w-4 h-4" />
            Download .crt
          </button>
        </div>
      </div>
    </div>
  );
}

export default function TlsDecryptionPage() {
  return (
    <PluginDisabledGate pluginId="tls-decryption">
      <TlsDecryptionPageContent />
    </PluginDisabledGate>
  );
}
