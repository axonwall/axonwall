'use client';

import React, { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  AlertCircle,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  Eye,
  EyeOff,
  Key,
  Loader2,
  Lock,
  QrCode,
  Shield,
  Terminal,
} from 'lucide-react';
import { Logo } from '@/components/Logo';

interface InvitePreview {
  status: 'valid' | 'expired' | 'used' | 'revoked' | 'invalid';
  username?: string;
  displayName?: string;
  mode?: 'onboard' | 'reset';
  expiresAt?: string;
  createStarterKey?: boolean;
  requiresPin?: boolean;
  magicDnsDomain?: string;
  minPasswordLength?: number;
}

interface RedeemedData {
  username: string;
  serverUrl: string;
  magicDnsDomain: string;
  redirectTo: string;
  quickConnectCommand: string;
  starterKey: {
    id: string | number;
    key: string;
    expiration?: string;
  } | null;
}

type QrMode = 'command' | 'authkey' | 'server';

const WELCOME_STORAGE_KEY = 'axonwall_mesh_welcome';

export default function InviteRedeemPage() {
  const params = useParams<{ token: string }>();
  const token = typeof params?.token === 'string' ? params.token : '';

  const [preview, setPreview] = useState<InvitePreview | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [pin, setPin] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const [redeemedData, setRedeemedData] = useState<RedeemedData | null>(null);
  const [qrMode, setQrMode] = useState<QrMode>('command');
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setPreview({ status: 'invalid' });
      setLoading(false);
      return;
    }
    let active = true;
    setLoading(true);
    fetch(`/api/v1/vpn/mesh/invites/preview?token=${encodeURIComponent(token)}`, {
      cache: 'no-store',
    })
      .then(async (res) => {
        const json = await res.json().catch(() => null);
        if (!res.ok || json?.status !== 'ok') {
          throw new Error(json?.error || `Failed to verify invite link (HTTP ${res.status})`);
        }
        if (active) setPreview(json.data);
      })
      .catch((err: any) => {
        if (active) setLoadError(err?.message || 'Unable to check invite link');
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [token]);

  const qrPayload = useMemo(() => {
    if (!redeemedData) return '';
    if (qrMode === 'authkey') {
      return redeemedData.starterKey?.key || redeemedData.quickConnectCommand || redeemedData.serverUrl;
    }
    if (qrMode === 'server') {
      return redeemedData.serverUrl || redeemedData.quickConnectCommand;
    }
    return redeemedData.quickConnectCommand || redeemedData.serverUrl;
  }, [redeemedData, qrMode]);

  useEffect(() => {
    let active = true;
    if (!redeemedData || !qrPayload) {
      setQrDataUrl(null);
      return;
    }
    import('qrcode')
      .then((QRCode) => QRCode.toDataURL(qrPayload, { width: 192, margin: 1 }))
      .then((url) => {
        if (active) setQrDataUrl(url);
      })
      .catch(() => {
        if (active) setQrDataUrl(null);
      });
    return () => {
      active = false;
    };
  }, [redeemedData, qrPayload]);

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 2000);
    } catch {}
  };

  const minLen = preview?.minPasswordLength ?? 12;
  const requiresPin = Boolean(preview?.requiresPin);
  const pinOk = !requiresPin || /^\d{6}$/.test(pin);
  const lengthOk = password.length >= minLen;
  const matches = password.length > 0 && password === confirmPassword;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);
    if (!pinOk) {
      setSubmitError('Please enter the 6-digit verification PIN provided by your administrator.');
      return;
    }
    if (!lengthOk) {
      setSubmitError(`Password must be at least ${minLen} characters long.`);
      return;
    }
    if (!matches) {
      setSubmitError('Password and confirmation do not match.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch('/api/v1/vpn/mesh/invites/redeem', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          password,
          confirmPassword,
          ...(requiresPin ? { pin } : {}),
        }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Activation failed (HTTP ${res.status})`);
      }

      if (json.starterKey) {
        try {
          sessionStorage.setItem(
            WELCOME_STORAGE_KEY,
            JSON.stringify({
              starterKey: json.starterKey,
              serverUrl: json.serverUrl || '',
              magicDnsDomain: json.magicDnsDomain || '',
              username: json.username || preview?.username || '',
            })
          );
        } catch {}
      }

      setRedeemedData({
        username: json.username || preview?.username || '',
        serverUrl: json.serverUrl || '',
        magicDnsDomain: json.magicDnsDomain || preview?.magicDnsDomain || '',
        redirectTo: json.redirectTo || '/vpn',
        quickConnectCommand: json.quickConnectCommand || '',
        starterKey: json.starterKey || null,
      });
      setSubmitting(false);
    } catch (err: any) {
      setSubmitError(err?.message || 'Could not activate account');
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div
        className={`w-full ${redeemedData ? 'max-w-xl' : 'max-w-md'} bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-8 space-y-6`}
      >
        <div className="flex flex-col items-center text-center space-y-2">
          <Logo variant="full" size="md" />
          <h1 className="text-xl font-bold text-white pt-2">
            {redeemedData
              ? "You're Ready to Connect"
              : preview?.mode === 'reset'
                ? 'Reset Your Mesh VPN Password'
                : 'Activate Your Mesh VPN Account'}
          </h1>
          <p className="text-xs text-slate-400">
            Self-service private WireGuard mesh onboarding powered by Axonwall &amp; Headscale
          </p>
        </div>

        {loading ? (
          <div className="py-8 flex items-center justify-center gap-2.5 text-sm text-slate-400">
            <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
            <span>Verifying invitation link...</span>
          </div>
        ) : loadError ? (
          <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-sm text-red-200 flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span>{loadError}</span>
          </div>
        ) : redeemedData ? (
          <div className="space-y-5 text-xs">
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-200 flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div className="font-semibold text-sm text-white">
                  Account <code className="font-mono text-emerald-300">{redeemedData.username}</code> activated
                </div>
                <p className="text-emerald-100/80">
                  Tailnet: <code className="font-mono">{redeemedData.magicDnsDomain || 'headscale'}</code>
                </p>
              </div>
            </div>

            {redeemedData.quickConnectCommand && (
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                    <span>1. Connect This Device (CLI)</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy(redeemedData.quickConnectCommand, 'redeem-cmd')}
                    className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded flex items-center gap-1 cursor-pointer"
                  >
                    {copiedId === 'redeem-cmd' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedId === 'redeem-cmd' ? 'Copied' : 'Copy Command'}</span>
                  </button>
                </div>
                <pre className="bg-slate-900 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-emerald-300 whitespace-pre-wrap break-all">
                  {redeemedData.quickConnectCommand}
                </pre>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 space-y-3">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-slate-400 font-medium">Control Server URL</span>
                    {redeemedData.serverUrl && (
                      <button
                        type="button"
                        onClick={() => handleCopy(redeemedData.serverUrl, 'redeem-server')}
                        className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedId === 'redeem-server' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedId === 'redeem-server' ? 'Copied' : 'Copy'}</span>
                      </button>
                    )}
                  </div>
                  <code className="block font-mono text-[11px] text-slate-200 break-all">
                    {redeemedData.serverUrl || 'Configured on appliance'}
                  </code>
                </div>

                {redeemedData.starterKey?.key ? (
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-slate-400 font-medium">Single-Use Setup Auth Key</span>
                      <button
                        type="button"
                        onClick={() => handleCopy(redeemedData.starterKey!.key, 'redeem-key')}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedId === 'redeem-key' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedId === 'redeem-key' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <code className="block font-mono text-[11px] text-cyan-300 break-all">
                      {redeemedData.starterKey.key}
                    </code>
                    {redeemedData.starterKey.expiration && (
                      <p className="text-[11px] text-slate-500 mt-1">
                        Expires {new Date(redeemedData.starterKey.expiration).toLocaleString()}
                      </p>
                    )}
                  </div>
                ) : (
                  <p className="text-[11px] text-slate-400">
                    Open the Tailscale client, choose Custom Control Server URL above, and register via your administrator or the self-service portal once connected.
                  </p>
                )}

                <div className="pt-1 border-t border-slate-800/80 text-[11px] text-slate-400 space-y-1">
                  <p className="font-semibold text-slate-300">Client Setup Tips</p>
                  <p>
                    <strong>Desktop/Linux:</strong> Install Tailscale, then run the connect command above.
                  </p>
                  <p>
                    <strong>iOS/Android:</strong> Tailscale app → Settings → Custom Control Server → paste URL &amp; use Setup Key or scan QR.
                  </p>
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col items-center justify-between space-y-2.5">
                <div className="w-full flex items-center justify-between">
                  <span className="text-slate-300 font-medium flex items-center gap-1.5">
                    <QrCode className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Scan QR</span>
                  </span>
                  <div className="flex gap-1 bg-slate-900 p-0.5 rounded border border-slate-800 text-[10px]">
                    <button
                      type="button"
                      onClick={() => setQrMode('command')}
                      className={`px-1.5 py-0.5 rounded cursor-pointer ${qrMode === 'command' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'}`}
                    >
                      Cmd
                    </button>
                    {redeemedData.starterKey?.key && (
                      <button
                        type="button"
                        onClick={() => setQrMode('authkey')}
                        className={`px-1.5 py-0.5 rounded cursor-pointer ${qrMode === 'authkey' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'}`}
                      >
                        Key
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => setQrMode('server')}
                      className={`px-1.5 py-0.5 rounded cursor-pointer ${qrMode === 'server' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'}`}
                    >
                      URL
                    </button>
                  </div>
                </div>

                {qrDataUrl ? (
                  <div className="bg-white p-2 rounded-lg">
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={qrDataUrl} alt="Tailscale setup QR code" className="w-40 h-40" />
                  </div>
                ) : (
                  <div className="w-40 h-40 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-center text-slate-500">
                    Generating QR...
                  </div>
                )}

                <p className="text-[11px] text-slate-400 text-center">
                  {qrMode === 'authkey'
                    ? 'Encodes starter setup key'
                    : qrMode === 'server'
                      ? 'Encodes Control Server URL'
                      : 'Encodes full tailscale up command'}
                </p>
              </div>
            </div>

            <div className="pt-1 space-y-1.5">
              <Link
                href={redeemedData.redirectTo || '/vpn'}
                className="w-full bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 font-medium py-2.5 rounded-lg text-xs flex items-center justify-center gap-2 transition"
              >
                <ExternalLink className="w-3.5 h-3.5 text-emerald-400" />
                <span>Open Self-Service VPN Portal (/vpn)</span>
              </Link>
              <p className="text-[11px] text-slate-500 text-center">
                Available once connected to the Tailnet or LAN (blocked on public WAN for security)
              </p>
            </div>
          </div>
        ) : preview?.status !== 'valid' ? (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-sm text-amber-200 space-y-1.5">
              <div className="font-semibold flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                <span>
                  {preview?.status === 'used'
                    ? 'Invite Link Already Used'
                    : preview?.status === 'expired'
                      ? 'Invite Link Expired'
                      : preview?.status === 'revoked'
                        ? 'Invite Link Revoked'
                        : 'Invalid Invite Link'}
                </span>
              </div>
              <p className="text-xs text-amber-100/80">
                {preview?.status === 'used'
                  ? 'This single-use link has already been activated. Sign in from the LAN or Tailnet portal with your username and password.'
                  : 'Please ask your network administrator to generate a fresh Mesh VPN invite link.'}
              </p>
            </div>
            <Link
              href="/login"
              className="w-full bg-slate-800 hover:bg-slate-700 text-white font-medium py-2.5 rounded-lg text-sm flex items-center justify-center gap-2 transition"
            >
              <Key className="w-4 h-4" />
              <span>Go to Sign In</span>
            </Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-1.5 text-xs">
              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">Account</span>
                <span className="font-semibold text-white">
                  {preview.displayName && preview.displayName !== preview.username
                    ? `${preview.displayName} (${preview.username})`
                    : preview.username}
                </span>
              </div>
              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">Username</span>
                <code className="font-mono text-emerald-400">{preview.username}</code>
              </div>
              {preview.magicDnsDomain && (
                <div className="flex items-center justify-between text-slate-300">
                  <span className="text-slate-400">Tailnet</span>
                  <code className="font-mono text-slate-200">{preview.magicDnsDomain}</code>
                </div>
              )}
              {preview.expiresAt && (
                <div className="flex items-center justify-between text-slate-400 tabular-nums">
                  <span>Invite expires</span>
                  <span>{new Date(preview.expiresAt).toLocaleString()}</span>
                </div>
              )}
            </div>

            {submitError && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{submitError}</span>
              </div>
            )}

            {requiresPin && (
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  6-Digit Verification PIN
                </label>
                <div className="relative">
                  <Key className="absolute left-3 top-2.5 w-4 h-4 text-amber-400" />
                  <input
                    type="text"
                    inputMode="numeric"
                    required
                    maxLength={6}
                    pattern="\d{6}"
                    value={pin}
                    onChange={(e) => setPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-amber-200 font-mono tracking-widest placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                    placeholder="6-digit PIN from administrator"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Choose Password (min {minLen} chars)
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  minLength={minLen}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-10 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  placeholder="Create a strong password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 cursor-pointer"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  minLength={minLen}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  placeholder="Re-enter password"
                />
              </div>
            </div>

            <div className="flex flex-col gap-1 text-xs">
              {requiresPin && (
                <div className={`flex items-center gap-1.5 ${pinOk ? 'text-emerald-400' : 'text-slate-400'}`}>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>6-digit verification PIN entered</span>
                </div>
              )}
              <div className={`flex items-center gap-1.5 ${lengthOk ? 'text-emerald-400' : 'text-slate-400'}`}>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>At least {minLen} characters</span>
              </div>
              <div className={`flex items-center gap-1.5 ${matches ? 'text-emerald-400' : 'text-slate-400'}`}>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Passwords match</span>
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting || !pinOk || !lengthOk || !matches}
              className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium py-2.5 rounded-lg text-sm flex items-center justify-center gap-2 transition cursor-pointer"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
              <span>
                {submitting
                  ? 'Activating Account...'
                  : preview.mode === 'reset'
                    ? 'Update Password & Show Setup'
                    : 'Activate Account & Show Setup'}
              </span>
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
