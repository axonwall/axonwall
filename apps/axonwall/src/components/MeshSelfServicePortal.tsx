'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  AlertCircle,
  Check,
  CheckCircle2,
  Copy,
  Edit3,
  Eye,
  EyeOff,
  Key,
  Laptop,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  RotateCcw,
  Server,
  Shield,
  Smartphone,
  Terminal,
  Trash2,
  X,
} from 'lucide-react';
import { buildTailscaleConnectCommand, sanitizeHttpUrl } from '@/lib/shell-quote';

interface SelfDevice {
  id: string | number;
  name: string;
  hostname?: string;
  ipAddresses: string[];
  lastSeen: string | null;
  online: boolean;
  approvedRoutes?: string[];
  availableRoutes?: string[];
  expiry?: string | null;
}

interface SelfKey {
  id: string | number;
  keyPreview: string;
  reusable: boolean;
  ephemeral: boolean;
  used: boolean;
  expired: boolean;
  expiration?: string;
  createdAt?: string;
}

interface SelfPayload {
  account: {
    username: string;
    displayName: string;
    headscaleUser: string;
    role: string;
    source: string;
    canChangePassword: boolean;
  };
  network: {
    enabled: boolean;
    serviceRunning: boolean;
    serverUrl: string;
    magicDnsDomain: string;
    allowSelfRegistration: boolean;
    defaultKeyExpiryHours: number;
  };
  headscaleError: string | null;
  devices: SelfDevice[];
  keys: SelfKey[];
}

type ClientOsTab = 'linux' | 'macos' | 'windows' | 'mobile' | 'docker';
type WizardTab = 'authkey' | 'approve';

export function MeshSelfServicePortal() {
  const [data, setData] = useState<SelfPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Add Device modal
  const [isAddDeviceOpen, setIsAddDeviceOpen] = useState(false);
  const [wizardTab, setWizardTab] = useState<WizardTab>('authkey');
  const [osTab, setOsTab] = useState<ClientOsTab>('linux');
  const [mintingKey, setMintingKey] = useState(false);
  const [keyExpiryHours, setKeyExpiryHours] = useState(24);
  const [keyReusable, setKeyReusable] = useState(false);
  const [keyEphemeral, setKeyEphemeral] = useState(false);
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [serverQrUrl, setServerQrUrl] = useState<string | null>(null);

  // Pending device approval (node key / auth ID)
  const [registerInput, setRegisterInput] = useState('');
  const [registering, setRegistering] = useState(false);

  // Device inline operations
  const [editingDeviceId, setEditingDeviceId] = useState<string | number | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [busyDeviceId, setBusyDeviceId] = useState<string | number | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | number | null>(null);
  const [busyKeyId, setBusyKeyId] = useState<string | number | null>(null);

  // Password change
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);
  const [passwordStatus, setPasswordStatus] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const loadSelf = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/self', { cache: 'no-store' });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Failed to load VPN account (HTTP ${res.status})`);
      }
      setData(json.data);
      if (json.data?.network?.defaultKeyExpiryHours) {
        setKeyExpiryHours(json.data.network.defaultKeyExpiryHours);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to load Mesh VPN portal');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSelf();
  }, [loadSelf]);

  const effectiveServerUrl = useMemo(() => {
    return sanitizeHttpUrl(data?.network?.serverUrl) ?? '';
  }, [data?.network?.serverUrl]);

  useEffect(() => {
    let active = true;
    if (!effectiveServerUrl || !isAddDeviceOpen) {
      return;
    }
    import('qrcode')
      .then((QRCode) => QRCode.toDataURL(effectiveServerUrl, { width: 176, margin: 1 }))
      .then((url) => {
        if (active) setServerQrUrl(url);
      })
      .catch(() => {
        if (active) setServerQrUrl(null);
      });
    return () => {
      active = false;
    };
  }, [effectiveServerUrl, isAddDeviceOpen]);

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 2000);
    } catch {}
  };

  const handleMintKey = async (openModal = false) => {
    setMintingKey(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/self/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'create',
          reusable: keyReusable,
          ephemeral: keyEphemeral,
          expiryHours: keyExpiryHours,
        }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Failed to create setup key (HTTP ${res.status})`);
      }
      setGeneratedKey(json.data.key);
      if (openModal) {
        setWizardTab('authkey');
        setIsAddDeviceOpen(true);
      }
      await loadSelf();
    } catch (err: any) {
      setError(err?.message || 'Could not generate setup key');
    } finally {
      setMintingKey(false);
    }
  };

  const handleRevokeKey = async (keyId: string | number) => {
    setBusyKeyId(keyId);
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/self/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'expire', keyId }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Failed to revoke key (HTTP ${res.status})`);
      }
      setNotice('Setup key expired.');
      await loadSelf();
    } catch (err: any) {
      setError(err?.message || 'Failed to revoke setup key');
    } finally {
      setBusyKeyId(null);
    }
  };

  const handleRegisterDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!registerInput.trim()) return;
    setRegistering(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/self/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: registerInput.trim() }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Device approval failed (HTTP ${res.status})`);
      }
      setRegisterInput('');
      setIsAddDeviceOpen(false);
      setNotice('Device registered to your VPN account.');
      await loadSelf();
    } catch (err: any) {
      setError(err?.message || 'Failed to register device');
    } finally {
      setRegistering(false);
    }
  };

  const handleDeviceAction = async (
    action: 'rename' | 'expire' | 'delete',
    machineId: string | number,
    newName?: string
  ) => {
    setBusyDeviceId(machineId);
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/self/devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, machineId, newName }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Failed to ${action} device (HTTP ${res.status})`);
      }
      setEditingDeviceId(null);
      setConfirmDeleteId(null);
      setNotice(
        action === 'rename'
          ? 'Device renamed.'
          : action === 'expire'
            ? 'Device session expired; re-authentication will be required.'
            : 'Device removed from your account.'
      );
      await loadSelf();
    } catch (err: any) {
      setError(err?.message || `Device ${action} failed`);
    } finally {
      setBusyDeviceId(null);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordStatus(null);
    if (newPassword !== confirmPassword) {
      setPasswordStatus({ type: 'err', text: 'New password and confirmation do not match.' });
      return;
    }
    if (newPassword.length < 8) {
      setPasswordStatus({ type: 'err', text: 'Password must be at least 8 characters long.' });
      return;
    }

    setChangingPassword(true);
    try {
      const res = await fetch('/api/v1/vpn/mesh/self/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword, confirmPassword }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Password update failed (HTTP ${res.status})`);
      }
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setPasswordStatus({
        type: 'ok',
        text: 'Password updated cleanly. Older sessions have been signed out.',
      });
    } catch (err: any) {
      setPasswordStatus({ type: 'err', text: err?.message || 'Password update failed' });
    } finally {
      setChangingPassword(false);
    }
  };

  const loginArg = effectiveServerUrl || '<YOUR_HEADSCALE_URL>';
  const commandByOs: Record<ClientOsTab, { label: string; command: string; hint: string }> = {
    linux: {
      label: 'Linux',
      command: buildTailscaleConnectCommand('linux', effectiveServerUrl, generatedKey),
      hint: 'Install Tailscale if missing: curl -fsSL https://tailscale.com/install.sh | sh',
    },
    macos: {
      label: 'macOS',
      command: buildTailscaleConnectCommand('macos', effectiveServerUrl, generatedKey),
      hint: 'Or in the Tailscale menu bar app, hold Option while clicking Log In and set the custom server URL.',
    },
    windows: {
      label: 'Windows',
      command: buildTailscaleConnectCommand('windows', effectiveServerUrl, generatedKey),
      hint: 'Run inside an elevated PowerShell prompt after installing the Tailscale Windows client.',
    },
    mobile: {
      label: 'iOS & Android',
      command: effectiveServerUrl || 'Ask your administrator for your public Headscale Server URL',
      hint: 'Open the Tailscale app -> Menu -> Use alternate server URL -> paste or scan QR -> sign in or approve in the next tab.',
    },
    docker: {
      label: 'Docker',
      command: buildTailscaleConnectCommand('docker', effectiveServerUrl, generatedKey),
      hint: 'Mounts minimal ephemeral or volume-backed container identity using the same Tailscale binary.',
    },
  };

  if (loading && !data) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-10 flex items-center justify-center gap-3 text-sm text-slate-400">
        <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
        <span>Loading your Mesh VPN workspace...</span>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 text-sm text-red-200 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
        <button
          type="button"
          onClick={() => void loadSelf()}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-medium cursor-pointer"
        >
          Retry
        </button>
      </div>
    );
  }

  const devices = data?.devices || [];
  const keys = data?.keys || [];
  const onlineCount = devices.filter((d) => d.online).length;
  const serviceReady = Boolean(data?.network?.serviceRunning && !data?.headscaleError);

  return (
    <div className="space-y-6">
      {/* Status Summary Strip */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-5">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold text-white tracking-tight">My Mesh VPN</h1>
            <span
              className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-0.5 rounded-full border ${
                serviceReady
                  ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                  : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  serviceReady ? 'bg-emerald-400' : 'bg-amber-400'
                }`}
              />
              {serviceReady ? 'Control Plane Online' : 'Service Offline'}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-slate-400">
            <span>
              Namespace:{' '}
              <code className="text-slate-200 font-mono">{data?.account.headscaleUser}</code>
            </span>
            <span>
              MagicDNS:{' '}
              <code className="text-emerald-400 font-mono">{data?.network.magicDnsDomain}</code>
            </span>
            <span className="tabular-nums">
              Devices:{' '}
              <strong className="text-slate-200">
                {onlineCount}/{devices.length} online
              </strong>
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 pt-0.5">
            <span>Server URL:</span>
            {effectiveServerUrl ? (
              <button
                type="button"
                onClick={() => handleCopy(effectiveServerUrl, 'server-url')}
                className="inline-flex items-center gap-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded px-2 py-0.5 font-mono text-emerald-300 transition cursor-pointer"
                title="Copy Headscale Server URL"
              >
                <span>{effectiveServerUrl}</span>
                {copiedId === 'server-url' ? (
                  <Check className="w-3 h-3 text-emerald-400" />
                ) : (
                  <Copy className="w-3 h-3 text-slate-400" />
                )}
              </button>
            ) : (
              <span className="text-amber-300/90">
                Public server URL not yet set by administrator
              </span>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => void loadSelf()}
            className="px-3 py-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs font-medium text-slate-300 flex items-center gap-1.5 cursor-pointer transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            disabled={!serviceReady}
            onClick={() => {
              setWizardTab('authkey');
              setIsAddDeviceOpen(true);
            }}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium flex items-center gap-2 cursor-pointer transition shadow-sm"
          >
            <Plus className="w-4 h-4" />
            <span>Add Device</span>
          </button>
        </div>
      </div>

      {/* Notices & Errors */}
      {data?.headscaleError && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-xs text-amber-200 flex items-start gap-2.5">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <span>{data.headscaleError}</span>
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3.5 text-xs text-red-200 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => setError(null)}
            className="text-red-300 hover:text-white cursor-pointer"
            aria-label="Dismiss error"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {notice && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-3.5 text-xs text-emerald-200 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{notice}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="text-emerald-300 hover:text-white cursor-pointer"
            aria-label="Dismiss notice"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* My Devices */}
      <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Laptop className="w-4 h-4 text-emerald-400" />
              My Devices
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Devices enrolled under <code className="text-slate-300 font-mono">{data?.account.headscaleUser}</code>. Only you and administrators can see these machines.
            </p>
          </div>
        </div>

        {devices.length === 0 ? (
          <div className="p-8 text-center space-y-3">
            <p className="text-sm text-slate-300">No devices connected to your account yet.</p>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Generate a one-click setup key and paste the Tailscale connect command on your laptop, phone, or server.
            </p>
            <div className="pt-1">
              <button
                type="button"
                disabled={!serviceReady}
                onClick={() => {
                  setWizardTab('authkey');
                  setIsAddDeviceOpen(true);
                }}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Connect Your First Device</span>
              </button>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {devices.map((device) => {
              const fqdn =
                data?.network.magicDnsDomain && device.name
                  ? `${device.name}.${data.network.magicDnsDomain}`
                  : device.name;
              const isEditing = editingDeviceId === device.id;
              const isBusy = busyDeviceId === device.id;
              const isConfirmingDelete = confirmDeleteId === device.id;

              return (
                <div
                  key={String(device.id)}
                  className="p-4 sm:px-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-slate-800/30 transition"
                >
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`w-2 h-2 rounded-full shrink-0 ${
                          device.online ? 'bg-emerald-400' : 'bg-slate-600'
                        }`}
                        title={device.online ? 'Online' : 'Offline'}
                      />
                      {isEditing ? (
                        <form
                          onSubmit={(e) => {
                            e.preventDefault();
                            if (renameValue.trim()) {
                              void handleDeviceAction('rename', device.id, renameValue.trim());
                            }
                          }}
                          className="flex items-center gap-2"
                        >
                          <input
                            type="text"
                            value={renameValue}
                            onChange={(e) => setRenameValue(e.target.value)}
                            className="bg-slate-950 border border-emerald-500 rounded px-2 py-0.5 text-sm text-white font-mono w-44 focus:outline-none"
                            autoFocus
                          />
                          <button
                            type="submit"
                            disabled={isBusy}
                            className="px-2 py-0.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs cursor-pointer"
                          >
                            Save
                          </button>
                          <button
                            type="button"
                            onClick={() => setEditingDeviceId(null)}
                            className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded text-xs cursor-pointer"
                          >
                            Cancel
                          </button>
                        </form>
                      ) : (
                        <>
                          <span className="font-semibold text-sm text-white">{device.name}</span>
                          <span className="text-xs font-mono text-slate-400 truncate">{fqdn}</span>
                        </>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      {device.ipAddresses?.map((ip) => (
                        <button
                          key={ip}
                          type="button"
                          onClick={() => handleCopy(ip, `ip-${device.id}-${ip}`)}
                          className="inline-flex items-center gap-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded px-2 py-0.5 font-mono text-emerald-300 tabular-nums cursor-pointer"
                          title="Copy Tailscale IP"
                        >
                          <span>{ip}</span>
                          {copiedId === `ip-${device.id}-${ip}` ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3 text-slate-500" />
                          )}
                        </button>
                      ))}
                      <span className="text-slate-400 tabular-nums">
                        Last seen:{' '}
                        {device.lastSeen ? new Date(device.lastSeen).toLocaleString() : 'Never'}
                      </span>
                    </div>

                    {(device.approvedRoutes?.length || 0) > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                        <span className="text-[11px] text-slate-400">Approved routes:</span>
                        {device.approvedRoutes!.map((r) => (
                          <span
                            key={r}
                            className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30"
                          >
                            {r}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => {
                        setEditingDeviceId(device.id);
                        setRenameValue(device.name);
                      }}
                      className="px-2.5 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-300 flex items-center gap-1 cursor-pointer"
                      title="Rename device"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                      <span>Rename</span>
                    </button>
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void handleDeviceAction('expire', device.id)}
                      className="px-2.5 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-amber-300 flex items-center gap-1 cursor-pointer"
                      title="Force device to re-authenticate"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>Expire</span>
                    </button>
                    {isConfirmingDelete ? (
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => void handleDeviceAction('delete', device.id)}
                          className="px-2.5 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-medium cursor-pointer"
                        >
                          Confirm Remove
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirmDeleteId(null)}
                          className="px-2 py-1.5 bg-slate-800 text-slate-300 rounded-lg text-xs cursor-pointer"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => setConfirmDeleteId(device.id)}
                        className="px-2.5 py-1.5 bg-slate-950 hover:bg-red-950/60 border border-slate-800 hover:border-red-500/40 rounded-lg text-xs text-red-300 flex items-center gap-1 cursor-pointer"
                        title="Remove device"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>Remove</span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Setup Keys & Account Security Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* My Setup Keys */}
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Key className="w-4 h-4 text-emerald-400" />
                My Setup Keys
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Full key secrets are shown once when created; revoke unused keys anytime.
              </p>
            </div>
            <button
              type="button"
              disabled={!serviceReady || mintingKey}
              onClick={() => void handleMintKey(true)}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white rounded-lg text-xs font-medium flex items-center gap-1.5 cursor-pointer border border-slate-700"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Key</span>
            </button>
          </div>

          {keys.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-400">
              No setup keys issued yet. Click <strong>New Key</strong> or <strong>Add Device</strong> to generate one.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {keys.map((k) => {
                const inactive = k.expired || (!k.reusable && k.used);
                return (
                  <div
                    key={String(k.id)}
                    className="px-5 py-3.5 flex items-center justify-between gap-3 text-xs"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <code className="font-mono text-slate-200">{k.keyPreview || `Key #${k.id}`}</code>
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {k.reusable ? 'Reusable' : 'Single-use'}
                        </span>
                        {k.ephemeral && (
                          <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                            Ephemeral
                          </span>
                        )}
                        <span
                          className={`px-1.5 py-0.5 rounded border ${
                            inactive
                              ? 'bg-slate-800/70 text-slate-400 border-slate-700'
                              : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                          }`}
                        >
                          {k.expired ? 'Expired' : !k.reusable && k.used ? 'Used' : 'Active'}
                        </span>
                      </div>
                      <div className="text-slate-400 tabular-nums">
                        Expires: {k.expiration ? new Date(k.expiration).toLocaleString() : 'Unknown'}
                      </div>
                    </div>

                    {!inactive && (
                      <button
                        type="button"
                        disabled={busyKeyId === k.id}
                        onClick={() => void handleRevokeKey(k.id)}
                        className="px-2.5 py-1 bg-slate-950 hover:bg-red-950/60 border border-slate-800 hover:border-red-500/40 rounded text-xs text-red-300 cursor-pointer shrink-0"
                      >
                        {busyKeyId === k.id ? 'Revoking...' : 'Revoke'}
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* Account Security */}
        <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              Account Security
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Signed in as <code className="text-slate-200 font-mono">{data?.account.username}</code> ({data?.account.role}).
            </p>
          </div>

          {data?.account.canChangePassword ? (
            <form onSubmit={handleChangePassword} className="space-y-3">
              {passwordStatus && (
                <div
                  className={`p-3 rounded-lg text-xs border ${
                    passwordStatus.type === 'ok'
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                      : 'bg-red-500/10 border-red-500/30 text-red-200'
                  }`}
                >
                  {passwordStatus.text}
                </div>
              )}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Current Password
                </label>
                <input
                  type={showPasswords ? 'text' : 'password'}
                  required
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    New Password
                  </label>
                  <input
                    type={showPasswords ? 'text' : 'password'}
                    required
                    minLength={8}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Confirm Password
                  </label>
                  <input
                    type={showPasswords ? 'text' : 'password'}
                    required
                    minLength={8}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>
              <div className="flex items-center justify-between pt-1">
                <button
                  type="button"
                  onClick={() => setShowPasswords(!showPasswords)}
                  className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer"
                >
                  {showPasswords ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  <span>{showPasswords ? 'Hide passwords' : 'Show passwords'}</span>
                </button>
                <button
                  type="submit"
                  disabled={changingPassword}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium cursor-pointer transition"
                >
                  {changingPassword ? 'Updating...' : 'Update Password'}
                </button>
              </div>
            </form>
          ) : (
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 text-xs text-slate-300 space-y-2">
              {data?.account.source === 'local_admin' ? (
                <>
                  <p>You are signed in with the local break-glass administrator account.</p>
                  <Link
                    href="/system/users"
                    className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300 font-medium"
                  >
                    <Shield className="w-3.5 h-3.5" />
                    <span>Manage console users & credentials</span>
                  </Link>
                </>
              ) : (
                <p>
                  Your password and MFA are managed by your external authentication provider ({data?.account.source.toUpperCase()}).
                </p>
              )}
            </div>
          )}
        </section>
      </div>

      {/* Add Device Modal */}
      {isAddDeviceOpen && (
        <div
          className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="add-device-title"
        >
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h2 id="add-device-title" className="text-lg font-semibold text-white">
                  Connect a Device to Mesh VPN
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Enrolls directly under <code className="text-emerald-400 font-mono">{data?.account.headscaleUser}</code>
                </p>
              </div>
              <button
                type="button"
                onClick={() => setIsAddDeviceOpen(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
                aria-label="Close modal"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-6 border-b border-slate-800 flex gap-6 text-sm">
              <button
                type="button"
                onClick={() => setWizardTab('authkey')}
                className={`py-3 border-b-2 font-medium cursor-pointer transition ${
                  wizardTab === 'authkey'
                    ? 'border-emerald-500 text-emerald-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Quick Connect (Auth Key)
              </button>
              {data?.network.allowSelfRegistration !== false && (
                <button
                  type="button"
                  onClick={() => setWizardTab('approve')}
                  className={`py-3 border-b-2 font-medium cursor-pointer transition ${
                    wizardTab === 'approve'
                      ? 'border-emerald-500 text-emerald-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Approve Pending Device
                </button>
              )}
            </div>

            {wizardTab === 'authkey' ? (
              <div className="p-6 space-y-5">
                <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-950 border border-slate-800 rounded-lg p-3.5 text-xs">
                  <div className="flex flex-wrap items-center gap-4 text-slate-300">
                    <label className="flex items-center gap-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={keyReusable}
                        onChange={(e) => setKeyReusable(e.target.checked)}
                        className="accent-emerald-500"
                      />
                      <span>Reusable</span>
                    </label>
                    <label className="flex items-center gap-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={keyEphemeral}
                        onChange={(e) => setKeyEphemeral(e.target.checked)}
                        className="accent-emerald-500"
                      />
                      <span>Ephemeral</span>
                    </label>
                    <label className="flex items-center gap-1.5">
                      <span className="text-slate-400">Expires:</span>
                      <select
                        value={keyExpiryHours}
                        onChange={(e) => setKeyExpiryHours(Number(e.target.value))}
                        className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-white"
                      >
                        <option value={1}>1 hour</option>
                        <option value={24}>24 hours</option>
                        <option value={168}>7 days</option>
                        <option value={720}>30 days</option>
                      </select>
                    </label>
                  </div>
                  <button
                    type="button"
                    disabled={mintingKey}
                    onClick={() => void handleMintKey(false)}
                    className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium flex items-center gap-1.5 cursor-pointer"
                  >
                    {mintingKey ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Key className="w-3.5 h-3.5" />}
                    <span>{generatedKey ? 'Generate New Key' : 'Generate Setup Key'}</span>
                  </button>
                </div>

                {generatedKey && (
                  <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3 flex items-center justify-between gap-3 text-xs">
                    <div className="min-w-0">
                      <span className="text-emerald-300 font-medium block mb-0.5">Active Setup Key</span>
                      <code className="font-mono text-white break-all">{generatedKey}</code>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopy(generatedKey, 'modal-auth-key')}
                      className="shrink-0 px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-slate-200 hover:text-white flex items-center gap-1 cursor-pointer"
                    >
                      {copiedId === 'modal-auth-key' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedId === 'modal-auth-key' ? 'Copied' : 'Copy Key'}</span>
                    </button>
                  </div>
                )}

                <div className="space-y-3">
                  <div className="flex flex-wrap gap-1.5">
                    {(['linux', 'macos', 'windows', 'mobile', 'docker'] as ClientOsTab[]).map((t) => (
                      <button
                        key={t}
                        type="button"
                        onClick={() => setOsTab(t)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium border cursor-pointer transition flex items-center gap-1.5 ${
                          osTab === t
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
                            : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                        }`}
                      >
                        {t === 'mobile' ? <Smartphone className="w-3.5 h-3.5" /> : t === 'docker' ? <Server className="w-3.5 h-3.5" /> : <Terminal className="w-3.5 h-3.5" />}
                        <span>{commandByOs[t].label}</span>
                      </button>
                    ))}
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <pre className="text-xs font-mono text-emerald-300 whitespace-pre-wrap break-all flex-1">
                        {commandByOs[osTab].command}
                      </pre>
                      {commandByOs[osTab].command && (
                        <button
                          type="button"
                          onClick={() => handleCopy(commandByOs[osTab].command, `os-cmd-${osTab}`)}
                          className="shrink-0 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs flex items-center gap-1 cursor-pointer"
                        >
                          {copiedId === `os-cmd-${osTab}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          <span>{copiedId === `os-cmd-${osTab}` ? 'Copied' : 'Copy'}</span>
                        </button>
                      )}
                    </div>
                    <p className="text-xs text-slate-400">{commandByOs[osTab].hint}</p>

                    {osTab === 'mobile' && serverQrUrl && (
                      <div className="pt-2 flex items-center gap-4 border-t border-slate-800/80">
                        <div className="bg-white p-2 rounded-lg shrink-0">
                          <img src={serverQrUrl} alt="Headscale Server URL QR Code" className="w-28 h-28" />
                        </div>
                        <p className="text-xs text-slate-300">
                          Scan or copy the server URL into the Tailscale iOS/Android app&apos;s custom control server field, then approve the registration request under <strong>Approve Pending Device</strong>.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <form onSubmit={handleRegisterDevice} className="p-6 space-y-4">
                <p className="text-xs text-slate-300 leading-relaxed">
                  When a phone, tablet, or desktop runs <code className="text-emerald-300 font-mono">tailscale up --login-server={loginArg}</code> without an auth key, Tailscale shows an auth ID (<code className="font-mono text-slate-200">hskey-authreq-...</code>), node key (<code className="font-mono text-slate-200">mkey:...</code>), or full register command. Paste any of them below to bind that device to your account.
                </p>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    Auth ID, Node Key, or Headscale Register Command
                  </label>
                  <input
                    type="text"
                    required
                    value={registerInput}
                    onChange={(e) => setRegisterInput(e.target.value)}
                    placeholder="hskey-authreq-...  or  mkey:...  or full command"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-sm font-mono text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div className="flex justify-end gap-2.5">
                  <button
                    type="button"
                    onClick={() => setIsAddDeviceOpen(false)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={registering || !registerInput.trim()}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium cursor-pointer flex items-center gap-1.5"
                  >
                    {registering && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    <span>Approve Device</span>
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
