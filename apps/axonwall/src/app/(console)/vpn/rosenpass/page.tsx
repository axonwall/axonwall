'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  ShieldCheck,
  KeyRound,
  RefreshCw,
  Download,
  Upload,
  Plus,
  Trash2,
  Save,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Cpu,
  FileCode,
  Activity,
  Sliders,
} from 'lucide-react';
import { compileRosenpass } from '@axonwall/lib/compile/rosenpass';
import { compileWireGuard } from '@axonwall/lib/compile/wireguard';
import type { DesiredState, RosenpassConfig, RosenpassPeer } from '@axonwall/lib/schemas';
import {
  getCurrentDesiredState,
  applyDesiredState,
  getRosenpassStatusAction,
  generateRosenpassKeypairAction,
  exportRosenpassPublicKeyAction,
  uploadRosenpassPeerPublicKeyAction,
  type RosenpassLiveStatus,
} from '@/server/agent';

type TabId = 'control' | 'telemetry' | 'simulator';

export default function RosenpassPage() {
  const [activeTab, setActiveTab] = useState<TabId>('control');
  const [fullState, setFullState] = useState<DesiredState | null>(null);
  const [liveStatus, setLiveStatus] = useState<RosenpassLiveStatus | null>(null);
  const [saving, setSaving] = useState(false);
  const [keygenLoading, setKeygenLoading] = useState(false);
  const [statusBanner, setStatusBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const [config, setConfig] = useState<RosenpassConfig>({
    enabled: false,
    listenPort: 9999,
    listenAddresses: ['0.0.0.0:9999', '[::]:9999'],
    wgDevice: 'wg0',
    verbosity: 'Quiet',
    rekeyIntervalSeconds: 120,
    failClosedBootGuard: true,
    memfdSecret: true,
    publicKeyPath: '/etc/rosenpass/pq.pk',
    secretKeyPath: '/etc/rosenpass/pq.sk',
    publicKeySha256: undefined,
    peers: [],
  });

  // New Peer Form State
  const [peerName, setPeerName] = useState('');
  const [wgPeerPubKey, setWgPeerPubKey] = useState('');
  const [peerEndpoint, setPeerEndpoint] = useState('');
  const [peerPqPath, setPeerPqPath] = useState('');
  const [peerPqSha256, setPeerPqSha256] = useState('');
  const [uploadingPeerKey, setUploadingPeerKey] = useState(false);

  // Simulator State (ported from PostQuantumMeshSimulator.tsx)
  const [crqcActive, setCrqcActive] = useState<boolean>(true);
  const [diskCompromised, setDiskCompromised] = useState<boolean>(false);
  const [latticeBroken, setLatticeBroken] = useState<boolean>(false);
  const [rekeySeconds, setRekeySeconds] = useState<number>(120);

  const refreshAll = async (wgDev = 'wg0') => {
    try {
      const [st, live] = await Promise.all([
        getCurrentDesiredState(),
        getRosenpassStatusAction(wgDev),
      ]);
      setFullState(st);
      setLiveStatus(live);
      if (st.rosenpass) {
        setConfig({
          enabled: st.rosenpass.enabled ?? false,
          listenPort: st.rosenpass.listenPort ?? 9999,
          listenAddresses: st.rosenpass.listenAddresses ?? ['0.0.0.0:9999', '[::]:9999'],
          wgDevice: st.rosenpass.wgDevice ?? 'wg0',
          verbosity: st.rosenpass.verbosity ?? 'Quiet',
          rekeyIntervalSeconds: st.rosenpass.rekeyIntervalSeconds ?? 120,
          failClosedBootGuard: st.rosenpass.failClosedBootGuard ?? true,
          memfdSecret: st.rosenpass.memfdSecret ?? true,
          publicKeyPath: st.rosenpass.publicKeyPath ?? '/etc/rosenpass/pq.pk',
          secretKeyPath: st.rosenpass.secretKeyPath ?? '/etc/rosenpass/pq.sk',
          publicKeySha256: st.rosenpass.publicKeySha256 || live.publicKeySha256 || undefined,
          peers: st.rosenpass.peers ?? [],
        });
      } else if (live.publicKeySha256) {
        setConfig((prev) => ({ ...prev, publicKeySha256: live.publicKeySha256 }));
      }
    } catch {}
  };

  useEffect(() => {
    refreshAll();
  }, []);

  const persistConfig = async (nextCfg: RosenpassConfig) => {
    setConfig(nextCfg);
    setSaving(true);
    setStatusBanner(null);
    try {
      const current = fullState || (await getCurrentDesiredState());
      const plugins = [...(current.plugins || [])];
      const idx = plugins.findIndex((p) => p.id === 'rosenpass');
      if (idx >= 0) {
        plugins[idx] = { ...plugins[idx], enabled: nextCfg.enabled };
      } else if (nextCfg.enabled) {
        plugins.push({ id: 'rosenpass', enabled: true });
      }

      const nextState: DesiredState = {
        ...current,
        plugins,
        rosenpass: {
          ...nextCfg,
          listenAddresses: [`0.0.0.0:${nextCfg.listenPort}`, `[::]:${nextCfg.listenPort}`],
        },
      };
      const res = await applyDesiredState(nextState);
      setFullState(nextState);
      setStatusBanner({
        type: 'success',
        text: res.message || 'Saved Post-Quantum Rosenpass configuration to /etc/axonwall/vpn.yaml',
      });
    } catch (err: any) {
      setStatusBanner({
        type: 'error',
        text: err?.message || 'Failed to save Rosenpass configuration',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleGenerateLocalKeys = async (force: boolean) => {
    setKeygenLoading(true);
    setStatusBanner(null);
    try {
      const res = await generateRosenpassKeypairAction(force);
      if (res.success && res.sha256) {
        const nextCfg = {
          ...config,
          publicKeyPath: res.publicKeyPath || '/etc/rosenpass/pq.pk',
          publicKeySha256: res.sha256,
        };
        setConfig(nextCfg);
        await refreshAll(config.wgDevice);
        setStatusBanner({
          type: 'success',
          text: `Generated Classic McEliece 460896 keypair (${((res.sizeBytes || 524160) / 1024).toFixed(1)} KB) — SHA-256: ${res.sha256.slice(0, 24)}...`,
        });
      } else {
        setStatusBanner({
          type: 'error',
          text: res.error || 'Failed to generate Classic McEliece keypair',
        });
      }
    } catch (err: any) {
      setStatusBanner({
        type: 'error',
        text: err?.message || 'Error generating Classic McEliece keypair',
      });
    } finally {
      setKeygenLoading(false);
    }
  };

  const handleDownloadPublicKey = async () => {
    try {
      const res = await exportRosenpassPublicKeyAction();
      if (!res.success || !res.publicKeyBase64) {
        setStatusBanner({
          type: 'error',
          text: res.error || 'Generate a local Classic McEliece keypair first before exporting.',
        });
        return;
      }
      const binaryString = atob(res.publicKeyBase64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${fullState?.system?.hostname || 'axonwall'}-pq.pk`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setStatusBanner({
        type: 'error',
        text: err?.message || 'Failed to export pq.pk',
      });
    }
  };

  const handlePeerFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const targetName = peerName.trim() || file.name.replace(/(-pq)?\.pk$/i, '').replace(/[^a-zA-Z0-9_-]/g, '-');
    if (!peerName.trim()) {
      setPeerName(targetName);
    }
    setUploadingPeerKey(true);
    setStatusBanner(null);
    try {
      const arrayBuffer = await file.arrayBuffer();
      const bytes = new Uint8Array(arrayBuffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const base64 = btoa(binary);
      const res = await uploadRosenpassPeerPublicKeyAction(targetName, base64);
      if (res.success && res.path) {
        setPeerPqPath(res.path);
        setPeerPqSha256(res.sha256 || '');
        setStatusBanner({
          type: 'success',
          text: `Uploaded peer public key (${((res.sizeBytes || bytes.byteLength) / 1024).toFixed(1)} KB) to ${res.path}`,
        });
        await refreshAll(config.wgDevice);
      } else {
        setStatusBanner({
          type: 'error',
          text: res.error || 'Failed to upload peer public key',
        });
      }
    } catch (err: any) {
      setStatusBanner({
        type: 'error',
        text: err?.message || 'Failed to read peer key file',
      });
    } finally {
      setUploadingPeerKey(false);
    }
  };

  const handleAddPeer = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = peerName.trim().replace(/[^a-zA-Z0-9_-]/g, '');
    if (!cleanName || !wgPeerPubKey.trim()) return;

    const paddedWgKey =
      wgPeerPubKey.trim().length >= 32
        ? wgPeerPubKey.trim()
        : `${wgPeerPubKey.trim()}${'A'.repeat(32 - wgPeerPubKey.trim().length)}=`;

    const newPeer: RosenpassPeer = {
      name: cleanName,
      wgPeerPublicKey: paddedWgKey,
      endpoint: peerEndpoint.trim() || undefined,
      pqPublicKeyPath: peerPqPath.trim() || `/etc/rosenpass/peers/${cleanName}-pq.pk`,
      pqPublicKeySha256: peerPqSha256 || undefined,
      wgDevice: config.wgDevice || 'wg0',
      enabled: true,
    };

    const nextCfg: RosenpassConfig = {
      ...config,
      enabled: true,
      peers: [...config.peers.filter((p) => p.name !== cleanName), newPeer],
    };

    setPeerName('');
    setWgPeerPubKey('');
    setPeerEndpoint('');
    setPeerPqPath('');
    setPeerPqSha256('');
    await persistConfig(nextCfg);
  };

  const handleRemovePeer = async (name: string) => {
    const nextCfg: RosenpassConfig = {
      ...config,
      peers: config.peers.filter((p) => p.name !== name),
    };
    await persistConfig(nextCfg);
  };

  const compiledRosenpass = useMemo(() => compileRosenpass(config), [config]);
  const compiledWireGuard = useMemo(() => {
    const wg = fullState?.wireguard || {
      enabled: true,
      address: '10.99.0.1/24',
      listenPort: 51820,
      peers: config.peers.map((p, idx) => ({
        name: p.name,
        publicKey: p.wgPeerPublicKey,
        allowedIps: [`10.99.0.${idx + 2}/32`],
        endpoint: p.endpoint ? p.endpoint.replace(/:\d+$/, ':51820') : undefined,
        persistentKeepalive: 25,
        enabled: p.enabled,
      })),
    };
    return compileWireGuard(wg as any, config);
  }, [fullState?.wireguard, config]);

  // Simulator evaluation matrix (ported from PostQuantumMeshSimulator.tsx)
  const simArchitectures = useMemo(() => {
    const classicalBroken = crqcActive;
    const staticPskBroken = crqcActive && diskCompromised;
    const singleKemBroken = crqcActive && latticeBroken;
    const dualKemBroken = crqcActive && latticeBroken && diskCompromised;

    return [
      {
        id: 'classical-wg',
        name: '1. Classical WireGuard (Noise_IKpsk2, PSK = 0x00)',
        primitives: 'Curve25519 + ChaCha20-Poly1305',
        wireBytes: '148 B',
        pkDiskBytes: '32 B',
        status: classicalBroken ? 'COMPROMISED (HNDL)' : 'SECURE (CLASSICAL ONLY)',
        isSecure: !classicalBroken,
        verdict: classicalBroken
          ? 'Shor’s algorithm recovers Curve25519 static & ephemeral private keys from passive PCAPs. With PSK = 0x00..00, all recorded historical sessions are decrypted.'
          : 'Secure against purely classical adversaries, but zero protection against Harvest-Now, Decrypt-Later (HNDL) quantum adversaries.',
      },
      {
        id: 'static-psk-wg',
        name: '2. WireGuard + Static Pre-Shared Key (wg genpsk)',
        primitives: 'Curve25519 + Static 256-bit PSK on Disk',
        wireBytes: '148 B',
        pkDiskBytes: '64 B',
        status: staticPskBroken
          ? 'COMPROMISED (NO PQ FORWARD SECRECY)'
          : classicalBroken
            ? 'FRAGILE (NO PQ FORWARD SECRECY)'
            : 'SECURE',
        isSecure: !staticPskBroken,
        isWarning: classicalBroken && !staticPskBroken,
        verdict: staticPskBroken
          ? 'Static PSK was exfiltrated from /etc/wireguard/wg0.conf during endpoint breach. Combined with Shor’s algorithm on Curve25519, all past PCAPs are retroactively decrypted.'
          : classicalBroken
            ? 'Blocks immediate quantum decryption via Grover-resistant 256-bit PSK, but lacks Post-Quantum Forward Secrecy: a single future disk breach compromises all historical traffic.'
            : 'Provides symmetric 256-bit pre-shared key mixing.',
      },
      {
        id: 'single-kem-mlkem',
        name: '3. Single-KEM Hybrid (X25519 + ML-KEM-768 Only)',
        primitives: 'X25519 + Ephemeral ML-KEM-768 (Lattice)',
        wireBytes: '2,368 B (IP Frag)',
        pkDiskBytes: '1,216 B',
        status: singleKemBroken ? 'COMPROMISED (SINGLE-FAMILY FAILURE)' : 'SECURE (SINGLE PQ FAMILY)',
        isSecure: !singleKemBroken,
        verdict: singleKemBroken
          ? 'Both classical ECDH (broken by CRQC) and the single lattice KEM (ML-KEM) failed simultaneously, collapsing tunnel confidentiality.'
          : 'Provides post-quantum forward secrecy, but relies on a single post-quantum mathematical assumption (Module-LWE) and exceeds 1500B Ethernet MTU if embedded inline.',
      },
      {
        id: 'rosenpass-dual-kem',
        name: '4. WireGuard + Rosenpass Dual-KEM (McEliece + ML-KEM)',
        primitives: 'Curve25519 + Classic McEliece 460896 + ML-KEM-512',
        wireBytes: '1,212 B (Fits 1500 MTU)',
        pkDiskBytes: '524,160 B (~512 KB)',
        status: dualKemBroken ? 'COMPROMISED' : 'QUANTUM-SAFE + PQ FORWARD SECRET',
        isSecure: !dualKemBroken,
        verdict: dualKemBroken
          ? 'Total catastrophic break of Elliptic Curves, Lattices, AND physical endpoint disk simultaneously.'
          : diskCompromised
            ? `Even with /etc/rosenpass/pq.sk leaked and CRQC active, ephemeral ML-KEM-512 keys were zeroized in memfd_secret() every ${rekeySeconds}s—preserving Forward Secrecy!`
            : latticeBroken
              ? 'Even if a breakthrough weakens ML-KEM lattices and CRQC breaks Curve25519, Classic McEliece 460896 (code-based Syndrome Decoding) independently protects the OSKK!'
              : `Combiner mixes Curve25519, Classic McEliece 460896, and ephemeral ML-KEM-512 via keyed BLAKE2b PRF tree, rotating kernel WireGuard PSK every ${rekeySeconds}s.`,
      },
    ];
  }, [crqcActive, diskCompromised, latticeBroken, rekeySeconds]);

  const activeSha = config.publicKeySha256 || liveStatus?.publicKeySha256 || '';

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-2xl font-bold tracking-tight text-white">
                Post-Quantum WireGuard Mesh (Rosenpass)
              </h1>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                Classic McEliece 460896 + ML-KEM-512
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Out-of-band Dual-KEM post-quantum control plane rotating kernel <code className="text-emerald-400 font-mono">wireguard.ko</code> pre-shared keys every 120s.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => refreshAll(config.wgDevice)}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            onClick={() => persistConfig(config)}
            disabled={saving}
            className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3.5 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? 'Applying...' : 'Save & Apply to vpn.yaml'}</span>
          </button>
        </div>
      </div>

      {statusBanner && (
        <div
          className={`p-3 rounded-lg text-xs flex items-center gap-2 border ${
            statusBanner.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-red-500/10 border-red-500/30 text-red-300'
          }`}
        >
          {statusBanner.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          )}
          <span>{statusBanner.text}</span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        <button
          type="button"
          onClick={() => setActiveTab('control')}
          className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition cursor-pointer ${
            activeTab === 'control'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
              : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
          }`}
        >
          <KeyRound className="w-3.5 h-3.5" />
          <span>1. Dual-KEM Control Plane & Peers</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('telemetry')}
          className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition cursor-pointer ${
            activeTab === 'telemetry'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
              : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>2. Live Kernel PQ-PSK Telemetry & Configs</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('simulator')}
          className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition cursor-pointer ${
            activeTab === 'simulator'
              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
              : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>3. HNDL & Dual-KEM Threat Simulator</span>
        </button>
      </div>

      {/* TAB 1: Control Plane & Peers */}
      {activeTab === 'control' && (
        <div className="space-y-6">
          {/* Top Grid: Daemon Control + Local Classic McEliece Keypair */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Daemon Settings Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <Cpu className="w-4 h-4 text-emerald-400" />
                  <h2 className="text-base font-bold text-white">Rosenpass Daemon Control Plane</h2>
                </div>
                <button
                  type="button"
                  onClick={() => persistConfig({ ...config, enabled: !config.enabled })}
                  className={`text-xs px-3 py-1 rounded-lg font-semibold cursor-pointer border transition ${
                    config.enabled
                      ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  {config.enabled ? 'Daemon Enabled' : 'Daemon Disabled'}
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">UDP Listen Port</label>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={config.listenPort}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        listenPort: Number(e.target.value) || 9999,
                      })
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">WireGuard Interface</label>
                  <input
                    type="text"
                    value={config.wgDevice}
                    onChange={(e) => setConfig({ ...config, wgDevice: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-emerald-400 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">OSKK Rekey Interval (sec)</label>
                  <input
                    type="number"
                    min={30}
                    max={300}
                    value={config.rekeyIntervalSeconds}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        rekeyIntervalSeconds: Math.min(300, Math.max(30, Number(e.target.value) || 120)),
                      })
                    }
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Daemon Verbosity</label>
                  <select
                    value={config.verbosity}
                    onChange={(e) => setConfig({ ...config, verbosity: e.target.value as 'Quiet' | 'Verbose' })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white"
                  >
                    <option value="Quiet">Quiet (Production)</option>
                    <option value="Verbose">Verbose (Handshake Debug)</option>
                  </select>
                </div>
              </div>

              <div className="space-y-2.5 pt-2 border-t border-slate-800">
                <label className="flex items-start gap-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.failClosedBootGuard}
                    onChange={(e) => setConfig({ ...config, failClosedBootGuard: e.target.checked })}
                    className="mt-1 accent-emerald-500"
                  />
                  <div>
                    <span className="text-xs font-semibold text-white block">
                      Fail-Closed Boot Guard (<code className="text-emerald-400 font-mono">PostUp /dev/urandom</code> PSK Seed)
                    </span>
                    <span className="text-[11px] text-slate-400 block">
                      Seeds each peer with a random 256-bit throwaway key on <code className="font-mono">wg0</code> bring-up so the kernel refuses classical-only (<code className="font-mono">0x00..00</code>) handshakes before Rosenpass finishes its first Dual-KEM exchange.
                    </span>
                  </div>
                </label>

                <label className="flex items-start gap-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.memfdSecret}
                    onChange={(e) => setConfig({ ...config, memfdSecret: e.target.checked })}
                    className="mt-1 accent-emerald-500"
                  />
                  <div>
                    <span className="text-xs font-semibold text-white block">
                      Linux <code className="text-emerald-400 font-mono">memfd_secret()</code> &amp; <code className="text-emerald-400 font-mono">mlock()</code> Ephemeral Key Isolation
                    </span>
                    <span className="text-[11px] text-slate-400 block">
                      Locks ephemeral <code className="font-mono">ML-KEM-512</code> decapsulation keys and BLAKE2b chaining states into unswappable secret pages unmapped from the kernel direct map.
                    </span>
                  </div>
                </label>
              </div>
            </div>

            {/* Local Node Classic McEliece 460896 Identity Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <Lock className="w-4 h-4 text-emerald-400" />
                  <h2 className="text-base font-bold text-white">Local Classic McEliece 460896 Identity</h2>
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  524,160 B (~512 KB PK)
                </span>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500 font-sans">Public Key Path:</span>
                  <span className="text-slate-200">{config.publicKeyPath}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-500 font-sans">Secret Key Path (0600):</span>
                  <span className="text-slate-200">{config.secretKeyPath}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-500 font-sans">Wire Ciphertext Overhead:</span>
                  <span className="text-emerald-400">156 Bytes (No IP Fragmentation)</span>
                </div>
                <div className="pt-2 border-t border-slate-800/80">
                  <span className="text-slate-500 font-sans block mb-1">
                    Local Public Key SHA-256 Fingerprint (Out-of-Band Verification):
                  </span>
                  {activeSha ? (
                    <div className="bg-slate-900 border border-emerald-500/30 rounded px-2.5 py-1.5 text-emerald-300 break-all select-all text-[11px]">
                      {activeSha}
                    </div>
                  ) : (
                    <div className="text-amber-400 font-sans text-xs">
                      No Classic McEliece 460896 keypair generated yet. Click below to provision.
                    </div>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2.5 pt-1">
                <button
                  type="button"
                  onClick={() => handleGenerateLocalKeys(Boolean(activeSha))}
                  disabled={keygenLoading}
                  className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  <span>
                    {keygenLoading
                      ? 'Generating 512 KB McEliece Keypair...'
                      : activeSha
                        ? 'Rotate Classic McEliece Keypair'
                        : 'Generate Classic McEliece Keypair'}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={handleDownloadPublicKey}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download pq.pk (512 KB)</span>
                </button>
              </div>
            </div>
          </div>

          {/* Post-Quantum Peer Bindings Table & Add Form */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Post-Quantum Dual-KEM Peer Bindings</h2>
                <p className="text-xs text-slate-400">
                  Each peer pairs a 512 KB <code className="text-emerald-400 font-mono">Classic McEliece 460896</code> public key on disk with a kernel WireGuard <code className="text-emerald-400 font-mono">Curve25519</code> peer on <code className="font-mono">{config.wgDevice}</code>.
                </p>
              </div>
              <span className="text-xs font-mono text-slate-400">{config.peers.length} PQ peers</span>
            </div>

            {config.peers.length === 0 ? (
              <div className="p-8 text-center border border-slate-800 rounded-lg text-slate-400">
                <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="text-sm font-semibold text-slate-300">No Post-Quantum Peers Configured</p>
                <p className="text-xs text-slate-500 mt-1">
                  Bind a WireGuard peer below and upload its <code className="text-emerald-400">pq.pk</code> file to begin 120-second Dual-KEM PSK rotation.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800 font-sans">
                    <tr>
                      <th className="px-4 py-3">Peer Name</th>
                      <th className="px-4 py-3">WireGuard Peer (Curve25519)</th>
                      <th className="px-4 py-3">Rosenpass UDP Endpoint</th>
                      <th className="px-4 py-3">McEliece PK Path &amp; SHA-256</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {config.peers.map((peer) => (
                      <tr key={peer.name} className="hover:bg-slate-800/40 transition">
                        <td className="px-4 py-3 font-semibold text-white font-sans">{peer.name}</td>
                        <td className="px-4 py-3 text-slate-300">{peer.wgPeerPublicKey.slice(0, 20)}...</td>
                        <td className="px-4 py-3 text-emerald-400">{peer.endpoint || 'Passive Responder'}</td>
                        <td className="px-4 py-3">
                          <div className="text-slate-200">{peer.pqPublicKeyPath}</div>
                          {peer.pqPublicKeySha256 && (
                            <div className="text-[10px] text-slate-500">
                              SHA-256: {peer.pqPublicKeySha256.slice(0, 24)}...
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            type="button"
                            onClick={() => handleRemovePeer(peer.name)}
                            className="text-slate-500 hover:text-red-400 transition p-1 cursor-pointer"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Add PQ Peer Form */}
            <form onSubmit={handleAddPeer} className="space-y-3 pt-4 border-t border-slate-800">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Peer Identifier</label>
                  <input
                    type="text"
                    value={peerName}
                    onChange={(e) => setPeerName(e.target.value)}
                    placeholder="beta-node"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">
                    WireGuard Peer Public Key
                    {fullState?.wireguard?.peers && fullState.wireguard.peers.length > 0 && (
                      <select
                        onChange={(e) => {
                          const found = fullState.wireguard?.peers.find((p) => p.publicKey === e.target.value);
                          if (found) {
                            setWgPeerPubKey(found.publicKey);
                            if (!peerName) setPeerName(found.name.replace(/[^a-zA-Z0-9_-]/g, '-'));
                          }
                        }}
                        className="ml-2 bg-slate-900 border border-slate-700 rounded px-1.5 py-0.5 text-[10px] text-emerald-300"
                        defaultValue=""
                      >
                        <option value="" disabled>
                          Select from wg0...
                        </option>
                        {fullState.wireguard.peers.map((p) => (
                          <option key={p.name} value={p.publicKey}>
                            {p.name}
                          </option>
                        ))}
                      </select>
                    )}
                  </label>
                  <input
                    type="text"
                    value={wgPeerPubKey}
                    onChange={(e) => setWgPeerPubKey(e.target.value)}
                    placeholder="Base64 Curve25519 Public Key"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Rosenpass UDP Endpoint (Optional)</label>
                  <input
                    type="text"
                    value={peerEndpoint}
                    onChange={(e) => setPeerEndpoint(e.target.value)}
                    placeholder="203.0.113.20:9999"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Peer Classic McEliece Public Key (.pk)</label>
                  <label className="w-full bg-slate-950 hover:bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-emerald-300 flex items-center justify-center gap-1.5 cursor-pointer transition">
                    <Upload className="w-3.5 h-3.5" />
                    <span>{uploadingPeerKey ? 'Uploading...' : peerPqPath ? 'Uploaded pq.pk ✓' : 'Upload Peer pq.pk'}</span>
                    <input type="file" accept=".pk,application/octet-stream" onChange={handlePeerFileUpload} className="hidden" />
                  </label>
                </div>
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={saving}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add Post-Quantum Peer</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* TAB 2: Live Kernel PQ-PSK Telemetry & Configs */}
      {activeTab === 'telemetry' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">
                  Zero-Key-Leakage Kernel <code className="text-emerald-400 font-mono">wg0</code> PQ-PSK Rotation Telemetry
                </h2>
                <p className="text-xs text-slate-400">
                  <code className="font-mono">axonwalld</code> hashes <code className="font-mono">wg show {config.wgDevice} preshared-keys</code> via SHA-256 in Go before returning telemetry—verifying 120s <code className="text-emerald-400 font-mono">OSKK</code> rotation without ever exposing raw key bytes.
                </p>
              </div>
              <span
                className={`text-xs font-mono px-2.5 py-1 rounded border ${
                  liveStatus?.serviceActive
                    ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                    : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}
              >
                rosenpass.service: {liveStatus?.serviceActive ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </div>

            {(!liveStatus?.wireguardPeers || liveStatus.wireguardPeers.length === 0) ? (
              <div className="p-6 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-400">
                No active kernel WireGuard peers reported by <code className="text-emerald-400 font-mono">wg show {config.wgDevice} preshared-keys</code> yet. Below is the configured peer state and compiled fail-closed configuration.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800 font-sans">
                    <tr>
                      <th className="px-4 py-3">WireGuard Peer Public Key</th>
                      <th className="px-4 py-3">Kernel PSK Status</th>
                      <th className="px-4 py-3">Active OSKK SHA-256 Prefix</th>
                      <th className="px-4 py-3">Latest Handshake</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {liveStatus.wireguardPeers.map((wp) => (
                      <tr key={wp.wgPeerPublicKey}>
                        <td className="px-4 py-3 text-white">{wp.wgPeerPublicKey}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-sans font-semibold border ${
                              wp.pskStatus === 'active_pq_psk'
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                : 'bg-red-500/15 text-red-300 border-red-500/30'
                            }`}
                          >
                            {wp.pskStatus === 'active_pq_psk' ? 'ACTIVE PQ-PSK' : 'UNSEEDED (CLASSICAL ONLY)'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-emerald-400">
                          {wp.pskSha256Prefix ? `sha256:${wp.pskSha256Prefix}...` : '0x00..00 (None)'}
                        </td>
                        <td className="px-4 py-3 text-slate-400">
                          {wp.latestHandshakeUnix > 0
                            ? new Date(wp.latestHandshakeUnix * 1000).toLocaleTimeString()
                            : 'Awaiting handshake'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Compiled Config Previews */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-white flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-emerald-400" />
                  <span>Compiled /etc/rosenpass/config.toml (0600)</span>
                </span>
              </div>
              <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 text-xs font-mono text-emerald-300 overflow-x-auto">
                {compiledRosenpass.configToml}
              </pre>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-white flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-emerald-400" />
                  <span>Compiled /etc/wireguard/wg0.conf (Fail-Closed PostUp)</span>
                </span>
              </div>
              <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 text-xs font-mono text-slate-300 overflow-x-auto">
                {compiledWireGuard.wgConfig}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Interactive HNDL & Dual-KEM Threat Simulator */}
      {activeTab === 'simulator' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <span className="text-[11px] font-mono uppercase tracking-wider text-emerald-400 block">
              Interactive Cryptographic Resilience &amp; HNDL Simulator
            </span>
            <h2 className="text-lg font-bold text-white mt-1">
              WireGuard + Rosenpass Dual-KEM vs. Quantum &amp; Endpoint Compromise Models
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Toggle adversary capabilities below to evaluate how Classical ECDH, Static PSK, Single-KEM Lattice, and Rosenpass Dual-KEM (<code className="text-emerald-400 font-mono">Classic McEliece 460896</code> + <code className="text-emerald-400 font-mono">ML-KEM-512</code>) respond to Harvest-Now-Decrypt-Later (HNDL) and state compromise.
            </p>
          </div>

          {/* Adversary Controls */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 bg-slate-950 border border-slate-800 rounded-xl p-4">
            <label className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-900 border border-slate-800 cursor-pointer">
              <input
                type="checkbox"
                checked={crqcActive}
                onChange={(e) => setCrqcActive(e.target.checked)}
                className="mt-1 accent-red-500"
              />
              <div>
                <span className="text-xs font-bold text-white block">CRQC Active (Shor’s Algorithm)</span>
                <span className="text-[11px] text-slate-400 block">
                  Breaks Curve25519 ECDH discrete logarithms in polynomial time.
                </span>
              </div>
            </label>

            <label className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-900 border border-slate-800 cursor-pointer">
              <input
                type="checkbox"
                checked={diskCompromised}
                onChange={(e) => setDiskCompromised(e.target.checked)}
                className="mt-1 accent-amber-500"
              />
              <div>
                <span className="text-xs font-bold text-white block">Future Disk Compromise</span>
                <span className="text-[11px] text-slate-400 block">
                  Adversary later exfiltrates /etc/wireguard &amp; /etc/rosenpass static keys.
                </span>
              </div>
            </label>

            <label className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-900 border border-slate-800 cursor-pointer">
              <input
                type="checkbox"
                checked={latticeBroken}
                onChange={(e) => setLatticeBroken(e.target.checked)}
                className="mt-1 accent-purple-500"
              />
              <div>
                <span className="text-xs font-bold text-white block">Lattice Cryptanalysis Flaw</span>
                <span className="text-[11px] text-slate-400 block">
                  Hypothetical mathematical break of Module-LWE (ML-KEM-512 / 768).
                </span>
              </div>
            </label>

            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex flex-col justify-between">
              <div className="flex justify-between text-xs">
                <span className="text-slate-400 font-semibold">PQ-PSK Rekey Interval</span>
                <span className="text-emerald-400 font-mono font-bold">{rekeySeconds}s</span>
              </div>
              <input
                type="range"
                min={30}
                max={300}
                step={30}
                value={rekeySeconds}
                onChange={(e) => setRekeySeconds(Number(e.target.value))}
                className="w-full accent-emerald-500 my-1"
              />
              <span className="text-[10px] text-slate-500 font-mono">
                Matches wireguard.ko REKEY_AFTER_TIME (120s)
              </span>
            </div>
          </div>

          {/* 4-Architecture Comparison Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {simArchitectures.map((arch) => (
              <div
                key={arch.id}
                className={`rounded-xl p-4 border space-y-3 ${
                  arch.isSecure
                    ? arch.isWarning
                      ? 'bg-amber-950/15 border-amber-500/40'
                      : 'bg-emerald-950/15 border-emerald-500/40'
                    : 'bg-red-950/20 border-red-500/40'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-bold text-white">{arch.name}</h3>
                    <span className="text-[11px] font-mono text-slate-400">{arch.primitives}</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border whitespace-nowrap ${
                      arch.isSecure
                        ? arch.isWarning
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        : 'bg-red-500/20 text-red-300 border-red-500/40'
                    }`}
                  >
                    {arch.status}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 bg-slate-950/80 border border-slate-800/80 rounded-lg p-2.5 text-xs font-mono">
                  <div>
                    <span className="text-[10px] text-slate-500 block font-sans">Handshake Wire Size</span>
                    <span className="text-slate-200">{arch.wireBytes}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 block font-sans">Disk Public Key Size</span>
                    <span className="text-slate-200">{arch.pkDiskBytes}</span>
                  </div>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{arch.verdict}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
