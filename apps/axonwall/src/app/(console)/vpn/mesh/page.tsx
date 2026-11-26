'use client';

import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  AlertCircle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Edit3,
  ExternalLink,
  Globe,
  Key,
  Link2,
  Loader2,
  Plus,
  RefreshCw,
  RotateCcw,
  Route,
  Save,
  Server,
  Shield,
  Trash2,
  UserPlus,
  Users,
  X,
} from 'lucide-react';
import { getCurrentDesiredState } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import type { DesiredState } from '@axonwall/lib/schemas';

type Tab = 'people' | 'machines' | 'keys';

interface PersonRow {
  id: string | number;
  name: string;
  createdAt?: string;
  machineCount: number;
  onlineCount: number;
  activeKeyCount: number;
  applianceRole: string | null;
  displayName: string;
  hasDirectoryAccount: boolean;
}

interface DirectorySummary {
  username: string;
  comment: string;
  applianceRole: string;
  passwordLocked: boolean;
}

interface InviteRow {
  id: string;
  username: string;
  displayName: string;
  mode: 'onboard' | 'reset';
  createdAt: string;
  expiresAt: string;
  createdBy: string;
  createStarterKey: boolean;
  requiresPin?: boolean;
  effectiveStatus: 'pending' | 'redeemed' | 'revoked' | 'expired';
}

interface WanWindowStatus {
  enabled: boolean;
  autoWindow: boolean;
  bindPort: number;
  hostname: string;
  windowOpen: boolean;
  reason: 'disabled' | 'always_open' | 'pending_invites' | 'manual_arm' | 'closed';
  pendingCount: number;
  pendingExpiresAt?: string;
  manualExpiresAt?: string;
  effectiveExpiresAt?: string;
  portKnockingEnabled: boolean;
  knockProtocol?: string;
  knockSequence?: number[];
  knockedIPs: string[];
  lastSyncError?: string;
  daemonAvailable?: boolean;
}

export default function MeshVpnPage() {
  const { applyState } = useDesiredStateApply();
  const [activeTab, setActiveTab] = useState<Tab>('people');
  const [fullState, setFullState] = useState<DesiredState | null>(null);

  // Headscale DesiredState config
  const [headscaleEnabled, setHeadscaleEnabled] = useState(false);
  const [serverUrl, setServerUrl] = useState('');
  const [magicDnsDomain, setMagicDnsDomain] = useState('tailnet.axonwall.local');
  const [portalUrl, setPortalUrl] = useState('');
  const [allowSelfRegistration, setAllowSelfRegistration] = useState(true);
  const [defaultKeyExpiryHours, setDefaultKeyExpiryHours] = useState(24);
  const [savingConfig, setSavingConfig] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  // WAN Invite Access & Port Knocking config + live window status
  const [wanSectionOpen, setWanSectionOpen] = useState(false);
  const [wanInviteEnabled, setWanInviteEnabled] = useState(false);
  const [wanHostname, setWanHostname] = useState('');
  const [wanBindPort, setWanBindPort] = useState(8443);
  const [wanCertName, setWanCertName] = useState('hub');
  const [wanAutoWindow, setWanAutoWindow] = useState(true);
  const [wanRequirePin, setWanRequirePin] = useState(false);
  const [wanAllowedCidrsInput, setWanAllowedCidrsInput] = useState('');
  const [wanExposeControl, setWanExposeControl] = useState(false);
  const [knockEnabled, setKnockEnabled] = useState(false);
  const [knockProtocol, setKnockProtocol] = useState<'udp' | 'tcp'>('udp');
  const [knockSequenceInput, setKnockSequenceInput] = useState('41821, 52913, 38477');
  const [knockStepTimeoutSec, setKnockStepTimeoutSec] = useState(15);
  const [knockOpenDurationSec, setKnockOpenDurationSec] = useState(900);
  const [wanWindowStatus, setWanWindowStatus] = useState<WanWindowStatus | null>(null);
  const [updatingWanWindow, setUpdatingWanWindow] = useState(false);

  // People & Invites data
  const [headscaleAvailable, setHeadscaleAvailable] = useState(true);
  const [headscaleError, setHeadscaleError] = useState<string | null>(null);
  const [directoryAvailable, setDirectoryAvailable] = useState(true);
  const [minPasswordLength, setMinPasswordLength] = useState(12);
  const [people, setPeople] = useState<PersonRow[]>([]);
  const [eligibleExisting, setEligibleExisting] = useState<DirectorySummary[]>([]);
  const [invites, setInvites] = useState<InviteRow[]>([]);

  // Machines & Keys data
  const [machines, setMachines] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [keys, setKeys] = useState<any[]>([]);

  // Shared UI states
  const [loading, setLoading] = useState(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Add / Invite Person Modal
  const [isAddPersonOpen, setIsAddPersonOpen] = useState(false);
  const [personFlow, setPersonFlow] = useState<'invite' | 'direct'>('invite');
  const [personUsername, setPersonUsername] = useState('');
  const [personDisplayName, setPersonDisplayName] = useState('');
  const [inviteMode, setInviteMode] = useState<'onboard' | 'reset'>('onboard');
  const [inviteExpiryHours, setInviteExpiryHours] = useState(48);
  const [starterKeyEnabled, setStarterKeyEnabled] = useState(true);
  const [inviteRequirePin, setInviteRequirePin] = useState(false);
  const [autoGeneratePassword, setAutoGeneratePassword] = useState(true);
  const [directPassword, setDirectPassword] = useState('');
  const [submittingPerson, setSubmittingPerson] = useState(false);
  const [personModalError, setPersonModalError] = useState<string | null>(null);
  const [onboardedResult, setOnboardedResult] = useState<any | null>(null);

  // Remove Person confirmation modal
  const [removingPerson, setRemovingPerson] = useState<PersonRow | null>(null);
  const [removeMachinesChecked, setRemoveMachinesChecked] = useState(false);
  const [removeDirChecked, setRemoveDirChecked] = useState(false);
  const [submittingRemove, setSubmittingRemove] = useState(false);

  // Auth Key Tab creation state
  const [newKeyUser, setNewKeyUser] = useState('');
  const [newKeyReusable, setNewKeyReusable] = useState(false);
  const [newKeyEphemeral, setNewKeyEphemeral] = useState(false);
  const [newKeyDaysOrHours, setNewKeyDaysOrHours] = useState(24);
  const [createdKeyBanner, setCreatedKeyBanner] = useState<{
    key: string;
    user: string;
    command: string;
  } | null>(null);

  // Machine management modals & inline controls
  const [isRegisterModalOpen, setIsRegisterModalOpen] = useState(false);
  const [registerUser, setRegisterUser] = useState('');
  const [registerKeyInput, setRegisterKeyInput] = useState('');
  const [submittingRegister, setSubmittingRegister] = useState(false);

  const [editingMachineId, setEditingMachineId] = useState<string | number | null>(null);
  const [renameMachineValue, setRenameMachineValue] = useState('');

  const [routeMachine, setRouteMachine] = useState<any | null>(null);
  const [routeCandidates, setRouteCandidates] = useState<Array<{ prefix: string; enabled: boolean }>>([]);
  const [customRoutesInput, setCustomRoutesInput] = useState('');
  const [loadingRoutes, setLoadingRoutes] = useState(false);
  const [savingRoutes, setSavingRoutes] = useState(false);

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        setFullState(state);
        if (state.headscale) {
          setHeadscaleEnabled(Boolean(state.headscale.enabled));
          setMagicDnsDomain(state.headscale.magicDnsDomain || 'tailnet.axonwall.local');
          setServerUrl(state.headscale.serverUrl || '');
          setPortalUrl(state.headscale.portalUrl || '');
          setAllowSelfRegistration(state.headscale.allowSelfRegistration !== false);
          setDefaultKeyExpiryHours(state.headscale.defaultKeyExpiryHours ?? 24);
          const wan = state.headscale.wanInvite;
          if (wan) {
            setWanInviteEnabled(Boolean(wan.enabled));
            setWanSectionOpen(Boolean(wan.enabled));
            setWanHostname(wan.hostname || '');
            setWanBindPort(wan.bindPort ?? 8443);
            setWanCertName(wan.certName || 'hub');
            setWanAutoWindow(wan.autoWindow !== false);
            setWanRequirePin(Boolean(wan.requirePin));
            setWanAllowedCidrsInput((wan.allowedCidrs ?? []).join(', '));
            setWanExposeControl(Boolean(wan.exposeHeadscaleControl));
            if (wan.portKnocking) {
              setKnockEnabled(Boolean(wan.portKnocking.enabled));
              setKnockProtocol(wan.portKnocking.protocol === 'tcp' ? 'tcp' : 'udp');
              if (wan.portKnocking.sequence?.length) {
                setKnockSequenceInput(wan.portKnocking.sequence.join(', '));
              }
              setKnockStepTimeoutSec(wan.portKnocking.stepTimeoutSec ?? 15);
              setKnockOpenDurationSec(wan.portKnocking.openDurationSec ?? 900);
            }
          }
        }
      })
      .catch(() => {});

    fetch('/api/v1/vpn/mesh/config', { cache: 'no-store' })
      .then((r) => r.json())
      .then((json) => {
        if (json?.status === 'ok' && json.data) {
          setServerUrl((prev) => prev || json.data.serverUrl || '');
          setMagicDnsDomain((prev) => prev || json.data.magicDnsDomain || 'tailnet.axonwall.local');
        }
      })
      .catch(() => {});
  }, []);

  const fetchWanWindowStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/vpn/mesh/wan-window', { cache: 'no-store' });
      const json = await res.json().catch(() => null);
      if (res.ok && json?.status === 'ok' && json.data) {
        setWanWindowStatus(json.data);
      }
    } catch {}
  }, []);

  const fetchTabData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (activeTab === 'people') {
        const res = await fetch('/api/v1/vpn/mesh/people', { cache: 'no-store' });
        const json = await res.json().catch(() => null);
        if (!res.ok || json?.status !== 'ok') {
          throw new Error(json?.error || `Failed to load people directory (HTTP ${res.status})`);
        }
        const d = json.data;
        setHeadscaleAvailable(Boolean(d.headscaleAvailable));
        setHeadscaleError(d.headscaleError || null);
        setDirectoryAvailable(Boolean(d.directoryAvailable));
        setMinPasswordLength(d.passwordPolicy?.minLength ?? 12);
        setPeople(d.headscaleUsers || []);
        setUsers(d.headscaleUsers || []);
        setEligibleExisting(d.eligibleExistingUsers || []);
        setInvites(d.invites || []);
        void fetchWanWindowStatus();
      } else if (activeTab === 'machines') {
        const [mRes, uRes] = await Promise.all([
          fetch('/api/v1/vpn/mesh/machines', { cache: 'no-store' }),
          fetch('/api/v1/vpn/mesh/users', { cache: 'no-store' }),
        ]);
        const mJson = await mRes.json().catch(() => null);
        const uJson = await uRes.json().catch(() => null);
        if (!mRes.ok || mJson?.status !== 'ok') {
          throw new Error(mJson?.error || 'Failed to fetch machines');
        }
        setMachines(mJson.data || []);
        if (uRes.ok && uJson?.status === 'ok') {
          setUsers(uJson.data || []);
        }
      } else if (activeTab === 'keys') {
        const [kRes, uRes] = await Promise.all([
          fetch('/api/v1/vpn/mesh/keys', { cache: 'no-store' }),
          fetch('/api/v1/vpn/mesh/users', { cache: 'no-store' }),
        ]);
        const kJson = await kRes.json().catch(() => null);
        const uJson = await uRes.json().catch(() => null);
        if (!kRes.ok || kJson?.status !== 'ok') {
          throw new Error(kJson?.error || 'Failed to fetch auth keys');
        }
        setKeys(kJson.data || []);
        if (uRes.ok && uJson?.status === 'ok') {
          setUsers(uJson.data || []);
        }
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch Headscale data');
    } finally {
      setLoading(false);
    }
  }, [activeTab, fetchWanWindowStatus]);

  useEffect(() => {
    void fetchTabData();
  }, [fetchTabData]);

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 2000);
    } catch {}
  };

  const handleSaveHeadscaleConfig = async () => {
    const prevFullState = fullState;
    setSavingConfig(true);
    setStatusMsg(null);
    try {
      const cleanDomain = magicDnsDomain.trim() || 'tailnet.axonwall.local';
      const cleanServerUrl = serverUrl.trim().replace(/\/+$/, '');
      const cleanPortalUrl = portalUrl.trim().replace(/\/+$/, '');
      const parsedAllowedCidrs = wanAllowedCidrsInput
        .split(/[,\s]+/)
        .map((c) => c.trim())
        .filter(Boolean);
      const parsedKnockSeq = knockSequenceInput
        .split(/[,\s]+/)
        .map((s) => Number.parseInt(s.trim(), 10))
        .filter((n) => Number.isInteger(n) && n >= 1024 && n <= 65535)
        .slice(0, 5);
      const effectiveKnockSeq = parsedKnockSeq.length >= 2 ? parsedKnockSeq : [41821, 52913, 38477];

      const current = await getCurrentDesiredState();
      const nextState: DesiredState = {
        ...current,
        headscale: {
          enabled: headscaleEnabled,
          magicDnsDomain: cleanDomain,
          serverUrl: cleanServerUrl,
          portalUrl: cleanPortalUrl,
          allowSelfRegistration,
          defaultKeyExpiryHours,
          wanInvite: {
            enabled: wanInviteEnabled,
            hostname: wanHostname.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, ''),
            bindPort: Math.min(65535, Math.max(1, Math.round(Number(wanBindPort) || 8443))),
            certName: wanCertName.trim() || 'hub',
            autoWindow: wanAutoWindow,
            requirePin: wanRequirePin,
            allowedCidrs: parsedAllowedCidrs,
            exposeHeadscaleControl: wanExposeControl,
            portKnocking: {
              enabled: knockEnabled,
              protocol: knockProtocol,
              sequence: effectiveKnockSeq,
              stepTimeoutSec: Math.min(60, Math.max(3, Math.round(Number(knockStepTimeoutSec) || 15))),
              openDurationSec: Math.min(86400, Math.max(60, Math.round(Number(knockOpenDurationSec) || 900))),
            },
          },
        },
      };
      setFullState(nextState);
      const res = await applyState(nextState);

      let syncSuffix = '';
      try {
        const syncRes = await fetch('/api/v1/vpn/mesh/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            serverUrl: cleanServerUrl,
            magicDnsDomain: cleanDomain,
          }),
        });
        const syncJson = await syncRes.json().catch(() => null);
        if (!syncRes.ok || syncJson?.status !== 'ok') {
          syncSuffix = ` (Warning syncing /etc/headscale/config.yaml: ${syncJson?.error || syncRes.status})`;
        } else if (syncJson?.data?.reloaded) {
          syncSuffix = ' and reloaded headscale.service';
        }
      } catch {}

      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('axonwall-capabilities-updated'));
      }
      setStatusMsg(
        (res.message || 'Saved Headscale configuration to /etc/axonwall/vpn.yaml') + syncSuffix
      );
      void fetchTabData();
      void fetchWanWindowStatus();
    } catch (err: any) {
      setFullState(prevFullState);
      setStatusMsg(`Error: ${err?.message || 'Failed to save Headscale settings'}`);
    } finally {
      setSavingConfig(false);
    }
  };

  const handleWanWindowAction = async (action: 'arm' | 'close' | 'sync', durationSec = 1800) => {
    setUpdatingWanWindow(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/wan-window', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, durationSec }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Failed to update WAN window (${res.status})`);
      }
      setWanWindowStatus(json.data);
      setStatusMsg(
        action === 'close'
          ? 'WAN invite manual window closed.'
          : action === 'arm'
            ? `WAN invite window manually armed for ${Math.round(durationSec / 60)} minutes.`
            : 'Synced WAN invite window with active invites.'
      );
    } catch (err: any) {
      setError(err?.message || 'Failed to update WAN invite window');
    } finally {
      setUpdatingWanWindow(false);
    }
  };

  const openAddPersonModal = (opts?: { flow?: 'invite' | 'direct'; mode?: 'onboard' | 'reset'; username?: string; displayName?: string }) => {
    setPersonFlow(opts?.flow ?? 'invite');
    setInviteMode(opts?.mode ?? 'onboard');
    setPersonUsername(opts?.username ?? '');
    setPersonDisplayName(opts?.displayName ?? '');
    setDirectPassword('');
    setInviteRequirePin(wanRequirePin);
    setPersonModalError(null);
    setOnboardedResult(null);
    setIsAddPersonOpen(true);
  };

  const handleSubmitPerson = async (e: React.FormEvent) => {
    e.preventDefault();
    setPersonModalError(null);
    setSubmittingPerson(true);
    try {
      const payload =
        personFlow === 'invite'
          ? {
              action: 'invite',
              username: personUsername.trim().toLowerCase(),
              displayName: personDisplayName.trim(),
              mode: inviteMode,
              expiryHours: inviteExpiryHours,
              createStarterKey: starterKeyEnabled,
              requirePin: inviteRequirePin,
            }
          : {
              action: 'create_direct',
              username: personUsername.trim().toLowerCase(),
              displayName: personDisplayName.trim(),
              generatePassword: autoGeneratePassword,
              password: autoGeneratePassword ? undefined : directPassword,
              createStarterKey: starterKeyEnabled,
              keyExpiryHours: defaultKeyExpiryHours,
            };

      const res = await fetch('/api/v1/vpn/mesh/people', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Operation failed (HTTP ${res.status})`);
      }
      setOnboardedResult(json.data);
      void fetchTabData();
    } catch (err: any) {
      setPersonModalError(err?.message || 'Failed to add person');
    } finally {
      setSubmittingPerson(false);
    }
  };

  const handleEnableExistingUser = async (u: DirectorySummary) => {
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/people', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'enable_existing',
          username: u.username,
          grantPortalRole: u.applianceRole === 'os_only',
        }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Failed to enable Mesh VPN for ${u.username}`);
      }
      setStatusMsg(`Mesh VPN enabled for '${u.username}'. They can manage their own devices at /vpn.`);
      void fetchTabData();
    } catch (err: any) {
      setError(err?.message || 'Failed to enable existing user');
    }
  };

  const handleRevokeInvite = async (inviteId: string) => {
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/people', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'revoke_invite', inviteId }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || 'Failed to revoke invite');
      }
      void fetchTabData();
    } catch (err: any) {
      setError(err?.message || 'Failed to revoke invite');
    }
  };

  const handleRemovePerson = async () => {
    if (!removingPerson) return;
    setSubmittingRemove(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/people', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'remove_person',
          username: removingPerson.name,
          deleteMachines: removeMachinesChecked,
          deleteDirectoryUser: removeDirChecked,
        }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Failed to remove '${removingPerson.name}'`);
      }
      setRemovingPerson(null);
      setStatusMsg(`Removed '${removingPerson.name}' from Headscale.`);
      void fetchTabData();
    } catch (err: any) {
      setError(err?.message || 'Removal failed');
    } finally {
      setSubmittingRemove(false);
    }
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyUser.trim()) return;
    setError(null);
    setCreatedKeyBanner(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'create',
          user: newKeyUser.trim(),
          reusable: newKeyReusable,
          ephemeral: newKeyEphemeral,
          expiration: new Date(Date.now() + newKeyDaysOrHours * 3600 * 1000).toISOString(),
        }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Failed to create auth key (HTTP ${res.status})`);
      }
      const loginArg = serverUrl.trim() ? `--login-server=${serverUrl.trim().replace(/\/+$/, '')}` : '--login-server=<HEADSCALE_URL>';
      setCreatedKeyBanner({
        key: json.data.key,
        user: newKeyUser.trim(),
        command: `sudo tailscale up ${loginArg} --authkey=${json.data.key}`,
      });
      void fetchTabData();
    } catch (err: any) {
      setError(err?.message || 'Failed to create auth key');
    }
  };

  const handleExpireKey = async (k: any) => {
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'expire',
          user: k.user?.name || '',
          keyId: k.id,
          key: k.key,
        }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || 'Failed to expire key');
      }
      void fetchTabData();
    } catch (err: any) {
      setError(err?.message || 'Failed to expire key');
    }
  };

  const handleMachineAction = async (
    action: 'rename' | 'expire' | 'delete',
    machineId: string | number,
    newName?: string
  ) => {
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/machines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, machineId, newName }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || `Failed to ${action} machine`);
      }
      setEditingMachineId(null);
      void fetchTabData();
    } catch (err: any) {
      setError(err?.message || `Machine ${action} failed`);
    }
  };

  const handleRegisterMachine = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!registerUser.trim() || !registerKeyInput.trim()) return;
    setSubmittingRegister(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/vpn/mesh/machines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'register',
          user: registerUser.trim(),
          key: registerKeyInput.trim(),
        }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || 'Failed to register machine');
      }
      setIsRegisterModalOpen(false);
      setRegisterKeyInput('');
      setStatusMsg(`Registered device to '${registerUser.trim()}'.`);
      void fetchTabData();
    } catch (err: any) {
      setError(err?.message || 'Machine registration failed');
    } finally {
      setSubmittingRegister(false);
    }
  };

  const openRoutesModal = async (machine: any) => {
    setRouteMachine(machine);
    setLoadingRoutes(true);
    setRouteCandidates([]);
    setCustomRoutesInput('');
    try {
      const res = await fetch(
        `/api/v1/vpn/mesh/routes?machineId=${encodeURIComponent(String(machine.id))}`,
        { cache: 'no-store' }
      );
      const json = await res.json().catch(() => null);
      const list: Array<{ prefix: string; enabled: boolean }> = [];
      if (res.ok && json?.status === 'ok' && Array.isArray(json.data) && json.data.length > 0) {
        for (const r of json.data) {
          if (typeof r === 'string') {
            list.push({ prefix: r, enabled: (machine.approvedRoutes || []).includes(r) });
          } else if (r?.prefix) {
            list.push({ prefix: r.prefix, enabled: Boolean(r.enabled) });
          }
        }
      } else {
        const avail = Array.isArray(machine.availableRoutes) ? machine.availableRoutes : [];
        const appr = Array.isArray(machine.approvedRoutes) ? machine.approvedRoutes : [];
        const combined = Array.from(new Set([...avail, ...appr]));
        for (const p of combined) {
          list.push({ prefix: p, enabled: appr.includes(p) });
        }
      }
      setRouteCandidates(list);
    } catch {
      setRouteCandidates([]);
    } finally {
      setLoadingRoutes(false);
    }
  };

  const handleSaveRoutes = async () => {
    if (!routeMachine) return;
    setSavingRoutes(true);
    setError(null);
    try {
      const checked = routeCandidates.filter((r) => r.enabled).map((r) => r.prefix);
      const extras = customRoutesInput
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const routes = Array.from(new Set([...checked, ...extras]));
      const res = await fetch('/api/v1/vpn/mesh/routes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ machineId: routeMachine.id, routes }),
      });
      const json = await res.json().catch(() => null);
      if (!res.ok || json?.status !== 'ok') {
        throw new Error(json?.error || 'Failed to update machine routes');
      }
      setRouteMachine(null);
      setStatusMsg(`Updated approved routes for ${routeMachine.name}.`);
      void fetchTabData();
    } catch (err: any) {
      setError(err?.message || 'Failed to save routes');
    } finally {
      setSavingRoutes(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-emerald-400" />
            Mesh VPN (Headscale)
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Add people with one-click invite links or instant credentials, synced with{' '}
            <code className="text-emerald-400 font-mono">/etc/axonwall/vpn.yaml</code> and{' '}
            <code className="text-slate-300 font-mono">/etc/headscale/config.yaml</code>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <Link
            href="/vpn"
            className="bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5 transition"
          >
            <ExternalLink className="w-3.5 h-3.5 text-emerald-400" />
            <span>My Self-Service Portal</span>
          </Link>
          <button
            type="button"
            onClick={() => openAddPersonModal({ flow: 'invite', mode: 'onboard' })}
            className="bg-emerald-600 hover:bg-emerald-500 text-white px-3.5 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer shadow-sm"
          >
            <UserPlus className="w-3.5 h-3.5" />
            <span>Add / Invite Person</span>
          </button>
          <button
            type="button"
            onClick={handleSaveHeadscaleConfig}
            disabled={savingConfig}
            className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white border border-slate-700 px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5 transition cursor-pointer"
          >
            <Save className="w-3.5 h-3.5 text-emerald-400" />
            <span>{savingConfig ? 'Saving...' : 'Save Settings'}</span>
          </button>
        </div>
      </div>

      {statusMsg && (
        <div
          className={`p-3.5 rounded-lg text-xs flex items-center justify-between gap-2 ${
            statusMsg.startsWith('Error:')
              ? 'bg-red-500/10 border border-red-500/30 text-red-300'
              : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {statusMsg.startsWith('Error:') ? (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            )}
            <span>{statusMsg}</span>
          </div>
          <button
            type="button"
            onClick={() => setStatusMsg(null)}
            className="text-slate-400 hover:text-white cursor-pointer"
            aria-label="Dismiss status message"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Control Plane Configuration */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
        <div className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5">
          <span className="font-medium text-slate-200">Control Plane</span>
          <button
            type="button"
            onClick={() => setHeadscaleEnabled(!headscaleEnabled)}
            className={`px-2.5 py-1 rounded font-medium border cursor-pointer transition ${
              headscaleEnabled
                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
          >
            {headscaleEnabled ? 'Enabled' : 'Disabled'}
          </button>
        </div>

        <div>
          <label className="block text-[11px] font-medium text-slate-400 mb-1">
            Public Control Server URL (for Tailscale clients)
          </label>
          <input
            type="url"
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
            placeholder="https://vpn.example.com"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-emerald-300 font-mono placeholder-slate-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div>
          <label className="block text-[11px] font-medium text-slate-400 mb-1">
            MagicDNS Base Domain
          </label>
          <input
            type="text"
            value={magicDnsDomain}
            onChange={(e) => setMagicDnsDomain(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div>
          <label className="block text-[11px] font-medium text-slate-400 mb-1">
            Invite &amp; Portal Base URL (optional override)
          </label>
          <input
            type="url"
            value={portalUrl}
            onChange={(e) => setPortalUrl(e.target.value)}
            placeholder="Defaults to current console origin"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 font-mono placeholder-slate-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5">
          <span className="font-medium text-slate-200">Member Self-Registration (Auth ID / Key)</span>
          <button
            type="button"
            onClick={() => setAllowSelfRegistration(!allowSelfRegistration)}
            className={`px-2.5 py-1 rounded font-medium border cursor-pointer transition ${
              allowSelfRegistration
                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
          >
            {allowSelfRegistration ? 'Allowed' : 'Keys Only'}
          </button>
        </div>

        <div>
          <label className="block text-[11px] font-medium text-slate-400 mb-1">
            Default Self-Service Key TTL
          </label>
          <select
            value={defaultKeyExpiryHours}
            onChange={(e) => setDefaultKeyExpiryHours(Number(e.target.value))}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-100 focus:outline-none focus:border-emerald-500"
          >
            <option value={1}>1 hour</option>
            <option value={24}>24 hours</option>
            <option value={72}>3 days</option>
            <option value={168}>7 days</option>
          </select>
        </div>
      </div>

      {/* WAN Invite Access & Port Knocking */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden text-xs">
        <div className="px-5 py-3.5 flex flex-wrap items-center justify-between gap-3 bg-slate-900/90">
          <button
            type="button"
            onClick={() => setWanSectionOpen((prev) => !prev)}
            className="flex items-center gap-2.5 text-left cursor-pointer"
          >
            <Globe className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <div className="font-semibold text-white flex flex-wrap items-center gap-2">
                <span>WAN Invite Access &amp; Port Knocking</span>
                <span
                  className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                    !wanInviteEnabled
                      ? 'bg-slate-800 text-slate-400 border-slate-700'
                      : wanWindowStatus?.windowOpen
                        ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                        : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                  }`}
                >
                  {!wanInviteEnabled
                    ? 'WAN Invite Disabled'
                    : wanWindowStatus?.reason === 'always_open'
                      ? `Open (Always On :${wanBindPort})`
                      : wanWindowStatus?.windowOpen
                        ? `Window Open (${wanWindowStatus.pendingCount} pending · :${wanWindowStatus.bindPort})`
                        : 'Window Closed (0 open ports)'}
                </span>
                {wanInviteEnabled && knockEnabled && (
                  <span className="px-2 py-0.5 rounded-full text-[11px] font-medium bg-amber-500/15 text-amber-300 border border-amber-500/30">
                    Knock Required
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Exposes only <code className="text-emerald-400 font-mono">/invite/*</code> via SNI-pinned HAProxy while blocking{' '}
                <code className="text-slate-300 font-mono">/login</code> and <code className="text-slate-300 font-mono">/vpn</code> from WAN. Remember to click <strong>Save Settings</strong> after edits.
              </p>
            </div>
            {wanSectionOpen ? (
              <ChevronUp className="w-4 h-4 text-slate-400 shrink-0" />
            ) : (
              <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
            )}
          </button>

          <div className="flex flex-wrap items-center gap-2">
            {wanInviteEnabled && wanAutoWindow && (
              <>
                <button
                  type="button"
                  disabled={updatingWanWindow}
                  onClick={() => void handleWanWindowAction('arm', 1800)}
                  className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 disabled:opacity-50 border border-slate-700 rounded text-emerald-300 cursor-pointer"
                >
                  Open Window (30m)
                </button>
                <button
                  type="button"
                  disabled={updatingWanWindow}
                  onClick={() => void handleWanWindowAction('close', 0)}
                  className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 disabled:opacity-50 border border-slate-700 rounded text-amber-300 cursor-pointer"
                >
                  Close Now
                </button>
              </>
            )}
            <button
              type="button"
              onClick={() => {
                const next = !wanInviteEnabled;
                setWanInviteEnabled(next);
                if (next) setWanSectionOpen(true);
              }}
              className={`px-2.5 py-1 rounded font-medium border cursor-pointer transition ${
                wanInviteEnabled
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}
            >
              {wanInviteEnabled ? 'Enabled' : 'Disabled'}
            </button>
          </div>
        </div>

        {wanSectionOpen && (
          <div className="p-5 pt-4 border-t border-slate-800 space-y-4">
            {wanWindowStatus && wanInviteEnabled && (
              <div className="bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-3 text-[11px] text-slate-300">
                <div className="flex flex-wrap items-center gap-4">
                  <span>
                    Active Pending Invites: <strong className="text-white">{wanWindowStatus.pendingCount}</strong>
                  </span>
                  {wanWindowStatus.effectiveExpiresAt && (
                    <span>
                      Auto-Closes: <strong className="text-emerald-300">{new Date(wanWindowStatus.effectiveExpiresAt).toLocaleString()}</strong>
                    </span>
                  )}
                  {wanWindowStatus.portKnockingEnabled && (
                    <span>
                      Knocked-In IPs: <strong className="text-cyan-300">{wanWindowStatus.knockedIPs.length}</strong>
                      {wanWindowStatus.knockedIPs.length > 0 && (
                        <span className="text-slate-400 font-mono ml-1.5">
                          ({wanWindowStatus.knockedIPs.slice(0, 3).join(', ')}{wanWindowStatus.knockedIPs.length > 3 ? '...' : ''})
                        </span>
                      )}
                    </span>
                  )}
                </div>
                {wanWindowStatus.lastSyncError && (
                  <span className="text-amber-300">{wanWindowStatus.lastSyncError}</span>
                )}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Public Invite Hostname (SNI Pinned)
                </label>
                <input
                  type="text"
                  value={wanHostname}
                  onChange={(e) => setWanHostname(e.target.value)}
                  placeholder="join.example.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-emerald-300 font-mono placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  WAN HTTPS Bind Port
                </label>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={wanBindPort}
                  onChange={(e) => setWanBindPort(Number(e.target.value) || 8443)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  TLS Certificate Name (/etc/axonwall/certs/&lt;name&gt;.pem)
                </label>
                <input
                  type="text"
                  value={wanCertName}
                  onChange={(e) => setWanCertName(e.target.value)}
                  placeholder="hub"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Allowed Source CIDRs (optional comma list)
                </label>
                <input
                  type="text"
                  value={wanAllowedCidrsInput}
                  onChange={(e) => setWanAllowedCidrsInput(e.target.value)}
                  placeholder="Any IP when blank"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 font-mono placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <label className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 cursor-pointer">
                <div>
                  <span className="font-medium text-slate-200 block">Auto-Close Window (Zero Open Ports)</span>
                  <span className="text-[11px] text-slate-400">Closes port automatically when 0 invites are pending</span>
                </div>
                <input
                  type="checkbox"
                  checked={wanAutoWindow}
                  onChange={(e) => setWanAutoWindow(e.target.checked)}
                  className="accent-emerald-500"
                />
              </label>

              <label className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 cursor-pointer">
                <div>
                  <span className="font-medium text-slate-200 block">Require Out-of-Band 6-Digit PIN</span>
                  <span className="text-[11px] text-slate-400">Default PIN gate for newly issued invites</span>
                </div>
                <input
                  type="checkbox"
                  checked={wanRequirePin}
                  onChange={(e) => setWanRequirePin(e.target.checked)}
                  className="accent-emerald-500"
                />
              </label>

              <label className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 cursor-pointer">
                <div>
                  <span className="font-medium text-slate-200 block">Co-Host Headscale Control Plane</span>
                  <span className="text-[11px] text-slate-400">
                    Allows Tailscale client paths on this port{wanAutoWindow ? ' (blocked while window closed)' : ''}
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={wanExposeControl}
                  onChange={(e) => setWanExposeControl(e.target.checked)}
                  className="accent-emerald-500"
                />
              </label>
            </div>

            {/* Optional Kernel-Native Port Knocking */}
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <span className="font-semibold text-slate-200">
                    Optional Stateful nftables Port Knocking
                  </span>
                  <p className="text-[11px] text-slate-400">
                    Require WAN visitors to knock a stealth port sequence before the kernel accepts TLS packets to port {wanBindPort}.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setKnockEnabled(!knockEnabled)}
                  className={`px-2.5 py-1 rounded font-medium border cursor-pointer transition ${
                    knockEnabled
                      ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  {knockEnabled ? 'Knock Required' : 'Off'}
                </button>
              </div>

              {knockEnabled && (
                <div className="space-y-3 pt-2 border-t border-slate-800/80">
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1">Protocol</label>
                      <select
                        value={knockProtocol}
                        onChange={(e) => setKnockProtocol(e.target.value === 'tcp' ? 'tcp' : 'udp')}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-100"
                      >
                        <option value="udp">UDP (Stealth / Silent)</option>
                        <option value="tcp">TCP SYN</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1">
                        Knock Port Sequence (2–5 ports)
                      </label>
                      <input
                        type="text"
                        value={knockSequenceInput}
                        onChange={(e) => setKnockSequenceInput(e.target.value)}
                        placeholder="41821, 52913, 38477"
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-amber-200 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1">
                        Step Timeout (3–60s)
                      </label>
                      <input
                        type="number"
                        min={3}
                        max={60}
                        value={knockStepTimeoutSec}
                        onChange={(e) => setKnockStepTimeoutSec(Number(e.target.value) || 15)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-100 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1">
                        Source Allow TTL (60–86400s)
                      </label>
                      <input
                        type="number"
                        min={60}
                        max={86400}
                        value={knockOpenDurationSec}
                        onChange={(e) => setKnockOpenDurationSec(Number(e.target.value) || 900)}
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-100 font-mono"
                      />
                    </div>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-[11px]">
                    <span className="text-slate-400 block mb-1">Client Knock Command Preview:</span>
                    <code className="font-mono text-amber-300 break-all">
                      {`for p in ${knockSequenceInput
                        .split(/[,\s]+/)
                        .map((s) => s.trim())
                        .filter(Boolean)
                        .join(' ')}; do ${
                        knockProtocol === 'tcp' ? 'nc -z -w 1' : "printf 'knock' | nc -u -w 1"
                      } ${wanHostname.trim() || '<INVITE_HOST>'} "$p" >/dev/null 2>&1 || true; sleep 0.25; done`}
                    </code>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-800 flex items-center justify-between gap-4">
        <nav className="-mb-px flex space-x-6" aria-label="Tabs">
          <button
            type="button"
            onClick={() => setActiveTab('people')}
            className={`whitespace-nowrap py-3.5 px-1 border-b-2 font-medium text-sm flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'people'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Users className="w-4 h-4" />
            <span>People &amp; Invites</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('machines')}
            className={`whitespace-nowrap py-3.5 px-1 border-b-2 font-medium text-sm flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'machines'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-4 h-4" />
            <span>Machines</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('keys')}
            className={`whitespace-nowrap py-3.5 px-1 border-b-2 font-medium text-sm flex items-center gap-2 cursor-pointer transition ${
              activeTab === 'keys'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Key className="w-4 h-4" />
            <span>Auth Keys</span>
          </button>
        </nav>

        <button
          type="button"
          onClick={() => void fetchTabData()}
          className="text-xs text-slate-400 hover:text-white flex items-center gap-1.5 pb-1 cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-200 px-4 py-3 rounded-lg text-xs flex items-center justify-between gap-2">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)} className="cursor-pointer">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* PEOPLE & INVITES TAB */}
      {activeTab === 'people' && (
        <div className="space-y-6">
          {!headscaleAvailable && (
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 text-xs text-amber-200 flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Headscale control plane is not running yet.</p>
                <p className="text-amber-100/80 mt-0.5">
                  {headscaleError || 'Enable Headscale above and click Save Settings to start headscale.service.'} You can still prepare invite links or enable directory accounts below.
                </p>
              </div>
            </div>
          )}

          {/* Existing Axonwall Directory Users Quick-Enable */}
          {directoryAvailable && eligibleExisting.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold text-white">Enable Existing Axonwall Users in Mesh VPN</h2>
                  <p className="text-xs text-slate-400">
                    One click creates their Headscale namespace (and grants Self-Service Portal access if OS-only).
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                {eligibleExisting.map((u) => (
                  <button
                    key={u.username}
                    type="button"
                    onClick={() => void handleEnableExistingUser(u)}
                    className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-emerald-500/40 rounded-lg text-xs text-slate-200 flex items-center gap-2 cursor-pointer transition"
                  >
                    <Plus className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="font-mono">{u.username}</span>
                    <span className="text-[11px] text-slate-400">({u.applianceRole})</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Active People Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-white">Mesh VPN People</h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Each person gets an isolated namespace and can self-manage only their own devices at{' '}
                  <code className="text-emerald-400 font-mono">/vpn</code>.
                </p>
              </div>
            </div>

            {loading ? (
              <div className="p-6 text-sm text-slate-400 flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
                <span>Loading Mesh VPN members...</span>
              </div>
            ) : people.length === 0 ? (
              <div className="p-10 text-center space-y-3">
                <p className="text-sm text-slate-300">No people added to Headscale yet.</p>
                <button
                  type="button"
                  onClick={() => openAddPersonModal({ flow: 'invite', mode: 'onboard' })}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Invite Your First Person</span>
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">Person / Namespace</th>
                      <th className="px-4 py-3">Role</th>
                      <th className="px-4 py-3">Devices</th>
                      <th className="px-4 py-3">Active Keys</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {people.map((p) => (
                      <tr key={String(p.id)} className="hover:bg-slate-800/30 transition">
                        <td className="px-4 py-3">
                          <div className="font-semibold text-white">{p.displayName}</div>
                          <div className="text-slate-400 font-mono">{p.name}</div>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex px-2 py-0.5 rounded-full border text-[11px] font-medium ${
                              p.applianceRole === 'vpn_user'
                                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                                : p.applianceRole === 'admin'
                                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                  : p.applianceRole
                                    ? 'bg-blue-500/15 text-blue-300 border-blue-500/30'
                                    : 'bg-slate-800 text-slate-400 border-slate-700'
                            }`}
                          >
                            {p.applianceRole === 'vpn_user'
                              ? 'VPN Member (Self-Service)'
                              : p.applianceRole || 'Headscale Namespace Only'}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono tabular-nums text-slate-200">
                          {p.onlineCount}/{p.machineCount} online
                        </td>
                        <td className="px-4 py-3 font-mono tabular-nums text-slate-300">
                          {p.activeKeyCount}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              type="button"
                              onClick={() => {
                                setNewKeyUser(p.name);
                                setActiveTab('keys');
                              }}
                              className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-slate-200 cursor-pointer"
                            >
                              Issue Key
                            </button>
                            {p.applianceRole === 'vpn_user' && (
                              <button
                                type="button"
                                onClick={() =>
                                  openAddPersonModal({
                                    flow: 'invite',
                                    mode: 'reset',
                                    username: p.name,
                                    displayName: p.displayName,
                                  })
                                }
                                className="px-2.5 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-cyan-300 cursor-pointer"
                              >
                                Reset Link
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => {
                                setRemovingPerson(p);
                                setRemoveMachinesChecked(p.machineCount > 0);
                                setRemoveDirChecked(p.applianceRole === 'vpn_user');
                              }}
                              className="px-2.5 py-1 bg-slate-950 hover:bg-red-950/60 border border-slate-800 hover:border-red-500/40 rounded text-red-300 cursor-pointer"
                            >
                              Remove
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Pending & Recent Invites */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Link2 className="w-4 h-4 text-emerald-400" />
                Invite Links
              </h2>
            </div>

            {invites.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-400">
                No invite links generated yet. Use <strong>Add / Invite Person</strong> to send a single-use onboarding link.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">Person</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Expires</th>
                      <th className="px-4 py-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {invites.map((inv) => (
                      <tr key={inv.id} className="hover:bg-slate-800/30">
                        <td className="px-4 py-3">
                          <div className="font-semibold text-white">{inv.displayName}</div>
                          <div className="text-slate-400 font-mono">{inv.username}</div>
                        </td>
                        <td className="px-4 py-3 text-slate-300">
                          {inv.mode === 'reset' ? 'Password Reset' : 'Account Onboard'}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded border text-[11px] font-medium ${
                              inv.effectiveStatus === 'pending'
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                : inv.effectiveStatus === 'redeemed'
                                  ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                                  : 'bg-slate-800 text-slate-400 border-slate-700'
                            }`}
                          >
                            {inv.effectiveStatus}
                          </span>
                          {inv.requiresPin && (
                            <span className="ml-1.5 px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 text-[10px]">
                              PIN
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-slate-400 tabular-nums">
                          {new Date(inv.expiresAt).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 text-right">
                          {inv.effectiveStatus === 'pending' && (
                            <button
                              type="button"
                              onClick={() => void handleRevokeInvite(inv.id)}
                              className="px-2.5 py-1 bg-slate-950 hover:bg-red-950/60 border border-slate-800 rounded text-red-300 cursor-pointer"
                            >
                              Revoke
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* MACHINES TAB */}
      {activeTab === 'machines' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-5 border-b border-slate-800 flex flex-wrap justify-between items-center gap-3">
            <div>
              <h2 className="text-base font-bold text-white">Connected Machines</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Approve subnet routes, rename, expire, or register nodes on behalf of any user.
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                setRegisterUser(users[0]?.name || '');
                setIsRegisterModalOpen(true);
              }}
              className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium flex items-center gap-1.5 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Register Pending Device</span>
            </button>
          </div>
          {loading ? (
            <div className="p-5 text-sm text-slate-400">Loading machines...</div>
          ) : machines.length === 0 ? (
            <div className="p-10 text-center text-sm text-slate-400">
              No machines connected yet. Add a person and have them sign in to <code className="text-emerald-400 font-mono">/vpn</code> or mint an auth key.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Machine</th>
                    <th className="px-4 py-3">IP Addresses</th>
                    <th className="px-4 py-3">User</th>
                    <th className="px-4 py-3">Routes</th>
                    <th className="px-4 py-3">Last Seen</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {machines.map((m: any) => (
                    <tr key={m.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span
                            className={`w-2 h-2 rounded-full ${m.online ? 'bg-emerald-400' : 'bg-slate-600'}`}
                          />
                          {editingMachineId === m.id ? (
                            <form
                              onSubmit={(e) => {
                                e.preventDefault();
                                if (renameMachineValue.trim()) {
                                  void handleMachineAction('rename', m.id, renameMachineValue.trim());
                                }
                              }}
                              className="flex items-center gap-1.5"
                            >
                              <input
                                type="text"
                                value={renameMachineValue}
                                onChange={(e) => setRenameMachineValue(e.target.value)}
                                className="bg-slate-950 border border-emerald-500 rounded px-2 py-0.5 text-xs font-mono text-white w-36"
                                autoFocus
                              />
                              <button type="submit" className="px-2 py-0.5 bg-emerald-600 text-white rounded">
                                Save
                              </button>
                              <button
                                type="button"
                                onClick={() => setEditingMachineId(null)}
                                className="px-1.5 py-0.5 bg-slate-800 text-slate-300 rounded"
                              >
                                Cancel
                              </button>
                            </form>
                          ) : (
                            <div>
                              <div className="font-semibold text-white">{m.name}</div>
                              <div className="text-slate-500 font-mono">ID {m.id}</div>
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-emerald-400 font-mono tabular-nums">
                        {m.ipAddresses?.join(', ') || '-'}
                      </td>
                      <td className="px-4 py-3 text-slate-200 font-mono">{m.user?.name || '-'}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap items-center gap-1">
                          {(m.approvedRoutes || []).map((r: string) => (
                            <span
                              key={r}
                              className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-mono"
                            >
                              {r}
                            </span>
                          ))}
                          {(m.availableRoutes || [])
                            .filter((r: string) => !(m.approvedRoutes || []).includes(r))
                            .map((r: string) => (
                              <span
                                key={r}
                                className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 font-mono"
                                title="Advertised subnet route awaiting approval"
                              >
                                {r} (pending)
                              </span>
                            ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-slate-400 tabular-nums">
                        {m.lastSeen ? new Date(m.lastSeen).toLocaleString() : 'Never'}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => void openRoutesModal(m)}
                            className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-cyan-300 flex items-center gap-1 cursor-pointer"
                          >
                            <Route className="w-3 h-3" />
                            <span>Routes</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setEditingMachineId(m.id);
                              setRenameMachineValue(m.name);
                            }}
                            className="p-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-slate-300 cursor-pointer"
                            title="Rename machine"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleMachineAction('expire', m.id)}
                            className="p-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-amber-300 cursor-pointer"
                            title="Expire machine session"
                          >
                            <RotateCcw className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              if (window.confirm(`Delete machine '${m.name}' (${m.id})?`)) {
                                void handleMachineAction('delete', m.id);
                              }
                            }}
                            className="p-1.5 bg-slate-950 hover:bg-red-950/60 border border-slate-800 rounded text-red-300 cursor-pointer"
                            title="Delete machine"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* KEYS TAB */}
      {activeTab === 'keys' && (
        <div className="space-y-4">
          <form onSubmit={handleCreateKey} className="bg-slate-900 border border-slate-800 rounded-xl p-5 grid grid-cols-1 sm:grid-cols-4 gap-4 items-end">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Select User</label>
              <select
                value={newKeyUser}
                onChange={(e) => setNewKeyUser(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
              >
                <option value="">-- Choose User --</option>
                {users.map((u) => (
                  <option key={u.id ?? u.name} value={u.name}>
                    {u.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Expiration</label>
              <select
                value={newKeyDaysOrHours}
                onChange={(e) => setNewKeyDaysOrHours(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
              >
                <option value={1}>1 hour</option>
                <option value={24}>24 hours</option>
                <option value={168}>7 days</option>
                <option value={720}>30 days</option>
                <option value={2160}>90 days</option>
              </select>
            </div>
            <div className="flex items-center gap-4 pb-2 text-xs text-slate-300">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={newKeyReusable}
                  onChange={(e) => setNewKeyReusable(e.target.checked)}
                  className="accent-emerald-500"
                />
                <span>Reusable</span>
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={newKeyEphemeral}
                  onChange={(e) => setNewKeyEphemeral(e.target.checked)}
                  className="accent-emerald-500"
                />
                <span>Ephemeral</span>
              </label>
            </div>
            <button
              type="submit"
              disabled={!newKeyUser}
              className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Generate Auth Key</span>
            </button>
          </form>

          {createdKeyBanner && (
            <div className="bg-emerald-950/40 border border-emerald-500/40 rounded-xl p-4 space-y-2.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-emerald-300">
                  Created key for <code className="font-mono text-white">{createdKeyBanner.user}</code> (copy now)
                </span>
                <button type="button" onClick={() => setCreatedKeyBanner(null)} className="text-slate-400 hover:text-white cursor-pointer">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 flex items-center justify-between gap-2">
                <code className="font-mono text-emerald-300 break-all">{createdKeyBanner.command}</code>
                <button
                  type="button"
                  onClick={() => handleCopy(createdKeyBanner.command, 'created-key-cmd')}
                  className="shrink-0 px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded flex items-center gap-1 cursor-pointer"
                >
                  {copiedId === 'created-key-cmd' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy Command</span>
                </button>
              </div>
            </div>
          )}

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            {loading ? (
              <div className="p-5 text-sm text-slate-400">Loading keys...</div>
            ) : keys.length === 0 ? (
              <div className="p-10 text-center text-sm text-slate-400">No auth keys found.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-3">User</th>
                      <th className="px-4 py-3">Key</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Expiration</th>
                      <th className="px-4 py-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {keys.map((k: any) => {
                      const inactive = k.expired || (!k.reusable && k.used);
                      return (
                        <tr key={k.id} className="hover:bg-slate-800/40 transition">
                          <td className="px-4 py-3 font-semibold text-white">{k.user?.name || '-'}</td>
                          <td className="px-4 py-3 font-mono">
                            <div className="flex items-center gap-2">
                              <span className="text-emerald-400 bg-emerald-400/10 px-2 py-0.5 rounded truncate max-w-[200px]">
                                {k.keyPreview || k.key || `#${k.id}`}
                              </span>
                              {k.key && (
                                <button
                                  type="button"
                                  onClick={() => handleCopy(k.key, String(k.id))}
                                  className="text-slate-400 hover:text-white cursor-pointer"
                                  title="Copy key"
                                >
                                  {copiedId === String(k.id) ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-500" />
                                  ) : (
                                    <Copy className="w-3.5 h-3.5" />
                                  )}
                                </button>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3 text-slate-300">
                            {k.reusable ? 'Reusable' : 'Single-use'}
                            {k.ephemeral ? ' · Ephemeral' : ''}
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`px-2 py-0.5 rounded border ${
                                inactive
                                  ? 'bg-slate-800 text-slate-400 border-slate-700'
                                  : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                              }`}
                            >
                              {k.expired ? 'Expired' : !k.reusable && k.used ? 'Used' : 'Active'}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-slate-400 tabular-nums">
                            {k.expiration ? new Date(k.expiration).toLocaleString() : '-'}
                          </td>
                          <td className="px-4 py-3 text-right">
                            {!inactive && (
                              <button
                                type="button"
                                onClick={() => void handleExpireKey(k)}
                                className="px-2.5 py-1 bg-slate-950 hover:bg-red-950/60 border border-slate-800 rounded text-red-300 cursor-pointer"
                              >
                                Expire
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ADD / INVITE PERSON MODAL */}
      {isAddPersonOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">
                {inviteMode === 'reset' ? 'Issue Password Reset Link' : 'Add Person to Mesh VPN'}
              </h2>
              <button
                type="button"
                onClick={() => setIsAddPersonOpen(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {onboardedResult ? (
              <div className="p-6 space-y-4 text-xs">
                <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3.5 text-emerald-200 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    {onboardedResult.inviteUrl
                      ? 'Invite link created! Share it below (token cannot be viewed again once closed).'
                      : `Account '${onboardedResult.username}' created with self-service VPN access.`}
                  </span>
                </div>

                {onboardedResult.headscaleWarning && (
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-amber-200">
                    {onboardedResult.headscaleWarning}
                  </div>
                )}

                {onboardedResult.inviteUrl && (
                  <div>
                    <span className="block text-slate-400 mb-1">One-Time Activation Link</span>
                    <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 flex items-center justify-between gap-2">
                      <code className="font-mono text-emerald-300 break-all">{onboardedResult.inviteUrl}</code>
                      <button
                        type="button"
                        onClick={() => handleCopy(onboardedResult.inviteUrl, 'res-invite-url')}
                        className="shrink-0 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded cursor-pointer"
                      >
                        {copiedId === 'res-invite-url' ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>
                )}

                {onboardedResult.invitePin && (
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-amber-200">
                        Out-of-Band Verification PIN (Send via Separate Channel)
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopy(onboardedResult.invitePin, 'res-invite-pin')}
                        className="shrink-0 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded cursor-pointer"
                      >
                        {copiedId === 'res-invite-pin' ? 'Copied' : 'Copy PIN'}
                      </button>
                    </div>
                    <div className="font-mono text-base font-bold tracking-widest text-amber-300">
                      {onboardedResult.invitePin}
                    </div>
                  </div>
                )}

                {onboardedResult.knockCommands?.unix && (
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-slate-400">Port Knock Command (Run Before Opening Link)</span>
                      <button
                        type="button"
                        onClick={() => handleCopy(onboardedResult.knockCommands.unix, 'res-knock-cmd')}
                        className="text-amber-300 hover:text-amber-200 flex items-center gap-1 cursor-pointer"
                      >
                        {copiedId === 'res-knock-cmd' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedId === 'res-knock-cmd' ? 'Copied' : 'Copy Knock Cmd'}</span>
                      </button>
                    </div>
                    <pre className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-[11px] font-mono text-amber-200 whitespace-pre-wrap break-all">
                      {onboardedResult.knockCommands.unix}
                    </pre>
                  </div>
                )}

                {onboardedResult.password && (
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Username</span>
                      <code className="font-mono text-white">{onboardedResult.username}</code>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Temporary Password</span>
                      <code className="font-mono text-emerald-300">{onboardedResult.password}</code>
                    </div>
                    {onboardedResult.starterKey?.key && (
                      <div className="flex justify-between gap-3">
                        <span className="text-slate-400 shrink-0">Starter Auth Key</span>
                        <code className="font-mono text-cyan-300 break-all">{onboardedResult.starterKey.key}</code>
                      </div>
                    )}
                  </div>
                )}

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-slate-400">Ready-to-Send Welcome Message</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(onboardedResult.welcomeMessage, 'res-welcome')}
                      className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
                    >
                      {copiedId === 'res-welcome' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedId === 'res-welcome' ? 'Copied' : 'Copy Message'}</span>
                    </button>
                  </div>
                  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-[11px] font-mono text-slate-200 whitespace-pre-wrap break-all">
                    {onboardedResult.welcomeMessage}
                  </pre>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    type="button"
                    onClick={() => setIsAddPersonOpen(false)}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium cursor-pointer"
                  >
                    Done
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmitPerson} className="p-6 space-y-4 text-xs">
                {inviteMode !== 'reset' && (
                  <div className="grid grid-cols-2 gap-2 bg-slate-950 p-1 rounded-lg border border-slate-800">
                    <button
                      type="button"
                      onClick={() => setPersonFlow('invite')}
                      className={`py-2 rounded-md font-medium cursor-pointer transition ${
                        personFlow === 'invite'
                          ? 'bg-emerald-600 text-white'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Invite Link (Recommended)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPersonFlow('direct')}
                      className={`py-2 rounded-md font-medium cursor-pointer transition ${
                        personFlow === 'direct'
                          ? 'bg-emerald-600 text-white'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      Direct Account
                    </button>
                  </div>
                )}

                {personModalError && (
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300">
                    {personModalError}
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Username *</label>
                    <input
                      type="text"
                      required
                      readOnly={inviteMode === 'reset'}
                      value={personUsername}
                      onChange={(e) => setPersonUsername(e.target.value)}
                      placeholder="alice"
                      pattern="^[a-z][a-z0-9_-]{0,31}$"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Display Name</label>
                    <input
                      type="text"
                      value={personDisplayName}
                      onChange={(e) => setPersonDisplayName(e.target.value)}
                      placeholder="Alice Smith"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                </div>

                {personFlow === 'invite' ? (
                  <div className="space-y-3">
                    <div>
                      <label className="block text-slate-300 font-medium mb-1">Invite Expiration</label>
                      <select
                        value={inviteExpiryHours}
                        onChange={(e) => setInviteExpiryHours(Number(e.target.value))}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white"
                      >
                        <option value={24}>24 hours</option>
                        <option value={48}>48 hours</option>
                        <option value={168}>7 days</option>
                      </select>
                    </div>
                    <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={inviteRequirePin}
                        onChange={(e) => setInviteRequirePin(e.target.checked)}
                        className="accent-emerald-500"
                      />
                      <span>Require 6-digit verification PIN (sent out-of-band)</span>
                    </label>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={autoGeneratePassword}
                        onChange={(e) => setAutoGeneratePassword(e.target.checked)}
                        className="accent-emerald-500"
                      />
                      <span>Auto-generate strong temporary password</span>
                    </label>
                    {!autoGeneratePassword && (
                      <div>
                        <label className="block text-slate-300 font-medium mb-1">
                          Password (min {minPasswordLength} chars)
                        </label>
                        <input
                          type="password"
                          required
                          minLength={minPasswordLength}
                          value={directPassword}
                          onChange={(e) => setDirectPassword(e.target.value)}
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white"
                        />
                      </div>
                    )}
                  </div>
                )}

                <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={starterKeyEnabled}
                    onChange={(e) => setStarterKeyEnabled(e.target.checked)}
                    className="accent-emerald-500"
                  />
                  <span>Include a single-use starter device setup key</span>
                </label>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsAddPersonOpen(false)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submittingPerson || !personUsername.trim()}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg font-medium flex items-center gap-1.5 cursor-pointer"
                  >
                    {submittingPerson && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    <span>
                      {personFlow === 'invite' ? 'Generate Invite Link' : 'Create VPN Account'}
                    </span>
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* REMOVE PERSON MODAL */}
      {removingPerson && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 space-y-4 text-xs">
            <h2 className="text-base font-semibold text-white">
              Remove <code className="text-emerald-400 font-mono">{removingPerson.name}</code>
            </h2>
            <p className="text-slate-300">
              Removes their Headscale namespace and signs out active self-service sessions.
            </p>
            <div className="space-y-2 bg-slate-950 border border-slate-800 rounded-lg p-3">
              {removingPerson.machineCount > 0 && (
                <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={removeMachinesChecked}
                    onChange={(e) => setRemoveMachinesChecked(e.target.checked)}
                    className="accent-red-500"
                  />
                  <span>Also delete all {removingPerson.machineCount} owned device(s)</span>
                </label>
              )}
              {removingPerson.applianceRole === 'vpn_user' && (
                <label className="flex items-center gap-2 text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={removeDirChecked}
                    onChange={(e) => setRemoveDirChecked(e.target.checked)}
                    className="accent-red-500"
                  />
                  <span>Also delete VPN-only directory login account</span>
                </label>
              )}
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setRemovingPerson(null)}
                className="px-4 py-2 bg-slate-800 text-slate-200 rounded-lg cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={submittingRemove}
                onClick={() => void handleRemovePerson()}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white rounded-lg font-medium cursor-pointer"
              >
                {submittingRemove ? 'Removing...' : 'Confirm Remove'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* REGISTER PENDING DEVICE MODAL */}
      {isRegisterModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 space-y-4 text-xs">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-white">Register Pending Device</h2>
              <button type="button" onClick={() => setIsRegisterModalOpen(false)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleRegisterMachine} className="space-y-3">
              <div>
                <label className="block text-slate-300 mb-1">Owner User</label>
                <select
                  value={registerUser}
                  onChange={(e) => setRegisterUser(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white"
                  required
                >
                  <option value="">-- Choose User --</option>
                  {users.map((u) => (
                    <option key={u.id ?? u.name} value={u.name}>
                      {u.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Auth ID, Node Key, or Command</label>
                <input
                  type="text"
                  required
                  value={registerKeyInput}
                  onChange={(e) => setRegisterKeyInput(e.target.value)}
                  placeholder="hskey-authreq-... or mkey:..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm font-mono text-white"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsRegisterModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-200 rounded-lg cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingRegister || !registerUser || !registerKeyInput.trim()}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg font-medium cursor-pointer"
                >
                  {submittingRegister ? 'Registering...' : 'Register Device'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ROUTE APPROVAL MODAL */}
      {routeMachine && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-xs flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 space-y-4 text-xs">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-white">
                Approve Routes — {routeMachine.name}
              </h2>
              <button type="button" onClick={() => setRouteMachine(null)} className="text-slate-400 hover:text-white cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
            {loadingRoutes ? (
              <div className="py-4 text-slate-400 flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
                <span>Loading advertised routes...</span>
              </div>
            ) : (
              <div className="space-y-3">
                {routeCandidates.length === 0 ? (
                  <p className="text-slate-400">No routes currently advertised by this machine.</p>
                ) : (
                  <div className="space-y-2 bg-slate-950 border border-slate-800 rounded-lg p-3">
                    {routeCandidates.map((r, idx) => (
                      <label key={r.prefix} className="flex items-center gap-2 font-mono text-slate-200 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={r.enabled}
                          onChange={(e) => {
                            const next = [...routeCandidates];
                            next[idx] = { ...r, enabled: e.target.checked };
                            setRouteCandidates(next);
                          }}
                          className="accent-emerald-500"
                        />
                        <span>{r.prefix}</span>
                      </label>
                    ))}
                  </div>
                )}
                <div>
                  <label className="block text-slate-400 mb-1">
                    Additional CIDR routes to approve (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={customRoutesInput}
                    onChange={(e) => setCustomRoutesInput(e.target.value)}
                    placeholder="e.g. 10.20.0.0/24, 0.0.0.0/0"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm font-mono text-white"
                  />
                </div>
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setRouteMachine(null)}
                    className="px-4 py-2 bg-slate-800 text-slate-200 rounded-lg cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    disabled={savingRoutes}
                    onClick={() => void handleSaveRoutes()}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg font-medium cursor-pointer"
                  >
                    {savingRoutes ? 'Saving...' : 'Save Approved Routes'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
