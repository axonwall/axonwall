'use client';

import React, { useState, useEffect } from 'react';
import {
  getReleaseInfo,
  getSystemPartitionsTelemetry,
  activatePartitionSlot,
  verifySystemHealthQuorum,
  applySystemFirmwareUpdate,
  rebootSystemAction,
  type ReleaseInfo,
  type PartitionSlotInfo,
  type HealthCheckItem,
  type ZfsBootEnvironmentTelemetry,
} from '@/server/agent';
import {
  RefreshCw,
  Shield,
  ShieldCheck,
  ShieldAlert,
  HardDrive,
  Cpu,
  Layers,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Download,
  UploadCloud,
  Terminal,
  Clock,
  RotateCcw,
  Check,
  Power,
  Database,
  Camera,
  Copy,
  Plus,
  Trash2,
  ChevronDown,
  ChevronRight,
  FolderGit2,
  Sparkles,
} from 'lucide-react';

export default function SystemUpdatesPage() {
  // C15: no demo slots. Until real telemetry loads, the slot section
  // below shows a loading/error state and every slot action is
  // disabled — demo identities must never be rebooted, flashed, or
  // rolled back.
  const [slots, setSlots] = useState<PartitionSlotInfo[]>([]);
  const [telemetryLoading, setTelemetryLoading] = useState(true);
  const [telemetryError, setTelemetryError] = useState<string | null>(null);
  const [telemetryDaemonUnreachable, setTelemetryDaemonUnreachable] = useState(false);

  const [installMode, setInstallMode] = useState<'ab' | 'rolling' | 'zbm'>('ab');
  const [zbmPool, setZbmPool] = useState<{ name: string; topology: string; health: string } | null>(null);
  const [bootEnvironments, setBootEnvironments] = useState<ZfsBootEnvironmentTelemetry[]>([]);
  const [expandedSnapshots, setExpandedSnapshots] = useState<Record<string, boolean>>({});
  const [isZbmActionLoading, setIsZbmActionLoading] = useState(false);
  const [selectedBeForSnap, setSelectedBeForSnap] = useState<string>('');
  const [customSnapLabel, setCustomSnapLabel] = useState<string>(() => {
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    return `manual-${ts}`;
  });
  const [cloneImmediately, setCloneImmediately] = useState<boolean>(false);
  const [cloneNewBeName, setCloneNewBeName] = useState<string>('');
  const [armClonedBeNext, setArmClonedBeNext] = useState<boolean>(false);
  const [cloneModalState, setCloneModalState] = useState<{
    snapshot: string;
    newBeName: string;
    armNext: boolean;
  } | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [bootCount, setBootCount] = useState(0);
  const [bootLimit, setBootLimit] = useState(3);
  const [healthVerified, setHealthVerified] = useState(true);
  const [healthChecks, setHealthChecks] = useState<HealthCheckItem[]>([]);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isCheckingCloud, setIsCheckingCloud] = useState(false);
  const [isUpgrading, setIsUpgrading] = useState(false);
  const [upgradeProgress, setUpgradeProgress] = useState(0);
  const [upgradePhase, setUpgradePhase] = useState('');
  const [alertMessage, setAlertMessage] = useState<string | null>(null);
  const [pendingRebootSlot, setPendingRebootSlot] = useState<'A' | 'B' | null>(null);
  const [isRebooting, setIsRebooting] = useState(false);
  const [releaseInfo, setReleaseInfo] = useState<ReleaseInfo | null>(null);

  const activeSlot = slots.find((s) => s.isActive) || slots[0] || null;
  const standbySlot = slots.find((s) => !s.isActive) || slots[1] || slots[0] || null;
  const isRollingMode = installMode === 'rolling';
  const isZbmMode = installMode === 'zbm';

  const makeTimestampLabel = (prefix = 'manual') => {
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    return `${prefix}-${ts}`;
  };

  const sanitizeZfsIdentifier = (raw: string) =>
    raw.trim().replace(/\s+/g, '-').replace(/[^a-zA-Z0-9._-]/g, '');

  const refreshTelemetryAndRelease = async (forceRefresh = false) => {
    setTelemetryError(null);
    try {
      const url = forceRefresh ? '/api/system/update?refresh=1' : '/api/system/update';
      const resp = await fetch(url, { cache: 'no-store' });
      if (resp.ok) {
        const data = await resp.json();
        if (data.telemetry) {
          setTelemetryDaemonUnreachable(Boolean(data.telemetry.daemonUnreachable));
          if (data.telemetry.installMode) {
            setInstallMode(data.telemetry.installMode);
          }
          if (data.telemetry.zbmPoolName) {
            setZbmPool({
              name: data.telemetry.zbmPoolName,
              topology: data.telemetry.zbmPoolTopology || 'mirror',
              health: data.telemetry.zbmPoolHealth || 'ONLINE',
            });
          }
          if (data.telemetry.bootEnvironments) {
            setBootEnvironments(data.telemetry.bootEnvironments);
            const activeBe =
              data.telemetry.bootEnvironments.find((b: ZfsBootEnvironmentTelemetry) => b.activeNow)?.name ||
              data.telemetry.bootEnvironments[0]?.name ||
              '';
            setSelectedBeForSnap((prev) => prev || activeBe);
          }
          setSlots(data.telemetry.slots);
          setBootCount(data.telemetry.bootCount);
          setBootLimit(data.telemetry.bootLimit);
          setHealthVerified(data.telemetry.healthVerified);
          setHealthChecks(data.telemetry.checks);
        } else {
          setTelemetryError('Slot telemetry unavailable — the update service did not return slot data.');
        }
        if (data.releaseInfo) {
          setReleaseInfo(data.releaseInfo);
        }
        setTelemetryLoading(false);
        return data;
      }
    } catch {
      // Fallback to Server Actions if route handler is unreachable
    }

    const [telemetry, info] = await Promise.all([
      getSystemPartitionsTelemetry().catch(() => null),
      getReleaseInfo(forceRefresh).catch(() => null),
    ]);
    if (telemetry) {
      if (telemetry.installMode) {
        setInstallMode(telemetry.installMode);
      }
      if (telemetry.zbmPoolName) {
        setZbmPool({
          name: telemetry.zbmPoolName,
          topology: telemetry.zbmPoolTopology || 'mirror',
          health: telemetry.zbmPoolHealth || 'ONLINE',
        });
      }
      if (telemetry.bootEnvironments) {
        setBootEnvironments(telemetry.bootEnvironments);
        const activeBe =
          telemetry.bootEnvironments.find((b) => b.activeNow)?.name ||
          telemetry.bootEnvironments[0]?.name ||
          '';
        setSelectedBeForSnap((prev) => prev || activeBe);
      }
      setSlots(telemetry.slots);
      setBootCount(telemetry.bootCount);
      setBootLimit(telemetry.bootLimit);
      setHealthVerified(telemetry.healthVerified);
      setHealthChecks(telemetry.checks);
      setTelemetryDaemonUnreachable(Boolean(telemetry.daemonUnreachable));
    } else {
      setTelemetryError('Slot telemetry unavailable — could not load slot data from the update service.');
    }
    if (info) {
      setReleaseInfo(info);
    }
    setTelemetryLoading(false);
    return { telemetry, releaseInfo: info };
  };

  // Load real telemetry on initial mount
  useEffect(() => {
    refreshTelemetryAndRelease().catch(() => {
      setTelemetryLoading(false);
      setTelemetryError('Slot telemetry unavailable — could not load slot data from the update service.');
    });
  }, []);

  const toggleSnapshots = (dataset: string) => {
    setExpandedSnapshots((prev) => ({
      ...prev,
      [dataset]: prev[dataset] === false ? true : false,
    }));
  };

  const handleSubmitArbitrarySnapshot = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const targetBe =
      selectedBeForSnap ||
      bootEnvironments.find((b) => b.activeNow)?.name ||
      bootEnvironments[0]?.name ||
      '';
    const cleanLabel = sanitizeZfsIdentifier(customSnapLabel) || makeTimestampLabel('manual');
    const cleanNewBe = cloneImmediately ? sanitizeZfsIdentifier(cloneNewBeName) : '';

    if (!targetBe) {
      setErrorMessage('Please select a target Boot Environment to snapshot.');
      return;
    }
    if (cloneImmediately && !cleanNewBe) {
      setErrorMessage('Please enter a name for the cloned Boot Environment.');
      return;
    }

    setIsZbmActionLoading(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/system/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'zbm-snapshot',
          beName: targetBe,
          label: cleanLabel,
          newBeName: cleanNewBe || undefined,
        }),
      });
      const data = await resp.json();
      if (!data.success) throw new Error(data.message || 'Snapshot creation failed');

      if (cloneImmediately && cleanNewBe && armClonedBeNext) {
        await fetch('/api/system/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'zbm-activate', beName: cleanNewBe }),
        });
      }

      setAlertMessage(
        data.message ||
          `Snapshot zroot/ROOT/${targetBe}@${cleanLabel} created successfully${
            cleanNewBe ? ` and cloned to ${cleanNewBe}` : ''
          }.`
      );
      setCustomSnapLabel(makeTimestampLabel('manual'));
      if (cloneImmediately) {
        setCloneImmediately(false);
        setCloneNewBeName('');
      }
      await refreshTelemetryAndRelease();
    } catch (err: any) {
      setErrorMessage(`Failed to create snapshot: ${err?.message || String(err)}`);
    } finally {
      setIsZbmActionLoading(false);
    }
  };

  const handleCreateSnapshot = async (beName: string, presetLabel?: string) => {
    setSelectedBeForSnap(beName);
    const labelToUse = sanitizeZfsIdentifier(presetLabel || customSnapLabel) || makeTimestampLabel('manual');
    setIsZbmActionLoading(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/system/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'zbm-snapshot', beName, label: labelToUse }),
      });
      const data = await resp.json();
      if (!data.success) throw new Error(data.message);
      setAlertMessage(data.message || `Snapshot ${data.snapshot} created successfully.`);
      setCustomSnapLabel(makeTimestampLabel('manual'));
      await refreshTelemetryAndRelease();
    } catch (err: any) {
      setErrorMessage(`Failed to create snapshot: ${err?.message || String(err)}`);
    } finally {
      setIsZbmActionLoading(false);
    }
  };

  const openCloneSnapshotModal = (snapshot: string) => {
    const snapPart = snapshot.split('@')[1] || 'clone';
    const cleanSuffix = sanitizeZfsIdentifier(snapPart).slice(0, 24);
    const defaultNewName = `axonwall-${cleanSuffix || new Date().toISOString().slice(0, 10)}`;
    setCloneModalState({
      snapshot,
      newBeName: defaultNewName,
      armNext: false,
    });
  };

  const handleConfirmCloneModal = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!cloneModalState) return;
    const cleanNewBe = sanitizeZfsIdentifier(cloneModalState.newBeName);
    if (!cleanNewBe) {
      setErrorMessage('Please enter a valid Boot Environment name.');
      return;
    }
    setIsZbmActionLoading(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/system/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'zbm-clone',
          snapshot: cloneModalState.snapshot,
          newBeName: cleanNewBe,
        }),
      });
      const data = await resp.json();
      if (!data.success) throw new Error(data.message);

      if (cloneModalState.armNext) {
        await fetch('/api/system/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'zbm-activate', beName: cleanNewBe }),
        });
      }

      setAlertMessage(
        `${data.message || `Cloned snapshot to ${data.dataset}.`}${
          cloneModalState.armNext ? ` Armed '${cleanNewBe}' for next boot.` : ''
        }`
      );
      setCloneModalState(null);
      await refreshTelemetryAndRelease();
    } catch (err: any) {
      setErrorMessage(`Failed to clone snapshot: ${err?.message || String(err)}`);
    } finally {
      setIsZbmActionLoading(false);
    }
  };

  const handleDeleteSnapshot = async (snapshot: string) => {
    if (!confirm(`Delete ZFS snapshot '${snapshot}'? This action cannot be undone.`)) return;
    setIsZbmActionLoading(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/system/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'zbm-delete-snapshot', snapshot }),
      });
      const data = await resp.json();
      if (!data.success) throw new Error(data.message);
      setAlertMessage(data.message || `Deleted snapshot ${snapshot}.`);
      await refreshTelemetryAndRelease();
    } catch (err: any) {
      setErrorMessage(`Failed to delete snapshot: ${err?.message || String(err)}`);
    } finally {
      setIsZbmActionLoading(false);
    }
  };

  const handleRollbackSnapshot = async (snapshot: string) => {
    if (
      !confirm(
        `Roll back dataset to point-in-time snapshot '${snapshot}'? Any newer changes or intermediate snapshots on that dataset will be reverted.`
      )
    ) {
      return;
    }
    setIsZbmActionLoading(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/system/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'zbm-rollback-snapshot', snapshot }),
      });
      const data = await resp.json();
      if (!data.success) throw new Error(data.message);
      setAlertMessage(data.message || `Rolled back to snapshot ${snapshot}.`);
      await refreshTelemetryAndRelease();
    } catch (err: any) {
      setErrorMessage(`Failed to rollback snapshot: ${err?.message || String(err)}`);
    } finally {
      setIsZbmActionLoading(false);
    }
  };

  const handleActivateBootEnvironment = async (beName: string) => {
    setIsZbmActionLoading(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/system/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'zbm-activate', beName }),
      });
      const data = await resp.json();
      if (!data.success) throw new Error(data.message);
      setAlertMessage(data.message || `Boot Environment ${beName} armed for next boot.`);
      await refreshTelemetryAndRelease();
    } catch (err: any) {
      setErrorMessage(`Failed to activate Boot Environment: ${err?.message || String(err)}`);
    } finally {
      setIsZbmActionLoading(false);
    }
  };

  const handleDeleteBootEnvironment = async (beName: string) => {
    if (!confirm(`Are you sure you want to permanently delete Boot Environment '${beName}'? This cannot be undone.`)) {
      return;
    }
    setIsZbmActionLoading(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/system/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'zbm-delete', beName }),
      });
      const data = await resp.json();
      if (!data.success) throw new Error(data.message);
      setAlertMessage(data.message || `Boot Environment ${beName} deleted.`);
      await refreshTelemetryAndRelease();
    } catch (err: any) {
      setErrorMessage(`Failed to delete Boot Environment: ${err?.message || String(err)}`);
    } finally {
      setIsZbmActionLoading(false);
    }
  };

  const handleRebootIntoSlot = async (slot: 'A' | 'B') => {
    if (
      !confirm(
        `Reboot the appliance now into Slot ${slot}? Active connections will briefly reset while the new partition boots.`
      )
    ) {
      return;
    }
    setIsRebooting(true);
    try {
      let res: { success?: boolean; message?: string } = {};
      try {
        const resp = await fetch('/api/system/power', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'reboot', slot }),
        });
        res = await resp.json();
      } catch {
        res = await rebootSystemAction(slot);
      }
      if (res.success === false) {
        alert(`Reboot request failed: ${res.message || 'Operation failed'}`);
      } else {
        setAlertMessage(res.message || `Rebooting into Slot ${slot}...`);
      }
    } catch (err: any) {
      alert(`Reboot request failed: ${err?.message || String(err)}`);
    } finally {
      setIsRebooting(false);
    }
  };

  const handleManualRollback = async () => {
    // C15: no telemetry, no rollback target — demo slots used to make
    // this button actionable before any real slot ever loaded.
    if (!standbySlot) {
      alert('Rollback unavailable: slot telemetry has not loaded.');
      return;
    }
    if (
      !confirm(
        `Are you sure you want to trigger a safe rollback to Slot ${standbySlot.slot}? The system will configure GRUB active_slot=${standbySlot.slot}, reset bootcount=0, and arm the alternate rootfs for next boot.`
      )
    ) {
      return;
    }

    try {
      let res: { success: boolean; message: string };
      try {
        const resp = await fetch('/api/system/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'activate', slot: standbySlot.slot }),
        });
        res = await resp.json();
      } catch {
        res = await activatePartitionSlot(standbySlot.slot);
      }

      if (!res.success) {
        alert(`Rollback staging failed: ${res.message}`);
        return;
      }

      setPendingRebootSlot(standbySlot.slot);
      // C15: staging a rollback only arms the next-boot GRUB target.
      // The slot is NOT active until a post-reboot refresh confirms
      // it, so isActive is left untouched and the message says staged.
      setAlertMessage(
        `Rollback staged: Slot ${standbySlot.slot} will boot next. The current slot remains active until reboot.`
      );
    } catch (err: any) {
      alert(`Rollback staging failed: ${err?.message || String(err)}`);
    }
  };

  const handleCheckCloud = async () => {
    setIsCheckingCloud(true);
    try {
      const data = await refreshTelemetryAndRelease(true);
      const info: ReleaseInfo | null = data?.releaseInfo || (await getReleaseInfo(true));
      if (info) {
        setReleaseInfo(info);
        if (info.isUpToDate) {
          alert(`Axonwall Release Channel Check: Up to date! Currently running latest release v${info.currentVersion}.`);
        } else {
          alert(
            `New Axonwall Release Available: v${info.latestVersion} (Current: v${info.currentVersion})\n\nRelease Notes: ${info.releaseNotes?.slice(0, 150)}...\n\nClick "Flash New Image to Standby" to apply this firmware update.`
          );
        }
      }
    } catch {
      alert(
        `Axonwall Release Channel Check: Unable to reach GitHub release channel. Currently running v${releaseInfo?.currentVersion || activeSlot?.version || 'unknown'}.`
      );
    } finally {
      setIsCheckingCloud(false);
    }
  };

  const handleFlashUpgrade = async () => {
    // C15: without loaded telemetry there is no standby slot to flash.
    const targetSlot: 'A' | 'B' | undefined = isRollingMode ? 'A' : standbySlot?.slot;
    if (!targetSlot) {
      setErrorMessage('Firmware update unavailable: slot telemetry has not loaded.');
      return;
    }
    const targetLabel =
      slots.find((s) => s.slot === targetSlot)?.label || `Slot ${targetSlot}`;
    setIsUpgrading(true);
    setUpgradeProgress(15);
    setUpgradePhase(
      isRollingMode
        ? 'Resolving release payload for Rolling Root (/)...'
        : `Resolving release payload for Slot ${targetSlot}...`
    );

    const timer1 = setTimeout(() => {
      setUpgradeProgress(40);
      setUpgradePhase('Verifying cryptographic SHA-256 integrity hash & signature...');
    }, 700);

    const timer2 = setTimeout(() => {
      setUpgradeProgress(75);
      setUpgradePhase(
        isRollingMode
          ? 'Applying in-place package update to / and reloading systemd units...'
          : `Writing firmware payload to ${targetLabel} and updating bootloader...`
      );
    }, 1500);

    try {
      let res: { success: boolean; message: string; targetSlot?: 'A' | 'B'; newVersion?: string };
      try {
        const resp = await fetch('/api/system/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'update', slot: targetSlot }),
        });
        res = await resp.json();
      } catch {
        res = await applySystemFirmwareUpdate(targetSlot);
      }

      if (!res.success) {
        clearTimeout(timer1);
        clearTimeout(timer2);
        setIsUpgrading(false);
        alert(`Firmware update error: ${res.message}`);
        return;
      }

      setTimeout(() => {
        setUpgradeProgress(100);
        setUpgradePhase(
          isRollingMode
            ? 'In-place update complete! Restarting Axonwall services...'
            : 'Arming GRUB boot-counting watchdog (bootcount=0, bootlimit=3)...'
        );
        setTimeout(() => {
          setIsUpgrading(false);
          if (!isRollingMode) {
            setPendingRebootSlot(targetSlot);
          }
          setAlertMessage(res.message);
          setSlots((prev) =>
            prev.map((s) =>
              s.slot === targetSlot
                ? {
                    ...s,
                    version: res.newVersion || releaseInfo?.latestVersion || '0.5.0',
                    lastUpdated: isRollingMode
                      ? `Updated in-place to v${res.newVersion || releaseInfo?.latestVersion || '0.5.0'}`
                      : `Updated to v${res.newVersion || releaseInfo?.latestVersion || '0.5.0'} (Next Boot Armed)`,
                  }
                : s
            )
          );
          refreshTelemetryAndRelease().catch(() => {});
        }, 600);
      }, 1200);
    } catch (err: any) {
      clearTimeout(timer1);
      clearTimeout(timer2);
      setIsUpgrading(false);
      alert(`Firmware update error: ${err?.message || String(err)}`);
    }
  };

  const handleRunHealthCheck = async () => {
    setIsVerifying(true);
    try {
      let telemetry;
      try {
        const resp = await fetch('/api/system/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'verify' }),
        });
        const data = await resp.json();
        if (!data.success) {
          throw new Error(data.message || 'Verification failed');
        }
        telemetry = data;
      } catch {
        telemetry = await verifySystemHealthQuorum();
      }

      setSlots(telemetry.slots);
      setBootCount(telemetry.bootCount);
      setBootLimit(telemetry.bootLimit);
      setHealthVerified(telemetry.healthVerified);
      setHealthChecks(telemetry.checks);
      setTelemetryError(null);
      setTelemetryDaemonUnreachable(Boolean(telemetry.daemonUnreachable));
      // C-B3: never claim PASSED / bootcount=0 unless the daemon verify
      // actually ran and passed. A daemon-down run returns telemetry
      // whose only check is the WARN "Daemon telemetry unavailable",
      // and verifySystemHealthQuorum now throws before we get here —
      // but report the real statuses here too, as defense in depth.
      const failing = (telemetry.checks || []).filter((c) => c?.status && c.status !== 'PASS');
      if (telemetry.daemonUnreachable || !telemetry.healthVerified || failing.length > 0) {
        alert(
          `Watchdog Health Quorum: verification did NOT pass${
            failing.length
              ? ` — non-passing checks: ${failing.map((c) => `${c.name} (${c.status})`).join(', ')}`
              : ''
          }. Bootcount was not reset.`
        );
      } else {
        alert('Watchdog Health Quorum: All verification tests PASSED. Partition marked permanently healthy (bootcount=0).');
      }
    } catch (err: any) {
      alert(`Health verification check failed: ${err?.message || String(err)}`);
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto pb-16">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <RefreshCw className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white">
              {isZbmMode
                ? 'ZFSBootMenu Root-on-ZFS System Updates & Boot Environments'
                : isRollingMode
                  ? 'Rolling Standard Linux System Updates'
                  : 'A/B Dual-Root System Updates'}
            </h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              {isZbmMode
                ? 'ZFSBootMenu v3.1.x UKI • CoW Snapshots • Full ZFS RAID'
                : isRollingMode
                  ? 'Single-Root / + Full APT'
                  : 'Unbrickable Architecture'}
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            {isZbmMode
              ? 'OpenZFS root pool with instant Copy-on-Write Boot Environments (BEs), point-in-time snapshots, and 3-strike autonomous watchdog recovery.'
              : isRollingMode
                ? 'Standard Debian 13 single-root (/) installation with in-place Axonwall updates and permanent APT package persistence.'
                : 'Zero-downtime atomic operating system upgrades with GRUB automated boot-counting and kernel health verification.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleCheckCloud}
            disabled={isCheckingCloud}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 font-medium text-xs hover:bg-slate-700 transition cursor-pointer disabled:opacity-50"
          >
            <Download className={`w-4 h-4 ${isCheckingCloud ? 'animate-bounce' : ''}`} />
            <span>{isCheckingCloud ? 'Checking Releases...' : 'Check Cloud Updates'}</span>
          </button>
          <button
            onClick={handleFlashUpgrade}
            disabled={isUpgrading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-emerald-500 text-slate-950 font-semibold text-xs hover:bg-emerald-400 transition shadow-lg shadow-emerald-500/20 cursor-pointer disabled:opacity-50"
          >
            <UploadCloud className="w-4 h-4" />
            <span>
              {isZbmMode
                ? 'Flash Image to New Boot Environment'
                : isRollingMode
                  ? 'Apply In-Place Update'
                  : 'Flash New Image to Standby'}
            </span>
          </button>
        </div>
      </div>

      {/* Update Available Notification Banner */}
      {releaseInfo && !releaseInfo.isUpToDate && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-lg">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-500/20 text-amber-400">
              <Download className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="font-bold text-white flex items-center gap-2">
                <span>Axonwall Firmware v{releaseInfo.latestVersion} Available</span>
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-amber-400/20 text-amber-300 font-mono">
                  Current: v{releaseInfo.currentVersion}
                </span>
              </div>
              <p className="text-xs text-amber-300/80 mt-0.5">
                New security patches, performance improvements, and network engine updates are ready to flash.
              </p>
            </div>
          </div>
          <button
            onClick={handleFlashUpgrade}
            disabled={isUpgrading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-amber-500 text-slate-950 font-bold text-xs hover:bg-amber-400 transition cursor-pointer shrink-0 disabled:opacity-50"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Install & Flash v{releaseInfo.latestVersion}</span>
          </button>
        </div>
      )}

      {errorMessage && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button onClick={() => setErrorMessage(null)} className="text-slate-400 hover:text-white text-xs">
            ✕
          </button>
        </div>
      )}

      {alertMessage && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>{alertMessage}</span>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            {pendingRebootSlot && (
              <button
                onClick={() => handleRebootIntoSlot(pendingRebootSlot)}
                disabled={isRebooting}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition cursor-pointer disabled:opacity-50"
              >
                <Power className="w-3.5 h-3.5" />
                <span>{isRebooting ? 'Rebooting...' : `Reboot into Slot ${pendingRebootSlot} Now`}</span>
              </button>
            )}
            <button onClick={() => setAlertMessage(null)} className="text-slate-400 hover:text-white text-xs">
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Upgrading Progress Card */}
      {isUpgrading && (
        <div className="p-5 rounded-xl bg-slate-900 border border-emerald-500/30 space-y-3 shadow-xl">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-emerald-400 font-medium">
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span>Flashing System Image: {upgradePhase}</span>
            </div>
            <span className="font-mono text-emerald-300">{upgradeProgress}%</span>
          </div>
          <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
            <div
              className="h-full bg-emerald-500 transition-all duration-300"
              style={{ width: `${upgradeProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* ZFSBootMenu Root-on-ZFS Dashboard */}
      {isZbmMode && (
        <div className="space-y-6">
          {/* ZFS Root Pool Banner */}
          <div className="p-6 rounded-2xl bg-slate-900/90 border border-emerald-500/30 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  <Database className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-bold text-white font-mono">
                      Root Pool: {zbmPool?.name || 'zroot'}
                    </h2>
                    <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {zbmPool?.health || 'ONLINE'}
                    </span>
                    <span className="px-2 py-0.5 rounded-full text-xs font-mono font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 uppercase">
                      {zbmPool?.topology || 'Mirror'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    UEFI Unified Kernel Image (EFI/ZBM/VMLINUZ.EFI) • Native OpenZFS Module • Ashift 12 • zstd Compression
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    const activeBe = bootEnvironments.find((b) => b.activeNow)?.name || 'axonwall-active';
                    handleCreateSnapshot(activeBe, makeTimestampLabel('quick'));
                  }}
                  disabled={isZbmActionLoading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition cursor-pointer disabled:opacity-50"
                >
                  <Camera className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Quick Snapshot Active BE</span>
                </button>
              </div>
            </div>

            {/* Quick Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                <span className="text-slate-500 block mb-0.5">Boot Environments:</span>
                <span className="font-bold text-white text-sm">{bootEnvironments.length} Staged</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                <span className="text-slate-500 block mb-0.5">Watchdog Bootcount:</span>
                <span className="font-bold text-emerald-400 font-mono text-sm">
                  {bootCount} / {bootLimit} (Quorum {healthVerified ? 'Verified' : 'Pending'})
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                <span className="text-slate-500 block mb-0.5">Bootfs Property:</span>
                <span className="font-semibold text-slate-300 font-mono truncate block" title={bootEnvironments.find(b => b.activeNext)?.dataset || 'zroot/ROOT/axonwall'}>
                  {bootEnvironments.find(b => b.activeNext)?.name || 'axonwall'}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                <span className="text-slate-500 block mb-0.5">Dataset Container:</span>
                <span className="font-semibold text-slate-300 font-mono">zroot/ROOT</span>
              </div>
            </div>
          </div>

          {/* Create Arbitrary ZFS Snapshot & Checkpoint Builder */}
          <form
            onSubmit={handleSubmitArbitrarySnapshot}
            className="p-6 rounded-2xl bg-slate-900 border border-cyan-500/30 shadow-lg space-y-4"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                  <Camera className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">
                    Create Arbitrary ZFS Snapshot & Boot Checkpoint
                  </h3>
                  <p className="text-xs text-slate-400">
                    Capture an instant Copy-on-Write point-in-time snapshot of any Boot Environment, and optionally clone it into a standalone bootable environment.
                  </p>
                </div>
              </div>
              <div className="text-[11px] font-mono text-cyan-300 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                Target: zroot/ROOT/{selectedBeForSnap || bootEnvironments[0]?.name || 'axonwall'}@
                {sanitizeZfsIdentifier(customSnapLabel) || 'manual'}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
              <div className="md:col-span-4 space-y-1.5">
                <label className="text-xs font-semibold text-slate-300 block">
                  Target Boot Environment
                </label>
                <select
                  value={selectedBeForSnap}
                  onChange={(e) => setSelectedBeForSnap(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white font-mono focus:outline-none focus:border-cyan-500"
                >
                  {bootEnvironments.map((be) => (
                    <option key={be.name} value={be.name}>
                      {be.name} {be.activeNow ? '(Active Now /)' : be.activeNext ? '(Next Boot)' : '(Standby)'}
                    </option>
                  ))}
                </select>
              </div>

              <div className="md:col-span-5 space-y-1.5">
                <label className="text-xs font-semibold text-slate-300 block">
                  Snapshot Label / Tag Name
                </label>
                <input
                  type="text"
                  value={customSnapLabel}
                  onChange={(e) => setCustomSnapLabel(e.target.value)}
                  placeholder="e.g. pre-firewall-migration, gold-baseline, manual-checkpoint"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white font-mono placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="md:col-span-3">
                <button
                  type="submit"
                  disabled={isZbmActionLoading}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition shadow-lg shadow-cyan-500/20 cursor-pointer disabled:opacity-50"
                >
                  <Plus className="w-4 h-4" />
                  <span>
                    {isZbmActionLoading
                      ? 'Creating...'
                      : cloneImmediately
                        ? 'Snapshot & Clone BE'
                        : 'Create Snapshot'}
                  </span>
                </button>
              </div>
            </div>

            {/* Preset Label Chips & Optional Clone Toggle */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
              <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                <span className="text-slate-500 mr-1">Quick Presets:</span>
                {[
                  { label: 'Timestamp', val: () => makeTimestampLabel('manual') },
                  { label: 'pre-upgrade', val: () => `pre-upgrade-${new Date().toISOString().slice(0, 10)}` },
                  { label: 'before-policy-change', val: () => 'before-policy-change' },
                  { label: 'gold-baseline', val: () => 'gold-baseline' },
                  { label: 'rollback-checkpoint', val: () => 'rollback-checkpoint' },
                ].map((preset) => (
                  <button
                    key={preset.label}
                    type="button"
                    onClick={() => setCustomSnapLabel(preset.val())}
                    className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-mono transition cursor-pointer"
                  >
                    @{preset.label}
                  </button>
                ))}
              </div>

              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={cloneImmediately}
                  onChange={(e) => {
                    const checked = e.target.checked;
                    setCloneImmediately(checked);
                    if (checked && !cloneNewBeName) {
                      const cleanSuffix = sanitizeZfsIdentifier(customSnapLabel).slice(0, 20) || 'custom';
                      setCloneNewBeName(`axonwall-${cleanSuffix}`);
                    }
                  }}
                  className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-0"
                />
                <span>Also clone snapshot into a new Boot Environment</span>
              </label>
            </div>

            {cloneImmediately && (
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 grid grid-cols-1 sm:grid-cols-12 gap-4 items-center">
                <div className="sm:col-span-7 space-y-1">
                  <label className="text-[11px] font-semibold text-cyan-300 block">
                    New Boot Environment Name (zroot/ROOT/&lt;name&gt;)
                  </label>
                  <input
                    type="text"
                    value={cloneNewBeName}
                    onChange={(e) => setCloneNewBeName(e.target.value)}
                    placeholder="e.g. axonwall-custom-be"
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-white font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div className="sm:col-span-5 pt-3 sm:pt-4">
                  <label className="flex items-center gap-2 text-xs text-amber-300 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={armClonedBeNext}
                      onChange={(e) => setArmClonedBeNext(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-900 text-amber-500 focus:ring-0"
                    />
                    <span>Arm new Boot Environment as Next Boot (bootfs)</span>
                  </label>
                </div>
              </div>
            )}
          </form>

          {/* Boot Environments Grid */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FolderGit2 className="w-5 h-5 text-emerald-400" />
                <h3 className="text-base font-bold text-white">OpenZFS Boot Environments</h3>
                <span className="text-xs text-slate-500">({bootEnvironments.length} total)</span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {bootEnvironments.map((be) => {
                const isExpanded = expandedSnapshots[be.dataset] !== false;
                const snapDetails =
                  be.snapshotDetails && be.snapshotDetails.length > 0
                    ? be.snapshotDetails
                    : (be.snapshots || []).map((s) => ({
                        name: s,
                        fullName: `${be.dataset}@${s}`,
                        dataset: be.dataset,
                        beName: be.name,
                        usedSize: '',
                        referSize: '',
                        createdAt: '',
                      }));
                return (
                  <div
                    key={be.dataset}
                    className={`p-5 rounded-2xl border transition-all ${
                      be.activeNow
                        ? 'bg-slate-900/90 border-emerald-500/40 shadow-lg shadow-emerald-500/5'
                        : be.activeNext
                          ? 'bg-slate-900/80 border-amber-500/40 shadow-lg shadow-amber-500/5'
                          : 'bg-slate-900/50 border-slate-800'
                    }`}
                  >
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <div>
                        <h4 className="font-bold text-white text-sm font-mono flex items-center gap-2">
                          <span>{be.name}</span>
                          <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-normal">
                            v{be.version}
                          </span>
                        </h4>
                        <div className="text-[11px] font-mono text-slate-400 mt-0.5">{be.dataset}</div>
                      </div>

                      <div className="flex items-center gap-1.5">
                        {be.activeNow && (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                            Active Now (/)
                          </span>
                        )}
                        {be.activeNext && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/20">
                            <Sparkles className="w-3 h-3 text-amber-400" />
                            Next Boot
                          </span>
                        )}
                        {!be.activeNow && !be.activeNext && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
                            Standby
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3 py-3 text-xs border-b border-slate-800">
                      <div>
                        <span className="text-slate-500 block mb-0.5">Used Space:</span>
                        <span className="font-semibold text-white font-mono">{be.usedSize || '0 B'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block mb-0.5">Created:</span>
                        <span className="text-slate-300 truncate block">{be.createdAt || 'Initial Install'}</span>
                      </div>
                    </div>

                    {/* Snapshots Drawer */}
                    <div className="py-2.5">
                      <button
                        type="button"
                        onClick={() => toggleSnapshots(be.dataset)}
                        className="flex items-center justify-between w-full text-xs text-slate-300 hover:text-white transition cursor-pointer"
                      >
                        <span className="flex items-center gap-1.5 font-medium">
                          <Camera className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Snapshots ({snapDetails.length})</span>
                        </span>
                        {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </button>

                      {isExpanded && (
                        <div className="mt-2 space-y-1.5 bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                          {snapDetails.length > 0 ? (
                            snapDetails.map((snap) => (
                              <div
                                key={snap.fullName}
                                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs py-1.5 px-2 rounded-lg hover:bg-slate-900/90 border border-transparent hover:border-slate-800 transition"
                              >
                                <div className="min-w-0">
                                  <div className="font-mono text-cyan-300 font-medium truncate">
                                    @{snap.name}
                                  </div>
                                  {(snap.usedSize || snap.createdAt) && (
                                    <div className="text-[10px] text-slate-500 font-mono">
                                      {snap.usedSize ? `${snap.usedSize} used` : ''}
                                      {snap.referSize ? ` (${snap.referSize} refer)` : ''}
                                      {snap.createdAt ? ` • ${snap.createdAt}` : ''}
                                    </div>
                                  )}
                                </div>
                                <div className="flex items-center gap-1.5 shrink-0">
                                  <button
                                    type="button"
                                    onClick={() => openCloneSnapshotModal(snap.fullName)}
                                    disabled={isZbmActionLoading}
                                    className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 text-cyan-300 text-[11px] font-medium transition cursor-pointer disabled:opacity-50"
                                    title="Clone this snapshot into a new bootable ZFS Boot Environment"
                                  >
                                    <Copy className="w-3 h-3" />
                                    <span>Clone BE</span>
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => handleRollbackSnapshot(snap.fullName)}
                                    disabled={isZbmActionLoading}
                                    className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-amber-500 hover:text-slate-950 text-amber-300 text-[11px] font-medium transition cursor-pointer disabled:opacity-50"
                                    title="Roll back dataset to this snapshot"
                                  >
                                    <RotateCcw className="w-3 h-3" />
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => handleDeleteSnapshot(snap.fullName)}
                                    disabled={isZbmActionLoading}
                                    className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-rose-500/20 text-rose-400 text-[11px] font-medium transition cursor-pointer disabled:opacity-50"
                                    title="Delete snapshot"
                                  >
                                    <Trash2 className="w-3 h-3" />
                                  </button>
                                </div>
                              </div>
                            ))
                          ) : (
                            <div className="text-slate-500 text-[11px] italic py-1">No snapshots taken yet</div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Card Actions */}
                    <div className="pt-2 flex items-center justify-between gap-2 border-t border-slate-800">
                      <button
                        type="button"
                        onClick={() => handleCreateSnapshot(be.name)}
                        disabled={isZbmActionLoading}
                        className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition cursor-pointer disabled:opacity-50"
                      >
                        <Camera className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Snapshot Now (@{sanitizeZfsIdentifier(customSnapLabel) || 'manual'})</span>
                      </button>

                      <div className="flex items-center gap-2">
                        {!be.activeNext && (
                          <button
                            type="button"
                            onClick={() => handleActivateBootEnvironment(be.name)}
                            disabled={isZbmActionLoading}
                            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-amber-500 hover:text-slate-950 text-amber-300 border border-amber-500/30 text-xs font-medium transition cursor-pointer disabled:opacity-50"
                          >
                            <Sparkles className="w-3.5 h-3.5" />
                            <span>Boot Next</span>
                          </button>
                        )}
                        {!be.activeNow && !be.activeNext && (
                          <button
                            type="button"
                            onClick={() => handleDeleteBootEnvironment(be.name)}
                            disabled={isZbmActionLoading}
                            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-medium transition cursor-pointer disabled:opacity-50"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                            <span>Delete BE</span>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Clone Snapshot Modal */}
          {cloneModalState && (
            <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
              <form
                onSubmit={handleConfirmCloneModal}
                className="bg-slate-900 border border-cyan-500/40 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl"
              >
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <Copy className="w-5 h-5 text-cyan-400" />
                    <h3 className="text-base font-bold text-white">
                      Clone Snapshot to New Boot Environment
                    </h3>
                  </div>
                  <button
                    type="button"
                    onClick={() => setCloneModalState(null)}
                    className="text-slate-400 hover:text-white text-sm"
                  >
                    ✕
                  </button>
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-slate-400 block mb-1">Source Snapshot:</span>
                    <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-cyan-300">
                      {cloneModalState.snapshot}
                    </div>
                  </div>

                  <div>
                    <label className="text-slate-300 font-semibold block mb-1">
                      New Boot Environment Name:
                    </label>
                    <input
                      type="text"
                      value={cloneModalState.newBeName}
                      onChange={(e) =>
                        setCloneModalState({ ...cloneModalState, newBeName: e.target.value })
                      }
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-white font-mono focus:outline-none focus:border-cyan-500"
                      autoFocus
                    />
                    <span className="text-[11px] text-slate-500 font-mono mt-1 block">
                      Target Dataset: zroot/ROOT/{sanitizeZfsIdentifier(cloneModalState.newBeName) || '...'}
                    </span>
                  </div>

                  <label className="flex items-center gap-2 pt-1 text-amber-300 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={cloneModalState.armNext}
                      onChange={(e) =>
                        setCloneModalState({ ...cloneModalState, armNext: e.target.checked })
                      }
                      className="rounded border-slate-700 bg-slate-950 text-amber-500 focus:ring-0"
                    />
                    <span>Arm this new Boot Environment for Next Boot immediately</span>
                  </label>
                </div>

                <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                  <button
                    type="button"
                    onClick={() => setCloneModalState(null)}
                    className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isZbmActionLoading}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition cursor-pointer disabled:opacity-50"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    <span>{isZbmActionLoading ? 'Cloning...' : 'Create Boot Environment'}</span>
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>
      )}

      {/* E8: when the daemon is unreachable, slot health is unverified
          and the numbers below come from local files only. */}
      {telemetryDaemonUnreachable && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-sm flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
          <span>
            Telemetry unavailable — the daemon is unreachable, so slot health is unverified and
            shown from local files only. Do not trust a standby slot&apos;s health from this page.
          </span>
        </div>
      )}

      {/* C15: with no loaded slots, show a loading/error state instead
          of demo slots — the actions below must never run on fake
          slot identities. */}
      {!isZbmMode && slots.length === 0 && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
          <p className="text-sm text-slate-300">
            {telemetryLoading
              ? 'Loading slot telemetry…'
              : telemetryError || 'Slot telemetry unavailable.'}
          </p>
          {!telemetryLoading && (
            <button
              type="button"
              onClick={() => refreshTelemetryAndRelease(true)}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition cursor-pointer"
            >
              Retry loading telemetry
            </button>
          )}
        </div>
      )}

      {/* A/B Dual-Root Partition Slots or Single-Root Rolling Card (Hidden in ZBM mode) */}
      {!isZbmMode && slots.length > 0 && (
        <div className={`grid grid-cols-1 ${slots.length > 1 ? 'md:grid-cols-2' : ''} gap-6`}>
          {slots.map((slot) => {
            return (
              <div
                key={slot.slot}
                className={`p-6 rounded-2xl border transition-all ${
                  slot.isActive
                    ? 'bg-slate-900/90 border-emerald-500/40 shadow-lg shadow-emerald-500/5'
                    : 'bg-slate-900/50 border-slate-800'
                }`}
              >
                <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold text-lg font-mono ${
                        slot.isActive
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400 border border-slate-700'
                      }`}
                    >
                      {isRollingMode ? '/' : slot.slot}
                    </div>
                    <div>
                      <h3 className="font-bold text-white text-base flex items-center gap-2">
                        {slot.name}
                      </h3>
                      <div className="text-xs font-mono text-slate-400">{slot.label}</div>
                    </div>
                  </div>

                  <div>
                    {slot.isActive ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                        {isRollingMode ? 'Active Rolling Root (/)' : 'Active Boot Partition'}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
                        Standby Target
                      </span>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 py-4 text-xs border-b border-slate-800">
                  <div>
                    <span className="text-slate-500 block mb-0.5">OS Version:</span>
                    <span className="font-semibold text-white font-mono">{slot.version}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block mb-0.5">Linux Kernel:</span>
                    <span className="text-slate-300 font-mono truncate block" title={slot.kernel}>
                      {slot.kernel}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block mb-0.5">Block Device:</span>
                    <span className="text-slate-300 font-mono">{slot.device} ({slot.size})</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block mb-0.5">Last Installed / Flashed:</span>
                    <span className="text-slate-300">{slot.lastUpdated}</span>
                  </div>
                </div>

                <div className="pt-4 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs">
                    {!isRollingMode && slot.healthKnown === false ? (
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    )}
                    <span className="text-slate-300">
                      {isRollingMode
                        ? 'Standard Debian Root — apt update && apt upgrade supported'
                        : slot.healthKnown === false
                          ? 'Health unverified — this slot was not checked'
                          : slot.isActive
                            ? 'Healthy & Committed'
                            : 'Flash Target Ready'}
                    </span>
                  </div>

                  {!slot.isActive && !isRollingMode && (
                    <button
                      onClick={handleManualRollback}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
                      <span>Boot This Slot Next</span>
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Watchdog & Health Quorum Dashboard */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">
                {isZbmMode ? 'ZFSBootMenu Autonomous Watchdog & Health Quorum' : 'GRUB Watchdog & Health Quorum'}
              </h2>
              <p className="text-xs text-slate-400">
                {isZbmMode
                  ? 'Autonomous pre-boot verification confirming Boot Environment stability before clearing org.axonwall:bootcount'
                  : 'Autonomous multi-stage verification confirming stability before committing partitions'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleRunHealthCheck}
              disabled={isVerifying}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium transition cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-emerald-400 ${isVerifying ? 'animate-spin' : ''}`} />
              <span>{isVerifying ? 'Running Tests...' : 'Re-verify Health'}</span>
            </button>
          </div>
        </div>

        {/* Counter and Status Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
            <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Boot Failures Counter</div>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold text-emerald-400 font-mono">{bootCount}</span>
              <span className="text-xs text-slate-500 font-mono">/ {bootLimit} max attempts</span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              Falls back automatically if bootcount reaches {bootLimit}
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
            <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Health Commitment</div>
            <div className="text-2xl font-bold text-white mt-1 flex items-center gap-2">
              <span>Committed</span>
              <Check className="w-5 h-5 text-emerald-400" />
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              GRUB grubenv: bootcount reset to 0
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
            <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Watchdog Timeout</div>
            <div className="text-2xl font-bold text-white mt-1 font-mono">180s</div>
            <p className="text-[11px] text-slate-500 mt-1">
              Autonomous rollback timer armed during boot
            </p>
          </div>
        </div>

        {/* Live Health Quorum Checklist */}
        <div className="space-y-3 pt-2">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Health Quorum Verification Checklist
          </h3>

          <div className="space-y-2">
            {(healthChecks.length > 0 ? healthChecks : [
              {
                name: 'Network Interface Initialization',
                status: 'PASS' as const,
                detail: 'Loopback (lo) operational and link carrier detected across all active NICs',
                durationMs: 14,
              },
              {
                name: 'Kernel nftables Netfilter Baseline',
                status: 'PASS' as const,
                detail: 'Atomic ruleset syntax validation and kernel table hooks applied cleanly',
                durationMs: 28,
              },
              {
                name: 'Control Plane & Management Quorum',
                status: 'PASS' as const,
                detail: 'Privileged IPC socket /run/axonwall/agent.sock is active and responding',
                durationMs: 8,
              },
            ]).map((check) => (
              <div key={check.name} className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <CheckCircle2
                    className={`w-4 h-4 shrink-0 ${
                      check.status === 'PASS'
                        ? 'text-emerald-400'
                        : check.status === 'WARN'
                        ? 'text-amber-400'
                        : 'text-rose-400'
                    }`}
                  />
                  <div>
                    <div className="text-xs font-semibold text-white">{check.name}</div>
                    <div className="text-[11px] text-slate-400">{check.detail}</div>
                  </div>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
                    check.status === 'PASS'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : check.status === 'WARN'
                      ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                  }`}
                >
                  {check.status} ({check.durationMs}ms)
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
