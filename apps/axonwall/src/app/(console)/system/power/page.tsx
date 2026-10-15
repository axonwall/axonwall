'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Power,
  RotateCcw,
  Layers,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  Clock,
  Server,
  RefreshCw,
  ArrowRight,
  ShieldAlert,
  Loader2,
  Zap,
} from 'lucide-react';
import { getSystemPartitionsTelemetry, type SystemPartitionsTelemetry, type PartitionSlotInfo } from '@/server/agent';

export default function PowerManagementPage() {
  const [telemetry, setTelemetry] = useState<SystemPartitionsTelemetry | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedSlot, setSelectedSlot] = useState<'A' | 'B'>('B');
  const [modalAction, setModalAction] = useState<'reboot_current' | 'reboot_slot' | 'poweroff' | null>(null);
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionMessage, setExecutionMessage] = useState<string | null>(null);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const [pingAttempts, setPingAttempts] = useState(0);

  const fetchTelemetry = async () => {
    try {
      let data: SystemPartitionsTelemetry | null = null;
      try {
        const resp = await fetch('/api/system/update');
        const json = await resp.json();
        if (json.telemetry) data = json.telemetry;
      } catch {
        data = await getSystemPartitionsTelemetry();
      }
      if (data) {
        setTelemetry(data);
        const standby = data.slots.find((s) => !s.isActive);
        if (standby) setSelectedSlot(standby.slot);
      }
    } catch (err) {
      console.error('Failed to load system partitions telemetry:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  const activeSlot = telemetry?.slots.find((s) => s.isActive);
  const standbySlot = telemetry?.slots.find((s) => !s.isActive);

  const handleExecutePower = async (action: 'reboot' | 'poweroff', targetSlot?: 'A' | 'B') => {
    setIsExecuting(true);
    setExecutionMessage(
      action === 'reboot'
        ? `Initiating system reboot${targetSlot ? ` into Slot ${targetSlot}` : ''}...`
        : 'Initiating system shutdown sequence...'
    );

    try {
      const resp = await fetch('/api/system/power', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, slot: targetSlot }),
      });
      const data = await resp.json();

      if (!data.success) {
        alert(`Operation failed: ${data.message}`);
        setIsExecuting(false);
        setModalAction(null);
        return;
      }

      setExecutionMessage(data.message || 'Signal sent successfully. Disconnecting...');
      setModalAction(null);

      if (action === 'reboot') {
        setIsReconnecting(true);
        startReconnectionProbe();
      } else {
        alert('Appliance power off in progress. Storage has been cleanly unmounted and system is halted.');
      }
    } catch (err: any) {
      alert(`Power execution error: ${err?.message || String(err)}`);
      setIsExecuting(false);
      setModalAction(null);
    }
  };

  const startReconnectionProbe = () => {
    let attempts = 0;
    const interval = setInterval(async () => {
      attempts++;
      setPingAttempts(attempts);
      try {
        const res = await fetch('/api/system/update', { cache: 'no-store' });
        if (res.ok) {
          clearInterval(interval);
          setIsReconnecting(false);
          setIsExecuting(false);
          alert('Axonwall Appliance is back online! Reloading system state...');
          window.location.reload();
        }
      } catch {
        // Appliance still rebooting
      }
    }, 3000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">
              <Power className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-3">
                Power & Reboot Management
              </h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Graceful system reboot, A/B rootfs partition slot switching, and hardware shutdown controls
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchTelemetry}
            disabled={isLoading}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-lg border border-border/60 bg-muted/40 hover:bg-muted text-foreground transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh Status
          </button>
          <Link
            href="/system/updates"
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-lg border border-primary/30 bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
          >
            <Layers className="w-3.5 h-3.5" />
            A/B Firmware Updates
          </Link>
        </div>
      </div>

      {/* Reconnection Screen Overlay */}
      {isReconnecting && (
        <div className="rounded-2xl border border-cyan-500/30 bg-cyan-950/20 p-8 text-center space-y-4 shadow-xl">
          <div className="inline-flex p-4 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse">
            <Loader2 className="w-8 h-8 animate-spin" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-foreground">Reboot in Progress</h3>
            <p className="text-sm text-muted-foreground mt-1 max-w-md mx-auto">
              Axonwall is cycling network services and booting into the requested partition slot. Probing control plane
              socket... (Attempt {pingAttempts})
            </p>
          </div>
          <div className="inline-block px-4 py-1.5 rounded-full bg-background/80 border border-border/60 text-xs font-mono text-muted-foreground">
            Heartbeat ping interval: 3000ms
          </div>
        </div>
      )}

      {/* Partition Telemetry Banner */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Active Slot */}
        <div className="p-5 rounded-xl border border-emerald-500/30 bg-emerald-950/10 relative overflow-hidden">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                  Active Running Partition
                </span>
              </div>
              <h3 className="text-lg font-bold text-foreground">
                Slot {activeSlot?.slot || 'A'} &mdash; {activeSlot?.name || 'Primary Rootfs'}
              </h3>
              <p className="text-xs text-muted-foreground font-mono">
                {activeSlot?.device || '/dev/disk/by-label/axon_root_a'} ({activeSlot?.size || '16.0 GB ext4'})
              </p>
            </div>
            <div className="px-3 py-1 rounded-md bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 font-mono text-xs font-semibold">
              v{activeSlot?.version || '0.5.0'}
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-emerald-500/20 flex items-center justify-between text-xs text-muted-foreground">
            <span>Kernel: {activeSlot?.kernel || 'Linux 6.12.111'}</span>
            <span className="text-emerald-400 font-medium">Currently Booted & Serving Traffic</span>
          </div>
        </div>

        {/* Standby Slot */}
        <div className="p-5 rounded-xl border border-blue-500/30 bg-blue-950/10 relative overflow-hidden">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-blue-400">
                  Alternate Standby Partition
                </span>
              </div>
              <h3 className="text-lg font-bold text-foreground">
                Slot {standbySlot?.slot || 'B'} &mdash; {standbySlot?.name || 'Alternate Standby'}
              </h3>
              <p className="text-xs text-muted-foreground font-mono">
                {standbySlot?.device || '/dev/disk/by-label/axon_root_b'} ({standbySlot?.size || '16.0 GB ext4'})
              </p>
            </div>
            <div className="px-3 py-1 rounded-md bg-blue-500/20 border border-blue-500/30 text-blue-300 font-mono text-xs font-semibold">
              v{standbySlot?.version || '0.5.0'}
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-blue-500/20 flex items-center justify-between text-xs text-muted-foreground">
            <span>Kernel: {standbySlot?.kernel || 'Linux 6.12.111'}</span>
            <span className="text-blue-400 font-medium">Ready for Boot Switch / Rollback</span>
          </div>
        </div>
      </div>

      {/* Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Action 1: Graceful Reboot */}
        <div className="rounded-xl border border-border/60 bg-card p-6 flex flex-col justify-between space-y-5 hover:border-amber-500/40 transition-all">
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <RotateCcw className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-foreground">Graceful Reboot</h3>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                Cleanly restarts all firewall, network, and storage services, cleanly syncs filesystem caches, and boots
                back into the currently active slot (
                <strong className="text-foreground">Slot {activeSlot?.slot || 'A'}</strong>).
              </p>
            </div>
            <div className="rounded-lg bg-muted/40 p-3 text-xs text-muted-foreground space-y-1">
              <div className="flex items-center justify-between">
                <span>Active Slot:</span>
                <span className="font-semibold text-foreground">Slot {activeSlot?.slot || 'A'}</span>
              </div>
              <div className="flex items-center justify-between">
                <span>Version:</span>
                <span className="font-mono text-foreground">v{activeSlot?.version || '0.5.0'}</span>
              </div>
            </div>
          </div>

          <button
            onClick={() => setModalAction('reboot_current')}
            disabled={isExecuting || isReconnecting}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-amber-500 hover:bg-amber-600 text-amber-950 font-semibold text-xs tracking-wide transition-colors shadow-sm disabled:opacity-50"
          >
            <RotateCcw className="w-4 h-4" />
            Reboot Appliance
          </button>
        </div>

        {/* Action 2: Reboot into Alternate Slot */}
        <div className="rounded-xl border border-border/60 bg-card p-6 flex flex-col justify-between space-y-5 hover:border-primary/40 transition-all">
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Layers className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-foreground">Reboot into Target Slot</h3>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                Arms the GRUB bootloader to boot into the selected partition slot, resets watchdog boot limits, and
                executes a verified boot cycle.
              </p>
            </div>

            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">Select Target Boot Slot:</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedSlot('A')}
                  className={`p-2.5 rounded-lg border text-left text-xs transition-colors ${
                    selectedSlot === 'A'
                      ? 'border-primary bg-primary/10 text-foreground font-semibold'
                      : 'border-border/60 bg-muted/20 text-muted-foreground hover:bg-muted/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span>Slot A</span>
                    {activeSlot?.slot === 'A' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400">Active</span>
                    )}
                  </div>
                  <div className="text-[11px] font-mono text-muted-foreground mt-0.5">
                    v{telemetry?.slots.find((s) => s.slot === 'A')?.version || '0.5.0'}
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => setSelectedSlot('B')}
                  className={`p-2.5 rounded-lg border text-left text-xs transition-colors ${
                    selectedSlot === 'B'
                      ? 'border-primary bg-primary/10 text-foreground font-semibold'
                      : 'border-border/60 bg-muted/20 text-muted-foreground hover:bg-muted/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span>Slot B</span>
                    {activeSlot?.slot === 'B' && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400">Active</span>
                    )}
                  </div>
                  <div className="text-[11px] font-mono text-muted-foreground mt-0.5">
                    v{telemetry?.slots.find((s) => s.slot === 'B')?.version || '0.5.0'}
                  </div>
                </button>
              </div>
            </div>
          </div>

          <button
            onClick={() => setModalAction('reboot_slot')}
            disabled={isExecuting || isReconnecting}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground font-semibold text-xs tracking-wide transition-colors shadow-sm disabled:opacity-50"
          >
            <ArrowRight className="w-4 h-4" />
            Reboot into Slot {selectedSlot}
          </button>
        </div>

        {/* Action 3: Power Off */}
        <div className="rounded-xl border border-red-500/30 bg-card p-6 flex flex-col justify-between space-y-5 hover:border-red-500/60 transition-all">
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-500">
              <Power className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-foreground">Power Off Appliance</h3>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                Gracefully stops daemon processes, closes database write-ahead logs, and unmounts filesystems before
                halting ACPI system power.
              </p>
            </div>
            <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 text-xs text-red-400 space-y-1">
              <div className="flex items-center gap-1.5 font-semibold">
                <AlertTriangle className="w-3.5 h-3.5" />
                Physical Access Required
              </div>
              <p className="text-[11px] leading-normal text-red-300/80">
                You will need physical access, IPMI/iLO/DRAC, or Wake-on-LAN to power the system back on.
              </p>
            </div>
          </div>

          <button
            onClick={() => setModalAction('poweroff')}
            disabled={isExecuting || isReconnecting}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-red-600 hover:bg-red-700 text-white font-semibold text-xs tracking-wide transition-colors shadow-sm disabled:opacity-50"
          >
            <Power className="w-4 h-4" />
            Power Off Appliance
          </button>
        </div>
      </div>

      {/* Confirmation Modal */}
      {modalAction && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-border/80 bg-card p-6 shadow-2xl space-y-5 animate-in fade-in-50 zoom-in-95">
            <div className="flex items-center gap-3">
              <div
                className={`p-3 rounded-xl border ${
                  modalAction === 'poweroff'
                    ? 'bg-red-500/10 border-red-500/20 text-red-400'
                    : 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                }`}
              >
                {modalAction === 'poweroff' ? <Power className="w-6 h-6" /> : <RotateCcw className="w-6 h-6" />}
              </div>
              <div>
                <h3 className="text-base font-bold text-foreground">
                  {modalAction === 'reboot_current' && 'Confirm System Reboot'}
                  {modalAction === 'reboot_slot' && `Reboot into Slot ${selectedSlot}`}
                  {modalAction === 'poweroff' && 'Confirm Appliance Power Off'}
                </h3>
                <p className="text-xs text-muted-foreground">Action requires administrative confirmation</p>
              </div>
            </div>

            <div className="text-xs text-muted-foreground space-y-2 leading-relaxed bg-muted/30 p-3 rounded-lg border border-border/40">
              {modalAction === 'reboot_current' && (
                <p>
                  Are you sure you want to reboot Axonwall into{' '}
                  <strong className="text-foreground">Slot {activeSlot?.slot || 'A'} (v{activeSlot?.version || '0.5.0'})</strong>?
                  All active firewall connections will be momentarily interrupted while services reload.
                </p>
              )}
              {modalAction === 'reboot_slot' && (
                <p>
                  Are you sure you want to reboot into{' '}
                  <strong className="text-foreground">
                    Slot {selectedSlot} (v{telemetry?.slots.find((s) => s.slot === selectedSlot)?.version || '0.5.0'})
                  </strong>
                  ? The GRUB bootloader will be armed to switch roots. Watchdog will run a 3-step health check upon boot.
                </p>
              )}
              {modalAction === 'poweroff' && (
                <p className="text-red-400 font-medium">
                  WARNING: Powering off will shut down all network interfaces and halt the CPU. The web console will become
                  unreachable until the unit is manually powered back on.
                </p>
              )}
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setModalAction(null)}
                disabled={isExecuting}
                className="px-4 py-2 rounded-lg border border-border text-xs font-medium text-muted-foreground hover:bg-muted transition-colors"
              >
                Cancel
              </button>

              {modalAction === 'reboot_current' && (
                <button
                  type="button"
                  onClick={() => handleExecutePower('reboot', activeSlot?.slot || 'A')}
                  disabled={isExecuting}
                  className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-600 text-amber-950 text-xs font-semibold transition-colors flex items-center gap-1.5"
                >
                  {isExecuting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5" />}
                  Confirm Reboot
                </button>
              )}

              {modalAction === 'reboot_slot' && (
                <button
                  type="button"
                  onClick={() => handleExecutePower('reboot', selectedSlot)}
                  disabled={isExecuting}
                  className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-semibold transition-colors flex items-center gap-1.5"
                >
                  {isExecuting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ArrowRight className="w-3.5 h-3.5" />}
                  Reboot into Slot {selectedSlot}
                </button>
              )}

              {modalAction === 'poweroff' && (
                <button
                  type="button"
                  onClick={() => handleExecutePower('poweroff')}
                  disabled={isExecuting}
                  className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold transition-colors flex items-center gap-1.5"
                >
                  {isExecuting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Power className="w-3.5 h-3.5" />}
                  Confirm Power Off
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
