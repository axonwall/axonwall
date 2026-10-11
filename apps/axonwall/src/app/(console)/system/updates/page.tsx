'use client';

import React, { useState } from 'react';
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
} from 'lucide-react';

interface PartitionSlot {
  slot: 'A' | 'B';
  name: string;
  isActive: boolean;
  isHealthy: boolean;
  version: string;
  kernel: string;
  device: string;
  label: string;
  size: string;
  lastUpdated: string;
}

export default function SystemUpdatesPage() {
  const [slots, setSlots] = useState<PartitionSlot[]>([
    {
      slot: 'A',
      name: 'Slot A (Primary Rootfs)',
      isActive: true,
      isHealthy: true,
      version: '2.4.0-enterprise',
      kernel: 'Linux 6.12.111+deb13-amd64',
      device: '/dev/sda2',
      label: 'axon_root_a',
      size: '16.0 GB (ext4)',
      lastUpdated: '2026-10-09 14:32 UTC',
    },
    {
      slot: 'B',
      name: 'Slot B (Alternate Standby)',
      isActive: false,
      isHealthy: true,
      version: '2.4.1-rc1 (Staged Candidate)',
      kernel: 'Linux 6.12.111+deb13-amd64',
      device: '/dev/sda3',
      label: 'axon_root_b',
      size: '16.0 GB (ext4)',
      lastUpdated: '2026-10-11 18:20 UTC',
    },
  ]);

  const [bootCount, setBootCount] = useState(0);
  const [bootLimit] = useState(3);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isCheckingCloud, setIsCheckingCloud] = useState(false);
  const [isUpgrading, setIsUpgrading] = useState(false);
  const [upgradeProgress, setUpgradeProgress] = useState(0);
  const [upgradePhase, setUpgradePhase] = useState('');
  const [alertMessage, setAlertMessage] = useState<string | null>(null);

  const activeSlot = slots.find((s) => s.isActive) || slots[0];
  const standbySlot = slots.find((s) => !s.isActive) || slots[1];

  const handleManualRollback = () => {
    if (
      !confirm(
        `Are you sure you want to trigger a safe rollback to Slot ${standbySlot.slot}? The system will set active_slot=${standbySlot.slot}, reset bootcount=0, and reboot into the alternate rootfs.`
      )
    ) {
      return;
    }

    setAlertMessage(`Switching GRUB active_slot to ${standbySlot.slot}. System reboot scheduled in 5 seconds...`);
    setSlots(
      slots.map((s) => ({
        ...s,
        isActive: !s.isActive,
      }))
    );
  };

  const handleCheckCloud = () => {
    setIsCheckingCloud(true);
    setTimeout(() => {
      setIsCheckingCloud(false);
      alert('Axonwall Release Channel Check: Up to date! Available candidate 2.4.1-rc1 is already staged on Standby Slot B.');
    }, 1500);
  };

  const handleFlashUpgrade = () => {
    setIsUpgrading(true);
    setUpgradeProgress(10);
    setUpgradePhase('Streaming cryptographically signed rootfs image to ' + standbySlot.device + '...');

    setTimeout(() => {
      setUpgradeProgress(45);
      setUpgradePhase('Verifying SHA-256 integrity hash & cryptographic GPG signature...');
    }, 1200);

    setTimeout(() => {
      setUpgradeProgress(80);
      setUpgradePhase('Writing rootfs payload to ' + standbySlot.label + ' and updating /etc/fstab...');
    }, 2400);

    setTimeout(() => {
      setUpgradeProgress(100);
      setUpgradePhase('Arming GRUB boot-counting watchdog (bootcount=0, bootlimit=3)...');
      setTimeout(() => {
        setIsUpgrading(false);
        setAlertMessage(`Firmware 2.4.1-rc1 successfully flashed to Slot ${standbySlot.slot}! System will boot Slot ${standbySlot.slot} on next reboot with Watchdog supervision.`);
      }, 800);
    }, 3600);
  };

  const handleRunHealthCheck = () => {
    setIsVerifying(true);
    setTimeout(() => {
      setIsVerifying(false);
      setBootCount(0);
      alert('Watchdog Health Quorum: All 3 verification tests PASSED. Partition marked permanently healthy (bootcount=0).');
    }, 1200);
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
            <h1 className="text-2xl font-bold tracking-tight text-white">A/B Dual-Root System Updates</h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Unbrickable Architecture
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Zero-downtime atomic operating system upgrades with GRUB automated boot-counting and kernel health verification.
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
            <span>Flash New Image to Standby</span>
          </button>
        </div>
      </div>

      {alertMessage && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-sm flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>{alertMessage}</span>
          </div>
          <button onClick={() => setAlertMessage(null)} className="text-slate-400 hover:text-white text-xs">
            ✕
          </button>
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

      {/* A/B Dual-Root Partition Slots */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
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
                    {slot.slot}
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
                      Active Boot Partition
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
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span className="text-slate-300">
                    {slot.isActive ? 'Healthy & Committed' : 'Flash Target Ready'}
                  </span>
                </div>

                {!slot.isActive && (
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

      {/* GRUB Watchdog & Health Quorum Dashboard */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">GRUB Watchdog & Health Quorum</h2>
              <p className="text-xs text-slate-400">
                Autonomous multi-stage verification confirming stability before committing partitions
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
            <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <div>
                  <div className="text-xs font-semibold text-white">Network Interface Initialization</div>
                  <div className="text-[11px] text-slate-400">
                    Loopback (lo) operational and link carrier detected across all active NICs
                  </div>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                PASSED (14ms)
              </span>
            </div>

            <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <div>
                  <div className="text-xs font-semibold text-white">Kernel nftables Netfilter Baseline</div>
                  <div className="text-[11px] text-slate-400">
                    Atomic ruleset syntax validation and kernel table hooks applied cleanly
                  </div>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                PASSED (28ms)
              </span>
            </div>

            <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <div>
                  <div className="text-xs font-semibold text-white">Control Plane & Management Quorum</div>
                  <div className="text-[11px] text-slate-400">
                    Privileged IPC socket /run/axonwall/agent.sock is active and responding
                  </div>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                PASSED (8ms)
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
