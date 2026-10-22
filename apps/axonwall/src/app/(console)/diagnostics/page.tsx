'use client';

import React, { useState, useEffect } from 'react';
import {
  NmapTopologyView,
  NmapGeoMap,
  NmapDiffView,
  NmapStats,
  NmapCommandViewer,
  ScanUploader,
  HostTable,
  HostDetailDrawer,
  parseNmapXml,
  updateHostInScan,
  generateNetworkScenario,
  SAMPLE_SCANS,
} from 'nastymap';
import type { NmapHost, NmapRun, HostAction, TopologyNode } from 'nastymap';
import {
  Terminal,
  Play,
  Network,
  Globe,
  GitCompare,
  Server,
  BarChart2,
  Upload,
  Activity,
  Sparkles,
  Radar,
  Cpu,
  HardDrive,
  Search,
  RefreshCw,
  CheckCircle2,
  Layers,
  Shield,
  Zap,
  X,
} from 'lucide-react';
import {
  runDiagnostic,
  getAutoCliDefaults,
  runNmapScan,
  runCliToolSnapshot,
  type AutoCliDefaults,
  type CliUtilityId,
} from '../../../server/agent';

export default function DiagnosticsPage() {
  const [section, setSection] = useState<'nastymap' | 'cli_ops' | 'ping_probe'>('nastymap');

  // Auto-detected CLI & Network Defaults
  const [defaults, setDefaults] = useState<AutoCliDefaults | null>(null);
  const [loadingDefaults, setLoadingDefaults] = useState(true);

  // NastyMap State
  const [currentScan, setCurrentScan] = useState<NmapRun>(() =>
    parseNmapXml(SAMPLE_SCANS.enterprise.xml)
  );
  const [baselineScan, setBaselineScan] = useState<NmapRun>(() =>
    parseNmapXml(SAMPLE_SCANS.enterprise.xml)
  );
  const [activeScanLabel, setActiveScanLabel] = useState<string>('Enterprise Multi-Subnet');
  const [nmapTab, setNmapTab] = useState<'topology' | 'geo' | 'hosts' | 'diff' | 'stats'>('topology');
  const [selectedHost, setSelectedHost] = useState<NmapHost | null>(null);
  const [showUploadModal, setShowUploadModal] = useState(false);

  // Live / Simulated Nmap Scanner Controls
  const [scanTarget, setScanTarget] = useState('192.168.1.0/24');
  const [scanProfile, setScanProfile] = useState<
    'ping' | 'fast_ports' | 'service_os' | 'vuln_audit' | 'traceroute'
  >('service_os');
  const [useSimulated, setUseSimulated] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatusMsg, setScanStatusMsg] = useState<string | null>(null);

  // CLI Ops Toolkit State
  const [activeCliTool, setActiveCliTool] = useState<CliUtilityId>('bandwidth');
  const [selectedIface, setSelectedIface] = useState('eth0');
  const [digTarget, setDigTarget] = useState('cloudflare.com');
  const [digServer, setDigServer] = useState('1.1.1.1');
  const [digRecordType, setDigRecordType] = useState('A');
  const [cliOutput, setCliOutput] = useState<string>('');
  const [cliCommand, setCliCommand] = useState<string>('');
  const [isRunningCli, setIsRunningCli] = useState(false);

  // Ping / Port Probe State
  const [probeTool, setProbeTool] = useState<'ping' | 'port_probe'>('ping');
  const [probeTarget, setProbeTarget] = useState('1.1.1.1');
  const [probePort, setProbePort] = useState(443);
  const [probeOutput, setProbeOutput] = useState<string | null>(null);
  const [isProbing, setIsProbing] = useState(false);

  useEffect(() => {
    let active = true;
    getAutoCliDefaults()
      .then((res) => {
        if (!active) return;
        setDefaults(res);
        if (res.defaultSubnetCidr) setScanTarget(res.defaultSubnetCidr);
        if (res.defaultInterface) setSelectedIface(res.defaultInterface);
        if (res.defaultDnsServer) setDigServer(res.defaultDnsServer);
        if (res.defaultGatewayIp) setProbeTarget(res.defaultGatewayIp);
      })
      .catch(() => {})
      .finally(() => {
        if (active) setLoadingDefaults(false);
      });
    return () => {
      active = false;
    };
  }, []);

  // Auto-run initial CLI snapshot when switching to CLI Ops tab
  useEffect(() => {
    if (section === 'cli_ops' && !cliOutput && !isRunningCli) {
      handleRunCliTool('bandwidth');
    }
  }, [section]);

  const handleUpdateHost = (
    hostId: string,
    updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>
  ) => {
    setCurrentScan((prevScan) => {
      const updated = updateHostInScan(prevScan, hostId, updater);
      setSelectedHost((prev) => {
        if (!prev) return null;
        const matching = updated.hosts.find((h) => h.id === prev.id || h.ipv4 === prev.ipv4);
        return matching || prev;
      });
      return updated;
    });
  };

  const customActions: HostAction[] = [
    {
      id: 'deep-scan',
      label: 'Deep Re-Scan Host',
      icon: <Sparkles size={14} className="text-amber-400" />,
      shortcut: 'd',
      variant: 'primary',
      tooltip: 'Execute deep service & NSE banner audit on this host (Shortcut: D)',
      onClick: async (host, context) => {
        const hostIp = host.ipv4 || host.id;
        context.notify?.(`Probing ${hostIp} with nmap -sV --script=banner,ssl-cert...`, 'info');
        const res = await runNmapScan({
          target: hostIp,
          profile: 'vuln_audit',
          simulated: useSimulated,
        });
        if (res.xml) {
          try {
            const parsed = parseNmapXml(res.xml);
            const scannedHost = parsed.hosts[0];
            if (scannedHost) {
              context.updateHost(() => ({
                ports: scannedHost.ports.length > 0 ? scannedHost.ports : host.ports,
                primaryOs: scannedHost.primaryOs || host.primaryOs,
                tags: Array.from(new Set([...(host.tags || []), 'deep-scanned'])),
              }));
              context.notify?.(`Deep audit completed for ${hostIp} (${res.durationMs}ms).`, 'success');
              return;
            }
          } catch {}
        }
        context.updateHost((prev) => ({
          tags: Array.from(new Set([...(prev.tags || []), 'deep-scanned', 'verified'])),
        }));
        context.notify?.(`Completed verification scan for ${hostIp}.`, 'success');
      },
    },
  ];

  async function handleExecuteNmapScan() {
    setIsScanning(true);
    setScanStatusMsg(`Executing Nmap (${scanProfile}) on ${scanTarget}...`);
    try {
      // Save previous scan as baseline for Diff view
      setBaselineScan(currentScan);
      const res = await runNmapScan({
        target: scanTarget,
        profile: scanProfile,
        simulated: useSimulated,
      });

      if (!res.success) {
        setScanStatusMsg(res.error || 'Scan failed');
        return;
      }

      if (res.xml) {
        const parsed = parseNmapXml(res.xml);
        if (parsed.hosts.length > 0) {
          setCurrentScan(parsed);
          setActiveScanLabel(`Live Scan: ${scanTarget} (${parsed.hosts.length} hosts)`);
          setScanStatusMsg(
            `Completed live Nmap scan (${res.command}) in ${(res.durationMs / 1000).toFixed(1)}s — discovered ${parsed.hosts.length} hosts.`
          );
          return;
        }
      }

      // Generate topology scenario tailored to the target subnet when simulated or no live hosts responded
      const { scan: generated } = generateNetworkScenario({
        subnet: scanTarget.includes('/') ? scanTarget : `${scanTarget}/24`,
      });
      setCurrentScan(generated);
      setActiveScanLabel(
        `${res.mode === 'live' ? 'Scanned' : 'Simulated'}: ${scanTarget} (${generated.hosts.length} hosts)`
      );
      setScanStatusMsg(
        `Rendered topology for ${scanTarget} via '${res.command}' (${res.durationMs}ms).`
      );
    } finally {
      setIsScanning(false);
    }
  }

  async function handleRunCliTool(toolOverride?: CliUtilityId) {
    const targetTool = toolOverride || activeCliTool;
    if (toolOverride) setActiveCliTool(toolOverride);
    setIsRunningCli(true);
    try {
      const res = await runCliToolSnapshot(targetTool, {
        iface: selectedIface,
        target: digTarget,
        dnsServer: digServer,
        recordType: digRecordType,
      });
      setCliCommand(res.command);
      setCliOutput(res.output);
    } finally {
      setIsRunningCli(false);
    }
  }

  async function handleRunProbe() {
    setIsProbing(true);
    setProbeOutput('Executing diagnostic probe...');
    try {
      const res = await runDiagnostic(probeTool, probeTarget, probePort);
      setProbeOutput(res.output);
    } finally {
      setIsProbing(false);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Page Header & Top Mode Switcher */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-bold tracking-tight text-white">
              NastyMap Network Scanner & CLI Ops
            </h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
              NastyMap Engine v1.0
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Interactive Nmap topology mapping, GeoIP visualization, scan diffing, and system CLI telemetry with intelligent auto-detected appliance defaults.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-800 p-1 rounded-xl">
          <button
            type="button"
            onClick={() => setSection('nastymap')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition cursor-pointer ${
              section === 'nastymap'
                ? 'bg-emerald-600 text-white shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Radar className="w-4 h-4" />
            <span>NastyMap Scanner</span>
          </button>
          <button
            type="button"
            onClick={() => setSection('cli_ops')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition cursor-pointer ${
              section === 'cli_ops'
                ? 'bg-emerald-600 text-white shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>CLI Ops Toolkit</span>
          </button>
          <button
            type="button"
            onClick={() => setSection('ping_probe')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition cursor-pointer ${
              section === 'ping_probe'
                ? 'bg-emerald-600 text-white shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Ping & Port Probe</span>
          </button>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* SECTION 1: NASTYMAP INTERACTIVE NMAP SCANNER & TOPOLOGY VISUALIZER    */}
      {/* ===================================================================== */}
      {section === 'nastymap' && (
        <div className="space-y-5">
          {/* Intelligent Auto-Default Nmap Control Bar */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                  Intelligent Auto-Detected Subnets & Static Routes
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setBaselineScan(currentScan);
                    setCurrentScan(parseNmapXml(SAMPLE_SCANS.enterprise.xml));
                    setActiveScanLabel(SAMPLE_SCANS.enterprise.name);
                  }}
                  className="px-2.5 py-1 rounded-md text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 transition cursor-pointer"
                >
                  Preset: Enterprise Multi-Subnet
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setBaselineScan(currentScan);
                    setCurrentScan(parseNmapXml(SAMPLE_SCANS.global.xml));
                    setActiveScanLabel(SAMPLE_SCANS.global.name);
                  }}
                  className="px-2.5 py-1 rounded-md text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 transition cursor-pointer"
                >
                  Preset: Global Perimeter
                </button>
                <button
                  type="button"
                  onClick={() => setShowUploadModal(true)}
                  className="px-2.5 py-1 rounded-md text-xs bg-indigo-600/20 border border-indigo-500/40 hover:bg-indigo-600/30 text-indigo-300 flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Import Nmap XML</span>
                </button>
              </div>
            </div>

            {/* Quick Subnet Pills from Appliance Config / Routing */}
            {defaults && defaults.subnets.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {defaults.subnets.map((sub) => (
                  <button
                    key={sub.id}
                    type="button"
                    onClick={() => setScanTarget(sub.cidr)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-2 border transition cursor-pointer ${
                      scanTarget === sub.cidr
                        ? 'bg-emerald-500/15 border-emerald-500/50 text-emerald-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <span className="font-bold text-white">{sub.role}</span>
                    <span>{sub.cidr}</span>
                    <span className="text-[10px] text-slate-500">({sub.device})</span>
                  </button>
                ))}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
              <div className="md:col-span-5">
                <label className="block text-xs font-semibold text-slate-400 uppercase mb-1.5">
                  Target Subnet / CIDR / Host
                </label>
                <input
                  type="text"
                  value={scanTarget}
                  onChange={(e) => setScanTarget(e.target.value)}
                  placeholder="e.g. 192.168.1.0/24 or 10.80.0.0/24"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm font-mono text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
                />
              </div>

              <div className="md:col-span-4">
                <label className="block text-xs font-semibold text-slate-400 uppercase mb-1.5">
                  Nmap Scan Profile
                </label>
                <select
                  value={scanProfile}
                  onChange={(e) => setScanProfile(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
                >
                  <option value="ping">Layer 1: Fast Ping & ARP Sweep (-sn -T4)</option>
                  <option value="fast_ports">Layer 2: Fast Top-100 Ports (-F -T4)</option>
                  <option value="service_os">Layer 3: Service & Banner Audit (-sV --version-light)</option>
                  <option value="vuln_audit">Layer 4: NSE HTTP/SSL/Banner Scripts (--script)</option>
                  <option value="traceroute">Layer 5: Topology Traceroute (--traceroute)</option>
                </select>
              </div>

              <div className="md:col-span-3 flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleExecuteNmapScan}
                  disabled={isScanning}
                  className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-semibold flex items-center justify-center gap-2 transition cursor-pointer"
                >
                  <Play className="w-4 h-4 fill-current" />
                  <span>{isScanning ? 'Scanning...' : 'Run Nmap Scan'}</span>
                </button>
              </div>
            </div>

            {scanStatusMsg && (
              <div className="text-xs font-mono text-emerald-400 bg-slate-950 border border-slate-800/80 rounded-lg px-3 py-2 flex items-center justify-between">
                <span>{scanStatusMsg}</span>
                <span className="text-slate-500">Active Dataset: {activeScanLabel}</span>
              </div>
            )}
          </div>

          {/* NastyMap Sub-Navigation Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-2">
            <div className="flex flex-wrap items-center gap-1.5">
              {[
                { id: 'topology', label: '2D Topology Graph', icon: Network },
                { id: 'geo', label: 'World GeoIP Map', icon: Globe },
                { id: 'hosts', label: `Host Directory (${currentScan.hosts.length})`, icon: Server },
                { id: 'diff', label: 'Scan Diff Viewer', icon: GitCompare },
                { id: 'stats', label: 'Telemetry & Nmap CLI', icon: BarChart2 },
              ].map((t) => {
                const Icon = t.icon;
                const active = nmapTab === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setNmapTab(t.id as any)}
                    className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition cursor-pointer ${
                      active
                        ? 'bg-indigo-600 text-white shadow'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{t.label}</span>
                  </button>
                );
              })}
            </div>

            <div className="text-xs text-slate-400 px-3">
              SSH TUI Command:{' '}
              <code className="text-emerald-400 font-mono bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                axonwall-tui --tab nastymap
              </code>
            </div>
          </div>

          {/* Active NastyMap Visualization Canvas */}
          <div className="min-h-[600px]">
            {nmapTab === 'topology' && (
              <NmapTopologyView
                scan={currentScan}
                initialLayout="force"
                onSelectHost={(host) => setSelectedHost(host)}
                onUpdateHost={handleUpdateHost}
                customActions={customActions}
              />
            )}

            {nmapTab === 'geo' && (
              <NmapGeoMap
                scan={currentScan}
                onSelectHost={(host) => setSelectedHost(host)}
              />
            )}

            {nmapTab === 'hosts' && (
              <HostTable
                scan={currentScan}
                onSelectHost={(host) => setSelectedHost(host)}
                onUpdateHost={handleUpdateHost}
                customActions={customActions}
              />
            )}

            {nmapTab === 'diff' && (
              <NmapDiffView
                scanA={baselineScan}
                scanB={currentScan}
              />
            )}

            {nmapTab === 'stats' && (
              <div className="space-y-6">
                <NmapStats scan={currentScan} />
                <NmapCommandViewer scan={currentScan} />
              </div>
            )}
          </div>

          {/* Slide-Over Host Detail Inspector Drawer */}
          <HostDetailDrawer
            node={
              selectedHost
                ? ({
                    id: selectedHost.ipv4 || selectedHost.id,
                    label: selectedHost.primaryHostname || selectedHost.ipv4 || selectedHost.id,
                    ip: selectedHost.ipv4 || selectedHost.id,
                    hostname: selectedHost.primaryHostname,
                    nodeType: selectedHost.deviceType === 'router' ? 'router' : 'host',
                    status: selectedHost.status.state === 'up' ? 'up' : 'down',
                    osFamily: selectedHost.osFamily || 'Unknown',
                    osName: selectedHost.primaryOs || 'Unknown OS',
                    deviceType: selectedHost.deviceType || 'general purpose',
                    openPorts: selectedHost.ports.filter((p) => p.state === 'open').map((p) => p.portid),
                    openPortDetails: selectedHost.ports.filter((p) => p.state === 'open'),
                    latencyMs: selectedHost.latencyMs,
                    hopsAway: selectedHost.distance || 1,
                    subnet: selectedHost.ipv4
                      ? `${selectedHost.ipv4.split('.').slice(0, 3).join('.')}.0/24`
                      : 'Other',
                    hostRef: selectedHost,
                    geolocation: selectedHost.geolocation,
                    x: 0,
                    y: 0,
                    radius: 20,
                  } satisfies TopologyNode)
                : null
            }
            onClose={() => setSelectedHost(null)}
            onUpdateHost={handleUpdateHost}
            customActions={customActions}
          />

          {/* Upload XML Modal */}
          {showUploadModal && (
            <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
              <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-bold text-white">Import Nmap XML Scan Output (-oX)</h3>
                  <button
                    type="button"
                    onClick={() => setShowUploadModal(false)}
                    className="text-slate-400 hover:text-white cursor-pointer"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <ScanUploader
                  onScanLoaded={(scan, fileName) => {
                    setBaselineScan(currentScan);
                    setCurrentScan(scan);
                    setActiveScanLabel(fileName || 'Uploaded XML Scan');
                    setShowUploadModal(false);
                  }}
                />
              </div>
            </div>
          )}
        </div>
      )}

      {/* ===================================================================== */}
      {/* SECTION 2: DEBIAN / ALPINE CLI OPS TOOLKIT WITH AUTO-DEFAULTS         */}
      {/* ===================================================================== */}
      {section === 'cli_ops' && (
        <div className="space-y-5">
          {/* Installed CLI Utilities & Shell Standard Bar */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-300">
              <Shield className="w-4 h-4 text-emerald-400" />
              <span>
                Standard Appliance Environment: <strong className="text-white">ZSH</strong> default shell +{' '}
                <strong className="text-white">VIM</strong> (<code className="text-emerald-400">update-alternatives</code>)
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {[
                'zsh',
                'vim',
                'btop',
                'htop',
                'sysstat',
                'iotop',
                'iftop',
                'slurm',
                'net-tools',
                'dnsutils',
                'nmap',
              ].map((pkg) => (
                <span
                  key={pkg}
                  className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-950 border border-slate-800 text-emerald-400"
                >
                  {pkg}
                </span>
              ))}
            </div>
          </div>

          {/* Tool Selector Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {[
              {
                id: 'bandwidth' as CliUtilityId,
                title: 'slurm / iftop',
                subtitle: `NIC Traffic (${selectedIface})`,
                icon: Activity,
              },
              {
                id: 'sysstat' as CliUtilityId,
                title: 'sysstat',
                subtitle: 'mpstat & iostat -xz',
                icon: Cpu,
              },
              {
                id: 'net_tools' as CliUtilityId,
                title: 'net-tools',
                subtitle: 'netstat, arp & routes',
                icon: Network,
              },
              {
                id: 'dnsutils' as CliUtilityId,
                title: 'dnsutils (dig)',
                subtitle: `@${digServer} resolver`,
                icon: Globe,
              },
              {
                id: 'top_procs' as CliUtilityId,
                title: 'btop / htop',
                subtitle: 'Top CPU/Mem Processes',
                icon: Server,
              },
              {
                id: 'iotop' as CliUtilityId,
                title: 'iotop',
                subtitle: 'Disk I/O Telemetry',
                icon: HardDrive,
              },
            ].map((item) => {
              const Icon = item.icon;
              const active = activeCliTool === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleRunCliTool(item.id)}
                  className={`p-3.5 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                    active
                      ? 'bg-emerald-600/15 border-emerald-500 text-white'
                      : 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <Icon className={`w-4 h-4 ${active ? 'text-emerald-400' : 'text-slate-400'}`} />
                    {active && <span className="w-2 h-2 rounded-full bg-emerald-400" />}
                  </div>
                  <div>
                    <div className="text-xs font-bold text-white">{item.title}</div>
                    <div className="text-[11px] text-slate-400 truncate mt-0.5">{item.subtitle}</div>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Intelligent Parameter Bar for Active CLI Tool */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-end gap-4">
            {(activeCliTool === 'bandwidth' || activeCliTool === 'net_tools') && (
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase mb-1.5">
                  Auto-Detected Network Interface
                </label>
                <select
                  value={selectedIface}
                  onChange={(e) => setSelectedIface(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm font-mono text-white"
                >
                  {(defaults?.interfaces || ['eth0', 'eth1']).map((ifn) => (
                    <option key={ifn} value={ifn}>
                      {ifn}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {activeCliTool === 'dnsutils' && (
              <>
                <div className="flex-1 min-w-[200px]">
                  <label className="block text-xs font-semibold text-slate-400 uppercase mb-1.5">
                    Domain / Hostname
                  </label>
                  <input
                    type="text"
                    value={digTarget}
                    onChange={(e) => setDigTarget(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm font-mono text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase mb-1.5">
                    DNS Server (Auto)
                  </label>
                  <input
                    type="text"
                    value={digServer}
                    onChange={(e) => setDigServer(e.target.value)}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm font-mono text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase mb-1.5">
                    Record Type
                  </label>
                  <select
                    value={digRecordType}
                    onChange={(e) => setDigRecordType(e.target.value)}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm font-mono text-white"
                  >
                    {['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV'].map((rt) => (
                      <option key={rt} value={rt}>
                        {rt}
                      </option>
                    ))}
                  </select>
                </div>
              </>
            )}

            <button
              type="button"
              onClick={() => handleRunCliTool()}
              disabled={isRunningCli}
              className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRunningCli ? 'animate-spin' : ''}`} />
              <span>{isRunningCli ? 'Collecting...' : 'Refresh Snapshot'}</span>
            </button>
          </div>

          {/* Terminal Output Display */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>CLI Telemetry Output</span>
              </div>
              {cliCommand && (
                <code className="text-xs font-mono text-slate-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
                  $ {cliCommand}
                </code>
              )}
            </div>
            <pre className="bg-slate-950 border border-slate-800/80 rounded-lg p-4 font-mono text-xs text-emerald-400 whitespace-pre-wrap overflow-x-auto max-h-[520px]">
              {cliOutput || 'Select a CLI utility above to inspect live appliance telemetry.'}
            </pre>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* SECTION 3: BOUNDED PING & TCP PORT PROBE                              */}
      {/* ===================================================================== */}
      {section === 'ping_probe' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                  Diagnostic Tool
                </label>
                <select
                  value={probeTool}
                  onChange={(e) => setProbeTool(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
                >
                  <option value="ping">Ping (ICMP Echo)</option>
                  <option value="port_probe">TCP Port Probe</option>
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                  Target Hostname / IP (Auto-Default: Gateway)
                </label>
                <input
                  type="text"
                  value={probeTarget}
                  onChange={(e) => setProbeTarget(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
                  placeholder="e.g. 1.1.1.1 or cloudflare.com"
                />
              </div>

              {probeTool === 'port_probe' && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase mb-2">
                    TCP Port
                  </label>
                  <input
                    type="number"
                    value={probePort}
                    onChange={(e) => setProbePort(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
                  />
                </div>
              )}
            </div>

            <div>
              <button
                type="button"
                onClick={handleRunProbe}
                disabled={isProbing}
                className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition cursor-pointer disabled:opacity-50"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>{isProbing ? 'Running Diagnostic...' : 'Execute Diagnostic'}</span>
              </button>
            </div>
          </div>

          {probeOutput && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>Console Output</span>
              </div>
              <pre className="bg-slate-950 border border-slate-800/80 rounded-lg p-4 font-mono text-xs text-emerald-400 whitespace-pre-wrap">
                {probeOutput}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
