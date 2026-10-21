import React, { useState, useRef, useEffect, useMemo } from 'react';
import type {
  DetailLevelSettings,
  FilterOptions,
  NmapHost,
  NmapRun,
  TopologyGraph,
  TopologyLayoutType,
  TopologyNode,
  HostAction,
  CustomDrawerTab,
} from '../types/nmap';
import {
  generateTopology,
  filterTopology,
  applyLayout,
  stepPhysicsSimulation,
} from '../topology/topology-engine';
import { exportSvgElement, exportToPng, generateHtmlReport } from '../export/exporter';
import { HostDetailDrawer } from './HostDetailDrawer';
import { getHostIcon } from '../icons/index';
import {
  Network,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Download,
  Filter,
  SlidersHorizontal,
  Search,
  Layers,
  Activity,
  Play,
  Pause,
  RefreshCw,
  FileCode,
  Shield,
  Tag,
  Radio,
  FileText,
  Zap,
  Info,
} from 'lucide-react';

export interface NmapTopologyViewProps {
  scan: NmapRun;
  initialLayout?: TopologyLayoutType;
  onSelectHost?: (host: NmapHost) => void;
  onUpdateHost?: (hostId: string, updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>) => void;
  onNodeContextMenu?: (node: TopologyNode, e: React.MouseEvent) => void;
  customActions?: HostAction[];
  customTabs?: CustomDrawerTab[];
  className?: string;
}

export function NmapTopologyView({
  scan,
  initialLayout = 'force',
  onSelectHost,
  onUpdateHost,
  onNodeContextMenu,
  customActions = [],
  customTabs = [],
  className = '',
}: NmapTopologyViewProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Layout & Simulation State
  const [layout, setLayout] = useState<TopologyLayoutType>(initialLayout);
  const [isPhysicsRunning, setIsPhysicsRunning] = useState<boolean>(initialLayout === 'force');

  // Pan & Zoom
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Dragging individual node
  const [draggedNodeId, setDraggedNodeId] = useState<string | null>(null);

  // Selected Host / Drawer
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);

  // Filtering
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedOs, setSelectedOs] = useState<string>('all');
  const [selectedSubnet, setSelectedSubnet] = useState<string>('all');
  const [quickPortFilter, setQuickPortFilter] = useState<number | null>(null);
  const [onlyOpenPorts, setOnlyOpenPorts] = useState<boolean>(false);
  const [onlyUpHosts, setOnlyUpHosts] = useState<boolean>(false);
  const [maxLatency, setMaxLatency] = useState<number>(1000);
  const [showFilterDrawer, setShowFilterDrawer] = useState<boolean>(false);

  // Detail Level Settings
  const [detailSettings, setDetailSettings] = useState<DetailLevelSettings>({
    showLabels: true,
    labelType: 'both',
    showOsIcons: true,
    showPortBadges: true,
    showLatency: true,
    showIntermediateHops: true,
    showUptime: false,
    showSubnetHulls: true,
    nodeSize: 'standard',
  });
  const [showSettingsDrawer, setShowSettingsDrawer] = useState<boolean>(false);
  const [showExportMenu, setShowExportMenu] = useState<boolean>(false);

  const width = 1400;
  const height = 900;

  // Generate initial graph
  const graph: TopologyGraph = useMemo(() => {
    return generateTopology(scan, { layout, width, height });
  }, [scan]);

  // Compute active filters
  const filterOptions: FilterOptions = useMemo(() => {
    return {
      searchQuery,
      osFamily: selectedOs,
      subnetFilter: selectedSubnet,
      portFilter: quickPortFilter ? [quickPortFilter] : undefined,
      onlyOpenPorts,
      onlyUpHosts,
      maxLatencyMs: maxLatency < 1000 ? maxLatency : undefined,
    };
  }, [searchQuery, selectedOs, selectedSubnet, quickPortFilter, onlyOpenPorts, onlyUpHosts, maxLatency]);

  const { visibleNodeIds, visibleLinkIds } = useMemo(() => {
    return filterTopology(graph, filterOptions);
  }, [graph, filterOptions]);

  // Re-apply layout when layout type changes
  const handleLayoutChange = (newLayout: TopologyLayoutType) => {
    setLayout(newLayout);
    applyLayout(graph, newLayout, width, height);
    setIsPhysicsRunning(newLayout === 'force');
  };

  // Physics animation loop
  useEffect(() => {
    if (!isPhysicsRunning || layout !== 'force') return;

    let animFrame: number;
    const tick = () => {
      stepPhysicsSimulation(graph, width, height, 0.25);
      // Trigger re-render by updating dummy state or tick
      setTickCount((t) => t + 1);
      animFrame = requestAnimationFrame(tick);
    };

    animFrame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animFrame);
  }, [isPhysicsRunning, layout, graph]);

  const [, setTickCount] = useState(0);

  // Mouse pan & zoom handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsDraggingCanvas(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggedNodeId) {
      const node = graph.nodes.find((n) => n.id === draggedNodeId);
      if (node && containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        // Convert client mouse coordinates to SVG viewbox coordinates
        const scaleX = width / (rect.width * zoom);
        const scaleY = height / (rect.height * zoom);
        const mouseSvgX = (e.clientX - rect.left - pan.x) * scaleX;
        const mouseSvgY = (e.clientY - rect.top - pan.y) * scaleY;
        node.x = mouseSvgX;
        node.y = mouseSvgY;
        node.isPinned = true;
        setTickCount((t) => t + 1);
      }
      return;
    }

    if (!isDraggingCanvas) return;
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = () => {
    setIsDraggingCanvas(false);
    setDraggedNodeId(null);
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.12 : 0.88;
    setZoom((z) => Math.min(4, Math.max(0.3, z * zoomFactor)));
  };

  const handleResetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  // Context Menu State
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; node: TopologyNode } | null>(null);

  // Keyboard shortcut listener for selected node on canvas
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) return;
      if (!selectedNode || !selectedNode.hostRef) return;

      for (const action of customActions) {
        if (!action.shortcut) continue;
        const s = action.shortcut.toLowerCase();
        const matches =
          e.key.toLowerCase() === s ||
          (e.shiftKey && `shift+${e.key.toLowerCase()}` === s) ||
          (e.ctrlKey && `ctrl+${e.key.toLowerCase()}` === s);

        if (matches) {
          e.preventDefault();
          const host = selectedNode.hostRef;
          action.onClick(host, {
            node: selectedNode,
            updateHost: (updater) => {
              if (onUpdateHost) onUpdateHost(host.id, updater);
            },
            scan,
          });
          break;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedNode, customActions, onUpdateHost, scan]);

  // Node Selection
  const handleNodeClick = (node: TopologyNode, e: React.MouseEvent) => {
    e.stopPropagation();
    setContextMenu(null);
    setSelectedNode(node);
    if (onSelectHost && node.hostRef) {
      onSelectHost(node.hostRef);
    }
  };

  const handleNodeContextMenu = (node: TopologyNode, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setSelectedNode(node);
    if (onNodeContextMenu) {
      onNodeContextMenu(node, e);
    }
    const bounds = containerRef.current?.getBoundingClientRect();
    if (bounds) {
      setContextMenu({
        x: e.clientX - bounds.left,
        y: e.clientY - bounds.top,
        node,
      });
    }
  };

  // Export handlers
  const handleExportSvg = () => {
    if (svgRef.current) {
      exportSvgElement(svgRef.current, `nmap-topology-${Date.now()}.svg`);
      setShowExportMenu(false);
    }
  };

  const handleExportPng = async () => {
    if (svgRef.current) {
      await exportToPng(svgRef.current, `nmap-topology-${Date.now()}.png`);
      setShowExportMenu(false);
    }
  };

  const handleDownloadReport = () => {
    const reportHtml = generateHtmlReport(scan, graph);
    const blob = new Blob([reportHtml], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nmap-report-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
    setShowExportMenu(false);
  };

  // Extract unique OS list and Subnet list for filters
  const uniqueOsList = useMemo(() => {
    const set = new Set<string>();
    scan.hosts.forEach((h) => {
      if (h.osFamily) set.add(h.osFamily);
    });
    return Array.from(set);
  }, [scan]);

  return (
    <div className={`relative rounded-2xl bg-zinc-950 border border-zinc-800/80 overflow-hidden select-none flex flex-col ${className}`}>
      {/* Top Toolbar */}
      <div className="p-3.5 bg-zinc-900/90 backdrop-blur-xl border-b border-zinc-800 flex flex-wrap items-center justify-between gap-3 z-20">
        {/* Search & Quick Filters */}
        <div className="flex items-center gap-2.5 flex-1 min-w-[280px] max-w-lg">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-2.5 text-zinc-400" />
            <input
              type="text"
              placeholder="Search IP, hostname, OS, port, or service..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-zinc-950 border border-zinc-800 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-sky-500 font-sans"
            />
          </div>

          {/* Quick Port Badges */}
          <div className="hidden lg:flex items-center gap-1">
            {[22, 80, 443, 3389, 445, 23].map((port) => (
              <button
                key={port}
                onClick={() => setQuickPortFilter((curr) => (curr === port ? null : port))}
                className={`px-2 py-1 rounded text-[11px] font-mono transition-colors ${
                  quickPortFilter === port
                    ? 'bg-sky-600 text-white font-bold shadow'
                    : 'bg-zinc-950 text-zinc-400 hover:text-zinc-200 border border-zinc-800'
                }`}
              >
                :{port}
              </button>
            ))}
          </div>
        </div>

        {/* Layout & Control Buttons */}
        <div className="flex items-center gap-2">
          {/* Layout Selector */}
          <div className="flex items-center bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs font-medium">
            <button
              onClick={() => handleLayoutChange('force')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                layout === 'force' ? 'bg-sky-600 text-white font-semibold shadow' : 'text-zinc-400 hover:text-white'
              }`}
              title="Force-Directed Dynamic Physics"
            >
              Force
            </button>
            <button
              onClick={() => handleLayoutChange('traceroute')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                layout === 'traceroute' ? 'bg-sky-600 text-white font-semibold shadow' : 'text-zinc-400 hover:text-white'
              }`}
              title="Traceroute Hop Hierarchy"
            >
              Route Tree
            </button>
            <button
              onClick={() => handleLayoutChange('radial')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                layout === 'radial' ? 'bg-sky-600 text-white font-semibold shadow' : 'text-zinc-400 hover:text-white'
              }`}
              title="Radial Concentric Rings"
            >
              Radial
            </button>
            <button
              onClick={() => handleLayoutChange('subnet')}
              className={`px-2.5 py-1 rounded-md transition-colors ${
                layout === 'subnet' ? 'bg-sky-600 text-white font-semibold shadow' : 'text-zinc-400 hover:text-white'
              }`}
              title="Subnet Grouped Grid"
            >
              Subnets
            </button>
          </div>

          {/* Quick 1-Click Toggle for Open Ports Only */}
          <button
            onClick={() => setOnlyOpenPorts((v) => !v)}
            className={`px-2.5 py-1.5 rounded-lg border text-xs font-semibold flex items-center gap-1.5 transition-all ${
              onlyOpenPorts
                ? 'bg-amber-500/20 border-amber-500 text-amber-300 shadow-sm'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700'
            }`}
            title={onlyOpenPorts ? 'Showing only hosts with open ports (Click to show all)' : 'Click to hide/exclude hosts with zero open ports'}
          >
            <Shield size={13} className={onlyOpenPorts ? 'text-amber-400' : 'text-zinc-500'} />
            <span className="hidden sm:inline">Open Ports Only</span>
            <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
              onlyOpenPorts ? 'bg-amber-400/30 text-amber-200' : 'bg-zinc-800 text-zinc-400'
            }`}>
              {graph.nodes.filter((n) => n.nodeType === 'host' && n.openPorts.length > 0).length}/{graph.nodes.filter((n) => n.nodeType === 'host').length}
            </span>
          </button>

          {/* Quick 1-Click Toggle for Ping Responsive (Up) */}
          <button
            onClick={() => setOnlyUpHosts((v) => !v)}
            className={`px-2.5 py-1.5 rounded-lg border text-xs font-semibold flex items-center gap-1.5 transition-all ${
              onlyUpHosts
                ? 'bg-emerald-500/20 border-emerald-500 text-emerald-300 shadow-sm'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700'
            }`}
            title={onlyUpHosts ? 'Showing only hosts that responded to ping/discovery (Click to show all)' : 'Click to filter and show only ping-responsive hosts'}
          >
            <Radio size={13} className={onlyUpHosts ? 'text-emerald-400 animate-pulse' : 'text-zinc-500'} />
            <span className="hidden sm:inline">Ping Up</span>
            <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
              onlyUpHosts ? 'bg-emerald-400/30 text-emerald-200' : 'bg-zinc-800 text-zinc-400'
            }`}>
              {graph.nodes.filter((n) => n.nodeType === 'host' && n.status === 'up').length}/{graph.nodes.filter((n) => n.nodeType === 'host').length}
            </span>
          </button>

          {/* Physics Play/Pause (only for force layout) */}
          {layout === 'force' && (
            <button
              onClick={() => setIsPhysicsRunning((r) => !r)}
              className="p-1.5 rounded-lg bg-zinc-950 border border-zinc-800 text-zinc-300 hover:text-white transition-colors"
              title={isPhysicsRunning ? 'Pause Physics' : 'Resume Physics'}
            >
              {isPhysicsRunning ? <Pause size={15} className="text-amber-400" /> : <Play size={15} className="text-emerald-400" />}
            </button>
          )}

          {/* Filter Drawer Toggle */}
          <button
            onClick={() => setShowFilterDrawer((v) => !v)}
            className={`p-1.5 rounded-lg border transition-colors ${
              showFilterDrawer || (selectedOs !== 'all' || selectedSubnet !== 'all' || onlyOpenPorts || onlyUpHosts)
                ? 'bg-sky-950/60 border-sky-500 text-sky-300'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-white'
            }`}
            title="Filter Settings"
          >
            <Filter size={15} />
          </button>

          {/* Detail Settings Toggle */}
          <button
            onClick={() => setShowSettingsDrawer((v) => !v)}
            className="p-1.5 rounded-lg bg-zinc-950 border border-zinc-800 text-zinc-400 hover:text-white transition-colors"
            title="Display Options"
          >
            <SlidersHorizontal size={15} />
          </button>

          {/* Export Menu */}
          <div className="relative">
            <button
              onClick={() => setShowExportMenu((v) => !v)}
              className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow flex items-center gap-1.5 transition-colors"
            >
              <Download size={14} />
              <span>Export</span>
            </button>

            {showExportMenu && (
              <div className="absolute right-0 mt-2 w-48 rounded-xl bg-zinc-900 border border-zinc-800 shadow-2xl p-1.5 z-50 text-xs text-zinc-200 space-y-0.5">
                <button
                  onClick={handleExportSvg}
                  className="w-full text-left px-3 py-2 rounded-lg hover:bg-zinc-800 flex items-center gap-2"
                >
                  <FileCode size={14} className="text-sky-400" />
                  <span>Export as SVG (Vector)</span>
                </button>
                <button
                  onClick={handleExportPng}
                  className="w-full text-left px-3 py-2 rounded-lg hover:bg-zinc-800 flex items-center gap-2"
                >
                  <FileCode size={14} className="text-emerald-400" />
                  <span>Export as PNG (High-Res)</span>
                </button>
                <button
                  onClick={handleDownloadReport}
                  className="w-full text-left px-3 py-2 rounded-lg hover:bg-zinc-800 flex items-center gap-2"
                >
                  <FileText size={14} className="text-amber-400" />
                  <span>Standalone HTML Report</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Filter Options Bar (collapsible) */}
      {showFilterDrawer && (
        <div className="p-3.5 bg-zinc-900/95 border-b border-zinc-800 flex flex-wrap items-center gap-4 text-xs z-10">
          <div className="flex items-center gap-2">
            <span className="text-zinc-400 font-semibold">OS Family:</span>
            <select
              value={selectedOs}
              onChange={(e) => setSelectedOs(e.target.value)}
              className="px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-100 focus:outline-none"
            >
              <option value="all">All Operating Systems</option>
              {uniqueOsList.map((os) => (
                <option key={os} value={os}>{os}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-zinc-400 font-semibold">Subnet:</span>
            <select
              value={selectedSubnet}
              onChange={(e) => setSelectedSubnet(e.target.value)}
              className="px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-100 focus:outline-none"
            >
              <option value="all">All Subnets</option>
              {graph.subnets.map((sub) => (
                <option key={sub} value={sub}>{sub}</option>
              ))}
            </select>
          </div>

          <label className="flex items-center gap-1.5 text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={onlyOpenPorts}
              onChange={(e) => setOnlyOpenPorts(e.target.checked)}
              className="rounded bg-zinc-950 border-zinc-800 text-sky-500 focus:ring-0"
            />
            <span>Only with Open Ports</span>
          </label>

          <label className="flex items-center gap-1.5 text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={onlyUpHosts}
              onChange={(e) => setOnlyUpHosts(e.target.checked)}
              className="rounded bg-zinc-950 border-zinc-800 text-sky-500 focus:ring-0"
            />
            <span>Only Responsive (Up)</span>
          </label>

          <button
            onClick={() => {
              setSearchQuery('');
              setSelectedOs('all');
              setSelectedSubnet('all');
              setQuickPortFilter(null);
              setOnlyOpenPorts(false);
              setOnlyUpHosts(false);
            }}
            className="text-sky-400 hover:underline ml-auto font-medium"
          >
            Reset Filters
          </button>
        </div>
      )}

      {/* Detail Level Settings Drawer (collapsible) */}
      {showSettingsDrawer && (
        <div className="p-3.5 bg-zinc-900/95 border-b border-zinc-800 flex flex-wrap items-center gap-5 text-xs z-10">
          <label className="flex items-center gap-1.5 text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={detailSettings.showLabels}
              onChange={(e) => setDetailSettings((s) => ({ ...s, showLabels: e.target.checked }))}
            />
            <span>Show Host Labels</span>
          </label>

          <label className="flex items-center gap-1.5 text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={detailSettings.showOsIcons}
              onChange={(e) => setDetailSettings((s) => ({ ...s, showOsIcons: e.target.checked }))}
            />
            <span>Show OS Icons</span>
          </label>

          <label className="flex items-center gap-1.5 text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={detailSettings.showPortBadges}
              onChange={(e) => setDetailSettings((s) => ({ ...s, showPortBadges: e.target.checked }))}
            />
            <span>Show Open Port Badges</span>
          </label>

          <label className="flex items-center gap-1.5 text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={detailSettings.showLatency}
              onChange={(e) => setDetailSettings((s) => ({ ...s, showLatency: e.target.checked }))}
            />
            <span>Show Latency on Links</span>
          </label>

          <label className="flex items-center gap-1.5 text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={detailSettings.showUptime}
              onChange={(e) => setDetailSettings((s) => ({ ...s, showUptime: e.target.checked }))}
            />
            <span>Show Uptime</span>
          </label>
        </div>
      )}

      {/* Graph Area */}
      <div
        ref={containerRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        className="w-full h-[640px] bg-[#070b14] relative overflow-hidden cursor-grab active:cursor-grabbing"
      >
        {/* Floating Zoom & Controls Box in Canvas */}
        <div className="absolute bottom-4 right-4 z-10 flex items-center gap-1 bg-zinc-900/90 backdrop-blur-md p-1.5 rounded-xl border border-zinc-800 shadow-2xl">
          <button
            onClick={() => setZoom((z) => Math.min(4, z * 1.25))}
            className="p-1.5 rounded-lg text-zinc-300 hover:text-white hover:bg-zinc-800"
            title="Zoom In"
          >
            <ZoomIn size={16} />
          </button>
          <button
            onClick={() => setZoom((z) => Math.max(0.3, z * 0.8))}
            className="p-1.5 rounded-lg text-zinc-300 hover:text-white hover:bg-zinc-800"
            title="Zoom Out"
          >
            <ZoomOut size={16} />
          </button>
          <button
            onClick={handleResetView}
            className="p-1.5 rounded-lg text-zinc-300 hover:text-white hover:bg-zinc-800"
            title="Reset View"
          >
            <Maximize2 size={16} />
          </button>
        </div>

        {/* Live Nodes Count Badge */}
        <div className="absolute bottom-4 left-4 z-10 flex items-center gap-2 bg-zinc-900/80 backdrop-blur-md px-3 py-1.5 rounded-xl border border-zinc-800 text-[11px] font-mono text-zinc-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>{visibleNodeIds.size} / {graph.nodes.length} Nodes</span>
          <span className="text-zinc-600">·</span>
          <span>{visibleLinkIds.size} Links</span>
        </div>

        {/* Main SVG Visualization */}
        <svg
          ref={svgRef}
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-full"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: 'center center',
          }}
        >
          <defs>
            <radialGradient id="nodeGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Links / Network Edges */}
          <g id="links">
            {graph.links.map((link) => {
              const sId = typeof link.source === 'string' ? link.source : (link.source as TopologyNode).id;
              const tId = typeof link.target === 'string' ? link.target : (link.target as TopologyNode).id;

              const sourceNode = graph.nodes.find((n) => n.id === sId);
              const targetNode = graph.nodes.find((n) => n.id === tId);
              if (!sourceNode || !targetNode) return null;

              const isVisible = visibleLinkIds.has(link.id);
              const strokeColor = link.type === 'traceroute' ? '#38bdf8' : '#64748b';
              const isSelected = selectedNode && (selectedNode.id === sId || selectedNode.id === tId);

              return (
                <g key={link.id} opacity={isVisible ? (isSelected ? 1 : 0.6) : 0.1}>
                  <line
                    x1={sourceNode.x}
                    y1={sourceNode.y}
                    x2={targetNode.x}
                    y2={targetNode.y}
                    stroke={isSelected ? '#38bdf8' : strokeColor}
                    strokeWidth={isSelected ? 2.5 : 1.5}
                    strokeDasharray={link.type === 'subnet' ? '4,4' : undefined}
                  />

                  {/* Latency Label on Edge */}
                  {detailSettings.showLatency && link.label && isVisible && (
                    <g transform={`translate(${(sourceNode.x + targetNode.x) / 2}, ${(sourceNode.y + targetNode.y) / 2})`}>
                      <rect
                        x="-18"
                        y="-8"
                        width="36"
                        height="14"
                        rx="4"
                        fill="#090d16"
                        stroke="#334155"
                        strokeWidth="0.8"
                      />
                      <text
                        y="2.5"
                        fill="#94a3b8"
                        fontSize="9"
                        fontFamily="monospace"
                        textAnchor="middle"
                      >
                        {link.label}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </g>

          {/* Nodes */}
          <g id="nodes">
            {graph.nodes.map((node) => {
              const isVisible = visibleNodeIds.has(node.id);
              const isSelected = selectedNode?.id === node.id;
              const isScanner = node.nodeType === 'scanner';
              const IconComponent = getHostIcon(node.osFamily, node.deviceType, node.nodeType);

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  opacity={isVisible ? 1 : 0.15}
                  className="cursor-pointer group"
                  onClick={(e) => handleNodeClick(node, e)}
                  onContextMenu={(e) => handleNodeContextMenu(node, e)}
                  onMouseDown={(e) => {
                    e.stopPropagation();
                    setDraggedNodeId(node.id);
                  }}
                >
                  {/* Selection Ring */}
                  {isSelected && (
                    <circle
                      r={node.radius + 8}
                      fill="none"
                      stroke="#38bdf8"
                      strokeWidth="2"
                      strokeDasharray="4,4"
                      className="animate-spin-slow"
                    />
                  )}

                  {/* Quarantine / Incident Alert Halo */}
                  {(node.hostRef?.isQuarantined || node.isQuarantined) && (
                    <circle
                      r={node.radius + 11}
                      fill="none"
                      stroke="#f59e0b"
                      strokeWidth="2.5"
                      strokeDasharray="6,3"
                      className="animate-pulse"
                    />
                  )}

                  {/* Outer Status Ring */}
                  <circle
                    r={node.radius}
                    fill={node.color || '#3b82f6'}
                    stroke={
                      isScanner
                        ? '#a855f7'
                        : (node.hostRef?.isQuarantined || node.isQuarantined)
                        ? '#f59e0b'
                        : node.status === 'up'
                        ? '#22c55e'
                        : '#ef4444'
                    }
                    strokeWidth={isScanner ? 3 : 2.2}
                    className="group-hover:scale-110 transition-transform"
                  />

                  {/* Inner Icon / Badge */}
                  <foreignObject
                    x={-10}
                    y={-10}
                    width={20}
                    height={20}
                    className="pointer-events-none"
                  >
                    <div className="w-full h-full flex items-center justify-center text-white">
                      <IconComponent size={14} />
                    </div>
                  </foreignObject>

                  {/* Labels */}
                  {detailSettings.showLabels && (
                    <g transform={`translate(0, ${node.radius + 14})`}>
                      <text
                        fill="#f8fafc"
                        fontSize="11"
                        fontWeight="600"
                        fontFamily="sans-serif"
                        textAnchor="middle"
                        className="group-hover:fill-sky-300"
                      >
                        {node.label}
                      </text>
                      <text
                        y="12"
                        fill="#94a3b8"
                        fontSize="9"
                        fontFamily="monospace"
                        textAnchor="middle"
                      >
                        {node.ip}
                      </text>
                    </g>
                  )}

                  {/* Open Ports Badges Pill */}
                  {detailSettings.showPortBadges && node.openPorts.length > 0 && (
                    <g transform={`translate(0, -${node.radius + 8})`}>
                      <rect
                        x="-16"
                        y="-7"
                        width="32"
                        height="14"
                        rx="4"
                        fill="#065f46"
                        stroke="#34d399"
                        strokeWidth="0.8"
                      />
                      <text
                        y="3.5"
                        fill="#ffffff"
                        fontSize="9"
                        fontWeight="bold"
                        fontFamily="monospace"
                        textAnchor="middle"
                      >
                        {node.openPorts.length} {node.openPorts.length === 1 ? 'port' : 'ports'}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </g>
        </svg>

        {/* Node Right-Click Context Menu */}
        {contextMenu && (
          <div
            style={{ top: contextMenu.y, left: contextMenu.x }}
            className="absolute z-50 bg-zinc-950/95 backdrop-blur-xl border border-zinc-800 shadow-2xl rounded-xl p-1.5 min-w-[220px] text-xs font-sans animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-2.5 py-1.5 border-b border-zinc-800 text-[11px] font-mono text-zinc-400 flex items-center justify-between">
              <span className="font-bold text-white truncate max-w-[120px]">{contextMenu.node.label}</span>
              <span className="text-[10px] text-zinc-500">{contextMenu.node.ip}</span>
            </div>

            <div className="py-1 space-y-0.5">
              <button
                onClick={() => {
                  setSelectedNode(contextMenu.node);
                  if (onSelectHost && contextMenu.node.hostRef) onSelectHost(contextMenu.node.hostRef);
                  setContextMenu(null);
                }}
                className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-zinc-800 text-zinc-200 flex items-center gap-2 transition-colors"
              >
                <Info size={13} className="text-sky-400" />
                <span>Inspect Host Details</span>
              </button>

              {customActions.map((action) => {
                const host = contextMenu.node.hostRef;
                if (!host) return null;
                if (action.isVisible && !action.isVisible(host)) return null;
                const disabled = action.isDisabled && action.isDisabled(host);

                return (
                  <button
                    key={action.id}
                    disabled={disabled}
                    onClick={async () => {
                      setContextMenu(null);
                      const res = await action.onClick(host, {
                        node: contextMenu.node,
                        updateHost: (updater) => {
                          if (onUpdateHost) onUpdateHost(host.id, updater);
                        },
                        scan,
                      });
                      if (res && onUpdateHost) {
                        onUpdateHost(host.id, () => res);
                      }
                    }}
                    className={`w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-zinc-800 text-zinc-200 flex items-center justify-between transition-colors ${
                      disabled ? 'opacity-50 cursor-not-allowed' : ''
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      {action.icon || <Zap size={13} className="text-amber-400" />}
                      <span>{action.label}</span>
                    </div>
                    {action.shortcut && (
                      <kbd className="px-1 py-0.5 bg-black/40 font-mono text-[9px] rounded text-zinc-400 border border-zinc-800">
                        {action.shortcut.toUpperCase()}
                      </kbd>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Host Inspector Drawer (renders if not handled externally) */}
      {!onSelectHost && (
        <HostDetailDrawer
          node={selectedNode}
          onClose={() => setSelectedNode(null)}
          onUpdateHost={onUpdateHost}
          customActions={customActions}
          customTabs={customTabs}
          onUpdateComment={(hostId, comment) => {
            if (selectedNode && selectedNode.hostRef) {
              selectedNode.hostRef.comments = comment;
            }
          }}
          onUpdateTags={(hostId, tags) => {
            if (selectedNode && selectedNode.hostRef) {
              selectedNode.hostRef.tags = tags;
            }
          }}
        />
      )}
    </div>
  );
}
