import React, { useState, useRef, useEffect } from 'react';
import type { NmapHost, NmapRun, TopologyNode } from '../types/nmap';
import { geocodeIp } from '../geoip/geocoder';
import { getHostIcon } from '../icons/index';
import {
  Globe,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Navigation,
  MapPin,
  Activity,
  Layers,
  Server,
  Info,
  Shield,
  Radio,
} from 'lucide-react';

export interface NmapGeoMapProps {
  scan: NmapRun;
  onSelectHost?: (host: NmapHost) => void;
  className?: string;
}

// Vector Landmass Geo Path Approximations (Equirectangular projection: x = (lng + 180) * (w / 360), y = (90 - lat) * (h / 180))
const CONTINENTS_POLYGONS = [
  // North America
  [[-165, 65], [-140, 70], [-100, 75], [-60, 80], [-55, 50], [-70, 42], [-80, 25], [-90, 15], [-105, 20], [-120, 35], [-130, 50], [-165, 65]],
  // South America
  [[-80, 10], [-50, -5], [-35, -5], [-40, -22], [-55, -55], [-75, -50], [-80, -15], [-80, 10]],
  // Europe
  [[-10, 36], [0, 44], [10, 45], [25, 38], [35, 40], [30, 60], [20, 70], [5, 60], [-5, 50], [-10, 36]],
  // Africa
  [[-18, 30], [10, 37], [32, 30], [50, 12], [40, -15], [30, -34], [18, -34], [10, 5], [-15, 12], [-18, 30]],
  // Asia
  [[35, 40], [60, 40], [80, 70], [140, 70], [170, 65], [140, 35], [120, 25], [100, 10], [80, 10], [60, 25], [45, 30], [35, 40]],
  // Australia
  [[115, -20], [130, -12], [145, -15], [152, -28], [140, -38], [115, -35], [115, -20]],
  // Great Britain & Ireland
  [[-10, 52], [-5, 58], [2, 52], [-5, 50], [-10, 52]],
  // Japan
  [[130, 32], [138, 36], [142, 44], [140, 38], [130, 32]],
];

export function NmapGeoMap({ scan, onSelectHost, className = '' }: NmapGeoMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [startPan, setStartPan] = useState({ x: 0, y: 0 });
  const [hoveredHost, setHoveredHost] = useState<NmapHost | null>(null);
  const [showFlightArcs, setShowFlightArcs] = useState(true);
  const [onlyOpenPorts, setOnlyOpenPorts] = useState(false);
  const [onlyUpHosts, setOnlyUpHosts] = useState(false);

  const baseWidth = 1000;
  const baseHeight = 500;

  // Transform lat/lng to SVG coordinates
  const latLngToCoords = (lat: number, lng: number) => {
    const x = ((lng + 180) / 360) * baseWidth;
    const y = ((90 - lat) / 180) * baseHeight;
    return { x, y };
  };

  // Scanner Origin (Defaults to SF / Local Datacenter)
  const scannerGeo = { lat: 37.7749, lng: -122.4194 };
  const scannerCoords = latLngToCoords(scannerGeo.lat, scannerGeo.lng);

  // Group hosts by unique coordinates to handle clusters
  const visibleHosts = scan.hosts.filter((h) => {
    if (onlyOpenPorts && !h.ports.some((p) => p.state === 'open')) return false;
    if (onlyUpHosts && h.status.state !== 'up') return false;
    return true;
  });

  const geoClusters = new Map<string, { lat: number; lng: number; hosts: NmapHost[] }>();
  for (const host of visibleHosts) {
    const geo = host.geolocation || geocodeIp(host.ipv4 || host.id);
    const key = `${geo.latitude.toFixed(2)},${geo.longitude.toFixed(2)}`;
    if (!geoClusters.has(key)) {
      geoClusters.set(key, { lat: geo.latitude, lng: geo.longitude, hosts: [] });
    }
    geoClusters.get(key)!.hosts.push(host);
  }

  // Pan event handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsPanning(true);
    setStartPan({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isPanning) return;
    setPan({ x: e.clientX - startPan.x, y: e.clientY - startPan.y });
  };

  const handleMouseUp = () => setIsPanning(false);

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.15 : 0.85;
    setZoom((prev) => Math.min(6, Math.max(0.7, prev * zoomFactor)));
  };

  const handleReset = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  return (
    <div className={`relative rounded-2xl bg-zinc-950 border border-zinc-800/80 overflow-hidden select-none ${className}`}>
      {/* Top Map Header & Controls */}
      <div className="absolute top-4 left-4 right-4 z-10 flex items-center justify-between pointer-events-none">
        <div className="pointer-events-auto flex items-center gap-3 bg-zinc-900/90 backdrop-blur-md px-4 py-2 rounded-xl border border-zinc-800 shadow-xl">
          <Globe size={18} className="text-sky-400 animate-spin-slow" />
          <div>
            <h4 className="text-xs font-bold text-white uppercase tracking-wider">Geographic Threat Map</h4>
            <p className="text-[11px] text-zinc-400 font-mono">
              {geoClusters.size} Locations · {scan.hosts.length} Geocoded Targets
            </p>
          </div>
        </div>

        <div className="pointer-events-auto flex items-center gap-1.5 bg-zinc-900/90 backdrop-blur-md p-1.5 rounded-xl border border-zinc-800 shadow-xl">
          <button
            onClick={() => setZoom((z) => Math.min(6, z * 1.25))}
            className="p-1.5 rounded-lg text-zinc-300 hover:text-white hover:bg-zinc-800 transition-colors"
            title="Zoom In"
          >
            <ZoomIn size={16} />
          </button>
          <button
            onClick={() => setZoom((z) => Math.max(0.7, z * 0.8))}
            className="p-1.5 rounded-lg text-zinc-300 hover:text-white hover:bg-zinc-800 transition-colors"
            title="Zoom Out"
          >
            <ZoomOut size={16} />
          </button>
          <button
            onClick={handleReset}
            className="p-1.5 rounded-lg text-zinc-300 hover:text-white hover:bg-zinc-800 transition-colors"
            title="Reset Map View"
          >
            <Maximize2 size={16} />
          </button>
          <div className="w-px h-4 bg-zinc-800 mx-1" />
          <button
            onClick={() => setShowFlightArcs((v) => !v)}
            className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors ${
              showFlightArcs
                ? 'bg-sky-600/30 text-sky-300 border border-sky-500/40'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Flight Arcs
          </button>
          <button
            onClick={() => setOnlyOpenPorts((v) => !v)}
            className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              onlyOpenPorts
                ? 'bg-amber-600/30 text-amber-300 border border-amber-500/40'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
            title="Filter out hosts with zero open ports"
          >
            <Shield size={12} className={onlyOpenPorts ? 'text-amber-300' : 'text-zinc-400'} />
            <span>Open Ports ({scan.hosts.filter((h) => h.ports.some((p) => p.state === 'open')).length}/{scan.hosts.length})</span>
          </button>
          <button
            onClick={() => setOnlyUpHosts((v) => !v)}
            className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              onlyUpHosts
                ? 'bg-emerald-600/30 text-emerald-300 border border-emerald-500/40'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
            title="Filter to hosts that responded to ping (state=up)"
          >
            <Radio size={12} className={onlyUpHosts ? 'text-emerald-300 animate-pulse' : 'text-zinc-400'} />
            <span>Ping Up ({scan.hosts.filter((h) => h.status.state === 'up').length}/{scan.hosts.length})</span>
          </button>
        </div>
      </div>

      {/* Interactive Map SVG Canvas */}
      <div
        ref={containerRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        className="w-full h-[540px] cursor-grab active:cursor-grabbing bg-[#070b14] relative overflow-hidden"
      >
        <svg
          viewBox={`0 0 ${baseWidth} ${baseHeight}`}
          className="w-full h-full"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: 'center center',
            transition: isPanning ? 'none' : 'transform 0.15s ease-out',
          }}
        >
          <defs>
            {/* Graticule Grid Pattern */}
            <pattern id="graticule" width="50" height="50" patternUnits="userSpaceOnUse">
              <path d="M 50 0 L 0 0 0 50" fill="none" stroke="#1e293b" strokeWidth="0.5" strokeOpacity="0.4" />
            </pattern>
            {/* Scanner Pulse Animation */}
            <radialGradient id="scannerGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.8" />
              <stop offset="100%" stop-color="#0284c7" stop-opacity="0" />
            </radialGradient>
            {/* Arc Gradient */}
            <linearGradient id="arcGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#6366f1" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#38bdf8" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.8" />
            </linearGradient>
          </defs>

          {/* Background Grid */}
          <rect width={baseWidth} height={baseHeight} fill="#060913" />
          <rect width={baseWidth} height={baseHeight} fill="url(#graticule)" />

          {/* World Continents Outlines */}
          <g id="continents" opacity="0.85">
            {CONTINENTS_POLYGONS.map((polygon, pIdx) => {
              const d = polygon
                .map(([lng, lat], idx) => {
                  const pt = latLngToCoords(lat, lng);
                  return `${idx === 0 ? 'M' : 'L'} ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`;
                })
                .join(' ') + ' Z';
              return (
                <path
                  key={pIdx}
                  d={d}
                  fill="#0f172a"
                  stroke="#334155"
                  strokeWidth="0.8"
                  className="transition-colors hover:fill-[#1e293b]"
                />
              );
            })}
          </g>

          {/* Traceroute / Flight Arcs */}
          {showFlightArcs && (
            <g id="flight-arcs">
              {Array.from(geoClusters.values()).map((cluster, cIdx) => {
                const targetCoords = latLngToCoords(cluster.lat, cluster.lng);
                // Calculate quadratic curve control point
                const midX = (scannerCoords.x + targetCoords.x) / 2;
                const midY = (scannerCoords.y + targetCoords.y) / 2 - Math.min(80, Math.abs(scannerCoords.x - targetCoords.x) * 0.25);
                const pathD = `M ${scannerCoords.x} ${scannerCoords.y} Q ${midX} ${midY} ${targetCoords.x} ${targetCoords.y}`;

                return (
                  <g key={cIdx}>
                    <path
                      d={pathD}
                      fill="none"
                      stroke="url(#arcGrad)"
                      strokeWidth="1.2"
                      strokeDasharray="4,4"
                      opacity="0.6"
                    />
                    {/* Animated packet beacon */}
                    <circle r="3" fill="#38bdf8" opacity="0.9">
                      <animateMotion path={pathD} dur={`${2 + (cIdx % 3)}s`} repeatCount="indefinite" />
                    </circle>
                  </g>
                );
              })}
            </g>
          )}

          {/* Scanner Origin Pin */}
          <g transform={`translate(${scannerCoords.x}, ${scannerCoords.y})`}>
            <circle r="18" fill="url(#scannerGlow)" opacity="0.4" />
            <circle r="7" fill="#6366f1" stroke="#a5b4fc" strokeWidth="2" />
            <circle r="2.5" fill="#ffffff" />
            <text y="-12" fill="#a5b4fc" fontSize="9" fontWeight="bold" fontFamily="sans-serif" textAnchor="middle">
              Scanner Origin
            </text>
          </g>

          {/* Host Geo Clusters */}
          <g id="geo-clusters">
            {Array.from(geoClusters.entries()).map(([key, cluster]) => {
              const coords = latLngToCoords(cluster.lat, cluster.lng);
              const count = cluster.hosts.length;
              const primaryHost = cluster.hosts[0];
              const isSingle = count === 1;

              return (
                <g
                  key={key}
                  transform={`translate(${coords.x}, ${coords.y})`}
                  className="cursor-pointer group"
                  onClick={() => onSelectHost && onSelectHost(primaryHost)}
                  onMouseEnter={() => setHoveredHost(primaryHost)}
                  onMouseLeave={() => setHoveredHost(null)}
                >
                  {/* Ping Ring Animation */}
                  <circle r="12" fill="none" stroke="#38bdf8" strokeWidth="1" opacity="0.5">
                    <animate attributeName="r" values="8;20" dur="2.5s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.8;0" dur="2.5s" repeatCount="indefinite" />
                  </circle>

                  {/* Marker Circle */}
                  <circle
                    r={isSingle ? 7 : 10}
                    fill={isSingle ? '#0284c7' : '#0d9488'}
                    stroke="#f8fafc"
                    strokeWidth="1.5"
                    className="group-hover:scale-125 transition-transform"
                  />

                  {/* Cluster Count Text */}
                  {!isSingle && (
                    <text
                      y="3.5"
                      fill="#ffffff"
                      fontSize="9"
                      fontWeight="bold"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {count}
                    </text>
                  )}

                  {/* Location Label */}
                  <text
                    y="18"
                    fill="#e2e8f0"
                    fontSize="9"
                    fontWeight="500"
                    fontFamily="sans-serif"
                    textAnchor="middle"
                    className="opacity-80 group-hover:opacity-100 group-hover:fill-sky-300 font-semibold"
                  >
                    {primaryHost.geolocation?.city || primaryHost.ipv4 || primaryHost.id}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* Floating Hover Info Popup */}
      {hoveredHost && (
        <div className="absolute bottom-4 left-4 z-20 p-4 rounded-xl bg-zinc-900/95 backdrop-blur-xl border border-zinc-800 shadow-2xl text-xs space-y-1.5 pointer-events-none max-w-sm">
          <div className="flex items-center justify-between gap-3">
            <span className="font-mono font-bold text-sky-400 text-sm">{hoveredHost.ipv4 || hoveredHost.id}</span>
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 font-semibold uppercase text-[10px] border border-emerald-800">
              {hoveredHost.status.state}
            </span>
          </div>
          {hoveredHost.primaryHostname && (
            <p className="text-white font-medium">{hoveredHost.primaryHostname}</p>
          )}
          <div className="text-zinc-400 space-y-0.5 font-mono text-[11px] pt-1 border-t border-zinc-800">
            <div>
              Location: <span className="text-zinc-200">{hoveredHost.geolocation?.city}, {hoveredHost.geolocation?.country}</span>
            </div>
            {hoveredHost.geolocation?.org && (
              <div>Org: <span className="text-zinc-200">{hoveredHost.geolocation.org}</span></div>
            )}
            <div>
              Open Ports: <span className="text-emerald-400 font-bold">{hoveredHost.ports.filter((p) => p.state === 'open').length}</span>
            </div>
            {hoveredHost.latencyMs !== undefined && (
              <div>Latency: <span className="text-amber-400">{hoveredHost.latencyMs} ms</span></div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
