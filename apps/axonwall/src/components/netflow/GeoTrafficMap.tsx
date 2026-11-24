'use client';

import React, { useMemo } from 'react';
import { Globe } from 'lucide-react';
import { formatBytes } from '@axonwall/lib/compile/netflow';
import type { NetFlowGeoArcSnapshot, NetFlowTopEntrySnapshot } from './types';

interface GeoTrafficMapProps {
  geoArcs?: NetFlowGeoArcSnapshot[];
  topCountries?: NetFlowTopEntrySnapshot[];
  onFilterFql: (clause: string) => void;
}

const WIDTH = 900;
const HEIGHT = 420;

function project(lat: number, lon: number): [number, number] {
  const x = ((lon + 180) / 360) * WIDTH;
  const y = ((90 - lat) / 180) * HEIGHT;
  return [Math.max(12, Math.min(WIDTH - 12, x)), Math.max(12, Math.min(HEIGHT - 12, y))];
}

// Simplified equirectangular continent paths for offline rendering with zero external requests
const CONTINENT_PATHS: Array<{ name: string; points: Array<[number, number]> }> = [
  {
    name: 'North America',
    points: [
      [70, -165], [71, -135], [68, -95], [60, -64], [46, -53], [41, -70], [25, -80],
      [18, -88], [8, -78], [16, -98], [32, -117], [49, -125], [60, -148],
    ],
  },
  {
    name: 'South America',
    points: [
      [11, -74], [10, -61], [0, -50], [-8, -35], [-23, -42], [-38, -58], [-55, -67],
      [-48, -75], [-18, -71], [-4, -81],
    ],
  },
  {
    name: 'Europe',
    points: [
      [70, 28], [60, 30], [54, 19], [46, 30], [41, 29], [37, 22], [36, -6], [43, -9],
      [48, -5], [58, -5], [60, 5], [71, 25],
    ],
  },
  {
    name: 'Africa',
    points: [
      [36, -6], [37, 10], [31, 32], [12, 44], [11, 51], [-12, 41], [-34, 26], [-34, 18],
      [-15, 12], [5, 8], [5, -10], [15, -17],
    ],
  },
  {
    name: 'Asia',
    points: [
      [72, 60], [74, 110], [68, 175], [55, 162], [43, 132], [35, 129], [22, 114], [10, 106],
      [1, 104], [16, 97], [8, 77], [24, 67], [25, 56], [13, 44], [36, 36], [42, 29], [52, 48],
    ],
  },
  {
    name: 'Australia',
    points: [
      [-12, 130], [-14, 145], [-28, 154], [-38, 147], [-34, 115], [-21, 114],
    ],
  },
];

export function GeoTrafficMap({ geoArcs = [], topCountries = [], onFilterFql }: GeoTrafficMapProps) {
  const polygons = useMemo(
    () =>
      CONTINENT_PATHS.map((c) => ({
        name: c.name,
        pts: c.points.map(([lat, lon]) => project(lat, lon).join(',')).join(' '),
      })),
    [],
  );

  const maxBytes = useMemo(
    () => Math.max(1, ...geoArcs.map((a) => a.bytes)),
    [geoArcs],
  );

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <div>
            <h3 className="text-sm font-semibold text-white">World Geo-Traffic Arcs &amp; Country Attribution</h3>
            <p className="text-xs text-slate-400">
              Plotted offline from local MMDB GeoIP coordinates ({geoArcs.length} active country pairs; rose = Threat IOC match)
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {topCountries.slice(0, 6).map((c) => (
            <button
              key={c.key}
              type="button"
              onClick={() => onFilterFql(`country=${c.key}`)}
              className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 text-[11px] font-mono text-cyan-300"
            >
              {c.key}: {formatBytes(c.bytes)}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-slate-950 rounded-lg overflow-hidden">
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full h-auto max-h-[340px] block">
          {/* Lat/Lon Graticule */}
          {[-60, -30, 0, 30, 60].map((lat) => {
            const [, y] = project(lat, 0);
            return <line key={lat} x1={0} y1={y} x2={WIDTH} y2={y} stroke="#0f172a" strokeWidth={1} />;
          })}
          {[-120, -60, 0, 60, 120].map((lon) => {
            const [x] = project(0, lon);
            return <line key={lon} x1={x} y1={0} x2={x} y2={HEIGHT} stroke="#0f172a" strokeWidth={1} />;
          })}

          {/* Continents */}
          {polygons.map((poly) => (
            <polygon
              key={poly.name}
              points={poly.pts}
              fill="#1e293b"
              stroke="#334155"
              strokeWidth={1}
            />
          ))}

          {/* Geo Arcs */}
          {geoArcs.map((arc, idx) => {
            const [x1, y1] = project(arc.srcLat, arc.srcLon);
            const [x2, y2] = project(arc.dstLat, arc.dstLon);
            const mx = (x1 + x2) / 2;
            const dist = Math.hypot(x2 - x1, y2 - y1);
            const my = Math.max(10, Math.min(y1, y2) - Math.min(90, dist * 0.28));
            const weight = Math.max(1.2, Math.min(5, 1.2 + (Math.log10(Math.max(1, arc.bytes)) / Math.log10(Math.max(10, maxBytes))) * 3.5));
            const color = arc.threat ? '#fb7185' : '#38bdf8';
            return (
              <g
                key={`${arc.srcCountry}-${arc.dstCountry}-${idx}`}
                className="cursor-pointer"
                onClick={() => onFilterFql(`country=${arc.dstCountry === 'LAN' ? arc.srcCountry : arc.dstCountry}`)}
              >
                <title>{`${arc.srcCountry}${arc.srcCity ? ` (${arc.srcCity})` : ''} → ${arc.dstCountry}${arc.dstCity ? ` (${arc.dstCity})` : ''}: ${formatBytes(arc.bytes)} (${arc.flows} flows)`}</title>
                <path
                  d={`M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`}
                  fill="none"
                  stroke={color}
                  strokeOpacity={0.7}
                  strokeWidth={weight}
                />
                <circle cx={x1} cy={y1} r={3.5} fill="#10b981" />
                <circle cx={x2} cy={y2} r={4} fill={color} />
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
