import React, { useMemo } from 'react';

interface MeshGraphProps {
  nodes: { id: string; label: string; isDegraded?: boolean }[];
}

export function MeshGraph({ nodes }: MeshGraphProps) {
  const width = 400;
  const height = 300;
  const radius = 100;
  const cx = width / 2;
  const cy = height / 2;

  const nodePositions = useMemo(() => {
    return nodes.map((node, i) => {
      const angle = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
      return {
        ...node,
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      };
    });
  }, [nodes, cx, cy, radius]);

  return (
    <div className="w-full flex justify-center items-center p-4 bg-slate-900/50 rounded-xl border border-slate-800">
      <svg width={width} height={height} className="overflow-visible">
        {/* Draw edges (Full Mesh) */}
        {nodePositions.map((n1, i) =>
          nodePositions.slice(i + 1).map((n2, j) => (
            <line
              key={`${n1.id}-${n2.id}`}
              x1={n1.x}
              y1={n1.y}
              x2={n2.x}
              y2={n2.y}
              stroke="rgba(16, 185, 129, 0.3)" // Emerald 500 with opacity
              strokeWidth={2}
              strokeDasharray="4 4"
              className="animate-pulse"
            />
          ))
        )}

        {/* Draw nodes */}
        {nodePositions.map((n) => (
          <g key={n.id} transform={`translate(${n.x}, ${n.y})`}>
            <circle
              r={18}
              fill="#0f172a" // slate-950
              stroke={n.isDegraded ? "#f59e0b" : "#10b981"} // amber-500 or emerald-500
              strokeWidth={3}
            />
            <text
              y={32}
              textAnchor="middle"
              fill="#cbd5e1" // slate-300
              fontSize={12}
              fontWeight={500}
            >
              {n.label}
            </text>
            {/* Draw a small icon or indicator inside */}
            <circle
              r={6}
              fill={n.isDegraded ? "#f59e0b" : "#10b981"}
              className={n.isDegraded ? "" : "animate-pulse"}
            />
          </g>
        ))}
      </svg>
    </div>
  );
}
