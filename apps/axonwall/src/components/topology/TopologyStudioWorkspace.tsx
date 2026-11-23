'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  applyNodeChanges,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Connection,
  type NodeChange,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  AlertTriangle,
  Check,
  FileSpreadsheet,
  GitCommit,
  Layers,
  LayoutGrid,
  Loader2,
  Pause,
  Play,
  Plus,
  Radio,
  Redo2,
  RefreshCw,
  Route,
  Save,
  Search,
  Undo2,
} from 'lucide-react';
import {
  analyzeTopologyDiagnostics,
  evaluateFabricHealth,
  type TopologyDiagnostic,
} from '@axonwall/lib/compile/topology';
import {
  TopologyConfigSchema,
  type DesiredState,
  type TopologyCableEdge,
  type TopologyCanvasNode,
  type TopologyLayer,
} from '@axonwall/lib/schemas';
import { getCurrentDesiredState } from '@/server/agent';
import { useDesiredStateApply } from '@/lib/use-desired-state-apply';
import { autoLayoutTopologyNodes } from './autoLayout';
import { CableCutSheetDrawer } from './drawers/CableCutSheetDrawer';
import { CommandPaletteModal } from './drawers/CommandPaletteModal';
import { DiagnosticsDrawer } from './drawers/DiagnosticsDrawer';
import { FabricSettingsModal } from './drawers/FabricSettingsModal';
import { InspectorDrawer } from './drawers/InspectorDrawer';
import { PathTracerDrawer } from './drawers/PathTracerDrawer';
import { ScenarioManagerModal } from './drawers/ScenarioManagerModal';
import { StagedDiffModal } from './drawers/StagedDiffModal';
import { TriadSyncModal } from './drawers/TriadSyncModal';
import { TOPOLOGY_EDGE_TYPES } from './edges/FabricEdge';
import { buildProbeSnapshotForEval, hydrateFabricGraph } from './hydrateFabric';
import { TOPOLOGY_NODE_TYPES } from './nodes/TopologyNodes';
import {
  NODE_KIND_CATALOG,
  type StagedK3sEdit,
  type StagedPeerEdit,
  type TopologyFilterLayer,
  type TopologyFlowEdge,
  type TopologyFlowNode,
} from './types';
import { useFabricTelemetry } from './useFabricTelemetry';
import { useGraphHistory } from './useGraphHistory';

const LAYER_FILTERS: Array<{ id: TopologyFilterLayer; label: string }> = [
  { id: 'all', label: 'All Layers' },
  { id: 'physical', label: 'Physical' },
  { id: 'l2-l3', label: 'L2 / L3' },
  { id: 'vpn', label: 'VPN' },
  { id: 'k3s', label: 'K3s / Ingress' },
  { id: 'virt', label: 'KVM / LXC' },
];

type RightPanelMode = 'none' | 'inspector' | 'diagnostics' | 'cutsheet' | 'tracer';

function upsertById<T extends { id: string }>(items: T[], next: T): T[] {
  const idx = items.findIndex((i) => i.id === next.id);
  if (idx === -1) return [...items, next];
  const copy = items.slice();
  copy[idx] = next;
  return copy;
}

function TopologyStudioCanvas() {
  const { fitView, setCenter } = useReactFlow();
  const { applyState } = useDesiredStateApply();

  const [liveState, setLiveState] = useState<DesiredState | null>(null);
  const [draftState, setDraftState] = useState<DesiredState | null>(null);
  const [loadingState, setLoadingState] = useState(true);
  const [savingLayout, setSavingLayout] = useState(false);
  const [banner, setBanner] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const [activeScenarioId, setActiveScenarioId] = useState<string | undefined>(undefined);
  const [layerFilter, setLayerFilter] = useState<TopologyFilterLayer>('all');
  const [showAddPalette, setShowAddPalette] = useState(true);

  const [rightPanel, setRightPanel] = useState<RightPanelMode>('none');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedPortId, setSelectedPortId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  const [stagedModalOpen, setStagedModalOpen] = useState(false);
  const [triadModalOpen, setTriadModalOpen] = useState(false);
  const [paletteModalOpen, setPaletteModalOpen] = useState(false);
  const [scenarioModalOpen, setScenarioModalOpen] = useState(false);
  const [settingsModalOpen, setSettingsModalOpen] = useState(false);

  const [k3sEdits, setK3sEdits] = useState<StagedK3sEdit[]>([]);
  const [peerEdits, setPeerEdits] = useState<StagedPeerEdit[]>([]);

  const [traceEndpoints, setTraceEndpoints] = useState<{ src: string; dst: string }>({ src: '', dst: '' });
  const [tracedHighlight, setTracedHighlight] = useState<{ nodes: Set<string>; cables: Set<string> }>({
    nodes: new Set(),
    cables: new Set(),
  });

  const history = useGraphHistory();
  const initialFitDone = useRef(false);

  const loadDesiredState = useCallback(async () => {
    setLoadingState(true);
    try {
      const s = await getCurrentDesiredState();
      setLiveState(s);
      setDraftState(structuredClone(s));
      setActiveScenarioId(s.topology?.activeScenarioId || undefined);
    } catch (err) {
      setBanner({
        kind: 'err',
        text: err instanceof Error ? err.message : 'Failed to load DesiredState',
      });
    } finally {
      setLoadingState(false);
    }
  }, []);

  useEffect(() => {
    void loadDesiredState();
  }, [loadDesiredState]);

  const pollingCfg = useMemo(
    () => draftState?.topology?.polling ?? { localIntervalSec: 5, peerIntervalSec: 10, pauseWhenHidden: true },
    [draftState?.topology?.polling],
  );

  const { fabric, probing, paused, setPaused, lastUpdated, probeError, probeNow } = useFabricTelemetry(pollingCfg);

  const activeScenario = useMemo(
    () =>
      activeScenarioId
        ? draftState?.topology?.scenarios?.find((sc) => sc.id === activeScenarioId)
        : undefined,
    [activeScenarioId, draftState?.topology?.scenarios],
  );

  const savedNodes = useMemo(
    () => activeScenario?.nodes ?? draftState?.topology?.nodes ?? [],
    [activeScenario?.nodes, draftState?.topology?.nodes],
  );
  const savedCables = useMemo(
    () => activeScenario?.cables ?? draftState?.topology?.cables ?? [],
    [activeScenario?.cables, draftState?.topology?.cables],
  );

  const hydrated = useMemo(
    () => hydrateFabricGraph(draftState, fabric, savedNodes, savedCables),
    [draftState, fabric, savedNodes, savedCables],
  );

  const probeEval = useMemo(() => buildProbeSnapshotForEval(fabric, draftState), [fabric, draftState]);

  const health = useMemo(
    () => evaluateFabricHealth(hydrated.nodes, hydrated.cables, probeEval),
    [hydrated.nodes, hydrated.cables, probeEval],
  );

  const diagnostics = useMemo(
    () => analyzeTopologyDiagnostics(hydrated.nodes, hydrated.cables, health, probeEval),
    [hydrated.nodes, hydrated.cables, health, probeEval],
  );

  const activeAlertCountByNode = useMemo(() => {
    const map = new Map<string, number>();
    const alerts = fabric?.librenms?.alerts ?? [];
    if (alerts.length === 0) return map;
    for (const n of hydrated.nodes) {
      const key = (n.hostRef || n.label).toLowerCase();
      const count = alerts.filter(
        (a) =>
          a.deviceHostname.toLowerCase().includes(key) ||
          key.includes(a.deviceHostname.toLowerCase()),
      ).length;
      if (count > 0) map.set(n.id, count);
    }
    return map;
  }, [fabric?.librenms?.alerts, hydrated.nodes]);

  const commitGraphToDraft = useCallback(
    (nextNodes: TopologyCanvasNode[], nextCables: TopologyCableEdge[], recordHistory = true) => {
      if (recordHistory) {
        history.pushSnapshot({ nodes: savedNodes, cables: savedCables });
      }
      setDraftState((prev) => {
        if (!prev) return prev;
        const cur = TopologyConfigSchema.parse(prev.topology ?? {});
        if (activeScenarioId) {
          return {
            ...prev,
            topology: {
              ...cur,
              scenarios: cur.scenarios.map((sc) =>
                sc.id === activeScenarioId
                  ? { ...sc, updatedAt: new Date().toISOString(), nodes: nextNodes, cables: nextCables }
                  : sc,
              ),
            },
          };
        }
        return {
          ...prev,
          topology: {
            ...cur,
            nodes: nextNodes,
            cables: nextCables,
          },
        };
      });
    },
    [activeScenarioId, history, savedCables, savedNodes],
  );

  // Filtered nodes & cables for canvas display
  const visibleNodeModels = useMemo(() => {
    if (layerFilter === 'all') return hydrated.nodes;
    return hydrated.nodes.filter((n) => n.layer === layerFilter || n.kind === 'wan' || n.kind === 'edge-ngfw');
  }, [hydrated.nodes, layerFilter]);

  const visibleNodeIdSet = useMemo(() => new Set(visibleNodeModels.map((n) => n.id)), [visibleNodeModels]);

  const visibleCableModels = useMemo(
    () =>
      hydrated.cables.filter(
        (c) =>
          (layerFilter === 'all' || c.layer === layerFilter || c.layer === 'physical') &&
          visibleNodeIdSet.has(c.sourceNodeId) &&
          visibleNodeIdSet.has(c.targetNodeId),
      ),
    [hydrated.cables, layerFilter, visibleNodeIdSet],
  );

  const derivedRfNodes: TopologyFlowNode[] = useMemo(
    () =>
      visibleNodeModels.map((model) => {
        const portHealthMap: Record<string, (typeof health.portHealth)[string]> = {};
        for (const p of model.ports) {
          const pk = `${model.id}:${p.id}`;
          if (health.portHealth[pk]) {
            portHealthMap[pk] = health.portHealth[pk];
          }
        }
        return {
          id: model.id,
          type: 'fabricNode',
          position: model.position,
          selected: model.id === selectedNodeId,
          data: {
            model,
            health: health.nodeHealth[model.id],
            portHealth: portHealthMap,
            activeAlertsCount: activeAlertCountByNode.get(model.id) ?? 0,
            isTraced: tracedHighlight.nodes.has(model.id),
            onSelectPort: (nid, pid) => {
              setSelectedNodeId(nid);
              setSelectedPortId(pid);
              setSelectedEdgeId(null);
              setRightPanel('inspector');
            },
          },
        };
      }),
    [visibleNodeModels, health, selectedNodeId, activeAlertCountByNode, tracedHighlight.nodes],
  );

  const [rfNodes, setRfNodes] = useState<TopologyFlowNode[]>([]);

  useEffect(() => {
    setRfNodes(derivedRfNodes);
    if (!initialFitDone.current && derivedRfNodes.length > 0) {
      initialFitDone.current = true;
      setTimeout(() => {
        void fitView({ padding: 0.14, duration: 250 });
      }, 60);
    }
  }, [derivedRfNodes, fitView]);

  const rfEdges: TopologyFlowEdge[] = useMemo(
    () =>
      visibleCableModels.map((model) => ({
        id: model.id,
        type: 'fabricEdge',
        source: model.sourceNodeId,
        sourceHandle: model.sourcePortId,
        target: model.targetNodeId,
        targetHandle: model.targetPortId,
        selected: model.id === selectedEdgeId,
        data: {
          model,
          health: health.cableHealth[model.id],
          isTraced: tracedHighlight.cables.has(model.id),
        },
      })),
    [visibleCableModels, health.cableHealth, selectedEdgeId, tracedHighlight.cables],
  );

  const handleNodesChange = useCallback((changes: NodeChange<TopologyFlowNode>[]) => {
    setRfNodes((prev) => applyNodeChanges(changes, prev));
  }, []);

  const handleNodeDragStop = useCallback(
    (_evt: React.MouseEvent | MouseEvent | TouchEvent, draggedNode: TopologyFlowNode) => {
      const targetModel = hydrated.nodes.find((n) => n.id === draggedNode.id);
      if (!targetModel) return;
      const updatedNode: TopologyCanvasNode = {
        ...targetModel,
        position: {
          x: Math.round(draggedNode.position.x),
          y: Math.round(draggedNode.position.y),
        },
      };
      commitGraphToDraft(upsertById(savedNodes, updatedNode), savedCables, true);
    },
    [commitGraphToDraft, hydrated.nodes, savedCables, savedNodes],
  );

  const handleConnect = useCallback(
    (conn: Connection) => {
      if (!conn.source || !conn.target) return;
      const srcNode = hydrated.nodes.find((n) => n.id === conn.source);
      const dstNode = hydrated.nodes.find((n) => n.id === conn.target);
      const srcPort = conn.sourceHandle || srcNode?.ports[0]?.id || 'eth0';
      const dstPort = conn.targetHandle || dstNode?.ports[0]?.id || 'eth0';
      const layer: TopologyLayer =
        srcNode?.layer === 'k3s' || dstNode?.layer === 'k3s'
          ? 'k3s'
          : srcNode?.layer === 'vpn' || dstNode?.layer === 'vpn'
            ? 'vpn'
            : srcNode?.layer === 'l2-l3' || dstNode?.layer === 'l2-l3'
              ? 'l2-l3'
              : 'physical';
      const newEdge: TopologyCableEdge = {
        id: `cable-${Date.now().toString(36)}`,
        sourceNodeId: conn.source,
        sourcePortId: srcPort,
        targetNodeId: conn.target,
        targetPortId: dstPort,
        layer,
        medium: layer === 'physical' ? 'rj45-cat6a' : layer === 'vpn' ? 'wireguard' : 'k3s-route',
        status: layer === 'physical' ? 'planned' : 'virtual',
        cableLabel: layer === 'physical' ? `${srcPort} ↔ ${dstPort}` : undefined,
        vlanIds: [],
      };
      const ensuredNodes = [srcNode, dstNode].reduce((acc, n) => (n ? upsertById(acc, n) : acc), savedNodes);
      commitGraphToDraft(ensuredNodes, upsertById(savedCables, newEdge), true);
      setSelectedEdgeId(newEdge.id);
      setSelectedNodeId(null);
      setRightPanel('inspector');
    },
    [commitGraphToDraft, hydrated.nodes, savedCables, savedNodes],
  );

  const handleInsertCatalogNode = useCallback(
    (kind: TopologyCanvasNode['kind']) => {
      const cat = NODE_KIND_CATALOG.find((c) => c.kind === kind);
      if (!cat) return;
      const offset = (savedNodes.length % 6) * 35;
      const newNode: TopologyCanvasNode = {
        id: `custom-${kind}-${Date.now().toString(36)}`,
        kind,
        label: cat.label,
        layer: cat.layer,
        managed: false,
        position: { x: 420 + offset, y: 200 + offset },
        ports: structuredClone(cat.defaultPorts),
        metadata: {},
      };
      commitGraphToDraft(upsertById(savedNodes, newNode), savedCables, true);
      setSelectedNodeId(newNode.id);
      setSelectedEdgeId(null);
      setRightPanel('inspector');
    },
    [commitGraphToDraft, savedCables, savedNodes],
  );

  const handleUpdateNode = useCallback(
    (updated: TopologyCanvasNode) => {
      commitGraphToDraft(upsertById(savedNodes, updated), savedCables, true);
    },
    [commitGraphToDraft, savedCables, savedNodes],
  );

  const handleDeleteNode = useCallback(
    (nodeId: string) => {
      commitGraphToDraft(
        savedNodes.filter((n) => n.id !== nodeId),
        savedCables.filter((c) => c.sourceNodeId !== nodeId && c.targetNodeId !== nodeId),
        true,
      );
      if (selectedNodeId === nodeId) {
        setSelectedNodeId(null);
        setRightPanel('none');
      }
    },
    [commitGraphToDraft, savedCables, savedNodes, selectedNodeId],
  );

  const handleUpdateEdge = useCallback(
    (updated: TopologyCableEdge) => {
      commitGraphToDraft(savedNodes, upsertById(savedCables, updated), true);
    },
    [commitGraphToDraft, savedCables, savedNodes],
  );

  const handleDeleteEdge = useCallback(
    (edgeId: string) => {
      commitGraphToDraft(
        savedNodes,
        savedCables.filter((c) => c.id !== edgeId),
        true,
      );
      if (selectedEdgeId === edgeId) {
        setSelectedEdgeId(null);
        setRightPanel('none');
      }
    },
    [commitGraphToDraft, savedCables, savedNodes, selectedEdgeId],
  );

  const handleAutoLayout = useCallback(() => {
    const laidOutAll = autoLayoutTopologyNodes(hydrated.nodes);
    const savedIdSet = new Set(savedNodes.map((n) => n.id));
    const nextSaved = laidOutAll.map((n) =>
      savedIdSet.has(n.id) ? n : { ...n, position: n.position },
    );
    commitGraphToDraft(nextSaved, savedCables, true);
    setTimeout(() => {
      void fitView({ padding: 0.14, duration: 250 });
    }, 60);
  }, [commitGraphToDraft, fitView, hydrated.nodes, savedCables, savedNodes]);

  const handleUndo = useCallback(() => {
    const prev = history.undo({ nodes: savedNodes, cables: savedCables });
    if (prev) {
      commitGraphToDraft(prev.nodes, prev.cables, false);
    }
  }, [commitGraphToDraft, history, savedCables, savedNodes]);

  const handleRedo = useCallback(() => {
    const next = history.redo({ nodes: savedNodes, cables: savedCables });
    if (next) {
      commitGraphToDraft(next.nodes, next.cables, false);
    }
  }, [commitGraphToDraft, history, savedCables, savedNodes]);

  // Keyboard shortcuts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const inInput =
        target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT');
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteModalOpen(true);
        return;
      }
      if (inInput) return;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'z') {
        e.preventDefault();
        if (e.shiftKey) handleRedo();
        else handleUndo();
      }
      if (e.key === 'Delete' || e.key === 'Backspace') {
        if (selectedEdgeId) {
          const existsSaved = savedCables.some((c) => c.id === selectedEdgeId);
          if (existsSaved) handleDeleteEdge(selectedEdgeId);
        } else if (selectedNodeId) {
          const node = hydrated.nodes.find((n) => n.id === selectedNodeId);
          if (node && !node.managed) handleDeleteNode(selectedNodeId);
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [handleDeleteEdge, handleDeleteNode, handleRedo, handleUndo, hydrated.nodes, savedCables, selectedEdgeId, selectedNodeId]);

  const handleQuickFix = useCallback(
    (diag: TopologyDiagnostic) => {
      if (!diag.quickFix || !diag.edgeId) return;
      const edgeModel = hydrated.cables.find((c) => c.id === diag.edgeId);
      if (!edgeModel) return;
      const patch = diag.quickFix.patch as Partial<TopologyCableEdge>;
      const patched: TopologyCableEdge = {
        ...edgeModel,
        ...patch,
      };
      commitGraphToDraft(savedNodes, upsertById(savedCables, patched), true);
      setBanner({ kind: 'ok', text: `Quick-Fix applied to cable ${patched.cableLabel || patched.id}` });
    },
    [commitGraphToDraft, hydrated.cables, savedCables, savedNodes],
  );

  const handleFocusTarget = useCallback(
    (nodeId?: string, edgeId?: string) => {
      if (nodeId) {
        const node = hydrated.nodes.find((n) => n.id === nodeId);
        setSelectedNodeId(nodeId);
        setSelectedEdgeId(null);
        setRightPanel('inspector');
        if (node) {
          void setCenter(node.position.x + 120, node.position.y + 80, { zoom: 1.05, duration: 300 });
        }
      } else if (edgeId) {
        setSelectedEdgeId(edgeId);
        setSelectedNodeId(null);
        setRightPanel('inspector');
      }
    },
    [hydrated.nodes, setCenter],
  );

  const handleSaveLayout = useCallback(async () => {
    if (!draftState) return;
    setSavingLayout(true);
    setBanner(null);
    try {
      const res = await applyState(draftState);
      if (res.success) {
        setLiveState(structuredClone(draftState));
        setBanner({ kind: 'ok', text: res.message || 'Saved topology layout to topology.yaml' });
      } else {
        setBanner({ kind: 'err', text: res.message || 'Failed to save topology layout' });
      }
    } catch (err) {
      setBanner({
        kind: 'err',
        text: err instanceof Error ? err.message : 'Failed to save topology layout',
      });
    } finally {
      setSavingLayout(false);
    }
  }, [applyState, draftState]);

  const stageLocalState = useCallback((updater: (prev: DesiredState) => DesiredState) => {
    setDraftState((prev) => (prev ? updater(prev) : prev));
  }, []);

  const stagedChangeCount = useMemo(() => {
    let count = k3sEdits.length + peerEdits.length;
    if (liveState && draftState && JSON.stringify(liveState) !== JSON.stringify(draftState)) {
      count += 1;
    }
    return count;
  }, [draftState, k3sEdits.length, liveState, peerEdits.length]);

  const diagErrorCount = useMemo(
    () => diagnostics.filter((d) => d.severity === 'error' || d.severity === 'warning').length,
    [diagnostics],
  );

  const selectedNode = useMemo(
    () => (selectedNodeId ? hydrated.nodes.find((n) => n.id === selectedNodeId) ?? null : null),
    [hydrated.nodes, selectedNodeId],
  );
  const selectedEdge = useMemo(
    () => (selectedEdgeId ? hydrated.cables.find((c) => c.id === selectedEdgeId) ?? null : null),
    [hydrated.cables, selectedEdgeId],
  );

  if (loadingState) {
    return (
      <div className="h-full flex items-center justify-center bg-slate-950 text-slate-300 text-sm gap-2">
        <Loader2 className="w-4 h-4 animate-spin text-sky-400" />
        Loading Topology Studio...
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-slate-950 text-slate-100 overflow-hidden">
      {/* Top Toolbar */}
      <header className="px-3 py-2 border-b border-slate-800 bg-slate-900 flex flex-wrap items-center justify-between gap-2 shrink-0">
        <div className="flex flex-wrap items-center gap-1.5">
          {/* Layer Filters */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            {LAYER_FILTERS.map((lf) => (
              <button
                key={lf.id}
                type="button"
                onClick={() => setLayerFilter(lf.id)}
                className={`px-2 py-1 rounded text-[11px] font-medium ${
                  layerFilter === lf.id
                    ? 'bg-sky-600 text-white'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {lf.label}
              </button>
            ))}
          </div>

          {/* Scenario Switcher */}
          <button
            type="button"
            onClick={() => setScenarioModalOpen(true)}
            className={`px-2.5 py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 ${
              activeScenario
                ? 'bg-amber-500/15 border-amber-500/50 text-amber-300'
                : 'bg-slate-950 border-slate-800 text-slate-200 hover:border-slate-700'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>{activeScenario ? `What-If: ${activeScenario.name}` : 'Live Fabric'}</span>
          </button>

          {/* Undo / Redo / Auto-Layout */}
          <div className="flex items-center gap-1">
            <button
              type="button"
              disabled={!history.canUndo}
              onClick={handleUndo}
              className="p-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-35"
              title="Undo (Ctrl+Z)"
            >
              <Undo2 className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              disabled={!history.canRedo}
              onClick={handleRedo}
              className="p-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-35"
              title="Redo (Ctrl+Shift+Z)"
            >
              <Redo2 className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleAutoLayout}
              className="px-2 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 hover:text-white text-xs flex items-center gap-1"
              title="Re-run tiered fabric auto-layout"
            >
              <LayoutGrid className="w-3.5 h-3.5" />
              <span className="hidden xl:inline">Layout</span>
            </button>
          </div>
        </div>

        {/* Right Toolbar Actions */}
        <div className="flex flex-wrap items-center gap-1.5">
          {/* Telemetry Live / Pause + Refresh */}
          <button
            type="button"
            onClick={() => setPaused((p) => !p)}
            className={`px-2 py-1.5 rounded border text-xs font-mono flex items-center gap-1 ${
              paused
                ? 'bg-slate-950 border-slate-700 text-slate-400'
                : 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
            }`}
            title={lastUpdated ? `Last probe: ${lastUpdated}` : 'Toggle live telemetry polling'}
          >
            {paused ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
            <span>{paused ? 'Paused' : 'Live'}</span>
          </button>

          <button
            type="button"
            onClick={() => void probeNow()}
            className="p-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 hover:text-white"
            title="Probe Fabric Now"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${probing ? 'animate-spin text-sky-400' : ''}`} />
          </button>

          <button
            type="button"
            onClick={() => setPaletteModalOpen(true)}
            className="px-2 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 hover:text-white text-xs flex items-center gap-1"
            title="Command Palette (Ctrl+K)"
          >
            <Search className="w-3.5 h-3.5" />
            <span className="hidden lg:inline font-mono text-[11px]">Ctrl+K</span>
          </button>

          <button
            type="button"
            onClick={() => setRightPanel((p) => (p === 'tracer' ? 'none' : 'tracer'))}
            className={`px-2.5 py-1.5 rounded border text-xs flex items-center gap-1 ${
              rightPanel === 'tracer'
                ? 'bg-sky-600 border-sky-500 text-white'
                : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white'
            }`}
          >
            <Route className="w-3.5 h-3.5" />
            <span>Trace</span>
          </button>

          <button
            type="button"
            onClick={() => setRightPanel((p) => (p === 'diagnostics' ? 'none' : 'diagnostics'))}
            className={`px-2.5 py-1.5 rounded border text-xs flex items-center gap-1 ${
              rightPanel === 'diagnostics'
                ? 'bg-sky-600 border-sky-500 text-white'
                : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white'
            }`}
          >
            <AlertTriangle className={`w-3.5 h-3.5 ${diagErrorCount > 0 ? 'text-amber-400' : ''}`} />
            <span>Diag</span>
            {diagErrorCount > 0 && (
              <span className="px-1.5 rounded-full bg-amber-500/20 text-amber-300 font-mono text-[10px]">
                {diagErrorCount}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setRightPanel((p) => (p === 'cutsheet' ? 'none' : 'cutsheet'))}
            className={`px-2.5 py-1.5 rounded border text-xs flex items-center gap-1 ${
              rightPanel === 'cutsheet'
                ? 'bg-sky-600 border-sky-500 text-white'
                : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white'
            }`}
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Cut-Sheet</span>
          </button>

          <button
            type="button"
            onClick={() => setTriadModalOpen(true)}
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-200 text-xs"
          >
            Triad Sync
          </button>

          <button
            type="button"
            onClick={() => setSettingsModalOpen(true)}
            className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-200 text-xs flex items-center gap-1"
            title="LLDP (WAN-Excluded) & Peer Hosts"
          >
            <Radio className="w-3.5 h-3.5 text-sky-400" />
            <span className="hidden xl:inline">LLDP &amp; Peers</span>
          </button>

          <button
            type="button"
            disabled={savingLayout || !draftState}
            onClick={() => void handleSaveLayout()}
            className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white text-xs font-medium flex items-center gap-1"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{savingLayout ? 'Saving...' : 'Save'}</span>
          </button>

          <button
            type="button"
            onClick={() => setStagedModalOpen(true)}
            className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 ${
              stagedChangeCount > 0
                ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
            }`}
          >
            <GitCommit className="w-3.5 h-3.5" />
            <span>Diff / Apply</span>
            {stagedChangeCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-black/30 font-mono text-[10px]">
                {stagedChangeCount}
              </span>
            )}
          </button>
        </div>
      </header>

      {/* Optional Status / Probe Banner */}
      {(banner || probeError) && (
        <div
          className={`px-4 py-1.5 text-xs flex items-center justify-between border-b shrink-0 ${
            banner?.kind === 'ok'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
          }`}
        >
          <span className="flex items-center gap-1.5 font-mono">
            {banner?.kind === 'ok' ? <Check className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
            {banner?.text || probeError}
          </span>
          {banner && (
            <button type="button" onClick={() => setBanner(null)} className="text-[11px] underline">
              Dismiss
            </button>
          )}
        </div>
      )}

      {/* Workspace Body: Left Palette + ReactFlow Canvas + Right Drawer */}
      <div className="flex-1 min-h-0 flex overflow-hidden">
        {showAddPalette ? (
          <aside className="w-52 shrink-0 bg-slate-950 border-r border-slate-800 flex flex-col overflow-hidden">
            <div className="px-3 py-2.5 border-b border-slate-800 flex items-center justify-between bg-slate-900">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-300">
                Add Fabric Node
              </span>
              <button
                type="button"
                onClick={() => setShowAddPalette(false)}
                className="text-[11px] text-slate-400 hover:text-white"
              >
                Hide
              </button>
            </div>
            <div className="p-2 space-y-1 overflow-y-auto flex-1 text-xs">
              {NODE_KIND_CATALOG.map((item) => (
                <button
                  key={item.kind}
                  type="button"
                  onClick={() => handleInsertCatalogNode(item.kind)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-left flex items-center justify-between gap-1.5"
                >
                  <span className="truncate text-slate-200 flex items-center gap-1.5">
                    <Plus className="w-3 h-3 text-sky-400 shrink-0" />
                    <span className="truncate">{item.label}</span>
                  </span>
                  <span className="font-mono text-[10px] text-slate-500 shrink-0">{item.layer}</span>
                </button>
              ))}
            </div>
          </aside>
        ) : (
          <div className="border-r border-slate-800 bg-slate-950 p-1.5 flex items-start">
            <button
              type="button"
              onClick={() => setShowAddPalette(true)}
              className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300"
              title="Show Add Node Palette"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* ReactFlow Canvas */}
        <div className="flex-1 min-w-0 h-full relative bg-slate-950">
          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            nodeTypes={TOPOLOGY_NODE_TYPES}
            edgeTypes={TOPOLOGY_EDGE_TYPES}
            onNodesChange={handleNodesChange}
            onNodeDragStop={handleNodeDragStop}
            onConnect={handleConnect}
            onNodeClick={(_e, node) => {
              setSelectedNodeId(node.id);
              setSelectedPortId(null);
              setSelectedEdgeId(null);
              setRightPanel('inspector');
            }}
            onEdgeClick={(_e, edge) => {
              setSelectedEdgeId(edge.id);
              setSelectedNodeId(null);
              setSelectedPortId(null);
              setRightPanel('inspector');
            }}
            onPaneClick={() => {
              setSelectedNodeId(null);
              setSelectedPortId(null);
              setSelectedEdgeId(null);
            }}
            minZoom={0.2}
            maxZoom={2.2}
            colorMode="dark"
          >
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1e293b" />
            <Controls className="!bg-slate-900 !border-slate-800 !text-slate-200" />
            <MiniMap
              className="!bg-slate-900 !border !border-slate-800"
              nodeColor={(n) => {
                const status = (n.data as TopologyFlowNode['data'])?.health?.status;
                return status === 'red' ? '#ef4444' : status === 'green' ? '#10b981' : '#f59e0b';
              }}
            />
          </ReactFlow>

          {/* Compact Health Legend Overlay */}
          <div className="absolute bottom-3 left-3 z-10 px-3 py-1.5 rounded-lg bg-slate-900/95 border border-slate-800 text-[11px] flex items-center gap-3 pointer-events-none">
            <span className="flex items-center gap-1.5 text-emerald-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              Verified Up
            </span>
            <span className="flex items-center gap-1.5 text-amber-300">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              Planned / Unverified
            </span>
            <span className="flex items-center gap-1.5 text-rose-300">
              <span className="w-2 h-2 rounded-full bg-rose-500" />
              Faulty / Down
            </span>
          </div>
        </div>

        {/* Context Right Drawer */}
        {rightPanel === 'inspector' && (
          <InspectorDrawer
            selectedNode={selectedNode}
            selectedPortId={selectedPortId}
            selectedEdge={selectedEdge}
            nodes={hydrated.nodes}
            health={health}
            fabric={fabric}
            draftState={draftState}
            onUpdateNode={handleUpdateNode}
            onDeleteNode={handleDeleteNode}
            onUpdateEdge={handleUpdateEdge}
            onDeleteEdge={handleDeleteEdge}
            onStageLocalState={stageLocalState}
            onStageK3sEdit={(edit) =>
              setK3sEdits((prev) => upsertById(prev, edit))
            }
            onStagePeerEdit={(edit) =>
              setPeerEdits((prev) => [
                ...prev.filter((p) => p.peerId !== edit.peerId),
                edit,
              ])
            }
            onClose={() => setRightPanel('none')}
          />
        )}

        {rightPanel === 'diagnostics' && (
          <DiagnosticsDrawer
            open
            onClose={() => setRightPanel('none')}
            diagnostics={diagnostics}
            onFocusTarget={handleFocusTarget}
            onApplyQuickFix={handleQuickFix}
          />
        )}

        {rightPanel === 'cutsheet' && (
          <CableCutSheetDrawer
            open
            onClose={() => setRightPanel('none')}
            nodes={hydrated.nodes}
            cables={hydrated.cables}
            health={health}
          />
        )}

        {rightPanel === 'tracer' && (
          <PathTracerDrawer
            open
            onClose={() => setRightPanel('none')}
            nodes={hydrated.nodes}
            cables={hydrated.cables}
            health={health}
            draftState={draftState}
            fabric={fabric}
            sourceNodeId={traceEndpoints.src}
            targetNodeId={traceEndpoints.dst}
            onChangeEndpoints={(src, dst) => setTraceEndpoints({ src, dst })}
            onHighlightPath={(nodeIds, cableIds) =>
              setTracedHighlight({ nodes: new Set(nodeIds), cables: new Set(cableIds) })
            }
          />
        )}
      </div>

      {/* Modals */}
      <StagedDiffModal
        open={stagedModalOpen}
        onClose={() => setStagedModalOpen(false)}
        liveState={liveState}
        draftState={draftState}
        k3sEdits={k3sEdits}
        peerEdits={peerEdits}
        onRemoveK3sEdit={(id) => setK3sEdits((prev) => prev.filter((k) => k.id !== id))}
        onRemovePeerEdit={(peerId) => setPeerEdits((prev) => prev.filter((p) => p.peerId !== peerId))}
        onResetDraft={() => {
          setDraftState(liveState ? structuredClone(liveState) : null);
          setK3sEdits([]);
          setPeerEdits([]);
        }}
        onApplyComplete={(appliedLocal) => {
          setK3sEdits([]);
          setPeerEdits([]);
          if (appliedLocal && draftState) {
            setLiveState(structuredClone(draftState));
          }
          setBanner({ kind: 'ok', text: 'Phased fabric apply succeeded.' });
          void probeNow();
        }}
      />

      <TriadSyncModal
        open={triadModalOpen}
        onClose={() => setTriadModalOpen(false)}
        nodes={hydrated.nodes}
        cables={hydrated.cables}
        health={health}
        fabric={fabric}
        onFabricRefresh={() => void probeNow()}
        onPullMerged={({ nodes: pulledN, cables: pulledC }) => {
          let nextN = savedNodes;
          for (const n of pulledN ?? []) nextN = upsertById(nextN, n);
          let nextC = savedCables;
          for (const c of pulledC ?? []) nextC = upsertById(nextC, c);
          commitGraphToDraft(nextN, nextC, true);
          setBanner({ kind: 'ok', text: 'Merged NetBox inventory into Topology Studio canvas.' });
        }}
      />

      <CommandPaletteModal
        open={paletteModalOpen}
        onClose={() => setPaletteModalOpen(false)}
        nodes={hydrated.nodes}
        onSelectNode={(nid) => handleFocusTarget(nid)}
        onInsertCatalogNode={handleInsertCatalogNode}
      />

      <ScenarioManagerModal
        open={scenarioModalOpen}
        onClose={() => setScenarioModalOpen(false)}
        draftState={draftState}
        liveNodes={draftState?.topology?.nodes ?? []}
        liveCables={draftState?.topology?.cables ?? []}
        activeScenarioId={activeScenarioId}
        onSelectScenario={(sid) => {
          setActiveScenarioId(sid);
          history.clearHistory();
        }}
        onCreateScenario={(name, description, cloneCurrent) => {
          const now = new Date().toISOString();
          const newId = `scenario-${Date.now().toString(36)}`;
          const newSc = {
            id: newId,
            name,
            description,
            createdAt: now,
            updatedAt: now,
            nodes: cloneCurrent ? structuredClone(hydrated.nodes) : [],
            cables: cloneCurrent ? structuredClone(hydrated.cables) : [],
          };
          setDraftState((prev) => {
            if (!prev) return prev;
            const cur = TopologyConfigSchema.parse(prev.topology ?? {});
            return {
              ...prev,
              topology: {
                ...cur,
                scenarios: [...cur.scenarios, newSc],
              },
            };
          });
          setActiveScenarioId(newId);
        }}
        onDeleteScenario={(sid) => {
          if (activeScenarioId === sid) setActiveScenarioId(undefined);
          setDraftState((prev) => {
            if (!prev) return prev;
            const cur = TopologyConfigSchema.parse(prev.topology ?? {});
            return {
              ...prev,
              topology: {
                ...cur,
                scenarios: cur.scenarios.filter((sc) => sc.id !== sid),
              },
            };
          });
        }}
        onPromoteScenarioToLive={(sid) => {
          const sc = draftState?.topology?.scenarios?.find((s) => s.id === sid);
          if (!sc) return;
          setDraftState((prev) => {
            if (!prev) return prev;
            const cur = TopologyConfigSchema.parse(prev.topology ?? {});
            return {
              ...prev,
              topology: {
                ...cur,
                nodes: structuredClone(sc.nodes),
                cables: structuredClone(sc.cables),
              },
            };
          });
          setActiveScenarioId(undefined);
          setBanner({ kind: 'ok', text: `Promoted scenario "${sc.name}" into Live Fabric draft.` });
        }}
      />

      <FabricSettingsModal
        open={settingsModalOpen}
        onClose={() => setSettingsModalOpen(false)}
        draftState={draftState}
        onStageLocalState={stageLocalState}
      />
    </div>
  );
}

export function TopologyStudioWorkspace() {
  return (
    <ReactFlowProvider>
      <TopologyStudioCanvas />
    </ReactFlowProvider>
  );
}
