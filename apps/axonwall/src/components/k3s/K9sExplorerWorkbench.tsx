'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowUpDown,
  Boxes,
  Check,
  CheckCircle2,
  Command,
  Copy,
  Cpu,
  Database,
  Eye,
  FileCode,
  FileText,
  Globe,
  HardDrive,
  HelpCircle,
  KeyRound,
  Layers,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  Terminal,
  Trash2,
  X,
} from 'lucide-react';
import {
  executeK3sAction,
  getK3sApiResourcesAction,
  getK3sClusterPulseAction,
  getK3sNamespacesAction,
  inspectK3sResourceAction,
  listK3sResourcesAction,
} from '@/server/agent';
import {
  K9S_RESOURCE_CATALOG,
  K9S_RESOURCE_GROUPS,
  K9S_RESOURCE_MAP,
  formatAge,
  formatBytes,
  formatCpuMillis,
  getStatusBadgeClass,
  resolveK9sResourceAlias,
  type K3sAPIResource,
  type K3sClusterPulse,
  type K3sNamespaceSummary,
  type K3sResourceInspectResponse,
  type K3sResourceItem,
  type K3sTopologyNode,
} from './types';
import { K3sPulseCharts } from './K3sPulseCharts';
import { K3sTopologyMap } from './K3sTopologyMap';
import { K3sInspectorDrawer, type InspectorTab } from './K3sInspectorDrawer';
import {
  appendPulseHistory,
  computeClusterCapacitySummary,
  type K3sPulseHistoryPoint,
} from '@/lib/k3s-visuals';

type ViewMode = 'explorer' | 'pulse' | 'topology';

interface CrumbFrame {
  label: string;
  resource: string;
  namespace: string;
  labelSelector?: string;
}

const KEYBOARD_SHORTCUTS: { key: string; desc: string }[] = [
  { key: ':', desc: 'Open K9s Command Palette (:po, :svc, :ing, :pulse, :topo, :ns <name>)' },
  { key: '/', desc: 'Focus live table filter (supports substring, !exclude, /regex/)' },
  { key: '0..9', desc: 'Switch namespace (0 = All Namespaces, 1..9 = Quick Namespaces)' },
  { key: 'j / ↓  &  k / ↑', desc: 'Move row cursor down / up' },
  { key: 'Enter', desc: 'Open Inspector Drawer (or drill down from CRD to instances)' },
  { key: 'd', desc: 'Describe selected resource (kubectl describe)' },
  { key: 'y', desc: 'View & Edit YAML for selected resource (with Server Dry-Run & Apply)' },
  { key: 'l', desc: 'Stream Live Logs for Pod / Deployment / StatefulSet / DaemonSet / Job' },
  { key: 'p', desc: 'View Previous container logs (--previous)' },
  { key: 's', desc: 'Open Pod Exec Shell (for Pods) or Scale dialog (for Workloads)' },
  { key: 'r', desc: 'Rollout Restart Deployment / StatefulSet / DaemonSet' },
  { key: 'x', desc: 'Decode Secret in Inspector (Admin)' },
  { key: 'c / u', desc: 'Cordon / Uncordon selected Node' },
  { key: 't', desc: 'Trigger CronJob manually' },
  { key: 'Ctrl+D', desc: 'Delete selected resource (with confirmation)' },
  { key: 'Esc', desc: 'Close modal/drawer or return from drill-down' },
  { key: '?', desc: 'Toggle this K9s shortcut reference' },
];

function matchFilterQuery(item: K3sResourceItem, rawQuery: string): boolean {
  const q = rawQuery.trim();
  if (!q) return true;
  const hay = [
    item.name,
    item.namespace || '',
    item.status,
    item.kind,
    JSON.stringify(item.summary || {}),
    JSON.stringify(item.labels || {}),
  ]
    .join(' ')
    .toLowerCase();

  const neg = q.startsWith('!');
  const expr = neg ? q.slice(1).trim() : q;
  if (!expr) return true;

  let matched = false;
  if (expr.startsWith('/') && expr.endsWith('/') && expr.length > 2) {
    try {
      const re = new RegExp(expr.slice(1, -1), 'i');
      matched = re.test(hay);
    } catch {
      matched = hay.includes(expr.toLowerCase());
    }
  } else {
    const terms = expr.toLowerCase().split(/\s+/).filter(Boolean);
    matched = terms.every((t) => hay.includes(t));
  }
  return neg ? !matched : matched;
}

export function K9sExplorerWorkbench() {
  const searchParams = useSearchParams();

  const initialViewParam = searchParams.get('view');
  const initialResParam = searchParams.get('resource');
  const initialNsParam = searchParams.get('namespace');
  const initialNameParam = searchParams.get('name');
  const initialTabParam = searchParams.get('tab') as InspectorTab | null;

  const [viewMode, setViewMode] = useState<ViewMode>(
    initialViewParam === 'pulse'
      ? 'pulse'
      : initialViewParam === 'topology'
        ? 'topology'
        : 'explorer'
  );
  const [activeResource, setActiveResource] = useState<string>(
    initialResParam ? resolveK9sResourceAlias(initialResParam) : 'pods'
  );
  const [activeNamespace, setActiveNamespace] = useState<string>(initialNsParam || '_all');
  const [labelSelector, setLabelSelector] = useState<string>('');
  const [breadcrumbs, setBreadcrumbs] = useState<CrumbFrame[]>([]);

  const [pulse, setPulse] = useState<K3sClusterPulse | null>(null);
  const [pulseHistory, setPulseHistory] = useState<K3sPulseHistoryPoint[]>([]);
  const [apiResources, setApiResources] = useState<K3sAPIResource[]>([]);
  const [namespaces, setNamespaces] = useState<K3sNamespaceSummary[]>([]);
  const [items, setItems] = useState<K3sResourceItem[]>([]);
  const [resourceNamespaced, setResourceNamespaced] = useState<boolean>(true);
  const [loadingList, setLoadingList] = useState<boolean>(true);
  const [loadingPulse, setLoadingPulse] = useState<boolean>(true);
  const [listError, setListError] = useState<string | null>(null);

  const [filterQuery, setFilterQuery] = useState<string>('');
  const [sortCol, setSortCol] = useState<'name' | 'status' | 'namespace' | 'age'>('name');
  const [sortAsc, setSortAsc] = useState<boolean>(true);
  const [cursorIndex, setCursorIndex] = useState<number>(0);

  const [autoRefreshSec, setAutoRefreshSec] = useState<number>(5);
  const [railOpen, setRailOpen] = useState<boolean>(true);
  const [cliBarOpen, setCliBarOpen] = useState<boolean>(false);
  const [helpOpen, setHelpOpen] = useState<boolean>(false);
  const [paletteOpen, setPaletteOpen] = useState<boolean>(false);
  const [paletteInput, setPaletteInput] = useState<string>('');
  const [paletteCursor, setPaletteCursor] = useState<number>(0);

  // Toast message
  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  // Quick Scale Modal (keyboard [s] on workloads)
  const [scaleTarget, setScaleTarget] = useState<K3sResourceItem | null>(null);
  const [scaleVal, setScaleVal] = useState<number>(1);
  // Quick Delete Confirm Modal (keyboard Ctrl+D on row)
  const [deleteTarget, setDeleteTarget] = useState<K3sResourceItem | null>(null);

  // Inspector Drawer
  const [drawerOpen, setDrawerOpen] = useState<boolean>(false);
  const [drawerLoading, setDrawerLoading] = useState<boolean>(false);
  const [drawerData, setDrawerData] = useState<K3sResourceInspectResponse | null>(null);
  const [drawerError, setDrawerError] = useState<string | null>(null);
  const [drawerTab, setDrawerTab] = useState<InspectorTab>('overview');
  const [drawerTarget, setDrawerTarget] = useState<{
    resource: string;
    name: string;
    namespace?: string;
    decode?: boolean;
  } | null>(null);
  const [drawerPrevLogs, setDrawerPrevLogs] = useState<boolean>(false);

  const filterInputRef = useRef<HTMLInputElement>(null);
  const paletteInputRef = useRef<HTMLInputElement>(null);

  const showToast = useCallback((ok: boolean, text: string) => {
    setToast({ ok, text });
    setTimeout(() => setToast(null), 4000);
  }, []);

  // Load Pulse + API Resources + Namespaces
  const refreshClusterTelemetry = useCallback(async () => {
    setLoadingPulse(true);
    try {
      const [p, apis, nss] = await Promise.all([
        getK3sClusterPulseAction(),
        getK3sApiResourcesAction().catch(() => []),
        getK3sNamespacesAction().catch(() => []),
      ]);
      setPulse(p);
      setPulseHistory((prev) => appendPulseHistory(prev, p));
      if (apis.length > 0) setApiResources(apis);
      if (nss.length > 0) setNamespaces(nss);
    } catch {
    } finally {
      setLoadingPulse(false);
    }
  }, []);

  // Lightweight live pulse snapshot for continuous polling history
  const refreshPulseSnapshot = useCallback(async () => {
    try {
      const p = await getK3sClusterPulseAction();
      setPulse(p);
      setPulseHistory((prev) => appendPulseHistory(prev, p));
    } catch {
    }
  }, []);

  // Load current Resource table
  const refreshResourceList = useCallback(async () => {
    setLoadingList(true);
    setListError(null);
    try {
      const resp = await listK3sResourcesAction({
        resource: activeResource,
        namespace: activeNamespace,
        labelSelector: labelSelector || undefined,
      });
      setResourceNamespaced(resp.namespaced);
      if (resp.error) {
        setListError(resp.error);
        setItems([]);
      } else {
        setItems(resp.items || []);
      }
    } catch (e: any) {
      setListError(e?.message || 'Failed to load Kubernetes resources.');
      setItems([]);
    } finally {
      setLoadingList(false);
    }
  }, [activeResource, activeNamespace, labelSelector]);

  useEffect(() => {
    refreshClusterTelemetry();
  }, [refreshClusterTelemetry]);

  useEffect(() => {
    refreshResourceList();
  }, [refreshResourceList]);

  // Open Inspector automatically when URL has ?name=...
  const deepLinkedRef = useRef(false);
  useEffect(() => {
    if (deepLinkedRef.current) return;
    if (initialNameParam) {
      deepLinkedRef.current = true;
      openInspector({
        resource: initialResParam ? resolveK9sResourceAlias(initialResParam) : 'pods',
        name: initialNameParam,
        namespace: initialNsParam && initialNsParam !== '_all' ? initialNsParam : 'default',
        tab: initialTabParam || 'overview',
      });
    }
  }, [initialNameParam, initialResParam, initialNsParam, initialTabParam]);

  // Auto refresh interval
  const pollTickRef = useRef(0);
  useEffect(() => {
    if (autoRefreshSec <= 0) return;
    const timer = setInterval(() => {
      pollTickRef.current += 1;
      if (viewMode === 'explorer') {
        refreshResourceList();
        if (pollTickRef.current % 2 === 0) {
          refreshPulseSnapshot();
        }
      } else {
        refreshPulseSnapshot();
      }
    }, autoRefreshSec * 1000);
    return () => clearInterval(timer);
  }, [autoRefreshSec, viewMode, refreshResourceList, refreshPulseSnapshot]);

  const openInspector = useCallback(
    async (opts: {
      resource: string;
      name: string;
      namespace?: string;
      tab?: InspectorTab;
      decode?: boolean;
      previousLogs?: boolean;
    }) => {
      const res = resolveK9sResourceAlias(opts.resource);
      setDrawerOpen(true);
      setDrawerLoading(true);
      setDrawerError(null);
      setDrawerPrevLogs(Boolean(opts.previousLogs));
      setDrawerTab(opts.tab || 'overview');
      setDrawerTarget({
        resource: res,
        name: opts.name,
        namespace: opts.namespace,
        decode: opts.decode,
      });

      try {
        const resp = await inspectK3sResourceAction({
          resource: res,
          name: opts.name,
          namespace: opts.namespace,
          decodeSecret: Boolean(opts.decode),
        });
        if (resp.error) {
          setDrawerError(resp.error);
          setDrawerData(null);
        } else {
          setDrawerData(resp);
        }
      } catch (e: any) {
        setDrawerError(e?.message || 'Failed to inspect resource');
        setDrawerData(null);
      } finally {
        setDrawerLoading(false);
      }
    },
    []
  );

  // Quick namespaces 1..9 prioritized cleanly
  const namespaceNames = useMemo(() => {
    const names = namespaces.length > 0
      ? namespaces.map((n) => n.name)
      : (pulse?.namespaceStats || []).map((n) => n.name);
    if (names.length === 0) return ['default', 'kube-system'];
    const priority = ['default', 'kube-system', 'vow-system', 'openebs', 'monitoring'];
    const ordered: string[] = [];
    for (const p of priority) {
      if (names.includes(p)) ordered.push(p);
    }
    for (const n of names) {
      if (!ordered.includes(n)) ordered.push(n);
    }
    return ordered;
  }, [namespaces, pulse?.namespaceStats]);

  const quickNamespaces = useMemo(() => namespaceNames.slice(0, 9), [namespaceNames]);

  // Visible sorted & filtered items
  const visibleItems = useMemo(() => {
    const filtered = items.filter((it) => matchFilterQuery(it, filterQuery));
    filtered.sort((a, b) => {
      let cmp = 0;
      if (sortCol === 'name') cmp = a.name.localeCompare(b.name);
      else if (sortCol === 'namespace') cmp = (a.namespace || '').localeCompare(b.namespace || '');
      else if (sortCol === 'status') cmp = a.status.localeCompare(b.status);
      else if (sortCol === 'age') cmp = (a.creationTimestamp || '').localeCompare(b.creationTimestamp || '');
      return sortAsc ? cmp : -cmp;
    });
    return filtered;
  }, [items, filterQuery, sortCol, sortAsc]);

  useEffect(() => {
    if (cursorIndex >= visibleItems.length) {
      setCursorIndex(Math.max(0, visibleItems.length - 1));
    }
  }, [visibleItems.length, cursorIndex]);

  // Resource counts from Pulse
  const resourceCounts = useMemo<Record<string, number>>(() => {
    if (!pulse?.available) return {} as Record<string, number>;
    const c = pulse.counts;
    return {
      pods: c.podsTotal,
      deployments: c.deploymentsTotal,
      statefulsets: c.statefulSetsTotal,
      daemonsets: c.daemonSetsTotal,
      jobs: c.jobsActive + c.jobsSucceeded + c.jobsFailed,
      cronjobs: c.cronJobsTotal,
      services: c.servicesTotal,
      ingresses: c.ingressesTotal,
      networkpolicies: c.networkPoliciesTotal,
      persistentvolumeclaims: c.pvcsTotal,
      persistentvolumes: c.pvsTotal,
      storageclasses: c.storageClassesTotal,
      configmaps: c.configMapsTotal,
      secrets: c.secretsTotal,
      horizontalpodautoscalers: c.hpasTotal,
      nodes: c.nodesTotal,
      namespaces: c.namespacesTotal,
      events: c.warningEventsCount + c.normalEventsCount,
      customresourcedefinitions: c.crdsTotal,
    };
  }, [pulse]);

  // Palette suggestions (views + built-in resources + live CRDs)
  const paletteEntries = useMemo(() => {
    type PaletteEntry = {
      cmd: string;
      label: string;
      desc: string;
      type: 'view' | 'resource' | 'namespace';
      target: string;
    };
    const list: PaletteEntry[] = [
      { cmd: 'pulse', label: 'Cluster Pulse & Visualizations', desc: 'Charts, Node CPU/MEM, Events', type: 'view', target: 'pulse' },
      { cmd: 'topo', label: 'Interactive Topology Map', desc: 'Ingress → Service → Pod → Node → PVC', type: 'view', target: 'topology' },
      ...K9S_RESOURCE_CATALOG.map((r) => ({
        cmd: r.shortName,
        label: r.label,
        desc: `${r.id} (${r.aliases.join(', ')})`,
        type: 'resource' as const,
        target: r.id,
      })),
    ];

    const seen = new Set(K9S_RESOURCE_CATALOG.map((r) => r.id));
    for (const api of apiResources) {
      if (!seen.has(api.name)) {
        seen.add(api.name);
        const shortsStr = Array.isArray(api.shortNames) && api.shortNames.length > 0 ? api.shortNames.join(', ') : '';
        list.push({
          cmd: api.name,
          label: `${api.kind} (${api.apiVersion})`,
          desc: `${shortsStr || api.name} • ${api.namespaced ? 'Namespaced' : 'Cluster'}`,
          type: 'resource',
          target: api.name,
        });
      }
    }

    const q = paletteInput.trim().toLowerCase().replace(/^:/, '');
    if (q.startsWith('ns ') || q.startsWith('namespace ')) {
      const nsFilter = q.replace(/^(ns|namespace)\s+/, '').trim();
      const nsChoices: PaletteEntry[] = [
        { cmd: 'ns all', label: 'All Namespaces (_all)', desc: 'Switch active scope to all namespaces', type: 'namespace', target: '_all' },
        ...namespaceNames.map((n) => ({
          cmd: `ns ${n}`,
          label: `Namespace: ${n}`,
          desc: 'Switch active namespace filter',
          type: 'namespace' as const,
          target: n,
        })),
      ];
      return nsChoices.filter(
        (x) => !nsFilter || x.target.toLowerCase().includes(nsFilter) || x.label.toLowerCase().includes(nsFilter)
      );
    }

    if (!q) return list.slice(0, 40);
    return list
      .filter(
        (x) =>
          x.cmd.toLowerCase().includes(q) ||
          x.target.toLowerCase().includes(q) ||
          x.label.toLowerCase().includes(q) ||
          x.desc.toLowerCase().includes(q)
      )
      .slice(0, 40);
  }, [paletteInput, apiResources, namespaceNames]);

  const executePaletteChoice = useCallback(
    (entry: { type: string; target: string } | undefined) => {
      const raw = paletteInput.trim().replace(/^:/, '');
      if (raw.startsWith('ns ')) {
        const nsArg = raw.slice(3).trim();
        const resolvedNs = nsArg === 'all' || nsArg === '0' ? '_all' : nsArg;
        setActiveNamespace(resolvedNs);
        setPaletteOpen(false);
        setPaletteInput('');
        return;
      }
      if (entry) {
        if (entry.type === 'view') {
          setViewMode(entry.target as ViewMode);
        } else if (entry.type === 'namespace') {
          setActiveNamespace(entry.target);
        } else {
          setViewMode('explorer');
          setLabelSelector('');
          setBreadcrumbs([]);
          setActiveResource(entry.target);
        }
      } else if (raw) {
        if (raw === 'pulse') setViewMode('pulse');
        else if (raw === 'topo' || raw === 'topology') setViewMode('topology');
        else {
          setViewMode('explorer');
          setLabelSelector('');
          setBreadcrumbs([]);
          setActiveResource(resolveK9sResourceAlias(raw));
        }
      }
      setPaletteOpen(false);
      setPaletteInput('');
    },
    [paletteInput]
  );

  const drillDownToResource = (label: string, resource: string, ns: string, selector: string) => {
    setBreadcrumbs((prev) => [
      ...prev,
      {
        label: `${activeResource}${activeNamespace !== '_all' ? ` (${activeNamespace})` : ''}`,
        resource: activeResource,
        namespace: activeNamespace,
        labelSelector,
      },
    ]);
    setViewMode('explorer');
    setActiveResource(resource);
    setActiveNamespace(ns);
    setLabelSelector(selector);
    setFilterQuery('');
  };

  const popBreadcrumb = useCallback(() => {
    setBreadcrumbs((prev) => {
      if (prev.length === 0) return prev;
      const last = prev[prev.length - 1];
      setActiveResource(last.resource);
      setActiveNamespace(last.namespace);
      setLabelSelector(last.labelSelector || '');
      return prev.slice(0, -1);
    });
  }, []);

  // Enter / Drill-down behavior
  const handleRowPrimaryAction = useCallback(
    (item: K3sResourceItem) => {
      if (activeResource === 'namespaces') {
        drillDownToResource(item.name, 'pods', item.name, '');
        return;
      }
      if (activeResource === 'customresourcedefinitions' && item.summary?.plural) {
        drillDownToResource(item.name, String(item.summary.plural), '_all', '');
        return;
      }
      openInspector({
        resource: activeResource,
        name: item.name,
        namespace: item.namespace,
        tab: 'overview',
      });
    },
    [activeResource, openInspector]
  );

  // Global K9s Keyboard Shortcuts (carefully guarded!)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase() || '';
      const inInput = tag === 'input' || tag === 'textarea' || tag === 'select' || target?.isContentEditable;

      if (e.key === 'Escape') {
        if (paletteOpen) {
          setPaletteOpen(false);
          return;
        }
        if (helpOpen) {
          setHelpOpen(false);
          return;
        }
        if (scaleTarget) {
          setScaleTarget(null);
          return;
        }
        if (deleteTarget) {
          setDeleteTarget(null);
          return;
        }
        if (drawerOpen) {
          setDrawerOpen(false);
          return;
        }
        if (inInput) {
          (target as HTMLInputElement).blur();
          return;
        }
        if (breadcrumbs.length > 0) {
          popBreadcrumb();
          return;
        }
        if (filterQuery) {
          setFilterQuery('');
          return;
        }
        return;
      }

      if (inInput) return;
      if (paletteOpen || helpOpen || scaleTarget || deleteTarget) return;

      if (e.key === ':') {
        e.preventDefault();
        setPaletteOpen(true);
        setPaletteInput('');
        setPaletteCursor(0);
        setTimeout(() => paletteInputRef.current?.focus(), 20);
        return;
      }

      if (e.key === '?') {
        e.preventDefault();
        setHelpOpen((o) => !o);
        return;
      }

      if (e.key === '/') {
        e.preventDefault();
        setViewMode('explorer');
        filterInputRef.current?.focus();
        return;
      }

      if (drawerOpen) {
        // Drawer-scoped shortcuts
        if (e.key === 'd') {
          e.preventDefault();
          setDrawerTab('describe');
        } else if (e.key === 'y') {
          e.preventDefault();
          setDrawerTab('yaml');
        } else if (e.key === 'l') {
          e.preventDefault();
          setDrawerTab('logs');
        } else if (e.key === 's') {
          e.preventDefault();
          setDrawerTab('exec');
        } else if (e.key === 'x' && drawerData?.kind === 'Secret' && drawerTarget) {
          e.preventDefault();
          openInspector({
            ...drawerTarget,
            tab: drawerTab,
            decode: drawerData.secretRedacted ? true : false,
          });
        }
        return;
      }

      if (viewMode !== 'explorer') return;

      // 0..9 namespace shortcuts
      if (e.key >= '0' && e.key <= '9' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        if (e.key === '0') {
          setActiveNamespace('_all');
        } else {
          const idx = Number(e.key) - 1;
          if (quickNamespaces[idx]) {
            setActiveNamespace(quickNamespaces[idx]);
          }
        }
        return;
      }

      const selected = visibleItems[cursorIndex];

      if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault();
        setCursorIndex((i) => Math.min(Math.max(0, visibleItems.length - 1), i + 1));
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault();
        setCursorIndex((i) => Math.max(0, i - 1));
      } else if (e.key === 'Enter' && selected) {
        e.preventDefault();
        handleRowPrimaryAction(selected);
      } else if (e.key === 'd' && selected) {
        e.preventDefault();
        openInspector({ resource: activeResource, name: selected.name, namespace: selected.namespace, tab: 'describe' });
      } else if (e.key === 'y' && selected) {
        e.preventDefault();
        openInspector({ resource: activeResource, name: selected.name, namespace: selected.namespace, tab: 'yaml' });
      } else if (e.key === 'l' && selected) {
        e.preventDefault();
        openInspector({ resource: activeResource, name: selected.name, namespace: selected.namespace, tab: 'logs' });
      } else if (e.key === 'p' && selected) {
        e.preventDefault();
        openInspector({
          resource: activeResource,
          name: selected.name,
          namespace: selected.namespace,
          tab: 'logs',
          previousLogs: true,
        });
      } else if (e.key === 's' && selected) {
        e.preventDefault();
        if (selected.kind === 'Pod') {
          openInspector({ resource: 'pods', name: selected.name, namespace: selected.namespace, tab: 'exec' });
        } else if (
          selected.kind === 'Deployment' ||
          selected.kind === 'StatefulSet' ||
          selected.kind === 'ReplicaSet'
        ) {
          setScaleVal(Number(selected.summary?.desired ?? 1));
          setScaleTarget(selected);
        }
      } else if (
        e.key === 'r' &&
        selected &&
        (selected.kind === 'Deployment' || selected.kind === 'StatefulSet' || selected.kind === 'DaemonSet')
      ) {
        e.preventDefault();
        executeK3sAction({
          action: 'rollout-restart',
          resource: activeResource,
          namespace: selected.namespace,
          name: selected.name,
        }).then((r) => {
          showToast(r.success, r.message || 'Rollout restarted');
          refreshResourceList();
        });
      } else if (e.key === 'x' && selected && selected.kind === 'Secret') {
        e.preventDefault();
        openInspector({
          resource: 'secrets',
          name: selected.name,
          namespace: selected.namespace,
          tab: 'overview',
          decode: true,
        });
      } else if ((e.key === 'c' || e.key === 'u') && selected && selected.kind === 'Node') {
        e.preventDefault();
        executeK3sAction({
          action: e.key === 'c' ? 'cordon' : 'uncordon',
          name: selected.name,
        }).then((r) => {
          showToast(r.success, r.message || `Node ${e.key === 'c' ? 'cordoned' : 'uncordoned'}`);
          refreshResourceList();
          refreshClusterTelemetry();
        });
      } else if (e.key === 't' && selected && selected.kind === 'CronJob') {
        e.preventDefault();
        executeK3sAction({
          action: 'trigger-cronjob',
          namespace: selected.namespace,
          name: selected.name,
        }).then((r) => {
          showToast(r.success, r.message || 'CronJob triggered');
          refreshResourceList();
        });
      } else if (e.ctrlKey && e.key.toLowerCase() === 'd' && selected) {
        e.preventDefault();
        setDeleteTarget(selected);
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [
    paletteOpen,
    helpOpen,
    scaleTarget,
    deleteTarget,
    drawerOpen,
    drawerData,
    drawerTarget,
    drawerTab,
    breadcrumbs.length,
    popBreadcrumb,
    filterQuery,
    viewMode,
    visibleItems,
    cursorIndex,
    quickNamespaces,
    activeResource,
    openInspector,
    handleRowPrimaryAction,
    refreshResourceList,
    refreshClusterTelemetry,
    showToast,
  ]);

  const activeDef = K9S_RESOURCE_MAP[activeResource];

  const capSummary = useMemo(
    () => (pulse?.available ? computeClusterCapacitySummary(pulse) : null),
    [pulse]
  );

  const toggleSort = (col: 'name' | 'status' | 'namespace' | 'age') => {
    if (sortCol === col) setSortAsc((a) => !a);
    else {
      setSortCol(col);
      setSortAsc(true);
    }
  };

  return (
    <div className="p-4 sm:p-6 max-w-[1600px] mx-auto space-y-4">
      {/* K9s ASCII / Cockpit Header */}
      <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
            <Terminal className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-xl font-bold text-white tracking-tight">
                K9s Live Explorer &amp; Cluster Visualizations
              </h1>
              {pulse?.available ? (
                <span className="px-2 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-[10px] font-mono text-emerald-300 font-bold">
                  CONNECTED • {pulse.k3sVersion || 'k3s'} • CNI: {pulse.cniPlugin}
                </span>
              ) : loadingPulse ? (
                <span className="px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-[10px] font-mono text-slate-300">
                  PROBING API...
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded-full bg-rose-500/15 border border-rose-500/30 text-[10px] font-mono text-rose-300 font-bold">
                  CLUSTER UNREACHABLE
                </span>
              )}
            </div>
            {pulse?.available && (
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono tabular-nums text-slate-400">
                  <span>
                    Nodes: <strong className="text-emerald-300">{pulse.counts.nodesReady}/{pulse.counts.nodesTotal}</strong>
                  </span>
                  <span>
                    Pods: <strong className="text-emerald-300">{pulse.counts.podsRunning}/{pulse.counts.podsTotal}</strong>
                  </span>
                  <span>
                    Deploy: <strong className="text-sky-300">{pulse.counts.deploymentsReady}/{pulse.counts.deploymentsTotal}</strong>
                  </span>
                  <span>
                    Svc/Ing: <strong className="text-cyan-300">{pulse.counts.servicesTotal}/{pulse.counts.ingressesTotal}</strong>
                  </span>
                  <span>
                    PVCs: <strong className="text-amber-300">{pulse.counts.pvcsBound}/{pulse.counts.pvcsTotal}</strong>
                  </span>
                  <span>
                    Warnings: <strong className={pulse.counts.warningEventsCount > 0 ? 'text-amber-300' : 'text-slate-300'}>{pulse.counts.warningEventsCount}</strong>
                  </span>
                </div>

                {capSummary && (
                  <div className="flex flex-wrap items-center gap-4 text-[10px] font-mono tabular-nums text-slate-300">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="text-slate-400">CPU</span>
                      <span className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden inline-block">
                        <span className="h-full bg-emerald-500 block" style={{ width: `${capSummary.cpuUsagePct}%` }} />
                      </span>
                      <span className="text-emerald-300">{capSummary.cpuUsagePct}%</span>
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <span className="text-slate-400">MEM</span>
                      <span className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden inline-block">
                        <span className="h-full bg-sky-500 block" style={{ width: `${capSummary.memUsagePct}%` }} />
                      </span>
                      <span className="text-sky-300">{capSummary.memUsagePct}%</span>
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <span className="text-slate-400">SLOTS</span>
                      <span className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden inline-block">
                        <span className="h-full bg-cyan-500 block" style={{ width: `${capSummary.podDensityPct}%` }} />
                      </span>
                      <span className="text-cyan-300">{capSummary.podDensityPct}%</span>
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* View Mode Switcher */}
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-xl p-1 text-xs">
            {(
              [
                { id: 'explorer', label: 'K9s Explorer', icon: Terminal },
                { id: 'pulse', label: 'Pulse & Charts', icon: Activity },
                { id: 'topology', label: 'Topology Map', icon: Network },
              ] as const
            ).map((v) => {
              const Icon = v.icon;
              return (
                <button
                  key={v.id}
                  type="button"
                  onClick={() => setViewMode(v.id)}
                  className={`px-3 py-1.5 rounded-lg font-medium flex items-center gap-1.5 transition ${
                    viewMode === v.id
                      ? 'bg-emerald-600 text-white shadow'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {v.label}
                </button>
              );
            })}
          </div>

          <button
            type="button"
            onClick={() => {
              setPaletteOpen(true);
              setPaletteInput('');
              setTimeout(() => paletteInputRef.current?.focus(), 20);
            }}
            className="px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-emerald-300 flex items-center gap-1.5"
            title="Command Palette (:)"
          >
            <Command className="w-3.5 h-3.5" /> :cmd
          </button>

          <select
            value={autoRefreshSec}
            onChange={(e) => setAutoRefreshSec(Number(e.target.value))}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-300"
            title="Auto-refresh interval"
          >
            <option value={0}>Poll: Off</option>
            <option value={3}>Poll: 3s</option>
            <option value={5}>Poll: 5s</option>
            <option value={15}>Poll: 15s</option>
          </select>

          <button
            type="button"
            onClick={() => {
              refreshClusterTelemetry();
              refreshResourceList();
            }}
            className="p-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300"
            title="Refresh Now"
          >
            <RefreshCw className={`w-4 h-4 ${loadingList || loadingPulse ? 'animate-spin' : ''}`} />
          </button>

          <button
            type="button"
            onClick={() => setCliBarOpen((o) => !o)}
            className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-1.5 ${
              cliBarOpen
                ? 'bg-sky-500/15 border-sky-500/40 text-sky-300'
                : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" /> CLI k9s
          </button>

          <button
            type="button"
            onClick={() => setHelpOpen(true)}
            className="p-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300"
            title="Keyboard Shortcuts (?)"
          >
            <HelpCircle className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* CLI k9s Quick Launch Tip Drawer */}
      {cliBarOpen && (
        <div className="p-4 rounded-xl bg-slate-900 border border-sky-500/30 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
          <div className="space-y-1">
            <div className="font-bold text-sky-300">
              Native CLI <code className="font-mono text-white">k9s</code> (v0.51.0) Pre-Installed
            </div>
            <p className="text-slate-400">
              SSH into any Axonwall node or use Web Shell — KUBECONFIG is auto-detected for{' '}
              <code className="font-mono text-slate-200">/etc/rancher/k3s/k3s.yaml</code> (or sync locally with{' '}
              <code className="font-mono text-emerald-300">axonwall-kubeconfig</code>).
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 font-mono">
            {[
              activeNamespace !== '_all' ? `k9s -n ${activeNamespace}` : 'k9s -A',
              'axonwall-kubeconfig --vip',
            ].map((cmd) => (
              <button
                key={cmd}
                type="button"
                onClick={() => {
                  navigator.clipboard?.writeText(cmd).catch(() => {});
                  setCopiedCmd(cmd);
                  setTimeout(() => setCopiedCmd(null), 1500);
                }}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-sky-500/40 text-emerald-300 inline-flex items-center gap-2"
              >
                <span>$ {cmd}</span>
                {copiedCmd === cmd ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3 text-slate-400" />}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Toast */}
      {toast && (
        <div
          className={`p-3 rounded-xl border text-xs font-mono flex items-center justify-between ${
            toast.ok
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          <span>{toast.text}</span>
          <button type="button" onClick={() => setToast(null)}>✕</button>
        </div>
      )}

      {/* Fail-closed Cluster Unavailable Banner (Audit A-H2 / C5) */}
      {pulse && !pulse.available && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-amber-300">Kubernetes API / K3s Cluster Unavailable</div>
              <div className="text-slate-300 font-mono mt-0.5">{pulse.error}</div>
            </div>
          </div>
          <Link
            href="/k3s/cluster"
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 hover:text-white font-semibold"
          >
            Go to K3s Control Plane →
          </Link>
        </div>
      )}

      {/* Main View Content */}
      {viewMode === 'pulse' ? (
        pulse?.available ? (
          <K3sPulseCharts
            pulse={pulse}
            history={pulseHistory}
            autoRefreshSec={autoRefreshSec}
            onSelectFilter={(opts) => {
              setViewMode('explorer');
              setActiveResource(resolveK9sResourceAlias(opts.resource));
              if (opts.namespace) setActiveNamespace(opts.namespace);
              if (opts.search !== undefined) setFilterQuery(opts.search);
            }}
            onInspectResource={(opts) => {
              openInspector({
                resource: opts.resource,
                name: opts.name,
                namespace: opts.namespace,
                tab: opts.tab || 'overview',
              });
            }}
          />
        ) : (
          <div className="p-12 rounded-2xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-400">
            {loadingPulse
              ? 'Loading live cluster telemetry...'
              : 'Cluster telemetry unavailable. Verify k3s.service is active on the appliance.'}
          </div>
        )
      ) : viewMode === 'topology' ? (
        pulse?.available ? (
          <K3sTopologyMap
            graph={pulse.topology}
            namespaces={namespaceNames}
            initialNamespace={activeNamespace}
            pulse={pulse}
            nodes={pulse.nodes}
            topResourcePods={pulse.topResourcePods}
            topRestartingPods={pulse.topRestartingPods}
            onInspectNode={(node: K3sTopologyNode) => {
              openInspector({
                resource: node.resource,
                name: node.name,
                namespace: node.namespace,
                tab: 'overview',
              });
            }}
            onInspectResource={(opts) => {
              openInspector({
                resource: opts.resource,
                name: opts.name,
                namespace: opts.namespace,
                tab: opts.tab || 'overview',
              });
            }}
          />
        ) : (
          <div className="p-12 rounded-2xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-400">
            Topology map unavailable until the K3s API server answers.
          </div>
        )
      ) : (
        /* EXPLORER COCKPIT MODE */
        <div className="space-y-3">
          {/* Namespace Quick Bar + Breadcrumbs */}
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex flex-wrap items-center gap-1.5">
              {breadcrumbs.length > 0 && (
                <button
                  type="button"
                  onClick={popBreadcrumb}
                  className="px-2.5 py-1 rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-300 font-mono flex items-center gap-1 mr-1"
                >
                  <ArrowLeft className="w-3 h-3" /> Back (Esc)
                </button>
              )}
              <button
                type="button"
                onClick={() => setActiveNamespace('_all')}
                className={`px-2.5 py-1 rounded-lg font-mono border transition ${
                  activeNamespace === '_all'
                    ? 'bg-emerald-600 text-white border-emerald-500'
                    : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white'
                }`}
              >
                <span className="text-slate-400 mr-1">[0]</span>all
              </button>
              {quickNamespaces.map((ns, idx) => (
                <button
                  key={ns}
                  type="button"
                  onClick={() => setActiveNamespace(ns)}
                  className={`px-2.5 py-1 rounded-lg font-mono border transition ${
                    activeNamespace === ns
                      ? 'bg-emerald-600 text-white border-emerald-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white'
                  }`}
                >
                  <span className="opacity-60 mr-1">[{idx + 1}]</span>
                  {ns}
                </button>
              ))}
              {namespaceNames.length > 9 && (
                <select
                  value={activeNamespace}
                  onChange={(e) => setActiveNamespace(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 font-mono text-slate-200"
                >
                  <option value="_all">All Namespaces</option>
                  {namespaceNames.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              )}
            </div>

            {labelSelector && (
              <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-sky-500/15 border border-sky-500/30 font-mono text-sky-300">
                <span>-l {labelSelector}</span>
                <button type="button" onClick={() => setLabelSelector('')}>
                  ✕
                </button>
              </div>
            )}
          </div>

          <div className="flex flex-col lg:flex-row gap-4">
            {/* Collapsible Left Resource Rail */}
            {railOpen ? (
              <aside className="lg:w-60 shrink-0 rounded-2xl bg-slate-900 border border-slate-800 p-3 space-y-4 max-h-[720px] overflow-y-auto">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                  <span className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                    Resources
                  </span>
                  <button
                    type="button"
                    onClick={() => setRailOpen(false)}
                    className="text-slate-400 hover:text-white"
                    title="Collapse Sidebar"
                  >
                    <PanelLeftClose className="w-4 h-4" />
                  </button>
                </div>

                {K9S_RESOURCE_GROUPS.map((grp) => {
                  const groupItems = K9S_RESOURCE_CATALOG.filter((r) => r.group === grp);
                  return (
                    <div key={grp} className="space-y-1">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 px-2">
                        {grp}
                      </div>
                      {groupItems.map((res) => {
                        const isAct = activeResource === res.id;
                        const cnt = resourceCounts[res.id];
                        return (
                          <button
                            key={res.id}
                            type="button"
                            onClick={() => {
                              setLabelSelector('');
                              setBreadcrumbs([]);
                              setActiveResource(res.id);
                            }}
                            className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-mono transition ${
                              isAct
                                ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-semibold'
                                : 'text-slate-300 hover:bg-slate-800/70'
                            }`}
                          >
                            <span className="truncate">{res.label}</span>
                            <span className="text-[10px] text-slate-400 ml-2 shrink-0">
                              {cnt !== undefined ? cnt : `:${res.shortName}`}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  );
                })}
              </aside>
            ) : (
              <div>
                <button
                  type="button"
                  onClick={() => setRailOpen(true)}
                  className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
                  title="Expand Resource Rail"
                >
                  <PanelLeftOpen className="w-4 h-4" />
                </button>
              </div>
            )}

            {/* Main K9s Resource Table */}
            <div className="flex-1 min-w-0 rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden flex flex-col">
              {/* Filter Bar */}
              <div className="p-3.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/60">
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-mono text-xs font-bold">
                    {activeDef ? `${activeDef.label} (:${activeDef.shortName})` : activeResource}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    {visibleItems.length}/{items.length} items
                    {resourceNamespaced && activeNamespace !== '_all' ? ` in ${activeNamespace}` : ''}
                  </span>
                </div>

                <div className="relative flex-1 max-w-md">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    ref={filterInputRef}
                    type="text"
                    value={filterQuery}
                    onChange={(e) => setFilterQuery(e.target.value)}
                    placeholder="[/] Filter rows (e.g. nginx, !Completed, /^coredns/)..."
                    className="w-full bg-slate-900 border border-slate-800 focus:border-emerald-500/50 focus:outline-none rounded-lg pl-8 pr-7 py-1.5 text-xs font-mono text-white"
                  />
                  {filterQuery && (
                    <button
                      type="button"
                      onClick={() => setFilterQuery('')}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>

              {listError && (
                <div className="m-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs font-mono text-rose-300">
                  {listError}
                </div>
              )}

              <div className="overflow-x-auto flex-1">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-950/80 text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      {resourceNamespaced && (
                        <th
                          onClick={() => toggleSort('namespace')}
                          className="py-3 px-3 cursor-pointer hover:text-white whitespace-nowrap"
                        >
                          Namespace
                        </th>
                      )}
                      <th
                        onClick={() => toggleSort('name')}
                        className="py-3 px-3 cursor-pointer hover:text-white whitespace-nowrap"
                      >
                        Name ↕
                      </th>
                      <th
                        onClick={() => toggleSort('status')}
                        className="py-3 px-3 cursor-pointer hover:text-white whitespace-nowrap"
                      >
                        Status ↕
                      </th>
                      {activeResource === 'pods' && (
                        <>
                          <th className="py-3 px-3 whitespace-nowrap">Ready</th>
                          <th className="py-3 px-3 whitespace-nowrap">Restarts</th>
                          <th className="py-3 px-3 whitespace-nowrap">CPU</th>
                          <th className="py-3 px-3 whitespace-nowrap">Mem</th>
                          <th className="py-3 px-3 whitespace-nowrap">Pod IP</th>
                          <th className="py-3 px-3 whitespace-nowrap">Node</th>
                        </>
                      )}
                      {(activeResource === 'deployments' ||
                        activeResource === 'statefulsets' ||
                        activeResource === 'daemonsets' ||
                        activeResource === 'replicasets') && (
                        <>
                          <th className="py-3 px-3 whitespace-nowrap">Ready</th>
                          <th className="py-3 px-3 whitespace-nowrap">Images</th>
                        </>
                      )}
                      {activeResource === 'services' && (
                        <>
                          <th className="py-3 px-3 whitespace-nowrap">ClusterIP</th>
                          <th className="py-3 px-3 whitespace-nowrap">ExternalIP</th>
                          <th className="py-3 px-3 whitespace-nowrap">Ports</th>
                        </>
                      )}
                      {activeResource === 'ingresses' && (
                        <>
                          <th className="py-3 px-3 whitespace-nowrap">Class</th>
                          <th className="py-3 px-3 whitespace-nowrap">Hosts</th>
                          <th className="py-3 px-3 whitespace-nowrap">Backends</th>
                        </>
                      )}
                      {activeResource === 'nodes' && (
                        <>
                          <th className="py-3 px-3 whitespace-nowrap">Roles</th>
                          <th className="py-3 px-3 whitespace-nowrap">Internal IP</th>
                          <th className="py-3 px-3 whitespace-nowrap">Version</th>
                          <th className="py-3 px-3 whitespace-nowrap">CPU / Mem</th>
                        </>
                      )}
                      {activeResource === 'persistentvolumeclaims' && (
                        <>
                          <th className="py-3 px-3 whitespace-nowrap">Capacity</th>
                          <th className="py-3 px-3 whitespace-nowrap">StorageClass</th>
                          <th className="py-3 px-3 whitespace-nowrap">Volume</th>
                        </>
                      )}
                      {activeResource === 'events' && (
                        <>
                          <th className="py-3 px-3 whitespace-nowrap">Object</th>
                          <th className="py-3 px-3 whitespace-nowrap">Reason</th>
                          <th className="py-3 px-3 whitespace-nowrap">Message</th>
                        </>
                      )}
                      {(activeResource === 'secrets' || activeResource === 'configmaps') && (
                        <>
                          <th className="py-3 px-3 whitespace-nowrap">Keys</th>
                        </>
                      )}
                      <th
                        onClick={() => toggleSort('age')}
                        className="py-3 px-3 cursor-pointer hover:text-white whitespace-nowrap"
                      >
                        Age ↕
                      </th>
                      <th className="py-3 px-3 text-right whitespace-nowrap">Actions</th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {loadingList && visibleItems.length === 0 ? (
                      <tr>
                        <td colSpan={12} className="py-12 text-center text-slate-400">
                          Loading {activeResource}...
                        </td>
                      </tr>
                    ) : visibleItems.length === 0 ? (
                      <tr>
                        <td colSpan={12} className="py-12 text-center text-slate-500">
                          No {activeResource} found matching current namespace/filter.
                        </td>
                      </tr>
                    ) : (
                      visibleItems.map((item, idx) => {
                        const isCursor = idx === cursorIndex;
                        const s = item.summary || {};
                        const supportsLogs =
                          item.kind === 'Pod' ||
                          item.kind === 'Deployment' ||
                          item.kind === 'StatefulSet' ||
                          item.kind === 'DaemonSet' ||
                          item.kind === 'Job';
                        const isPod = item.kind === 'Pod';

                        return (
                          <tr
                            key={`${item.namespace || ''}-${item.name}-${item.uid || idx}`}
                            onClick={() => {
                              setCursorIndex(idx);
                              handleRowPrimaryAction(item);
                            }}
                            className={`cursor-pointer transition ${
                              isCursor
                                ? 'bg-emerald-500/10 ring-1 ring-inset ring-emerald-500/30'
                                : 'hover:bg-slate-800/40'
                            }`}
                          >
                            {resourceNamespaced && (
                              <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                                {item.namespace || '—'}
                              </td>
                            )}
                            <td className="py-2.5 px-3 text-white font-semibold max-w-xs truncate">
                              <span className="flex items-center gap-1.5 truncate">
                                {isCursor && <span className="text-emerald-400">›</span>}
                                <span className="truncate">{item.name}</span>
                              </span>
                            </td>
                            <td className="py-2.5 px-3 whitespace-nowrap">
                              <span
                                className={`px-2 py-0.5 rounded border text-[10px] ${getStatusBadgeClass(
                                  item.statusTone
                                )}`}
                              >
                                {item.status}
                              </span>
                            </td>

                            {activeResource === 'pods' && (
                              <>
                                <td className="py-2.5 px-3 text-slate-300">{s.ready || '—'}</td>
                                <td
                                  className={`py-2.5 px-3 ${
                                    Number(s.restarts || 0) > 0 ? 'text-rose-300 font-bold' : 'text-slate-400'
                                  }`}
                                >
                                  {s.restarts ?? 0}
                                </td>
                                <td className="py-2.5 px-3 text-emerald-300 whitespace-nowrap">
                                  {formatCpuMillis(s.cpuMillis)}
                                </td>
                                <td className="py-2.5 px-3 text-sky-300 whitespace-nowrap">
                                  {formatBytes(s.memBytes)}
                                </td>
                                <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                                  {s.podIP || '—'}
                                </td>
                                <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                                  {s.nodeName || '—'}
                                </td>
                              </>
                            )}

                            {(activeResource === 'deployments' ||
                              activeResource === 'statefulsets' ||
                              activeResource === 'daemonsets' ||
                              activeResource === 'replicasets') && (
                              <>
                                <td className="py-2.5 px-3 text-slate-200">{s.ready || item.status}</td>
                                <td className="py-2.5 px-3 text-slate-400 max-w-xs truncate">
                                  {Array.isArray(s.images) ? s.images.join(', ') : '—'}
                                </td>
                              </>
                            )}

                            {activeResource === 'services' && (
                              <>
                                <td className="py-2.5 px-3 text-slate-300">{s.clusterIP || 'None'}</td>
                                <td className="py-2.5 px-3 text-emerald-300">{s.externalIP || '<none>'}</td>
                                <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate">
                                  {Array.isArray(s.ports) ? s.ports.join(', ') : '—'}
                                </td>
                              </>
                            )}

                            {activeResource === 'ingresses' && (
                              <>
                                <td className="py-2.5 px-3 text-slate-300">{s.class || 'default'}</td>
                                <td className="py-2.5 px-3 text-cyan-300 max-w-xs truncate">
                                  {Array.isArray(s.hosts) ? s.hosts.join(', ') : '*'}
                                </td>
                                <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate">
                                  {Array.isArray(s.backends) ? s.backends.join(', ') : '—'}
                                </td>
                              </>
                            )}

                            {activeResource === 'nodes' && (
                              <>
                                <td className="py-2.5 px-3 text-sky-300">{s.roles || 'worker'}</td>
                                <td className="py-2.5 px-3 text-slate-300">{s.internalIp || '—'}</td>
                                <td className="py-2.5 px-3 text-slate-400">{s.version || '—'}</td>
                                <td className="py-2.5 px-3 text-emerald-300 whitespace-nowrap">
                                  {formatCpuMillis(s.cpuMillis)} / {formatBytes(s.memBytes)}
                                </td>
                              </>
                            )}

                            {activeResource === 'persistentvolumeclaims' && (
                              <>
                                <td className="py-2.5 px-3 text-amber-300">{s.capacity || '—'}</td>
                                <td className="py-2.5 px-3 text-slate-300">{s.storageClass || '—'}</td>
                                <td className="py-2.5 px-3 text-slate-400 truncate max-w-xs">
                                  {s.volume || '—'}
                                </td>
                              </>
                            )}

                            {activeResource === 'events' && (
                              <>
                                <td className="py-2.5 px-3 text-emerald-300 whitespace-nowrap">
                                  {s.object || '—'}
                                </td>
                                <td className="py-2.5 px-3 text-white whitespace-nowrap">
                                  {s.reason || '—'}
                                </td>
                                <td className="py-2.5 px-3 text-slate-300 max-w-md truncate font-sans">
                                  {s.message || '—'}
                                </td>
                              </>
                            )}

                            {(activeResource === 'secrets' || activeResource === 'configmaps') && (
                              <td className="py-2.5 px-3 text-slate-400 max-w-md truncate">
                                {Array.isArray(s.dataKeys) ? s.dataKeys.join(', ') : '—'}
                              </td>
                            )}

                            <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                              {formatAge(item.creationTimestamp)}
                            </td>

                            <td
                              className="py-2.5 px-3 text-right whitespace-nowrap"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <div className="inline-flex items-center gap-1">
                                <button
                                  type="button"
                                  onClick={() =>
                                    openInspector({
                                      resource: activeResource,
                                      name: item.name,
                                      namespace: item.namespace,
                                      tab: 'describe',
                                    })
                                  }
                                  className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                                  title="Describe (d)"
                                >
                                  <FileText className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() =>
                                    openInspector({
                                      resource: activeResource,
                                      name: item.name,
                                      namespace: item.namespace,
                                      tab: 'yaml',
                                    })
                                  }
                                  className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-sky-300"
                                  title="Edit YAML (y)"
                                >
                                  <FileCode className="w-3.5 h-3.5" />
                                </button>
                                {supportsLogs && (
                                  <button
                                    type="button"
                                    onClick={() =>
                                      openInspector({
                                        resource: activeResource,
                                        name: item.name,
                                        namespace: item.namespace,
                                        tab: 'logs',
                                      })
                                    }
                                    className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-emerald-300"
                                    title="Logs (l)"
                                  >
                                    <Activity className="w-3.5 h-3.5" />
                                  </button>
                                )}
                                {isPod && (
                                  <button
                                    type="button"
                                    onClick={() =>
                                      openInspector({
                                        resource: 'pods',
                                        name: item.name,
                                        namespace: item.namespace,
                                        tab: 'exec',
                                      })
                                    }
                                    className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-emerald-300"
                                    title="Shell Exec (s)"
                                  >
                                    <Terminal className="w-3.5 h-3.5" />
                                  </button>
                                )}
                                <button
                                  type="button"
                                  onClick={() => setDeleteTarget(item)}
                                  className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-rose-400"
                                  title="Delete (Ctrl+D)"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* Footer Shortcut Strip */}
              <div className="px-4 py-2 border-t border-slate-800 bg-slate-950/90 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] font-mono text-slate-400">
                <span><strong className="text-emerald-400">&lt;:&gt;</strong> cmd</span>
                <span><strong className="text-emerald-400">&lt;/&gt;</strong> filter</span>
                <span><strong className="text-emerald-400">&lt;0..9&gt;</strong> ns</span>
                <span><strong className="text-emerald-400">&lt;Enter&gt;</strong> inspect</span>
                <span><strong className="text-emerald-400">&lt;d&gt;</strong> describe</span>
                <span><strong className="text-emerald-400">&lt;y&gt;</strong> yaml</span>
                <span><strong className="text-emerald-400">&lt;l&gt;</strong> logs</span>
                <span><strong className="text-emerald-400">&lt;s&gt;</strong> shell/scale</span>
                <span><strong className="text-emerald-400">&lt;r&gt;</strong> restart</span>
                <span><strong className="text-emerald-400">&lt;Ctrl+D&gt;</strong> delete</span>
                <span><strong className="text-emerald-400">&lt;?&gt;</strong> all shortcuts</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Command Palette Modal (:) */}
      {paletteOpen && (
        <div
          className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-start justify-center pt-20 p-4"
          onClick={() => setPaletteOpen(false)}
        >
          <div
            className="w-full max-w-xl rounded-2xl bg-slate-900 border border-emerald-500/40 shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-3.5 border-b border-slate-800 flex items-center gap-2 bg-slate-950">
              <span className="text-emerald-400 font-mono font-bold text-sm">:</span>
              <input
                ref={paletteInputRef}
                type="text"
                value={paletteInput}
                onChange={(e) => {
                  setPaletteInput(e.target.value);
                  setPaletteCursor(0);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    setPaletteCursor((c) => Math.min(Math.max(0, paletteEntries.length - 1), c + 1));
                  } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    setPaletteCursor((c) => Math.max(0, c - 1));
                  } else if (e.key === 'Enter') {
                    e.preventDefault();
                    executePaletteChoice(paletteEntries[paletteCursor]);
                  } else if (e.key === 'Escape') {
                    setPaletteOpen(false);
                  }
                }}
                placeholder="Type resource or command (po, deploy, svc, ing, pulse, topo, ns <name>)..."
                className="flex-1 bg-transparent text-sm font-mono text-white placeholder-slate-500 focus:outline-none"
              />
              <button type="button" onClick={() => setPaletteOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/60">
              {paletteEntries.map((entry, i) => (
                <button
                  key={`${entry.type}-${entry.target}-${entry.cmd}`}
                  type="button"
                  onClick={() => executePaletteChoice(entry)}
                  className={`w-full px-4 py-2.5 text-left flex items-center justify-between text-xs transition ${
                    i === paletteCursor ? 'bg-emerald-500/15 text-emerald-200' : 'hover:bg-slate-800/60 text-slate-200'
                  }`}
                >
                  <div>
                    <span className="font-mono font-bold text-emerald-300 mr-2">:{entry.cmd}</span>
                    <span className="font-semibold">{entry.label}</span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-400 truncate max-w-[220px]">
                    {entry.desc}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Shortcuts Help Modal (?) */}
      {helpOpen && (
        <div
          className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
          onClick={() => setHelpOpen(false)}
        >
          <div
            className="w-full max-w-2xl rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Command className="w-4 h-4 text-emerald-400" /> K9s Browser Keyboard Shortcuts
              </h3>
              <button type="button" onClick={() => setHelpOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-2.5 max-h-[75vh] overflow-y-auto text-xs">
              {KEYBOARD_SHORTCUTS.map((sc) => (
                <div
                  key={sc.key}
                  className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3"
                >
                  <kbd className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-emerald-300 font-mono text-[11px] shrink-0">
                    {sc.key}
                  </kbd>
                  <span className="text-slate-300 leading-snug">{sc.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Keyboard Scale Modal (s) */}
      {scaleTarget && (
        <div
          className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
          onClick={() => setScaleTarget(null)}
        >
          <div
            className="w-full max-w-sm rounded-2xl bg-slate-900 border border-slate-700 p-5 space-y-4 text-xs"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-sm font-bold text-white font-mono">
              Scale {scaleTarget.kind}/{scaleTarget.name}
            </h3>
            <div>
              <label className="block text-slate-400 mb-1">Desired Replicas (0–200)</label>
              <input
                type="number"
                min={0}
                max={200}
                value={scaleVal}
                onChange={(e) => setScaleVal(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setScaleTarget(null)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  const res = await executeK3sAction({
                    action: 'scale',
                    resource: activeResource,
                    namespace: scaleTarget.namespace,
                    name: scaleTarget.name,
                    replicas: scaleVal,
                  });
                  showToast(res.success, res.message || 'Scaled workload');
                  setScaleTarget(null);
                  refreshResourceList();
                }}
                className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold"
              >
                Apply Scale
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Row Delete Confirmation Modal */}
      {deleteTarget && (
        <div
          className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
          onClick={() => setDeleteTarget(null)}
        >
          <div
            className="w-full max-w-md rounded-2xl bg-slate-900 border border-rose-500/40 p-5 space-y-4 text-xs"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-sm font-bold text-rose-300">Confirm Resource Deletion</h3>
            <p className="text-slate-300">
              Delete <code className="font-mono text-white font-bold">{deleteTarget.kind}/{deleteTarget.name}</code>
              {deleteTarget.namespace ? ` in namespace '${deleteTarget.namespace}'` : ''}?
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  const res = await executeK3sAction({
                    action: 'delete',
                    resource: activeResource,
                    namespace: deleteTarget.namespace,
                    name: deleteTarget.name,
                  });
                  showToast(res.success, res.message || 'Resource deleted');
                  setDeleteTarget(null);
                  refreshResourceList();
                  refreshClusterTelemetry();
                }}
                className="px-3.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Inspector Drawer */}
      <K3sInspectorDrawer
        open={drawerOpen}
        loading={drawerLoading}
        data={drawerData}
        error={drawerError}
        activeTab={drawerTab}
        onTabChange={setDrawerTab}
        onClose={() => setDrawerOpen(false)}
        initialPreviousLogs={drawerPrevLogs}
        onRefresh={(decodeSecret) => {
          if (!drawerTarget) return;
          openInspector({
            resource: drawerTarget.resource,
            name: drawerTarget.name,
            namespace: drawerTarget.namespace,
            tab: drawerTab,
            decode: decodeSecret ?? drawerTarget.decode,
          });
        }}
        onNavigateRelated={(rel) => {
          openInspector({
            resource: rel.resource,
            name: rel.name,
            namespace: rel.namespace,
            tab: 'overview',
          });
        }}
        onActionSuccess={(msg, deleted) => {
          showToast(true, msg);
          if (deleted) {
            setDrawerOpen(false);
          }
          refreshResourceList();
          refreshClusterTelemetry();
        }}
      />
    </div>
  );
}
