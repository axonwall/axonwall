'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  Cpu,
  Download,
  Eye,
  EyeOff,
  FileCode,
  FileText,
  Globe,
  HardDrive,
  KeyRound,
  Layers,
  Lock,
  Maximize2,
  Minimize2,
  Pause,
  Play,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Trash2,
  X,
} from 'lucide-react';
import {
  executeK3sAction,
  getK3sPodLogsAction,
} from '@/server/agent';
import {
  formatAge,
  formatBytes,
  formatCpuMillis,
  getStatusBadgeClass,
  type K3sActionRequest,
  type K3sResourceInspectResponse,
} from './types';

export type InspectorTab = 'overview' | 'describe' | 'yaml' | 'logs' | 'exec' | 'events';

interface K3sInspectorDrawerProps {
  open: boolean;
  loading: boolean;
  data: K3sResourceInspectResponse | null;
  error?: string | null;
  activeTab: InspectorTab;
  onTabChange: (tab: InspectorTab) => void;
  onClose: () => void;
  onRefresh: (decodeSecret?: boolean) => void;
  onNavigateRelated: (opts: {
    resource: string;
    name: string;
    namespace?: string;
    tab?: InspectorTab;
  }) => void;
  onActionSuccess: (msg: string, deleted?: boolean) => void;
  initialPreviousLogs?: boolean;
}

const LOG_SUPP_KINDS = new Set(['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job']);

const EXEC_QUICK_TOOLS = [
  { label: 'ps aux', cmd: 'ps aux' },
  { label: 'env', cmd: 'env | sort' },
  { label: 'id / uid', cmd: 'id' },
  { label: 'ip addr', cmd: 'ip addr 2>/dev/null || ifconfig' },
  { label: 'sockets', cmd: 'ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null' },
  { label: 'resolv.conf', cmd: 'cat /etc/resolv.conf' },
  { label: 'df -h', cmd: 'df -h' },
];

export function K3sInspectorDrawer({
  open,
  loading,
  data,
  error,
  activeTab,
  onTabChange,
  onClose,
  onRefresh,
  onNavigateRelated,
  onActionSuccess,
  initialPreviousLogs = false,
}: K3sInspectorDrawerProps) {
  const [sizeMode, setSizeMode] = useState<'wide' | 'full'>('wide');
  const [actionMsg, setActionMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [acting, setActing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<'none' | 'soft' | 'force'>('none');
  const [confirmDrain, setConfirmDrain] = useState(false);

  // Copy feedback
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Describe search
  const [descSearch, setDescSearch] = useState('');

  // Editable YAML
  const [yamlDraft, setYamlDraft] = useState('');
  const [yamlDirty, setYamlDirty] = useState(false);

  // Secret reveal state per key
  const [revealedKeys, setRevealedKeys] = useState<Record<string, boolean>>({});

  // Scale input
  const [scaleReplicas, setScaleReplicas] = useState<number>(1);

  // Logs state
  const [selectedContainer, setSelectedContainer] = useState<string>('');
  const [logTail, setLogTail] = useState<number>(300);
  const [logPrevious, setLogPrevious] = useState<boolean>(initialPreviousLogs);
  const [logTimestamps, setLogTimestamps] = useState<boolean>(true);
  const [logWrap, setLogWrap] = useState<boolean>(false);
  const [logAutoScroll, setLogAutoScroll] = useState<boolean>(true);
  const [logFilter, setLogFilter] = useState<string>('');
  const [logLines, setLogLines] = useState<string[]>([]);
  const [logLoading, setLogLoading] = useState<boolean>(false);
  const [logError, setLogError] = useState<string | null>(null);
  const [streamingLogs, setStreamingLogs] = useState<boolean>(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  // Exec state
  const [execCmd, setExecCmd] = useState('');
  const [execRunning, setExecRunning] = useState(false);
  const [execHistory, setExecHistory] = useState<
    { cmd: string; container: string; output: string; exitCode: number; latencyMs?: number; ts: string }[]
  >([]);
  const execEndRef = useRef<HTMLDivElement>(null);

  const obj = data?.object || {};
  const meta = (obj.metadata as Record<string, any>) || {};
  const spec = (obj.spec as Record<string, any>) || {};
  const status = (obj.status as Record<string, any>) || {};
  const kind = data?.kind || '';

  const containerNames = useMemo(() => {
    const names: string[] = [];
    const tplSpec = spec?.template?.spec || spec?.jobTemplate?.spec?.template?.spec || spec;
    if (Array.isArray(tplSpec?.containers)) {
      for (const c of tplSpec.containers) {
        if (c?.name) names.push(String(c.name));
      }
    }
    if (Array.isArray(tplSpec?.initContainers)) {
      for (const c of tplSpec.initContainers) {
        if (c?.name && !names.includes(String(c.name))) names.push(String(c.name));
      }
    }
    return names;
  }, [spec]);

  // Reset per-object state when target changes
  const targetIdentity = `${data?.resource || ''}/${data?.namespace || ''}/${data?.name || ''}`;
  useEffect(() => {
    setActionMsg(null);
    setConfirmDelete('none');
    setConfirmDrain(false);
    setRevealedKeys({});
    setExecHistory([]);
    setLogLines([]);
    setLogError(null);
    stopLogStream();
    if (data?.yaml) {
      setYamlDraft(data.yaml);
      setYamlDirty(false);
    } else {
      setYamlDraft('');
      setYamlDirty(false);
    }
    if (typeof spec?.replicas === 'number') {
      setScaleReplicas(spec.replicas);
    }
    if (containerNames.length > 0) {
      setSelectedContainer(containerNames[0]);
    } else {
      setSelectedContainer('');
    }
  }, [targetIdentity]);

  useEffect(() => {
    setLogPrevious(initialPreviousLogs);
  }, [initialPreviousLogs, targetIdentity]);

  useEffect(() => {
    if (data?.yaml && !yamlDirty) {
      setYamlDraft(data.yaml);
    }
  }, [data?.yaml, yamlDirty]);

  const stopLogStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setStreamingLogs(false);
  };

  useEffect(() => {
    if (!open) {
      stopLogStream();
    }
    return () => stopLogStream();
  }, [open]);

  const fetchSnapshotLogs = async () => {
    if (!data?.name || !LOG_SUPP_KINDS.has(kind)) return;
    stopLogStream();
    setLogLoading(true);
    setLogError(null);
    try {
      const resp = await getK3sPodLogsAction({
        namespace: data.namespace || 'default',
        name: data.name,
        resource: data.resource,
        container: selectedContainer || undefined,
        tail: logTail,
        previous: logPrevious,
        timestamps: logTimestamps,
      });
      if (resp.error) {
        setLogError(resp.error);
        setLogLines([]);
      } else {
        setLogLines(resp.logs ? resp.logs.replace(/\n$/, '').split('\n') : []);
      }
    } catch (e: any) {
      setLogError(e?.message || 'Failed to load logs');
    } finally {
      setLogLoading(false);
    }
  };

  const startLiveLogStream = () => {
    if (!data?.name || !LOG_SUPP_KINDS.has(kind)) return;
    stopLogStream();
    setLogError(null);
    setLogLines([]);
    setStreamingLogs(true);

    const qs = new URLSearchParams();
    qs.set('namespace', data.namespace || 'default');
    qs.set('name', data.name);
    qs.set('resource', data.resource);
    if (selectedContainer) qs.set('container', selectedContainer);
    qs.set('tail', String(logTail));
    if (logPrevious) qs.set('previous', 'true');
    if (logTimestamps) qs.set('timestamps', 'true');

    const es = new EventSource(`/api/k3s/logs/stream?${qs.toString()}`);
    eventSourceRef.current = es;

    es.addEventListener('log', (ev: MessageEvent) => {
      try {
        const parsed = JSON.parse(ev.data);
        if (typeof parsed.line === 'string') {
          setLogLines((prev) => {
            const next = [...prev, parsed.line];
            return next.length > 3500 ? next.slice(next.length - 3500) : next;
          });
        }
      } catch {}
    });

    es.addEventListener('error', (ev: Event) => {
      const msgEv = ev as MessageEvent;
      if (msgEv.data) {
        try {
          const parsed = JSON.parse(msgEv.data);
          if (parsed.error) setLogError(parsed.error);
        } catch {}
      }
      es.close();
      eventSourceRef.current = null;
      setStreamingLogs(false);
    });

    es.addEventListener('done', () => {
      es.close();
      eventSourceRef.current = null;
      setStreamingLogs(false);
    });
  };

  useEffect(() => {
    if (open && activeTab === 'logs' && data?.name && LOG_SUPP_KINDS.has(kind)) {
      fetchSnapshotLogs();
    } else if (activeTab !== 'logs') {
      stopLogStream();
    }
  }, [open, activeTab, targetIdentity, selectedContainer, logTail, logPrevious, logTimestamps]);

  useEffect(() => {
    if (logAutoScroll && activeTab === 'logs') {
      logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logLines, logAutoScroll, activeTab]);

  useEffect(() => {
    if (activeTab === 'exec') {
      execEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [execHistory, activeTab]);

  const filteredDescribeLines = useMemo(() => {
    const raw = data?.describe || '';
    if (!descSearch.trim()) return raw;
    const q = descSearch.trim().toLowerCase();
    return raw
      .split('\n')
      .filter((line) => line.toLowerCase().includes(q))
      .join('\n');
  }, [data?.describe, descSearch]);

  if (!open) return null;

  const copyText = (key: string, text: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1600);
  };

  const runK9sOp = async (payload: K3sActionRequest, label: string, isDelete = false) => {
    setActing(true);
    setActionMsg(null);
    try {
      const res = await executeK3sAction(payload);
      setActionMsg({
        ok: res.success,
        text: res.message || res.output || `${label} ${res.success ? 'succeeded' : 'failed'}`,
      });
      if (res.success) {
        if (isDelete) {
          onActionSuccess(res.message || `${label} completed`, true);
        } else {
          onActionSuccess(res.message || `${label} completed`, false);
          onRefresh();
        }
      }
    } catch (e: any) {
      setActionMsg({ ok: false, text: e?.message || `${label} failed` });
    } finally {
      setActing(false);
      setConfirmDelete('none');
      setConfirmDrain(false);
    }
  };

  const handleExec = async (cmdOverride?: string) => {
    const cmd = (cmdOverride ?? execCmd).trim();
    if (!cmd || !data?.name || execRunning) return;
    setExecRunning(true);
    try {
      const res = await executeK3sAction({
        action: 'exec',
        namespace: data.namespace || 'default',
        name: data.name,
        container: selectedContainer || undefined,
        command: cmd,
      });
      setExecHistory((prev) => [
        ...prev,
        {
          cmd,
          container: selectedContainer || containerNames[0] || 'default',
          output: res.output || res.message || '<no output>',
          exitCode: res.exitCode ?? (res.success ? 0 : 1),
          latencyMs: res.latencyMs,
          ts: new Date().toLocaleTimeString(),
        },
      ]);
      if (!cmdOverride) setExecCmd('');
    } catch (e: any) {
      setExecHistory((prev) => [
        ...prev,
        {
          cmd,
          container: selectedContainer || 'default',
          output: `Execution error: ${e?.message || 'Failed to exec'}`,
          exitCode: 1,
          ts: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setExecRunning(false);
    }
  };

  const filteredLogLines = logFilter.trim()
    ? logLines.filter((l) => l.toLowerCase().includes(logFilter.trim().toLowerCase()))
    : logLines;

  const drawerWidthClass =
    sizeMode === 'full'
      ? 'fixed inset-3 rounded-2xl'
      : 'fixed top-0 right-0 bottom-0 w-full max-w-5xl border-l';

  const supportsLogs = LOG_SUPP_KINDS.has(kind);
  const supportsExec = kind === 'Pod';
  const supportsScale = kind === 'Deployment' || kind === 'StatefulSet' || kind === 'ReplicaSet';
  const supportsRestart = kind === 'Deployment' || kind === 'StatefulSet' || kind === 'DaemonSet';
  const isNode = kind === 'Node';
  const isCronJob = kind === 'CronJob';
  const isSecret = kind === 'Secret';

  const labels = (meta.labels as Record<string, string>) || {};
  const annotations = (meta.annotations as Record<string, string>) || {};

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm">
      <div
        className={`${drawerWidthClass} bg-slate-950 border-slate-800 shadow-2xl flex flex-col overflow-hidden`}
      >
        {/* Drawer Header */}
        <div className="px-5 py-4 bg-slate-900 border-b border-slate-800 flex flex-wrap items-start justify-between gap-3 shrink-0">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-mono text-[11px] font-bold">
                {kind || data?.resource || 'Resource'}
              </span>
              {data?.namespace && (
                <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-sky-300 font-mono text-[11px]">
                  ns: {data.namespace}
                </span>
              )}
              <h2 className="text-base font-bold text-white font-mono truncate">
                {data?.name || 'Inspecting...'}
              </h2>
              {meta.creationTimestamp && (
                <span className="text-xs font-mono text-slate-400">
                  Age {formatAge(meta.creationTimestamp)}
                </span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400">
              {data?.apiVersion && <span>apiVersion: {data.apiVersion}</span>}
              {meta.uid && <span className="hidden sm:inline">uid: {meta.uid}</span>}
              {data?.name && (
                <button
                  type="button"
                  onClick={() =>
                    copyText(
                      'kubectl',
                      `kubectl get ${data.resource} ${data.name}${data.namespace ? ` -n ${data.namespace}` : ''} -o yaml`
                    )
                  }
                  className="inline-flex items-center gap-1 text-sky-400 hover:text-sky-300"
                >
                  {copiedKey === 'kubectl' ? (
                    <Check className="w-3 h-3" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  Copy kubectl
                </button>
              )}
            </div>
          </div>

          {/* Controls & Window Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            {supportsScale && (
              <div className="inline-flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs">
                <span className="text-slate-400 font-mono">Replicas:</span>
                <input
                  type="number"
                  min={0}
                  max={200}
                  value={scaleReplicas}
                  onChange={(e) => setScaleReplicas(Number(e.target.value))}
                  className="w-12 bg-slate-900 border border-slate-700 rounded px-1.5 py-0.5 text-white font-mono text-center"
                />
                <button
                  type="button"
                  disabled={acting}
                  onClick={() =>
                    runK9sOp(
                      {
                        action: 'scale',
                        resource: data!.resource,
                        namespace: data!.namespace,
                        name: data!.name,
                        replicas: scaleReplicas,
                      },
                      'Scale'
                    )
                  }
                  className="px-2 py-0.5 rounded bg-sky-600 hover:bg-sky-500 text-white font-semibold"
                >
                  Scale
                </button>
              </div>
            )}

            {supportsRestart && (
              <>
                <button
                  type="button"
                  disabled={acting}
                  onClick={() =>
                    runK9sOp(
                      {
                        action: 'rollout-restart',
                        resource: data!.resource,
                        namespace: data!.namespace,
                        name: data!.name,
                      },
                      'Rollout Restart'
                    )
                  }
                  className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-emerald-300 font-medium inline-flex items-center gap-1.5"
                >
                  <RotateCcw className="w-3.5 h-3.5" /> Restart
                </button>
                <button
                  type="button"
                  disabled={acting}
                  onClick={() =>
                    runK9sOp(
                      {
                        action: 'rollout-undo',
                        resource: data!.resource,
                        namespace: data!.namespace,
                        name: data!.name,
                      },
                      'Rollout Undo'
                    )
                  }
                  className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-amber-300 font-medium"
                >
                  Undo Rollout
                </button>
              </>
            )}

            {isNode && (
              <>
                <button
                  type="button"
                  disabled={acting}
                  onClick={() =>
                    runK9sOp(
                      {
                        action: spec.unschedulable ? 'uncordon' : 'cordon',
                        name: data!.name,
                      },
                      spec.unschedulable ? 'Uncordon' : 'Cordon'
                    )
                  }
                  className="px-2.5 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-xs text-amber-300 font-medium"
                >
                  {spec.unschedulable ? 'Uncordon (u)' : 'Cordon (c)'}
                </button>
                <button
                  type="button"
                  disabled={acting}
                  onClick={() => setConfirmDrain(true)}
                  className="px-2.5 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-xs text-rose-300 font-medium"
                >
                  Drain Node
                </button>
              </>
            )}

            {isCronJob && (
              <>
                <button
                  type="button"
                  disabled={acting}
                  onClick={() =>
                    runK9sOp(
                      {
                        action: 'trigger-cronjob',
                        namespace: data!.namespace,
                        name: data!.name,
                      },
                      'Trigger Job'
                    )
                  }
                  className="px-2.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs text-white font-semibold"
                >
                  Trigger Now (t)
                </button>
                <button
                  type="button"
                  disabled={acting}
                  onClick={() =>
                    runK9sOp(
                      {
                        action: 'suspend-cronjob',
                        namespace: data!.namespace,
                        name: data!.name,
                        suspend: !Boolean(spec.suspend),
                      },
                      spec.suspend ? 'Resume CronJob' : 'Suspend CronJob'
                    )
                  }
                  className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-amber-300"
                >
                  {spec.suspend ? 'Resume' : 'Suspend'}
                </button>
              </>
            )}

            {isSecret && (
              <button
                type="button"
                onClick={() => onRefresh(data?.secretRedacted ? true : false)}
                className="px-2.5 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-xs text-amber-300 font-medium inline-flex items-center gap-1.5"
              >
                {data?.secretRedacted ? (
                  <>
                    <Eye className="w-3.5 h-3.5" /> Decode Secret (x)
                  </>
                ) : (
                  <>
                    <EyeOff className="w-3.5 h-3.5" /> Mask Secret
                  </>
                )}
              </button>
            )}

            {data?.name && (
              <button
                type="button"
                disabled={acting}
                onClick={() => setConfirmDelete('soft')}
                className="px-2.5 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-xs text-rose-300 font-medium inline-flex items-center gap-1"
              >
                <Trash2 className="w-3.5 h-3.5" /> Delete
              </button>
            )}

            <button
              type="button"
              onClick={() => onRefresh()}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              type="button"
              onClick={() => setSizeMode((m) => (m === 'wide' ? 'full' : 'wide'))}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
              title={sizeMode === 'wide' ? 'Maximize Drawer' : 'Restore Width'}
            >
              {sizeMode === 'wide' ? (
                <Maximize2 className="w-4 h-4" />
              ) : (
                <Minimize2 className="w-4 h-4" />
              )}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
              title="Close (Esc)"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Confirm Bars & Feedback Banners */}
        {confirmDelete !== 'none' && data && (
          <div className="px-5 py-3 bg-rose-950/60 border-b border-rose-500/40 flex flex-wrap items-center justify-between gap-3 text-xs">
            <span className="text-rose-200 font-medium">
              Confirm deleting <code className="font-mono font-bold">{data.resource}/{data.name}</code>
              {data.namespace ? ` in namespace '${data.namespace}'` : ''}?
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={acting}
                onClick={() =>
                  runK9sOp(
                    {
                      action: 'delete',
                      resource: data.resource,
                      namespace: data.namespace,
                      name: data.name,
                      force: false,
                    },
                    'Delete',
                    true
                  )
                }
                className="px-3 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white font-semibold"
              >
                Confirm Delete
              </button>
              <button
                type="button"
                disabled={acting}
                onClick={() =>
                  runK9sOp(
                    {
                      action: 'delete',
                      resource: data.resource,
                      namespace: data.namespace,
                      name: data.name,
                      force: true,
                    },
                    'Force Delete',
                    true
                  )
                }
                className="px-3 py-1 rounded bg-rose-800 hover:bg-rose-700 text-rose-100 font-semibold"
              >
                Force (--grace-period=0)
              </button>
              <button
                type="button"
                onClick={() => setConfirmDelete('none')}
                className="px-2.5 py-1 rounded bg-slate-800 text-slate-300"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {confirmDrain && data && (
          <div className="px-5 py-3 bg-amber-950/60 border-b border-amber-500/40 flex flex-wrap items-center justify-between gap-3 text-xs">
            <span className="text-amber-200 font-medium">
              Drain node <code className="font-mono font-bold">{data.name}</code> (--ignore-daemonsets --delete-emptydir-data)? Pods will be evicted.
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={acting}
                onClick={() => runK9sOp({ action: 'drain', name: data.name }, 'Drain Node')}
                className="px-3 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-semibold"
              >
                Confirm Drain
              </button>
              <button
                type="button"
                onClick={() => setConfirmDrain(false)}
                className="px-2.5 py-1 rounded bg-slate-800 text-slate-300"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {actionMsg && (
          <div
            className={`px-5 py-2.5 border-b text-xs font-mono flex items-center justify-between ${
              actionMsg.ok
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
            }`}
          >
            <span className="truncate">{actionMsg.text}</span>
            <button type="button" onClick={() => setActionMsg(null)} className="text-slate-400 hover:text-white ml-2">
              ✕
            </button>
          </div>
        )}

        {/* Drawer Tab Bar */}
        <div className="px-5 bg-slate-900/70 border-b border-slate-800 flex flex-wrap items-center gap-1 shrink-0">
          {(
            [
              { id: 'overview', label: 'Overview & X-Ray', icon: Layers, show: true },
              { id: 'describe', label: 'Describe (d)', icon: FileText, show: true },
              { id: 'yaml', label: 'YAML & Apply (y)', icon: FileCode, show: true },
              { id: 'logs', label: 'Live Logs (l)', icon: Activity, show: supportsLogs },
              { id: 'exec', label: 'Shell Exec (s)', icon: Terminal, show: supportsExec },
              {
                id: 'events',
                label: `Events (${data?.events?.length || 0})`,
                icon: AlertTriangle,
                show: true,
              },
            ] as const
          )
            .filter((t) => t.show)
            .map((t) => {
              const Icon = t.icon;
              const isAct = activeTab === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => onTabChange(t.id)}
                  className={`px-3.5 py-2.5 text-xs font-medium flex items-center gap-1.5 border-b-2 transition ${
                    isAct
                      ? 'border-emerald-400 text-emerald-300 bg-slate-950/60'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {t.label}
                </button>
              );
            })}
        </div>

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loading && !data ? (
            <div className="py-20 text-center text-xs font-mono text-slate-400 flex flex-col items-center gap-3">
              <RefreshCw className="w-6 h-6 animate-spin text-emerald-400" />
              <span>Fetching deep Kubernetes object state, events &amp; X-Ray relations...</span>
            </div>
          ) : error && !data ? (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300 font-mono">
              {error}
            </div>
          ) : !data ? (
            <div className="text-xs text-slate-500 text-center py-12">Select a resource to inspect.</div>
          ) : activeTab === 'overview' ? (
            <div className="space-y-5">
              {/* X-Ray Relations Strip */}
              {data.related && data.related.length > 0 && (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
                  <div className="text-xs font-bold text-white flex items-center gap-2">
                    <ArrowRight className="w-4 h-4 text-emerald-400" /> X-Ray Resource Relations
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {data.related.map((rel, idx) => (
                      <button
                        key={`${rel.relation}-${rel.resource}-${rel.name}-${idx}`}
                        type="button"
                        onClick={() =>
                          onNavigateRelated({
                            resource: rel.resource,
                            name: rel.name,
                            namespace: rel.namespace,
                          })
                        }
                        className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-500/40 text-left transition flex items-center gap-2 text-xs"
                      >
                        <span className="text-[10px] font-mono text-slate-400 uppercase">
                          {rel.relation}:
                        </span>
                        <span className="font-mono text-emerald-300 font-semibold">
                          {rel.kind}/{rel.name}
                        </span>
                        {rel.status && (
                          <span
                            className={`px-1.5 py-0.5 rounded border text-[10px] font-mono ${getStatusBadgeClass(
                              rel.statusTone
                            )}`}
                          >
                            {rel.status}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* POD DEEP DIVE */}
              {kind === 'Pod' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[11px]">Phase / Pod IP</span>
                      <span className="font-mono font-bold text-white mt-0.5 block">
                        {status.phase || 'Unknown'} • {status.podIP || 'Pending'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[11px]">Scheduled Node</span>
                      <span className="font-mono font-bold text-sky-300 mt-0.5 block">
                        {spec.nodeName || '<unscheduled>'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[11px]">QoS Class / SA</span>
                      <span className="font-mono font-bold text-white mt-0.5 block">
                        {status.qosClass || 'BestEffort'} • {spec.serviceAccountName || 'default'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[11px]">Isolation / eBPF Token</span>
                      <span className="font-mono font-bold text-emerald-300 mt-0.5 block">
                        {spec.hostUsers === false ? 'UserNS (hostUsers: false)' : 'Standard HostNS'}
                      </span>
                    </div>
                  </div>

                  {/* Containers */}
                  <div className="space-y-2.5">
                    <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                      Containers ({Array.isArray(spec.containers) ? spec.containers.length : 0})
                    </h4>
                    {(Array.isArray(spec.containers) ? spec.containers : []).map((c: any) => {
                      const cs = (Array.isArray(status.containerStatuses)
                        ? status.containerStatuses
                        : []
                      ).find((x: any) => x.name === c.name);
                      const stateKey = cs?.state ? Object.keys(cs.state)[0] : 'unknown';
                      const stateObj = cs?.state?.[stateKey] || {};
                      return (
                        <div
                          key={c.name}
                          className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono font-bold text-white text-sm">{c.name}</span>
                              <span
                                className={`px-2 py-0.5 rounded border text-[10px] font-mono ${
                                  cs?.ready
                                    ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                                    : 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                                }`}
                              >
                                {stateKey}
                                {stateObj?.reason ? `: ${stateObj.reason}` : ''}
                                {cs ? ` • Restarts: ${cs.restartCount ?? 0}` : ''}
                              </span>
                            </div>
                            <span className="font-mono text-sky-300 text-[11px]">{c.image}</span>
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] font-mono">
                            <div className="p-2 rounded bg-slate-950 border border-slate-800">
                              <span className="text-slate-400">Requests / Limits: </span>
                              <span className="text-slate-200">
                                CPU {c.resources?.requests?.cpu || '—'}/{c.resources?.limits?.cpu || '—'} •
                                MEM {c.resources?.requests?.memory || '—'}/{c.resources?.limits?.memory || '—'}
                              </span>
                            </div>
                            <div className="p-2 rounded bg-slate-950 border border-slate-800">
                              <span className="text-slate-400">Ports: </span>
                              <span className="text-slate-200">
                                {Array.isArray(c.ports) && c.ports.length > 0
                                  ? c.ports
                                      .map((p: any) => `${p.containerPort}/${p.protocol || 'TCP'}`)
                                      .join(', ')
                                  : '<none>'}
                              </span>
                            </div>
                            <div className="p-2 rounded bg-slate-950 border border-slate-800 flex flex-wrap gap-1.5 items-center">
                              <span className="text-slate-400">Probes:</span>
                              {c.livenessProbe && (
                                <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300">
                                  Liveness
                                </span>
                              )}
                              {c.readinessProbe && (
                                <span className="px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-300">
                                  Readiness
                                </span>
                              )}
                              {c.startupProbe && (
                                <span className="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300">
                                  Startup
                                </span>
                              )}
                              {!c.livenessProbe && !c.readinessProbe && !c.startupProbe && (
                                <span className="text-slate-500">&lt;none&gt;</span>
                              )}
                            </div>
                          </div>

                          {Array.isArray(c.volumeMounts) && c.volumeMounts.length > 0 && (
                            <div className="text-[11px] font-mono text-slate-400">
                              <span className="text-slate-300">Mounts: </span>
                              {c.volumeMounts
                                .map((m: any) => `${m.name}→${m.mountPath}${m.readOnly ? '(ro)' : ''}`)
                                .join(' • ')}
                            </div>
                          )}

                          {Array.isArray(c.env) && c.env.length > 0 && (
                            <div className="text-[11px] font-mono text-slate-400 flex flex-wrap gap-1.5">
                              <span className="text-slate-300">Env: </span>
                              {c.env.slice(0, 14).map((e: any) => (
                                <span
                                  key={e.name}
                                  className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300"
                                >
                                  {e.name}=
                                  {e.valueFrom?.secretKeyRef
                                    ? `secret(${e.valueFrom.secretKeyRef.name})`
                                    : e.valueFrom?.configMapKeyRef
                                      ? `cm(${e.valueFrom.configMapKeyRef.name})`
                                      : String(e.value ?? '').slice(0, 28)}
                                </span>
                              ))}
                              {c.env.length > 14 && (
                                <span className="text-slate-500">+{c.env.length - 14} more</span>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* Port Forward Helper */}
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                    <span className="text-slate-400">
                      Quick CLI: <span className="text-emerald-300">kubectl port-forward -n {data.namespace || 'default'} pod/{data.name} 8080:80</span>
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        copyText(
                          'pf',
                          `kubectl port-forward -n ${data.namespace || 'default'} pod/${data.name} 8080:80`
                        )
                      }
                      className="text-sky-400 hover:underline inline-flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                  </div>
                </div>
              )}

              {/* SERVICE DEEP DIVE */}
              {kind === 'Service' && (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                    <div>
                      <span className="text-slate-400 block text-[10px]">Type</span>
                      <span className="text-white font-bold">{spec.type || 'ClusterIP'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">Cluster IP</span>
                      <span className="text-white">{spec.clusterIP || 'None'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">Session Affinity</span>
                      <span className="text-slate-300">{spec.sessionAffinity || 'None'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">External / LB IP</span>
                      <span className="text-emerald-300">
                        {(status.loadBalancer?.ingress || [])
                          .map((x: any) => x.ip || x.hostname)
                          .concat(spec.externalIPs || [])
                          .join(', ') || '<none>'}
                      </span>
                    </div>
                  </div>
                  {Array.isArray(spec.ports) && spec.ports.length > 0 && (
                    <table className="w-full text-left border-collapse font-mono text-[11px]">
                      <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="py-2 px-3">Port Name</th>
                          <th className="py-2 px-3">Service Port</th>
                          <th className="py-2 px-3">Target Port</th>
                          <th className="py-2 px-3">NodePort</th>
                          <th className="py-2 px-3">Protocol</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {spec.ports.map((p: any, i: number) => (
                          <tr key={i}>
                            <td className="py-1.5 px-3 text-slate-300">{p.name || '—'}</td>
                            <td className="py-1.5 px-3 text-white font-bold">{p.port}</td>
                            <td className="py-1.5 px-3 text-sky-300">{String(p.targetPort ?? p.port)}</td>
                            <td className="py-1.5 px-3 text-amber-300">{p.nodePort || '—'}</td>
                            <td className="py-1.5 px-3 text-slate-400">{p.protocol || 'TCP'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {/* INGRESS DEEP DIVE */}
              {kind === 'Ingress' && (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono">
                    <div>
                      <span className="text-slate-400 block text-[10px]">IngressClass</span>
                      <span className="text-white font-bold">{spec.ingressClassName || 'default'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">TLS Certificates</span>
                      <span className="text-emerald-300">
                        {Array.isArray(spec.tls) && spec.tls.length > 0
                          ? spec.tls.map((t: any) => t.secretName || (t.hosts || []).join(',')).join('; ')
                          : 'None (HTTP)'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">LB Address</span>
                      <span className="text-sky-300">
                        {(status.loadBalancer?.ingress || [])
                          .map((x: any) => x.ip || x.hostname)
                          .join(', ') || 'Pending'}
                      </span>
                    </div>
                  </div>
                  <table className="w-full text-left border-collapse font-mono text-[11px]">
                    <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="py-2 px-3">Host</th>
                        <th className="py-2 px-3">Path</th>
                        <th className="py-2 px-3">PathType</th>
                        <th className="py-2 px-3">Backend Service : Port</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {(Array.isArray(spec.rules) ? spec.rules : []).flatMap((r: any, ri: number) =>
                        (Array.isArray(r.http?.paths) ? r.http.paths : []).map((p: any, pi: number) => (
                          <tr key={`${ri}-${pi}`}>
                            <td className="py-1.5 px-3 text-white font-bold">{r.host || '*'}</td>
                            <td className="py-1.5 px-3 text-slate-300">{p.path || '/'}</td>
                            <td className="py-1.5 px-3 text-slate-400">{p.pathType || 'Prefix'}</td>
                            <td className="py-1.5 px-3 text-cyan-300">
                              {p.backend?.service?.name || p.backend?.serviceName}:
                              {p.backend?.service?.port?.number || p.backend?.service?.port?.name || p.backend?.servicePort}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              )}

              {/* WORKLOAD DEEP DIVE (Deployment / StatefulSet / DaemonSet / Job / CronJob) */}
              {(kind === 'Deployment' ||
                kind === 'StatefulSet' ||
                kind === 'DaemonSet' ||
                kind === 'ReplicaSet' ||
                kind === 'Job' ||
                kind === 'CronJob') && (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                    <div>
                      <span className="text-slate-400 block text-[10px]">Desired / Ready</span>
                      <span className="text-white font-bold">
                        {kind === 'DaemonSet'
                          ? `${status.numberReady ?? 0}/${status.desiredNumberScheduled ?? 0}`
                          : kind === 'Job'
                            ? `${status.succeeded ?? 0}/${spec.completions ?? 1}`
                            : kind === 'CronJob'
                              ? spec.suspend
                                ? 'Suspended'
                                : 'Scheduled'
                              : `${status.readyReplicas ?? 0}/${spec.replicas ?? 0}`}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">
                        {kind === 'CronJob' ? 'Cron Schedule' : 'Strategy / Update'}
                      </span>
                      <span className="text-sky-300 font-bold">
                        {kind === 'CronJob'
                          ? spec.schedule || '—'
                          : spec.strategy?.type || spec.updateStrategy?.type || 'RollingUpdate'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">Available / Updated</span>
                      <span className="text-emerald-300 font-bold">
                        {status.availableReplicas ?? status.numberAvailable ?? status.active ?? 0} /{' '}
                        {status.updatedReplicas ?? status.updatedNumberScheduled ?? 0}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">Selector</span>
                      <span className="text-slate-300 truncate block">
                        {spec.selector?.matchLabels
                          ? Object.entries(spec.selector.matchLabels)
                              .map(([k, v]) => `${k}=${v}`)
                              .join(', ')
                          : '—'}
                      </span>
                    </div>
                  </div>
                  {containerNames.length > 0 && (
                    <div className="text-[11px] font-mono text-slate-300 bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                      Containers:{' '}
                      {(
                        spec?.template?.spec?.containers ||
                        spec?.jobTemplate?.spec?.template?.spec?.containers ||
                        []
                      )
                        .map((c: any) => `${c.name} (${c.image})`)
                        .join(' • ')}
                    </div>
                  )}
                </div>
              )}

              {/* STORAGE DEEP DIVE (PVC / PV / StorageClass) */}
              {(kind === 'PersistentVolumeClaim' ||
                kind === 'PersistentVolume' ||
                kind === 'StorageClass') && (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div>
                    <span className="text-slate-400 block text-[10px]">
                      {kind === 'StorageClass' ? 'Provisioner' : 'Status / Phase'}
                    </span>
                    <span className="text-white font-bold">
                      {kind === 'StorageClass' ? obj.provisioner || '—' : status.phase || 'Pending'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">
                      {kind === 'StorageClass' ? 'Reclaim Policy' : 'Capacity'}
                    </span>
                    <span className="text-emerald-300 font-bold">
                      {kind === 'StorageClass'
                        ? obj.reclaimPolicy || 'Delete'
                        : status.capacity?.storage ||
                          spec.capacity?.storage ||
                          spec.resources?.requests?.storage ||
                          '—'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">
                      {kind === 'StorageClass' ? 'Binding Mode' : 'StorageClass'}
                    </span>
                    <span className="text-sky-300 font-bold">
                      {kind === 'StorageClass'
                        ? obj.volumeBindingMode || 'Immediate'
                        : spec.storageClassName || 'default'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">
                      {kind === 'StorageClass' ? 'Expansion Allowed' : 'Volume / AccessModes'}
                    </span>
                    <span className="text-slate-300 truncate block">
                      {kind === 'StorageClass'
                        ? String(Boolean(obj.allowVolumeExpansion))
                        : `${spec.volumeName || '—'} (${(spec.accessModes || []).join(',')})`}
                    </span>
                  </div>
                </div>
              )}

              {/* NODE DEEP DIVE */}
              {kind === 'Node' && (
                <div className="space-y-4 text-xs">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">CPU Allocatable / Cap</span>
                      <span className="text-white font-bold">
                        {status.allocatable?.cpu} / {status.capacity?.cpu}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">Mem Allocatable / Cap</span>
                      <span className="text-white font-bold">
                        {status.allocatable?.memory} / {status.capacity?.memory}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">Kernel / OS</span>
                      <span className="text-sky-300 font-bold">
                        {status.nodeInfo?.kernelVersion}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">Runtime / Kubelet</span>
                      <span className="text-emerald-300 font-bold">
                        {status.nodeInfo?.containerRuntimeVersion}
                      </span>
                    </div>
                  </div>
                  {Array.isArray(status.conditions) && (
                    <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                      <h4 className="font-bold text-slate-200">Node Conditions</h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {status.conditions.map((c: any) => (
                          <div
                            key={c.type}
                            className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
                          >
                            <span className="font-mono text-white">{c.type}</span>
                            <span
                              className={`font-mono text-[11px] ${
                                (c.type === 'Ready' && c.status === 'True') ||
                                (c.type !== 'Ready' && c.status === 'False')
                                  ? 'text-emerald-400'
                                  : 'text-amber-300'
                              }`}
                            >
                              {c.status} ({c.reason})
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* CONFIGMAP / SECRET KEY-VALUE EXPLORER */}
              {(kind === 'ConfigMap' || kind === 'Secret') && (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
                  <div className="flex items-center justify-between">
                    <h4 className="font-bold text-white flex items-center gap-2">
                      <KeyRound className="w-4 h-4 text-amber-400" />
                      {kind === 'Secret'
                        ? data.secretRedacted
                          ? 'Secret Keys (Redacted — Admin click "Decode Secret (x)" to reveal)'
                          : 'Decoded Secret Values (Admin Cleartext)'
                        : 'ConfigMap Data Entries'}
                    </h4>
                  </div>
                  {kind === 'ConfigMap' ? (
                    <div className="space-y-2">
                      {Object.entries((obj.data as Record<string, string>) || {}).map(([k, v]) => (
                        <div key={k} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                          <div className="flex items-center justify-between font-mono text-emerald-300 font-bold">
                            <span>{k}</span>
                            <button
                              type="button"
                              onClick={() => copyText(`cm-${k}`, String(v))}
                              className="text-sky-400 hover:underline text-[10px]"
                            >
                              {copiedKey === `cm-${k}` ? 'Copied' : 'Copy'}
                            </button>
                          </div>
                          <pre className="text-[11px] text-slate-300 font-mono whitespace-pre-wrap max-h-48 overflow-y-auto">
                            {String(v)}
                          </pre>
                        </div>
                      ))}
                    </div>
                  ) : data.decodedSecretData ? (
                    <div className="space-y-2">
                      {Object.entries(data.decodedSecretData).map(([k, v]) => {
                        const isRev = Boolean(revealedKeys[k]);
                        return (
                          <div key={k} className="p-3 rounded-lg bg-slate-950 border border-amber-500/30 space-y-1">
                            <div className="flex items-center justify-between font-mono">
                              <span className="text-amber-300 font-bold">{k}</span>
                              <div className="flex items-center gap-2 text-[10px]">
                                <button
                                  type="button"
                                  onClick={() =>
                                    setRevealedKeys((prev) => ({ ...prev, [k]: !prev[k] }))
                                  }
                                  className="text-slate-300 hover:text-white"
                                >
                                  {isRev ? 'Hide' : 'Reveal'}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => copyText(`sec-${k}`, v)}
                                  className="text-sky-400 hover:underline"
                                >
                                  {copiedKey === `sec-${k}` ? 'Copied' : 'Copy Value'}
                                </button>
                              </div>
                            </div>
                            <pre className="text-[11px] text-slate-200 font-mono whitespace-pre-wrap break-all">
                              {isRev ? v : '••••••••••••••••••••••••••••'}
                            </pre>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {Object.keys((obj.data as Record<string, any>) || {}).map((k) => (
                        <span
                          key={k}
                          className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 font-mono text-amber-200"
                        >
                          {k}: &lt;redacted&gt;
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Labels & Annotations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                  <span className="font-bold text-slate-300 uppercase text-[10px] tracking-wider block">
                    Labels ({Object.keys(labels).length})
                  </span>
                  {Object.keys(labels).length === 0 ? (
                    <span className="text-slate-500 font-mono">&lt;none&gt;</span>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {Object.entries(labels).map(([k, v]) => (
                        <span
                          key={k}
                          className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] text-sky-300 break-all"
                        >
                          {k}={v}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                  <span className="font-bold text-slate-300 uppercase text-[10px] tracking-wider block">
                    Annotations ({Object.keys(annotations).length})
                  </span>
                  {Object.keys(annotations).length === 0 ? (
                    <span className="text-slate-500 font-mono">&lt;none&gt;</span>
                  ) : (
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {Object.entries(annotations).map(([k, v]) => (
                        <div
                          key={k}
                          className="p-1.5 rounded bg-slate-950 border border-slate-800 font-mono text-[10px] text-slate-300 break-all"
                        >
                          <span className="text-slate-400">{k}:</span> {v}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : activeTab === 'describe' ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="relative flex-1 max-w-sm">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={descSearch}
                    onChange={(e) => setDescSearch(e.target.value)}
                    placeholder="Filter describe lines..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white font-mono"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => copyText('desc', data.describe || '')}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 inline-flex items-center gap-1.5"
                >
                  <Copy className="w-3.5 h-3.5" />
                  {copiedKey === 'desc' ? 'Copied' : 'Copy Describe'}
                </button>
              </div>
              <pre className="p-4 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed overflow-x-auto">
                {filteredDescribeLines || '<no describe output>'}
              </pre>
            </div>
          ) : activeTab === 'yaml' ? (
            <div className="space-y-3 h-full flex flex-col">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs text-slate-400 font-mono">
                  {yamlDirty ? 'Modified (unsaved changes)' : 'Live cluster manifest YAML'}
                </span>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => copyText('yaml', yamlDraft)}
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 inline-flex items-center gap-1"
                  >
                    <Copy className="w-3.5 h-3.5" /> {copiedKey === 'yaml' ? 'Copied' : 'Copy'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const blob = new Blob([yamlDraft], { type: 'text/yaml' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `${data.name}.yaml`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 inline-flex items-center gap-1"
                  >
                    <Download className="w-3.5 h-3.5" /> Download
                  </button>
                  <button
                    type="button"
                    disabled={acting || !yamlDraft.trim()}
                    onClick={() =>
                      runK9sOp({ action: 'apply-yaml', dryRun: true, yaml: yamlDraft }, 'Server Dry-Run')
                    }
                    className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white"
                  >
                    Dry-Run (Server)
                  </button>
                  <button
                    type="button"
                    disabled={acting || !yamlDraft.trim() || Boolean(data.secretRedacted)}
                    onClick={() =>
                      runK9sOp({ action: 'apply-yaml', dryRun: false, yaml: yamlDraft }, 'Apply YAML')
                    }
                    title={data.secretRedacted ? 'Decode secret before editing/applying' : undefined}
                    className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-xs font-semibold text-white inline-flex items-center gap-1"
                  >
                    <Save className="w-3.5 h-3.5" /> Apply YAML
                  </button>
                </div>
              </div>
              <textarea
                value={yamlDraft}
                onChange={(e) => {
                  setYamlDraft(e.target.value);
                  setYamlDirty(true);
                }}
                spellCheck={false}
                className="w-full flex-1 min-h-[460px] p-4 rounded-xl bg-slate-900 border border-slate-800 focus:border-emerald-500/50 focus:outline-none font-mono text-xs text-emerald-100 leading-relaxed resize-y"
              />
            </div>
          ) : activeTab === 'logs' && supportsLogs ? (
            <div className="space-y-3 h-full flex flex-col">
              {/* Logs Controls */}
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  {containerNames.length > 0 && (
                    <select
                      value={selectedContainer}
                      onChange={(e) => setSelectedContainer(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-white font-mono"
                    >
                      {containerNames.map((cn) => (
                        <option key={cn} value={cn}>
                          container: {cn}
                        </option>
                      ))}
                    </select>
                  )}
                  <select
                    value={logTail}
                    onChange={(e) => setLogTail(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-white font-mono"
                  >
                    <option value={100}>Tail 100</option>
                    <option value={300}>Tail 300</option>
                    <option value={1000}>Tail 1000</option>
                    <option value={3000}>Tail 3000</option>
                  </select>
                  <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={logPrevious}
                      onChange={(e) => setLogPrevious(e.target.checked)}
                    />
                    Previous (-p)
                  </label>
                  <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={logTimestamps}
                      onChange={(e) => setLogTimestamps(e.target.checked)}
                    />
                    Timestamps
                  </label>
                  <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={logWrap}
                      onChange={(e) => setLogWrap(e.target.checked)}
                    />
                    Wrap
                  </label>
                  <label className="inline-flex items-center gap-1.5 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={logAutoScroll}
                      onChange={(e) => setLogAutoScroll(e.target.checked)}
                    />
                    Auto-scroll
                  </label>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={logFilter}
                    onChange={(e) => setLogFilter(e.target.value)}
                    placeholder="grep filter..."
                    className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-white font-mono w-36"
                  />
                  {streamingLogs ? (
                    <button
                      type="button"
                      onClick={stopLogStream}
                      className="px-3 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold inline-flex items-center gap-1"
                    >
                      <Pause className="w-3 h-3" /> Stop Stream
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={startLiveLogStream}
                      className="px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold inline-flex items-center gap-1"
                    >
                      <Play className="w-3 h-3" /> Live Follow (-f)
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={fetchSnapshotLogs}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200"
                  >
                    Reload
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const blob = new Blob([filteredLogLines.join('\n')], { type: 'text/plain' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `${data.name}.log`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200"
                    title="Download logs"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {logError && (
                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs font-mono text-rose-300">
                  {logError}
                </div>
              )}

              <div className="flex-1 min-h-[430px] max-h-[60vh] overflow-y-auto p-3.5 rounded-xl bg-black/80 border border-slate-800 font-mono text-[11px] leading-relaxed">
                {logLoading ? (
                  <div className="text-slate-400">Loading container logs...</div>
                ) : filteredLogLines.length === 0 ? (
                  <div className="text-slate-500">No log lines available.</div>
                ) : (
                  filteredLogLines.map((line, i) => {
                    const lower = line.toLowerCase();
                    const lineClass =
                      lower.includes('error') || lower.includes('fatal') || lower.includes('panic')
                        ? 'text-rose-300'
                        : lower.includes('warn')
                          ? 'text-amber-200'
                          : 'text-slate-300';
                    return (
                      <div
                        key={i}
                        className={`${lineClass} ${logWrap ? 'whitespace-pre-wrap break-all' : 'whitespace-pre'} hover:bg-slate-900/60 px-1 rounded`}
                      >
                        {line}
                      </div>
                    );
                  })
                )}
                <div ref={logEndRef} />
              </div>
            </div>
          ) : activeTab === 'exec' && supportsExec ? (
            <div className="space-y-3 h-full flex flex-col">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-xs text-slate-400 mr-1">Quick Exec:</span>
                  {EXEC_QUICK_TOOLS.map((qt) => (
                    <button
                      key={qt.label}
                      type="button"
                      disabled={execRunning}
                      onClick={() => handleExec(qt.cmd)}
                      className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-slate-300"
                    >
                      {qt.label}
                    </button>
                  ))}
                </div>
                {containerNames.length > 1 && (
                  <select
                    value={selectedContainer}
                    onChange={(e) => setSelectedContainer(e.target.value)}
                    className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-white font-mono"
                  >
                    {containerNames.map((cn) => (
                      <option key={cn} value={cn}>
                        -c {cn}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <div className="flex-1 min-h-[380px] max-h-[55vh] rounded-xl bg-black/90 border border-slate-800 p-4 overflow-y-auto space-y-3 font-mono text-xs">
                {execHistory.length === 0 && (
                  <p className="text-slate-500">
                    Run a command inside pod <span className="text-emerald-300">{data.namespace}/{data.name}</span>{' '}
                    ({selectedContainer || containerNames[0] || 'default'}) via <span className="text-sky-300">kubectl exec</span>.
                  </p>
                )}
                {execHistory.map((item, idx) => (
                  <div key={idx} className="space-y-1">
                    <div className="flex items-center gap-2 text-emerald-400">
                      <span className="text-slate-500">[{item.ts}]</span>
                      <span className="text-sky-400">{item.container}$</span>
                      <span className="text-white font-semibold">{item.cmd}</span>
                      <span className="ml-auto text-[10px] text-slate-500">
                        {item.latencyMs ?? 0}ms | exit {item.exitCode}
                      </span>
                    </div>
                    <pre className="text-slate-300 whitespace-pre-wrap pl-3 border-l border-slate-800 py-1">
                      {item.output}
                    </pre>
                  </div>
                ))}
                <div ref={execEndRef} />
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleExec();
                }}
                className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-xl p-2"
              >
                <span className="text-emerald-400 font-mono text-xs pl-2">
                  {selectedContainer || 'sh'}$
                </span>
                <input
                  type="text"
                  value={execCmd}
                  onChange={(e) => setExecCmd(e.target.value)}
                  disabled={execRunning}
                  placeholder="Enter command to run in container..."
                  className="flex-1 bg-transparent text-xs font-mono text-white placeholder-slate-500 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={execRunning || !execCmd.trim()}
                  className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs font-semibold text-white"
                >
                  {execRunning ? 'Running...' : 'Exec'}
                </button>
              </form>
            </div>
          ) : (
            /* Events Tab */
            <div className="space-y-2">
              {(data.events || []).length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500">
                  No recent Kubernetes events recorded for {data.name}.
                </div>
              ) : (
                <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead className="bg-slate-950 border-b border-slate-800 text-[10px] uppercase text-slate-400">
                      <tr>
                        <th className="py-2.5 px-3">Age</th>
                        <th className="py-2.5 px-3">Type</th>
                        <th className="py-2.5 px-3">Reason</th>
                        <th className="py-2.5 px-3">Source</th>
                        <th className="py-2.5 px-3">Message</th>
                        <th className="py-2.5 px-3 text-right">Count</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {data.events.map((ev, i) => (
                        <tr key={i}>
                          <td className="py-2 px-3 font-mono text-slate-400">
                            {formatAge(ev.lastTimestamp)}
                          </td>
                          <td className="py-2 px-3">
                            <span
                              className={`px-1.5 py-0.5 rounded font-mono text-[10px] border ${
                                ev.type === 'Warning'
                                  ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                                  : 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                              }`}
                            >
                              {ev.type}
                            </span>
                          </td>
                          <td className="py-2 px-3 font-mono text-white">{ev.reason}</td>
                          <td className="py-2 px-3 font-mono text-slate-400">{ev.source || '—'}</td>
                          <td className="py-2 px-3 text-slate-300">{ev.message}</td>
                          <td className="py-2 px-3 font-mono text-right text-slate-400">
                            {ev.count}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
