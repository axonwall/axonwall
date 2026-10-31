import React, { useState, useEffect } from 'react';
import type { NmapHost, TopologyNode, HostAction, CustomDrawerTab, HostActionContext } from '../types/nmap';
import { getHostIcon } from '../icons/index';
import {
  X,
  Shield,
  Activity,
  Globe,
  Clock,
  Tag,
  MessageSquare,
  ChevronRight,
  Terminal,
  ExternalLink,
  Info,
  Server,
  Layers,
  MapPin,
  Sparkles,
  Zap,
  CheckCircle2,
  AlertTriangle,
  SlidersHorizontal,
  Eye,
  PanelRight,
  Maximize2,
  Minimize2,
} from 'lucide-react';

export interface HostDetailDrawerProps {
  node: TopologyNode | null;
  onClose: () => void;
  onUpdateComment?: (hostId: string, comment: string) => void;
  onUpdateTags?: (hostId: string, tags: string[]) => void;
  onUpdateHost?: (hostId: string, updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>) => void;
  customActions?: HostAction[];
  customTabs?: CustomDrawerTab[];
  renderHostActions?: (host: NmapHost, context: HostActionContext) => React.ReactNode;
}

export function HostDetailDrawer({
  node,
  onClose,
  onUpdateComment,
  onUpdateTags,
  onUpdateHost,
  customActions = [],
  customTabs = [],
  renderHostActions,
}: HostDetailDrawerProps) {
  const host = node?.hostRef;
  const [commentText, setCommentText] = useState(host?.comments || '');
  const [tagInput, setTagInput] = useState('');
  const [tags, setTags] = useState<string[]>(host?.tags || []);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'info' | 'success' | 'warning' | 'error' } | null>(null);

  useEffect(() => {
    setCommentText(host?.comments || '');
    setTags(host?.tags || []);
    setTagInput('');
    setActiveTab('overview');
  }, [node?.id, host?.id]);

  // Modal Transparency & Positioning Settings
  const [opacity, setOpacity] = useState<number>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('nastymap_modal_opacity');
      if (saved) {
        const parsed = parseFloat(saved);
        if (!isNaN(parsed) && parsed >= 0.2 && parsed <= 1.0) return parsed;
      }
    }
    return 0.95;
  });
  const [showOpacityControls, setShowOpacityControls] = useState<boolean>(false);
  const [dockMode, setDockMode] = useState<'center' | 'right'>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('nastymap_modal_dock');
      if (saved === 'right' || saved === 'center') return saved;
    }
    return 'center';
  });

  if (!node) return null;

  const handleSetOpacity = (newOpacity: number) => {
    setOpacity(newOpacity);
    if (typeof window !== 'undefined') {
      localStorage.setItem('nastymap_modal_opacity', newOpacity.toString());
    }
  };

  const handleSetDockMode = (newMode: 'center' | 'right') => {
    setDockMode(newMode);
    if (typeof window !== 'undefined') {
      localStorage.setItem('nastymap_modal_dock', newMode);
    }
  };

  const IconComp = getHostIcon(node.osFamily, node.deviceType, node.nodeType);

  const notify = (message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast((prev) => (prev?.message === message ? null : prev));
    }, 4000);
  };

  const handleUpdateHostInternal = (updater: (prev: NmapHost) => NmapHost | Partial<NmapHost>) => {
    if (onUpdateHost && host) {
      onUpdateHost(host.id, updater);
    }
  };

  const actionContext: HostActionContext = {
    node,
    updateHost: handleUpdateHostInternal,
    notify,
    closeDrawer: onClose,
  };

  const handleExecuteAction = async (action: HostAction) => {
    if (!host) return;
    if (action.isDisabled && action.isDisabled(host)) return;

    try {
      setActionLoadingId(action.id);
      const result = await action.onClick(host, actionContext);
      if (result && onUpdateHost) {
        onUpdateHost(host.id, () => result);
      }
    } catch (err: any) {
      notify(`Action failed: ${err.message || 'Unknown error'}`, 'error');
    } finally {
      setActionLoadingId(null);
    }
  };

  // Keyboard shortcut listener for custom host actions & escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
        return;
      }
      const target = e.target as HTMLElement;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) {
        return;
      }

      const pressedKey = e.key.toLowerCase();
      const matchedAction = customActions.find(
        (a) => a.shortcut && a.shortcut.toLowerCase() === pressedKey
      );

      if (matchedAction) {
        e.preventDefault();
        handleExecuteAction(matchedAction);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [customActions, host, onClose]);

  const handleSaveComment = () => {
    if (onUpdateComment && host) {
      onUpdateComment(host.id, commentText);
    }
    if (onUpdateHost && host) {
      onUpdateHost(host.id, (prev) => ({ comments: commentText }));
    }
    notify('Security notes saved', 'success');
  };

  const handleAddTag = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && tagInput.trim()) {
      const newTags = Array.from(new Set([...tags, tagInput.trim()]));
      setTags(newTags);
      setTagInput('');
      if (onUpdateTags && host) {
        onUpdateTags(host.id, newTags);
      }
      if (onUpdateHost && host) {
        onUpdateHost(host.id, (prev) => ({ tags: newTags }));
      }
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    const newTags = tags.filter((t) => t !== tagToRemove);
    setTags(newTags);
    if (onUpdateTags && host) {
      onUpdateTags(host.id, newTags);
    }
    if (onUpdateHost && host) {
      onUpdateHost(host.id, (prev) => ({ tags: newTags }));
    }
  };

  const builtInTabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'ports', label: `Ports (${node.openPorts.length})` },
    { id: 'trace', label: 'Route Trace' },
    { id: 'scripts', label: 'Scripts' },
    { id: 'notes', label: 'Notes & Tags' },
  ];

  const allTabs = [
    ...builtInTabs,
    ...customTabs.map((ct) => ({
      id: ct.id,
      label: ct.badge && host ? `${ct.label} (${ct.badge(host)})` : ct.label,
    })),
  ];

  // Calculate backdrop opacity based on modal opacity setting
  const backdropAlpha = Math.max(0.15, opacity * 0.55);

  return (
    <div
      className={`fixed inset-0 z-50 transition-all duration-200 ${
        dockMode === 'center'
          ? 'flex items-center justify-center p-3 sm:p-6'
          : 'flex items-stretch justify-end p-0'
      }`}
      style={{
        backgroundColor: `rgba(0, 0, 0, ${backdropAlpha})`,
        backdropFilter: opacity < 0.95 ? 'blur(3px)' : 'blur(8px)',
      }}
      onClick={onClose}
    >
      <aside
        aria-label="Host Inspector Modal"
        onClick={(e) => e.stopPropagation()}
        style={{
          backgroundColor: `rgba(9, 9, 11, ${opacity})`,
          backdropFilter: opacity < 1.0 ? 'blur(20px)' : 'none',
        }}
        className={`w-full border border-zinc-700/80 shadow-2xl flex flex-col text-zinc-100 font-sans overflow-hidden transition-all duration-200 ${
          dockMode === 'center'
            ? 'max-w-[580px] max-h-[88vh] rounded-2xl'
            : 'max-w-[540px] h-full rounded-l-2xl border-r-0'
        }`}
      >
        {/* Top Header */}
        <div className="p-4 sm:p-5 border-b border-zinc-800 flex items-start justify-between bg-zinc-900/60">
          <div className="flex items-center gap-3.5">
            <div
              className="w-12 h-12 rounded-xl flex items-center justify-center border shadow-inner shrink-0"
              style={{
                backgroundColor: `${node.color || '#3b82f6'}20`,
                borderColor: `${node.color || '#3b82f6'}60`,
                color: node.color || '#3b82f6',
              }}
            >
              <IconComp size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base sm:text-lg font-bold tracking-tight text-white">{node.label}</h2>
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                    node.status === 'up'
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                      : 'bg-rose-950 text-rose-400 border border-rose-800/60'
                  }`}
                >
                  {node.status}
                </span>
                {host?.isQuarantined && (
                  <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 text-[10px] font-bold border border-amber-800 animate-pulse">
                    QUARANTINED
                  </span>
                )}
              </div>
              <p className="text-xs font-mono text-zinc-400 mt-0.5">{node.ip}</p>
            </div>
          </div>

          {/* Header Controls: Transparency, Docking, Close */}
          <div className="flex items-center gap-1.5 shrink-0">
            {/* Opacity Control Toggle */}
            <button
              onClick={() => setShowOpacityControls((v) => !v)}
              className={`p-1.5 rounded-lg text-xs font-mono flex items-center gap-1 transition-colors ${
                showOpacityControls
                  ? 'bg-sky-950 text-sky-300 border border-sky-700'
                  : 'text-zinc-400 hover:text-white hover:bg-zinc-800 border border-zinc-800'
              }`}
              title="Adjust Modal Transparency"
            >
              <SlidersHorizontal size={14} />
              <span className="text-[11px] font-bold">{Math.round(opacity * 100)}%</span>
            </button>

            {/* Dock Position Mode Toggle */}
            <button
              onClick={() => handleSetDockMode(dockMode === 'center' ? 'right' : 'center')}
              className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 border border-zinc-800 transition-colors"
              title={dockMode === 'center' ? 'Dock to Right Panel' : 'Switch to Center Modal'}
            >
              <PanelRight size={15} className={dockMode === 'right' ? 'text-sky-400' : ''} />
            </button>

            {/* Close Button */}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 border border-zinc-800 transition-colors"
              title="Close (Esc)"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Quick Adjustable Opacity Bar (Dropdown / Drawer) */}
        {showOpacityControls && (
          <div className="px-4 py-2.5 bg-zinc-900 border-b border-zinc-800 flex flex-wrap items-center justify-between gap-3 text-xs font-mono animate-in fade-in slide-in-from-top-1 duration-150">
            <div className="flex items-center gap-2">
              <Eye size={14} className="text-sky-400" />
              <span className="text-zinc-300 font-semibold">Transparency:</span>
              <input
                type="range"
                min="0.30"
                max="1.0"
                step="0.05"
                value={opacity}
                onChange={(e) => handleSetOpacity(parseFloat(e.target.value))}
                className="w-24 sm:w-32 h-1.5 bg-zinc-700 rounded-lg appearance-none cursor-pointer accent-sky-500"
              />
              <span className="text-sky-300 font-bold w-9 text-right">{Math.round(opacity * 100)}%</span>
            </div>

            {/* Preset Buttons */}
            <div className="flex items-center gap-1 text-[10.5px]">
              {[
                { label: '50%', val: 0.5 },
                { label: '75%', val: 0.75 },
                { label: '90%', val: 0.9 },
                { label: '100% Solid', val: 1.0 },
              ].map((preset) => (
                <button
                  key={preset.label}
                  onClick={() => handleSetOpacity(preset.val)}
                  className={`px-2 py-0.5 rounded border transition-colors ${
                    Math.abs(opacity - preset.val) < 0.04
                      ? 'bg-sky-600 text-white border-sky-500 font-bold'
                      : 'bg-zinc-800 text-zinc-300 border-zinc-700 hover:bg-zinc-700'
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Custom Actions Toolbar */}
        {(customActions.length > 0 || renderHostActions) && (
          <div className="px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800 flex items-center gap-2 overflow-x-auto">
            <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-1 shrink-0">
              <Zap size={12} className="text-amber-400" />
              Actions:
            </span>
            <div className="flex items-center gap-1.5 flex-wrap">
              {customActions.map((action) => {
                const isLoading = actionLoadingId === action.id;
                const isDisabled = (action.isDisabled && host && action.isDisabled(host)) || isLoading;
                if (action.isVisible && host && !action.isVisible(host)) return null;

                return (
                  <button
                    key={action.id}
                    disabled={isDisabled}
                    onClick={() => handleExecuteAction(action)}
                    title={action.tooltip || action.description}
                    className={`px-2.5 py-1 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-all shadow-sm ${
                      action.variant === 'primary'
                        ? 'bg-sky-600 hover:bg-sky-500 text-white'
                        : action.variant === 'danger'
                        ? 'bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800'
                        : action.variant === 'warning'
                        ? 'bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-800'
                        : action.variant === 'success'
                        ? 'bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800'
                        : 'bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700'
                    } ${isDisabled ? 'opacity-50 cursor-not-allowed' : ''}`}
                  >
                    {isLoading ? (
                      <div className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    ) : (
                      action.icon
                    )}
                    <span>{action.label}</span>
                    {action.shortcut && (
                      <kbd className="px-1 py-0.2 bg-black/40 text-[9px] font-mono rounded text-zinc-300 border border-zinc-700/50">
                        {action.shortcut.toUpperCase()}
                      </kbd>
                    )}
                  </button>
                );
              })}

              {renderHostActions && host && renderHostActions(host, actionContext)}
            </div>
          </div>
        )}

        {/* Toast / Notification Banner */}
        {toast && (
          <div
            className={`px-4 py-2 text-xs flex items-center gap-2 border-b ${
              toast.type === 'success'
                ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                : toast.type === 'error'
                ? 'bg-rose-950 text-rose-300 border-rose-800'
                : toast.type === 'warning'
                ? 'bg-amber-950 text-amber-300 border-amber-800'
                : 'bg-sky-950 text-sky-300 border-sky-800'
            }`}
          >
            {toast.type === 'success' ? (
              <CheckCircle2 size={14} className="text-emerald-400" />
            ) : (
              <AlertTriangle size={14} className="text-amber-400" />
            )}
            <span className="font-medium">{toast.message}</span>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="flex border-b border-zinc-800 px-4 gap-4 overflow-x-auto bg-zinc-900/40 shrink-0">
          {allTabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-2.5 text-xs font-semibold border-b-2 whitespace-nowrap transition-colors ${
                activeTab === tab.id
                  ? 'border-sky-500 text-sky-400'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Body Content (Scrollable with solid cards for maximum readability) */}
        <div className="p-4 sm:p-5 overflow-y-auto space-y-4 flex-1">
          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="space-y-4">
              {/* Host Quick Metadata */}
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 space-y-1">
                  <span className="text-zinc-400 block text-[10px] uppercase tracking-wider font-sans font-semibold">
                    Operating System
                  </span>
                  <p className="font-bold text-white text-xs">{node.osFamily || 'Unknown OS'}</p>
                </div>
                <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 space-y-1">
                  <span className="text-zinc-400 block text-[10px] uppercase tracking-wider font-sans font-semibold">
                    Device Role
                  </span>
                  <p className="font-bold text-sky-400 capitalize text-xs">{node.deviceType}</p>
                </div>
                <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 space-y-1">
                  <span className="text-zinc-400 block text-[10px] uppercase tracking-wider font-sans font-semibold">
                    Latency / RTT
                  </span>
                  <p className="font-bold text-amber-400 text-xs">{host?.latencyMs ? `${host.latencyMs} ms` : 'Local / Unknown'}</p>
                </div>
                <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 space-y-1">
                  <span className="text-zinc-400 block text-[10px] uppercase tracking-wider font-sans font-semibold">
                    Subnet CIDR
                  </span>
                  <p className="font-bold text-emerald-400 text-xs">{node.subnet || 'Direct'}</p>
                </div>
              </div>

              {/* Ping Response Reason */}
              {host?.status.reason && (
                <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 text-xs flex items-center justify-between font-mono">
                  <span className="text-zinc-400">Ping Probe Response:</span>
                  <span className="text-emerald-400 font-bold">{host.status.reason}</span>
                </div>
              )}

              {/* Hostnames */}
              {host?.hostnames && host.hostnames.length > 0 && (
                <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 text-xs space-y-1.5">
                  <span className="text-zinc-400 block text-[10px] uppercase tracking-wider font-semibold">
                    Associated Hostnames
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {host.hostnames.map((h, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-200 font-mono text-[11px] border border-zinc-700"
                      >
                        {h.name} {h.type ? `(${h.type})` : ''}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Geolocation Section */}
              {host?.geolocation && (
                <div className="p-3.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs space-y-2">
                  <div className="flex items-center gap-1.5 font-semibold text-zinc-300">
                    <MapPin size={14} className="text-rose-400" />
                    <span>Geolocation & Physical Routing</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-zinc-400">
                    <div>
                      City: <span className="text-zinc-200 font-semibold">{host.geolocation.city}</span>
                    </div>
                    <div>
                      Country: <span className="text-zinc-200 font-semibold">{host.geolocation.country}</span>
                    </div>
                    <div>
                      Latitude: <span className="text-zinc-200">{host.geolocation.latitude.toFixed(4)}</span>
                    </div>
                    <div>
                      Longitude: <span className="text-zinc-200">{host.geolocation.longitude.toFixed(4)}</span>
                    </div>
                    {host.geolocation.org && (
                      <div className="col-span-2">
                        Organization: <span className="text-zinc-200">{host.geolocation.org}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Security Tags */}
              <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 text-xs space-y-2">
                <span className="text-zinc-400 block text-[10px] uppercase tracking-wider font-semibold">
                  Host Tags
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {tags.length > 0 ? (
                    tags.map((t) => (
                      <span
                        key={t}
                        className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-200 font-mono text-[11px] border border-zinc-700"
                      >
                        {t}
                      </span>
                    ))
                  ) : (
                    <span className="text-zinc-500 text-[11px]">No tags assigned</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* PORTS & SERVICES TAB */}
          {activeTab === 'ports' && (
            <div className="space-y-3">
              {node.openPorts.length === 0 ? (
                <div className="p-8 text-center text-zinc-500 text-xs bg-zinc-900 rounded-xl border border-zinc-800">
                  <Shield size={24} className="mx-auto mb-2 text-zinc-600" />
                  <p>No open ports discovered on this host.</p>
                </div>
              ) : (
                host?.ports.map((port) => (
                  <div
                    key={`${port.protocol}-${port.portid}`}
                    className={`p-3.5 rounded-xl border space-y-2 text-xs font-mono transition-colors ${
                      port.state === 'open'
                        ? 'bg-zinc-900 border-zinc-800 hover:border-zinc-700'
                        : 'bg-zinc-950/60 border-zinc-900 opacity-60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white text-sm">
                          {port.portid}/{port.protocol}
                        </span>
                        <span
                          className={`px-1.5 py-0.2 rounded text-[10px] font-bold uppercase ${
                            port.state === 'open'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                              : 'bg-zinc-800 text-zinc-400'
                          }`}
                        >
                          {port.state}
                        </span>
                      </div>
                      <span className="font-semibold text-sky-400 font-sans">{port.service?.name || 'unknown'}</span>
                    </div>

                    {/* Service Details */}
                    {port.service && (
                      <div className="text-[11px] text-zinc-400 space-y-0.5 pt-1.5 border-t border-zinc-800/80">
                        {port.service.product && (
                          <div>
                            Product: <strong className="text-zinc-200">{port.service.product}</strong>
                          </div>
                        )}
                        {port.service.version && (
                          <div>
                            Version: <span className="text-zinc-300">{port.service.version}</span>
                          </div>
                        )}
                        {port.service.extrainfo && (
                          <div>
                            Extra Info: <span className="text-zinc-400">{port.service.extrainfo}</span>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Port Scripts */}
                    {port.scripts && port.scripts.length > 0 && (
                      <div className="space-y-1.5 pt-2">
                        <span className="text-[10px] uppercase font-bold text-zinc-400 tracking-wider">
                          NSE Script Output:
                        </span>
                        {port.scripts.map((s, idx) => (
                          <div key={idx} className="p-2 rounded bg-black/70 border border-zinc-800 text-[11px]">
                            <div className="font-bold text-sky-400">{s.id}</div>
                            <pre className="text-zinc-300 whitespace-pre-wrap mt-0.5 font-mono text-[10px] overflow-x-auto">
                              {s.output}
                            </pre>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {/* TRACE ROUTE TAB */}
          {activeTab === 'trace' && (
            <div className="space-y-3">
              {host?.trace?.hops && host.trace.hops.length > 0 ? (
                <div className="space-y-2">
                  <div className="p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs flex items-center justify-between font-mono">
                    <span className="text-zinc-400">Total Route Hops:</span>
                    <span className="text-sky-400 font-bold">{host.trace.hops.length}</span>
                  </div>
                  <div className="space-y-1.5">
                    {host.trace.hops.map((hop) => (
                      <div
                        key={hop.ttl}
                        className="p-2.5 rounded-xl bg-zinc-900 border border-zinc-800 text-xs font-mono flex items-center justify-between"
                      >
                        <div className="flex items-center gap-2">
                          <span className="w-6 h-6 rounded-full bg-zinc-800 text-sky-400 flex items-center justify-center font-bold text-[10px]">
                            {hop.ttl}
                          </span>
                          <span className="font-bold text-white">{hop.ipaddr || '*'}</span>
                          {hop.host && <span className="text-zinc-400">({hop.host})</span>}
                        </div>
                        <span className="text-amber-400 font-bold">{hop.rtt !== undefined ? `${hop.rtt} ms` : '-'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-zinc-500 text-xs bg-zinc-900 rounded-xl border border-zinc-800">
                  <p>No traceroute hops recorded for this target.</p>
                </div>
              )}
            </div>
          )}

          {/* SCRIPTS TAB */}
          {activeTab === 'scripts' && (
            <div className="space-y-3">
              {host?.hostscripts && host.hostscripts.length > 0 ? (
                host.hostscripts.map((script, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-zinc-900 border border-zinc-800 space-y-1.5">
                    <span className="font-mono font-bold text-xs text-sky-400">{script.id}</span>
                    <pre className="text-xs font-mono text-zinc-300 whitespace-pre-wrap bg-black/60 p-2.5 rounded border border-zinc-800 overflow-x-auto">
                      {script.output}
                    </pre>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center text-zinc-500 text-xs bg-zinc-900 rounded-xl border border-zinc-800">
                  <p>No host scripts executed for this target.</p>
                </div>
              )}
            </div>
          )}

          {/* NOTES & TAGS TAB */}
          {activeTab === 'notes' && (
            <div className="space-y-5">
              <div className="space-y-2">
                <label className="text-xs font-semibold text-zinc-300 uppercase tracking-wider flex items-center gap-1.5">
                  <Tag size={13} className="text-sky-400" />
                  <span>Custom Tags</span>
                </label>
                <div className="flex flex-wrap gap-1.5 mb-2">
                  {tags.map((t) => (
                    <span
                      key={t}
                      className="px-2 py-1 rounded bg-zinc-800 text-zinc-200 text-xs font-mono flex items-center gap-1.5 border border-zinc-700"
                    >
                      {t}
                      <button onClick={() => handleRemoveTag(t)} className="hover:text-rose-400">
                        <X size={12} />
                      </button>
                    </span>
                  ))}
                </div>
                <input
                  type="text"
                  placeholder="Type a tag and press Enter (e.g. Prod, DMZ, Review)..."
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyDown={handleAddTag}
                  className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="space-y-2">
                <label className="text-xs font-semibold text-zinc-300 uppercase tracking-wider flex items-center gap-1.5">
                  <MessageSquare size={13} className="text-emerald-400" />
                  <span>Security Analyst Notes</span>
                </label>
                <textarea
                  rows={5}
                  placeholder="Add comments or investigation findings on this host..."
                  value={commentText}
                  onChange={(e) => setCommentText(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-sky-500 font-sans"
                />
                <button
                  onClick={handleSaveComment}
                  className="px-4 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow transition-colors"
                >
                  Save Notes
                </button>
              </div>
            </div>
          )}

          {/* CUSTOM INJECTED TABS */}
          {customTabs.map((ct) => {
            if (activeTab !== ct.id || !host) return null;
            return (
              <div key={ct.id} className="space-y-4">
                {ct.render(host, handleUpdateHostInternal)}
              </div>
            );
          })}
        </div>
      </aside>
    </div>
  );
}
