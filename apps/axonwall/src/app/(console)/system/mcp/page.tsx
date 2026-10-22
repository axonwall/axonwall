'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  KeyRound,
  AlertTriangle,
  CheckCircle2,
  Trash2,
  Plus,
  Copy,
  RefreshCw,
  Flame,
  Gauge,
  ArrowRightLeft,
  Globe,
  Lock,
  Terminal,
  Activity,
  Power,
  PowerOff,
} from 'lucide-react';
import {
  getMcpDashboardData,
  createMcpApiKeyAction,
  revokeMcpApiKeyAction,
  toggleMcpApiKeyAction,
  revertMcpLeaseAction,
  emergencyFlushMcpLeasesAction,
  toggleMcpServerMasterSwitchAction,
  type McpDashboardData,
} from '@/server/agent';
import type { McpScope } from '@axonwall/lib/mcp';

const ALL_SCOPES: { scope: McpScope; label: string; desc: string; tier: 'read' | 'tactical' | 'critical' }[] = [
  {
    scope: 'mcp:telemetry:read',
    label: 'Telemetry & Flows (Read)',
    desc: 'Read conntrack flows, Suricata EVE alerts, interface counters, ruleset summary, and NastyMap host inventory',
    tier: 'read',
  },
  {
    scope: 'mcp:pcap:capture',
    label: 'Bounded BPF Packet Capture',
    desc: 'Capture up to 100 packets (max 15s) matching BPF filters for deep protocol forensics',
    tier: 'read',
  },
  {
    scope: 'mcp:traffic:blackhole',
    label: 'Tactical Blackhole & C2 Severing',
    desc: 'Quarantine IPs/CIDRs in table inet axonwall_mcp, add kernel blackhole routes, and kill active conntrack flows',
    tier: 'tactical',
  },
  {
    scope: 'mcp:traffic:shape',
    label: 'Traffic Shaping & Tarpitting (QoS)',
    desc: 'Apply dynamic Linux tc HTB bandwidth throttles, netem latency/loss tarpits, and DSCP markings',
    tier: 'tactical',
  },
  {
    scope: 'mcp:traffic:redirect',
    label: 'Deception DNAT & DNS Sinkholing',
    desc: 'Redirect attacker flows to allowlisted honeypots (DNAT/policy route) or sinkhole malicious domains in Unbound',
    tier: 'tactical',
  },
  {
    scope: 'mcp:fleet:broadcast',
    label: 'Fleet Satellite Block Broadcast',
    desc: 'Propagate tactical IP quarantines to downstream SD-WAN satellites',
    tier: 'tactical',
  },
  {
    scope: 'mcp:firewall:write',
    label: 'Stage Declarative Firewall Rules',
    desc: 'Propose persistent rules into DesiredState (protected by anti-lockout validator)',
    tier: 'critical',
  },
  {
    scope: 'mcp:firewall:apply',
    label: 'Apply Config (Forced Commit-Confirm)',
    desc: 'Compile and apply DesiredState with mandatory Commit-Confirm automatic watchdog rollback',
    tier: 'critical',
  },
];

export default function McpControlPlanePage() {
  const [data, setData] = useState<McpDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Create key modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [keyName, setKeyName] = useState('VigilSOC Autonomous Responder');
  const [agentType, setAgentType] = useState<'vigilsoc' | 'soar' | 'custom-ai' | 'readonly-analyst'>('vigilsoc');
  const [selectedScopes, setSelectedScopes] = useState<McpScope[]>([
    'mcp:telemetry:read',
    'mcp:pcap:capture',
    'mcp:traffic:blackhole',
    'mcp:traffic:shape',
    'mcp:traffic:redirect',
  ]);
  const [allowedSourceCidrs, setAllowedSourceCidrs] = useState('');
  const [mtlsFingerprint, setMtlsFingerprint] = useState('');
  const [maxIpv4PrefixLen, setMaxIpv4PrefixLen] = useState(24);
  const [maxIpv6PrefixLen, setMaxIpv6PrefixLen] = useState(64);
  const [maxTtlSeconds, setMaxTtlSeconds] = useState(86400);
  const [rateLimitPerMinute, setRateLimitPerMinute] = useState(120);
  const [allowedRedirectTargets, setAllowedRedirectTargets] = useState('10.99.0.10, 10.99.0.10:2222');
  const [expiresInDays, setExpiresInDays] = useState(90);

  // Newly created raw token display
  const [createdToken, setCreatedToken] = useState<{ name: string; rawToken: string } | null>(null);

  const refreshData = useCallback(async () => {
    try {
      setLoading(true);
      const res = await getMcpDashboardData();
      setData(res);
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: err?.message || 'Failed to load MCP control plane state' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshData();
  }, [refreshData]);

  const handlePresetChange = (type: 'vigilsoc' | 'soar' | 'custom-ai' | 'readonly-analyst') => {
    setAgentType(type);
    if (type === 'readonly-analyst') {
      setSelectedScopes(['mcp:telemetry:read', 'mcp:pcap:capture']);
    } else if (type === 'vigilsoc' || type === 'soar') {
      setSelectedScopes([
        'mcp:telemetry:read',
        'mcp:pcap:capture',
        'mcp:traffic:blackhole',
        'mcp:traffic:shape',
        'mcp:traffic:redirect',
      ]);
    }
  };

  const toggleScope = (scope: McpScope) => {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
    );
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);
    const res = await createMcpApiKeyAction({
      name: keyName,
      agentType,
      scopes: selectedScopes,
      allowedSourceCidrs: allowedSourceCidrs
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      mtlsCertFingerprintSha256: mtlsFingerprint.trim() || undefined,
      expiresInDays,
      policyLimits: {
        maxIpv4PrefixLen: Number(maxIpv4PrefixLen) || 24,
        maxIpv6PrefixLen: Number(maxIpv6PrefixLen) || 64,
        maxTtlSeconds: Number(maxTtlSeconds) || 86400,
        rateLimitPerMinute: Number(rateLimitPerMinute) || 120,
        allowedRedirectTargets: allowedRedirectTargets
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      },
    });

    if (!res.success || !res.rawToken) {
      setStatusMsg({ type: 'error', text: res.error || 'Failed to create MCP API key' });
      return;
    }

    setCreatedToken({ name: keyName, rawToken: res.rawToken });
    setShowCreateModal(false);
    await refreshData();
  };

  const handleRevokeKey = async (id: string, name: string) => {
    if (!confirm(`Revoke MCP API key "${name}" immediately? Active AI agents using this key will lose access.`)) {
      return;
    }
    const res = await revokeMcpApiKeyAction(id);
    if (res.success) {
      setStatusMsg({ type: 'success', text: `Revoked MCP API key "${name}"` });
      await refreshData();
    } else {
      setStatusMsg({ type: 'error', text: res.error || 'Failed to revoke key' });
    }
  };

  const handleToggleKey = async (id: string, enabled: boolean) => {
    await toggleMcpApiKeyAction(id, enabled);
    await refreshData();
  };

  const handleToggleMasterSwitch = async (newEnabled: boolean) => {
    const actionText = newEnabled ? 'enable' : 'completely disable';
    const confirmPrompt = newEnabled
      ? 'Enable the Axonwall MCP Subsystem? AI agents with valid keys will be permitted to connect and execute tools.'
      : 'COMPLETELY DISABLE AXONWALL MCP SUBSYSTEM?\n\nThis will:\n1. Immediately block all incoming MCP connections on HTTPS port 2966 (/api/v1/mcp)\n2. Forbid Stdio MCP command execution\n3. Reject all mutating /v1/mcp/* daemon endpoints\n4. Automatically flush all active AI tactical leases from the kernel.';
    if (!confirm(confirmPrompt)) {
      return;
    }
    const res = await toggleMcpServerMasterSwitchAction(newEnabled);
    if (res.success) {
      setStatusMsg({
        type: 'success',
        text: `MCP Subsystem ${newEnabled ? 'enabled successfully' : 'completely disabled across all transports and kernel engines'}.`,
      });
      await refreshData();
    } else {
      setStatusMsg({
        type: 'error',
        text: res.error || `Failed to ${actionText} MCP subsystem`,
      });
    }
  };

  const handleRevertLease = async (leaseId: string) => {
    const res = await revertMcpLeaseAction(leaseId);
    if (res.success) {
      setStatusMsg({ type: 'success', text: `Reverted tactical lease ${leaseId}` });
      await refreshData();
    } else {
      setStatusMsg({ type: 'error', text: res.error || 'Failed to revert lease' });
    }
  };

  const handlePanicFlush = async () => {
    if (
      !confirm(
        'EMERGENCY PANIC FLUSH: Immediately remove all AI/MCP tactical blackholes, tc shapers, DNAT redirects, and DNS sinkholes from the kernel?'
      )
    ) {
      return;
    }
    const res = await emergencyFlushMcpLeasesAction();
    setStatusMsg({
      type: 'success',
      text: `Emergency Panic Flush completed (${res.clearedCount} active AI tactical lease(s) purged from kernel).`,
    });
    await refreshData();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <KeyRound className="w-6 h-6 text-sky-400" />
            <h1 className="text-2xl font-bold text-slate-100">
              Security AI &amp; VigilSOC MCP Control Plane
            </h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-sky-500/15 text-sky-300 border border-sky-500/30">
              Strict AuthZ
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Grant VigilSOC and autonomous security AI systems scoped, blast-radius-bounded Model Context Protocol (MCP)
            access to reap live traffic telemetry and enforce tactical blackholing, shaping, and deception redirection.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={refreshData}
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium flex items-center gap-2 border border-slate-700"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handlePanicFlush}
            className="px-4 py-2 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/40 text-sm font-semibold flex items-center gap-2"
          >
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            Panic Flush All AI Rules
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 text-sm font-semibold flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Provision MCP Key
          </button>
        </div>
      </div>

      {/* Master Subsystem Kill-Switch Card */}
      {data?.serverStatus && (
        <div
          className={`p-5 rounded-2xl border transition-all ${
            data.serverStatus.enabled
              ? 'bg-slate-900/80 border-slate-800'
              : 'bg-rose-950/30 border-rose-600/40 shadow-lg shadow-rose-950/20'
          }`}
        >
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div className="flex items-start gap-3.5">
              <div
                className={`p-2.5 rounded-xl border mt-0.5 ${
                  data.serverStatus.enabled
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                }`}
              >
                {data.serverStatus.enabled ? (
                  <Power className="w-6 h-6" />
                ) : (
                  <PowerOff className="w-6 h-6" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h3 className="text-base font-semibold text-slate-100">
                    MCP Server Master Switch
                  </h3>
                  <span
                    className={`px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider rounded-full border ${
                      data.serverStatus.enabled
                        ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                        : 'bg-rose-500/20 border-rose-500/40 text-rose-300'
                    }`}
                  >
                    {data.serverStatus.enabled ? 'ACTIVE & SERVING' : 'COMPLETELY DISABLED'}
                  </span>
                  {data.serverStatus.source === 'env' && (
                    <span className="px-2 py-0.5 text-2xs font-mono rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      ENV OVERRIDE
                    </span>
                  )}
                </div>
                <p className="text-sm text-slate-400 mt-1 max-w-2xl">
                  {data.serverStatus.enabled ? (
                    'The MCP subsystem is currently accepting authorized client connections over HTTPS port 2966 and local Stdio transport. All AI tool executions are monitored and audited.'
                  ) : (
                    <span className="text-rose-200">
                      <strong>MCP Subsystem is completely disabled:</strong>{' '}
                      {data.serverStatus.disabledReason || 'All connections and tool invocations are rejected.'}
                    </span>
                  )}
                </p>
                {!data.serverStatus.enabled && data.serverStatus.disabledAt && (
                  <p className="text-xs text-slate-500 mt-1">
                    Disabled on {new Date(data.serverStatus.disabledAt).toLocaleString()}
                    {data.serverStatus.disabledBy ? ` by ${data.serverStatus.disabledBy}` : ''}
                  </p>
                )}
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              {data.serverStatus.source === 'env' ? (
                <div className="text-xs text-amber-400 bg-amber-950/30 border border-amber-500/30 px-3 py-2 rounded-lg max-w-xs text-center">
                  Locked via environment variable. Edit systemd service or container env to change.
                </div>
              ) : (
                <button
                  onClick={() => handleToggleMasterSwitch(!data.serverStatus.enabled)}
                  className={`px-5 py-2.5 rounded-xl font-semibold text-sm flex items-center gap-2 border transition-all ${
                    data.serverStatus.enabled
                      ? 'bg-rose-600/15 hover:bg-rose-600/25 border-rose-500/30 text-rose-300 hover:border-rose-500/50'
                      : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold border-transparent shadow-lg shadow-emerald-950/40'
                  }`}
                >
                  {data.serverStatus.enabled ? (
                    <>
                      <PowerOff className="w-4 h-4" />
                      Disable MCP Subsystem
                    </>
                  ) : (
                    <>
                      <Power className="w-4 h-4" />
                      Enable MCP Subsystem
                    </>
                  )}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {statusMsg && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between ${
            statusMsg.type === 'success'
              ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/40 border-rose-500/40 text-rose-200'
          }`}
        >
          <span className="text-sm">{statusMsg.text}</span>
          <button onClick={() => setStatusMsg(null)} className="text-xs underline opacity-80">
            Dismiss
          </button>
        </div>
      )}

      {/* Newly Created Token Banner (Copy Once) */}
      {createdToken && (
        <div className="p-5 rounded-xl bg-amber-950/40 border border-amber-500/40 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-amber-300 font-semibold">
              <KeyRound className="w-5 h-5" />
              <span>New Scoped MCP Token Created for &ldquo;{createdToken.name}&rdquo; — Copy Now (Shown Once)</span>
            </div>
            <button
              onClick={() => setCreatedToken(null)}
              className="text-xs text-amber-300 hover:underline"
            >
              Close
            </button>
          </div>
          <p className="text-xs text-slate-300">
            Axonwall only stores the SHA-256 digest of this token in <code>/var/lib/axonwall/mcp-keys.json</code>. Save
            it in your VigilSOC or MCP client configuration now:
          </p>
          <div className="flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-emerald-300">
            <span className="flex-1 break-all">{createdToken.rawToken}</span>
            <button
              onClick={() => navigator.clipboard.writeText(createdToken.rawToken)}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1"
            >
              <Copy className="w-3.5 h-3.5" />
              Copy Token
            </button>
          </div>
          <details className="text-xs text-slate-400">
            <summary className="cursor-pointer text-sky-400 font-medium">
              Show VigilSOC / MCP Client Configuration Snippet (HTTPS Port 2966 &amp; Stdio)
            </summary>
            <pre className="mt-2 p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 overflow-x-auto">
{`// Option A: Remote Streamable HTTP / SSE over HTTPS/mTLS (Port 2966)
{
  "mcpServers": {
    "axonwall-firewall": {
      "url": "https://<AXONWALL_IP>:2966/api/v1/mcp",
      "headers": {
        "Authorization": "Bearer ${createdToken.rawToken}"
      }
    }
  }
}

// Option B: Local / SSH Stdio CLI Transport
{
  "mcpServers": {
    "axonwall-firewall": {
      "command": "node",
      "args": ["/opt/axonwall/controller/dist/axonwall-mcp.js"],
      "env": {
        "AXONWALL_MCP_TOKEN": "${createdToken.rawToken}"
      }
    }
  }
}`}
            </pre>
          </details>
        </div>
      )}

      {/* Kernel Immunity & Anti-Lockout Posture */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-emerald-400 mb-2">
            <Shield className="w-4 h-4" />
            Kernel Anti-Lockout Immunity
          </div>
          <p className="text-xs text-slate-400">
            Protected Appliance IPs:{' '}
            <span className="text-slate-200 font-mono">
              {data?.protectedPosture.applianceIps.join(', ') || '192.168.1.1'}
            </span>
          </p>
          <p className="text-xs text-slate-400 mt-1">
            Protected Management Ports:{' '}
            <span className="text-slate-200 font-mono">
              {data?.protectedPosture.antiLockoutPorts.join(', ') || '2966, 22, 9876'}
            </span>
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-sky-400 mb-2">
            <Activity className="w-4 h-4" />
            Isolated Enforcement Plane
          </div>
          <p className="text-xs text-slate-400">
            Tactical AI actions execute in isolated <code>table inet axonwall_mcp</code> with automatic TTL expiry and
            cannot overwrite declarative <code>table inet axonwall</code> anti-lockout rules.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-purple-400 mb-2">
            <CheckCircle2 className="w-4 h-4" />
            SHA-256 Hash-Chained Audit Trail
          </div>
          <div className="flex items-center gap-2">
            <span
              className={`px-2 py-0.5 rounded text-xs font-semibold ${
                data?.auditIntegrity.valid !== false
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
              }`}
            >
              {data?.auditIntegrity.valid !== false ? 'CHAIN INTEGRITY VERIFIED' : 'TAMPER DETECTED'}
            </span>
            <span className="text-xs text-slate-400">
              {data?.auditIntegrity.totalEntries ?? 0} signed events
            </span>
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1.5 truncate">
            Head: {data?.auditIntegrity.headHash || '0000000000000000'}
          </p>
        </div>
      </div>

      {/* Active AI Tactical Leases */}
      <div className="rounded-xl bg-slate-900/70 border border-slate-800 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Flame className="w-4 h-4 text-amber-400" />
              Active AI Tactical Traffic Control Leases ({data?.leases.length ?? 0})
            </h2>
            <p className="text-xs text-slate-400">
              Live kernel blackholes, <code>tc</code> bandwidth throttles/tarpits, attacker-scoped DNAT honeypot
              redirects, and Unbound DNS sinkholes. All leases automatically expire when their TTL reaches 0.
            </p>
          </div>
        </div>

        {!data?.leases.length ? (
          <div className="p-8 text-center text-sm text-slate-500">
            No active AI tactical traffic control leases in kernel.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950/60 text-xs uppercase text-slate-400">
                <tr>
                  <th className="px-4 py-3">Lease ID</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Enforcement Summary</th>
                  <th className="px-4 py-3">AI Principal</th>
                  <th className="px-4 py-3">Justification &amp; MITRE</th>
                  <th className="px-4 py-3">Remaining TTL</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.leases.map((lease) => (
                  <tr key={lease.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono text-xs text-slate-300">{lease.id}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-semibold ${
                          lease.kind === 'blackhole'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : lease.kind === 'shape'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              : 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                        }`}
                      >
                        {lease.kind.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-200">{lease.targetSummary}</td>
                    <td className="px-4 py-3 text-xs text-slate-300">{lease.createdByKeyName}</td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      <div>{lease.audit?.reason}</div>
                      <div className="flex items-center gap-2 mt-0.5">
                        {lease.audit?.mitreTechniqueId && (
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-sky-300 font-mono text-[10px]">
                            {lease.audit.mitreTechniqueId}
                          </span>
                        )}
                        {lease.audit?.incidentId && (
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                            {lease.audit.incidentId}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-emerald-400">{lease.ttlSeconds}s</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleRevertLease(lease.id)}
                        className="px-2.5 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 text-xs font-medium"
                      >
                        Revert Now
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Scoped MCP API Keys Table */}
      <div className="rounded-xl bg-slate-900/70 border border-slate-800 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Lock className="w-4 h-4 text-sky-400" />
              Scoped MCP Principals &amp; Blast-Radius Policies ({data?.keys.length ?? 0})
            </h2>
            <p className="text-xs text-slate-400">
              Each AI system authenticates with a unique SHA-256 hashed key bound to explicit scopes, source CIDRs, and
              maximum subnet prefix bounds.
            </p>
          </div>
        </div>

        {!data?.keys.length ? (
          <div className="p-8 text-center text-sm text-slate-500">
            No MCP API keys provisioned yet. Click &ldquo;Provision MCP Key&rdquo; to authorize VigilSOC or another
            security AI agent.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950/60 text-xs uppercase text-slate-400">
                <tr>
                  <th className="px-4 py-3">Principal Name</th>
                  <th className="px-4 py-3">Key Prefix</th>
                  <th className="px-4 py-3">Granted Scopes</th>
                  <th className="px-4 py-3">Blast-Radius Guardrails</th>
                  <th className="px-4 py-3">Source CIDR / mTLS</th>
                  <th className="px-4 py-3">Last Active</th>
                  <th className="px-4 py-3 text-right">Controls</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.keys.map((k) => (
                  <tr key={k.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3">
                      <div className="font-semibold text-slate-100">{k.name}</div>
                      <div className="text-xs text-slate-400 uppercase">{k.agentType}</div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-sky-300">{k.keyPrefix}_***</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1 max-w-md">
                        {k.scopes.map((s) => (
                          <span
                            key={s}
                            className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 font-mono text-[11px]"
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-300 space-y-0.5">
                      <div>
                        Max Subnet: <span className="font-mono text-amber-300">/{k.policyLimits.maxIpv4PrefixLen}</span>{' '}
                        (v4) / <span className="font-mono text-amber-300">/{k.policyLimits.maxIpv6PrefixLen}</span> (v6)
                      </div>
                      <div>
                        Max TTL: <span className="font-mono">{k.policyLimits.maxTtlSeconds}s</span> | Rate:{' '}
                        <span className="font-mono">{k.policyLimits.rateLimitPerMinute}/min</span>
                      </div>
                      {k.policyLimits.allowedRedirectTargets?.length > 0 && (
                        <div className="text-[11px] text-purple-300 truncate max-w-xs">
                          Honeypots: {k.policyLimits.allowedRedirectTargets.join(', ')}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      <div>
                        CIDRs:{' '}
                        <span className="font-mono text-slate-200">
                          {k.allowedSourceCidrs.length ? k.allowedSourceCidrs.join(', ') : 'Any Mgmt'}
                        </span>
                      </div>
                      {k.mtlsCertFingerprintSha256 && (
                        <div className="text-[11px] text-emerald-400 font-mono truncate max-w-[160px]">
                          mTLS Pin: {k.mtlsCertFingerprintSha256.slice(0, 16)}…
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {k.lastUsedAt ? (
                        <div>
                          <div>{new Date(k.lastUsedAt).toLocaleString()}</div>
                          <div className="font-mono text-[11px] text-slate-500">{k.lastUsedIp}</div>
                        </div>
                      ) : (
                        'Never'
                      )}
                    </td>
                    <td className="px-4 py-3 text-right space-x-2">
                      <button
                        onClick={() => handleToggleKey(k.id, !k.enabled)}
                        className={`px-2.5 py-1 rounded text-xs font-medium border ${
                          k.enabled
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                      >
                        {k.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                      <button
                        onClick={() => handleRevokeKey(k.id, k.name)}
                        className="p-1.5 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30"
                        title="Revoke Key"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Tamper-Evident Audit Trail */}
      <div className="rounded-xl bg-slate-900/70 border border-slate-800 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800">
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-purple-400" />
            Tamper-Evident MCP Security Audit Trail
          </h2>
          <p className="text-xs text-slate-400">
            Every allowed or denied MCP tool call is cryptographically chained (`prevHash` &rarr; `entryHash`) in{' '}
            <code>/var/log/axonwall/mcp-audit.jsonl</code>.
          </p>
        </div>

        {!data?.auditEntries.length ? (
          <div className="p-8 text-center text-sm text-slate-500">No MCP audit events recorded yet.</div>
        ) : (
          <div className="overflow-x-auto max-h-96">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 uppercase text-slate-400 sticky top-0">
                <tr>
                  <th className="px-4 py-2.5">Timestamp</th>
                  <th className="px-4 py-2.5">Principal</th>
                  <th className="px-4 py-2.5">Tool / Resource</th>
                  <th className="px-4 py-2.5">Decision</th>
                  <th className="px-4 py-2.5">Parameters &amp; Justification</th>
                  <th className="px-4 py-2.5">SHA-256 Chain Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.auditEntries.map((entry) => (
                  <tr key={entry.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-2.5 font-mono text-slate-400 whitespace-nowrap">
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="text-slate-200 font-medium">{entry.keyName}</div>
                      <div className="font-mono text-[10px] text-slate-500">{entry.clientIp}</div>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-sky-300">{entry.toolName}</td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`px-2 py-0.5 rounded font-semibold ${
                          entry.decision === 'allowed'
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : 'bg-rose-500/20 text-rose-300'
                        }`}
                      >
                        {entry.decision.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-slate-300 max-w-md">
                      {entry.denialReason && <div className="text-rose-300 font-medium">{entry.denialReason}</div>}
                      {entry.auditMetadata?.reason && <div>{entry.auditMetadata.reason}</div>}
                      <div className="font-mono text-[10px] text-slate-500 truncate">
                        {JSON.stringify(entry.paramsSummary)}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[10px] text-slate-400">
                      {entry.entryHash.slice(0, 16)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create Scoped MCP Key Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                <KeyRound className="w-5 h-5 text-sky-400" />
                Provision Scoped Security AI MCP Key
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateKey} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                    Principal / Agent Name
                  </label>
                  <input
                    type="text"
                    value={keyName}
                    onChange={(e) => setKeyName(e.target.value)}
                    required
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-100"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                    Security AI Role Preset
                  </label>
                  <select
                    value={agentType}
                    onChange={(e) => handlePresetChange(e.target.value as any)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-100"
                  >
                    <option value="vigilsoc">VigilSOC Autonomous Responder</option>
                    <option value="soar">SOAR Tactical Containment Playbook</option>
                    <option value="readonly-analyst">Read-Only Threat Analyst AI</option>
                    <option value="custom-ai">Custom Security AI System</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase text-slate-400 mb-2">
                  Granted Capability Scopes (Principle of Least Privilege)
                </label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {ALL_SCOPES.map((item) => {
                    const checked = selectedScopes.includes(item.scope);
                    return (
                      <label
                        key={item.scope}
                        className={`p-2.5 rounded-lg border cursor-pointer flex items-start gap-2.5 text-xs ${
                          checked
                            ? 'bg-sky-500/10 border-sky-500/40 text-slate-100'
                            : 'bg-slate-950/60 border-slate-800 text-slate-400'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleScope(item.scope)}
                          className="mt-0.5"
                        />
                        <div>
                          <div className="font-semibold text-slate-200">{item.label}</div>
                          <div className="font-mono text-[10px] text-sky-400">{item.scope}</div>
                          <div className="text-[11px] text-slate-400 mt-0.5">{item.desc}</div>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div>
                  <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                    Max IPv4 Prefix (/8–/32)
                  </label>
                  <input
                    type="number"
                    min={8}
                    max={32}
                    value={maxIpv4PrefixLen}
                    onChange={(e) => setMaxIpv4PrefixLen(Number(e.target.value))}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-100"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                    Max IPv6 Prefix (/32–/128)
                  </label>
                  <input
                    type="number"
                    min={32}
                    max={128}
                    value={maxIpv6PrefixLen}
                    onChange={(e) => setMaxIpv6PrefixLen(Number(e.target.value))}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-100"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                    Max Lease TTL (sec)
                  </label>
                  <input
                    type="number"
                    min={60}
                    max={604800}
                    value={maxTtlSeconds}
                    onChange={(e) => setMaxTtlSeconds(Number(e.target.value))}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-100"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                    Rate Limit (/min)
                  </label>
                  <input
                    type="number"
                    min={5}
                    max={6000}
                    value={rateLimitPerMinute}
                    onChange={(e) => setRateLimitPerMinute(Number(e.target.value))}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-100"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                  Allowed Honeypot / Redirection Targets (Comma-Separated IP or IP:Port)
                </label>
                <input
                  type="text"
                  value={allowedRedirectTargets}
                  onChange={(e) => setAllowedRedirectTargets(e.target.value)}
                  placeholder="e.g. 10.99.0.10, 10.99.0.10:2222"
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-100 font-mono"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  <code>mcp_redirect_traffic</code> is strictly restricted to steering attacker traffic toward these
                  destinations.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                    Allowed Source CIDRs (Optional)
                  </label>
                  <input
                    type="text"
                    value={allowedSourceCidrs}
                    onChange={(e) => setAllowedSourceCidrs(e.target.value)}
                    placeholder="e.g. 10.42.0.0/16, 192.168.1.50/32"
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-100 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                    mTLS Cert SHA-256 Pin (Optional)
                  </label>
                  <input
                    type="text"
                    value={mtlsFingerprint}
                    onChange={(e) => setMtlsFingerprint(e.target.value)}
                    placeholder="Optional client cert SHA-256"
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-100 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                    Key Expiration (Days)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={3650}
                    value={expiresInDays}
                    onChange={(e) => setExpiresInDays(Number(e.target.value))}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs text-slate-100"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 text-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-sm"
                >
                  Generate Scoped MCP Token
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
