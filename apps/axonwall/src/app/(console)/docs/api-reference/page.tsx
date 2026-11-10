import React from 'react';
import Link from 'next/link';
import { Code2, Server, Radio, Terminal, GitBranch, Shield, Key } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'API & Developer Reference | Axonwall Documentation',
  description:
    'Complete REST API, Server-Sent Events (SSE) packet streams, and Go agent socket IPC specifications for Axonwall.',
};

export default function ApiReferenceDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Developer & Automation
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          REST & Agent API Reference
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Automate Axonwall through standardized REST APIs, real-time Server-Sent Events (SSE) telemetry streams, and low-latency Unix domain socket IPC.
        </p>
      </div>

      {/* Authentication */}
      <section className="space-y-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Key className="w-5 h-5 text-emerald-400" /> Authentication
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          All HTTP requests must supply an API token generated in <code className="text-slate-200">System &gt; Access &gt; API Keys</code> via the HTTP Authorization header:
        </p>
        <CodeBlock
          title="HTTP Header"
          language="http"
          code={`Authorization: Bearer axw_live_9f82c3e4a1b74d6e9012f`}
        />
      </section>

      {/* Packets SSE Stream */}
      <section id="packets" className="space-y-6 pt-6 border-t border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <span className="px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 font-mono text-xs font-bold uppercase">GET</span>
          <h2 className="text-lg font-mono font-bold text-white">/api/v1/events/packets</h2>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">
          Establishes a persistent Server-Sent Events (SSE) stream delivering real-time parsed packet events directly from the Linux kernel Netfilter tap.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-slate-800 rounded-xl overflow-hidden">
            <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Query Param</th>
                <th className="p-3">Type</th>
                <th className="p-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="p-3 font-mono text-emerald-400">iface</td>
                <td className="p-3">string</td>
                <td className="p-3">Filter by interface name (e.g., <code className="text-slate-200">wan0</code>, <code className="text-slate-200">lan0</code>).</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-emerald-400">proto</td>
                <td className="p-3">string</td>
                <td className="p-3">Filter by protocol: <code className="text-slate-200">tcp</code>, <code className="text-slate-200">udp</code>, <code className="text-slate-200">icmp</code>.</td>
              </tr>
              <tr>
                <td className="p-3 font-mono text-emerald-400">port</td>
                <td className="p-3">number</td>
                <td className="p-3">Filter by source or destination port (e.g. 443).</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Terminal PTY API */}
      <section id="terminal" className="space-y-6 pt-6 border-t border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono text-xs font-bold uppercase">POST</span>
          <h2 className="text-lg font-mono font-bold text-white">/api/v1/system/terminal</h2>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">
          Executes diagnostic commands inside the privileged agent PTY environment or allocates an interactive terminal channel.
        </p>
        <CodeBlock
          title="Request Body (JSON)"
          language="json"
          code={`{
  "command": "ethtool -m eth2",
  "cols": 120,
  "rows": 40
}`}
        />
      </section>

      {/* GitOps Revisions API */}
      <section id="gitops" className="space-y-6 pt-6 border-t border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <span className="px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 font-mono text-xs font-bold uppercase">GET</span>
          <h2 className="text-lg font-mono font-bold text-white">/api/v1/system/revisions</h2>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">
          Retrieves the immutable Git commit history of the firewall configuration repository.
        </p>

        <div className="flex items-center gap-2.5 pt-4">
          <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono text-xs font-bold uppercase">POST</span>
          <h2 className="text-lg font-mono font-bold text-white">/api/v1/system/rollback</h2>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">
          Initiates a 1-click rollback to a specific Git commit hash with Commit-Confirm watchdog engagement.
        </p>
        <CodeBlock
          title="Rollback Request Body"
          language="json"
          code={`{
  "commitHash": "9b1c4e7f82a4d3b6e8201a",
  "confirmTimeoutSeconds": 60
}`}
        />
      </section>

      {/* Privileged Unix Socket IPC */}
      <section id="agent-socket" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Server className="w-6 h-6 text-emerald-400" /> Privileged Agent Socket IPC (<code className="font-mono text-emerald-400">axonwalld</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Internal controllers and CLI tools communicate with <code className="text-emerald-400 font-mono">axonwalld</code>{' '}
          over three specialized Unix domain sockets in <code className="text-slate-200 font-mono">/run/axonwall/</code>,
          authenticated with the local token at <code className="text-slate-200 font-mono">/etc/axonwall/agent.token</code>:
        </p>

        <CodeBlock
          title="Agent HTTP API Socket (/run/axonwall/agent-api.sock)"
          language="bash"
          code={`# Query daemon status & Commit-Confirm watchdog timer:
sudo curl -s --unix-socket /run/axonwall/agent-api.sock \\
  -H "X-Axonwall-Agent-Token: $(sudo cat /etc/axonwall/agent.token)" \\
  http://localhost/v1/status | jq .

# Query HA Sync Trust & ECDSA P-256 PKI enrollment state:
sudo curl -s --unix-socket /run/axonwall/agent-api.sock \\
  -H "X-Axonwall-Agent-Token: $(sudo cat /etc/axonwall/agent.token)" \\
  http://localhost/v1/ha/sync-trust | jq .`}
        />

        <CodeBlock
          title="IPC Sockets & Endpoints Summary"
          language="typescript"
          code={`// 1. /run/axonwall/agent-api.sock (HTTP/1.1 + X-Axonwall-Agent-Token header)
//    GET  /v1/status          -> Daemon health, active bundle hash, pending Commit-Confirm job
//    POST /v1/apply           -> Compile & apply nftables + daemon configs with Commit-Confirm
//    POST /v1/confirm         -> Confirm pending jobId and disarm rollback timer
//    POST /v1/rollback        -> Immediately revert to last-known-good bundle
//    GET  /v1/ha/sync-trust   -> HA PKI enrollment, effective transport (mtls/token-http), SHA-256 fingerprints
//    GET  /v1/telemetry       -> HWMON thermal/fan/voltage sensors & SFP+/QSFP optical DOM

// 2. /run/axonwall/agent.sock (Newline-delimited JSON-RPC)
// 3. /run/axonwall/ha.sock    (Root SO_PEERCRED UID-0 verified Keepalived MASTER/BACKUP/FAULT transitions)`}
        />
      </section>
    </div>
  );
}
