import React from 'react';
import Link from 'next/link';
import { GitBranch, History, ShieldCheck, CheckCircle2, RotateCcw, FileDiff } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'GitOps Configuration Versioning & Audit Trail | Axonwall Documentation',
  description:
    'Git-backed configuration versioning, immutable compliance audit trails, unified diff inspection, and 1-click rollback in Axonwall.',
};

export default function GitOpsAuditDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Version Control & Audit
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          GitOps Configuration & Audit Trail
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Bring software engineering rigor to network security. Every configuration change in Axonwall is tracked as an immutable <code className="text-emerald-400 font-mono">Git commit</code>, providing cryptographic audit trails, unified diff previews, and 1-click rollbacks.
        </p>
      </div>

      {/* GitOps Architecture */}
      <section id="versioning" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <GitBranch className="w-6 h-6 text-emerald-400" /> Git-Backed State Management
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The complete state of your Axonwall firewall (rules, aliases, NAT, VPN tunnels, and system options) is maintained as a structured JSON model in <code className="text-slate-200 font-mono">/etc/axonwall/config.json</code>. Behind the scenes, Axonwall manages a local Git repository tracking this directory:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">Non-Repudiation</span>
            <p className="text-slate-400">Every commit records the logged-in administrator&apos;s identity, timestamp, and human-readable reason.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">Cryptographic Integrity</span>
            <p className="text-slate-400">Git commit hashes prevent silent tampering, satisfying strict compliance standards (SOC 2, ISO 27001).</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">Automated History</span>
            <p className="text-slate-400">Changes made via Web Console, REST API, or CLI are committed automatically without manual git commands.</p>
          </div>
        </div>
      </section>

      {/* Unified Diff Inspection */}
      <section id="diff-inspection" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <FileDiff className="w-6 h-6 text-emerald-400" /> Unified Diff Inspection
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Before applying changes or rolling back to an earlier revision, administrators can inspect the exact configuration deltas in a unified diff viewer:
        </p>

        <CodeBlock
          title="git diff HEAD~1"
          language="diff"
          code={`--- a/config.json
+++ b/config.json
@@ -42,6 +42,12 @@
     "rules": [
+      {
+        "id": "rule_dmz_https",
+        "action": "pass",
+        "protocol": "tcp",
+        "dst_port": 443,
+        "description": "Allow inbound HTTPS to DMZ cluster"
+      }
     ]`}
        />
      </section>

      {/* 1-Click Rollback */}
      <section id="rollback" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <RotateCcw className="w-6 h-6 text-emerald-400" /> 1-Click Rollback Lifecycle
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          If a recent policy change causes unexpected business disruption, rolling back takes a single click:
        </p>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3 font-mono text-xs text-slate-300">
          <div className="text-emerald-400 font-bold">ROLLBACK EXECUTION FLOW:</div>
          <p>1. Administrator selects desired historical commit from the revision timeline.</p>
          <p>2. Axonwall checks out <code className="text-slate-100">config.json</code> at that commit hash.</p>
          <p>3. Kernel ruleset is recompiled into <code className="text-slate-100">/run/axonwall/proposed.nft</code> and applied via <code className="text-emerald-400">axonwalld</code>.</p>
          <p>4. Commit-Confirm watchdog timer arms (60s). If administrator confirms, rollback is permanent.</p>
        </div>

        <Callout type="tip" title="Web Console Revisions">
          View all past revisions and audit history in your console at <code className="text-emerald-300 font-mono">System &gt; Configuration &amp; Revisions (/system)</code>.
        </Callout>
      </section>
    </div>
  );
}
