import React from 'react';
import Link from 'next/link';
import { GitBranch, History, ShieldCheck, CheckCircle2, RotateCcw, FileDiff } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'GitOps Configuration Versioning & Etckeeper /etc Audit | Axonwall Documentation',
  description:
    'Git-backed declarative YAML configuration versioning (/var/lib/axonwall/gitops), unified diff inspection, 1-click rollback, and Etckeeper /etc host configuration auditing in Axonwall v0.11.68.',
};

export default function GitOpsAuditDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Version Control &amp; Compliance Audit • v0.11.68
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          GitOps Configuration &amp; Etckeeper /etc Audit Trail
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Bring software engineering rigor to network security. Every Axonwall policy transaction across the 12 canonical <code className="text-emerald-400 font-mono">/etc/axonwall/*.yaml</code> domain files is recorded in an immutable Git revision repository (<code className="text-emerald-400 font-mono">/var/lib/axonwall/gitops</code>), paired with full host <code className="text-white font-mono">/etc</code> configuration versioning via integrated <strong>Etckeeper</strong>.
        </p>
      </div>

      {/* GitOps Architecture */}
      <section id="versioning" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <GitBranch className="w-6 h-6 text-emerald-400" /> Git-Backed Declarative State Management
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          The complete desired state of your Axonwall appliance is authored across 12 canonical YAML domain files in <code className="text-emerald-400 font-mono">/etc/axonwall/*.yaml</code> (plus optional <code className="text-slate-200 font-mono">/etc/axonwall/conf.d/*.yaml</code> drop-ins) and compiled into <code className="text-slate-200 font-mono">/etc/axonwall/state.json</code>. Behind the scenes, <code className="text-emerald-400 font-mono">axonwalld</code> maintains a dedicated local Git repository at <code className="text-emerald-400 font-mono">/var/lib/axonwall/gitops</code> tracking every confirmed bundle:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400">Non-Repudiation</span>
            <p className="text-slate-400">Every commit records the logged-in administrator or API actor identity, timestamp, and human-readable commit message.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-sky-400">Cryptographic Integrity</span>
            <p className="text-slate-400">Git SHA-1/SHA-256 tree hashes prevent silent tampering, satisfying strict compliance standards (SOC 2, PCI-DSS, ISO 27001).</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400">Automated History</span>
            <p className="text-slate-400">Confirmed changes from the Web Console, Neovim TUI (<code className="text-slate-200">axonwall-config</code>), REST API, or <code className="text-slate-200">axonwallctl apply</code> commit automatically.</p>
          </div>
        </div>
      </section>

      {/* Unified Diff Inspection */}
      <section id="diff-inspection" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <FileDiff className="w-6 h-6 text-emerald-400" /> Unified Diff Inspection
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Before applying changes (<code className="text-emerald-400 font-mono">axonwallctl diff</code> or <code className="text-emerald-400 font-mono">&lt;C-d&gt;</code> inside <code className="text-slate-200 font-mono">axonwall-config</code>) or rolling back to an earlier revision, administrators can inspect exact YAML deltas in a unified diff viewer:
        </p>

        <CodeBlock
          title="git diff HEAD~1 (/var/lib/axonwall/gitops)"
          language="diff"
          code={`--- a/firewall.yaml
+++ b/firewall.yaml
@@ -18,6 +18,13 @@ rules:
+  - id: rule_dmz_https
+    enabled: true
+    interface: wan
+    action: pass
+    protocol: tcp
+    destinationPort: "443"
+    description: Allow inbound HTTPS to DMZ cluster`}
        />
      </section>

      {/* 1-Click Rollback */}
      <section id="rollback" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <RotateCcw className="w-6 h-6 text-emerald-400" /> 1-Click Rollback Lifecycle
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          If a recent policy change causes unexpected business disruption, rolling back takes a single click in the Web Console or a single command (<code className="text-emerald-400 font-mono">sudo axonwallctl rollback [revision]</code>):
        </p>

        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3 font-mono text-xs text-slate-300">
          <div className="text-emerald-400 font-bold">ROLLBACK EXECUTION FLOW:</div>
          <p>1. Administrator selects desired historical commit SHA from <code className="text-slate-100">/var/lib/axonwall/gitops</code>.</p>
          <p>2. Axonwall restores <code className="text-slate-100">/etc/axonwall/*.yaml</code> and <code className="text-slate-100">/etc/axonwall/state.json</code> at that revision.</p>
          <p>3. Kernel ruleset is pre-flight validated (<code className="text-slate-100">nft -c</code>) and applied atomically via <code className="text-emerald-400">axonwalld</code>.</p>
          <p>4. Commit-Confirm watchdog timer arms (60–120s). Once confirmed, the rollback revision becomes HEAD.</p>
        </div>
      </section>

      {/* Etckeeper Host /etc Configuration Versioning */}
      <section id="etckeeper" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <History className="w-6 h-6 text-emerald-400" /> Etckeeper Host <code className="font-mono text-emerald-400">/etc</code> Configuration Versioning
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          While <code className="text-emerald-400 font-mono">/var/lib/axonwall/gitops</code> versions Axonwall&apos;s declarative YAML intent, enterprise compliance audits also require tracking every low-level daemon file rendered across <code className="text-white font-mono">/etc</code> (such as <code className="text-slate-200 font-mono">/etc/keepalived/</code>, <code className="text-slate-200 font-mono">/etc/unbound/</code>, <code className="text-slate-200 font-mono">/etc/ssh/sshd_config</code>, <code className="text-slate-200 font-mono">/etc/pam.d/</code>, and APT package postinst changes). Axonwall natively integrates <strong>Etckeeper</strong> with first-class daemon APIs and a dedicated Web Console workspace at <Link href="/system/etckeeper" className="text-emerald-400 underline font-mono">/system/etckeeper</Link>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Automatic Bundle-Apply &amp; APT Hooks</h3>
            <p className="text-slate-400 leading-relaxed">
              When <code className="text-emerald-400 font-mono">autoCommitOnApply: true</code> is enabled, <code className="text-slate-200 font-mono">axonwalld</code> automatically triggers an Etckeeper Git commit across <code className="text-slate-200 font-mono">/etc</code> after every confirmed configuration bundle apply, alongside standard daily cron and APT pre/post-install hooks.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Secret Exclusion (.gitignore) &amp; Diff Viewer</h3>
            <p className="text-slate-400 leading-relaxed">
              Manage <code className="text-slate-200 font-mono">/etc/.gitignore</code> rules directly in the UI (ensuring sensitive key material like <code className="text-slate-200 font-mono">/etc/axonwall/agent.token</code> or shadow hashes remain excluded as configured), create manual commit snapshots before maintenance windows, browse full commit history, and inspect colorized unified diffs per commit.
            </p>
          </div>
        </div>

        <CodeBlock
          title="axonwalld Etckeeper Agent Socket Endpoints (/run/axonwall/agent-api.sock)"
          language="bash"
          code={`# Check Etckeeper Git repo initialization state, dirty file count, and config:
sudo curl -s --unix-socket /run/axonwall/agent-api.sock \\
  -H "X-Axonwall-Agent-Token: $(sudo cat /etc/axonwall/agent.token)" \\
  http://localhost/v1/system/etckeeper/status | jq .

# Full Etckeeper lifecycle endpoints exposed by axonwalld:
# GET  /v1/system/etckeeper/status   -> Repo status, VCS backend, dirty files, autoCommitOnApply
# POST /v1/system/etckeeper/init     -> Initialize /etc Git repository via 'etckeeper init'
# POST /v1/system/etckeeper/config   -> Update etckeeper.conf, autoCommitOnApply & /etc/.gitignore
# POST /v1/system/etckeeper/commit   -> Create manual snapshot commit with operator message
# GET  /v1/system/etckeeper/history  -> List /etc Git commit log (SHA, author, timestamp, subject)
# GET  /v1/system/etckeeper/diff     -> Unified diff for a specific commit (?commit=<sha>)`}
        />

        <Callout type="tip" title="Web Console Revisions & Etckeeper">
          View Axonwall GitOps revisions at <code className="text-emerald-300 font-mono">System &gt; Configuration &amp; Revisions (/system)</code>, and manage host-wide <code className="text-emerald-300 font-mono">/etc</code> commits, <code className="text-emerald-300 font-mono">.gitignore</code> rules, and diffs at <Link href="/system/etckeeper" className="text-emerald-300 underline font-mono">/system/etckeeper</Link>.
        </Callout>
      </section>
    </div>
  );
}
