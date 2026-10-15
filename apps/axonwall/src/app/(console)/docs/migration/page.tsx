import React from 'react';
import Link from 'next/link';
import { FileCode, UploadCloud, CheckCircle2, AlertTriangle, Layers, ArrowRight, Shield } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Migration Studio & Importer | Axonwall Documentation',
  description:
    'Complete guide to migrating from pfSense, OPNsense, and Cisco ASA/FTD to Axonwall: automated config parsing, rule shadowing detection, dead-rule analysis, and selective cherry-pick merge.',
};

export default function MigrationDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          Enterprise Tooling
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Migration Studio & Multi-Vendor Importer
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Seamlessly transition from legacy firewalls to Axonwall. Import existing configurations from <code className="text-white font-mono">pfSense®</code>, <code className="text-white font-mono">OPNsense®</code>, and <code className="text-white font-mono">Cisco ASA / FTD</code> with automated rule shadowing and anomaly detection.
        </p>
      </div>

      {/* Supported Platforms */}
      <section id="supported-platforms" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <UploadCloud className="w-6 h-6 text-emerald-400" /> Supported Firewall Platforms
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <h3 className="font-bold text-white text-sm">pfSense® (config.xml)</h3>
            <p className="text-slate-400 leading-relaxed">
              Parses XML backup archives. Extracts network aliases, filter rules, port forwards, 1:1 NAT, gateways, and DHCP static reservations.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <h3 className="font-bold text-white text-sm">OPNsense® (config.xml)</h3>
            <p className="text-slate-400 leading-relaxed">
              Full compatibility with OPNsense 24.x/25.x XML schemas, including nested network groups, rule categories, and Unbound overrides.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <h3 className="font-bold text-white text-sm">Cisco ASA / FTD (CLI)</h3>
            <p className="text-slate-400 leading-relaxed">
              Parses raw Cisco CLI <code className="text-slate-300">running-config</code> exports, translating <code className="text-slate-300">object-group</code>, <code className="text-slate-300">access-list extended</code>, and NAT statements.
            </p>
          </div>
        </div>

        <h3 className="text-base font-semibold text-white pt-2">Cisco ASA CLI Parsing Example</h3>
        <CodeBlock
          title="cisco_asa_running_config.txt"
          language="cisco"
          code={`object network WEB_SERVER
 host 192.168.10.50
 description Primary Web Node

object-group network DMZ_SERVERS
 network-object 192.168.10.0 255.255.255.0

object-group service WEB_SERVICES tcp
 port-object eq 80
 port-object eq 443

access-list OUTSIDE_IN extended permit tcp any object WEB_SERVER eq 443
access-list OUTSIDE_IN extended permit object-group DMZ_SERVERS any object-group WEB_SERVICES`}
        />
      </section>

      {/* Rule Shadowing & Dead Rule Detection */}
      <section id="shadowing-algorithm" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-6 h-6 text-amber-400" /> Rule Shadowing & Dead-Rule Detection
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Over years of maintenance, legacy firewalls accumulate redundant, obsolete, and shadowed rules. Axonwall&apos;s Policy Analyzer conducts deep mathematical set analysis before importing rules:
        </p>

        <div className="space-y-4">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-400" /> How Rule Shadowing Occurs
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Rule <strong>B</strong> is shadowed by Rule <strong>A</strong> when every packet that could match Rule B is already intercepted by Rule A preceding it:
            </p>
            <div className="p-3 rounded-lg bg-black/40 font-mono text-xs space-y-1 text-slate-300">
              <p className="text-emerald-400">Rule 1 (A): Pass TCP from 10.0.0.0/16 to any port 443</p>
              <p className="text-rose-400">Rule 2 (B): Pass TCP from 10.0.1.0/24 to any port 443 [SHADOWED]</p>
            </div>
            <p className="text-xs text-slate-400">
              Axonwall flags shadowed rules directly in the Migration UI, allowing administrators to prune dead security policies before committing them into nftables.
            </p>
          </div>

          <h3 className="text-base font-semibold text-white pt-2">Subnet Collision Detection</h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            The analyzer verifies that imported network prefixes do not collide with active physical interfaces, preventing routing loops or accidental network severance.
          </p>
        </div>
      </section>

      {/* Cherry-Pick Selective Merge */}
      <section id="selective-merge" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-emerald-400" /> Cherry-Pick Selective Merge Engine
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Unlike legacy tools that force an &quot;all-or-nothing&quot; overwrite, Axonwall provides an interactive selective merge engine. Administrators can cherry-pick specific aliases, port-forwards, or rules:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="font-bold text-emerald-400 block mb-1">Skip Strategy</span>
            <p className="text-slate-400">Retains existing Axonwall entity and discards the imported duplicate with identical identifier.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="font-bold text-sky-400 block mb-1">Overwrite Strategy</span>
            <p className="text-slate-400">Replaces the active Axonwall object with the newly imported configuration definition.</p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
            <span className="font-bold text-purple-400 block mb-1">Rename Strategy</span>
            <p className="text-slate-400">Preserves both objects by automatically suffixing the imported record with <code className="text-slate-200">_imported</code>.</p>
          </div>
        </div>

        <Callout type="tip" title="Web Console Access">
          Access Migration Studio in your running appliance at <code className="text-emerald-300 font-mono">System &gt; Firewall Importer (/system/import)</code>.
        </Callout>
      </section>
    </div>
  );
}
