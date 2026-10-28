import React from 'react';
import Link from 'next/link';
import { Shield, Layers, GitBranch, Lock, Cpu, Eye, Terminal, Server } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Vigilant Octo Waffle (VOW) GitOps & Vigilante Cyber Operations | Axonwall Documentation',
  description:
    'Turnkey Zero-Trust K3s GitOps, DevSecOps, and Purple-Team Cyber Operations on Axonwall: Gitea, Tekton, HashiCorp Vault, DefectDojo, Wazuh SIEM, Cilium eBPF, Tetragon, and the Vigilante SOC suite.',
};

export default function VigilantOctoWaffleDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          K3s SecOps &amp; DevSecOps Orchestration • Requires core-k3s
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Vigilant Octo Waffle &amp; Vigilante Cyber Operations
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Transform your Axonwall K3s cluster into a turnkey Zero-Trust GitOps factory and autonomous Security Operations
          Center (SOC). The <code className="text-emerald-400 font-mono">vigilant-octo-waffle</code> plugin (with automatic{' '}
          <code className="text-white font-mono">core-k3s</code> dependency enforcement) provisions hardened Helm charts,
          NetworkPolicies, and Purple-Team defensive sensors directly onto your appliance.
        </p>
      </div>

      {/* Section 1: VOW Stack */}
      <section id="vow-stack" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <GitBranch className="w-6 h-6 text-emerald-400" /> 1. Vigilant Octo Waffle (<code className="font-mono text-emerald-400">vigilant-octo-waffle</code>) K3s Stack
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          When enabled in <code className="text-emerald-400 font-mono">/etc/axonwall/vow.yaml</code>,{' '}
          <code className="text-white font-mono">axonwalld</code> verifies that <code className="text-emerald-400 font-mono">core-k3s</code>{' '}
          is active and reconciles an air-gap-ready Kubernetes manifest bundle into{' '}
          <code className="text-white font-mono">/var/lib/rancher/k3s/server/manifests/axonwall-vow.yaml</code>:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Gitea + Tekton CI/CD</h3>
            <p className="text-slate-400 leading-relaxed">
              Self-hosted Git repositories and Tekton cloud-native pipelines with Cosign container image signing and
              SBOM attestation.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">HashiCorp Vault &amp; DefectDojo</h3>
            <p className="text-slate-400 leading-relaxed">
              Centralized PKI/secrets management paired with DefectDojo vulnerability deduplication and Trivy container
              admission scanning.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Cilium, Tetragon &amp; Wazuh SIEM</h3>
            <p className="text-slate-400 leading-relaxed">
              eBPF L7 service-mesh microsegmentation (Cilium), runtime process enforcement (Tetragon), and full Wazuh
              XDR/SIEM telemetry correlation.
            </p>
          </div>
        </div>

        <CodeBlock
          title="/etc/axonwall/vow.yaml"
          language="yaml"
          code={`enabled: true
namespace: "vow-system"
ingressDomain: "vow.axonwall.lan"
storageClass: "openebs-zfs-localpv"
airgapMode: false
autoSyncGitOps: true
gitRepoUrl: "https://github.com/DeployCoop/vigilant-octo-waffle.git"
gitBranch: "main"

components:
  gitea: true
  tekton: true
  vault: true
  defectDojo: true
  wazuh: true
  cilium: true
  tetragon: true
  trivy: true
  velero: true`}
        />
      </section>

      {/* Section 2: Vigilante Cyber Operations */}
      <section id="vigilante-soc" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" /> 2. Vigilante Cyber Operations Suite (<code className="font-mono text-emerald-400">/vigilante/*</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Paired with K3s and the Axonwall security engine, the <strong>Vigilante</strong> console provides six
          integrated cyber-defense workspaces:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-white text-sm">BattleStation &amp; Attack Graph</div>
            <p className="text-slate-400">
              Real-time lateral-movement blast-radius visualization correlating Suricata alerts, CrowdSec decisions, and
              K3s pod identity edges.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-white text-sm">Deception, Forensics &amp; Purple Team</div>
            <p className="text-slate-400">
              Deploy high-interaction decoy services, capture volatile memory/pcap evidence chains, and run continuous
              MITRE ATT&amp;CK validation exercises against your active nftables &amp; eBPF rules.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
