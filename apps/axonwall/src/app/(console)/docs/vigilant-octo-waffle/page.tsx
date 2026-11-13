import React from 'react';
import Link from 'next/link';
import { Shield, Layers, GitBranch, Lock, Cpu, Eye, Terminal, Server } from 'lucide-react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';

export const metadata = {
  title: 'Vigilant Octo Waffle (VOW) GitOps & DevSecOps Stack | Axonwall Documentation',
  description:
    'Turnkey Zero-Trust K3s GitOps and DevSecOps on Axonwall v0.11.68: Argo CD / Flux, Gitea, Tekton, HashiCorp Vault, DefectDojo, Wazuh SIEM, Cilium eBPF, Tetragon, and zero-touch OpenLDAP RBAC.',
};

export default function VigilantOctoWaffleDocPage() {
  return (
    <div className="space-y-12">
      {/* Page Header */}
      <div className="space-y-4 border-b border-slate-800/80 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          K3s SecOps &amp; DevSecOps Orchestration • Requires core-k3s • v0.11.68
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
          Vigilant Octo Waffle (VOW) DevSecOps &amp; GitOps Platform
        </h1>
        <p className="text-base sm:text-lg text-slate-400 leading-relaxed max-w-3xl">
          Transform your Axonwall K3s cluster into a turnkey Zero-Trust GitOps factory. Enabling the{' '}
          <code className="text-emerald-400 font-mono">vigilant-octo-waffle</code> plugin (<code className="text-slate-200 font-mono">sudo axonwallctl plugin enable vigilant-octo-waffle</code>) reconciles the{' '}
          <code className="text-emerald-400 font-mono">vow:</code> specification inside{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/k3s.yaml</code>—provisioning Argo CD or Flux, Gitea, Tekton, Vault, Wazuh, Cilium, Tetragon, Unbound split-horizon DNS records, and zero-touch OpenLDAP RBAC directly onto your appliance.
        </p>
      </div>

      {/* Section 1: VOW Stack */}
      <section id="vow-stack" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <GitBranch className="w-6 h-6 text-emerald-400" /> 1. Vigilant Octo Waffle (<code className="font-mono text-emerald-400">vow:</code> in <code className="font-mono text-emerald-400">/etc/axonwall/k3s.yaml</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          When <code className="text-emerald-400 font-mono">vow.enabled: true</code> is declared in{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/k3s.yaml</code>,{' '}
          <code className="text-white font-mono">axonwalld</code> verifies that <code className="text-emerald-400 font-mono">core-k3s</code>{' '}
          is active, syncs wildcard/app records into Unbound (<code className="text-slate-200 font-mono">syncUnboundDns: true</code>), mints internal TLS certificates (<code className="text-slate-200 font-mono">localTlsMkcert: true</code>), and reconciles the GitOps CD runner (<code className="text-slate-200 font-mono">argocd</code>, <code className="text-slate-200 font-mono">flux</code>, or <code className="text-slate-200 font-mono">both</code>):
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Argo CD / Flux + Gitea + Tekton</h3>
            <p className="text-slate-400 leading-relaxed">
              Continuous GitOps reconciliation (<code className="text-slate-200">cdRunner: &apos;argocd&apos; | &apos;flux&apos; | &apos;both&apos;</code>) paired with self-hosted Gitea repositories, Tekton pipelines, Cosign signing, and SBOM attestation.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Vault, DefectDojo &amp; OpenLDAP RBAC</h3>
            <p className="text-slate-400 leading-relaxed">
              Zero-touch <code className="text-slate-200">ldapAuth</code> auto-provisions the <code className="text-emerald-300 font-mono">svc-vow</code> bind account and <code className="text-emerald-300 font-mono">vow-admin</code>, <code className="text-emerald-300 font-mono">vow-operator</code>, and <code className="text-emerald-300 font-mono">vow-readonly</code> groups in embedded OpenLDAP.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white text-sm">Cilium, Tetragon &amp; Wazuh SIEM</h3>
            <p className="text-slate-400 leading-relaxed">
              eBPF L7 service-mesh microsegmentation (Cilium), runtime process enforcement (Tetragon), and stateful Wazuh XDR/SIEM backed by <code className="text-slate-200">axonwall-zfs-local</code> or <code className="text-slate-200">axonwall-replicated-ha</code> volumes.
            </p>
          </div>
        </div>

        <CodeBlock
          title="/etc/axonwall/k3s.yaml — VowConfigSchema (vow:)"
          language="yaml"
          code={`vow:
  enabled: true
  cdRunner: argocd               # 'argocd' | 'flux' | 'both'
  domain: vow.axonwall.local
  gitRepoUrl: https://github.com/DeployCoop/vigilant-octo-waffle.git
  localTlsMkcert: true
  syncUnboundDns: true
  activePreset: enterprise-secops
  enabledApps:
    - gitea
    - tekton
    - vault
    - defectdojo
    - wazuh
    - cilium
    - tetragon
  appOverrides:
    wazuh:
      storageClass: axonwall-replicated-ha
    gitea:
      storageClass: axonwall-zfs-local
  ldapAuth:
    enabled: true
    bindAccountCn: svc-vow
    adminGroup: vow-admin
    operatorGroup: vow-operator
    readonlyGroup: vow-readonly`}
        />

        <Callout type="tip" title="Manage via Web Console or Neovim Super Configurator">
          Edit VOW presets, storage classes, and OpenLDAP group bindings in the Web Console or via{' '}
          <code className="font-mono text-emerald-300">axonwall-config k3s</code> (editing <code className="font-mono text-emerald-300">/etc/axonwall/k3s.yaml</code>).
        </Callout>
      </section>

      {/* Section 2: Vigilante Cyber Operations */}
      <section id="vigilante-soc" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" /> 2. Companion Role: Vigilante Autonomous SOC (<code className="font-mono text-emerald-400">core-vigilante</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Paired with K3s and VOW, Axonwall&apos;s <code className="text-emerald-400 font-mono">core-vigilante</code> Core Role (<code className="text-emerald-400 font-mono">/etc/axonwall/vigilante.yaml</code>) provides autonomous SOC &amp; SOAR operations across BattleStation triage, Attack Graph correlation, Cyber Deception honeynets, Forensics evidence chains, and Purple Team MITRE ATT&amp;CK validation:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-white text-sm">BattleStation &amp; Attack Graph</div>
            <p className="text-slate-400">
              Real-time lateral-movement blast-radius visualization correlating Suricata alerts, CrowdSec decisions, eBPF process trees, and K3s pod identity edges.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
            <div className="font-bold text-white text-sm">Deception, Forensics, SOAR &amp; Purple Team</div>
            <p className="text-slate-400">
              Deploy high-interaction decoy services, capture volatile memory/pcap evidence chains, and execute automated SOAR containment playbooks.
            </p>
          </div>
        </div>

        <Callout type="info" title="Full Vigilante Cyber Operations Documentation">
          Explore the complete architecture, <code className="font-mono text-emerald-300">/etc/axonwall/vigilante.yaml</code> schema, and SOAR runbooks in{' '}
          <Link href="/docs/vigilante-cyber-ops" className="font-mono text-emerald-300 underline">
            /docs/vigilante-cyber-ops
          </Link>
          .
        </Callout>
      </section>
    </div>
  );
}
