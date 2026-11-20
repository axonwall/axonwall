import React from 'react';
import { Callout } from '../components/Callout';
import { CodeBlock } from '../components/CodeBlock';
import {
  Sparkles,
  Shield,
  Cpu,
  Lock,
  Layers,
  Activity,
  Terminal,
  Database,
} from 'lucide-react';

export const metadata = {
  title: 'Eluvix Sovereign AI Router, Tokenomics & DLP Guard | Axonwall Documentation',
  description:
    'Technical documentation for the Eluvix Sovereign AI Router plugin (eluvix) in /etc/axonwall/system.yaml: Switchyard 4-tier model routing (:8080), PromptGuard injection defense, PrivacyGuard PII/secret DLP tokenization, 8 agent harnesses, and enterprise tokenomics.',
};

export default function EluvixAiRouterDocPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="space-y-4 border-b border-slate-800 pb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-950/60 border border-purple-500/30 text-purple-300 text-xs font-semibold">
          <Sparkles className="w-3.5 h-3.5" /> Sovereign AI Gateway • DLP &amp; Tokenomics • v0.11.68
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Eluvix Sovereign AI Router &amp; Prompt/PII DLP Guard
        </h1>
        <p className="text-base text-slate-400 leading-relaxed max-w-3xl">
          The <code className="text-emerald-400 font-mono">eluvix</code> plugin (<code className="text-slate-200 font-mono">sudo axonwallctl plugin enable eluvix</code>) embeds the{' '}
          <strong className="text-white">Eluvix Sovereign AI Router</strong> directly into your Axonwall perimeter (control plane on port <code className="text-emerald-400 font-mono">3588</code> and Switchyard OpenAI/Anthropic-compatible proxy on port <code className="text-emerald-400 font-mono">8080</code>).
          Instead of allowing developer workstations, autonomous coding agents, and internal services to send raw source
          code, API keys, and PII directly to external cloud LLM APIs, Eluvix intercepts, sanitizes, caches, and routes
          every AI request through a zero-trust sovereign gateway.
        </p>
      </div>

      {/* 1. Switchyard 4-Tier Complexity Router */}
      <section id="switchyard" className="space-y-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-6 h-6 text-emerald-400" /> 1. Switchyard 4-Tier Complexity Routing
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Up to 75% of enterprise LLM traffic consists of low-complexity boilerplate, JSON formatting, log summarization,
          and tool-call argument extraction. Eluvix&apos;s <strong className="text-white">Switchyard</strong> classifier
          evaluates prompt complexity in sub-millisecond time and routes requests across four configurable tiers:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-emerald-400 text-sm">Tier 1 &amp; Tier 2: Local Sovereign SLMs ($0 / token)</div>
            <p className="text-slate-400 leading-relaxed">
              Routine classification, tool-call parsing, and code completion are routed to on-premise{' '}
              <code className="text-slate-200 font-mono">Ollama</code>, <code className="text-slate-200 font-mono">vLLM</code>,
              or <code className="text-slate-200 font-mono">Lemonade</code> NPU/GPU inference nodes on your LAN—keeping
              sensitive data 100% on-premise at zero marginal token cost.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-sky-400 text-sm">Tier 3 &amp; Tier 4: Sanitized Frontier Cloud Synthesis</div>
            <p className="text-slate-400 leading-relaxed">
              Deep architectural reasoning and multi-file synthesis are routed to frontier providers (Google Gemini,
              Anthropic Claude, OpenAI) only <strong className="text-slate-200">after</strong> passing through inline
              PromptGuard and PrivacyGuard DLP redaction.
            </p>
          </div>
        </div>
      </section>

      {/* 2. PromptGuard & PrivacyGuard DLP */}
      <section id="dlp-guard" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Lock className="w-6 h-6 text-amber-400" /> 2. Inline PromptGuard &amp; Reversible PrivacyGuard DLP
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Every inbound prompt and outbound tool observation passes through two deterministic security stages before
          reaching any external model:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" /> PrivacyGuard Reversible Tokenization
            </div>
            <p className="text-slate-400 leading-relaxed">
              Automatically detects and replaces AWS keys (<code className="text-slate-200 font-mono">AKIA*</code>),
              GitHub tokens (<code className="text-slate-200 font-mono">ghp_*</code>), OpenAI/Anthropic keys (<code className="text-slate-200 font-mono">sk-*</code>),
              PEM private keys, internal RFC 1918 IPv4/IPv6 addresses, emails, and SSNs with deterministic vault placeholders
              (e.g. <code className="text-emerald-300 font-mono">&lt;ELUVIX_SECRET_01&gt;</code>) before cloud egress, and
              re-hydrates them in the streaming response.
            </p>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="font-bold text-white text-sm flex items-center gap-2">
              <Activity className="w-4 h-4 text-amber-400" /> PromptGuard Injection &amp; Exfiltration Filter
            </div>
            <p className="text-slate-400 leading-relaxed">
              Inspects multi-turn agent context and MCP tool stdout/stderr for indirect prompt injections, system-prompt
              extraction attempts, and covert markdown/URL data exfiltration channels.
            </p>
          </div>
        </div>
      </section>

      {/* 3. Supported Agent Harnesses */}
      <section id="harnesses" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-purple-400" /> 3. Native Agent Harness Multiplexer (8 Harnesses)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Eluvix includes first-class protocol adapters and deep-fork runtime harnesses for autonomous coding and SecOps
          agents:
        </p>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-300">
                <th className="py-3 px-4 font-bold">Harness ID</th>
                <th className="py-3 px-4 font-bold">Protocol / Port</th>
                <th className="py-3 px-4 font-bold">Sovereign Integration Capabilities</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-3 px-4 font-mono text-emerald-400 font-semibold">opencode</td>
                <td className="py-3 px-4 font-mono">HTTP SSE (:4096)</td>
                <td className="py-3 px-4">Inline DLP on tool stdout/stderr, KV-cache prefix pinning, zero-copy Axonwall MCP binding.</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-sky-400 font-semibold">acp</td>
                <td className="py-3 px-4 font-mono">JSON-RPC 2.0 stdio</td>
                <td className="py-3 px-4">Universal multiplexer for Antigravity (<code className="font-mono">agy</code>), Claude Code ACP, and Goose inside gVisor/Firecracker.</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-purple-400 font-semibold">trueforge</td>
                <td className="py-3 px-4 font-mono">In-Process ReAct (:3588)</td>
                <td className="py-3 px-4">Sub-ms Switchyard tier switching per reasoning step + Graphiti episodic memory graph.</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-amber-400 font-semibold">openhands</td>
                <td className="py-3 px-4 font-mono">Action Stream (:3000)</td>
                <td className="py-3 px-4">Sandbox egress enforced via Axonwall nftables + credential scrubbing on bash observations.</td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-mono text-slate-200 font-semibold">mastra / letta / a2a / hermes</td>
                <td className="py-3 px-4 font-mono">:4111 / :8283 / :41241 / :4280</td>
                <td className="py-3 px-4">Structured workflows, stateful memory blocks, Google A2A JSON-RPC peer cards, and multi-channel messaging.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* 4. Declarative Configuration */}
      <section id="configuration" className="space-y-6 pt-6 border-t border-slate-800/80">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Database className="w-6 h-6 text-emerald-400" /> 4. Declarative Configuration (<code className="font-mono text-emerald-400">eluvix:</code> in <code className="font-mono text-emerald-400">/etc/axonwall/system.yaml</code>)
        </h2>
        <p className="text-sm text-slate-300 leading-relaxed">
          Enable the built-in <code className="text-emerald-400 font-mono">eluvix</code> plugin via{' '}
          <code className="text-emerald-400 font-mono">sudo axonwallctl plugin enable eluvix</code>, then configure{' '}
          <code className="text-emerald-400 font-mono">eluvix:</code> inside{' '}
          <code className="text-emerald-400 font-mono">/etc/axonwall/system.yaml</code>:
        </p>

        <CodeBlock
          title="/etc/axonwall/system.yaml — EluvixConfigSchema (eluvix:)"
          language="yaml"
          code={`eluvix:
  enabled: true
  deploymentMode: systemd          # 'systemd' | 'docker' | 'k3s-helm'
  listenPort: 3588
  switchyardPort: 8080
  domain: eluvix.axonwall.local
  teePolicy: prefer-sev-snp
  ldapAuth:
    enabled: true
    bindAccountCn: svc-eluvix
    adminGroup: eluvix-admin
    operatorGroup: eluvix-operator
    readonlyGroup: eluvix-readonly
  tokenomics:
    strategy: hybrid-sovereign
    semanticCacheEnabled: true
    kvArchitecture: deepseek-mla-fp8
    rdmaConnector: vllm-nixl
  promptGuard:
    enabled: true
    blockIndirectInjection: true
    inspectMcpToolStdout: true
  privacyGuard:
    enabled: true
    reversibleTokenization: true
    redactSecrets: true
    redactPii: true
    redactInternalIps: true
  harnessMesh:
    enabled: true
    sandboxBackend: gvisor
    memoryEngine: graphiti
    injectAxonwallMcp: true
    enabledHarnesses:
      - opencode
      - trueforge
      - acp
      - openhands
      - mastra
      - letta
      - a2a
      - hermes`}
        />

        <Callout type="tip" title="Manage via Web Console, Neovim TUI, or CLI">
          Configure Eluvix routing tiers, OpenLDAP RBAC bindings, KV-cache/RDMA tokenomics, and DLP redaction policies from the Web
          Console at <code className="font-mono text-emerald-300">/ai/eluvix</code>, in the Neovim Super Configurator via{' '}
          <code className="font-mono text-emerald-300">axonwall-config system</code>, or verify status via{' '}
          <code className="font-mono text-emerald-300">axonwallctl status</code>.
        </Callout>
      </section>
    </div>
  );
}
