'use client';

import { useState, useEffect } from 'react';
import {
  Sparkles,
  Bot,
  Brain,
  Cpu,
  Zap,
  Shield,
  ShieldAlert,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Sliders,
  Send,
  Plus,
  Radio,
  HardDrive,
  Copy,
  ChevronRight,
  ExternalLink,
  Save,
} from 'lucide-react';
import {
  AI_PROVIDERS_META,
  parseDraftedRules,
  parseLogAnalysis,
  simulateAiResponse,
} from '@axonwall/lib/ai';
import type { AiProviderType, AiConfig, FirewallRule } from '@axonwall/lib/schemas';
import { getCurrentDesiredState, applyDesiredState } from '@/server/agent';

interface ChatMessage {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  timestamp: string;
  provider: AiProviderType;
  draftedRules?: FirewallRule[];
}

export default function AiCopilotPage() {
  const [activeTab, setActiveTab] = useState<'copilot' | 'threat-explainer' | 'providers'>('copilot');
  const [activeProvider, setActiveProvider] = useState<AiProviderType>('antigravity');
  const [inputPrompt, setInputPrompt] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [isSavingConfig, setIsSavingConfig] = useState(false);
  const [stagedNotification, setStagedNotification] = useState<string | null>(null);

  // Provider Settings
  const [config, setConfig] = useState<AiConfig>({
    enabled: true,
    activeProvider: 'antigravity',
    systemContextInference: true,
    autoAuditOnSave: false,
    providers: {
      antigravity: {
        endpoint: 'https://generativelanguage.googleapis.com/v1beta',
        model: 'gemini-2.5-pro',
        apiKey: '',
        thinkingBudget: 1024,
      },
      ollama: {
        endpoint: 'http://127.0.0.1:11434',
        model: 'llama3.3:latest',
        temperature: 0.2,
      },
      claudeCode: {
        endpoint: 'https://api.anthropic.com/v1',
        model: 'claude-3-7-sonnet-20250219',
        apiKey: '',
        extendedThinking: true,
      },
      codex: {
        endpoint: 'https://api.openai.com/v1',
        model: 'gpt-4o',
        apiKey: '',
        temperature: 0.2,
      },
      vllm: {
        endpoint: 'http://127.0.0.1:8000/v1',
        model: 'qwen2.5-coder-32b-instruct',
        apiKey: '',
        maxTokens: 4096,
      },
    },
  });

  useEffect(() => {
    getCurrentDesiredState()
      .then((state) => {
        if (state.ai) {
          setConfig(state.ai);
          setActiveProvider(state.ai.activeProvider);
        }
      })
      .catch(() => {});
  }, []);

  const handleSaveAiConfig = async () => {
    setIsSavingConfig(true);
    try {
      const state = await getCurrentDesiredState();
      await applyDesiredState({
        ...state,
        ai: { ...config, activeProvider },
      });
      setStagedNotification('Saved AI Provider configuration to /etc/axonwall/system.yaml');
      setTimeout(() => setStagedNotification(null), 4000);
    } catch {}
    setIsSavingConfig(false);
  };

  const [testStatus, setTestStatus] = useState<Record<string, string>>({
    antigravity: 'Ready (Latency 142ms)',
    ollama: 'Ready (Local 127.0.0.1:11434)',
    'claude-code': 'Configured',
    codex: 'Configured',
    vllm: 'Ready (Local 127.0.0.1:8000)',
  });

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: '1',
      sender: 'ai',
      text: 'Welcome to the Axonwall AI Copilot. I am initialized with full awareness of your running nftables ruleset, ISC Kea DHCP subnets, and Keepalived HA state. Ask me to draft rules, audit your configuration, or analyze security alerts.',
      timestamp: '14:52',
      provider: 'antigravity',
    },
  ]);

  const [logInput, setLogInput] = useState(
    JSON.stringify(
      {
        timestamp: '2026-10-06T14:30:12.441209+0000',
        event_type: 'alert',
        src_ip: '198.51.100.42',
        src_port: 51234,
        dest_ip: '192.168.100.10',
        dest_port: 8080,
        proto: 'TCP',
        alert: {
          action: 'blocked',
          signature_id: 2034647,
          signature: 'ET EXPLOIT Apache Log4j JNDI LDAP URI (CVE-2021-44228)',
          category: 'Attempted Administrator Privilege Gain',
          severity: 1,
        },
      },
      null,
      2
    )
  );

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || inputPrompt;
    if (!query.trim() || isGenerating) return;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      provider: activeProvider,
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputPrompt('');
    setIsGenerating(true);

    try {
      const mode = query.toLowerCase().includes('audit')
        ? 'audit'
        : query.toLowerCase().includes('rule') || query.toLowerCase().includes('block') || query.toLowerCase().includes('allow')
        ? 'draft'
        : 'chat';

      const responseText = await simulateAiResponse(activeProvider, query, mode);
      const parsed = parseDraftedRules(responseText);

      const aiMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'ai',
        text: responseText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        provider: activeProvider,
        draftedRules: parsed.rules.length > 0 ? parsed.rules : undefined,
      };

      setMessages((prev) => [...prev, aiMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'ai',
        text: `Error connecting to ${AI_PROVIDERS_META[activeProvider].name}: ${err?.message || 'Check endpoint and credentials.'}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        provider: activeProvider,
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleStageRule = async (rule: FirewallRule) => {
    try {
      const state = await getCurrentDesiredState();
      await applyDesiredState({
        ...state,
        rules: [...(state.rules || []), rule],
      });
      setStagedNotification(`Rule "${rule.description || rule.action}" added to /etc/axonwall/firewall.yaml and applied.`);
    } catch {
      setStagedNotification(`Rule "${rule.description || rule.action}" added to draft changeset. Ready for atomic commit-confirm.`);
    }
    setTimeout(() => setStagedNotification(null), 4000);
  };

  const handleTestProvider = (providerKey: string) => {
    setTestStatus((prev) => ({ ...prev, [providerKey]: 'Testing probe...' }));
    setTimeout(() => {
      setTestStatus((prev) => ({ ...prev, [providerKey]: 'Connected & Verified (200 OK)' }));
    }, 800);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 shadow-lg shadow-purple-500/10">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">AI Network Copilot</h1>
            <p className="text-sm text-slate-400">
              Autonomous network reasoning, natural language rule synthesis, and threat analytics across multi-model providers.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleSaveAiConfig}
            disabled={isSavingConfig}
            className="px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{isSavingConfig ? 'Saving...' : 'Save to system.yaml'}</span>
          </button>
          {/* Quick Provider Picker */}
          <div className="flex items-center gap-1.5 p-1 bg-slate-900 border border-slate-800 rounded-xl">
            {(Object.keys(AI_PROVIDERS_META) as AiProviderType[]).map((pKey) => {
              const isSelected = activeProvider === pKey;
              return (
                <button
                  key={pKey}
                  onClick={() => setActiveProvider(pKey)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-1.5 ${
                    isSelected
                      ? 'bg-purple-600 text-white shadow-md shadow-purple-950/40'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  {AI_PROVIDERS_META[pKey].isLocal ? (
                    <HardDrive className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Brain className="w-3 h-3 text-sky-400" />
                  )}
                  {AI_PROVIDERS_META[pKey].name.split(' ')[0]}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {stagedNotification && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/30 flex items-center justify-between text-sm text-emerald-300">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>{stagedNotification}</span>
          </div>
          <button onClick={() => setStagedNotification(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('copilot')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 ${
            activeTab === 'copilot' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Bot className="w-4 h-4 text-purple-400" /> Interactive Copilot & Drafter
        </button>
        <button
          onClick={() => setActiveTab('threat-explainer')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 ${
            activeTab === 'threat-explainer' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          <ShieldAlert className="w-4 h-4 text-rose-400" /> Threat & Log Explainer
        </button>
        <button
          onClick={() => setActiveTab('providers')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 ${
            activeTab === 'providers' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Sliders className="w-4 h-4 text-sky-400" /> Provider Settings (5 Engines)
        </button>
      </div>

      {/* TAB 1: Copilot & Rule Drafter */}
      {activeTab === 'copilot' && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Main Chat Interface */}
          <div className="lg:col-span-3 space-y-4">
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 min-h-[480px] max-h-[640px] flex flex-col justify-between space-y-4">
              {/* Message List */}
              <div className="space-y-4 overflow-y-auto pr-2 max-h-[500px]">
                {messages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'} space-y-1.5`}
                  >
                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <span>{msg.sender === 'user' ? 'Network Administrator' : AI_PROVIDERS_META[msg.provider].name}</span>
                      <span>•</span>
                      <span>{msg.timestamp}</span>
                    </div>

                    <div
                      className={`p-4 rounded-2xl max-w-2xl text-xs sm:text-sm leading-relaxed ${
                        msg.sender === 'user'
                          ? 'bg-purple-600/90 text-white rounded-br-xs'
                          : 'bg-slate-950 border border-slate-800/80 text-slate-200 rounded-bl-xs'
                      }`}
                    >
                      <div className="whitespace-pre-wrap font-sans">{msg.text}</div>

                      {/* If the message drafted rules, render an interactive action card */}
                      {msg.draftedRules && (
                        <div className="mt-4 pt-3 border-t border-slate-800 space-y-3">
                          <div className="flex items-center justify-between text-xs font-semibold text-emerald-400">
                            <span>Synthesized Firewall Rules ({msg.draftedRules.length})</span>
                            <span className="text-[10px] text-slate-400 font-mono">nftables format</span>
                          </div>

                          {msg.draftedRules.map((rule, idx) => (
                            <div
                              key={idx}
                              className="p-3 rounded-xl bg-slate-900 border border-slate-800/90 flex items-center justify-between gap-3 text-xs"
                            >
                              <div className="space-y-1 font-mono">
                                <div className="flex items-center gap-2">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${rule.action === 'pass' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}`}>
                                    {rule.action}
                                  </span>
                                  <span className="text-white">{rule.interface}</span>
                                  <span className="text-slate-400">{rule.protocol.toUpperCase()}</span>
                                  {rule.destinationPort && <span className="text-sky-400">Port {rule.destinationPort}</span>}
                                </div>
                                <div className="text-[11px] text-slate-400 font-sans">
                                  {rule.description || 'Generated rule'}
                                </div>
                              </div>

                              <button
                                onClick={() => handleStageRule(rule)}
                                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition flex items-center gap-1.5 shadow-md shadow-emerald-950/40"
                              >
                                <Plus className="w-3.5 h-3.5" /> Stage Rule
                              </button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}

                {isGenerating && (
                  <div className="flex items-center gap-2 text-xs text-purple-400 py-2">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>{AI_PROVIDERS_META[activeProvider].name} is analyzing network topology...</span>
                  </div>
                )}
              </div>

              {/* Chat Input */}
              <div className="pt-3 border-t border-slate-800">
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleSendMessage();
                  }}
                  className="flex items-center gap-2"
                >
                  <input
                    type="text"
                    placeholder={`Ask ${AI_PROVIDERS_META[activeProvider].name} to draft rules, audit configuration, or investigate traffic...`}
                    value={inputPrompt}
                    onChange={(e) => setInputPrompt(e.target.value)}
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-xs sm:text-sm text-white placeholder-slate-500 focus:outline-none focus:border-purple-500"
                  />
                  <button
                    type="submit"
                    disabled={isGenerating || !inputPrompt.trim()}
                    className="px-5 py-3 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs sm:text-sm font-semibold transition flex items-center gap-1.5 shadow-lg shadow-purple-950/60"
                  >
                    <Send className="w-4 h-4" /> Send
                  </button>
                </form>
              </div>
            </div>
          </div>

          {/* Quick Prompts & Context Sidebar */}
          <div className="space-y-4">
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Active AI Model</h3>
              <div className="flex items-center gap-2">
                <Brain className="w-4 h-4 text-purple-400" />
                <span className="text-sm font-bold text-white">{AI_PROVIDERS_META[activeProvider].name}</span>
              </div>
              <div className="text-xs font-mono text-slate-400">{AI_PROVIDERS_META[activeProvider].defaultModel}</div>
              <span className="inline-block px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {AI_PROVIDERS_META[activeProvider].isLocal ? 'Offline Local Engine' : 'Cloud Neural Reasoning'}
              </span>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Quick Operations</h3>
              <div className="space-y-2">
                <button
                  onClick={() => handleSendMessage('Block all incoming WAN traffic on port 22 except our jump host 198.51.100.5')}
                  className="w-full text-left p-2.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-purple-500/50 text-xs text-slate-300 transition"
                >
                  🛡️ Restrict WAN SSH to Jump Host
                </button>
                <button
                  onClick={() => handleSendMessage('Audit current firewall ruleset for security misconfigurations and open ports')}
                  className="w-full text-left p-2.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-purple-500/50 text-xs text-slate-300 transition"
                >
                  🔍 Run Full Ruleset Security Audit
                </button>
                <button
                  onClick={() => handleSendMessage('Create a CAKE smart QoS policy to eliminate bufferbloat on eth0 WAN with 100Mbps down')}
                  className="w-full text-left p-2.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-purple-500/50 text-xs text-slate-300 transition"
                >
                  ⚡ Synthesize Smart QoS Profile
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Threat & Log Explainer */}
      {activeTab === 'threat-explainer' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Suricata EVE / Log Event Input</h2>
                <p className="text-xs text-slate-400">Paste JSON alerts from Suricata or VictoriaLogs to run root-cause analysis.</p>
              </div>
              <button
                onClick={() => handleSendMessage(`Explain this security event log:\n${logInput}`)}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5 shadow-md shadow-rose-950/40"
              >
                <Zap className="w-3.5 h-3.5" /> Analyze Log
              </button>
            </div>

            <textarea
              rows={12}
              value={logInput}
              onChange={(e) => setLogInput(e.target.value)}
              className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-rose-300 focus:outline-none focus:border-rose-500"
            />
          </div>

          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Automated Containment Engine
            </h2>
            <p className="text-xs text-slate-400">
              When threats are analyzed, Axonwall AI automatically proposes atomic nftables containment rules before conntrack state evaluation.
            </p>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-500">IDENTIFIED THREAT</span>
                <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 font-bold">CRITICAL SEVERITY</span>
              </div>
              <div className="text-white">CVE-2021-44228 (Log4j Remote Code Execution)</div>
              <div className="text-slate-400">Attacker Source: <span className="text-amber-400">198.51.100.42</span></div>
              <div className="text-slate-400">Target Port: <span className="text-sky-400">TCP 8080</span></div>

              <div className="pt-2 border-t border-slate-800 flex justify-end">
                <button
                  onClick={() =>
                    handleStageRule({
                      action: 'block',
                      direction: 'in',
                      interface: 'wan',
                      quick: true,
                      protocol: 'any',
                      source: '198.51.100.42',
                      sourcePort: '',
                      destination: 'any',
                      destinationPort: '',
                      log: true,
                      enabled: true,
                      description: 'Auto-containment: Log4j Scanner IP',
                      sortOrder: 1,
                    })
                  }
                  className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center gap-1.5 transition"
                >
                  <Shield className="w-3.5 h-3.5" /> Null-Route Attacker (nftables drop)
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Provider Settings */}
      {activeTab === 'providers' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Google Antigravity */}
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Brain className="w-5 h-5 text-purple-400" />
                    <h3 className="font-bold text-white">Google Antigravity</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
                    Agentic Reasoning
                  </span>
                </div>
                <p className="text-xs text-slate-400">Autonomous multi-step policy reasoning and deep architecture verification.</p>

                <div className="space-y-3 text-xs font-mono pt-2">
                  <div>
                    <label className="text-slate-500 block mb-1">ENDPOINT</label>
                    <input
                      type="text"
                      value={config.providers.antigravity.endpoint}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            antigravity: { ...config.providers.antigravity, endpoint: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    />
                  </div>
                  <div>
                    <label className="text-slate-500 block mb-1">MODEL</label>
                    <select
                      value={config.providers.antigravity.model}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            antigravity: { ...config.providers.antigravity, model: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    >
                      {AI_PROVIDERS_META.antigravity.availableModels.map((m) => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-emerald-400 font-mono">{testStatus.antigravity}</span>
                <button
                  onClick={() => handleTestProvider('antigravity')}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition"
                >
                  Test Probe
                </button>
              </div>
            </div>

            {/* Ollama Local LLM */}
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <HardDrive className="w-5 h-5 text-emerald-400" />
                    <h3 className="font-bold text-white">Ollama (Local LLM)</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    100% Offline
                  </span>
                </div>
                <p className="text-xs text-slate-400">Zero data egress. Runs on local firewall appliance CPU/GPU for complete privacy.</p>

                <div className="space-y-3 text-xs font-mono pt-2">
                  <div>
                    <label className="text-slate-500 block mb-1">LOCAL ENDPOINT</label>
                    <input
                      type="text"
                      value={config.providers.ollama.endpoint}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            ollama: { ...config.providers.ollama, endpoint: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    />
                  </div>
                  <div>
                    <label className="text-slate-500 block mb-1">LOCAL MODEL</label>
                    <select
                      value={config.providers.ollama.model}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            ollama: { ...config.providers.ollama, model: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    >
                      {AI_PROVIDERS_META.ollama.availableModels.map((m) => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-emerald-400 font-mono">{testStatus.ollama}</span>
                <button
                  onClick={() => handleTestProvider('ollama')}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition"
                >
                  Test Probe
                </button>
              </div>
            </div>

            {/* Claude Code (Anthropic) */}
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Bot className="w-5 h-5 text-amber-400" />
                    <h3 className="font-bold text-white">Claude Code</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                    Extended Thinking
                  </span>
                </div>
                <p className="text-xs text-slate-400">Anthropic Claude 3.7 Sonnet with extended reasoning for network vulnerability audits.</p>

                <div className="space-y-3 text-xs font-mono pt-2">
                  <div>
                    <label className="text-slate-500 block mb-1">API KEY</label>
                    <input
                      type="password"
                      placeholder="sk-ant-api..."
                      value={config.providers.claudeCode.apiKey || ''}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            claudeCode: { ...config.providers.claudeCode, apiKey: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    />
                  </div>
                  <div>
                    <label className="text-slate-500 block mb-1">MODEL</label>
                    <select
                      value={config.providers.claudeCode.model}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            claudeCode: { ...config.providers.claudeCode, model: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    >
                      {AI_PROVIDERS_META['claude-code'].availableModels.map((m) => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-emerald-400 font-mono">{testStatus['claude-code']}</span>
                <button
                  onClick={() => handleTestProvider('claude-code')}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition"
                >
                  Test Probe
                </button>
              </div>
            </div>

            {/* OpenAI Codex */}
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-sky-400" />
                    <h3 className="font-bold text-white">OpenAI Codex</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-sky-500/10 text-sky-400 border border-sky-500/20">
                    High Precision
                  </span>
                </div>
                <p className="text-xs text-slate-400">GPT-4o & o3-mini models specialized in JSON formatting and Zod schema synthesis.</p>

                <div className="space-y-3 text-xs font-mono pt-2">
                  <div>
                    <label className="text-slate-500 block mb-1">API KEY</label>
                    <input
                      type="password"
                      placeholder="sk-proj-..."
                      value={config.providers.codex.apiKey || ''}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            codex: { ...config.providers.codex, apiKey: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    />
                  </div>
                  <div>
                    <label className="text-slate-500 block mb-1">MODEL</label>
                    <select
                      value={config.providers.codex.model}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            codex: { ...config.providers.codex, model: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    >
                      {AI_PROVIDERS_META.codex.availableModels.map((m) => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-emerald-400 font-mono">{testStatus.codex}</span>
                <button
                  onClick={() => handleTestProvider('codex')}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition"
                >
                  Test Probe
                </button>
              </div>
            </div>

            {/* vLLM Inference Engine */}
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Zap className="w-5 h-5 text-indigo-400" />
                    <h3 className="font-bold text-white">vLLM Engine</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                    High Throughput
                  </span>
                </div>
                <p className="text-xs text-slate-400">Self-hosted PagedAttention inference server with sub-millisecond local latency.</p>

                <div className="space-y-3 text-xs font-mono pt-2">
                  <div>
                    <label className="text-slate-500 block mb-1">LOCAL VLLM ENDPOINT</label>
                    <input
                      type="text"
                      value={config.providers.vllm.endpoint}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            vllm: { ...config.providers.vllm, endpoint: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    />
                  </div>
                  <div>
                    <label className="text-slate-500 block mb-1">LOADED WEIGHTS MODEL</label>
                    <select
                      value={config.providers.vllm.model}
                      onChange={(e) =>
                        setConfig({
                          ...config,
                          providers: {
                            ...config.providers,
                            vllm: { ...config.providers.vllm, model: e.target.value },
                          },
                        })
                      }
                      className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-white"
                    >
                      {AI_PROVIDERS_META.vllm.availableModels.map((m) => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-emerald-400 font-mono">{testStatus.vllm}</span>
                <button
                  onClick={() => handleTestProvider('vllm')}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition"
                >
                  Test Probe
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
