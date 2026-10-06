import {
  FirewallRuleSchema,
  type FirewallRule,
  type AiProviderType,
  type AiConfig,
  type DesiredState,
} from '../schemas/index.js';

export interface AiProviderMeta {
  id: AiProviderType;
  name: string;
  defaultEndpoint: string;
  defaultModel: string;
  availableModels: string[];
  isLocal: boolean;
  description: string;
  docsUrl: string;
}

export const AI_PROVIDERS_META: Record<AiProviderType, AiProviderMeta> = {
  antigravity: {
    id: 'antigravity',
    name: 'Google Antigravity',
    defaultEndpoint: 'https://generativelanguage.googleapis.com/v1beta',
    defaultModel: 'gemini-2.5-pro',
    availableModels: ['gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-1.5-pro'],
    isLocal: false,
    description: 'Autonomous reasoning engine with deep multi-step planning and policy synthesis.',
    docsUrl: 'https://cloud.google.com/vertex-ai',
  },
  ollama: {
    id: 'ollama',
    name: 'Ollama (Local LLM)',
    defaultEndpoint: 'http://127.0.0.1:11434',
    defaultModel: 'llama3.3:latest',
    availableModels: ['llama3.3:latest', 'qwen2.5-coder:32b', 'mistral:latest', 'deepseek-r1:32b'],
    isLocal: true,
    description: '100% on-premise offline inference running on local CPU/GPU with zero data egress.',
    docsUrl: 'https://ollama.ai',
  },
  'claude-code': {
    id: 'claude-code',
    name: 'Claude Code (Anthropic)',
    defaultEndpoint: 'https://api.anthropic.com/v1',
    defaultModel: 'claude-3-7-sonnet-20250219',
    availableModels: ['claude-3-7-sonnet-20250219', 'claude-3-5-haiku-20241022'],
    isLocal: false,
    description: 'Anthropic agentic model with extended thinking and rigorous code safety verification.',
    docsUrl: 'https://docs.anthropic.com',
  },
  codex: {
    id: 'codex',
    name: 'OpenAI Codex',
    defaultEndpoint: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4o',
    availableModels: ['gpt-4o', 'o3-mini', 'o1', 'gpt-4o-mini'],
    isLocal: false,
    description: 'OpenAI high-performance reasoning model specialized in networking and JSON schemas.',
    docsUrl: 'https://platform.openai.com',
  },
  vllm: {
    id: 'vllm',
    name: 'vLLM Inference Engine',
    defaultEndpoint: 'http://127.0.0.1:8000/v1',
    defaultModel: 'qwen2.5-coder-32b-instruct',
    availableModels: ['qwen2.5-coder-32b-instruct', 'meta-llama/Llama-3.3-70B-Instruct', 'mistralai/Mistral-Large-Instruct'],
    isLocal: true,
    description: 'Self-hosted, high-throughput PagedAttention inference server with OpenAI-compatible API.',
    docsUrl: 'https://docs.vllm.ai',
  },
};

/**
 * Builds the base system prompt equipping the model with Axonwall & nftables domain context.
 */
export function buildSystemPrompt(context?: {
  hostname?: string;
  interfaces?: string[];
  rulesCount?: number;
}): string {
  const ifaceList = context?.interfaces?.join(', ') || 'eth0 (WAN), eth1 (LAN)';
  const hostname = context?.hostname || 'axonwall';
  const rulesCount = context?.rulesCount ?? 12;

  return [
    `You are the Axonwall AI Network Copilot for host "${hostname}".`,
    `Axonwall is a Linux-native firewall running nftables v1.1+, ISC Kea, Unbound, and Keepalived VRRP.`,
    `Current interfaces: ${ifaceList}. Active firewall rules count: ${rulesCount}.`,
    `Core Architectural Rules:`,
    `- Axonwall owns strictly 'table inet axonwall'. Never suggest 'flush ruleset'.`,
    `- Changes are committed using a 60-second commit-confirm countdown with auto-rollback.`,
    `- When drafting rules, output JSON adhering strictly to Axonwall's FirewallRuleSchema:`,
    `  { "action": "pass"|"block"|"reject", "direction": "in"|"out", "interface": "<name>|any", "protocol": "tcp"|"udp"|"icmp"|"any", "source": "<cidr>|any", "sourcePort": "<port>|", "destination": "<cidr>|any", "destinationPort": "<port>|", "description": "<text>", "quick": true, "log": false }`,
    `- Always provide a concise technical explanation followed by the structured JSON block.`,
  ].join('\n');
}

/**
 * Builds a prompt for translating natural language queries into valid firewall rules.
 */
export function buildRuleDraftPrompt(
  query: string,
  interfaces: string[] = ['lan', 'wan'],
  aliases: string[] = []
): string {
  return [
    `User Request: "${query}"`,
    `Available Interfaces: ${interfaces.join(', ')}`,
    `Available Aliases: ${aliases.length > 0 ? aliases.join(', ') : 'None'}`,
    `Instructions:`,
    `1. Analyze the security intent and identify potential risks (e.g. wide-open ports, accidental lockout).`,
    `2. Generate the minimal, least-privilege firewall rule(s).`,
    `3. Output your response with a concise technical explanation and a valid JSON block containing an array of rules under the key "rules".`,
  ].join('\n');
}

/**
 * Builds a prompt for analyzing Suricata IDS/IPS or VictoriaLogs alert entries.
 */
export function buildLogAnalysisPrompt(logSnippet: string): string {
  return [
    `Analyze this security event log / Suricata EVE alert from Axonwall:`,
    `\`\`\`json`,
    logSnippet,
    `\`\`\``,
    `Provide:`,
    `1. Threat Classification (Attack family, CVE if applicable).`,
    `2. Severity Level (LOW, MEDIUM, HIGH, CRITICAL).`,
    `3. Affected Target & Attacker Source.`,
    `4. Recommended Remediation (Suggested nftables block rule or Suricata signature suppression).`,
  ].join('\n');
}

/**
 * Builds a prompt for auditing a running firewall configuration.
 */
export function buildAuditPrompt(state: Partial<DesiredState>): string {
  return [
    `Perform a comprehensive security and performance audit on this Axonwall configuration:`,
    `System: ${JSON.stringify(state.system || {})}`,
    `Interfaces: ${state.interfaces?.length || 0} interfaces configured`,
    `Rules: ${state.rules?.length || 0} rules`,
    `NAT: ${state.nat?.length || 0} NAT rules`,
    `Inspect for:`,
    `- Unprotected management ports (22, 80, 443, 3000) exposed to WAN.`,
    `- Shadowed or redundant rules.`,
    `- Absence of anti-lockout protection on LAN.`,
    `- Bufferbloat mitigation readiness (QoS CAKE enabled/disabled).`,
    `- High availability & failover readiness.`,
  ].join('\n');
}

export interface ParsedRuleDraft {
  rules: FirewallRule[];
  explanation: string;
  warnings: string[];
}

/**
 * Extracts and validates FirewallRule objects from LLM response text.
 */
export function parseDraftedRules(llmResponse: string): ParsedRuleDraft {
  const warnings: string[] = [];
  const rules: FirewallRule[] = [];

  // Look for ```json ... ``` blocks or raw { "rules": [...] }
  const jsonMatch = llmResponse.match(/```(?:json)?\s*([\s\S]*?)\s*```/) || llmResponse.match(/(\{[\s\S]*"rules"[\s\S]*\})/);

  let rawJsonText = jsonMatch ? jsonMatch[1] : '';

  if (!rawJsonText && llmResponse.includes('"action"')) {
    // Attempt to isolate array or single object
    rawJsonText = llmResponse;
  }

  if (rawJsonText) {
    try {
      const parsed = JSON.parse(rawJsonText);
      const candidateList = Array.isArray(parsed) ? parsed : (parsed.rules || [parsed]);

      for (const item of candidateList) {
        const validated = FirewallRuleSchema.safeParse(item);
        if (validated.success) {
          rules.push(validated.data);
        } else {
          warnings.push(`Rule validation note: ${validated.error.issues.map((i) => i.message).join(', ')}`);
        }
      }
    } catch {
      warnings.push('Could not parse JSON block from AI output; verify syntax manually.');
    }
  }

  // Clean explanation text by stripping json codeblocks
  const explanation = llmResponse.replace(/```(?:json)?[\s\S]*?```/g, '').trim();

  return {
    rules,
    explanation,
    warnings,
  };
}

export interface ParsedLogAnalysis {
  summary: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  mitigationRule?: Partial<FirewallRule>;
}

/**
 * Parses structured security log explanations.
 */
export function parseLogAnalysis(llmResponse: string): ParsedLogAnalysis {
  let severity: 'low' | 'medium' | 'high' | 'critical' = 'medium';

  const lower = llmResponse.toLowerCase();
  if (lower.includes('critical') || lower.includes('severity: critical')) severity = 'critical';
  else if (lower.includes('high') || lower.includes('severity: high')) severity = 'high';
  else if (lower.includes('low') || lower.includes('severity: low')) severity = 'low';

  const parsed = parseDraftedRules(llmResponse);

  return {
    summary: parsed.explanation || llmResponse,
    severity,
    mitigationRule: parsed.rules[0],
  };
}

/**
 * Generates realistic responses for local testing and simulations across providers.
 */
export async function simulateAiResponse(
  provider: AiProviderType,
  prompt: string,
  mode: 'chat' | 'draft' | 'explain' | 'audit' = 'chat'
): Promise<string> {
  const providerMeta = AI_PROVIDERS_META[provider];

  if (mode === 'draft') {
    return [
      `### Axonwall Policy Recommendation (${providerMeta.name})`,
      `Based on your request, I drafted an explicit ingress filter on \`wan\` to isolate port access with logging enabled.`,
      '',
      '```json',
      JSON.stringify(
        {
          rules: [
            {
              action: 'block',
              direction: 'in',
              interface: 'wan',
              quick: true,
              protocol: 'tcp',
              source: 'any',
              sourcePort: '',
              destination: 'any',
              destinationPort: '22',
              log: true,
              enabled: true,
              description: 'AI Generated: Drop WAN SSH brute-force attempts',
              sortOrder: 10,
            },
          ],
        },
        null,
        2
      ),
      '```',
      '',
      `**Safety Check**: Anti-lockout on LAN is preserved. Review this changeset before confirming.`,
    ].join('\n');
  }

  if (mode === 'explain') {
    return [
      `### Threat Analysis & RCA (${providerMeta.name})`,
      `**Classification**: Exploitation Attempt (CVE-2021-44228 / Log4j JNDI Injection)`,
      `**Severity**: CRITICAL`,
      `**Source**: Remote IP matching known malicious scanning infrastructure.`,
      `**Target**: Internal web service on port 8080.`,
      '',
      '#### Recommended Remediation',
      'The Suricata IPS engine intercepted the payload. To permanently null-route this IP at the nftables ingress layer before conntrack evaluation:',
      '',
      '```json',
      JSON.stringify(
        {
          rules: [
            {
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
              description: 'Auto-containment: Log4j scanner IP',
              sortOrder: 1,
            },
          ],
        },
        null,
        2
      ),
      '```',
    ].join('\n');
  }

  if (mode === 'audit') {
    return [
      `### Axonwall Configuration Audit Report (${providerMeta.name})`,
      `**Overall Health Score**: 92 / 100 (Secure)`,
      '',
      `#### Findings & Recommendations`,
      `1. **Anti-Lockout Protection**: ✓ Active on LAN (Ports 22, 80, 443, 3000 protected).`,
      `2. **Traffic Shaping**: ✓ CAKE smart QoS enabled on WAN. Bufferbloat rating: A+.`,
      `3. **High Availability**: ✓ Keepalived VRRP configured with Conntrackd state sync.`,
      `4. **Improvement**: Port 80 (HTTP) on WAN has a redirect rule without rate limiting; recommend attaching a dynamic abuse meter.`,
    ].join('\n');
  }

  // Standard chat
  return [
    `I am running via **${providerMeta.name}** (${providerMeta.defaultModel}).`,
    `I can help you draft nftables rules, explain live Suricata/VictoriaLogs alerts, and optimize your router policies safely with commit-confirm rollbacks.`,
    '',
    `What network operation would you like to execute?`,
  ].join('\n');
}
