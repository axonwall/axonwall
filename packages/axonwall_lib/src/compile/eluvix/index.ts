import {
  EluvixConfigSchema,
  type DesiredState,
  type EluvixConfig,
} from '../../schemas/index.js';
import { isPluginEnabled } from '../../plugins/index.js';

export interface EluvixHarnessMetadata {
  id: 'opencode' | 'trueforge' | 'acp' | 'openhands' | 'mastra' | 'letta' | 'a2a' | 'hermes';
  name: string;
  protocol: string;
  defaultPort: number;
  forkPriority: 'tier-1-recommended' | 'tier-2-protocol' | 'tier-3-specialized';
  summary: string;
  deepForkAdvantages: string[];
}

export const ELUVIX_HARNESS_CATALOG: EluvixHarnessMetadata[] = [
  {
    id: 'opencode',
    name: 'OpenCode Server Harness',
    protocol: 'HTTP SSE + Session/Tool API (:4096)',
    defaultPort: 4096,
    forkPriority: 'tier-1-recommended',
    summary:
      'Stateful coding and infrastructure agent server with session persistence, granular permission gates, and native MCP tool execution.',
    deepForkAdvantages: [
      'Inline PromptGuard & PrivacyGuard interception on every tool stdout/stderr before context re-ingestion',
      'Deterministic KV-cache prefix pinning across multi-step agent turns via Switchyard session affinity',
      'Zero-copy Axonwall MCP tool bus binding without external stdio subprocess spawning',
    ],
  },
  {
    id: 'acp',
    name: 'Agent Client Protocol (ACP) Multiplexer',
    protocol: 'JSON-RPC 2.0 NDJSON over stdio (agy / claude-code-acp / goose)',
    defaultPort: 0,
    forkPriority: 'tier-1-recommended',
    summary:
      'Universal JSON-RPC 2.0 stdio harness bridging Antigravity (agy), Claude Code ACP, Goose, and OpenHands CLI binaries.',
    deepForkAdvantages: [
      'Unlocks client-side tool calling and populates session/new mcpServers directly from Eluvix & Axonwall',
      'Replaces per-request subprocess cold starts with a warm pre-attested zygote pool inside gVisor/Firecracker',
      'Routes fs/read_text_file, fs/write_text_file, and terminal/create RPCs through Eluvix PrivacyGuard DLP',
    ],
  },
  {
    id: 'trueforge',
    name: 'TrueForge Autonomous Loop',
    protocol: 'Native TypeScript ReAct + Tool-Call Loop',
    defaultPort: 3588,
    forkPriority: 'tier-1-recommended',
    summary:
      'Zero-dependency in-process ReAct agent loop embedded directly inside @eluvix/router-core with max-iteration budgets.',
    deepForkAdvantages: [
      'Sub-millisecond in-process Switchyard routing per reasoning step (Tier-1 local tool parsing, Tier-4 synthesis)',
      'Direct shared-memory access to SemanticCacheNode and Graphiti episodic memory graph',
      'Hardware TEE attestation binding on every autonomous tool invocation',
    ],
  },
  {
    id: 'openhands',
    name: 'OpenHands Sandbox Runtime',
    protocol: 'REST Action/Observation Stream (:3000)',
    defaultPort: 3000,
    forkPriority: 'tier-2-protocol',
    summary:
      'Containerized software engineering runtime with bash execution, browser automation, and Jupyter kernel.',
    deepForkAdvantages: [
      'Routes container sandbox egress through Axonwall nftables + Suricata DPI inspection',
      'Scans bash observation outputs for leaked credentials (sk-*, AKIA*, ghp_*) before LLM token serialization',
    ],
  },
  {
    id: 'mastra',
    name: 'Mastra Workflow & Agent Engine',
    protocol: 'HTTP Workflow & Structured Output API (:4111)',
    defaultPort: 4111,
    forkPriority: 'tier-2-protocol',
    summary:
      'Typed TypeScript multi-step workflow orchestrator with deterministic state machines and evaluation pipelines.',
    deepForkAdvantages: [
      'Per-step Switchyard model tiering across DAG nodes',
      'Automated PII token de-anonymization at workflow sink boundaries',
    ],
  },
  {
    id: 'letta',
    name: 'Letta (MemGPT) Stateful OS',
    protocol: 'Stateful Memory Block & Agent REST API (:8283)',
    defaultPort: 8283,
    forkPriority: 'tier-3-specialized',
    summary:
      'Self-editing core/archival memory agent runtime with tiered context paging.',
    deepForkAdvantages: [
      'Enforces PrivacyGuard DLP before writing long-term archival memory blocks',
      'Shares pgvector/Milvus backing store with Eluvix SemanticCacheNode',
    ],
  },
  {
    id: 'a2a',
    name: 'Google Agent-to-Agent (A2A) Federation',
    protocol: 'JSON-RPC 2.0 + AgentCard Discovery (:8003)',
    defaultPort: 8003,
    forkPriority: 'tier-2-protocol',
    summary:
      'Cross-domain multi-agent federation protocol with cryptographic AgentCards and task lifecycle streaming.',
    deepForkAdvantages: [
      'Attaches AMD SEV-SNP / Intel TDX hardware attestation quotes to outbound A2A AgentCards',
      'Applies strict cross-tenant PromptGuard & DLP at federation ingress/egress boundaries',
    ],
  },
  {
    id: 'hermes',
    name: 'Hermes Function-Calling Runtime',
    protocol: 'Nous Hermes XML/JSON Tool Call Engine (:8002)',
    defaultPort: 8002,
    forkPriority: 'tier-3-specialized',
    summary:
      'Low-latency local function-calling and schema-constrained grammar engine optimized for vLLM and SGLang.',
    deepForkAdvantages: [
      'Pins system tool schemas in DeepSeek MLA FP8 KV cache across all local worker nodes',
      'Executes read-only Axonwall diagnostic tools at zero cloud token cost',
    ],
  },
];

const INJECTION_PATTERNS: Record<
  'instructionOverride' | 'danJailbreak' | 'systemPromptLeak' | 'obfuscation',
  RegExp[]
> = {
  instructionOverride: [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|directives)/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)/i,
    /forget\s+(everything|all)\s+(you\s+)?(were\s+told|know|learned)/i,
    /new\s+instructions?:\s*/i,
    /override\s+(system|safety)\s+(prompt|instructions|rules)/i,
  ],
  danJailbreak: [
    /\bDAN\b.*\b(mode|anything\s+now)\b/i,
    /you\s+are\s+now\s+(in\s+)?(developer|debug|god|unrestricted|jailbreak)\s+mode/i,
    /act\s+as\s+an?\s+(unrestricted|unfiltered|uncensored)\s+AI/i,
    /pretend\s+you\s+have\s+no\s+(restrictions|limitations|guardrails|rules)/i,
  ],
  systemPromptLeak: [
    /repeat\s+(the\s+)?(words|text|instructions)\s+above\s+starting\s+with/i,
    /(print|show|reveal|output|display)\s+(your\s+)?(system\s+prompt|initial\s+instructions|hidden\s+instructions)/i,
    /what\s+(are|were)\s+your\s+(exact\s+)?(system\s+)?instructions/i,
  ],
  obfuscation: [
    /base64\s+decode\s+and\s+(execute|follow|run)/i,
    /rot13\s+decode/i,
    /(?:[A-Za-z0-9+/]{40,}={0,2})/,
  ],
};

const PII_PATTERNS: Record<
  'email' | 'ssn' | 'creditCard' | 'apiKey' | 'ipAddress' | 'phone',
  { regex: RegExp; token: string }
> = {
  apiKey: {
    regex: /\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}|xox[baprs]-[a-zA-Z0-9-]{10,})\b/g,
    token: '[REDACTED_API_KEY]',
  },
  ssn: {
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    token: '[REDACTED_SSN]',
  },
  creditCard: {
    regex: /\b(?:\d[ -]*?){13,16}\b/g,
    token: '[REDACTED_CREDIT_CARD]',
  },
  email: {
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    token: '[REDACTED_EMAIL]',
  },
  phone: {
    regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    token: '[REDACTED_PHONE]',
  },
  ipAddress: {
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    token: '[REDACTED_IP]',
  },
};

export interface EluvixGuardEvaluation {
  allowed: boolean;
  actionTaken: 'allow' | 'block' | 'strip' | 'divert' | 'anonymize' | 'warn';
  sanitizedPrompt: string;
  injectionDetected: boolean;
  injectionScore: number;
  triggeredVectors: string[];
  piiDetected: boolean;
  detectedPiiTypes: string[];
  redactionCount: number;
  complexityTier: 1 | 2 | 3 | 4;
  selectedRoute: string;
}

export interface EluvixTokenomicsEstimate {
  monthlyPromptsMillions: number;
  baselineCloudCostUsd: number;
  eluvixOptimizedCostUsd: number;
  monthlySavingsUsd: number;
  annualSavingsUsd: number;
  savingsPercentage: number;
  semanticCacheHitRatePct: number;
  localTierOffloadPct: number;
  kvPrefixCacheReusePct: number;
  kvBytesPerToken: number;
  gqaBaselineBytesPerToken: number;
  kvCompressionRatio: number;
}

export interface CompiledEluvixBundle {
  enabled: boolean;
  config: EluvixConfig;
  eluvixJson: string;
  helmValuesYaml: string;
  systemdUnit: string;
  unboundOverrides: Array<{ hostname: string; ip: string; description: string }>;
  tokenomics: EluvixTokenomicsEstimate;
}

export function resolveEluvixConfig(state?: Partial<DesiredState> | null): EluvixConfig {
  const parsed = EluvixConfigSchema.parse(state?.eluvix ?? {});
  const enabled = isPluginEnabled('eluvix', state);
  return {
    ...parsed,
    enabled,
  };
}

function portableHash10(str: string): string {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c64e6d;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(10, '0').slice(0, 10);
}

function redactMatch(match: string, token: string, style: 'token' | 'asterisk' | 'hash'): string {
  if (style === 'asterisk') {
    if (match.length <= 4) return '****';
    return `${match.slice(0, 2)}${'*'.repeat(Math.min(12, match.length - 4))}${match.slice(-2)}`;
  }
  if (style === 'hash') {
    const digest = portableHash10(match);
    return `[HASH:${digest}]`;
  }
  return token;
}

export function evaluateEluvixGuards(
  prompt: string,
  configInput?: Partial<EluvixConfig>,
): EluvixGuardEvaluation {
  const config = EluvixConfigSchema.parse(configInput ?? {});
  const pg = config.promptGuard;
  const priv = config.privacyGuard;

  let workingPrompt = prompt;
  const triggeredVectors: string[] = [];

  if (pg.enabled) {
    const activeVectors: Array<'instructionOverride' | 'danJailbreak' | 'systemPromptLeak' | 'obfuscation'> = [];
    if (pg.instructionOverride) activeVectors.push('instructionOverride');
    if (pg.danJailbreak) activeVectors.push('danJailbreak');
    if (pg.systemPromptLeak) activeVectors.push('systemPromptLeak');
    if (pg.obfuscation) activeVectors.push('obfuscation');

    for (const vec of activeVectors) {
      for (const regex of INJECTION_PATTERNS[vec]) {
        if (regex.test(workingPrompt)) {
          if (!triggeredVectors.includes(vec)) {
            triggeredVectors.push(vec);
          }
          if (pg.enforcementAction === 'strip') {
            workingPrompt = workingPrompt.replace(new RegExp(regex.source, 'gi'), '[STRIPPED_INJECTION_VECTOR]');
          }
        }
      }
    }

    for (const phrase of pg.bannedPhrases) {
      const trimmed = phrase.trim();
      if (!trimmed) continue;
      if (workingPrompt.toLowerCase().includes(trimmed.toLowerCase())) {
        if (!triggeredVectors.includes(`bannedPhrase:${trimmed}`)) {
          triggeredVectors.push(`bannedPhrase:${trimmed}`);
        }
        if (pg.enforcementAction === 'strip') {
          const escaped = trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          workingPrompt = workingPrompt.replace(new RegExp(escaped, 'gi'), '[STRIPPED_BANNED_PHRASE]');
        }
      }
    }
  }

  const rawScore = triggeredVectors.length === 0 ? 0 : Math.min(1.0, 0.72 + triggeredVectors.length * 0.14);
  const injectionDetected = pg.enabled && rawScore >= pg.threshold;

  const detectedPiiTypes: string[] = [];
  let redactionCount = 0;

  if (priv.enabled) {
    const activePii: Array<keyof typeof PII_PATTERNS> = [];
    if (priv.detectApiKey) activePii.push('apiKey');
    if (priv.detectSsn) activePii.push('ssn');
    if (priv.detectCreditCard) activePii.push('creditCard');
    if (priv.detectEmail) activePii.push('email');
    if (priv.detectPhone) activePii.push('phone');
    if (priv.detectIpAddress) activePii.push('ipAddress');

    const whitelistSet = new Set(priv.whitelist.map((w) => w.trim().toLowerCase()).filter(Boolean));

    for (const piiKey of activePii) {
      const { regex, token } = PII_PATTERNS[piiKey];
      const matches = workingPrompt.match(regex);
      if (matches && matches.length > 0) {
        const nonWhitelisted = matches.filter((m) => !whitelistSet.has(m.toLowerCase()));
        if (nonWhitelisted.length > 0) {
          detectedPiiTypes.push(piiKey);
          redactionCount += nonWhitelisted.length;
          if (priv.action === 'anonymize') {
            workingPrompt = workingPrompt.replace(regex, (m) =>
              whitelistSet.has(m.toLowerCase()) ? m : redactMatch(m, token, priv.redactionStyle),
            );
          }
        }
      }
    }
  }

  const piiDetected = detectedPiiTypes.length > 0;

  // Estimate prompt complexity tier (1..4) for Switchyard routing
  const approxTokens = Math.max(1, Math.ceil(workingPrompt.length / 4));
  let complexityTier: 1 | 2 | 3 | 4 = 1;
  if (approxTokens > 1024 || /\b(architect|formal\s+proof|vulnerability\s+audit|zero-day|synthesis)\b/i.test(workingPrompt)) {
    complexityTier = 4;
  } else if (approxTokens > 256 || /\b(refactor|implement|typescript|golang|nftables|kubernetes)\b/i.test(workingPrompt)) {
    complexityTier = 3;
  } else if (approxTokens > 64) {
    complexityTier = 2;
  }

  let allowed = true;
  let actionTaken: EluvixGuardEvaluation['actionTaken'] = 'allow';
  let selectedRoute =
    complexityTier <= 2
      ? 'tier-1-local-sglang (DeepSeek-R1-Distill-32B FP8)'
      : complexityTier === 3
        ? 'tier-2-disaggregated-vllm (Qwen-2.5-Coder-72B NIXL)'
        : 'tier-4-frontier-tee (Confidential Frontier Cluster)';

  if (injectionDetected) {
    if (pg.enforcementAction === 'block') {
      allowed = false;
      actionTaken = 'block';
      selectedRoute = 'blocked-by-eluvix-prompt-guard';
    } else if (pg.enforcementAction === 'divert') {
      allowed = true;
      actionTaken = 'divert';
      selectedRoute = 'honeypot-tarpit-llm (Eluvix Deception Sink)';
    } else if (pg.enforcementAction === 'strip') {
      allowed = true;
      actionTaken = 'strip';
    } else {
      allowed = true;
      actionTaken = 'warn';
    }
  }

  if (allowed && piiDetected) {
    if (priv.action === 'block') {
      allowed = false;
      actionTaken = 'block';
      selectedRoute = 'blocked-by-eluvix-privacy-guard';
    } else if (priv.action === 'anonymize' && actionTaken === 'allow') {
      actionTaken = 'anonymize';
    } else if (priv.action === 'warn' && actionTaken === 'allow') {
      actionTaken = 'warn';
    }
  }

  return {
    allowed,
    actionTaken,
    sanitizedPrompt: workingPrompt.trim(),
    injectionDetected,
    injectionScore: Number(rawScore.toFixed(2)),
    triggeredVectors,
    piiDetected,
    detectedPiiTypes,
    redactionCount,
    complexityTier,
    selectedRoute,
  };
}

export function estimateEluvixTokenomics(
  configInput?: Partial<EluvixConfig>,
): EluvixTokenomicsEstimate {
  const config = EluvixConfigSchema.parse(configInput ?? {});
  const tok = config.tokenomics;

  // Baseline assumption: average 1,200 input tokens + 400 output tokens per request on frontier cloud ($7.50 / 1M blended tokens = $12.00 per 1,000 requests = $12,000 per 1M prompts)
  const costPerMillionPromptsCloudUsd = 12000;
  const baselineCloudCostUsd = Math.round(tok.monthlyPromptVolumeMillions * costPerMillionPromptsCloudUsd);

  // 1. Semantic cache hit rate (depends on similarity threshold)
  const semanticCacheHitRatePct = tok.semanticCacheEnabled
    ? Math.round(Math.max(12, Math.min(48, (1.0 - tok.semanticCacheSimilarityThreshold) * 350 + 8)))
    : 0;

  // 2. Switchyard cost-complexity local/disaggregated offload
  const localTierOffloadPct =
    tok.strategy === 'cost-complexity' || tok.strategy === 'prefill-isolation'
      ? tok.localOffloadTargetPct
      : Math.round(tok.localOffloadTargetPct * 0.45);

  // 3. KV Prefix Affinity & Disaggregated Prefill/Decode savings on remaining prompts
  const kvPrefixCacheReusePct = tok.kvPrefixAffinityEnabled
    ? tok.rdmaConnector !== 'none'
      ? 38
      : 24
    : 0;

  const afterCacheMultiplier = 1 - semanticCacheHitRatePct / 100;
  // Local/SGLang/vLLM compute costs ~8% of cloud frontier token pricing per token
  const blendedRoutingMultiplier =
    (localTierOffloadPct / 100) * 0.08 + (1 - localTierOffloadPct / 100) * (1 - (kvPrefixCacheReusePct / 100) * 0.55);

  const eluvixOptimizedCostUsd = Math.max(
    1,
    Math.round(baselineCloudCostUsd * afterCacheMultiplier * blendedRoutingMultiplier),
  );
  const monthlySavingsUsd = Math.max(0, baselineCloudCostUsd - eluvixOptimizedCostUsd);
  const annualSavingsUsd = monthlySavingsUsd * 12;
  const savingsPercentage =
    baselineCloudCostUsd > 0
      ? Number(((monthlySavingsUsd / baselineCloudCostUsd) * 100).toFixed(1))
      : 0;

  // DeepSeek MLA FP8: 34.31 KiB/token vs GQA FP8: 160 KiB/token vs GQA BF16: 320 KiB/token
  const kvBytesPerToken =
    tok.kvArchitecture === 'deepseek-mla-fp8'
      ? 35133 // 34.31 KiB
      : tok.kvArchitecture === 'gqa-fp8'
        ? 163840 // 160.0 KiB
        : 327680; // 320.0 KiB
  const gqaBaselineBytesPerToken = 163840;
  const kvCompressionRatio = Number((gqaBaselineBytesPerToken / kvBytesPerToken).toFixed(2));

  return {
    monthlyPromptsMillions: tok.monthlyPromptVolumeMillions,
    baselineCloudCostUsd,
    eluvixOptimizedCostUsd,
    monthlySavingsUsd,
    annualSavingsUsd,
    savingsPercentage,
    semanticCacheHitRatePct,
    localTierOffloadPct,
    kvPrefixCacheReusePct,
    kvBytesPerToken,
    gqaBaselineBytesPerToken,
    kvCompressionRatio,
  };
}

export function compileEluvixBundle(state: Partial<DesiredState>): CompiledEluvixBundle {
  const config = resolveEluvixConfig(state);
  const tokenomics = estimateEluvixTokenomics(config);

  const lanIface = (state.interfaces ?? []).find((i) => i.name === 'lan' || i.role === 'lan');
  const lanIp = lanIface?.ipv4Address?.split('/')[0] || '192.168.1.1';

  const eluvixJsonObj = {
    version: '1.0.0',
    repository: config.gitRepoUrl,
    server: {
      listenPort: config.listenPort,
      switchyardPort: config.switchyardPort,
      domain: config.domain,
      samePortTlsAutoUpgrade: config.samePortTlsAutoUpgrade,
      teePolicy: config.teePolicy,
    },
    switchyard: {
      strategy: config.tokenomics.strategy,
      prefillIsolationThresholdTokens: config.tokenomics.prefillIsolationThresholdTokens,
      kvPrefixAffinity: config.tokenomics.kvPrefixAffinityEnabled,
      kvArchitecture: config.tokenomics.kvArchitecture,
      rdmaConnector: config.tokenomics.rdmaConnector,
      localOffloadTargetPct: config.tokenomics.localOffloadTargetPct,
    },
    semanticCache: {
      enabled: config.tokenomics.semanticCacheEnabled,
      similarityThreshold: config.tokenomics.semanticCacheSimilarityThreshold,
      backend: config.tokenomics.semanticCacheBackend,
    },
    promptGuard: config.promptGuard,
    privacyGuard: config.privacyGuard,
    harnessMesh: {
      ...config.harnessMesh,
      axonwallMcpEndpoint: config.harnessMesh.injectAxonwallMcp
        ? 'unix:///var/run/axonwalld.sock'
        : null,
    },
  };

  const eluvixJson = JSON.stringify(eluvixJsonObj, null, 2);

  const helmValuesYaml = [
    `# Generated by Axonwall Compiler for Eluvix (${config.gitRepoUrl})`,
    `replicaCount: 2`,
    `service:`,
    `  port: ${config.listenPort}`,
    `  switchyardPort: ${config.switchyardPort}`,
    `  samePortTlsAutoUpgrade: ${config.samePortTlsAutoUpgrade}`,
    `ingress:`,
    `  enabled: true`,
    `  host: ${config.domain}`,
    `tee:`,
    `  policy: ${config.teePolicy}`,
    `tokenomics:`,
    `  strategy: ${config.tokenomics.strategy}`,
    `  semanticCache:`,
    `    enabled: ${config.tokenomics.semanticCacheEnabled}`,
    `    similarityThreshold: ${config.tokenomics.semanticCacheSimilarityThreshold}`,
    `    backend: ${config.tokenomics.semanticCacheBackend}`,
    `  disaggregatedKv:`,
    `    kvPrefixAffinity: ${config.tokenomics.kvPrefixAffinityEnabled}`,
    `    prefillIsolationThresholdTokens: ${config.tokenomics.prefillIsolationThresholdTokens}`,
    `    kvArchitecture: ${config.tokenomics.kvArchitecture}`,
    `    rdmaConnector: ${config.tokenomics.rdmaConnector}`,
    `guards:`,
    `  promptGuard:`,
    `    enabled: ${config.promptGuard.enabled}`,
    `    mode: ${config.promptGuard.mode}`,
    `    threshold: ${config.promptGuard.threshold}`,
    `    action: ${config.promptGuard.enforcementAction}`,
    `  privacyGuard:`,
    `    enabled: ${config.privacyGuard.enabled}`,
    `    action: ${config.privacyGuard.action}`,
    `    redactionStyle: ${config.privacyGuard.redactionStyle}`,
    `    auditLogging: ${config.privacyGuard.auditLogging}`,
    `harnesses:`,
    `  enabled: ${config.harnessMesh.enabled}`,
    `  defaultHarness: ${config.harnessMesh.defaultHarness}`,
    `  approvalPolicy: ${config.harnessMesh.approvalPolicy}`,
    `  sandboxBackend: ${config.harnessMesh.sandboxBackend}`,
    `  memoryEngine: ${config.harnessMesh.memoryEngine}`,
    `  enabledHarnesses:`,
    ...config.harnessMesh.enabledHarnesses.map((h) => `    - ${h}`),
    ``,
  ].join('\n');

  const systemdUnit = [
    `[Unit]`,
    `Description=Eluvix Sovereign AI Router, Enterprise Tokenomics & Prompt/PII Guard Gateway`,
    `Documentation=https://github.com/Eluvixrouter/eluvix`,
    `After=network-online.target unbound.service`,
    `Wants=network-online.target`,
    ``,
    `[Service]`,
    `Type=simple`,
    `User=axonwall`,
    `Group=axonwall`,
    `WorkingDirectory=/opt/eluvix`,
    `Environment="ELUVIX_CONFIG=/etc/axonwall/eluvix/eluvix.json"`,
    `Environment="ELUVIX_PORT=${config.listenPort}"`,
    `Environment="ELUVIX_SWITCHYARD_PORT=${config.switchyardPort}"`,
    `Environment="ELUVIX_TEE_POLICY=${config.teePolicy}"`,
    `ExecStart=/usr/bin/env node /opt/eluvix/apps/server/dist/index.js`,
    `Restart=on-failure`,
    `RestartSec=5s`,
    `NoNewPrivileges=true`,
    `ProtectSystem=strict`,
    `ReadWritePaths=/etc/axonwall/eluvix /var/lib/eluvix /var/log/eluvix`,
    ``,
    `[Install]`,
    `WantedBy=multi-user.target`,
    ``,
  ].join('\n');

  const unboundOverrides =
    config.enabled && config.syncUnboundDns
      ? [
          {
            hostname: config.domain,
            ip: lanIp,
            description: `Eluvix Unified Multimodal AI Gateway (:${config.listenPort})`,
          },
          {
            hostname: `switchyard.${config.domain}`,
            ip: lanIp,
            description: `Eluvix Switchyard Cost-Complexity & KV Coordinator (:${config.switchyardPort})`,
          },
          {
            hostname: `agents.${config.domain}`,
            ip: lanIp,
            description: `Eluvix Multi-Harness Agent Mesh (${config.harnessMesh.defaultHarness})`,
          },
        ]
      : [];

  return {
    enabled: config.enabled,
    config,
    eluvixJson,
    helmValuesYaml,
    systemdUnit,
    unboundOverrides,
    tokenomics,
  };
}
