import { describe, it, expect } from 'vitest';
import {
  AI_PROVIDERS_META,
  buildSystemPrompt,
  buildRuleDraftPrompt,
  buildLogAnalysisPrompt,
  buildAuditPrompt,
  parseDraftedRules,
  parseLogAnalysis,
  simulateAiResponse,
} from './index.js';
import { AiConfigSchema, type AiProviderType } from '../schemas/index.js';

describe('AI Copilot: Provider Architecture & Configuration', () => {
  const expectedProviders: AiProviderType[] = [
    'antigravity',
    'ollama',
    'claude-code',
    'codex',
    'vllm',
  ];

  it('supports all 5 requested AI providers with metadata', () => {
    for (const provider of expectedProviders) {
      const meta = AI_PROVIDERS_META[provider];
      expect(meta).toBeDefined();
      expect(meta.name).toBeTypeOf('string');
      expect(meta.defaultEndpoint).toBeTypeOf('string');
      expect(meta.defaultModel).toBeTypeOf('string');
      expect(meta.availableModels.length).toBeGreaterThan(0);
    }
  });

  it('distinguishes between local and cloud providers', () => {
    expect(AI_PROVIDERS_META.ollama.isLocal).toBe(true);
    expect(AI_PROVIDERS_META.vllm.isLocal).toBe(true);
    expect(AI_PROVIDERS_META.antigravity.isLocal).toBe(false);
    expect(AI_PROVIDERS_META['claude-code'].isLocal).toBe(false);
    expect(AI_PROVIDERS_META.codex.isLocal).toBe(false);
  });

  it('validates AiConfigSchema with default settings', () => {
    const config = AiConfigSchema.parse({
      enabled: true,
      activeProvider: 'ollama',
    });

    expect(config.activeProvider).toBe('ollama');
    expect(config.providers.ollama.endpoint).toBe('http://127.0.0.1:11434');
    expect(config.providers.antigravity.model).toBe('gemini-2.5-pro');
    expect(config.providers.claudeCode.model).toContain('claude-3-7-sonnet');
    expect(config.providers.codex.model).toBe('gpt-4o');
    expect(config.providers.vllm.endpoint).toBe('http://127.0.0.1:8000/v1');
  });
});

describe('AI Copilot: Prompt Engineering', () => {
  it('constructs contextual system prompt with nftables and commit-confirm guidelines', () => {
    const prompt = buildSystemPrompt({
      hostname: 'core-router-01',
      interfaces: ['eth0', 'eth1', 'wg0'],
      rulesCount: 24,
    });

    expect(prompt).toContain('core-router-01');
    expect(prompt).toContain('eth0, eth1, wg0');
    expect(prompt).toContain('table inet axonwall');
    expect(prompt).toContain('commit-confirm');
  });

  it('generates rule drafting and log analysis prompts', () => {
    const draftPrompt = buildRuleDraftPrompt(
      'Block all incoming traffic on WAN port 22',
      ['wan', 'lan'],
      ['Admin_IPs']
    );
    expect(draftPrompt).toContain('Block all incoming traffic on WAN port 22');
    expect(draftPrompt).toContain('wan, lan');
    expect(draftPrompt).toContain('Admin_IPs');

    const logPrompt = buildLogAnalysisPrompt('{"alert": "ET SCAN Nmap Scripting Engine"}');
    expect(logPrompt).toContain('ET SCAN Nmap');
  });
});

describe('AI Copilot: Response Parsing & Validation', () => {
  it('parses structured JSON firewall rules from LLM output', () => {
    const llmOutput = `
Here is the recommended security rule to isolate SSH on WAN:
\`\`\`json
{
  "rules": [
    {
      "action": "block",
      "direction": "in",
      "interface": "wan",
      "quick": true,
      "protocol": "tcp",
      "source": "any",
      "sourcePort": "",
      "destination": "any",
      "destinationPort": "22",
      "log": true,
      "enabled": true,
      "description": "Block WAN SSH",
      "sortOrder": 10
    }
  ]
}
\`\`\`
This rule drops unsolicited SSH attempts while allowing LAN access.
`;

    const parsed = parseDraftedRules(llmOutput);
    expect(parsed.rules).toHaveLength(1);
    expect(parsed.rules[0].action).toBe('block');
    expect(parsed.rules[0].destinationPort).toBe('22');
    expect(parsed.rules[0].interface).toBe('wan');
    expect(parsed.warnings).toHaveLength(0);
    expect(parsed.explanation).toContain('Here is the recommended security rule');
  });

  it('parses threat severity and remediation from log explanation', () => {
    const llmLogOutput = `
### Threat Analysis
**Classification**: Log4j RCE Attempt
**Severity**: CRITICAL
Source: 198.51.100.25

\`\`\`json
{
  "rules": [
    {
      "action": "block",
      "direction": "in",
      "interface": "wan",
      "quick": true,
      "protocol": "any",
      "source": "198.51.100.25",
      "sourcePort": "",
      "destination": "any",
      "destinationPort": "",
      "log": true,
      "enabled": true,
      "description": "Auto-block attacker",
      "sortOrder": 1
    }
  ]
}
\`\`\`
`;

    const parsed = parseLogAnalysis(llmLogOutput);
    expect(parsed.severity).toBe('critical');
    expect(parsed.mitigationRule).toBeDefined();
    expect(parsed.mitigationRule?.source).toBe('198.51.100.25');
  });

  it('runs simulation for all providers and modes', async () => {
    const draft = await simulateAiResponse('antigravity', 'Block port 22', 'draft');
    expect(draft).toContain('Axonwall Policy Recommendation');
    expect(draft).toContain('rules');

    const explain = await simulateAiResponse('claude-code', 'Explain CVE', 'explain');
    expect(explain).toContain('Threat Analysis');
    expect(explain).toContain('CRITICAL');

    const audit = await simulateAiResponse('vllm', 'Audit config', 'audit');
    expect(audit).toContain('Configuration Audit Report');
  });
});
