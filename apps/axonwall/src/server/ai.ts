'use server';

import {
  AI_PROVIDERS_META,
  buildSystemPrompt,
  buildRuleDraftPrompt,
  buildLogAnalysisPrompt,
  buildAuditPrompt,
} from '@axonwall/lib/ai';
import type { AiProviderType, AiConfig } from '@axonwall/lib/schemas';
import { isPluginEnabled } from '@axonwall/lib/plugins';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { getDesiredStateInternal } from './desired-state-internal';
import { assertSafeOutboundUrl, ssrfSafeFetch, type SsrfSafeResponse } from './ssrf-guard';

export interface AiProbeResult {
  ok: boolean;
  status: string;
  latencyMs?: number;
  modelsFound?: string[];
  error?: string;
}

async function validateAiEndpoint(endpoint: string, isLocalExpected: boolean): Promise<string> {
  const clean = endpoint.trim().replace(/\/+$/, '');
  await assertSafeOutboundUrl(clean, {
    allowHttp: isLocalExpected,
    allowPrivate: isLocalExpected,
  });
  return clean;
}

function aiFetch(
  url: string,
  isLocalExpected: boolean,
  init: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }
): Promise<SsrfSafeResponse> {
  return ssrfSafeFetch(url, init, {
    allowHttp: isLocalExpected,
    allowPrivate: isLocalExpected,
  });
}

function resolveAiApiKey(
  configuredKey: string | undefined,
  envKey: string | undefined,
  endpoint: string,
  defaultEndpoint: string,
  isClientConfig: boolean
): string {
  const cleanConfigured =
    configuredKey && configuredKey !== '********' ? configuredKey.trim() : '';
  if (isClientConfig && endpoint !== defaultEndpoint) {
    return cleanConfigured;
  }
  return (cleanConfigured || envKey || '').trim();
}

function formatUpstreamHttpError(providerLabel: string, res: Pick<SsrfSafeResponse, 'status' | 'statusText'>): string {
  const safeStatusText = (res.statusText || 'Request Failed')
    .replace(/[^\w\s.-]/g, '')
    .trim()
    .slice(0, 64);
  return `${providerLabel} returned HTTP ${res.status}${safeStatusText ? ` (${safeStatusText})` : ''}`;
}

export async function testAiProviderProbe(
  provider: AiProviderType,
  currentConfig?: AiConfig
): Promise<AiProbeResult> {
  const session = await getSession();
  assertActionPermitted(session, currentConfig ? 'admin' : 'operator');

  const state = await getDesiredStateInternal();
  if (!isPluginEnabled('ai-copilot', state)) {
    return {
      ok: false,
      status: 'Plugin Disabled',
      error: 'AI Network Copilot plugin (ai-copilot) is disabled. Enable it in System > Plugins or /ai before probing providers.',
    };
  }
  const aiCfg = currentConfig || state.ai;
  const isClientConfig = Boolean(currentConfig);
  const start = Date.now();

  // N11: a probe that only checks connectivity/auth passes a typo'd,
  // retired, or not-yet-pulled model, which then fails at Send time.
  // Verify the configured model is in the provider's reported list.
  const modelMatches = (models: string[], configured: string): boolean => {
    const norm = (m: string) => m.replace(/^models\//, '');
    const want = norm(configured);
    return models.some((m) => {
      const got = norm(m);
      return got === want || got === `${want}:latest` || want === `${got}:latest`;
    });
  };
  const verifyConfiguredModel = (
    configuredModel: string,
    models: string[],
    latencyMs: number,
    isLocal: boolean
  ): AiProbeResult | null => {
    if (models.length === 0) {
      return {
        ok: false,
        status: `No models available (${latencyMs}ms)`,
        latencyMs,
        modelsFound: models,
        error: isLocal
          ? `No models are available on this ${AI_PROVIDERS_META[provider].name} endpoint — pull or serve '${configuredModel}' first.`
          : `The provider reported no models, so configured model '${configuredModel}' could not be verified.`,
      };
    }
    if (!modelMatches(models, configuredModel)) {
      return {
        ok: false,
        status: `Model '${configuredModel}' not available (${models.length} models, ${latencyMs}ms)`,
        latencyMs,
        modelsFound: models,
        error: `Configured model '${configuredModel}' was not found among the ${models.length} model(s) reported by ${AI_PROVIDERS_META[provider].name}. Check the model name or pull/install it before using this provider.`,
      };
    }
    return null;
  };

  try {
    switch (provider) {
      case 'antigravity': {
        const p = aiCfg?.providers?.antigravity;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.antigravity.defaultEndpoint;
        const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.antigravity.isLocal);
        const apiKey = resolveAiApiKey(
          p?.apiKey,
          process.env.GEMINI_API_KEY,
          endpoint,
          AI_PROVIDERS_META.antigravity.defaultEndpoint,
          isClientConfig
        );
        if (!apiKey) {
          return {
            ok: false,
            status: 'Missing API Key',
            error: 'No Gemini / Antigravity API key configured.',
          };
        }
        const res = await aiFetch(
          `${endpoint}/models?key=${encodeURIComponent(apiKey)}`,
          AI_PROVIDERS_META.antigravity.isLocal,
          {
            method: 'GET',
            signal: AbortSignal.timeout(5000),
          }
        );
        const latencyMs = Date.now() - start;
        if (!res.ok) {
          return {
            ok: false,
            status: `HTTP ${res.status} (${res.statusText || 'Auth Failed'})`,
            latencyMs,
            error: formatUpstreamHttpError('Gemini endpoint', res),
          };
        }
        const data = (await res.json().catch(() => ({}))) as any;
        const models = Array.isArray(data?.models)
          ? data.models.map((m: any) => String(m.name || '').replace(/^models\//, '')).filter(Boolean)
          : [];
        const configuredModel = p?.model || AI_PROVIDERS_META.antigravity.defaultModel;
        const modelCheck = verifyConfiguredModel(configuredModel, models, latencyMs, false);
        if (modelCheck) return modelCheck;
        return {
          ok: true,
          status: `Connected & Verified — model '${configuredModel}' available (${models.length} models, ${latencyMs}ms)`,
          latencyMs,
          modelsFound: models,
        };
      }

      case 'ollama': {
        const p = aiCfg?.providers?.ollama;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.ollama.defaultEndpoint;
        const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.ollama.isLocal);
        const res = await aiFetch(`${endpoint}/api/tags`, AI_PROVIDERS_META.ollama.isLocal, {
          method: 'GET',
          signal: AbortSignal.timeout(4000),
        });
        const latencyMs = Date.now() - start;
        if (!res.ok) {
          return {
            ok: false,
            status: `HTTP ${res.status} (${res.statusText || 'Error'})`,
            latencyMs,
            error: `Ollama endpoint at ${endpoint} returned HTTP ${res.status}`,
          };
        }
        const data = (await res.json().catch(() => ({}))) as any;
        const models = Array.isArray(data?.models)
          ? data.models.map((m: any) => String(m.name || '')).filter(Boolean)
          : [];
        const configuredModel = p?.model || AI_PROVIDERS_META.ollama.defaultModel;
        const modelCheck = verifyConfiguredModel(configuredModel, models, latencyMs, true);
        if (modelCheck) return modelCheck;
        return {
          ok: true,
          status: `Online — model '${configuredModel}' available (${models.length} models, ${latencyMs}ms)`,
          latencyMs,
          modelsFound: models,
        };
      }

      case 'claude-code': {
        const p = aiCfg?.providers?.claudeCode;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META['claude-code'].defaultEndpoint;
        const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META['claude-code'].isLocal);
        const apiKey = resolveAiApiKey(
          p?.apiKey,
          process.env.ANTHROPIC_API_KEY,
          endpoint,
          AI_PROVIDERS_META['claude-code'].defaultEndpoint,
          isClientConfig
        );
        if (!apiKey) {
          return {
            ok: false,
            status: 'Missing API Key',
            error: 'No Anthropic API key configured.',
          };
        }
        const res = await aiFetch(`${endpoint}/models`, AI_PROVIDERS_META['claude-code'].isLocal, {
          method: 'GET',
          headers: {
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
          },
          signal: AbortSignal.timeout(5000),
        });
        const latencyMs = Date.now() - start;
        if (!res.ok) {
          return {
            ok: false,
            status: `HTTP ${res.status} (${res.statusText || 'Auth Failed'})`,
            latencyMs,
            error: formatUpstreamHttpError('Anthropic endpoint', res),
          };
        }
        const data = (await res.json().catch(() => ({}))) as any;
        const models = Array.isArray(data?.data)
          ? data.data.map((m: any) => String(m.id || '')).filter(Boolean)
          : [];
        const configuredModel = p?.model || AI_PROVIDERS_META['claude-code'].defaultModel;
        const modelCheck = verifyConfiguredModel(configuredModel, models, latencyMs, false);
        if (modelCheck) return modelCheck;
        return {
          ok: true,
          status: `Connected & Verified — model '${configuredModel}' available (${models.length} models, ${latencyMs}ms)`,
          latencyMs,
          modelsFound: models,
        };
      }

      case 'codex': {
        const p = aiCfg?.providers?.codex;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.codex.defaultEndpoint;
        const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.codex.isLocal);
        const apiKey = resolveAiApiKey(
          p?.apiKey,
          process.env.OPENAI_API_KEY,
          endpoint,
          AI_PROVIDERS_META.codex.defaultEndpoint,
          isClientConfig
        );
        if (!apiKey) {
          return {
            ok: false,
            status: 'Missing API Key',
            error: 'No OpenAI API key configured.',
          };
        }
        const res = await aiFetch(`${endpoint}/models`, AI_PROVIDERS_META.codex.isLocal, {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${apiKey}`,
          },
          signal: AbortSignal.timeout(5000),
        });
        const latencyMs = Date.now() - start;
        if (!res.ok) {
          return {
            ok: false,
            status: `HTTP ${res.status} (${res.statusText || 'Auth Failed'})`,
            latencyMs,
            error: formatUpstreamHttpError('OpenAI endpoint', res),
          };
        }
        const data = (await res.json().catch(() => ({}))) as any;
        const models = Array.isArray(data?.data)
          ? data.data.map((m: any) => String(m.id || '')).filter(Boolean)
          : [];
        const configuredModel = p?.model || AI_PROVIDERS_META.codex.defaultModel;
        const modelCheck = verifyConfiguredModel(configuredModel, models, latencyMs, false);
        if (modelCheck) return modelCheck;
        return {
          ok: true,
          status: `Connected & Verified — model '${configuredModel}' available (${models.length} models, ${latencyMs}ms)`,
          latencyMs,
          modelsFound: models,
        };
      }

      case 'vllm': {
        const p = aiCfg?.providers?.vllm;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.vllm.defaultEndpoint;
        const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.vllm.isLocal);
        const apiKey = resolveAiApiKey(
          p?.apiKey,
          undefined,
          endpoint,
          AI_PROVIDERS_META.vllm.defaultEndpoint,
          isClientConfig
        );
        const headers: Record<string, string> = {};
        if (apiKey) {
          headers.Authorization = `Bearer ${apiKey}`;
        }
        const res = await aiFetch(`${endpoint}/models`, AI_PROVIDERS_META.vllm.isLocal, {
          method: 'GET',
          headers,
          signal: AbortSignal.timeout(4000),
        });
        const latencyMs = Date.now() - start;
        if (!res.ok) {
          return {
            ok: false,
            status: `HTTP ${res.status} (${res.statusText || 'Error'})`,
            latencyMs,
            error: `vLLM endpoint at ${endpoint} returned HTTP ${res.status}`,
          };
        }
        const data = (await res.json().catch(() => ({}))) as any;
        const models = Array.isArray(data?.data)
          ? data.data.map((m: any) => String(m.id || '')).filter(Boolean)
          : [];
        const configuredModel = p?.model || AI_PROVIDERS_META.vllm.defaultModel;
        const modelCheck = verifyConfiguredModel(configuredModel, models, latencyMs, true);
        if (modelCheck) return modelCheck;
        return {
          ok: true,
          status: `Online — model '${configuredModel}' available (${models.length} models, ${latencyMs}ms)`,
          latencyMs,
          modelsFound: models,
        };
      }
    }
  } catch (err: any) {
    const latencyMs = Date.now() - start;
    const causeMsg = err?.cause?.code || err?.cause?.message || err?.message || 'Connection failed';
    return {
      ok: false,
      status: `Unreachable (${causeMsg})`,
      latencyMs,
      error: `Failed to connect to ${AI_PROVIDERS_META[provider].name}: ${causeMsg}`,
    };
  }
}

export async function generateAiCompletion(
  provider: AiProviderType,
  userPrompt: string,
  mode: 'chat' | 'draft' | 'explain' | 'audit' = 'chat',
  currentConfig?: AiConfig
): Promise<string> {
  const session = await getSession();
  assertActionPermitted(session, (currentConfig || mode === 'audit') ? 'admin' : 'operator');

  const state = await getDesiredStateInternal();
  if (!isPluginEnabled('ai-copilot', state)) {
    throw new Error(
      'AI Network Copilot plugin (ai-copilot) is disabled. Enable it in System > Plugins or /ai before running completions.'
    );
  }
  const aiCfg = currentConfig || state.ai;
  const isClientConfig = Boolean(currentConfig);

  const systemPrompt = buildSystemPrompt({
    hostname: state.system?.hostname || 'axonwall',
    interfaces: (state.interfaces || []).map((i) => `${i.device} (${i.name})`),
    rulesCount: (state.rules || []).length,
  });

  let formattedUserPrompt = userPrompt;
  if (mode === 'draft') {
    formattedUserPrompt = buildRuleDraftPrompt(
      userPrompt,
      (state.interfaces || []).map((i) => i.name),
      (state.aliases || []).map((a) => a.name)
    );
  } else if (mode === 'explain') {
    formattedUserPrompt = buildLogAnalysisPrompt(userPrompt);
  } else if (mode === 'audit') {
    formattedUserPrompt = buildAuditPrompt(state);
  }

  switch (provider) {
    case 'antigravity': {
      const p = aiCfg?.providers?.antigravity;
      const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.antigravity.defaultEndpoint;
      const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.antigravity.isLocal);
      const model = p?.model || AI_PROVIDERS_META.antigravity.defaultModel;
      const apiKey = resolveAiApiKey(
        p?.apiKey,
        process.env.GEMINI_API_KEY,
        endpoint,
        AI_PROVIDERS_META.antigravity.defaultEndpoint,
        isClientConfig
      );
      if (!apiKey) {
        throw new Error('Missing API Key for Google Antigravity / Gemini. Enter your API key in the Provider Settings tab.');
      }

      const res = await aiFetch(
        `${endpoint}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`,
        AI_PROVIDERS_META.antigravity.isLocal,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            systemInstruction: {
              parts: [{ text: systemPrompt }],
            },
            contents: [
              {
                role: 'user',
                parts: [{ text: formattedUserPrompt }],
              },
            ],
          }),
          signal: AbortSignal.timeout(30000),
        }
      );

      if (!res.ok) {
        throw new Error(formatUpstreamHttpError('Gemini API', res));
      }

      const data = (await res.json()) as any;
      const text = data?.candidates?.[0]?.content?.parts?.map((pt: any) => pt.text || '').join('') || '';
      if (!text) {
        throw new Error('Empty response returned from Gemini API.');
      }
      return text;
    }

    case 'ollama': {
      const p = aiCfg?.providers?.ollama;
      const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.ollama.defaultEndpoint;
      const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.ollama.isLocal);
      const model = p?.model || AI_PROVIDERS_META.ollama.defaultModel;
      const temperature = p?.temperature ?? 0.2;

      const res = await aiFetch(`${endpoint}/api/chat`, AI_PROVIDERS_META.ollama.isLocal, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          stream: false,
          options: { temperature },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: formattedUserPrompt },
          ],
        }),
        signal: AbortSignal.timeout(45000),
      });

      if (!res.ok) {
        throw new Error(formatUpstreamHttpError('Ollama', res));
      }

      const data = (await res.json()) as any;
      const text = data?.message?.content || data?.response || '';
      if (!text) {
        throw new Error('Empty response returned from Ollama.');
      }
      return text;
    }

    case 'claude-code': {
      const p = aiCfg?.providers?.claudeCode;
      const rawEndpoint = p?.endpoint || AI_PROVIDERS_META['claude-code'].defaultEndpoint;
      const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META['claude-code'].isLocal);
      const model = p?.model || AI_PROVIDERS_META['claude-code'].defaultModel;
      const apiKey = resolveAiApiKey(
        p?.apiKey,
        process.env.ANTHROPIC_API_KEY,
        endpoint,
        AI_PROVIDERS_META['claude-code'].defaultEndpoint,
        isClientConfig
      );
      if (!apiKey) {
        throw new Error('Missing API Key for Claude Code (Anthropic). Enter your API key in the Provider Settings tab.');
      }

      const res = await aiFetch(`${endpoint}/messages`, AI_PROVIDERS_META['claude-code'].isLocal, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model,
          max_tokens: 4096,
          system: systemPrompt,
          messages: [{ role: 'user', content: formattedUserPrompt }],
        }),
        signal: AbortSignal.timeout(30000),
      });

      if (!res.ok) {
        throw new Error(formatUpstreamHttpError('Anthropic API', res));
      }

      const data = (await res.json()) as any;
      const text = Array.isArray(data?.content)
        ? data.content.map((c: any) => (c.type === 'text' ? c.text : '')).join('')
        : '';
      if (!text) {
        throw new Error('Empty response returned from Anthropic API.');
      }
      return text;
    }

    case 'codex': {
      const p = aiCfg?.providers?.codex;
      const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.codex.defaultEndpoint;
      const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.codex.isLocal);
      const model = p?.model || AI_PROVIDERS_META.codex.defaultModel;
      const apiKey = resolveAiApiKey(
        p?.apiKey,
        process.env.OPENAI_API_KEY,
        endpoint,
        AI_PROVIDERS_META.codex.defaultEndpoint,
        isClientConfig
      );
      if (!apiKey) {
        throw new Error('Missing API Key for OpenAI Codex. Enter your API key in the Provider Settings tab.');
      }

      const res = await aiFetch(`${endpoint}/chat/completions`, AI_PROVIDERS_META.codex.isLocal, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: formattedUserPrompt },
          ],
          temperature: p?.temperature ?? 0.2,
        }),
        signal: AbortSignal.timeout(30000),
      });

      if (!res.ok) {
        throw new Error(formatUpstreamHttpError('OpenAI API', res));
      }

      const data = (await res.json()) as any;
      const text = data?.choices?.[0]?.message?.content || '';
      if (!text) {
        throw new Error('Empty response returned from OpenAI API.');
      }
      return text;
    }

    case 'vllm': {
      const p = aiCfg?.providers?.vllm;
      const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.vllm.defaultEndpoint;
      const endpoint = await validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.vllm.isLocal);
      const model = p?.model || AI_PROVIDERS_META.vllm.defaultModel;
      const apiKey = resolveAiApiKey(
        p?.apiKey,
        undefined,
        endpoint,
        AI_PROVIDERS_META.vllm.defaultEndpoint,
        isClientConfig
      );
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (apiKey) {
        headers.Authorization = `Bearer ${apiKey}`;
      }

      const res = await aiFetch(`${endpoint}/chat/completions`, AI_PROVIDERS_META.vllm.isLocal, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: formattedUserPrompt },
          ],
          max_tokens: p?.maxTokens ?? 4096,
        }),
        signal: AbortSignal.timeout(45000),
      });

      if (!res.ok) {
        throw new Error(formatUpstreamHttpError('vLLM', res));
      }

      const data = (await res.json()) as any;
      const text = data?.choices?.[0]?.message?.content || '';
      if (!text) {
        throw new Error('Empty response returned from vLLM.');
      }
      return text;
    }
  }
}
