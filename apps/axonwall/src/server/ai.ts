'use server';

import {
  AI_PROVIDERS_META,
  buildSystemPrompt,
  buildRuleDraftPrompt,
  buildLogAnalysisPrompt,
  buildAuditPrompt,
} from '@axonwall/lib/ai';
import type { AiProviderType, AiConfig } from '@axonwall/lib/schemas';
import { getSession } from './auth';
import { assertActionPermitted } from './auth-guard';
import { getCurrentDesiredState } from './agent';

export interface AiProbeResult {
  ok: boolean;
  status: string;
  latencyMs?: number;
  modelsFound?: string[];
  error?: string;
}

function validateAiEndpoint(endpoint: string, isLocalExpected: boolean): string {
  const clean = endpoint.trim().replace(/\/+$/, '');
  let url: URL;
  try {
    url = new URL(clean);
  } catch {
    throw new Error('Invalid endpoint URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Endpoint must use http: or https:');
  }

  const hostname = url.hostname.toLowerCase();
  if (hostname === '169.254.169.254' || hostname.startsWith('169.254.')) {
    throw new Error('Access to cloud metadata endpoints is prohibited');
  }

  if (!isLocalExpected && url.protocol === 'http:' && hostname !== 'localhost' && hostname !== '127.0.0.1') {
    throw new Error('Remote AI provider endpoints must use HTTPS');
  }

  return clean;
}

function resolveAiApiKey(
  configuredKey: string | undefined,
  envKey: string | undefined,
  endpoint: string,
  defaultEndpoint: string,
  isClientConfig: boolean
): string {
  if (isClientConfig && endpoint !== defaultEndpoint) {
    return (configuredKey || '').trim();
  }
  return (configuredKey || envKey || '').trim();
}

export async function testAiProviderProbe(
  provider: AiProviderType,
  currentConfig?: AiConfig
): Promise<AiProbeResult> {
  const session = await getSession();
  assertActionPermitted(session, currentConfig ? 'admin' : undefined);

  const state = await getCurrentDesiredState();
  const aiCfg = currentConfig || state.ai;
  const isClientConfig = Boolean(currentConfig);
  const start = Date.now();

  try {
    switch (provider) {
      case 'antigravity': {
        const p = aiCfg?.providers?.antigravity;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.antigravity.defaultEndpoint;
        const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.antigravity.isLocal);
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
        const res = await fetch(`${endpoint}/models?key=${encodeURIComponent(apiKey)}`, {
          method: 'GET',
          signal: AbortSignal.timeout(5000),
        });
        const latencyMs = Date.now() - start;
        if (!res.ok) {
          const text = await res.text().catch(() => '');
          return {
            ok: false,
            status: `HTTP ${res.status} (${res.statusText || 'Auth Failed'})`,
            latencyMs,
            error: text.slice(0, 200) || `Endpoint returned HTTP ${res.status}`,
          };
        }
        const data = (await res.json().catch(() => ({}))) as any;
        const models = Array.isArray(data?.models)
          ? data.models.map((m: any) => String(m.name || '').replace(/^models\//, '')).filter(Boolean)
          : [];
        return {
          ok: true,
          status: `Connected & Verified (${latencyMs}ms)`,
          latencyMs,
          modelsFound: models,
        };
      }

      case 'ollama': {
        const p = aiCfg?.providers?.ollama;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.ollama.defaultEndpoint;
        const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.ollama.isLocal);
        const res = await fetch(`${endpoint}/api/tags`, {
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
        return {
          ok: true,
          status: `Online (${models.length} model${models.length === 1 ? '' : 's'}, ${latencyMs}ms)`,
          latencyMs,
          modelsFound: models,
        };
      }

      case 'claude-code': {
        const p = aiCfg?.providers?.claudeCode;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META['claude-code'].defaultEndpoint;
        const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META['claude-code'].isLocal);
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
        const res = await fetch(`${endpoint}/models`, {
          method: 'GET',
          headers: {
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
          },
          signal: AbortSignal.timeout(5000),
        });
        const latencyMs = Date.now() - start;
        if (!res.ok) {
          const text = await res.text().catch(() => '');
          return {
            ok: false,
            status: `HTTP ${res.status} (${res.statusText || 'Auth Failed'})`,
            latencyMs,
            error: text.slice(0, 200) || `Anthropic endpoint returned HTTP ${res.status}`,
          };
        }
        const data = (await res.json().catch(() => ({}))) as any;
        const models = Array.isArray(data?.data)
          ? data.data.map((m: any) => String(m.id || '')).filter(Boolean)
          : [];
        return {
          ok: true,
          status: `Connected & Verified (${latencyMs}ms)`,
          latencyMs,
          modelsFound: models,
        };
      }

      case 'codex': {
        const p = aiCfg?.providers?.codex;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.codex.defaultEndpoint;
        const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.codex.isLocal);
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
        const res = await fetch(`${endpoint}/models`, {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${apiKey}`,
          },
          signal: AbortSignal.timeout(5000),
        });
        const latencyMs = Date.now() - start;
        if (!res.ok) {
          const text = await res.text().catch(() => '');
          return {
            ok: false,
            status: `HTTP ${res.status} (${res.statusText || 'Auth Failed'})`,
            latencyMs,
            error: text.slice(0, 200) || `OpenAI endpoint returned HTTP ${res.status}`,
          };
        }
        const data = (await res.json().catch(() => ({}))) as any;
        const models = Array.isArray(data?.data)
          ? data.data.map((m: any) => String(m.id || '')).filter(Boolean)
          : [];
        return {
          ok: true,
          status: `Connected & Verified (${latencyMs}ms)`,
          latencyMs,
          modelsFound: models,
        };
      }

      case 'vllm': {
        const p = aiCfg?.providers?.vllm;
        const rawEndpoint = p?.endpoint || AI_PROVIDERS_META.vllm.defaultEndpoint;
        const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.vllm.isLocal);
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
        const res = await fetch(`${endpoint}/models`, {
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
        return {
          ok: true,
          status: `Online (${models.length} model${models.length === 1 ? '' : 's'}, ${latencyMs}ms)`,
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
  assertActionPermitted(session, (currentConfig || mode === 'audit') ? 'admin' : undefined);

  const state = await getCurrentDesiredState();
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
      const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.antigravity.isLocal);
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

      const res = await fetch(
        `${endpoint}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`,
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
        const errBody = await res.text().catch(() => '');
        throw new Error(`Gemini API HTTP ${res.status}: ${errBody.slice(0, 300) || res.statusText}`);
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
      const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.ollama.isLocal);
      const model = p?.model || AI_PROVIDERS_META.ollama.defaultModel;
      const temperature = p?.temperature ?? 0.2;

      const res = await fetch(`${endpoint}/api/chat`, {
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
        const errBody = await res.text().catch(() => '');
        throw new Error(`Ollama HTTP ${res.status}: ${errBody.slice(0, 300) || res.statusText}`);
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
      const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META['claude-code'].isLocal);
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

      const res = await fetch(`${endpoint}/messages`, {
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
        const errBody = await res.text().catch(() => '');
        throw new Error(`Anthropic API HTTP ${res.status}: ${errBody.slice(0, 300) || res.statusText}`);
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
      const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.codex.isLocal);
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

      const res = await fetch(`${endpoint}/chat/completions`, {
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
        const errBody = await res.text().catch(() => '');
        throw new Error(`OpenAI API HTTP ${res.status}: ${errBody.slice(0, 300) || res.statusText}`);
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
      const endpoint = validateAiEndpoint(rawEndpoint, AI_PROVIDERS_META.vllm.isLocal);
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

      const res = await fetch(`${endpoint}/chat/completions`, {
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
        const errBody = await res.text().catch(() => '');
        throw new Error(`vLLM HTTP ${res.status}: ${errBody.slice(0, 300) || res.statusText}`);
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
