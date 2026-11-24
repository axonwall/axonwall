import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DesiredStateSchema } from '@axonwall/lib/schemas';
import type { UserSession } from '@axonwall/lib/rbac';

const hoisted = vi.hoisted(() => {
  const adminSession: UserSession = {
    userId: 'admin-1',
    username: 'admin',
    displayName: 'Administrator',
    roles: ['admin'],
    privileges: [],
    passwordChangeRequired: false,
    source: 'local',
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  return {
    getSession: vi.fn(async () => adminSession),
    getDesiredStateInternal: vi.fn(async () => DesiredStateSchema.parse({ version: 1 })),
    assertSafeOutboundUrl: vi.fn(async (url: string) => url),
    ssrfSafeFetch: vi.fn(async () => {
      throw new Error('ssrfSafeFetch must not be called when ai-copilot is disabled');
    }),
  };
});

vi.mock('../auth', () => ({
  getSession: hoisted.getSession,
}));

vi.mock('../desired-state-internal', () => ({
  getDesiredStateInternal: hoisted.getDesiredStateInternal,
}));

vi.mock('../ssrf-guard', () => ({
  assertSafeOutboundUrl: hoisted.assertSafeOutboundUrl,
  ssrfSafeFetch: hoisted.ssrfSafeFetch,
}));

import { generateAiCompletion, testAiProviderProbe } from '../ai';

describe('AI Network Copilot (ai-copilot) server fail-closed gating', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hoisted.getDesiredStateInternal.mockResolvedValue(DesiredStateSchema.parse({ version: 1 }));
  });

  it('refuses provider probes with Plugin Disabled without calling outbound fetch when ai-copilot is disabled', async () => {
    const res = await testAiProviderProbe('ollama');
    expect(res.ok).toBe(false);
    expect(res.status).toBe('Plugin Disabled');
    expect(res.error).toContain('ai-copilot');
    expect(hoisted.ssrfSafeFetch).not.toHaveBeenCalled();
    expect(hoisted.assertSafeOutboundUrl).not.toHaveBeenCalled();
  });

  it('rejects completions fail-closed without calling outbound fetch when ai-copilot is disabled', async () => {
    await expect(
      generateAiCompletion('ollama', 'Draft an nftables rule to block port 22 on wan', 'draft'),
    ).rejects.toThrow(/ai-copilot.*disabled/i);

    expect(hoisted.ssrfSafeFetch).not.toHaveBeenCalled();
    expect(hoisted.assertSafeOutboundUrl).not.toHaveBeenCalled();
  });
});
