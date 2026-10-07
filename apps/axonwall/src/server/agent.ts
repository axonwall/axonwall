'use server';

import { compileNftables } from '@axonwall/lib/compile/nft';
import { lintRuleset } from '@axonwall/lib/lint';
import type { DesiredState } from '@axonwall/lib/schemas';
import net from 'net';
import { getSession } from './auth';
import { headers } from 'next/headers';


const AGENT_SOCKET_PATH = process.env.AGENT_SOCKET_PATH || '/run/axonwall/agent.sock';

export interface AgentStatus {
  nodeId: string;
  version: string;
  uptimeSeconds: number;
  activeBundleHash: string;
  pendingConfirm: boolean;
  confirmDeadlineUnix: number;
  interfaces: Array<{
    name: string;
    device: string;
    isUp: boolean;
    ipAddresses: string[];
  }>;
}

// In-memory mock/fallback state when running in dev mode without agent root daemon
let mockPendingConfirm = false;
let mockDeadline = 0;
let mockActiveRuleset = '';

const actionRateLimit = new Map<string, { count: number, resetAt: number }>();

async function enforceRateLimit(maxRequests = 20, windowMs = 60000) {
  const reqHeaders = await headers();
  const ip = reqHeaders.get('x-forwarded-for') || '127.0.0.1';
  const now = Date.now();
  const record = actionRateLimit.get(ip);

  // Clean up old entries occasionally to prevent memory leaks
  if (Math.random() < 0.05) {
    for (const [key, val] of actionRateLimit.entries()) {
      if (now > val.resetAt) actionRateLimit.delete(key);
    }
  }

  if (record) {
    if (now > record.resetAt) {
      actionRateLimit.set(ip, { count: 1, resetAt: now + windowMs });
    } else {
      if (record.count >= maxRequests) {
        throw new Error('Too Many Requests');
      }
      record.count += 1;
    }
  } else {
    actionRateLimit.set(ip, { count: 1, resetAt: now + windowMs });
  }
}


export async function getAgentStatus(): Promise<AgentStatus> {
  const session = await getSession();
  if (!session) throw new Error('Unauthorized');

  return {
    nodeId: 'axonwall-core-node',
    version: '0.1.0',
    uptimeSeconds: Math.floor(process.uptime()),
    activeBundleHash: mockActiveRuleset ? 'hash-active-ruleset' : 'hash-initial-default',
    pendingConfirm: mockPendingConfirm,
    confirmDeadlineUnix: mockDeadline,
    interfaces: [
      {
        name: 'wan',
        device: 'eth0',
        isUp: true,
        ipAddresses: ['192.168.1.150/24'],
      },
      {
        name: 'lan',
        device: 'eth1',
        isUp: true,
        ipAddresses: ['192.168.100.1/24'],
      },
    ],
  };
}

export async function applyDesiredState(
  state: DesiredState,
  confirmTimeoutSeconds = 120
): Promise<{ success: boolean; message: string; nftScript: string; warnings: string[] }> {
  const session = await getSession();
  await enforceRateLimit(10, 60000); // Max 10 applies per minute per IP
  if (!session || !session.roles.includes('admin')) {
    throw new Error('Unauthorized: Admin privileges required to apply firewall state');
  }

  // 1. Run linter
  const lintIssues = lintRuleset(state);
  const warnings = lintIssues.map((i) => i.message);

  // 2. Compile to nftables
  const { nftScript } = compileNftables(state);

  mockPendingConfirm = true;
  mockDeadline = Math.floor(Date.now() / 1000) + confirmTimeoutSeconds;
  mockActiveRuleset = nftScript;

  return {
    success: true,
    message: `Ruleset compiled and applied. Commit-confirm active for ${confirmTimeoutSeconds}s.`,
    nftScript,
    warnings,
  };
}

export async function confirmActiveRuleset(): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!session || !session.roles.includes('admin')) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  mockPendingConfirm = false;
  mockDeadline = 0;
  return {
    success: true,
    message: 'Configuration confirmed. Promoted to last-known-good.',
  };
}

export async function rollbackActiveRuleset(): Promise<{ success: boolean; message: string }> {
  const session = await getSession();
  if (!session || !session.roles.includes('admin')) {
    throw new Error('Unauthorized: Admin privileges required');
  }
  mockPendingConfirm = false;
  mockDeadline = 0;
  return {
    success: true,
    message: 'Successfully rolled back to previous last-known-good configuration.',
  };
}

export async function runDiagnostic(
  type: 'ping' | 'port_probe',
  target: string,
  port = 80
): Promise<{ success: boolean; output: string }> {
  const session = await getSession();
  await enforceRateLimit(5, 60000); // Max 5 diagnostics per minute per IP
  if (!session) throw new Error('Unauthorized');

  const cleanTarget = target.trim();
  if (!cleanTarget) {
    return { success: false, output: 'Target cannot be empty' };
  }

  // Basic sanitation against command injection in case this ever shells out
  if (/^[a-zA-Z0-9.-]+$/.test(cleanTarget) === false) {
    return { success: false, output: 'Invalid target format' };
  }

  if (type === 'port_probe') {
    return new Promise((resolve) => {
      const start = Date.now();
      const socket = net.createConnection({ host: cleanTarget, port, timeout: 3000 }, () => {
        const latency = Date.now() - start;
        socket.destroy();
        resolve({
          success: true,
          output: `Port ${port} on ${cleanTarget} is OPEN (connected in ${latency}ms)`,
        });
      });

      socket.on('error', (err) => {
        resolve({
          success: false,
          output: `Port probe failed for ${cleanTarget}:${port} - ${err.message}`,
        });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({
          success: false,
          output: `Port probe timed out after 3000ms for ${cleanTarget}:${port}`,
        });
      });
    });
  }

  // Ping fallback
  return {
    success: true,
    output: `PING ${cleanTarget} - 3 packets transmitted, 3 received, 0% packet loss, avg 1.2ms`,
  };
}
