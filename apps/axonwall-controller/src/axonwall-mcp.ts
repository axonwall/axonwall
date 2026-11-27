#!/usr/bin/env node
import * as path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { getMcpServerStatus } from '@axonwall/lib/mcp';
import { isPluginEnabled } from '@axonwall/lib/plugins';
import { DesiredStateSchema } from '@axonwall/lib/schemas';
import { resolveControllerDirs } from './dev-paths.js';
import { readCanonicalConfig } from './atomic-config.js';
import { authenticateMcpToken } from './mcp/authz.js';
import { processMcpJsonRpcMessage, type JsonRpcRequest } from './mcp/server.js';
import { recordMcpAuditEntry } from './mcp/audit.js';

function checkMcpPluginEnabledForStdio(): { enabled: boolean; reason?: string } {
  const status = getMcpServerStatus();
  if (!status.enabled) {
    return { enabled: false, reason: status.disabledReason || 'Axonwall MCP server is disabled by policy' };
  }
  const envEnabled = process.env.AXONWALL_MCP_ENABLED?.toLowerCase();
  if (envEnabled === 'true' || envEnabled === '1') {
    return { enabled: true };
  }
  const dirs = resolveControllerDirs();
  const state = readCanonicalConfig({
    canonicalPath: dirs.stateFile,
    mirrorPaths: [path.join(dirs.etcDir, 'state.json')],
    parse: (raw) => {
      try {
        const parsed = DesiredStateSchema.safeParse(JSON.parse(raw));
        return parsed.success ? parsed.data : null;
      } catch {
        return null;
      }
    },
    label: 'state.json',
  });
  if (state && !isPluginEnabled('mcp-ai-control', state)) {
    const explicitDisable =
      state.plugins?.some((p) => p.id === 'mcp-ai-control' && p.enabled === false) ||
      state.mcp?.enabled === false;
    if (explicitDisable || status.source !== 'settings_file') {
      return { enabled: false, reason: "Plugin 'mcp-ai-control' is not enabled in DesiredState." };
    }
  }
  return { enabled: true };
}

const MAX_STDIO_LINE_BYTES = 2_500_000;
const MAX_STDIN_TOKEN_BYTES = 4096;

function startBoundedStdinLineReader(
  maxLineBytes: number,
  onLine: (line: string) => Promise<void>,
  onOversizedLine: () => void,
  onClose?: () => void
): void {
  let chunks: Buffer[] = [];
  let totalBytes = 0;
  let discardingOversized = false;
  let chain: Promise<void> = Promise.resolve();

  const enqueueLine = (line: string) => {
    chain = chain.then(() => onLine(line)).catch((err) => {
      process.stderr.write(`[Axonwall MCP] Stdin line processing error: ${err?.message || err}\n`);
    });
  };

  process.stdin.on('data', (rawChunk: Buffer | string) => {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk, 'utf8');
    let offset = 0;

    while (offset < chunk.length) {
      const nlIdx = chunk.indexOf(0x0a, offset);
      if (discardingOversized) {
        if (nlIdx === -1) {
          offset = chunk.length;
        } else {
          discardingOversized = false;
          offset = nlIdx + 1;
          chain = chain.then(() => {
            onOversizedLine();
          });
        }
        continue;
      }

      const end = nlIdx === -1 ? chunk.length : nlIdx;
      const segLen = end - offset;
      if (totalBytes + segLen > maxLineBytes) {
        chunks = [];
        totalBytes = 0;
        if (nlIdx === -1) {
          discardingOversized = true;
          offset = chunk.length;
        } else {
          offset = nlIdx + 1;
          chain = chain.then(() => {
            onOversizedLine();
          });
        }
        continue;
      }

      if (segLen > 0) {
        chunks.push(chunk.subarray(offset, end));
        totalBytes += segLen;
      }

      if (nlIdx !== -1) {
        const line = Buffer.concat(chunks, totalBytes).toString('utf8');
        chunks = [];
        totalBytes = 0;
        offset = nlIdx + 1;
        enqueueLine(line);
      } else {
        offset = chunk.length;
      }
    }
  });

  process.stdin.on('end', () => {
    if (discardingOversized) {
      discardingOversized = false;
      chain = chain.then(() => {
        onOversizedLine();
      });
    } else if (totalBytes > 0) {
      const line = Buffer.concat(chunks, totalBytes).toString('utf8');
      chunks = [];
      totalBytes = 0;
      enqueueLine(line);
    }
    if (onClose) {
      chain = chain.then(() => onClose());
    }
  });
}

async function runStdioMcpServer() {
  const clientIp = process.env.SSH_CLIENT?.split(' ')[0] || '127.0.0.1';
  const pluginCheck = checkMcpPluginEnabledForStdio();
  if (!pluginCheck.enabled) {
    recordMcpAuditEntry({
      keyId: 'plugin-guard',
      keyName: 'stdio-startup',
      agentType: 'unknown',
      clientIp,
      toolName: 'stdio:startup',
      requiredScope: 'mcp:auth',
      decision: 'denied',
      denialReason: pluginCheck.reason || 'MCP plugin disabled',
      paramsSummary: { transport: 'stdio' },
    });
    process.stderr.write(`[Axonwall MCP] ${pluginCheck.reason}\n`);
    process.exit(1);
  }

  // SEC-L11: Reject --token / --token=<tok> CLI flags so secrets are never exposed in /proc/<pid>/cmdline.
  const cliArgs = process.argv.slice(2);
  if (cliArgs.some((arg) => arg === '--token' || arg.startsWith('--token='))) {
    const reason = 'Passing --token on the command line is rejected for security. Use AXONWALL_MCP_TOKEN or --token-stdin.';
    recordMcpAuditEntry({
      keyId: 'unauthenticated',
      keyName: 'unauthenticated-stdio',
      agentType: 'unknown',
      clientIp,
      toolName: 'stdio:startup',
      requiredScope: 'mcp:auth',
      decision: 'denied',
      denialReason: reason,
      paramsSummary: { transport: 'stdio' },
    });
    process.stderr.write(`[Axonwall MCP] ${reason}\n`);
    process.exit(1);
  }

  const useStdinToken = cliArgs.includes('--token-stdin');
  let rawToken = (process.env.AXONWALL_MCP_TOKEN || '').trim();
  let authenticatedKey: ReturnType<typeof authenticateMcpToken>['key'] | null = null;

  const authenticateOrExit = (candidateToken: string) => {
    const auth = authenticateMcpToken(candidateToken, clientIp);
    if (!auth.authenticated || !auth.key) {
      recordMcpAuditEntry({
        keyId: auth.key?.id ?? 'unauthenticated',
        keyName: auth.key?.name ?? 'unauthenticated-stdio',
        agentType: auth.key?.agentType ?? 'unknown',
        clientIp,
        toolName: 'stdio:startup',
        requiredScope: 'mcp:auth',
        decision: 'denied',
        denialReason: auth.errorMessage || 'Stdio MCP authentication failed',
        paramsSummary: { transport: 'stdio' },
      });
      process.stderr.write(`[Axonwall MCP] Authentication failed: ${auth.errorMessage}\n`);
      process.exit(1);
    }
    rawToken = candidateToken;
    authenticatedKey = auth.key;
  };

  if (rawToken || !useStdinToken) {
    authenticateOrExit(rawToken);
  }

  let awaitingTokenLine = Boolean(!authenticatedKey && useStdinToken);

  startBoundedStdinLineReader(
    MAX_STDIO_LINE_BYTES,
    async (line) => {
      const trimmed = line.trim();
      if (awaitingTokenLine) {
        if (Buffer.byteLength(line, 'utf8') > MAX_STDIN_TOKEN_BYTES) {
          process.stderr.write('[Axonwall MCP] Authentication failed: stdin token line exceeds maximum size\n');
          process.exit(1);
        }
        awaitingTokenLine = false;
        authenticateOrExit(trimmed);
        return;
      }

      if (!trimmed || !authenticatedKey) return;
      const key = authenticatedKey;
      try {
        const msg = JSON.parse(trimmed) as JsonRpcRequest;
        const freshAuth = authenticateMcpToken(rawToken, clientIp);
        if (!freshAuth.authenticated || !freshAuth.key) {
          recordMcpAuditEntry({
            keyId: freshAuth.key?.id ?? key.id,
            keyName: freshAuth.key?.name ?? key.name,
            agentType: freshAuth.key?.agentType ?? key.agentType,
            clientIp,
            toolName: `stdio:${msg.method || 'request'}`,
            requiredScope: 'mcp:auth',
            decision: 'denied',
            denialReason: freshAuth.errorMessage || 'Stdio MCP token re-authentication failed',
            paramsSummary: { transport: 'stdio', method: msg.method },
          });
          if (msg.id !== undefined) {
            process.stdout.write(
              JSON.stringify({
                jsonrpc: '2.0',
                id: msg.id ?? null,
                error: {
                  code: -32001,
                  message: freshAuth.errorMessage || 'Unauthorized or rate-limited MCP session',
                },
              }) + '\n'
            );
          }
          return;
        }
        const resp = await processMcpJsonRpcMessage(msg, {
          key: freshAuth.key,
          clientIp,
        });
        if (resp) {
          process.stdout.write(JSON.stringify(resp) + '\n');
        }
      } catch {
        process.stdout.write(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: { code: -32700, message: 'Parse error' },
          }) + '\n'
        );
      }
    },
    () => {
      if (awaitingTokenLine) {
        process.stderr.write('[Axonwall MCP] Authentication failed: stdin token line exceeds maximum size\n');
        process.exit(1);
      }
      process.stdout.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32600,
            message: `Request line exceeds maximum allowed size (${MAX_STDIO_LINE_BYTES} bytes)`,
          },
        }) + '\n'
      );
    },
    () => {
      if (awaitingTokenLine) {
        authenticateOrExit('');
      }
    }
  );
}

runStdioMcpServer().catch((err) => {
  process.stderr.write(`[Axonwall MCP] Fatal error: ${err?.message || err}\n`);
  process.exit(1);
});
