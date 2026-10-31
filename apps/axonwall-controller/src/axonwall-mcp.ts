#!/usr/bin/env node
import * as readline from 'node:readline';
import { authenticateMcpToken } from './mcp/authz.js';
import { processMcpJsonRpcMessage, type JsonRpcRequest } from './mcp/server.js';
import { recordMcpAuditEntry } from './mcp/audit.js';

async function runStdioMcpServer() {
  // Extract token from AXONWALL_MCP_TOKEN env var or --token=<tok> CLI flag
  let rawToken = process.env.AXONWALL_MCP_TOKEN || '';
  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith('--token=')) {
      rawToken = arg.slice('--token='.length).trim();
    }
  }

  const clientIp = process.env.SSH_CLIENT?.split(' ')[0] || '127.0.0.1';
  const auth = authenticateMcpToken(rawToken, clientIp);
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

  const key = auth.key;
  const rl = readline.createInterface({
    input: process.stdin,
    terminal: false,
  });

  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
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
  });
}

runStdioMcpServer().catch((err) => {
  process.stderr.write(`[Axonwall MCP] Fatal error: ${err?.message || err}\n`);
  process.exit(1);
});
