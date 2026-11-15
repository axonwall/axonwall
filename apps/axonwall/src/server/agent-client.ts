import http from 'node:http';
import fs from 'node:fs';
import { getAgentApiSocketPath, getAgentTokenCandidatePaths } from './dev-paths';

export const AGENT_API_SOCKET = getAgentApiSocketPath();

let cachedAgentToken: string | undefined;

export function getAgentToken(): string | undefined {
  if (cachedAgentToken) {
    return cachedAgentToken;
  }
  const envTok = process.env.AXONWALL_AGENT_TOKEN?.trim();
  if (envTok) {
    cachedAgentToken = envTok;
    return envTok;
  }
  for (const tokenPath of getAgentTokenCandidatePaths()) {
    try {
      if (!fs.existsSync(tokenPath)) continue;
      const tok = fs.readFileSync(tokenPath, 'utf8').trim();
      if (tok) {
        cachedAgentToken = tok;
        return tok;
      }
    } catch {}
  }
  return undefined;
}

export async function callAgentApi<T>(
  path: string,
  method = 'GET',
  body?: any,
  timeoutMs = 4000
): Promise<T | null> {
  return new Promise((resolve) => {
    const postData = body ? JSON.stringify(body) : undefined;
    const agentToken = getAgentToken();
    const socketPath = getAgentApiSocketPath();
    const req = http.request(
      {
        socketPath,
        path,
        method,
        headers: {
          ...(postData
            ? {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData),
              }
            : {}),
          ...(agentToken ? { 'X-Axonwall-Agent-Token': agentToken } : {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(data) as T);
            } catch {
              resolve(null);
            }
          } else {
            let errorMsg = '';
            try {
              const parsed = JSON.parse(data);
              errorMsg = parsed.message || parsed.error || '';
            } catch {
              errorMsg = data.trim();
            }
            if (!errorMsg) {
              errorMsg = `Daemon API error (${res.statusCode || 'unknown'})`;
            }
            // Return failure object carrying the daemon error message
            resolve({ success: false, message: errorMsg, error: errorMsg } as unknown as T);
          }
        });
      }
    );

    req.on('error', () => {
      resolve(null);
    });

    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}
