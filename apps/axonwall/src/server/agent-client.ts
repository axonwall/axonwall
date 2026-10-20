import http from 'node:http';
import fs from 'node:fs';

export const AGENT_API_SOCKET = process.env.AGENT_API_SOCKET || '/run/axonwall/agent-api.sock';

let cachedAgentToken: string | null | undefined;

export function getAgentToken(): string | undefined {
  if (cachedAgentToken !== undefined) {
    return cachedAgentToken ?? undefined;
  }
  let tok = process.env.AXONWALL_AGENT_TOKEN;
  if (!tok) {
    try {
      tok = fs
        .readFileSync(process.env.AXONWALL_AGENT_TOKEN_FILE || '/etc/axonwall/agent.token', 'utf8')
        .trim();
    } catch {}
  }
  cachedAgentToken = tok || null;
  return tok || undefined;
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
    const req = http.request(
      {
        socketPath: AGENT_API_SOCKET,
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
