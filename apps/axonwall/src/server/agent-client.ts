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

export type AgentApiResult<T> =
  | { kind: 'ok'; data: T }
  | { kind: 'http_error'; status: number; message: string; data?: any }
  | { kind: 'timeout' }
  | { kind: 'unreachable' };

function sendAgentApiRequest<T>(
  reqPath: string,
  method: string,
  postData: string | undefined,
  agentToken: string | undefined,
  socketPath: string,
  timeoutMs: number
): Promise<AgentApiResult<T>> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        socketPath,
        path: reqPath,
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
          const status = res.statusCode || 500;
          if (status >= 200 && status < 300) {
            try {
              resolve({ kind: 'ok', data: JSON.parse(data) as T });
            } catch {
              resolve({
                kind: 'http_error',
                status,
                message: 'Invalid JSON response from daemon API',
              });
            }
          } else {
            let parsedBody: any = undefined;
            let errorMsg = '';
            try {
              parsedBody = JSON.parse(data);
              errorMsg = parsedBody?.message || parsedBody?.error || '';
            } catch {
              errorMsg = data.trim();
            }
            if (!errorMsg) {
              errorMsg = `Daemon API error (${status})`;
            }
            resolve({ kind: 'http_error', status, message: errorMsg, data: parsedBody });
          }
        });
      }
    );

    req.on('error', () => {
      resolve({ kind: 'unreachable' });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ kind: 'timeout' });
    });

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

export async function callAgentApiDetailed<T>(
  path: string,
  method = 'GET',
  body?: any,
  timeoutMs = 4000
): Promise<AgentApiResult<T>> {
  const postData = body ? JSON.stringify(body) : undefined;
  const socketPath = getAgentApiSocketPath();
  let agentToken = getAgentToken();
  let res = await sendAgentApiRequest<T>(path, method, postData, agentToken, socketPath, timeoutMs);
  if (res.kind === 'http_error' && res.status === 401) {
    cachedAgentToken = undefined;
    agentToken = getAgentToken();
    res = await sendAgentApiRequest<T>(path, method, postData, agentToken, socketPath, timeoutMs);
  }
  return res;
}

export async function callAgentApi<T>(
  path: string,
  method = 'GET',
  body?: any,
  timeoutMs = 4000
): Promise<T | null> {
  const res = await callAgentApiDetailed<T>(path, method, body, timeoutMs);
  if (res.kind === 'ok') {
    return res.data;
  }
  return null;
}

export async function callAgentApiResponse<T extends { success?: boolean; message?: string; error?: string }>(
  path: string,
  method = 'GET',
  body?: any,
  timeoutMs = 4000
): Promise<T | null> {
  const res = await callAgentApiDetailed<T>(path, method, body, timeoutMs);
  if (res.kind === 'ok') {
    return res.data;
  }
  if (res.kind === 'http_error') {
    return {
      ...(res.data && typeof res.data === 'object' ? res.data : {}),
      success: false,
      message: res.message,
      error: res.message,
    } as T;
  }
  return null;
}

export async function callAgentApiBinary(
  path: string,
  method = 'GET',
  timeoutMs = 30000
): Promise<{ ok: boolean; status: number; buffer?: Buffer; error?: string }> {
  return new Promise((resolve) => {
    const agentToken = getAgentToken();
    const socketPath = getAgentApiSocketPath();
    const req = http.request(
      {
        socketPath,
        path,
        method,
        headers: {
          ...(agentToken ? { 'X-Axonwall-Agent-Token': agentToken } : {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          chunks.push(chunk);
        });
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          const status = res.statusCode || 500;
          if (status >= 200 && status < 300) {
            resolve({ ok: true, status, buffer: buf });
            return;
          }
          let errorMsg = buf.toString('utf8').trim();
          try {
            const parsed = JSON.parse(errorMsg);
            errorMsg = parsed.message || parsed.error || errorMsg;
          } catch {}
          resolve({
            ok: false,
            status,
            error: errorMsg || `Daemon API error (${status})`,
          });
        });
      }
    );

    req.on('error', (err) => {
      resolve({ ok: false, status: 503, error: err?.message || 'Daemon unreachable' });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, status: 504, error: `Daemon request timed out (${Math.round(timeoutMs / 1000)}s)` });
    });

    req.end();
  });
}
