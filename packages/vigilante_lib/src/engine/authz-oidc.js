import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import * as jose from 'jose';
import { assertSafeOutboundTarget, classifyIpRange } from './ssrf.js';

export const ALLOWED_OIDC_ALGORITHMS = ['RS256', 'ES256', 'PS256', 'EdDSA'];
const MAX_OIDC_RESPONSE_BYTES = 1024 * 1024; // 1 MB cap for discovery / JWKS payloads
const DEFAULT_OIDC_TIMEOUT_MS = 5000;

let cachedJwks = null;
let cachedIssuer = null;

async function assertSafeOidcUrl(rawUrl, label, { allowLoopback = true, dnsLookup } = {}) {
  return await assertSafeOutboundTarget(rawUrl, {
    label: `OIDC ${label}`,
    allowHttpOnlyForLoopback: allowLoopback,
    allowPrivate: false,
    allowLoopback,
    allowMetadata: false,
    failOnDnsError: true,
    ...(dnsLookup ? { dnsLookup } : {})
  });
}

function isLoopbackHost(urlObj) {
  const host = urlObj.hostname.replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  return host === 'localhost' || host.endsWith('.localhost') || classifyIpRange(host) === 'loopback';
}

function normalizeFetchHeaders(headersInput) {
  const out = {};
  if (!headersInput) return out;
  if (headersInput instanceof Headers) {
    for (const [k, v] of headersInput.entries()) {
      out[k] = v;
    }
    return out;
  }
  if (Array.isArray(headersInput)) {
    for (const [k, v] of headersInput) {
      out[String(k)] = String(v);
    }
    return out;
  }
  for (const [k, v] of Object.entries(headersInput)) {
    if (v !== undefined && v !== null) {
      out[k] = String(v);
    }
  }
  return out;
}

/**
 * Create a redirect-blocking, SSRF-validated, DNS-pinned fetch implementation
 * suitable for OIDC discovery and jose.createRemoteJWKSet({ [jose.customFetch] }).
 */
export function createPinnedOidcFetch({
  allowLoopback = true,
  label = 'jwks_uri',
  dnsLookup,
  maxBytes = MAX_OIDC_RESPONSE_BYTES,
  timeoutMs = DEFAULT_OIDC_TIMEOUT_MS
} = {}) {
  return async function pinnedOidcFetch(targetUrl, init = {}) {
    const rawUrl = targetUrl instanceof URL ? targetUrl.toString() : String(targetUrl ?? '');
    const { url: validatedUrl, hostname, isIp, addresses } = await assertSafeOidcUrl(rawUrl, label, {
      allowLoopback,
      dnsLookup
    });

    const pinnedIp = addresses[0];
    const family = pinnedIp ? net.isIP(pinnedIp) : 0;
    if (!pinnedIp || (family !== 4 && family !== 6)) {
      throw new Error(`OIDC ${label} could not pin a valid resolved IP address for '${hostname}'`);
    }

    const transport = validatedUrl.protocol === 'https:' ? https : http;
    const method = (init?.method || 'GET').toUpperCase();
    const headers = normalizeFetchHeaders(init?.headers);
    const signal = init?.signal;

    if (signal?.aborted) {
      throw signal.reason instanceof Error
        ? signal.reason
        : new DOMException('The operation was aborted', 'AbortError');
    }

    return await new Promise((resolve, reject) => {
      let settled = false;
      const finishReject = (err) => {
        if (!settled) {
          settled = true;
          cleanupSignal();
          reject(err);
        }
      };
      const finishResolve = (resObj) => {
        if (!settled) {
          settled = true;
          cleanupSignal();
          resolve(resObj);
        }
      };

      const reqOptions = {
        method,
        headers,
        timeout: timeoutMs,
        lookup: (_reqHost, opts, cb) => {
          const callback = typeof opts === 'function' ? opts : cb;
          if (typeof opts === 'object' && opts?.all) {
            callback(null, [{ address: pinnedIp, family }]);
          } else {
            callback(null, pinnedIp, family);
          }
        }
      };
      if (validatedUrl.protocol === 'https:' && !isIp) {
        reqOptions.servername = hostname;
      }

      const req = transport.request(validatedUrl, reqOptions, (res) => {
        const status = res.statusCode ?? 0;
        // Enforce strict redirect: 'error' semantics even when jose passes redirect: 'manual'
        if (status >= 300 && status < 400) {
          res.destroy();
          req.destroy();
          finishReject(new Error(`Blocked OIDC ${label} HTTP redirect (status ${status})`));
          return;
        }

        const chunks = [];
        let totalBytes = 0;

        res.on('data', (chunk) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          totalBytes += buf.length;
          if (totalBytes > maxBytes) {
            res.destroy();
            req.destroy();
            finishReject(new Error(`OIDC ${label} response exceeded ${maxBytes} bytes`));
            return;
          }
          chunks.push(buf);
        });

        res.on('end', () => {
          const responseHeaders = new Headers();
          for (const [k, v] of Object.entries(res.headers || {})) {
            if (Array.isArray(v)) {
              for (const item of v) responseHeaders.append(k, item);
            } else if (v !== undefined) {
              responseHeaders.set(k, String(v));
            }
          }
          const bodyBuf = Buffer.concat(chunks);
          finishResolve(
            new Response(bodyBuf, {
              status,
              statusText: res.statusMessage || '',
              headers: responseHeaders
            })
          );
        });

        res.on('error', (err) => {
          finishReject(err);
        });
      });

      const onAbort = () => {
        const reason = signal.reason instanceof Error
          ? signal.reason
          : new DOMException('The operation was aborted', 'AbortError');
        req.destroy(reason);
        finishReject(reason);
      };
      const cleanupSignal = () => {
        if (signal) {
          signal.removeEventListener('abort', onAbort);
        }
      };
      if (signal) {
        signal.addEventListener('abort', onAbort, { once: true });
      }

      req.on('timeout', () => {
        const err = new DOMException(`OIDC ${label} request timed out`, 'TimeoutError');
        req.destroy(err);
        finishReject(err);
      });
      req.on('error', (err) => {
        finishReject(err);
      });

      req.end();
    });
  };
}

/**
 * Get OIDC configuration from environment
 */
export function getOidcConfig() {
  const issuer = process.env.VIGILANTE_OIDC_ISSUER;
  const clientId = process.env.VIGILANTE_OIDC_CLIENT_ID;
  if (!issuer || !clientId) return null;
  return { issuer, clientId };
}

/**
 * Reset cached JWKS
 */
export function resetOidcCache() {
  cachedJwks = null;
  cachedIssuer = null;
}

/**
 * Verify an incoming Bearer JWT against the configured OIDC issuer
 * @param {string} token - Raw JWT string
 * @param {Object} store - Authz store
 * @param {Object} [options={}] - Optional verification overrides (e.g. dnsLookup for tests)
 * @returns {Promise<Object|null>} - Matched principal or null
 */
export async function verifyOidcToken(token, store, options = {}) {
  const config = getOidcConfig();
  if (!config || !token || typeof token !== 'string') return null;
  if (!store || !Array.isArray(store.principals)) return null;

  try {
    if (!cachedJwks || cachedIssuer !== config.issuer) {
      const { url: safeIssuerUrl } = await assertSafeOidcUrl(config.issuer, 'issuer', {
        dnsLookup: options.dnsLookup
      });
      const wellKnownUrl = new URL(
        '.well-known/openid-configuration',
        safeIssuerUrl.toString().endsWith('/') ? safeIssuerUrl.toString() : `${safeIssuerUrl.toString()}/`
      );

      const discoveryFetch = createPinnedOidcFetch({
        allowLoopback: true,
        label: 'discovery',
        dnsLookup: options.dnsLookup
      });
      const res = await discoveryFetch(wellKnownUrl.toString(), {
        redirect: 'error',
        signal: AbortSignal.timeout(DEFAULT_OIDC_TIMEOUT_MS)
      });
      if (!res.ok) {
        throw new Error(`OIDC discovery failed: ${res.status} ${res.statusText}`);
      }

      const discovery = await res.json();
      if (!discovery || typeof discovery.issuer !== 'string' || !discovery.issuer.trim()) {
        throw new Error('OIDC discovery response missing issuer');
      }
      if (discovery.issuer.trim().replace(/\/+$/, '') !== config.issuer.trim().replace(/\/+$/, '')) {
        throw new Error(`OIDC discovery issuer mismatch: '${discovery.issuer}' vs '${config.issuer}'`);
      }
      if (!discovery.jwks_uri || typeof discovery.jwks_uri !== 'string') {
        throw new Error('OIDC discovery response missing jwks_uri');
      }

      const allowLoopbackForJwks = isLoopbackHost(safeIssuerUrl);
      const { url: safeJwksUrl } = await assertSafeOidcUrl(discovery.jwks_uri, 'jwks_uri', {
        allowLoopback: allowLoopbackForJwks,
        dnsLookup: options.dnsLookup
      });
      const jwksFetch = createPinnedOidcFetch({
        allowLoopback: allowLoopbackForJwks,
        label: 'jwks_uri',
        dnsLookup: options.dnsLookup
      });

      cachedJwks = jose.createRemoteJWKSet(safeJwksUrl, {
        [jose.customFetch]: jwksFetch
      });
      cachedIssuer = config.issuer;
    }

    const { payload } = await jose.jwtVerify(token, cachedJwks, {
      issuer: config.issuer,
      audience: config.clientId,
      algorithms: ALLOWED_OIDC_ALGORITHMS
    });

    const subject = typeof payload.sub === 'string' && payload.sub.trim() ? payload.sub : null;
    const email = payload.email_verified === true && typeof payload.email === 'string' && payload.email.trim()
      ? payload.email
      : null;

    if (!subject && !email) return null;

    // Find principal with matching oidcSubject
    const principal = store.principals.find(p => {
      if (!p.oidcSubject || p.disabled) return false;
      return (subject && p.oidcSubject === subject) || (email && p.oidcSubject === email);
    });

    return principal || null;
  } catch {
    return null;
  }
}
