import * as jose from 'jose';
import net from 'node:net';

let cachedJwks = null;
let cachedIssuer = null;

function isLoopbackHost(hostname) {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

function isDisallowedPrivateOrMetadataHost(hostname) {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (isLoopbackHost(h)) return false;
  if (net.isIPv4(h)) {
    const [a, b] = h.split('.').map(Number);
    if (a === 169 && b === 254) return true; // cloud metadata / link-local
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  if (net.isIPv6(h)) {
    if (h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd') || h === '::') {
      return true;
    }
  }
  return false;
}

function assertSafeOidcUrl(rawUrl, label) {
  const parsed = new URL(rawUrl);
  const loopback = isLoopbackHost(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(loopback && parsed.protocol === 'http:')) {
    throw new Error(`Unsafe OIDC ${label} protocol '${parsed.protocol}'`);
  }
  if (!loopback && isDisallowedPrivateOrMetadataHost(parsed.hostname)) {
    throw new Error(`Unsafe private/metadata host in OIDC ${label}: ${parsed.hostname}`);
  }
  return parsed;
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
 * @returns {Promise<Object|null>} - Matched principal or null
 */
export async function verifyOidcToken(token, store) {
  const config = getOidcConfig();
  if (!config || !token) return null;

  try {
    if (!cachedJwks || cachedIssuer !== config.issuer) {
      const safeIssuerUrl = assertSafeOidcUrl(config.issuer, 'issuer');
      const wellKnownUrl = new URL(
        '.well-known/openid-configuration',
        safeIssuerUrl.toString().endsWith('/') ? safeIssuerUrl.toString() : `${safeIssuerUrl.toString()}/`
      );
      const res = await fetch(wellKnownUrl.toString(), {
        redirect: 'error',
        signal: AbortSignal.timeout(5000)
      });
      if (!res.ok) {
        throw new Error(`OIDC discovery failed: ${res.status} ${res.statusText}`);
      }
      const discovery = await res.json();
      if (discovery.issuer && discovery.issuer.replace(/\/+$/, '') !== config.issuer.replace(/\/+$/, '')) {
        throw new Error(`OIDC discovery issuer mismatch: '${discovery.issuer}' vs '${config.issuer}'`);
      }
      if (!discovery.jwks_uri) {
        throw new Error('OIDC discovery response missing jwks_uri');
      }
      const safeJwksUrl = assertSafeOidcUrl(discovery.jwks_uri, 'jwks_uri');
      cachedJwks = jose.createRemoteJWKSet(safeJwksUrl);
      cachedIssuer = config.issuer;
    }

    const { payload } = await jose.jwtVerify(token, cachedJwks, {
      issuer: config.issuer,
      audience: config.clientId
    });

    const subject = payload.sub;
    const email = payload.email_verified === true ? payload.email : null;

    if (!subject && !email) return null;

    // Find principal with matching oidcSubject
    const principal = store.principals.find(p => {
      if (!p.oidcSubject || p.disabled) return false;
      return p.oidcSubject === subject || (email && p.oidcSubject === email);
    });

    return principal || null;
  } catch (err) {
    return null;
  }
}
