import * as jose from 'jose';
import { assertSafeOutboundTarget, classifyIpRange } from './ssrf.js';

let cachedJwks = null;
let cachedIssuer = null;

async function assertSafeOidcUrl(rawUrl, label, { allowLoopback = true } = {}) {
  const { url } = await assertSafeOutboundTarget(rawUrl, {
    label: `OIDC ${label}`,
    allowHttpOnlyForLoopback: allowLoopback,
    allowPrivate: false,
    allowLoopback,
    allowMetadata: false
  });
  return url;
}

function isLoopbackHost(urlObj) {
  const host = urlObj.hostname.replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  return host === 'localhost' || host.endsWith('.localhost') || classifyIpRange(host) === 'loopback';
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
      const safeIssuerUrl = await assertSafeOidcUrl(config.issuer, 'issuer');
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
      const safeJwksUrl = await assertSafeOidcUrl(discovery.jwks_uri, 'jwks_uri', {
        allowLoopback: isLoopbackHost(safeIssuerUrl)
      });
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
