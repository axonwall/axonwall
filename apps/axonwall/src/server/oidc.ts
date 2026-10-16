import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

/**
 * OIDC helpers for SSO sign-in.
 *
 * Identity is only ever taken from a verified ID token: the login route
 * starts a real authorization-code flow (with state + nonce bound to an
 * httpOnly cookie), and the callback exchanges the code at the provider's
 * token endpoint and verifies the returned ID token against the
 * provider's JWKS before any session is minted. There is deliberately
 * no simulation or development shortcut here: if OIDC is not configured,
 * SSO is unavailable.
 */

export const OIDC_STATE_COOKIE = 'axonwall_oidc_state';

export interface OidcConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
}

export function getOidcConfig(): OidcConfig | null {
  const issuerUrl = process.env.OIDC_ISSUER_URL;
  const clientId = process.env.OIDC_CLIENT_ID;
  if (!issuerUrl || !clientId) return null;
  return {
    issuerUrl: issuerUrl.replace(/\/$/, ''),
    clientId,
    clientSecret: process.env.OIDC_CLIENT_SECRET || undefined,
  };
}

interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

let discoveryCache: { issuer: string; doc: OidcDiscovery; fetchedAt: number } | null = null;

export async function discoverOidc(cfg: OidcConfig): Promise<OidcDiscovery> {
  if (
    discoveryCache &&
    discoveryCache.issuer === cfg.issuerUrl &&
    Date.now() - discoveryCache.fetchedAt < 10 * 60 * 1000
  ) {
    return discoveryCache.doc;
  }
  const res = await fetch(`${cfg.issuerUrl}/.well-known/openid-configuration`, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`OIDC discovery failed: ${res.status}`);
  }
  const doc = (await res.json()) as OidcDiscovery;
  if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error('OIDC discovery document is incomplete');
  }
  discoveryCache = { issuer: cfg.issuerUrl, doc, fetchedAt: Date.now() };
  return doc;
}

export function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Buffer.from(buf).toString('base64url');
}

/**
 * Exchange an authorization code at the provider's token endpoint and
 * verify the returned ID token (signature via the provider JWKS, plus
 * issuer, audience, expiry, and the nonce bound at login time).
 * Returns the verified claims; throws on any failure.
 */
export async function exchangeCodeForIdentity(
  cfg: OidcConfig,
  discovery: OidcDiscovery,
  code: string,
  redirectUri: string,
  expectedNonce: string | undefined
): Promise<JWTPayload> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: cfg.clientId,
  });
  if (cfg.clientSecret) {
    body.set('client_secret', cfg.clientSecret);
  }

  const res = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body,
  });
  if (!res.ok) {
    throw new Error(`OIDC token exchange failed: ${res.status}`);
  }
  const tokens = (await res.json()) as { id_token?: string };
  if (!tokens.id_token) {
    throw new Error('OIDC token response contains no id_token');
  }

  const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
  const { payload } = await jwtVerify(tokens.id_token, jwks, {
    issuer: cfg.issuerUrl,
    audience: cfg.clientId,
  });
  if (expectedNonce && payload.nonce !== expectedNonce) {
    throw new Error('OIDC nonce mismatch');
  }
  return payload;
}

/**
 * Map verified IdP group claims to an Axonwall RBAC role. Anything
 * unrecognized fails closed to the least-privileged role.
 */
export function roleFromGroups(groups: unknown): 'admin' | 'operator' | 'readonly' {
  const list = Array.isArray(groups)
    ? groups.filter((g): g is string => typeof g === 'string')
    : [];
  const has = (needle: string) => list.some((g) => g.toLowerCase().includes(needle));
  if (has('admin')) return 'admin';
  if (has('operator') || has('noc')) return 'operator';
  return 'readonly';
}
