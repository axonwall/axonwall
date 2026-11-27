import crypto from 'node:crypto';
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from 'jose';
import { isPluginEnabled } from '@axonwall/lib/plugins';
import { getDesiredStateInternal } from './desired-state-internal';
import { assertSafeOutboundUrl, ssrfSafeFetch } from './ssrf-guard';

const OIDC_ALLOWED_JWS_ALGS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
];
const OIDC_MAX_RESPONSE_BYTES = 1024 * 1024;

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

export interface OidcRoleMapping {
  idpGroup: string;
  role: 'admin' | 'operator' | 'readonly' | 'vpn_user';
}

export interface OidcConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  scopes?: string[];
  groupClaim?: string;
  roleMappings?: OidcRoleMapping[];
}

export async function getOidcConfig(): Promise<OidcConfig | null> {
  let desiredState: Awaited<ReturnType<typeof getDesiredStateInternal>> | null = null;
  try {
    desiredState = await getDesiredStateInternal();
  } catch {
    desiredState = null;
  }

  const envIssuerUrl = process.env.OIDC_ISSUER_URL?.trim();
  const envClientId = process.env.OIDC_CLIENT_ID?.trim();
  if (envIssuerUrl && envClientId) {
    if (!desiredState || !isPluginEnabled('enterprise-sso', desiredState)) {
      return null;
    }
    return {
      issuerUrl: envIssuerUrl.replace(/\/+$/, ''),
      clientId: envClientId,
      clientSecret: process.env.OIDC_CLIENT_SECRET?.trim() || undefined,
      redirectUri: process.env.OIDC_REDIRECT_URI?.trim() || undefined,
    };
  }

  if (desiredState && isPluginEnabled('enterprise-sso', desiredState)) {
    const sso = desiredState.sso;
    if (
      sso?.enabled &&
      sso.provider === 'oidc' &&
      sso.issuerUrl?.trim() &&
      sso.clientId?.trim()
    ) {
      return {
        issuerUrl: sso.issuerUrl.trim().replace(/\/+$/, ''),
        clientId: sso.clientId.trim(),
        clientSecret: sso.clientSecret?.trim() || undefined,
        redirectUri: sso.redirectUri?.trim() || undefined,
        scopes: Array.isArray(sso.scopes) && sso.scopes.length > 0 ? sso.scopes : undefined,
        groupClaim: sso.groupClaim?.trim() || undefined,
        roleMappings: Array.isArray(sso.roleMappings) ? sso.roleMappings : undefined,
      };
    }
  }

  return null;
}

const SAFE_FORWARDED_HOST_RE = /^(?:\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(?::\d{1,5})?$/;

/**
 * Resolves the external browser-facing origin.
 * Never trusts untrusted X-Forwarded-Host / X-Forwarded-Proto headers unless
 * explicitly opted in via AXONWALL_TRUST_PROXY=1 or AXONWALL_TRUSTED_HOSTS.
 */
export function resolvePublicOrigin(
  reqHeaders: Pick<Headers, 'get'>,
  fallbackOrigin: string,
  configuredRedirectUri?: string
): string {
  for (const candidate of [configuredRedirectUri, process.env.AXONWALL_PUBLIC_URL]) {
    const trimmed = candidate?.trim();
    if (!trimmed) continue;
    try {
      const u = new URL(trimmed);
      if (u.protocol === 'https:' || u.protocol === 'http:') {
        return u.origin;
      }
    } catch {}
  }

  const trustProxy =
    process.env.AXONWALL_TRUST_PROXY === '1' || process.env.AXONWALL_TRUST_PROXY === 'true';
  const trustedHosts = new Set(
    (process.env.AXONWALL_TRUSTED_HOSTS || '')
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean)
  );

  const rawFwdHost = reqHeaders.get('x-forwarded-host')?.split(',')[0]?.trim();
  const fwdHostTrusted =
    Boolean(rawFwdHost) &&
    SAFE_FORWARDED_HOST_RE.test(rawFwdHost!) &&
    (trustProxy || trustedHosts.has(rawFwdHost!.toLowerCase()));

  if (fwdHostTrusted && rawFwdHost) {
    const rawProto = reqHeaders.get('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase();
    const proto =
      rawProto === 'http' || rawProto === 'https'
        ? rawProto
        : fallbackOrigin.startsWith('http://')
          ? 'http'
          : 'https';
    return `${proto}://${rawFwdHost}`;
  }

  const rawHost = reqHeaders.get('host')?.split(',')[0]?.trim();
  if (rawHost && SAFE_FORWARDED_HOST_RE.test(rawHost) && trustedHosts.has(rawHost.toLowerCase())) {
    const proto = fallbackOrigin.startsWith('http://') ? 'http' : 'https';
    return `${proto}://${rawHost}`;
  }

  return fallbackOrigin;
}

export function resolveOidcRedirectUri(publicOrigin: string, configuredRedirectUri?: string): string {
  const trimmed = configuredRedirectUri?.trim();
  if (trimmed) {
    try {
      const u = new URL(trimmed);
      if (u.protocol === 'https:' || u.protocol === 'http:') {
        return u.toString();
      }
    } catch {}
  }
  return `${publicOrigin.replace(/\/+$/, '')}/api/auth/callback/oidc`;
}

interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

let discoveryCache: { issuer: string; doc: OidcDiscovery; fetchedAt: number } | null = null;

export function isOidcHttpAllowed(cfg: Pick<OidcConfig, 'issuerUrl'>): boolean {
  return (
    cfg.issuerUrl.startsWith('http://') &&
    (process.env.NODE_ENV !== 'production' ||
      process.env.OIDC_ALLOW_HTTP === '1' ||
      process.env.AXONWALL_INSECURE_HTTP === '1')
  );
}

export function validateOidcAuthorizationEndpoint(rawUrl: string, allowHttp: boolean): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('OIDC authorization_endpoint is not a valid URL');
  }
  if (parsed.username || parsed.password) {
    throw new Error('OIDC authorization_endpoint must not contain embedded credentials');
  }
  if (parsed.protocol !== 'https:' && !(allowHttp && parsed.protocol === 'http:')) {
    throw new Error('OIDC authorization_endpoint must use HTTPS');
  }
  return parsed;
}

export async function discoverOidc(cfg: OidcConfig): Promise<OidcDiscovery> {
  if (
    discoveryCache &&
    discoveryCache.issuer === cfg.issuerUrl &&
    Date.now() - discoveryCache.fetchedAt < 10 * 60 * 1000
  ) {
    return discoveryCache.doc;
  }
  const allowHttp = isOidcHttpAllowed(cfg);
  const res = await ssrfSafeFetch(
    `${cfg.issuerUrl}/.well-known/openid-configuration`,
    {
      headers: { accept: 'application/json' },
      timeoutMs: 10000,
      maxResponseBytes: OIDC_MAX_RESPONSE_BYTES,
    },
    { allowHttp, allowPrivate: false }
  );
  if (!res.ok) {
    throw new Error(`OIDC discovery failed: ${res.status}`);
  }
  const doc = (await res.json()) as OidcDiscovery;
  if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error('OIDC discovery document is incomplete');
  }
  validateOidcAuthorizationEndpoint(doc.authorization_endpoint, allowHttp);
  await Promise.all([
    assertSafeOutboundUrl(doc.token_endpoint, { allowHttp, allowPrivate: false }),
    assertSafeOutboundUrl(doc.jwks_uri, { allowHttp, allowPrivate: false }),
  ]);
  discoveryCache = { issuer: cfg.issuerUrl, doc, fetchedAt: Date.now() };
  return doc;
}

export function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Buffer.from(buf).toString('base64url');
}

export function computePkceChallenge(codeVerifier: string): string {
  return crypto.createHash('sha256').update(codeVerifier).digest('base64url');
}

/**
 * Exchange an authorization code at the provider's token endpoint and
 * verify the returned ID token (signature via the provider JWKS, plus
 * issuer, audience, azp, expiry, and the nonce bound at login time).
 * Returns the verified claims; throws on any failure.
 */
export async function exchangeCodeForIdentity(
  cfg: OidcConfig,
  discovery: OidcDiscovery,
  code: string,
  redirectUri: string,
  expectedNonce: string | undefined,
  codeVerifier?: string
): Promise<JWTPayload> {
  if (!expectedNonce || !expectedNonce.trim()) {
    throw new Error('OIDC nonce missing');
  }
  if (!codeVerifier || !codeVerifier.trim()) {
    throw new Error('OIDC PKCE code_verifier missing');
  }

  const allowHttp = isOidcHttpAllowed(cfg);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: cfg.clientId,
    code_verifier: codeVerifier,
  });
  if (cfg.clientSecret) {
    body.set('client_secret', cfg.clientSecret);
  }

  const res = await ssrfSafeFetch(
    discovery.token_endpoint,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: body.toString(),
      timeoutMs: 10000,
      maxResponseBytes: OIDC_MAX_RESPONSE_BYTES,
    },
    { allowHttp, allowPrivate: false }
  );
  if (!res.ok) {
    throw new Error(`OIDC token exchange failed: ${res.status}`);
  }
  const tokens = (await res.json()) as { id_token?: string };
  if (!tokens.id_token) {
    throw new Error('OIDC token response contains no id_token');
  }

  const jwksRes = await ssrfSafeFetch(
    discovery.jwks_uri,
    {
      headers: { accept: 'application/json' },
      timeoutMs: 10000,
      maxResponseBytes: OIDC_MAX_RESPONSE_BYTES,
    },
    { allowHttp, allowPrivate: false }
  );
  if (!jwksRes.ok) {
    throw new Error(`OIDC JWKS fetch failed: ${jwksRes.status}`);
  }
  const jwksDoc = (await jwksRes.json()) as JSONWebKeySet;
  const jwks = createLocalJWKSet(jwksDoc);
  const { payload } = await jwtVerify(tokens.id_token, jwks, {
    issuer: cfg.issuerUrl,
    audience: cfg.clientId,
    algorithms: OIDC_ALLOWED_JWS_ALGS,
  });
  if (payload.nonce !== expectedNonce) {
    throw new Error('OIDC nonce mismatch');
  }
  if (typeof payload.sub !== 'string' || !payload.sub.trim()) {
    throw new Error('OIDC sub claim missing');
  }
  if (Array.isArray(payload.aud) && payload.aud.length > 1) {
    if (typeof payload.azp !== 'string' || payload.azp !== cfg.clientId) {
      throw new Error('OIDC azp claim missing or mismatch for multi-audience token');
    }
  } else if (payload.azp !== undefined && payload.azp !== cfg.clientId) {
    throw new Error('OIDC azp claim mismatch');
  }
  return payload;
}

/**
 * Map verified IdP group claims to an Axonwall RBAC role. Anything
 * unrecognized fails closed and returns null.
 */
export function roleFromGroups(
  groups: unknown,
  roleMappings?: OidcRoleMapping[]
): 'admin' | 'operator' | 'readonly' | 'vpn_user' | null {
  const list = Array.isArray(groups)
    ? groups.filter((g): g is string => typeof g === 'string')
    : [];

  const envAdminGroups = (process.env.OIDC_ADMIN_GROUPS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const envOperatorGroups = (process.env.OIDC_OPERATOR_GROUPS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const envVpnGroups = (process.env.OIDC_VPN_GROUPS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const adminSet =
    envAdminGroups.length > 0
      ? new Set(envAdminGroups)
      : new Set(['axonwall-admin', 'axonwall-admins']);

  const operatorSet =
    envOperatorGroups.length > 0
      ? new Set(envOperatorGroups)
      : new Set(['axonwall-operator', 'axonwall-operators']);

  const vpnSet =
    envVpnGroups.length > 0
      ? new Set(envVpnGroups)
      : new Set(['axonwall-vpn']);

  const readonlyExplicitSet = new Set(['axonwall-readonly', 'axonwall-auditors']);

  if (Array.isArray(roleMappings)) {
    for (const m of roleMappings) {
      const g = m?.idpGroup?.trim().toLowerCase();
      if (!g) continue;
      if (m.role === 'admin') adminSet.add(g);
      else if (m.role === 'operator') operatorSet.add(g);
      else if (m.role === 'vpn_user') vpnSet.add(g);
      else if (m.role === 'readonly') readonlyExplicitSet.add(g);
    }
  }

  const normalizedList = list.map((g) => g.trim().toLowerCase());

  for (const group of normalizedList) {
    if (adminSet.has(group)) return 'admin';
  }

  for (const group of normalizedList) {
    if (operatorSet.has(group)) return 'operator';
  }

  for (const group of normalizedList) {
    if (readonlyExplicitSet.has(group)) return 'readonly';
  }

  for (const group of normalizedList) {
    if (vpnSet.has(group)) return 'vpn_user';
  }

  return null;
}
