import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { isPluginEnabled } from '@axonwall/lib/plugins';
import { getDesiredStateInternal } from './desired-state-internal';

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
 * Resolves the external browser-facing origin behind a reverse proxy (e.g. axonwall-controller
 * on :2966 forwarding to Next.js on 127.0.0.1:3000) rather than using internal request.nextUrl.origin.
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

  const rawFwdHost = reqHeaders.get('x-forwarded-host')?.split(',')[0]?.trim();
  const rawHost = rawFwdHost || reqHeaders.get('host')?.split(',')[0]?.trim();
  if (rawHost && SAFE_FORWARDED_HOST_RE.test(rawHost)) {
    const rawProto = reqHeaders.get('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase();
    const proto =
      rawProto === 'http' || rawProto === 'https'
        ? rawProto
        : fallbackOrigin.startsWith('http://')
          ? 'http'
          : 'https';
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
  if (!expectedNonce || !expectedNonce.trim()) {
    throw new Error('OIDC nonce missing');
  }
  if (payload.nonce !== expectedNonce) {
    throw new Error('OIDC nonce mismatch');
  }
  return payload;
}

/**
 * Map verified IdP group claims to an Axonwall RBAC role. Anything
 * unrecognized fails closed to the least-privileged role.
 */
export function roleFromGroups(
  groups: unknown,
  roleMappings?: OidcRoleMapping[]
): 'admin' | 'operator' | 'readonly' | 'vpn_user' {
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

  return 'readonly';
}
