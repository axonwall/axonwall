/**
 * Client helper for fetching Mesh VPN invite metadata without leaking the
 * secret invite token in URL query strings (SEC-M18).
 */

export interface InvitePreviewData {
  status: 'valid' | 'expired' | 'used' | 'revoked' | 'invalid';
  username?: string;
  displayName?: string;
  mode?: 'onboard' | 'reset';
  expiresAt?: string;
  createStarterKey?: boolean;
  requiresPin?: boolean;
  magicDnsDomain?: string;
  minPasswordLength?: number;
  portalUrl?: string;
  loginUrl?: string;
  portalLoginUrl?: string;
}

export async function fetchInvitePreview(
  token: string,
  fetchFn: typeof fetch = fetch
): Promise<InvitePreviewData> {
  const res = await fetchFn('/api/v1/vpn/mesh/invites/preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
    cache: 'no-store',
  });
  const json = await res.json().catch(() => null);
  if (!res.ok || json?.status !== 'ok') {
    throw new Error(json?.error || `Failed to verify invite link (HTTP ${res.status})`);
  }
  return json.data as InvitePreviewData;
}
