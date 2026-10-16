import type { CaptivePortalConfig, CaptivePortalZone } from '../schemas/index.js';

export interface CaptiveSession {
  sessionId: string;
  zone: string;
  clientIp: string;
  clientMac: string;
  username: string;
  createdAt: number;
  expiresAt: number;
  downloadBytes: number;
  uploadBytes: number;
}

export interface CompiledCaptivePortal {
  nftRules: string[];
}

/**
 * Compiles Captive Portal zone settings into nftables redirection rules.
 * Redirects unauthenticated HTTP and HTTPS requests to the local captive portal portal web service.
 */
export function compileCaptivePortal(config?: CaptivePortalConfig): CompiledCaptivePortal {
  if (!config || !config.enabled || !config.zones || config.zones.length === 0) {
    return { nftRules: [] };
  }

  const nftRules: string[] = [];

  for (const zone of config.zones) {
    if (!zone.enabled) continue;
    const iface = zone.interface;
    const port = zone.listenPort || 8999;

    // Skip passthrough MACs
    for (const mac of zone.passThroughMacs) {
      nftRules.push(`iifname "${iface}" ether saddr ${mac} accept comment "captive-passthrough-mac"`);
    }

    // Skip passthrough IPs
    for (const ip of zone.passThroughIps) {
      nftRules.push(`iifname "${iface}" ip saddr ${ip} accept comment "captive-passthrough-ip"`);
    }

    // HTTP redirection to captive portal portal
    nftRules.push(
      `iifname "${iface}" tcp dport 80 redirect to :${port} comment "captive-${zone.name}-http"`,
      `iifname "${iface}" tcp dport 443 redirect to :${port} comment "captive-${zone.name}-https"`
    );
  }

  return { nftRules };
}

/**
 * In-memory / transactional session manager for captive portal guests.
 */
export class CaptiveSessionManager {
  private sessions: Map<string, CaptiveSession> = new Map();

  createSession(
    zone: CaptivePortalZone,
    clientIp: string,
    clientMac: string,
    username: string
  ): CaptiveSession {
    const sessionId = `sess_${Date.now()}_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
    const now = Date.now();
    const durationMs = (zone.sessionTimeoutMinutes || 720) * 60 * 1000;

    const session: CaptiveSession = {
      sessionId,
      zone: zone.name,
      clientIp,
      clientMac,
      username,
      createdAt: now,
      expiresAt: now + durationMs,
      downloadBytes: 0,
      uploadBytes: 0,
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  isClientAuthenticated(clientIp: string, clientMac?: string): boolean {
    const now = Date.now();
    for (const s of this.sessions.values()) {
      if (s.clientIp === clientIp || (clientMac && s.clientMac === clientMac)) {
        if (s.expiresAt > now) {
          return true;
        }
      }
    }
    return false;
  }

  terminateSession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  getActiveSessions(): CaptiveSession[] {
    const now = Date.now();
    const active: CaptiveSession[] = [];
    for (const s of this.sessions.values()) {
      if (s.expiresAt > now) {
        active.push(s);
      }
    }
    return active;
  }
}
